#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)] // libc::S_* are u16 or u32 depending on the platform

use ::serde::{Deserialize, Serialize};
use chacha20::cipher::{Iv, IvSizeUser, KeyIvInit, KeySizeUser};
use chacha20::ChaCha20;
use chacha20::Key;
use fd_lock_rs::{FdLock, LockType};
use fuser::consts::FOPEN_DIRECT_IO;
use fuser::consts::FUSE_HANDLE_KILLPRIV;
use fuser::consts::FUSE_WRITE_KILL_PRIV;
use fuser::TimeOrNow::Now;
use fuser::{
    Filesystem, KernelConfig, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow, FUSE_ROOT_ID,
};
use log::{debug, error, warn};
use std::cmp::min;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
#[cfg(target_os = "linux")]
use std::os::unix::io::IntoRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use typenum::ToInt;
use zeroize::Zeroizing;

use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::ctrl::Controller;
use crate::directory::DirectoryContents;
use crate::handle::Handler;
use crate::inode::DirectoryDescriptor;
use crate::inode::FileKind;
use crate::inode::Inode;
use crate::inode::InodeAttributes;
use crate::inode::BLOCK_SIZE;
use crate::serde::load;
use crate::serde::save;

mod atomic_file;
mod contents;
mod ctrl;
mod directory;
mod error;
mod handle;
mod inode;
mod serde;
mod util;

pub const MAX_NAME_LENGTH: u32 = 255;
const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024;
pub const ENTRY_TTL: Duration = Duration::new(3600, 0);

const FMODE_EXEC: i32 = 0x20;

#[cfg_attr(feature = "cli", derive(clap::Parser))]
pub struct BackupFSOptions {
    pub data_dir: PathBuf,
    #[cfg_attr(feature = "cli", arg(long))]
    pub direct_io: bool,
    #[cfg_attr(feature = "cli", arg(long))]
    pub setuid_support: bool,
    #[cfg_attr(feature = "cli", arg(long))]
    pub password: String,
    #[cfg_attr(feature = "cli", arg(long))]
    pub file_size_padding: Option<f64>,
}

// Stores inode metadata data in "$data_dir/inodes" and file contents in "$data_dir/contents"
// Directory data is stored in the file's contents, as a serialized DirectoryDescriptor
pub struct BackupFS {
    lock: FdLock<File>,
    handler: Handler,
}

const CHACHA_KEY_SIZE: usize = <<ChaCha20 as KeySizeUser>::KeySize as ToInt<usize>>::INT;
const CHACHA_IV_SIZE: usize = <<ChaCha20 as IvSizeUser>::IvSize as ToInt<usize>>::INT;

#[derive(Deserialize, Serialize)]
pub struct CryptInfo {
    pub key: Zeroizing<[u8; CHACHA_KEY_SIZE]>,
    pub inode_iv: [u8; CHACHA_IV_SIZE],
}
impl CryptInfo {
    pub fn new() -> Self {
        Self {
            key: Zeroizing::new(rand::random()),
            inode_iv: rand::random(),
        }
    }
    pub fn load(path: &Path, password: &str) -> io::Result<Self> {
        load(EncryptedFile::open_pbkdf2(File::open(path)?, password)?)
    }
    pub fn save(&self, path: PathBuf, password: &str) -> io::Result<()> {
        save(
            self,
            EncryptedFile::open_pbkdf2(AtomicFile::create(path)?, password)?,
        )
    }
}

impl BackupFS {
    pub fn new(config: BackupFSOptions) -> io::Result<BackupFS> {
        let BackupFSOptions {
            data_dir, password, ..
        } = &config;
        let lock = fd_lock_rs::FdLock::lock(
            File::create(data_dir.join(".lock"))?,
            LockType::Exclusive,
            false,
        )?;
        let cryptinfo_path = data_dir.join("cryptinfo");
        let cryptinfo = if cryptinfo_path.exists() {
            CryptInfo::load(&cryptinfo_path, password)?
        } else {
            let cryptinfo = CryptInfo::new();
            cryptinfo.save(cryptinfo_path, password)?;
            cryptinfo
        };
        let key = Key::clone_from_slice(&*cryptinfo.key);
        let iv = Iv::<ChaCha20>::clone_from_slice(&cryptinfo.inode_iv);
        let ctrl = Controller::new(config, key, iv);

        if !ctrl.exists::<InodeAttributes>(FUSE_ROOT_ID) {
            // Initialize with empty filesystem
            let root = InodeAttributes::new(FUSE_ROOT_ID, FileKind::Directory);
            let dir = DirectoryContents::new(FUSE_ROOT_ID);
            ctrl.save(&dir)?;
            ctrl.save(&root)?;
        } else {
            ctrl.load::<InodeAttributes>(FUSE_ROOT_ID)?;
            ctrl.load::<DirectoryContents>(FUSE_ROOT_ID)?;
        }
        Ok(BackupFS {
            lock,
            handler: Handler::new(ctrl),
        })
    }

    fn creation_mode(&self, mode: u32) -> u16 {
        if !self.handler.ctrl().config().setuid_support {
            (mode & !(libc::S_ISUID | libc::S_ISGID) as u32) as u16
        } else {
            mode as u16
        }
    }

    // Check whether a file should be removed from storage. Should be called after decrementing
    // the link count, or closing a file handle
    fn gc_inode(&self, inode: &InodeAttributes) -> bool {
        if inode.hardlinks == 0 && inode.open_file_handles == 0 {
            let inode_path = self.inode_dir.join(inode.inode.to_string());
            fs::remove_file(inode_path).unwrap();
            let content_path = self.inode_dir.join(inode.inode.to_string());
            fs::remove_file(content_path).unwrap();

            return true;
        }

        return false;
    }

    fn truncate(
        &self,
        inode: Inode,
        new_length: u64,
        uid: u32,
        gid: u32,
    ) -> Result<InodeAttributes, c_int> {
        if new_length > MAX_FILE_SIZE {
            return Err(libc::EFBIG);
        }

        let mut attrs = self.get_inode(inode)?;

        if !check_access(attrs.uid, attrs.gid, attrs.mode, uid, gid, libc::W_OK) {
            return Err(libc::EACCES);
        }

        let path = self.content_path(inode);
        let file = OpenOptions::new().write(true).open(path).unwrap();
        file.set_len(new_length).unwrap();

        attrs.size = new_length;
        attrs.last_metadata_changed = time_now();
        attrs.last_modified = time_now();

        // Clear SETUID & SETGID on truncate
        attrs.clear_suid_sgid();

        self.write_inode(&attrs);

        Ok(attrs)
    }

    fn insert_link(
        &self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        inode: u64,
        kind: FileKind,
    ) -> Result<(), c_int> {
        if self.lookup_name(parent, name).is_ok() {
            return Err(libc::EEXIST);
        }

        let mut parent_attrs = self.get_inode(parent)?;

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            return Err(libc::EACCES);
        }
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.write_inode(&parent_attrs);

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.insert(name.as_bytes().to_vec(), (inode, kind));
        self.write_directory_content(parent, entries);

        Ok(())
    }
}

impl Filesystem for BackupFS {
    fn init(
        &mut self,
        _req: &Request,
        #[allow(unused_variables)] config: &mut KernelConfig,
    ) -> Result<(), c_int> {
        config.add_capabilities(FUSE_HANDLE_KILLPRIV).unwrap();

        Ok(())
    }

    fn destroy(&mut self) {
        if let Err(e) = self.handler.close_all() {
            error!("error closing FS: {e}");
        }
    }

    fn lookup(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.handler.lookup(req, parent, name) {
            Ok(attr) => reply.entry(&ENTRY_TTL, &attr.into(), 0),
            Err(e) => reply.error(error::to_libc_err(&e)),
        }
    }

    fn forget(&mut self, _req: &Request, _ino: u64, _nlookup: u64) {}

    fn getattr(&mut self, _req: &Request, inode: u64, reply: ReplyAttr) {
        match self.handler.ctrl().load::<InodeAttributes>(inode) {
            Ok(attr) => reply.attr(&ENTRY_TTL, &attr.into()),
            Err(e) => reply.error(error::to_libc_err(&e)),
        }
    }

    fn setattr(
        &mut self,
        req: &Request,
        inode: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<u64>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        match self.handler.setattr(
            req, inode, mode, uid, gid, size, atime, mtime, ctime, fh, crtime, chgtime, bkuptime,
            flags,
        ) {
            Ok(attr) => reply.attr(&ENTRY_TTL, &attr.into()),
            Err(e) => reply.error(error::to_libc_err(&e)),
        }
    }

    fn readlink(&mut self, _req: &Request, inode: u64, reply: ReplyData) {
        debug!("readlink() called on {:?}", inode);
        let path = self.content_path(inode);
        if let Ok(mut file) = File::open(path) {
            let file_size = file.metadata().unwrap().len();
            let mut buffer = vec![0; file_size as usize];
            file.read_exact(&mut buffer).unwrap();
            reply.data(&buffer);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn mknod(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        let file_type = mode & libc::S_IFMT as u32;

        if file_type != libc::S_IFREG as u32
            && file_type != libc::S_IFLNK as u32
            && file_type != libc::S_IFDIR as u32
        {
            // TODO
            warn!("mknod() implementation is incomplete. Only supports regular files, symlinks, and directories. Got {:o}", mode);
            reply.error(libc::ENOSYS);
            return;
        }

        if self.lookup_name(parent, name).is_ok() {
            reply.error(libc::EEXIST);
            return;
        }

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.write_inode(&parent_attrs);

        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }

        let inode = self.allocate_next_inode();
        let attrs = InodeAttributes {
            inode,
            open_file_handles: 0,
            size: 0,
            last_accessed: time_now(),
            last_modified: time_now(),
            last_metadata_changed: time_now(),
            kind: as_file_kind(mode),
            mode: self.creation_mode(mode),
            hardlinks: 1,
            uid: req.uid(),
            gid: parent_attrs.creation_gid(req.gid()),
            xattrs: Default::default(),
        };
        self.write_inode(&attrs);
        File::create(self.content_path(inode)).unwrap();

        if as_file_kind(mode) == FileKind::Directory {
            let mut entries = BTreeMap::new();
            entries.insert(b".".to_vec(), (inode, FileKind::Directory));
            entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
            self.write_directory_content(inode, entries);
        }

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.insert(name.as_bytes().to_vec(), (inode, attrs.kind));
        self.write_directory_content(parent, entries);

        // TODO: implement flags
        reply.entry(&Duration::new(0, 0), &attrs.into(), 0);
    }

    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        debug!("mkdir() called with {:?} {:?} {:o}", parent, name, mode);
        if self.lookup_name(parent, name).is_ok() {
            reply.error(libc::EEXIST);
            return;
        }

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.write_inode(&parent_attrs);

        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }
        if parent_attrs.mode & libc::S_ISGID as u16 != 0 {
            mode |= libc::S_ISGID as u32;
        }

        let inode = self.allocate_next_inode();
        let attrs = InodeAttributes {
            inode,
            open_file_handles: 0,
            size: BLOCK_SIZE,
            last_accessed: time_now(),
            last_modified: time_now(),
            last_metadata_changed: time_now(),
            kind: FileKind::Directory,
            mode: self.creation_mode(mode),
            hardlinks: 2, // Directories start with link count of 2, since they have a self link
            uid: req.uid(),
            gid: parent_attrs.creation_gid(req.gid()),
            xattrs: Default::default(),
        };
        self.write_inode(&attrs);

        let mut entries = BTreeMap::new();
        entries.insert(b".".to_vec(), (inode, FileKind::Directory));
        entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
        self.write_directory_content(inode, entries);

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.insert(name.as_bytes().to_vec(), (inode, FileKind::Directory));
        self.write_directory_content(parent, entries);

        reply.entry(&Duration::new(0, 0), &attrs.into(), 0);
    }

    fn unlink(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        debug!("unlink() called with {:?} {:?}", parent, name);
        let mut attrs = match self.lookup_name(parent, name) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }

        let uid = req.uid();
        // "Sticky bit" handling
        if parent_attrs.mode & libc::S_ISVTX as u16 != 0
            && uid != 0
            && uid != parent_attrs.uid
            && uid != attrs.uid
        {
            reply.error(libc::EACCES);
            return;
        }

        parent_attrs.last_metadata_changed = time_now();
        parent_attrs.last_modified = time_now();
        self.write_inode(&parent_attrs);

        attrs.hardlinks -= 1;
        attrs.last_metadata_changed = time_now();
        self.write_inode(&attrs);
        self.gc_inode(&attrs);

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.remove(name.as_bytes());
        self.write_directory_content(parent, entries);

        reply.ok();
    }

    fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        debug!("rmdir() called with {:?} {:?}", parent, name);
        let mut attrs = match self.lookup_name(parent, name) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        // Directories always have a self and parent link
        if self.get_directory_content(attrs.inode).unwrap().len() > 2 {
            reply.error(libc::ENOTEMPTY);
            return;
        }
        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }

        // "Sticky bit" handling
        if parent_attrs.mode & libc::S_ISVTX as u16 != 0
            && req.uid() != 0
            && req.uid() != parent_attrs.uid
            && req.uid() != attrs.uid
        {
            reply.error(libc::EACCES);
            return;
        }

        parent_attrs.last_metadata_changed = time_now();
        parent_attrs.last_modified = time_now();
        self.write_inode(&parent_attrs);

        attrs.hardlinks = 0;
        attrs.last_metadata_changed = time_now();
        self.write_inode(&attrs);
        self.gc_inode(&attrs);

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.remove(name.as_bytes());
        self.write_directory_content(parent, entries);

        reply.ok();
    }

    fn symlink(
        &mut self,
        req: &Request,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        debug!(
            "symlink() called with {:?} {:?} {:?}",
            parent, link_name, target
        );
        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.write_inode(&parent_attrs);

        let inode = self.allocate_next_inode();
        let attrs = InodeAttributes {
            inode,
            open_file_handles: 0,
            size: target.as_os_str().as_bytes().len() as u64,
            last_accessed: time_now(),
            last_modified: time_now(),
            last_metadata_changed: time_now(),
            kind: FileKind::Symlink,
            mode: 0o777,
            hardlinks: 1,
            uid: req.uid(),
            gid: parent_attrs.creation_gid(req.gid()),
            xattrs: Default::default(),
        };

        if let Err(error_code) = self.insert_link(req, parent, link_name, inode, FileKind::Symlink)
        {
            reply.error(error_code);
            return;
        }
        self.write_inode(&attrs);

        let path = self.content_path(inode);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.write_all(target.as_os_str().as_bytes()).unwrap();

        reply.entry(&Duration::new(0, 0), &attrs.into(), 0);
    }

    fn rename(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let mut inode_attrs = match self.lookup_name(parent, name) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }

        // "Sticky bit" handling
        if parent_attrs.mode & libc::S_ISVTX as u16 != 0
            && req.uid() != 0
            && req.uid() != parent_attrs.uid
            && req.uid() != inode_attrs.uid
        {
            reply.error(libc::EACCES);
            return;
        }

        let mut new_parent_attrs = match self.get_inode(new_parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if !check_access(
            new_parent_attrs.uid,
            new_parent_attrs.gid,
            new_parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }

        // "Sticky bit" handling in new_parent
        if new_parent_attrs.mode & libc::S_ISVTX as u16 != 0 {
            if let Ok(existing_attrs) = self.lookup_name(new_parent, new_name) {
                if req.uid() != 0
                    && req.uid() != new_parent_attrs.uid
                    && req.uid() != existing_attrs.uid
                {
                    reply.error(libc::EACCES);
                    return;
                }
            }
        }

        #[cfg(target_os = "linux")]
        if flags & libc::RENAME_EXCHANGE as u32 != 0 {
            let mut new_inode_attrs = match self.lookup_name(new_parent, new_name) {
                Ok(attrs) => attrs,
                Err(error_code) => {
                    reply.error(error_code);
                    return;
                }
            };

            let mut entries = self.get_directory_content(new_parent).unwrap();
            entries.insert(
                new_name.as_bytes().to_vec(),
                (inode_attrs.inode, inode_attrs.kind),
            );
            self.write_directory_content(new_parent, entries);

            let mut entries = self.get_directory_content(parent).unwrap();
            entries.insert(
                name.as_bytes().to_vec(),
                (new_inode_attrs.inode, new_inode_attrs.kind),
            );
            self.write_directory_content(parent, entries);

            parent_attrs.last_metadata_changed = time_now();
            parent_attrs.last_modified = time_now();
            self.write_inode(&parent_attrs);
            new_parent_attrs.last_metadata_changed = time_now();
            new_parent_attrs.last_modified = time_now();
            self.write_inode(&new_parent_attrs);
            inode_attrs.last_metadata_changed = time_now();
            self.write_inode(&inode_attrs);
            new_inode_attrs.last_metadata_changed = time_now();
            self.write_inode(&new_inode_attrs);

            if inode_attrs.kind == FileKind::Directory {
                let mut entries = self.get_directory_content(inode_attrs.inode).unwrap();
                entries.insert(b"..".to_vec(), (new_parent, FileKind::Directory));
                self.write_directory_content(inode_attrs.inode, entries);
            }
            if new_inode_attrs.kind == FileKind::Directory {
                let mut entries = self.get_directory_content(new_inode_attrs.inode).unwrap();
                entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
                self.write_directory_content(new_inode_attrs.inode, entries);
            }

            reply.ok();
            return;
        }

        // Only overwrite an existing directory if it's empty
        if let Ok(new_name_attrs) = self.lookup_name(new_parent, new_name) {
            if new_name_attrs.kind == FileKind::Directory
                && self
                    .get_directory_content(new_name_attrs.inode)
                    .unwrap()
                    .len()
                    > 2
            {
                reply.error(libc::ENOTEMPTY);
                return;
            }
        }

        // Only move an existing directory to a new parent, if we have write access to it,
        // because that will change the ".." link in it
        if inode_attrs.kind == FileKind::Directory
            && parent != new_parent
            && !check_access(
                inode_attrs.uid,
                inode_attrs.gid,
                inode_attrs.mode,
                req.uid(),
                req.gid(),
                libc::W_OK,
            )
        {
            reply.error(libc::EACCES);
            return;
        }

        // If target already exists decrement its hardlink count
        if let Ok(mut existing_inode_attrs) = self.lookup_name(new_parent, new_name) {
            let mut entries = self.get_directory_content(new_parent).unwrap();
            entries.remove(new_name.as_bytes());
            self.write_directory_content(new_parent, entries);

            if existing_inode_attrs.kind == FileKind::Directory {
                existing_inode_attrs.hardlinks = 0;
            } else {
                existing_inode_attrs.hardlinks -= 1;
            }
            existing_inode_attrs.last_metadata_changed = time_now();
            self.write_inode(&existing_inode_attrs);
            self.gc_inode(&existing_inode_attrs);
        }

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.remove(name.as_bytes());
        self.write_directory_content(parent, entries);

        let mut entries = self.get_directory_content(new_parent).unwrap();
        entries.insert(
            new_name.as_bytes().to_vec(),
            (inode_attrs.inode, inode_attrs.kind),
        );
        self.write_directory_content(new_parent, entries);

        parent_attrs.last_metadata_changed = time_now();
        parent_attrs.last_modified = time_now();
        self.write_inode(&parent_attrs);
        new_parent_attrs.last_metadata_changed = time_now();
        new_parent_attrs.last_modified = time_now();
        self.write_inode(&new_parent_attrs);
        inode_attrs.last_metadata_changed = time_now();
        self.write_inode(&inode_attrs);

        if inode_attrs.kind == FileKind::Directory {
            let mut entries = self.get_directory_content(inode_attrs.inode).unwrap();
            entries.insert(b"..".to_vec(), (new_parent, FileKind::Directory));
            self.write_directory_content(inode_attrs.inode, entries);
        }

        reply.ok();
    }

    fn link(
        &mut self,
        req: &Request,
        inode: u64,
        new_parent: u64,
        new_name: &OsStr,
        reply: ReplyEntry,
    ) {
        debug!(
            "link() called for {}, {}, {:?}",
            inode, new_parent, new_name
        );
        let mut attrs = match self.get_inode(inode) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };
        if let Err(error_code) = self.insert_link(req, new_parent, new_name, inode, attrs.kind) {
            reply.error(error_code);
        } else {
            attrs.hardlinks += 1;
            attrs.last_metadata_changed = time_now();
            self.write_inode(&attrs);
            reply.entry(&Duration::new(0, 0), &attrs.into(), 0);
        }
    }

    fn open(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {
        debug!("open() called for {:?}", inode);
        let (access_mask, read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC != 0 {
                    reply.error(libc::EACCES);
                    return;
                }
                if flags & FMODE_EXEC != 0 {
                    // Open is from internal exec syscall
                    (libc::X_OK, true, false)
                } else {
                    (libc::R_OK, true, false)
                }
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            // Exactly one access mode flag must be specified
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        match self.get_inode(inode) {
            Ok(mut attr) => {
                if check_access(
                    attr.uid,
                    attr.gid,
                    attr.mode,
                    req.uid(),
                    req.gid(),
                    access_mask,
                ) {
                    attr.open_file_handles += 1;
                    self.write_inode(&attr);
                    let open_flags = if self.config.direct_io {
                        FOPEN_DIRECT_IO
                    } else {
                        0
                    };
                    reply.opened(self.allocate_next_file_handle(read, write), open_flags);
                } else {
                    reply.error(libc::EACCES);
                }
                return;
            }
            Err(error_code) => reply.error(error_code),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        debug!(
            "read() called on {:?} offset={:?} size={:?}",
            inode, offset, size
        );
        assert!(offset >= 0);
        if !self.check_file_handle_read(fh) {
            reply.error(libc::EACCES);
            return;
        }

        let path = self.content_path(inode);
        if let Ok(file) = File::open(path) {
            let file_size = file.metadata().unwrap().len();
            // Could underflow if file length is less than local_start
            let read_size = min(size, file_size.saturating_sub(offset as u64) as u32);

            let mut buffer = vec![0; read_size as usize];
            file.read_exact_at(&mut buffer, offset as u64).unwrap();
            reply.data(&buffer);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        #[allow(unused_variables)] flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        debug!("write() called with {:?} size={:?}", inode, data.len());
        assert!(offset >= 0);
        if !self.check_file_handle_write(fh) {
            reply.error(libc::EACCES);
            return;
        }

        let path = self.content_path(inode);
        if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
            file.seek(SeekFrom::Start(offset as u64)).unwrap();
            file.write_all(data).unwrap();

            let mut attrs = self.get_inode(inode).unwrap();
            attrs.last_metadata_changed = time_now();
            attrs.last_modified = time_now();
            if data.len() + offset as usize > attrs.size as usize {
                attrs.size = (data.len() + offset as usize) as u64;
            }
            if flags & FUSE_WRITE_KILL_PRIV as i32 != 0 {
                attrs.clear_suid_sgid();
            }
            // XXX: In theory we should only need to do this when WRITE_KILL_PRIV is set for 7.31+
            // However, xfstests fail in that case
            attrs.clear_suid_sgid();
            self.write_inode(&attrs);

            reply.written(data.len() as u32);
        } else {
            reply.error(libc::EBADF);
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Ok(mut attrs) = self.get_inode(inode) {
            attrs.open_file_handles -= 1;
        }
        reply.ok();
    }

    fn opendir(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {
        debug!("opendir() called on {:?}", inode);
        let (access_mask, read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC != 0 {
                    reply.error(libc::EACCES);
                    return;
                }
                (libc::R_OK, true, false)
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            // Exactly one access mode flag must be specified
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        match self.get_inode(inode) {
            Ok(mut attr) => {
                if check_access(
                    attr.uid,
                    attr.gid,
                    attr.mode,
                    req.uid(),
                    req.gid(),
                    access_mask,
                ) {
                    attr.open_file_handles += 1;
                    self.write_inode(&attr);
                    let open_flags = if self.config.direct_io {
                        FOPEN_DIRECT_IO
                    } else {
                        0
                    };
                    reply.opened(self.allocate_next_file_handle(read, write), open_flags);
                } else {
                    reply.error(libc::EACCES);
                }
                return;
            }
            Err(error_code) => reply.error(error_code),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        inode: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        debug!("readdir() called with {:?}", inode);
        assert!(offset >= 0);
        let entries = match self.get_directory_content(inode) {
            Ok(entries) => entries,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        for (index, entry) in entries.iter().skip(offset as usize).enumerate() {
            let (name, (inode, file_type)) = entry;

            let buffer_full: bool = reply.add(
                *inode,
                offset + index as i64 + 1,
                (*file_type).into(),
                OsStr::from_bytes(name),
            );

            if buffer_full {
                break;
            }
        }

        reply.ok();
    }

    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        _fh: u64,
        _flags: i32,
        reply: ReplyEmpty,
    ) {
        if let Ok(mut attrs) = self.get_inode(inode) {
            attrs.open_file_handles -= 1;
        }
        reply.ok();
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        warn!("statfs() implementation is a stub");
        // TODO: real implementation of this
        reply.statfs(
            10_000,
            10_000,
            10_000,
            1,
            10_000,
            BLOCK_SIZE as u32,
            MAX_NAME_LENGTH,
            BLOCK_SIZE as u32,
        );
    }

    fn setxattr(
        &mut self,
        request: &Request<'_>,
        inode: u64,
        key: &OsStr,
        value: &[u8],
        _flags: i32,
        _position: u32,
        reply: ReplyEmpty,
    ) {
        if let Ok(mut attrs) = self.get_inode(inode) {
            if let Err(error) = attrs.xattr_access_check(key.as_bytes(), libc::W_OK, request) {
                reply.error(error);
                return;
            }

            attrs.xattrs.insert(key.as_bytes().to_vec(), value.to_vec());
            attrs.last_metadata_changed = time_now();
            self.write_inode(&attrs);
            reply.ok();
        } else {
            reply.error(libc::EBADF);
        }
    }

    fn getxattr(
        &mut self,
        request: &Request<'_>,
        inode: u64,
        key: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        if let Ok(attrs) = self.get_inode(inode) {
            if let Err(error) = attrs.xattr_access_check(key.as_bytes(), libc::R_OK, request) {
                reply.error(error);
                return;
            }

            if let Some(data) = attrs.xattrs.get(key.as_bytes()) {
                if size == 0 {
                    reply.size(data.len() as u32);
                } else if data.len() <= size as usize {
                    reply.data(data);
                } else {
                    reply.error(libc::ERANGE);
                }
            } else {
                #[cfg(target_os = "linux")]
                reply.error(libc::ENODATA);
                #[cfg(not(target_os = "linux"))]
                reply.error(libc::ENOATTR);
            }
        } else {
            reply.error(libc::EBADF);
        }
    }

    fn listxattr(&mut self, _req: &Request<'_>, inode: u64, size: u32, reply: ReplyXattr) {
        if let Ok(attrs) = self.get_inode(inode) {
            let mut bytes = vec![];
            // Convert to concatenated null-terminated strings
            for key in attrs.xattrs.keys() {
                bytes.extend(key);
                bytes.push(0);
            }
            if size == 0 {
                reply.size(bytes.len() as u32);
            } else if bytes.len() <= size as usize {
                reply.data(&bytes);
            } else {
                reply.error(libc::ERANGE);
            }
        } else {
            reply.error(libc::EBADF);
        }
    }

    fn removexattr(&mut self, request: &Request<'_>, inode: u64, key: &OsStr, reply: ReplyEmpty) {
        if let Ok(mut attrs) = self.get_inode(inode) {
            if let Err(error) = attrs.xattr_access_check(key.as_bytes(), libc::W_OK, request) {
                reply.error(error);
                return;
            }

            if attrs.xattrs.remove(key.as_bytes()).is_none() {
                #[cfg(target_os = "linux")]
                reply.error(libc::ENODATA);
                #[cfg(not(target_os = "linux"))]
                reply.error(libc::ENOATTR);
                return;
            }
            attrs.last_metadata_changed = time_now();
            self.write_inode(&attrs);
            reply.ok();
        } else {
            reply.error(libc::EBADF);
        }
    }

    fn access(&mut self, req: &Request, inode: u64, mask: i32, reply: ReplyEmpty) {
        debug!("access() called with {:?} {:?}", inode, mask);
        match self.get_inode(inode) {
            Ok(attr) => {
                if check_access(attr.uid, attr.gid, attr.mode, req.uid(), req.gid(), mask) {
                    reply.ok();
                } else {
                    reply.error(libc::EACCES);
                }
            }
            Err(error_code) => reply.error(error_code),
        }
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        debug!("create() called with {:?} {:?}", parent, name);
        if self.lookup_name(parent, name).is_ok() {
            reply.error(libc::EEXIST);
            return;
        }

        let (read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => (true, false),
            libc::O_WRONLY => (false, true),
            libc::O_RDWR => (true, true),
            // Exactly one access mode flag must be specified
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let mut parent_attrs = match self.get_inode(parent) {
            Ok(attrs) => attrs,
            Err(error_code) => {
                reply.error(error_code);
                return;
            }
        };

        if !check_access(
            parent_attrs.uid,
            parent_attrs.gid,
            parent_attrs.mode,
            req.uid(),
            req.gid(),
            libc::W_OK,
        ) {
            reply.error(libc::EACCES);
            return;
        }
        parent_attrs.last_modified = time_now();
        parent_attrs.last_metadata_changed = time_now();
        self.write_inode(&parent_attrs);

        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }

        let inode = self.allocate_next_inode();
        let attrs = InodeAttributes {
            inode,
            open_file_handles: 1,
            size: 0,
            last_accessed: time_now(),
            last_modified: time_now(),
            last_metadata_changed: time_now(),
            kind: as_file_kind(mode),
            mode: self.creation_mode(mode),
            hardlinks: 1,
            uid: req.uid(),
            gid: parent_attrs.creation_gid(req.gid()),
            xattrs: Default::default(),
        };
        self.write_inode(&attrs);
        File::create(self.content_path(inode)).unwrap();

        if as_file_kind(mode) == FileKind::Directory {
            let mut entries = BTreeMap::new();
            entries.insert(b".".to_vec(), (inode, FileKind::Directory));
            entries.insert(b"..".to_vec(), (parent, FileKind::Directory));
            self.write_directory_content(inode, entries);
        }

        let mut entries = self.get_directory_content(parent).unwrap();
        entries.insert(name.as_bytes().to_vec(), (inode, attrs.kind));
        self.write_directory_content(parent, entries);

        // TODO: implement flags
        reply.created(
            &Duration::new(0, 0),
            &attrs.into(),
            0,
            self.allocate_next_file_handle(read, write),
            0,
        );
    }

    #[cfg(target_os = "linux")]
    fn fallocate(
        &mut self,
        _req: &Request<'_>,
        inode: u64,
        _fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        let path = self.content_path(inode);
        if let Ok(file) = OpenOptions::new().write(true).open(path) {
            unsafe {
                libc::fallocate64(file.into_raw_fd(), mode, offset, length);
            }
            if mode & libc::FALLOC_FL_KEEP_SIZE == 0 {
                let mut attrs = self.get_inode(inode).unwrap();
                attrs.last_metadata_changed = time_now();
                attrs.last_modified = time_now();
                if (offset + length) as u64 > attrs.size {
                    attrs.size = (offset + length) as u64;
                }
                self.write_inode(&attrs);
            }
            reply.ok();
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn copy_file_range(
        &mut self,
        _req: &Request<'_>,
        src_inode: u64,
        src_fh: u64,
        src_offset: i64,
        dest_inode: u64,
        dest_fh: u64,
        dest_offset: i64,
        size: u64,
        _flags: u32,
        reply: ReplyWrite,
    ) {
        debug!(
            "copy_file_range() called with src ({}, {}, {}) dest ({}, {}, {}) size={}",
            src_fh, src_inode, src_offset, dest_fh, dest_inode, dest_offset, size
        );
        if !self.check_file_handle_read(src_fh) {
            reply.error(libc::EACCES);
            return;
        }
        if !self.check_file_handle_write(dest_fh) {
            reply.error(libc::EACCES);
            return;
        }

        let src_path = self.content_path(src_inode);
        if let Ok(file) = File::open(src_path) {
            let file_size = file.metadata().unwrap().len();
            // Could underflow if file length is less than local_start
            let read_size = min(size, file_size.saturating_sub(src_offset as u64));

            let mut data = vec![0; read_size as usize];
            file.read_exact_at(&mut data, src_offset as u64).unwrap();

            let dest_path = self.content_path(dest_inode);
            if let Ok(mut file) = OpenOptions::new().write(true).open(dest_path) {
                file.seek(SeekFrom::Start(dest_offset as u64)).unwrap();
                file.write_all(&data).unwrap();

                let mut attrs = self.get_inode(dest_inode).unwrap();
                attrs.last_metadata_changed = time_now();
                attrs.last_modified = time_now();
                if data.len() + dest_offset as usize > attrs.size as usize {
                    attrs.size = (data.len() + dest_offset as usize) as u64;
                }
                self.write_inode(&attrs);

                reply.written(data.len() as u32);
            } else {
                reply.error(libc::EBADF);
            }
        } else {
            reply.error(libc::ENOENT);
        }
    }
}

fn as_file_kind(mut mode: u32) -> FileKind {
    mode &= libc::S_IFMT as u32;

    if mode == libc::S_IFREG as u32 {
        return FileKind::File;
    } else if mode == libc::S_IFLNK as u32 {
        return FileKind::Symlink;
    } else if mode == libc::S_IFDIR as u32 {
        return FileKind::Directory;
    } else {
        unimplemented!("{}", mode);
    }
}

pub fn get_groups(pid: u32) -> Vec<u32> {
    #[cfg(not(target_os = "macos"))]
    {
        let path = format!("/proc/{pid}/task/{pid}/status");
        let file = File::open(path).unwrap();
        for line in BufReader::new(file).lines() {
            let line = line.unwrap();
            if line.starts_with("Groups:") {
                return line["Groups: ".len()..]
                    .split(' ')
                    .filter(|x| !x.trim().is_empty())
                    .map(|x| x.parse::<u32>().unwrap())
                    .collect();
            }
        }
    }

    vec![]
}

pub fn fuse_allow_other_enabled() -> io::Result<bool> {
    let file = File::open("/etc/fuse.conf")?;
    for line in BufReader::new(file).lines() {
        if line?.trim_start().starts_with("user_allow_other") {
            return Ok(true);
        }
    }
    Ok(false)
}
