#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)] // libc::S_* are u16 or u32 depending on the platform

use chacha20::cipher::{IvSizeUser, KeySizeUser};
use chacha20::ChaCha20;
use fd_lock_rs::{FdLock, LockType};
use fuser::consts::FUSE_HANDLE_KILLPRIV;
use fuser::{
    Filesystem, KernelConfig, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyDirectoryPlus, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr,
    Request, TimeOrNow, FUSE_ROOT_ID,
};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::num::ParseIntError;
use std::os::raw::c_int;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};
use typenum::ToInt;
use zeroize::Zeroizing;

use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::ctrl::{Controller, StatFs};
use crate::directory::DirectoryContents;
use crate::error::{BkfsError, BkfsResult};
use crate::handle::{FileHandleId, Handler};
use crate::inode::FileData;
use crate::inode::BLOCK_SIZE;
use crate::inode::{Inode, InodeAttributes};
use crate::serde::load;
use crate::serde::save;

mod atomic_file;
mod contents;
mod ctrl;
mod directory;
pub mod error;
mod handle;
mod inode;
mod serde;
#[cfg(test)]
mod tests;
mod util;

pub const MAX_NAME_LENGTH: u32 = 255;
// const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024 * 1024;
pub const ENTRY_TTL: Duration = Duration::new(3600, 0);

const FMODE_EXEC: i32 = 0x20;

#[cfg_attr(feature = "cli", derive(clap::Parser))]
pub struct BackupFSOptions {
    pub data_dir: PathBuf,
    #[cfg_attr(feature = "cli", arg(long))]
    pub setuid_support: bool,
    #[cfg_attr(feature = "cli", arg(long))]
    pub password: String,
    #[cfg_attr(feature = "cli", arg(long))]
    pub file_size_padding: Option<f64>,
    #[cfg_attr(feature = "cli", arg(short, long))]
    pub readonly: bool,
    #[cfg_attr(feature = "cli", arg(long))]
    pub idmapped_root: Vec<IdMappedRoot>,
}

#[derive(Debug, Clone, Copy)]
pub struct IdMappedRoot {
    root_uid: u32,
    range: u32,
}
impl IdMappedRoot {
    pub fn is_root_for(&self, uid: u32, uids: impl IntoIterator<Item = u32>) -> bool {
        self.root_uid == uid
            && uids
                .into_iter()
                .all(|uid| uid >= self.root_uid && uid < self.root_uid + self.range)
    }
}
impl FromStr for IdMappedRoot {
    type Err = BkfsError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (root_uid, range) = s
            .split_once(":")
            .map(|(uid, range)| Ok::<(u32, u32), ParseIntError>((uid.parse()?, range.parse()?)))
            .ok_or_else(|| BkfsError::wrap(io::Error::other("invalid idmap")))?
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(Self { root_uid, range })
    }
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
    pub contents_iv: [u8; CHACHA_IV_SIZE],
}
impl CryptInfo {
    pub fn new() -> Self {
        Self {
            key: Zeroizing::new(rand::random()),
            inode_iv: rand::random(),
            contents_iv: rand::random(),
        }
    }
    pub fn load(path: &Path, password: &str) -> BkfsResult<Self> {
        load(EncryptedFile::open_pbkdf2(File::open(path)?, password)?)
    }
    pub fn save(&self, path: PathBuf, password: &str) -> BkfsResult<()> {
        save(
            self,
            EncryptedFile::create_pbkdf2(AtomicFile::create(path)?, password)?,
        )
    }
}

impl BackupFS {
    pub fn new(config: BackupFSOptions) -> BkfsResult<BackupFS> {
        let BackupFSOptions { data_dir, .. } = &config;
        let lock = fd_lock_rs::FdLock::lock(
            File::create(data_dir.join(".lock"))?,
            LockType::Exclusive,
            false,
        )
        .map_err(io::Error::from)?;

        let ctrl = Controller::new(config)?;

        if !ctrl.exists::<InodeAttributes>(Inode(FUSE_ROOT_ID)) {
            // Initialize with empty filesystem
            let root = InodeAttributes::new(
                Inode(FUSE_ROOT_ID),
                None,
                FileData::Directory(DirectoryContents::new()),
            );
            ctrl.save(&root)?;
        } else {
            ctrl.load::<InodeAttributes>(Inode(FUSE_ROOT_ID))?;
        }

        ctrl.load_inode_pool()?;

        Ok(BackupFS {
            lock,
            handler: Handler::new(ctrl),
        })
    }

    pub fn fsck(&mut self) -> BkfsResult<()> {
        self.handler.ctrl().fsck(false)
    }

    pub fn change_password(&mut self, password: &str) -> BkfsResult<()> {
        self.handler.ctrl().change_password(password)
    }
}

impl Filesystem for BackupFS {
    fn init(&mut self, _req: &Request, config: &mut KernelConfig) -> Result<(), c_int> {
        config.add_capabilities(FUSE_HANDLE_KILLPRIV).unwrap();

        log::info!("filesystem initialized");

        Ok(())
    }

    fn destroy(&mut self) {
        if let Err(e) = self.handler.close_all() {
            error!("error closing FS: {e}");
        }
    }

    fn lookup(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match self.handler.lookup(req, Inode(parent), name) {
            Ok(inode) => reply.entry(&ENTRY_TTL, &(&inode).into(), 0),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn forget(&mut self, _req: &Request, _inode: u64, _nlookup: u64) {}

    fn getattr(&mut self, _req: &Request<'_>, inode: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self
            .handler
            .mutate_inode(Inode(inode), |_, inode| Ok((&*inode).into()))
        {
            Ok(attr) => reply.attr(&ENTRY_TTL, &attr),
            Err(e) => reply.error(e.to_errno_log()),
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
            req,
            Inode(inode),
            mode,
            uid,
            gid,
            size,
            atime,
            mtime,
            ctime,
            fh.map(FileHandleId),
            crtime,
            chgtime,
            bkuptime,
            flags,
        ) {
            Ok(inode) => reply.attr(&ENTRY_TTL, &(&inode).into()),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn readlink(&mut self, req: &Request, inode: u64, reply: ReplyData) {
        match self.handler.readlink(req, Inode(inode)) {
            Ok(path) => reply.data(path.as_os_str().as_bytes()),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn mknod(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        rdev: u32,
        reply: ReplyEntry,
    ) {
        match self.handler.mknod(
            req,
            Inode(parent),
            name,
            mode,
            umask,
            rdev,
            None::<fn(Inode) -> FileData>,
        ) {
            Ok(inode) => reply.entry(&ENTRY_TTL, &(&inode).into(), 0),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn mkdir(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        self.mknod(req, parent, name, mode | libc::S_IFDIR, umask, 0, reply)
    }

    fn unlink(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.handler.unlink(req, Inode(parent), name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn rmdir(&mut self, req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.handler.unlink(req, Inode(parent), name) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn symlink(
        &mut self,
        req: &Request,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        match self.handler.mknod(
            req,
            Inode(parent),
            link_name,
            libc::S_IFLNK | 0o777,
            0,
            0,
            Some(|_| FileData::Symlink(target.to_owned())),
        ) {
            Ok(inode) => reply.entry(&ENTRY_TTL, &(&inode).into(), 0),
            Err(e) => reply.error(e.to_errno_log()),
        }
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
        match self.handler.rename(
            req,
            Inode(parent),
            name,
            Inode(new_parent),
            new_name,
            flags & libc::RENAME_EXCHANGE != 0,
        ) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno_log()),
        }
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
        match self
            .handler
            .link(req, Inode(inode), Inode(new_parent), new_name, None)
        {
            Ok(inode) => reply.entry(&ENTRY_TTL, &(&inode).into(), 0),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn open(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {
        debug!("open() called for {:?}", inode);
        match self.handler.open(req, Inode(inode), flags) {
            Ok(FileHandleId(fh)) => reply.opened(fh, 0),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn read(
        &mut self,
        req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        size: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        debug!(
            "read() called on {:?} offset={:?} size={:?}",
            inode, offset, size
        );
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        match self.handler.read(
            req,
            Inode(inode),
            FileHandleId(fh),
            offset as u64,
            size as usize,
            flags,
            lock_owner,
        ) {
            Ok(buf) => reply.data(&buf),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn write(
        &mut self,
        req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        write_flags: u32,
        flags: i32,
        lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        match self.handler.write(
            req,
            Inode(inode),
            FileHandleId(fh),
            offset as u64,
            data,
            write_flags,
            flags,
            lock_owner,
        ) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn flush(
        &mut self,
        _req: &Request,
        _inode: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        reply.ok()
    }

    fn release(
        &mut self,
        _req: &Request,
        _inode: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        match self.handler.fclose(FileHandleId(fh)) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn fsync(&mut self, req: &Request, inode: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        match self
            .handler
            .fsync(req, Inode(inode), FileHandleId(fh), datasync)
        {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn opendir(&mut self, req: &Request, inode: u64, flags: i32, reply: ReplyOpen) {
        debug!("opendir() called on {:?}", inode);
        match self.handler.opendir(req, Inode(inode), flags) {
            Ok(FileHandleId(fh)) => reply.opened(fh, 0),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn readdir(
        &mut self,
        req: &Request,
        inode: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        match self.handler.readdir(
            req,
            Inode(inode),
            FileHandleId(fh),
            offset,
            |_, name, entry, offset| Ok(reply.add(entry.inode.0, offset, entry.ty, name)),
        ) {
            Ok(done) => {
                if done {
                    // todo!();
                }
                reply.ok()
            }
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn readdirplus(
        &mut self,
        req: &Request<'_>,
        inode: u64,
        fh: u64,
        offset: i64,
        mut reply: ReplyDirectoryPlus,
    ) {
        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        match self.handler.readdir(
            req,
            Inode(inode),
            FileHandleId(fh),
            offset,
            |handler, name, entry, offset| {
                handler.mutate_inode(entry.inode, |_, inode| {
                    Ok(reply.add(
                        inode.inode.0,
                        offset,
                        name,
                        &ENTRY_TTL,
                        &(&*inode).into(),
                        0,
                    ))
                })
            },
        ) {
            Ok(done) => {
                if done {
                    // todo!();
                }
                reply.ok()
            }
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn releasedir(
        &mut self,
        req: &Request<'_>,
        inode: u64,
        fh: u64,
        flags: i32,
        reply: ReplyEmpty,
    ) {
        match self
            .handler
            .releasedir(req, Inode(inode), FileHandleId(fh), flags)
        {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn fsyncdir(
        &mut self,
        _req: &Request,
        _inode: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        reply.ok(); // directories are synced on write
    }

    fn statfs(&mut self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        let StatFs { files, ffree } = self.handler.ctrl().statfs();
        // TODO: real implementation of this
        reply.statfs(
            10_000,
            10_000,
            10_000,
            files,
            ffree,
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
        match self
            .handler
            .setxattr(request, Inode(inode), key.as_bytes(), value)
        {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e.to_errno_log()),
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
        match self.handler.getxattr(request, Inode(inode), key.as_bytes()) {
            Ok(data) => {
                if size == 0 {
                    reply.size(data.len() as u32);
                } else if data.len() <= size as usize {
                    reply.data(&data);
                } else {
                    reply.error(libc::ERANGE)
                }
            }
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn listxattr(&mut self, request: &Request<'_>, inode: u64, size: u32, reply: ReplyXattr) {
        match self.handler.listxattr(request, Inode(inode)) {
            Ok(attrs) => {
                let mut bytes = vec![];
                // Convert to concatenated null-terminated strings
                for (key, _) in attrs {
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
            }
            Err(_) => reply.error(libc::EBADF),
        }
    }

    fn removexattr(&mut self, request: &Request<'_>, inode: u64, key: &OsStr, reply: ReplyEmpty) {
        match self
            .handler
            .removexattr(request, Inode(inode), key.as_bytes())
        {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn access(&mut self, req: &Request, inode: u64, mask: i32, reply: ReplyEmpty) {
        match self
            .handler
            .ctrl()
            .load::<InodeAttributes>(Inode(inode))
            .and_then(|inode| {
                inode.attrs.check_access(
                    &self.handler.ctrl().config().idmapped_root,
                    req.uid(),
                    req.gid(),
                    mask,
                )
            }) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e.to_errno()),
        }
    }

    fn create(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        match self
            .handler
            .create(req, Inode(parent), name, mode, umask, flags)
        {
            Ok((attrs, handle)) => {
                reply.created(&Duration::new(0, 0), &(&attrs).into(), 0, handle.0, 0)
            }
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    #[cfg(target_os = "linux")]
    fn fallocate(
        &mut self,
        req: &Request<'_>,
        inode: u64,
        fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        if offset < 0 || length < 0 {
            reply.error(libc::EINVAL);
            return;
        }
        match self.handler.fallocate(
            req,
            Inode(inode),
            FileHandleId(fh),
            offset as u64,
            length as u64,
            mode,
        ) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }

    fn copy_file_range(
        &mut self,
        req: &Request<'_>,
        src_inode: u64,
        src_fh: u64,
        src_offset: i64,
        dest_inode: u64,
        dest_fh: u64,
        dest_offset: i64,
        size: u64,
        flags: u32,
        reply: ReplyWrite,
    ) {
        match self.handler.copy_file_range(
            req,
            Inode(src_inode),
            FileHandleId(src_fh),
            src_offset as u64,
            Inode(dest_inode),
            FileHandleId(dest_fh),
            dest_offset as u64,
            size as usize,
            flags,
        ) {
            Ok(len) => reply.written(len as u32),
            Err(e) => reply.error(e.to_errno_log()),
        }
    }
}

/*
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
*/

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

pub fn fuse_allow_other_enabled() -> BkfsResult<bool> {
    let file = File::open("/etc/fuse.conf")?;
    for line in BufReader::new(file).lines() {
        if line?.trim_start().starts_with("user_allow_other") {
            return Ok(true);
        }
    }
    Ok(false)
}
