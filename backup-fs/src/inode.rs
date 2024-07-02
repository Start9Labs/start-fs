use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::raw::c_int;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20::cipher::Iv;
use chacha20::ChaCha20;
use fuser::{Request, TimeOrNow};
use log::debug;
use serde::{Deserialize, Serialize};

use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::ctrl::{self, Controller, Exists, Load, Save};
use crate::directory::DirectoryContents;
use crate::get_groups;
use crate::handle::Handler;
use crate::serde::{load, save};

pub const BLOCK_SIZE: u64 = 512;

pub struct EncryptedInode {
    iv: Iv<ChaCha20>,
    attr: InodeAttributes,
}

pub type Inode = u64;

pub type DirectoryDescriptor = BTreeMap<Vec<u8>, (Inode, FileKind)>;

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq)]
pub enum FileKind {
    File,
    Directory,
    Symlink,
}

impl From<FileKind> for fuser::FileType {
    fn from(kind: FileKind) -> Self {
        match kind {
            FileKind::File => fuser::FileType::RegularFile,
            FileKind::Directory => fuser::FileType::Directory,
            FileKind::Symlink => fuser::FileType::Symlink,
        }
    }
}

#[derive(Debug)]
enum XattrNamespace {
    Security,
    System,
    Trusted,
    User,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InodeAttributes {
    pub inode: Inode,
    pub size: u64,
    pub crtime: (i64, u32),
    pub atime: (i64, u32),
    pub mtime: (i64, u32),
    pub ctime: (i64, u32),
    pub kind: FileKind,
    // Permissions and special mode bits
    pub mode: u16,
    pub hardlinks: u32,
    pub uid: u32,
    pub gid: u32,
    pub xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

fn system_time_from_time(secs: i64, nsecs: u32) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs)
    } else {
        UNIX_EPOCH - Duration::new((-secs) as u64, nsecs)
    }
}

pub fn time_now() -> (i64, u32) {
    time_from_system_time(&SystemTime::now())
}

pub fn time_from_system_time(system_time: &SystemTime) -> (i64, u32) {
    // Convert to signed 64-bit time with epoch at 0
    match system_time.duration_since(UNIX_EPOCH) {
        Ok(duration) => (duration.as_secs() as i64, duration.subsec_nanos()),
        Err(before_epoch_error) => (
            -(before_epoch_error.duration().as_secs() as i64),
            before_epoch_error.duration().subsec_nanos(),
        ),
    }
}

impl From<InodeAttributes> for fuser::FileAttr {
    fn from(attrs: InodeAttributes) -> Self {
        fuser::FileAttr {
            ino: attrs.inode,
            size: attrs.size,
            blocks: (attrs.size + BLOCK_SIZE - 1) / BLOCK_SIZE,
            atime: system_time_from_time(attrs.atime.0, attrs.atime.1),
            mtime: system_time_from_time(attrs.mtime.0, attrs.mtime.1),
            ctime: system_time_from_time(attrs.ctime.0, attrs.ctime.1),
            crtime: system_time_from_time(attrs.crtime.0, attrs.crtime.1),
            kind: attrs.kind.into(),
            perm: attrs.mode,
            nlink: attrs.hardlinks,
            uid: attrs.uid,
            gid: attrs.gid,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        }
    }
}

fn parse_xattr_namespace(key: &[u8]) -> Result<XattrNamespace, c_int> {
    let user = b"user.";
    if key.len() < user.len() {
        return Err(libc::ENOTSUP);
    }
    if key[..user.len()].eq(user) {
        return Ok(XattrNamespace::User);
    }

    let system = b"system.";
    if key.len() < system.len() {
        return Err(libc::ENOTSUP);
    }
    if key[..system.len()].eq(system) {
        return Ok(XattrNamespace::System);
    }

    let trusted = b"trusted.";
    if key.len() < trusted.len() {
        return Err(libc::ENOTSUP);
    }
    if key[..trusted.len()].eq(trusted) {
        return Ok(XattrNamespace::Trusted);
    }

    let security = b"security";
    if key.len() < security.len() {
        return Err(libc::ENOTSUP);
    }
    if key[..security.len()].eq(security) {
        return Ok(XattrNamespace::Security);
    }

    return Err(libc::ENOTSUP);
}

impl<'a> Save for &'a InodeAttributes {
    fn save(self, ctrl: &Controller) -> io::Result<()> {
        save(
            self,
            EncryptedFile::create(AtomicFile::create(ctrl.inode_path(self.inode))?, ctrl.key())?,
        )
    }
}

impl Load for InodeAttributes {
    type Args<'a> = Inode;
    fn load(ctrl: &Controller, args: Self::Args<'_>) -> io::Result<Self> {
        load(EncryptedFile::open(
            File::open(&ctrl.inode_path(args))?,
            ctrl.key(),
        )?)
    }
}

impl Exists for InodeAttributes {
    fn exists(ctrl: &Controller, args: Self::Args<'_>) -> bool {
        ctrl.inode_path(args).exists()
    }
}

impl InodeAttributes {
    pub fn new(inode: Inode, kind: FileKind) -> Self {
        let now = time_now();
        Self {
            inode,
            size: 0,
            crtime: now,
            atime: now,
            mtime: now,
            ctime: now,
            kind,
            mode: 0o777,
            hardlinks: if kind == FileKind::Directory { 2 } else { 1 },
            uid: 0,
            gid: 0,
            xattrs: Default::default(),
        }
    }
    pub fn setattr(
        &mut self,
        handler: &mut Handler,
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
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
    ) -> io::Result<bool> {
        let mut changed = false;
        let mut now_cell = None;
        let mut lazy_now = || *now_cell.get_or_insert(time_now());

        if let Some(mode) = mode {
            debug!("chmod() called with {:?}, {:o}", inode, mode);
            if req.uid() != 0 && req.uid() != self.uid {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            if req.uid() != 0 && req.gid() != self.gid && !get_groups(req.pid()).contains(&self.gid)
            {
                // If SGID is set and the file belongs to a group that the caller is not part of
                // then the SGID bit is suppose to be cleared during chmod
                self.mode = (mode & !libc::S_ISGID as u32) as u16;
            } else {
                self.mode = mode as u16;
            }
            changed = true;
        }

        if uid.is_some() || gid.is_some() {
            debug!("chown() called with {:?} {:?} {:?}", inode, uid, gid);
            if let Some(gid) = gid {
                // Non-root users can only change gid to a group they're in
                if req.uid() != 0 && !get_groups(req.pid()).contains(&gid) {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
            }
            if let Some(uid) = uid {
                if req.uid() != 0
                        // but no-op changes by the owner are not an error
                        && !(uid == self.uid && req.uid() == self.uid)
                {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
            }
            // Only owner may change the group
            if gid.is_some() && req.uid() != 0 && req.uid() != self.uid {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }

            if self.mode & (libc::S_IXUSR | libc::S_IXGRP | libc::S_IXOTH) as u16 != 0 {
                // SUID & SGID are suppose to be cleared when chown'ing an executable file
                self.clear_suid_sgid();
            }

            if let Some(uid) = uid {
                self.uid = uid;
                // Clear SETUID on owner change
                self.mode &= !libc::S_ISUID as u16;
            }
            if let Some(gid) = gid {
                self.gid = gid;
                // Clear SETGID unless user is root
                if req.uid() != 0 {
                    self.mode &= !libc::S_ISGID as u16;
                }
            }
            changed = true;
        }

        if let Some(size) = size {
            debug!("truncate() called with {:?} {:?}", inode, size);
            if let Some(fh) = fh {
                // If the file handle is available, check access locally.
                // This is important as it preserves the semantic that a file handle opened
                // with W_OK will never fail to truncate, even if the file has been subsequently
                // chmod'ed
                if !handler
                    .handle(fh)
                    .ok_or(libc::EACCES)
                    .map_err(io::Error::from_raw_os_error)?
                    .write
                {
                    return Err(io::Error::from_raw_os_error(libc::EACCES));
                }
            } else {
                if !self.check_access(req.uid(), req.gid(), libc::W_OK) {
                    return Err(io::Error::from_raw_os_error(libc::EACCES));
                }
            }
            self.size = size;
            changed = true;
        }

        if let Some(atime) = atime {
            debug!("utimens() called with {:?}, atime={:?}", inode, atime);

            if self.uid != req.uid() && req.uid() != 0 && atime != TimeOrNow::Now {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }

            if self.uid != req.uid() && !self.check_access(req.uid(), req.gid(), libc::W_OK) {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }

            self.atime = match atime {
                TimeOrNow::SpecificTime(time) => time_from_system_time(&time),
                TimeOrNow::Now => lazy_now(),
            };
            changed = true;
        }

        if let Some(mtime) = mtime {
            debug!("utimens() called with {:?}, mtime={:?}", inode, mtime);

            if self.uid != req.uid() && req.uid() != 0 && mtime != TimeOrNow::Now {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }

            if self.uid != req.uid() && !self.check_access(req.uid(), req.gid(), libc::W_OK) {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }

            self.mtime = match mtime {
                TimeOrNow::SpecificTime(time) => time_from_system_time(&time),
                TimeOrNow::Now => lazy_now(),
            };
            changed = true;
        }

        if let Some(ctime) = ctime {
            debug!("utimens() called with {:?}, ctime={:?}", inode, ctime);

            if self.uid != req.uid() && req.uid() != 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }

            self.ctime = time_from_system_time(&ctime);
            changed = true;
        }

        if let Some(crtime) = crtime {
            debug!("utimens() called with {:?}, crtime={:?}", inode, crtime);

            if self.uid != req.uid() && req.uid() != 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }

            self.crtime = time_from_system_time(&crtime);
            changed = true;
        }

        if changed && ctime.is_none() {
            self.ctime = lazy_now();
        }

        Ok(changed)
    }

    pub fn lookup(&self, ctrl: &Controller, name: &OsStr) -> io::Result<Inode> {
        if self.kind != FileKind::Directory {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }

        let contents = ctrl.load::<DirectoryContents>(self.inode)?;
        let (inode, _) = contents
            .get(name)
            .ok_or(libc::ENOENT)
            .map_err(io::Error::from_raw_os_error)?;
        Ok(inode)
    }

    pub fn check_access(&self, uid: u32, gid: u32, mut access_mask: i32) -> bool {
        // F_OK tests for existence of file
        if access_mask == libc::F_OK {
            return true;
        }
        let file_mode = i32::from(self.mode);

        // root is allowed to read & write anything
        if uid == 0 {
            // root only allowed to exec if one of the X bits is set
            access_mask &= libc::X_OK;
            access_mask -= access_mask & (file_mode >> 6);
            access_mask -= access_mask & (file_mode >> 3);
            access_mask -= access_mask & file_mode;
            return access_mask == 0;
        }

        if uid == self.uid {
            access_mask -= access_mask & (file_mode >> 6);
        } else if gid == self.gid {
            access_mask -= access_mask & (file_mode >> 3);
        } else {
            access_mask -= access_mask & file_mode;
        }

        return access_mask == 0;
    }

    pub fn clear_suid_sgid(&mut self) {
        self.mode &= !libc::S_ISUID as u16;
        // SGID is only suppose to be cleared if XGRP is set
        if self.mode & libc::S_IXGRP as u16 != 0 {
            self.mode &= !libc::S_ISGID as u16;
        }
    }

    pub fn creation_gid(&self, gid: u32) -> u32 {
        if self.mode & libc::S_ISGID as u16 != 0 {
            return self.gid;
        }

        gid
    }

    pub fn xattr_access_check(
        &self,
        key: &[u8],
        access_mask: i32,
        request: &Request<'_>,
    ) -> Result<(), c_int> {
        match parse_xattr_namespace(key)? {
            XattrNamespace::Security => {
                if access_mask != libc::R_OK && request.uid() != 0 {
                    return Err(libc::EPERM);
                }
            }
            XattrNamespace::Trusted => {
                if request.uid() != 0 {
                    return Err(libc::EPERM);
                }
            }
            XattrNamespace::System => {
                if key.eq(b"system.posix_acl_access") {
                    if !self.check_access(request.uid(), request.gid(), access_mask) {
                        return Err(libc::EPERM);
                    }
                } else if request.uid() != 0 {
                    return Err(libc::EPERM);
                }
            }
            XattrNamespace::User => {
                if !self.check_access(request.uid(), request.gid(), access_mask) {
                    return Err(libc::EPERM);
                }
            }
        }

        Ok(())
    }

    pub fn modified(&mut self) {
        let now = time_now();
        self.mtime = now;
        self.ctime = now;
    }

    pub fn changed(&mut self) {
        self.ctime = time_now();
    }
}
