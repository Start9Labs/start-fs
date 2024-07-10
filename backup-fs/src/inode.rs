use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{Request, TimeOrNow, FUSE_ROOT_ID};
use imbl::{OrdMap, OrdSet};
use log::debug;
use serde::{Deserialize, Serialize};

use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::ctrl::{Controller, Exists, Load, Save};
use crate::directory::DirectoryContents;
use crate::error::{BkfsError, BkfsResult, BkfsResultExt};
use crate::get_groups;
use crate::handle::{FileHandleId, Handler};
use crate::serde::{load, save};

pub const BLOCK_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct Inode(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct ContentId(pub u64);

impl From<Inode> for ContentId {
    fn from(value: Inode) -> Self {
        Self(value.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FileData {
    File(ContentId),
    Directory(DirectoryContents),
    Symlink(PathBuf),
}
impl FileData {
    fn nlink(&self) -> usize {
        if let Self::Directory(c) = self {
            c.nlink()
        } else {
            0
        }
    }
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Directory(_))
    }
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }
}

impl From<&FileData> for fuser::FileType {
    fn from(kind: &FileData) -> Self {
        match kind {
            FileData::File(_) => fuser::FileType::RegularFile,
            FileData::Directory(_) => fuser::FileType::Directory,
            FileData::Symlink(_) => fuser::FileType::Symlink,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attributes {
    pub size: u64,
    pub crtime: (i64, u32),
    pub atime: (i64, u32),
    pub mtime: (i64, u32),
    pub ctime: (i64, u32),
    pub contents: FileData,
    // Permissions and special mode bits
    pub mode: u16,
    pub parents: OrdSet<(Inode, OsString)>,
    pub uid: u32,
    pub gid: u32,
    pub xattrs: OrdMap<Vec<u8>, Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct InodeAttributes {
    pub inode: Inode,
    pub attrs: Attributes,
}

impl InodeAttributes {
    pub fn new(inode: Inode, parent: Option<(Inode, OsString)>, contents: FileData) -> Self {
        let now = time_now();
        Self {
            inode,
            attrs: Attributes {
                size: 0,
                crtime: now,
                atime: now,
                mtime: now,
                ctime: now,
                contents,
                mode: 0o777,
                parents: parent.into_iter().collect(),
                uid: 0,
                gid: 0,
                xattrs: Default::default(),
            },
        }
    }

    pub fn lookup(&self, name: &OsStr) -> BkfsResult<Inode> {
        let FileData::Directory(dir) = &self.attrs.contents else {
            return BkfsResult::errno(libc::ENOTDIR);
        };

        if name == OsStr::new(".") {
            return Ok(self.inode);
        } else if name == OsStr::new("..") {
            return Ok(self
                .attrs
                .parents
                .get_min()
                .map(|(p, _)| *p)
                .unwrap_or(self.inode));
        }

        match dir.get(name) {
            Some(inode) => Ok(inode.inode),
            None => BkfsResult::errno_notrace(libc::ENOENT),
        }
    }
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

impl From<&InodeAttributes> for fuser::FileAttr {
    fn from(InodeAttributes { inode, attrs, .. }: &InodeAttributes) -> Self {
        fuser::FileAttr {
            ino: inode.0,
            size: attrs.size,
            blocks: (attrs.size + BLOCK_SIZE - 1) / BLOCK_SIZE,
            atime: system_time_from_time(attrs.atime.0, attrs.atime.1),
            mtime: system_time_from_time(attrs.mtime.0, attrs.mtime.1),
            ctime: system_time_from_time(attrs.ctime.0, attrs.ctime.1),
            crtime: system_time_from_time(attrs.crtime.0, attrs.crtime.1),
            kind: (&attrs.contents).into(),
            perm: attrs.mode,
            nlink: if inode.0 == FUSE_ROOT_ID {
                2
            } else {
                (attrs.parents.len() + attrs.contents.nlink()) as u32
            },
            uid: attrs.uid,
            gid: attrs.gid,
            rdev: 0,
            blksize: BLOCK_SIZE as u32,
            flags: 0,
        }
    }
}

fn parse_xattr_namespace(key: &[u8]) -> BkfsResult<XattrNamespace> {
    let user = b"user.";
    if key.len() < user.len() {
        return BkfsResult::errno(libc::ENOTSUP);
    }
    if key[..user.len()].eq(user) {
        return Ok(XattrNamespace::User);
    }

    let system = b"system.";
    if key.len() < system.len() {
        return BkfsResult::errno(libc::ENOTSUP);
    }
    if key[..system.len()].eq(system) {
        return Ok(XattrNamespace::System);
    }

    let trusted = b"trusted.";
    if key.len() < trusted.len() {
        return BkfsResult::errno(libc::ENOTSUP);
    }
    if key[..trusted.len()].eq(trusted) {
        return Ok(XattrNamespace::Trusted);
    }

    let security = b"security";
    if key.len() < security.len() {
        return BkfsResult::errno(libc::ENOTSUP);
    }
    if key[..security.len()].eq(security) {
        return Ok(XattrNamespace::Security);
    }

    return BkfsResult::errno(libc::ENOTSUP);
}

impl<'a> Save for &'a InodeAttributes {
    fn save(self, ctrl: &Controller) -> BkfsResult<()> {
        save(
            &self.attrs,
            EncryptedFile::create(AtomicFile::create(ctrl.inode_path(self.inode))?, ctrl.key())?,
        )
    }
}

impl Load for InodeAttributes {
    type Args<'a> = Inode;
    fn load(ctrl: &Controller, inode: Self::Args<'_>) -> BkfsResult<Self> {
        Ok(InodeAttributes {
            inode,
            attrs: load(EncryptedFile::open(
                File::open(&ctrl.inode_path(inode))?,
                ctrl.key(),
            )?)?,
        })
    }
}

impl Exists for InodeAttributes {
    fn exists(ctrl: &Controller, inode: Self::Args<'_>) -> bool {
        ctrl.inode_path(inode).exists()
    }
}

impl Attributes {
    pub fn setattr(
        &mut self,
        handler: &mut Handler,
        req: &Request,
        inode: Inode,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        fh: Option<FileHandleId>,
        crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
    ) -> BkfsResult<bool> {
        let mut changed = false;
        let mut now_cell = None;
        let mut lazy_now = || *now_cell.get_or_insert(time_now());

        if let Some(mode) = mode {
            debug!("chmod() called with {:?}, {:o}", inode, mode);
            if req.uid() != 0 && req.uid() != self.uid {
                return BkfsResult::errno(libc::EPERM);
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
                    return BkfsResult::errno(libc::EPERM);
                }
            }
            if let Some(uid) = uid {
                if req.uid() != 0
                        // but no-op changes by the owner are not an error
                        && !(uid == self.uid && req.uid() == self.uid)
                {
                    return BkfsResult::errno(libc::EPERM);
                }
            }
            // Only owner may change the group
            if gid.is_some() && req.uid() != 0 && req.uid() != self.uid {
                return BkfsResult::errno(libc::EPERM);
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
                    return BkfsResult::errno(libc::EACCES);
                }
            } else {
                self.check_access(req.uid(), req.gid(), libc::W_OK)?;
            }
            self.size = size;
            changed = true;
        }

        if let Some(atime) = atime {
            debug!("utimens() called with {:?}, atime={:?}", inode, atime);

            if self.uid != req.uid() && req.uid() != 0 && atime != TimeOrNow::Now {
                return BkfsResult::errno(libc::EPERM);
            }

            if self.uid != req.uid() {
                self.check_access(req.uid(), req.gid(), libc::W_OK)?;
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
                return BkfsResult::errno(libc::EPERM);
            }

            if self.uid != req.uid() {
                self.check_access(req.uid(), req.gid(), libc::W_OK)?;
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
                return BkfsResult::errno(libc::EPERM);
            }

            self.ctime = time_from_system_time(&ctime);
            changed = true;
        }

        if let Some(crtime) = crtime {
            debug!("utimens() called with {:?}, crtime={:?}", inode, crtime);

            if self.uid != req.uid() && req.uid() != 0 {
                return BkfsResult::errno(libc::EPERM);
            }

            self.crtime = time_from_system_time(&crtime);
            changed = true;
        }

        if changed && ctime.is_none() {
            self.ctime = lazy_now();
        }

        Ok(changed)
    }

    pub fn check_access(&self, uid: u32, gid: u32, mut access_mask: i32) -> BkfsResult<()> {
        // F_OK tests for existence of file
        if access_mask == libc::F_OK {
            return Ok(());
        }
        let file_mode = i32::from(self.mode);

        // root is allowed to read & write anything
        if uid == 0 {
            // root only allowed to exec if one of the X bits is set
            access_mask &= libc::X_OK;
            access_mask -= access_mask & (file_mode >> 6);
            access_mask -= access_mask & (file_mode >> 3);
            access_mask -= access_mask & file_mode;
            return if access_mask == 0 {
                Ok(())
            } else {
                BkfsResult::errno(libc::EACCES)
            };
        }

        if uid == self.uid {
            access_mask -= access_mask & (file_mode >> 6);
        } else if gid == self.gid {
            access_mask -= access_mask & (file_mode >> 3);
        } else {
            access_mask -= access_mask & file_mode;
        }

        if access_mask == 0 {
            Ok(())
        } else {
            BkfsResult::errno(libc::EACCES)
        }
    }

    pub fn check_sticky(&self, child: &Self, uid: u32) -> BkfsResult<()> {
        if self.mode & libc::S_ISVTX as u16 != 0 && uid != 0 && uid != self.uid && uid != child.uid
        {
            BkfsResult::errno(libc::EACCES)
        } else {
            Ok(())
        }
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
    ) -> BkfsResult<()> {
        match parse_xattr_namespace(key)? {
            XattrNamespace::Security => {
                if access_mask != libc::R_OK && request.uid() != 0 {
                    return BkfsResult::errno(libc::EPERM);
                }
            }
            XattrNamespace::Trusted => {
                if request.uid() != 0 {
                    return BkfsResult::errno(libc::EPERM);
                }
            }
            XattrNamespace::System => {
                if key.eq(b"system.posix_acl_access") {
                    self.check_access(request.uid(), request.gid(), access_mask)
                        .map_err(|_| io::Error::from_raw_os_error(libc::EPERM))?;
                } else if request.uid() != 0 {
                    return BkfsResult::errno(libc::EPERM);
                }
            }
            XattrNamespace::User => {
                self.check_access(request.uid(), request.gid(), access_mask)
                    .map_err(|_| io::Error::from_raw_os_error(libc::EPERM))?;
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
