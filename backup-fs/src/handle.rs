use std::borrow::{Borrow, Cow};
use std::cell::RefCell;
use std::cmp::min;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::ops::{Bound, RangeFrom, RangeFull};
use std::path::PathBuf;
use std::rc::{Rc, Weak};
use std::time::SystemTime;

use fuser::consts::FUSE_WRITE_KILL_PRIV;
use fuser::{FileType, ReplyDirectory, Request, TimeOrNow};
use log::{debug, warn};

use crate::contents::{self, Contents};
use crate::ctrl::{Controller, Save};
use crate::directory::{DirectoryContents, DirectoryEntry};
use crate::inode::{Attributes, FileData, Inode, InodeAttributes};
use crate::{handle, FMODE_EXEC, MAX_NAME_LENGTH};

pub struct Handler {
    ctrl: Controller,
    next_fh: FileHandleId,
    inodes: BTreeMap<Inode, Weak<RefCell<Contents>>>,
    open_files: BTreeMap<FileHandleId, FileHandle>,
    open_dirs: BTreeMap<FileHandleId, DirHandle>,
}
impl Handler {
    pub fn new(ctrl: Controller) -> Self {
        Self {
            ctrl,
            next_fh: FileHandleId(1),
            inodes: BTreeMap::new(),
            open_files: BTreeMap::new(),
            open_dirs: BTreeMap::new(),
        }
    }
    pub fn ctrl(&self) -> &Controller {
        &self.ctrl
    }
    pub fn fopen(
        &mut self,
        inode: Inode,
        read: bool,
        write: bool,
        access: impl FnOnce(&InodeAttributes) -> io::Result<()>,
    ) -> io::Result<FileHandleId> {
        let contents = if let Some(contents) = self.inodes.get(&inode).and_then(Weak::upgrade) {
            contents
        } else {
            let contents = Rc::new(RefCell::new(Contents::open(self.ctrl.clone(), inode)?));
            self.inodes.insert(inode, Rc::downgrade(&contents));
            contents
        };
        access(&RefCell::borrow(&*contents).inode)?;
        let fh = self.next_fh;
        self.next_fh.0 += 1;
        self.open_files.insert(
            fh,
            FileHandle {
                inode,
                read,
                write,
                contents,
            },
        );
        Ok(fh)
    }
    pub fn handle(&self, fh: FileHandleId) -> Option<&FileHandle> {
        self.open_files.get(&fh)
    }
    pub fn fclose(&mut self, fh: FileHandleId) -> io::Result<()> {
        let Some(handle) = self.open_files.remove(&fh) else {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        };
        handle.close(self)?;
        Ok(())
    }

    fn creation_mode(&self, mode: u32) -> u16 {
        if !self.ctrl().config().setuid_support {
            (mode & !(libc::S_ISUID | libc::S_ISGID) as u32) as u16
        } else {
            mode as u16
        }
    }

    pub fn mutate_inode<F: FnOnce(&mut Self, &mut InodeAttributes) -> io::Result<T>, T>(
        &mut self,
        inode: Inode,
        f: F,
    ) -> io::Result<T> {
        if let Some(contents) = self.inodes.get(&inode).and_then(Weak::upgrade) {
            let mut contents = contents.borrow_mut();
            f(self, &mut contents.inode)
        } else {
            f(self, &mut self.ctrl().load::<InodeAttributes>(inode)?)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileHandleId(pub u64);

#[derive(Clone)]
pub struct FileHandle {
    pub inode: Inode,
    pub read: bool,
    pub write: bool,
    pub contents: Rc<RefCell<Contents>>,
}
impl FileHandle {
    pub fn close(self, handler: &mut Handler) -> io::Result<()> {
        if let Ok(contents) = Rc::try_unwrap(self.contents) {
            contents.into_inner().close(handler)?;
        }
        Ok(())
    }
}

pub struct DirHandle {
    pub inode: Inode,
    pub read: bool,
    pub cursors: BTreeMap<i64, OsString>,
}

pub struct OverwriteOptions {
    pub gc: bool,
}

impl Handler {
    pub fn close_all(&mut self) -> io::Result<()> {
        std::mem::take(&mut self.inodes);
        let mut errs = Vec::new();
        for (_, handle) in std::mem::take(&mut self.open_files) {
            if let Err(e) = handle.close(self) {
                errs.push(e);
            }
        }
        errs.into_iter().fold(Ok(()), |acc, x| match acc {
            Ok(()) => Err(x),
            Err(e) if e.kind() == x.kind() => Err(io::Error::new(e.kind(), format!("({e}) ({x})"))),
            Err(e) => Err(io::Error::other(format!(
                "({}: {e}) ({}: {x})",
                e.kind(),
                x.kind()
            ))),
        })
    }

    pub fn lookup(
        &mut self,
        req: &Request,
        parent: Inode,
        name: &OsStr,
    ) -> io::Result<InodeAttributes> {
        if name.len() > MAX_NAME_LENGTH as usize {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        let parent = self.ctrl().load::<InodeAttributes>(parent)?;
        parent
            .attrs
            .check_access(req.uid(), req.gid(), libc::X_OK)?;

        let inode = parent.lookup(name)?;
        self.mutate_inode(inode, |_, inode| {
            if !inode
                .attrs
                .parents
                .contains(&(parent.inode, name.to_owned()))
            {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            Ok(inode.clone())
        })
    }

    pub fn setattr(
        &mut self,
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
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<u32>,
    ) -> io::Result<InodeAttributes> {
        let (inode, changed) = self.mutate_inode(inode, |handler, inode| {
            let changed = inode.attrs.setattr(
                handler,
                req,
                inode.inode,
                mode,
                uid,
                gid,
                size,
                atime,
                mtime,
                ctime,
                fh,
                crtime,
                chgtime,
                bkuptime,
                flags,
            )?;
            Ok((inode.clone(), changed))
        })?;
        if changed {
            self.ctrl().save(&inode)?;
        }
        Ok(inode)
    }

    pub fn readlink(&mut self, req: &Request, inode: Inode) -> io::Result<PathBuf> {
        debug!("readlink() called on {:?}", inode);
        let inode = self.ctrl().load::<InodeAttributes>(inode)?;
        inode.attrs.check_access(req.uid(), req.gid(), libc::R_OK)?;
        let FileData::Symlink(p) = inode.attrs.contents else {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        };
        Ok(p)
    }

    pub fn mknod<F: FnOnce(Inode) -> FileData>(
        &mut self,
        req: &Request,
        parent: Inode,
        name: &OsStr,
        mut mode: u32,
        umask: u32,
        _rdev: u32,
        contents: Option<F>,
    ) -> io::Result<InodeAttributes> {
        let file_type = mode & libc::S_IFMT as u32;

        if file_type != libc::S_IFREG as u32
            && file_type != libc::S_IFLNK as u32
            && file_type != libc::S_IFDIR as u32
        {
            // TODO
            warn!("mknod() implementation is incomplete. Only supports regular files, symlinks, and directories. Got {:o}", mode);
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let mut parent = self.ctrl().load::<InodeAttributes>(parent)?;

        parent
            .attrs
            .check_access(req.uid(), req.gid(), libc::W_OK)?;

        let gid = parent.attrs.creation_gid(req.gid());

        let FileData::Directory(dir) = &mut parent.attrs.contents else {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        };

        if dir.get(name).is_some() {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }

        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }

        let inode = self.ctrl().next_inode()?;

        let contents = if let Some(contents) = contents {
            contents(inode)
        } else {
            let mode = mode & libc::S_IFMT as u32;

            if mode == libc::S_IFREG as u32 {
                FileData::File(inode.into())
            } else if mode == libc::S_IFLNK as u32 {
                FileData::Symlink(PathBuf::new())
            } else if mode == libc::S_IFDIR as u32 {
                FileData::Directory(DirectoryContents::new())
            } else {
                return Err(io::Error::from_raw_os_error(libc::ENOSYS));
            }
        };

        let mut new = InodeAttributes::new(inode, Some((parent.inode, name.to_owned())), contents);
        new.attrs.uid = req.uid();
        new.attrs.gid = gid;
        new.attrs.mode = self.creation_mode(mode & umask);

        dir.insert(
            name.to_owned(),
            DirectoryEntry {
                inode: new.inode,
                ty: (&new.attrs.contents).into(),
            },
        );

        self.ctrl().save(&new)?;

        self.ctrl().save(&parent)?;

        Ok(new)
    }

    pub fn gc_inode(&mut self, inode: &InodeAttributes) -> io::Result<bool> {
        if !inode.attrs.parents.is_empty() {
            return Ok(false);
        }
        if inode.attrs.contents.is_file()
            && self
                .inodes
                .get(&inode.inode)
                .filter(|rc| Weak::strong_count(rc) > 0)
                .is_some()
        {
            return Ok(false);
        }
        if inode.attrs.contents.is_dir() && self.open_dirs.values().any(|d| d.inode == inode.inode)
        {
            return Ok(false);
        }

        self.inodes.remove(&inode.inode);

        std::fs::remove_file(self.ctrl().inode_path(inode.inode))?;
        if let FileData::File(contents) = inode.attrs.contents {
            let path = self.ctrl().contents_path(contents);
            if path.exists() {
                std::fs::remove_file(path)?;
            }
        }

        Ok(true)
    }

    pub fn unlink(&mut self, req: &Request, parent: Inode, name: &OsStr) -> io::Result<()> {
        let mut parent = self.ctrl().load::<InodeAttributes>(parent)?;
        parent
            .attrs
            .check_access(req.uid(), req.gid(), libc::W_OK)?;

        let FileData::Directory(dir) = &mut parent.attrs.contents else {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        };

        let entry = dir
            .remove(name)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;

        self.mutate_inode(entry.inode, |handler, inode| {
            if let FileData::Directory(dir) = &inode.attrs.contents {
                if inode.attrs.parents.len() <= 1 && !dir.is_empty() {
                    return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));
                }
            }

            parent.attrs.check_sticky(&inode.attrs, req.uid())?;

            inode.attrs.parents.remove(&(parent.inode, name.to_owned()));

            handler.ctrl().save(&parent)?;
            if !handler.gc_inode(&*inode)? {
                handler.ctrl().save(&*inode)?;
            }

            Ok(())
        })
    }

    pub fn link(
        &mut self,
        req: &Request,
        inode: Inode,
        new_parent: Inode,
        new_name: &OsStr,
        overwrite: Option<OverwriteOptions>,
    ) -> io::Result<InodeAttributes> {
        self.mutate_inode(inode, |handler, inode| {
            let mut new_parent = handler.ctrl().load::<InodeAttributes>(new_parent)?;

            new_parent
                .attrs
                .check_access(req.uid(), req.gid(), libc::W_OK)?;

            let FileData::Directory(dir) = &mut new_parent.attrs.contents else {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
            };

            if let Some(inode) = dir.insert(
                new_name.to_owned(),
                DirectoryEntry {
                    inode: inode.inode,
                    ty: (&inode.attrs.contents).into(),
                },
            ) {
                if let Some(overwrite) = overwrite {
                    handler.mutate_inode(inode.inode, |handler, inode| {
                        inode
                            .attrs
                            .parents
                            .remove(&(new_parent.inode, new_name.to_owned()));
                        if !overwrite.gc || !handler.gc_inode(inode)? {
                            handler.ctrl().save(&*inode)?;
                        }
                        Ok(())
                    })?;
                } else {
                    return Err(io::Error::from_raw_os_error(libc::EEXIST));
                }
            }

            inode
                .attrs
                .parents
                .insert((new_parent.inode, new_name.to_owned()));

            handler.ctrl().save(&*inode)?;
            handler.ctrl().save(&new_parent)?;

            Ok(inode.clone())
        })
    }

    pub fn rename(
        &mut self,
        req: &Request,
        parent: Inode,
        name: &OsStr,
        new_parent: Inode,
        new_name: &OsStr,
        exchange: bool,
    ) -> io::Result<()> {
        let parent = self.ctrl().load::<InodeAttributes>(parent)?;

        parent
            .attrs
            .check_access(req.uid(), req.gid(), libc::W_OK)?;

        let inode = parent.lookup(name)?;

        if exchange {
            let new_parent = self.ctrl().load::<InodeAttributes>(new_parent)?;

            new_parent
                .attrs
                .check_access(req.uid(), req.gid(), libc::W_OK)?;

            let new_inode = new_parent.lookup(new_name)?;

            self.link(
                req,
                inode,
                new_parent.inode,
                new_name,
                Some(OverwriteOptions { gc: false }),
            )?;
            self.link(
                req,
                new_inode,
                parent.inode,
                name,
                Some(OverwriteOptions { gc: true }),
            )?;
        } else {
            self.link(
                req,
                inode,
                new_parent,
                new_name,
                Some(OverwriteOptions { gc: true }),
            )?;
            self.unlink(req, parent.inode, name)?;
        }

        Ok(())
    }

    pub fn open(&mut self, req: &Request, inode: Inode, flags: i32) -> io::Result<FileHandleId> {
        let (access_mask, read, write) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC != 0 {
                    return Err(io::Error::from_raw_os_error(libc::EACCES));
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
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
        };

        self.fopen(inode, read, write, |inode| {
            inode.attrs.check_access(req.uid(), req.gid(), access_mask)
        })
    }

    pub fn read(
        &mut self,
        _req: &Request,
        _inode: Inode,
        fh: FileHandleId,
        offset: u64,
        size: usize,
        _flags: i32,
        _lock_owner: Option<u64>,
    ) -> io::Result<Vec<u8>> {
        if offset < 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let fh = self
            .handle(fh)
            .ok_or(libc::EBADF)
            .map_err(io::Error::from_raw_os_error)?;
        if !fh.read {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }

        let mut contents = fh.contents.borrow_mut();

        let size = min(size, (contents.inode.attrs.size - offset) as usize);

        let mut buf = vec![0_u8; size];

        contents.read_exact_at(&mut buf, offset)?;

        Ok(buf)
    }

    pub fn write(
        &mut self,
        _req: &Request,
        _inode: Inode,
        fh: FileHandleId,
        offset: u64,
        data: &[u8],
        _write_flags: u32,
        flags: i32,
        _lock_owner: Option<u64>,
    ) -> io::Result<usize> {
        if offset < 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let fh = self
            .handle(fh)
            .ok_or(libc::EBADF)
            .map_err(io::Error::from_raw_os_error)?;
        if !fh.write {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }

        let mut contents = fh.contents.borrow_mut();

        let mut buf = data.to_vec();

        contents.write_all_at(&mut buf, offset)?;

        if flags & FUSE_WRITE_KILL_PRIV as i32 != 0 {
            contents.inode.attrs.clear_suid_sgid();
        }

        Ok(buf.len())
    }

    pub fn fsync(
        &mut self,
        _req: &Request,
        _inode: Inode,
        fh: FileHandleId,
        datasync: bool,
    ) -> io::Result<()> {
        let fh = self
            .handle(fh)
            .ok_or(libc::EBADF)
            .map_err(io::Error::from_raw_os_error)?;
        fh.contents.borrow_mut().fsync(datasync)?;
        Ok(())
    }

    pub fn opendir(&mut self, req: &Request, inode: Inode, flags: i32) -> io::Result<FileHandleId> {
        let inode = self.ctrl().load::<InodeAttributes>(inode)?;
        let (access_mask, read, _) = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => {
                // Behavior is undefined, but most filesystems return EACCES
                if flags & libc::O_TRUNC != 0 {
                    return Err(io::Error::from_raw_os_error(libc::EACCES));
                }
                (libc::R_OK, true, false)
            }
            libc::O_WRONLY => (libc::W_OK, false, true),
            libc::O_RDWR => (libc::R_OK | libc::W_OK, true, true),
            // Exactly one access mode flag must be specified
            _ => {
                return Err(io::Error::from_raw_os_error(libc::EINVAL));
            }
        };
        inode
            .attrs
            .check_access(req.uid(), req.gid(), access_mask)?;
        let fh = self.next_fh;
        self.next_fh.0 += 1;
        self.open_dirs.insert(
            fh,
            DirHandle {
                inode: inode.inode,
                read,
                cursors: BTreeMap::new(),
            },
        );
        Ok(fh)
    }

    pub fn readdir(
        &mut self,
        _req: &Request,
        inode: Inode,
        fh: FileHandleId,
        mut offset: i64,
        mut handle_entry: impl FnMut(&mut Self, &OsStr, &DirectoryEntry, i64) -> io::Result<bool>,
    ) -> io::Result<bool> {
        let inode = self.ctrl().load::<InodeAttributes>(inode)?;
        let Some(handle) = self.open_dirs.get_mut(&fh) else {
            return Err(io::Error::from_raw_os_error(libc::EACCES)); // opened without read perm
        };
        let FileData::Directory(dir) = inode.attrs.contents else {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        };

        let mut cur = handle.cursors.remove(&offset).map(Cow::Owned);

        let mut range = if let Some(cursor) = cur.as_deref() {
            dir.range::<_, OsStr>((Bound::Excluded(cursor), Bound::Unbounded))
        } else {
            dir.range::<_, OsStr>(..)
        };

        let self_entry = DirectoryEntry {
            inode: inode.inode,
            ty: FileType::Directory,
        };
        let parent_entry = DirectoryEntry {
            inode: inode
                .attrs
                .parents
                .get_min()
                .map(|(inode, _)| *inode)
                .unwrap_or(inode.inode),
            ty: FileType::Directory,
        };
        let special = if cur.is_none() {
            [
                Some((OsStr::new("."), &self_entry)),
                Some((OsStr::new(".."), &parent_entry)),
            ]
        } else if cur.as_deref() == Some(OsStr::new(".")) {
            [None, Some((OsStr::new(".."), &parent_entry))]
        } else {
            [None, None]
        };

        let mut res: io::Result<bool> = Ok(false);
        for (name, entry) in special
            .into_iter()
            .flatten()
            .chain((&mut range).map(|(s, e)| (&**s, e)))
        {
            res = handle_entry(self, name, entry, offset + 1);
            if res.as_ref().ok().copied() == Some(true) || res.is_err() {
                break;
            }
            offset += 1;
            cur = Some(Cow::Borrowed(name));
        }

        let Some(handle) = self.open_dirs.get_mut(&fh) else {
            return Err(io::Error::from_raw_os_error(libc::EACCES)); // opened without read perm
        };

        if let Some(cur) = cur {
            handle.cursors.insert(offset, cur.into_owned());
        }

        res?;

        Ok(range.next().is_none())
    }

    pub fn releasedir(
        &mut self,
        _req: &Request,
        _inode: Inode,
        fh: FileHandleId,
        _flags: i32,
    ) -> io::Result<()> {
        let Some(ent) = self.open_dirs.remove(&fh) else {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        };
        self.gc_inode(&self.ctrl().load(ent.inode)?)?;

        Ok(())
    }

    pub fn setxattr(
        &mut self,
        req: &Request,
        inode: Inode,
        key: &[u8],
        value: &[u8],
    ) -> io::Result<()> {
        let inode = self.mutate_inode(inode, |_, inode| {
            let attrs = &mut inode.attrs;
            attrs.xattr_access_check(key, libc::W_OK, req)?;
            attrs.xattrs.insert(key.to_vec(), value.to_vec());
            attrs.changed();
            Ok(inode.clone())
        })?;
        self.ctrl().save(&inode)?;
        Ok(())
    }

    pub fn getxattr(&self, req: &Request, inode: Inode, key: &[u8]) -> io::Result<Vec<u8>> {
        let inode = self.ctrl().load::<InodeAttributes>(inode)?;
        let attrs = inode.attrs;
        attrs.xattr_access_check(key, libc::R_OK, req)?;
        match attrs.xattrs.extract(key) {
            Some((v, _)) => Ok(v),
            #[cfg(target_os = "linux")]
            None => Err(io::Error::from_raw_os_error(libc::ENODATA)),
            #[cfg(not(target_os = "linux"))]
            None => Err(io::Error::from_raw_os_error(libc::ENOATTR)),
        }
    }

    pub fn listxattr<'r>(
        &self,
        req: &'r Request,
        inode: Inode,
    ) -> io::Result<impl Iterator<Item = (Vec<u8>, Vec<u8>)> + 'r> {
        let inode = self.ctrl().load::<InodeAttributes>(inode)?;
        let mut attrs = inode.attrs;
        let xattrs = std::mem::replace(&mut attrs.xattrs, Default::default());
        Ok(xattrs
            .into_iter()
            .filter(move |(key, _)| attrs.xattr_access_check(key, libc::R_OK, req).is_ok()))
    }

    pub fn removexattr(&mut self, req: &Request, inode: Inode, key: &[u8]) -> io::Result<Vec<u8>> {
        let (inode, value) = self.mutate_inode(inode, |_, inode| {
            let attrs = &mut inode.attrs;
            attrs.xattr_access_check(key, libc::W_OK, req)?;
            let value = attrs.xattrs.remove(key);
            attrs.changed();
            Ok((inode.clone(), value))
        })?;
        self.ctrl().save(&inode)?;
        match value {
            Some(v) => Ok(v),
            #[cfg(target_os = "linux")]
            None => Err(io::Error::from_raw_os_error(libc::ENODATA)),
            #[cfg(not(target_os = "linux"))]
            None => Err(io::Error::from_raw_os_error(libc::ENOATTR)),
        }
    }

    pub fn create(
        &mut self,
        req: &Request,
        parent: Inode,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
    ) -> io::Result<(InodeAttributes, FileHandleId)> {
        let attrs = self.mknod(
            req,
            parent,
            name,
            mode,
            umask,
            0,
            None::<fn(Inode) -> FileData>,
        )?;
        let handle = self.open(req, attrs.inode, flags)?;
        Ok((attrs, handle))
    }

    pub fn copy_file_range(
        &mut self,
        req: &Request,
        src_inode: Inode,
        src_fh: FileHandleId,
        src_offset: u64,
        dest_inode: Inode,
        dest_fh: FileHandleId,
        dest_offset: u64,
        size: usize,
        flags: u32,
    ) -> io::Result<usize> {
        if flags != 0 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        let bytes = self.read(req, src_inode, src_fh, src_offset, size, 0, None)?;
        self.write(req, dest_inode, dest_fh, dest_offset, &bytes, 0, 0, None)
    }

    pub fn fallocate(
        &mut self,
        _req: &Request,
        _inode: Inode,
        fh: FileHandleId,
        offset: u64,
        length: u64,
        mode: i32,
    ) -> io::Result<()> {
        let fh = self
            .handle(fh)
            .ok_or(libc::EBADF)
            .map_err(io::Error::from_raw_os_error)?;
        if !fh.write {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }

        let mut contents = fh.contents.borrow_mut();
        contents.fallocate(offset, length, mode, mode & libc::FALLOC_FL_KEEP_SIZE != 0)?;
        Ok(())
    }
}
