use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::rc::{Rc, Weak};
use std::time::SystemTime;

use fuser::{Request, TimeOrNow};
use log::{debug, warn};

use crate::contents::{Contents, EncryptedFile};
use crate::ctrl::{Controller, Save};
use crate::directory::DirectoryContents;
use crate::inode::{FileKind, Inode, InodeAttributes};
use crate::serde::load;
use crate::{as_file_kind, MAX_NAME_LENGTH};

pub struct Handler {
    ctrl: Controller,
    next_fh: u64,
    inodes: BTreeMap<Inode, Weak<RefCell<Contents>>>,
    open: BTreeMap<u64, FileHandle>,
}
impl Handler {
    pub fn new(ctrl: Controller) -> Self {
        Self {
            ctrl,
            next_fh: 1,
            inodes: BTreeMap::new(),
            open: BTreeMap::new(),
        }
    }
    pub fn ctrl(&self) -> &Controller {
        &self.ctrl
    }
    pub fn fopen(&mut self, inode: Inode, read: bool, write: bool) -> io::Result<u64> {
        let fh = self.next_fh;
        let contents = if let Some(contents) = self.inodes.get(&inode).and_then(Weak::upgrade) {
            contents
        } else {
            let contents = Rc::new(RefCell::new(Contents::open(self.ctrl.clone(), inode)?));
            self.inodes.insert(inode, Rc::downgrade(&contents));
            contents
        };
        self.open.insert(
            fh,
            FileHandle {
                inode,
                read,
                write,
                contents,
            },
        );
        self.next_fh += 1;
        Ok(fh)
    }
    pub fn handle(&self, fh: u64) -> Option<&FileHandle> {
        self.open.get(&fh)
    }
    pub fn fclose(&mut self, fh: u64) -> io::Result<()> {
        let Some(handle) = self.open.remove(&fh) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("file handle {fh} is not open"),
            ));
        };
        handle.close()?;
        Ok(())
    }

    fn creation_mode(&self, mode: u32) -> u16 {
        if !self.ctrl().config().setuid_support {
            (mode & !(libc::S_ISUID | libc::S_ISGID) as u32) as u16
        } else {
            mode as u16
        }
    }
}

#[derive(Clone)]
pub struct FileHandle {
    pub inode: Inode,
    pub read: bool,
    pub write: bool,
    pub contents: Rc<RefCell<Contents>>,
}
impl FileHandle {
    pub fn close(self) -> io::Result<()> {
        if let Ok(contents) = Rc::try_unwrap(self.contents) {
            contents.into_inner().close()?;
        }
        Ok(())
    }
}

impl Handler {
    pub fn close_all(&mut self) -> io::Result<()> {
        std::mem::take(&mut self.inodes);
        let mut errs = Vec::new();
        for (_, handle) in std::mem::take(&mut self.open) {
            if let Err(e) = handle.close() {
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
        parent: u64,
        name: &OsStr,
    ) -> io::Result<InodeAttributes> {
        if name.len() > MAX_NAME_LENGTH as usize {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG));
        }
        let parent_attrs = self.ctrl().load::<InodeAttributes>(parent)?;
        parent_attrs.check_access(req.uid(), req.gid(), libc::X_OK)?;

        let inode = parent_attrs.lookup(self.ctrl(), name)?;
        self.ctrl().load(inode)
    }

    pub fn setattr(
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
    ) -> io::Result<InodeAttributes> {
        let mut attrs;
        let changed;
        if let Some(contents) = self.inodes.get(&inode).and_then(Weak::upgrade) {
            let mut contents = contents.borrow_mut();
            changed = contents.inode.setattr(
                self, req, inode, mode, uid, gid, size, atime, mtime, ctime, fh, crtime, chgtime,
                bkuptime, flags,
            )?;
            attrs = contents.inode.clone();
        } else {
            attrs = self.ctrl().load::<InodeAttributes>(inode)?;
            changed = attrs.setattr(
                self, req, inode, mode, uid, gid, size, atime, mtime, ctime, fh, crtime, chgtime,
                bkuptime, flags,
            )?;
        }
        if changed {
            self.ctrl().save(&attrs)?;
        }
        Ok(attrs)
    }

    pub fn readlink(&mut self, req: &Request, inode: Inode) -> io::Result<PathBuf> {
        debug!("readlink() called on {:?}", inode);
        let inode = self.ctrl().load::<InodeAttributes>(inode)?;
        inode.check_access(req.uid(), req.gid(), libc::R_OK)?;
        if inode.kind != FileKind::Symlink {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        load(EncryptedFile::open(
            File::open(self.ctrl().contents_path(inode.inode))?,
            self.ctrl().key(),
        )?)
    }

    pub fn mknod<C: Save>(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        mut mode: u32,
        umask: u32,
        _rdev: u32,
        contents: Option<C>,
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

        let parent = self.ctrl().load::<InodeAttributes>(parent)?;

        if parent.kind != FileKind::Directory {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }

        parent.check_access(req.uid(), req.gid(), libc::W_OK)?;

        let mut parent_contents = self.ctrl().load::<DirectoryContents>(parent.inode)?;

        if parent_contents.get(name).is_some() {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }

        if req.uid() != 0 {
            mode &= !(libc::S_ISUID | libc::S_ISGID) as u32;
        }

        let mut new = InodeAttributes::new(self.ctrl().next_inode()?, as_file_kind(mode));
        new.uid = req.uid();
        new.gid = parent.creation_gid(req.gid());
        new.mode = self.creation_mode(mode & umask);

        parent_contents.insert(name.to_owned(), &new);

        if let Some(c) = contents {
            self.ctrl().save(c)?;
        } else {
            if as_file_kind(mode) == FileKind::Directory {
                let mut entries = DirectoryContents::new(new.inode, Some(parent.inode));
                entries.insert(".".into(), &new);
                entries.insert("..".into(), &parent);
                self.ctrl().save(&entries)?;
            } else {
                File::create(self.ctrl().contents_path(new.inode))?;
            }
        }

        self.ctrl().save(&new)?;

        self.ctrl().save(&parent)?;

        Ok(new)
    }

    pub fn gc_inode(&mut self, inode: &InodeAttributes) -> io::Result<bool> {
        if inode.hardlinks > 0 {
            return Ok(false);
        }
        if self
            .inodes
            .get(&inode.inode)
            .filter(|rc| Weak::strong_count(rc) > 0)
            .is_some()
        {
            return Ok(false);
        }

        self.inodes.remove(&inode.inode);

        std::fs::remove_file(self.ctrl().inode_path(inode.inode))?;
        std::fs::remove_file(self.ctrl().contents_path(inode.inode))?;

        Ok(true)
    }

    pub fn unlink(&mut self, req: &Request, parent: u64, name: &OsStr) -> io::Result<()> {
        debug!("unlink() called with {:?} {:?}", parent, name);
        let parent = self.ctrl().load::<InodeAttributes>(parent)?;
        parent.check_access(req.uid(), req.gid(), libc::W_OK)?;

        let mut parent_contents = self.ctrl().load::<DirectoryContents>(parent.inode)?;

        let (inode, _) = parent_contents
            .remove(name)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;

        let mut attrs = self.ctrl().load::<InodeAttributes>(inode)?;

        if attrs.kind == FileKind::Directory {
            let contents = self.ctrl().load::<DirectoryContents>(inode)?;
            if !contents.is_empty() {
                return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));
            }
        }

        let uid = req.uid();
        // "Sticky bit" handling
        if parent.mode & libc::S_ISVTX as u16 != 0
            && uid != 0
            && uid != parent.uid
            && uid != attrs.uid
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }

        attrs.hardlinks -= 1;

        self.ctrl().save(&parent_contents)?;
        self.ctrl().save(&parent)?;

        self.gc_inode(&attrs)?;

        Ok(())
    }
}
