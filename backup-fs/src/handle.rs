use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io;
use std::rc::{Rc, Weak};
use std::time::SystemTime;

use fuser::{Request, TimeOrNow};
use log::debug;

use crate::contents::Contents;
use crate::ctrl::{Controller, Save};
use crate::directory::DirectoryContents;
use crate::inode::{FileKind, Inode, InodeAttributes};
use crate::{get_groups, MAX_NAME_LENGTH};

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
    pub fn truncate(&self, size: u64) -> io::Result<()> {}
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
        if !parent_attrs.check_access(req.uid(), req.gid(), libc::X_OK) {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }

        if parent_attrs.kind != FileKind::Directory {
            return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
        }

        let contents = self.ctrl().load::<DirectoryContents>(parent)?;
        let (inode, _) = contents
            .get(name)
            .ok_or(libc::ENOENT)
            .map_err(io::Error::from_raw_os_error)?;
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
}
