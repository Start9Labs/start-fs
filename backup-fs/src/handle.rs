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

use crate::contents::{self, Contents};
use crate::ctrl::{Controller, Save};
use crate::directory::{DirectoryContents, DirectoryEntry};
use crate::inode::{Attributes, FileData, Inode, InodeAttributes};
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

    fn mutate_inode<F: FnOnce(&mut Self, &mut InodeAttributes) -> io::Result<T>, T>(
        &mut self,
        inode: Inode,
        f: F,
    ) -> io::Result<T> {
        if let Some(contents) = self.inodes.get(&inode).and_then(Weak::upgrade) {
            let mut contents = contents.borrow_mut();
            let res = f(self, &mut contents.inode);
            let new_inode = contents.inode.inode;
            drop(contents);
            if new_inode != inode {
                if let Some(inode) = self.inodes.remove(&inode) {
                    self.inodes.insert(new_inode, inode);
                }
            }
            res
        } else {
            f(self, &mut self.ctrl().load::<InodeAttributes>(inode)?)
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
    pub fn close(self, handler: &mut Handler) -> io::Result<()> {
        if let Ok(contents) = Rc::try_unwrap(self.contents) {
            contents.into_inner().close(handler)?;
        }
        Ok(())
    }
}

impl Handler {
    pub fn close_all(&mut self) -> io::Result<()> {
        std::mem::take(&mut self.inodes);
        let mut errs = Vec::new();
        for (_, handle) in std::mem::take(&mut self.open) {
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
        self.ctrl().load(inode)
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
        fh: Option<u64>,
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
                is_dir: new.attrs.contents.is_dir(),
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

            let uid = req.uid();
            // "Sticky bit" handling
            if parent.attrs.mode & libc::S_ISVTX as u16 != 0
                && uid != 0
                && uid != parent.attrs.uid
                && uid != inode.attrs.uid
            {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }

            inode.attrs.parents.remove(&(parent.inode, name.to_owned()));

            handler.ctrl().save(&parent)?;
            handler.ctrl().save(&*inode)?;
            handler.gc_inode(&*inode)?;

            Ok(())
        })
    }

    pub fn link(
        &mut self,
        req: &Request,
        inode: Inode,
        new_parent: Inode,
        new_name: &OsStr,
    ) -> io::Result<InodeAttributes> {
        self.mutate_inode(inode, |handler, inode| {
            let mut new_parent = handler.ctrl().load::<InodeAttributes>(new_parent)?;

            new_parent
                .attrs
                .check_access(req.uid(), req.gid(), libc::W_OK)?;

            let FileData::Directory(dir) = &mut new_parent.attrs.contents else {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
            };

            inode
                .attrs
                .parents
                .insert((new_parent.inode, new_name.to_owned()));

            dir.insert(
                new_name.to_owned(),
                DirectoryEntry {
                    inode: inode.inode,
                    is_dir: inode.attrs.contents.is_dir(),
                },
            );

            handler.ctrl().save(&*inode)?;
            handler.ctrl().save(&new_parent)?;

            Ok(inode.clone())
        })
    }

    pub fn rename(
        &mut self,
        req: &Request,
        parent: u64,
        name: &OsStr,
        new_parent: u64,
        new_name: &OsStr,
        flags: u32,
    ) -> io::Result<()> {
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

        Ok(())
    }
}
