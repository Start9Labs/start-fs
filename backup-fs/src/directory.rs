use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;

use serde::{Deserialize, Serialize};

use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::ctrl::{Controller, Exists, Load, Save};
use crate::inode::{FileKind, Inode, InodeAttributes};
use crate::serde::{load, save};

#[derive(Deserialize, Serialize)]
pub struct DirectoryContents {
    inode: Inode,
    parent: Option<Inode>,
    contents: BTreeMap<OsString, (Inode, FileKind)>,
}
impl DirectoryContents {
    pub fn new(inode: Inode, parent: Option<Inode>) -> Self {
        let contents = BTreeMap::new();
        Self {
            inode,
            parent,
            contents,
        }
    }
    pub fn get(&self, name: &OsStr) -> Option<(Inode, FileKind)> {
        if name == OsStr::new(".") {
            return Some((self.inode, FileKind::Directory));
        }
        if name == OsStr::new("..") {
            return self.parent.map(|p| (p, FileKind::Directory));
        }
        self.contents.get(name).copied()
    }
    pub fn remove(&mut self, name: &OsStr) -> Option<(Inode, FileKind)> {
        self.contents.remove(name)
    }
    pub fn insert(&mut self, name: OsString, inode: &InodeAttributes) {
        self.contents.insert(name, (inode.inode, inode.kind));
    }
    pub fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }
}
impl<'a> Save for &'a DirectoryContents {
    fn save(self, ctrl: &Controller) -> std::io::Result<()> {
        save(
            &self,
            EncryptedFile::create(
                AtomicFile::create(ctrl.contents_path(self.inode))?,
                ctrl.key(),
            )?,
        )
    }
}
impl Load for DirectoryContents {
    type Args<'a> = Inode;
    fn load(ctrl: &Controller, args: Self::Args<'_>) -> std::io::Result<Self> {
        load(EncryptedFile::open(
            File::open(ctrl.contents_path(args))?,
            ctrl.key(),
        )?)
    }
}
impl Exists for DirectoryContents {
    fn exists(ctrl: &Controller, args: Self::Args<'_>) -> bool {
        ctrl.contents_path(args).exists()
    }
}
