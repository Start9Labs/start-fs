use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;

use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::ctrl::{Controller, Exists, Load, Save};
use crate::inode::{FileKind, Inode};
use crate::serde::{load, save};

pub struct DirectoryContents {
    inode: Inode,
    contents: BTreeMap<OsString, (Inode, FileKind)>,
}
impl DirectoryContents {
    pub fn new(inode: Inode) -> Self {
        let mut contents = BTreeMap::new();
        contents.insert(".".into(), (inode, FileKind::Directory));
        Self { inode, contents }
    }
    pub fn get(&self, name: &OsStr) -> Option<(Inode, FileKind)> {
        self.contents.get(name).copied()
    }
}
impl<'a> Save for &'a DirectoryContents {
    fn save(self, ctrl: &Controller) -> std::io::Result<()> {
        save(
            &self.contents,
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
        Ok(Self {
            inode: args,
            contents: load(EncryptedFile::open(
                File::open(ctrl.contents_path(args))?,
                ctrl.key(),
            )?)?,
        })
    }
}
impl Exists for DirectoryContents {
    fn exists(ctrl: &Controller, args: Self::Args<'_>) -> bool {
        ctrl.contents_path(args).exists()
    }
}
