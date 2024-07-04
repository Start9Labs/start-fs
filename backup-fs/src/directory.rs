use std::ffi::OsString;
use std::ops::{Deref, DerefMut};

use fuser::FileType;
use imbl::OrdMap;
use serde::{Deserialize, Serialize};

use crate::inode::Inode;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DirectoryContents {
    contents: OrdMap<OsString, DirectoryEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DirectoryEntry {
    pub inode: Inode,
    pub ty: FileType,
}

impl DirectoryContents {
    pub fn new() -> Self {
        let contents = OrdMap::new();
        Self { contents }
    }
    pub fn nlink(&self) -> usize {
        1 + self
            .contents
            .values()
            .filter(|e| e.ty == FileType::Directory)
            .count()
    }
}
impl Deref for DirectoryContents {
    type Target = OrdMap<OsString, DirectoryEntry>;
    fn deref(&self) -> &Self::Target {
        &self.contents
    }
}
impl DerefMut for DirectoryContents {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.contents
    }
}
