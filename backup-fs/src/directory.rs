use std::ffi::OsString;
use std::ops::{Deref, DerefMut};

use imbl::OrdMap;
use serde::{Deserialize, Serialize};

use crate::inode::Inode;

#[derive(Clone, Deserialize, Serialize)]
pub struct DirectoryContents {
    contents: OrdMap<OsString, DirectoryEntry>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct DirectoryEntry {
    pub inode: Inode,
    pub is_dir: bool,
}

impl DirectoryContents {
    pub fn new() -> Self {
        let contents = OrdMap::new();
        Self { contents }
    }
    pub fn nlink(&self) -> usize {
        1 + self.contents.values().filter(|e| e.is_dir).count()
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
