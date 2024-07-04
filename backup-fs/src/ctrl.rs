use std::cell::RefCell;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;

use chacha20::cipher::{Iv, KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key};
use fuser::{FileType, FUSE_ROOT_ID};
use itertools::Itertools;
use log::error;
use rand::Rng;

use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::directory::{DirectoryContents, DirectoryEntry};
use crate::inode::{ContentId, FileData, Inode, InodeAttributes};
use crate::serde::{load, save};
use crate::util::IdPool;
use crate::BackupFSOptions;

#[derive(Clone)]
pub struct Controller(Rc<ControllerSeed>);

const U16_MSB: u16 = 0b1000_0000_0000_0000;

pub struct ControllerSeed {
    config: BackupFSOptions,
    key: Key,
    inode_cipher: RefCell<ChaCha20>,
    contents_cipher: RefCell<ChaCha20>,
    inode_dir: PathBuf,
    contents_dir: PathBuf,
    inode_pool_path: PathBuf,
    inode_pool: RefCell<IdPool>,
}

fn encrypted_u64(cipher: &RefCell<ChaCha20>, num: u64) -> [u16; 5] {
    let mut inode_buf = u64::to_be_bytes(num);
    let mut cipher = cipher.borrow_mut();
    cipher.seek(num * std::mem::size_of::<u64>() as u64);
    cipher.apply_keystream(&mut inode_buf);
    let a = u16::from_be_bytes([inode_buf[0], inode_buf[1]]);
    let b = u16::from_be_bytes([inode_buf[2], inode_buf[3]]);
    let c = u16::from_be_bytes([inode_buf[4], inode_buf[5]]);
    let d = u16::from_be_bytes([inode_buf[6], inode_buf[7]]);
    [
        a & !U16_MSB,
        b & !U16_MSB,
        c & !U16_MSB,
        d & !U16_MSB,
        (a & U16_MSB >> 12) | (a & U16_MSB >> 13) | (a & U16_MSB >> 14) | (a & U16_MSB >> 15),
    ]
}

impl Controller {
    pub fn new(
        config: BackupFSOptions,
        key: Key,
        inode_iv: Iv<ChaCha20>,
        contents_iv: Iv<ChaCha20>,
    ) -> Self {
        Self(Rc::new(ControllerSeed {
            inode_cipher: RefCell::new(ChaCha20::new(&key, &inode_iv)),
            contents_cipher: RefCell::new(ChaCha20::new(&key, &contents_iv)),
            key,
            inode_dir: config.data_dir.join("inodes"),
            contents_dir: config.data_dir.join("contents"),
            inode_pool_path: config.data_dir.join("inode_pool"),
            inode_pool: RefCell::new(IdPool::new()),
            config,
        }))
    }

    pub fn load_inode_pool(&self) -> io::Result<()> {
        if self.0.inode_pool_path.exists() {
            match File::open(&self.0.inode_pool_path)
                .and_then(|f| EncryptedFile::open(f, &self.key()))
                .and_then(load)
            {
                Ok(pool) => {
                    self.0.inode_pool.replace(pool);
                    return Ok(());
                }
                Err(e) => {
                    error!("failed to load inode pool: {e}\n    Reconstructing...");
                }
            }
        }
        self.fsck(false)?;

        Ok(())
    }

    pub fn fsck(&self, find_orphans: bool) -> io::Result<()> {
        self.0.inode_pool.replace(IdPool::new());
        self.fsck_inode(Inode(FUSE_ROOT_ID), None)?;
        if find_orphans {
            self.find_orphans()?;
        }
        Ok(())
    }

    fn fsck_inode(
        &self,
        inode: Inode,
        parent: Option<(&(Inode, OsString), &DirectoryEntry)>,
    ) -> io::Result<bool> {
        let mut prune = false;
        let mut changed = false;
        self.0.inode_pool.borrow_mut().remove(inode.0);
        // match self.load::(args)
        let mut inode = match self.load::<InodeAttributes>(inode) {
            Ok(mut inode) => {
                if let Some((parent, _)) = parent {
                    if inode.attrs.parents.is_empty() {
                        inode.attrs.parents.insert(parent.clone());
                        changed = true;
                    } else if !inode.attrs.parents.contains(parent) {
                        prune = true;
                    }
                }
                inode
            }
            Err(e) => {
                error!("failed to load inode: {e}\n    Reconstructing...");
                changed = true;
                if let Some((parent, entry)) = parent {
                    InodeAttributes::new(
                        inode,
                        Some(parent.clone()),
                        match entry.ty {
                            FileType::Directory => FileData::Directory(DirectoryContents::new()),
                            FileType::Symlink => FileData::Symlink(PathBuf::new()),
                            FileType::RegularFile => FileData::File(ContentId(inode.0)),
                            _ => return Err(io::Error::other("unsupported filetype in directory")),
                        },
                    )
                } else {
                    InodeAttributes::new(inode, None, FileData::Directory(DirectoryContents::new()))
                }
            }
        };
        if let FileData::Directory(dir) = &mut inode.attrs.contents {
            let mut to_prune = Vec::new();
            for (name, entry) in dir.iter() {
                let parent = (inode.inode, name.clone());
                if self.fsck_inode(entry.inode, Some((&parent, entry)))? {
                    to_prune.push(parent.1);
                }
            }
            for name in to_prune {
                dir.remove(&name);
                changed = true;
            }
        }
        if changed {
            self.save(&inode)?;
        }

        Ok(prune)
    }

    fn find_orphans(&self) -> io::Result<()> {
        // TODO
        Ok(())
    }

    pub fn inode_path(&self, inode: Inode) -> PathBuf {
        let [a, b, c, d, e] = encrypted_u64(&self.0.inode_cipher, inode.0);
        self.0
            .inode_dir
            .join(format!("{a:04x}/{b:04x}/{c:04x}/{d:04x}/{e:02x}"))
    }

    pub fn contents_path(&self, contents: ContentId) -> PathBuf {
        let [a, b, c, d, e] = encrypted_u64(&self.0.contents_cipher, contents.0);
        self.0
            .contents_dir
            .join(format!("{a:04x}/{b:04x}/{c:04x}/{d:04x}/{e:02x}"))
    }

    pub fn next_inode(&self) -> io::Result<Inode> {
        let mut pool = self.0.inode_pool.borrow_mut();
        let res: u64 = pool
            .next()
            .ok_or(libc::EMFILE)
            .map_err(io::Error::from_raw_os_error)?;
        save(
            &*pool,
            EncryptedFile::create(
                AtomicFile::create(self.0.inode_pool_path.clone())?,
                self.key(),
            )?,
        )?;
        Ok(Inode(res))
    }

    pub fn file_pad(&self, size: u64) -> u64 {
        size + (self
            .0
            .config
            .file_size_padding
            .map(|p| p * size as f64)
            .map(|p| p * rand::thread_rng().gen_range(0_f64..=1_f64))
            .map(|p| p as u64)
            .unwrap_or(0))
    }

    pub fn key(&self) -> &Key {
        &self.0.key
    }

    pub fn config(&self) -> &BackupFSOptions {
        &self.0.config
    }

    pub fn save<T: Save>(&self, item: T) -> io::Result<()> {
        item.save(self)
    }

    pub fn load<T: Load>(&self, args: T::Args<'_>) -> io::Result<T> {
        T::load(self, args)
    }

    pub fn exists<T: Exists>(&self, args: T::Args<'_>) -> bool {
        T::exists(self, args)
    }
}

pub trait Save {
    fn save(self, ctrl: &Controller) -> io::Result<()>;
}

pub trait Load: Sized {
    type Args<'a>;
    fn load(ctrl: &Controller, args: Self::Args<'_>) -> io::Result<Self>;
}

pub trait Exists: Load {
    fn exists(ctrl: &Controller, args: Self::Args<'_>) -> bool;
}

pub struct StatFs {
    pub files: u64,
    pub ffree: u64,
}

impl Controller {
    pub fn statfs(&self) -> StatFs {
        let pool = self.0.inode_pool.borrow();
        StatFs {
            ffree: pool.free_space(),
            files: pool.used_space(),
        }
    }
}
