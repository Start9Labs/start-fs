use std::cell::RefCell;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;

use chacha20::cipher::{Iv, KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key};
use fuser::FUSE_ROOT_ID;
use itertools::Itertools;
use rand::Rng;

use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::inode::{ContentId, Inode};
use crate::serde::{load, save};
use crate::BackupFSOptions;

#[derive(Clone)]
pub struct Controller(Rc<ControllerData>);

pub struct ControllerData {
    config: BackupFSOptions,
    key: Key,
    inode_cipher: RefCell<ChaCha20>,
    contents_cipher: RefCell<ChaCha20>,
    inode_dir: PathBuf,
    contents_dir: PathBuf,
    inode_ctr: PathBuf,
}

fn encrypted_u64(cipher: &RefCell<ChaCha20>, num: u64) -> [u16; 4] {
    let mut inode_buf = u64::to_be_bytes(num);
    let mut cipher = cipher.borrow_mut();
    cipher.seek(num * std::mem::size_of::<u64>() as u64);
    cipher.apply_keystream(&mut inode_buf);
    [
        u16::from_be_bytes([inode_buf[0], inode_buf[1]]),
        u16::from_be_bytes([inode_buf[2], inode_buf[3]]),
        u16::from_be_bytes([inode_buf[4], inode_buf[5]]),
        u16::from_be_bytes([inode_buf[6], inode_buf[7]]),
    ]
}

impl Controller {
    pub fn new(
        config: BackupFSOptions,
        key: Key,
        inode_iv: Iv<ChaCha20>,
        contents_iv: Iv<ChaCha20>,
    ) -> Self {
        Self(Rc::new(ControllerData {
            inode_cipher: RefCell::new(ChaCha20::new(&key, &inode_iv)),
            contents_cipher: RefCell::new(ChaCha20::new(&key, &contents_iv)),
            key,
            inode_dir: config.data_dir.join("inodes"),
            contents_dir: config.data_dir.join("contents"),
            inode_ctr: config.data_dir.join("inode_ctr"),
            config,
        }))
    }

    pub fn inode_path(&self, inode: Inode) -> PathBuf {
        let inode = encrypted_u64(&self.0.inode_cipher, inode.0);
        self.0.inode_dir.join(inode.into_iter().join("/"))
    }
    pub fn contents_path(&self, contents: ContentId) -> PathBuf {
        let contents = encrypted_u64(&self.0.contents_cipher, contents.0);
        self.0.contents_dir.join(contents.into_iter().join("/"))
    }
    pub fn next_inode(&self) -> io::Result<Inode> {
        let res: u64 = if self.0.inode_ctr.exists() {
            load(EncryptedFile::open(
                File::open(&self.0.inode_ctr)?,
                self.key(),
            )?)?
        } else {
            FUSE_ROOT_ID + 1
        };
        save(
            &(res + 1),
            EncryptedFile::create(AtomicFile::create(self.0.inode_ctr.clone())?, self.key())?,
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
