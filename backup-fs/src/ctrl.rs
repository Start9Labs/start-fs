use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::atomic_file::AtomicFile;
use crate::chunk::{self, ChunkId, ChunkRef, FileContents};
use crate::contents::EncryptedFile;
use crate::directory::{DirectoryContents, DirectoryEntry};
use crate::error::{BkfsError, BkfsResult, BkfsResultExt};
use crate::inode::{FileData, Inode, InodeAttributes};
use crate::serde::{load, save};
use crate::util::IdPool;
use crate::{BackupFSOptions, CryptInfo};
use chacha20::cipher::{Iv, KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key};
use fuser::{FileType, FUSE_ROOT_ID};
use log::error;

#[derive(Clone)]
pub struct Controller(Arc<ControllerSeed>);

// Controller is cloned across worker threads once the worker pool is
// wired up. Compile-time check that interior mutability stays
// thread-safe.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Controller>();
};

const U16_MSB: u16 = 0b1000_0000_0000_0000;

pub struct ControllerSeed {
    config: BackupFSOptions,
    cryptinfo_path: PathBuf,
    cryptinfo: CryptInfo,
    key: Key,
    inode_cipher: Mutex<ChaCha20>,
    inode_dir: PathBuf,
    contents_dir: PathBuf,
    inode_pool_path: PathBuf,
    inode_pool: Mutex<IdPool>,
    /// Counts fast (non-durable) saves since the last syncfs. Both
    /// dispatch-thread eviction and worker-thread content saves bump
    /// this; when it reaches the batch threshold, the next caller
    /// triggers a syncfs that flushes everything accumulated.
    pending_saves: AtomicUsize,
    /// Cached fd on the data dir for syncfs. Lazily opened and reused
    /// so the batched syncfs path doesn't pay an open(2) on every call.
    data_dir_fd: OnceLock<File>,
}

fn encrypt_u64(cipher: &Mutex<ChaCha20>, num: u64) -> [u8; 8] {
    let mut buf = u64::to_be_bytes(num);
    let mut cipher = cipher.lock().unwrap();
    cipher.seek(num * std::mem::size_of::<u64>() as u64);
    cipher.apply_keystream(&mut buf);
    buf
}

fn legacy_path(base: &PathBuf, encrypted: [u8; 8]) -> PathBuf {
    let a = u16::from_be_bytes([encrypted[0], encrypted[1]]);
    let b = u16::from_be_bytes([encrypted[2], encrypted[3]]);
    let c = u16::from_be_bytes([encrypted[4], encrypted[5]]);
    let d = u16::from_be_bytes([encrypted[6], encrypted[7]]);
    let e = (a & U16_MSB >> 12) | (a & U16_MSB >> 13) | (a & U16_MSB >> 14) | (a & U16_MSB >> 15);
    let a = a & !U16_MSB;
    let b = b & !U16_MSB;
    let c = c & !U16_MSB;
    let d = d & !U16_MSB;
    base.join(format!("{a:04x}/{b:04x}/{c:04x}/{d:04x}/{e:02x}"))
}

/// 2-level path: 2 bytes for directory (65K buckets), 6 bytes for filename.
/// Supports ~4B files before any bucket exceeds FAT32's 65K entry limit.
fn current_path(base: &PathBuf, encrypted: [u8; 8]) -> PathBuf {
    let dir = u16::from_be_bytes([encrypted[0], encrypted[1]]);
    let file = &encrypted[2..];
    base.join(format!(
        "{dir:04x}/{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        file[0], file[1], file[2], file[3], file[4], file[5]
    ))
}

/// Returns the current (2-level) path, falling back to legacy (5-level) if only that exists.
fn resolve_path(base: &PathBuf, encrypted: [u8; 8]) -> PathBuf {
    let path = current_path(base, encrypted);
    if path.exists() {
        return path;
    }
    let legacy = legacy_path(base, encrypted);
    if legacy.exists() {
        return legacy;
    }
    path
}

fn parse_chunk_hex(name: &str) -> Option<ChunkId> {
    if name.len() != 32 {
        return None;
    }
    let mut out = [0_u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&name[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(ChunkId(out))
}

impl Controller {
    pub fn new(config: BackupFSOptions) -> BkfsResult<Self> {
        let cryptinfo_path = config.data_dir.join("cryptinfo");
        let cryptinfo = if cryptinfo_path.exists() {
            CryptInfo::load(&cryptinfo_path, &config.password)?
        } else {
            if config.readonly {
                return BkfsResult::errno_notrace(libc::EROFS);
            }
            let cryptinfo = CryptInfo::new();
            cryptinfo.save(cryptinfo_path.clone(), &config.password)?;
            cryptinfo
        };
        let key = Key::clone_from_slice(&*cryptinfo.key);
        let inode_iv = Iv::<ChaCha20>::clone_from_slice(&cryptinfo.inode_iv);
        Ok(Self(Arc::new(ControllerSeed {
            inode_cipher: Mutex::new(ChaCha20::new(&key, &inode_iv)),
            key,
            inode_dir: config.data_dir.join("inodes"),
            contents_dir: config.data_dir.join("contents"),
            inode_pool_path: config.data_dir.join("inode_pool"),
            inode_pool: Mutex::new(IdPool::new()),
            pending_saves: AtomicUsize::new(0),
            data_dir_fd: OnceLock::new(),
            config,
            cryptinfo_path,
            cryptinfo,
        })))
    }

    pub fn load_inode_pool(&self) -> BkfsResult<()> {
        if self.0.inode_pool_path.exists() {
            match crate::open_direct(&self.0.inode_pool_path, false)
                .map_err(BkfsError::from)
                .and_then(|f| EncryptedFile::open(f, &self.key()))
                .and_then(load)
            {
                Ok(pool) => {
                    *self.0.inode_pool.lock().unwrap() = pool;
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

    pub fn fsck(&self, find_orphans: bool) -> BkfsResult<()> {
        *self.0.inode_pool.lock().unwrap() = IdPool::new();
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
    ) -> BkfsResult<bool> {
        let mut prune = false;
        let mut changed = false;
        self.0.inode_pool.lock().unwrap().remove(inode.0);
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
                            FileType::RegularFile => FileData::File(FileContents::new()),
                            FileType::NamedPipe
                            | FileType::CharDevice
                            | FileType::BlockDevice
                            | FileType::Socket => FileData::Special(entry.ty),
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

    fn find_orphans(&self) -> BkfsResult<()> {
        self.check_rw()?;
        let mut live = BTreeSet::new();
        let mut visited = BTreeSet::new();
        self.collect_live_chunks(Inode(FUSE_ROOT_ID), &mut visited, &mut live)?;

        if !self.0.contents_dir.exists() {
            return Ok(());
        }

        for l1 in std::fs::read_dir(&self.0.contents_dir)? {
            let l1 = l1?;
            if !l1.file_type()?.is_dir() {
                continue;
            }
            for l2 in std::fs::read_dir(l1.path())? {
                let l2 = l2?;
                if !l2.file_type()?.is_dir() {
                    continue;
                }
                for entry in std::fs::read_dir(l2.path())? {
                    let entry = entry?;
                    if !entry.file_type()?.is_file() {
                        continue;
                    }
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else { continue };
                    let Some(id) = parse_chunk_hex(name) else {
                        continue;
                    };
                    if !live.contains(&id) {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }
        Ok(())
    }

    fn collect_live_chunks(
        &self,
        inode: Inode,
        visited: &mut BTreeSet<Inode>,
        live: &mut BTreeSet<ChunkId>,
    ) -> BkfsResult<()> {
        if !visited.insert(inode) {
            return Ok(());
        }
        let inode = self.load::<InodeAttributes>(inode)?;
        match &inode.attrs.contents {
            FileData::File(contents) => contents.live_chunk_ids(live),
            FileData::Directory(dir) => {
                for (_, entry) in dir.iter() {
                    self.collect_live_chunks(entry.inode, visited, live)?;
                }
            }
            FileData::Symlink(_) | FileData::Special(_) => {}
        }
        Ok(())
    }

    pub fn change_password(&self, password: &str) -> BkfsResult<()> {
        self.check_rw()?;
        self.0
            .cryptinfo
            .save(self.0.cryptinfo_path.clone(), password)
    }

    pub fn check_rw(&self) -> BkfsResult<()> {
        if self.0.config.readonly {
            BkfsResult::errno_notrace(libc::EROFS)
        } else {
            Ok(())
        }
    }

    /// Returns the current (2-level) path for writing. Cleans up legacy (5-level) copy.
    pub fn inode_path(&self, inode: Inode) -> PathBuf {
        let encrypted = encrypt_u64(&self.0.inode_cipher, inode.0);
        self.cleanup_legacy(&self.0.inode_dir, encrypted);
        current_path(&self.0.inode_dir, encrypted)
    }

    pub fn chunk_path(&self, chunk: ChunkId) -> PathBuf {
        chunk::chunk_path(&self.0.contents_dir, chunk)
    }

    pub fn write_chunk(&self, chunk: ChunkId, data: &[u8]) -> BkfsResult<()> {
        self.check_rw()?;
        chunk::write_chunk_file(self.chunk_path(chunk), self.key(), data)
    }

    pub fn read_chunk(&self, reference: &ChunkRef) -> BkfsResult<Vec<u8>> {
        let data = chunk::read_chunk_file(&self.chunk_path(reference.id), self.key())?;
        if data.len() != reference.stored_len as usize
            || chunk::plaintext_hash(&data) != reference.hash
        {
            return Err(crate::error::BkfsError {
                kind: crate::error::BkfsErrorKind::BadChecksum,
                backtrace: None,
            });
        }
        Ok(data)
    }

    pub fn remove_chunk_best_effort(&self, chunk: ChunkId) {
        let _ = std::fs::remove_file(self.chunk_path(chunk));
    }

    fn cleanup_legacy(&self, base: &PathBuf, encrypted: [u8; 8]) {
        let legacy = legacy_path(base, encrypted);
        if legacy.exists() {
            let _ = std::fs::remove_file(&legacy);
        }
    }

    pub fn resolve_inode_path(&self, inode: Inode) -> PathBuf {
        resolve_path(
            &self.0.inode_dir,
            encrypt_u64(&self.0.inode_cipher, inode.0),
        )
    }

    pub fn next_inode(&self) -> BkfsResult<Inode> {
        self.check_rw()?;
        let mut pool = self.0.inode_pool.lock().unwrap();
        let res: u64 = pool
            .next()
            .ok_or(libc::EMFILE)
            .map_err(io::Error::from_raw_os_error)?;
        save(
            &*pool,
            EncryptedFile::create(
                crate::aligned_io::BufferedDirectFile::new(AtomicFile::create_buffered(
                    self.0.inode_pool_path.clone(),
                )?)?,
                self.key(),
            )?,
        )?;
        Ok(Inode(res))
    }

    pub fn key(&self) -> &Key {
        &self.0.key
    }

    pub fn config(&self) -> &BackupFSOptions {
        &self.0.config
    }

    pub fn save<T: Save>(&self, item: T) -> BkfsResult<()> {
        self.check_rw()?;
        item.save(self)
    }

    /// As `save`, but skips per-file sync_all. The caller must account for
    /// the write in `tick_save` (or call `syncfs` directly) so durability
    /// eventually catches up.
    pub fn save_fast<T: Save>(&self, item: T) -> BkfsResult<()> {
        self.check_rw()?;
        item.save_fast(self)
    }

    pub fn load<T: Load>(&self, args: T::Args<'_>) -> BkfsResult<T> {
        T::load(self, args)
    }

    pub fn exists<T: Exists>(&self, args: T::Args<'_>) -> bool {
        T::exists(self, args)
    }

    fn data_dir_fd(&self) -> io::Result<&File> {
        if let Some(f) = self.0.data_dir_fd.get() {
            return Ok(f);
        }
        let fd = File::open(&self.0.config.data_dir)?;
        // Another thread may have raced us; either outcome is fine,
        // the loser drops its fd.
        let _ = self.0.data_dir_fd.set(fd);
        Ok(self.0.data_dir_fd.get().unwrap())
    }

    /// Flush the entire backing filesystem's page cache and device
    /// write cache. One syncfs replaces many per-file fsync calls when
    /// batching writes with `save_fast`.
    pub fn syncfs(&self) -> io::Result<()> {
        let fd = self.data_dir_fd()?.as_raw_fd();
        // Zero the pending counter under the same call — any races
        // just cause an extra syncfs later, which is harmless.
        self.0.pending_saves.store(0, Ordering::Relaxed);
        // SAFETY: fd is a valid fd we own (held in data_dir_fd).
        if unsafe { libc::syncfs(fd) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Batch threshold for group-commit. Overridden via
    /// `BACKUPFS_SYNC_BATCH`. Larger batches amortize more per-fsync
    /// cost but widen the durability window.
    fn sync_batch() -> usize {
        static BATCH: OnceLock<usize> = OnceLock::new();
        *BATCH.get_or_init(|| {
            std::env::var("BACKUPFS_SYNC_BATCH")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(256)
        })
    }

    /// Account for one fast save. When the batch threshold is reached,
    /// issue a syncfs that flushes everything accumulated.
    pub fn tick_save(&self) -> io::Result<()> {
        let n = self.0.pending_saves.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= Self::sync_batch() {
            self.syncfs()?;
        }
        Ok(())
    }
}

pub trait Save {
    fn save(self, ctrl: &Controller) -> BkfsResult<()>;
    /// Save without sync_all. Default falls back to `save`; implement
    /// this for types whose save path supports the fast variant.
    fn save_fast(self, ctrl: &Controller) -> BkfsResult<()>
    where
        Self: Sized,
    {
        self.save(ctrl)
    }
}

pub trait Load: Sized {
    type Args<'a>;
    fn load(ctrl: &Controller, args: Self::Args<'_>) -> BkfsResult<Self>;
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
        let pool = self.0.inode_pool.lock().unwrap();
        StatFs {
            ffree: pool.free_space(),
            files: pool.used_space(),
        }
    }
}
