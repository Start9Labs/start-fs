use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use chacha20::cipher::{Iv, KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key};
use fuser::{FileType, FUSE_ROOT_ID};
use log::error;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::io::Write;

use crate::atomic_file::AtomicFile;
use crate::directory::{DirectoryContents, DirectoryEntry};
use crate::error::{BkfsError, BkfsResult, BkfsResultExt};
use crate::inode::{ContentId, FileData, Inode, InodeAttributes};
use crate::serde;
use crate::util::IdPool;
use crate::{BackupFSOptions, CryptInfo};

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
    dirents_dir: PathBuf,
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

impl Controller {
    pub fn new(config: BackupFSOptions) -> BkfsResult<Self> {
        let cryptinfo_path = config.data_dir.join("cryptinfo");
        let cryptinfo = if CryptInfo::any_exists(&cryptinfo_path) {
            CryptInfo::load(&cryptinfo_path, &config.password)?
        } else {
            if config.readonly {
                return BkfsResult::errno_notrace(libc::EROFS);
            }
            let cryptinfo = CryptInfo::new();
            cryptinfo.save(&cryptinfo_path, &config.password)?;
            cryptinfo
        };
        let key = Key::clone_from_slice(&*cryptinfo.key);
        let inode_iv = Iv::<ChaCha20>::clone_from_slice(&cryptinfo.inode_iv);
        Ok(Self(Arc::new(ControllerSeed {
            inode_cipher: Mutex::new(ChaCha20::new(&key, &inode_iv)),
            key,
            inode_dir: config.data_dir.join("inodes"),
            contents_dir: config.data_dir.join("contents"),
            dirents_dir: config.data_dir.join("dirents"),
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
            match std::fs::read(&self.0.inode_pool_path)
                .map_err(BkfsError::from)
                .and_then(|blob| serde::deserialize_sealed::<IdPool>(&blob, self.key()))
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
                            FileType::RegularFile => FileData::File(ContentId(inode.0)),
                            _ => {
                                return Err(
                                    io::Error::other("unsupported filetype in directory").into()
                                )
                            }
                        },
                    )
                } else {
                    InodeAttributes::new(inode, None, FileData::Directory(DirectoryContents::new()))
                }
            }
        };
        if let FileData::Directory(dir) = &inode.attrs.contents {
            let entries = dir.snapshot(self, inode.inode)?;
            let mut to_prune = Vec::new();
            for (name, entry) in entries.iter() {
                let parent = (inode.inode, name.clone());
                if self.fsck_inode(entry.inode, Some((&parent, entry)))? {
                    to_prune.push(name.clone());
                }
            }
            if !to_prune.is_empty() {
                if let FileData::Directory(dir) = &mut inode.attrs.contents {
                    for name in &to_prune {
                        dir.remove(self, inode.inode, name, true)?;
                    }
                }
                changed = true;
            }
            // Repair any cached len/subdirs that drifted across a crash.
            let inode_no = inode.inode;
            if let FileData::Directory(dir) = &mut inode.attrs.contents {
                if dir.recompute_counts(self, inode_no)? {
                    changed = true;
                }
            }
        }
        if changed {
            self.save(&inode)?;
        }

        Ok(prune)
    }

    fn find_orphans(&self) -> BkfsResult<()> {
        // TODO
        Ok(())
    }

    pub fn change_password(&self, password: &str) -> BkfsResult<()> {
        self.check_rw()?;
        self.0.cryptinfo.save(&self.0.cryptinfo_path, password)
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

    /// Deterministic, key-dependent filename for content block
    /// `(content, idx)`. The name is a keyed SHA-256 hash, so it leaks no
    /// information about the inode or offset, yet is stable across runs —
    /// editing one region of a file rewrites exactly one block file and
    /// every other block keeps its name (the property that makes
    /// rsync/rclone incremental copies cheap).
    pub fn block_path(&self, content: ContentId, idx: u64) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(self.0.key.as_slice());
        hasher.update(b"block");
        hasher.update(content.0.to_le_bytes());
        hasher.update(idx.to_le_bytes());
        let tag = hasher.finalize();
        // 2-level layout: 16-bit bucket (≤65 536 dirs) + 120-bit filename.
        // A 128-bit name makes collisions cryptographically negligible.
        let dir = u16::from_be_bytes([tag[0], tag[1]]);
        let mut name = String::with_capacity(30);
        for b in &tag[2..16] {
            name.push_str(&format!("{b:02x}"));
        }
        self.0.contents_dir.join(format!("{dir:04x}/{name}"))
    }

    /// Blocks have no legacy layout, so resolution is just [`Self::block_path`].
    pub fn resolve_block_path(&self, content: ContentId, idx: u64) -> PathBuf {
        self.block_path(content, idx)
    }

    /// Path of a spilled-directory bucket file, keyed by `(dir, gen, idx)`.
    fn dir_bucket_path(&self, dir: Inode, gen: u64, idx: u32) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(self.0.key.as_slice());
        hasher.update(b"dirbucket");
        hasher.update(dir.0.to_le_bytes());
        hasher.update(gen.to_le_bytes());
        hasher.update(idx.to_le_bytes());
        let tag = hasher.finalize();
        let bucket = u16::from_be_bytes([tag[0], tag[1]]);
        let mut name = String::with_capacity(30);
        for b in &tag[2..16] {
            name.push_str(&format!("{b:02x}"));
        }
        self.0.dirents_dir.join(format!("{bucket:04x}/{name}"))
    }

    /// Load one directory bucket; a missing file is an empty bucket.
    pub fn load_dir_bucket(
        &self,
        dir: Inode,
        gen: u64,
        idx: u32,
    ) -> BkfsResult<crate::directory::Bucket> {
        match std::fs::read(self.dir_bucket_path(dir, gen, idx)) {
            Ok(blob) => serde::deserialize_sealed(&blob, self.key()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Default::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Persist one directory bucket. An empty bucket is removed rather than
    /// written, so a bucket file exists iff it has entries.
    pub fn save_dir_bucket(
        &self,
        dir: Inode,
        gen: u64,
        idx: u32,
        bucket: &crate::directory::Bucket,
        durable: bool,
    ) -> BkfsResult<()> {
        self.check_rw()?;
        if bucket.is_empty() {
            return self.remove_dir_bucket(dir, gen, idx);
        }
        let blob = serde::serialize_sealed(bucket, self.key())?;
        let mut file = AtomicFile::create_buffered(self.dir_bucket_path(dir, gen, idx))?;
        file.write_all(&blob)?;
        if durable {
            file.save()
        } else {
            file.save_fast()?;
            self.tick_save()?;
            Ok(())
        }
    }

    /// Remove one directory bucket file, tolerating absence.
    pub fn remove_dir_bucket(&self, dir: Inode, gen: u64, idx: u32) -> BkfsResult<()> {
        match std::fs::remove_file(self.dir_bucket_path(dir, gen, idx)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn next_inode(&self) -> BkfsResult<Inode> {
        self.check_rw()?;
        let mut pool = self.0.inode_pool.lock().unwrap();
        let res: u64 = pool
            .next()
            .ok_or(libc::EMFILE)
            .map_err(io::Error::from_raw_os_error)?;
        // Fast (non-fsync) save: a per-creation sync_all here was a CIFS
        // round trip on every single file in a backup. The pool is
        // reconstructible by fsck, and its update rides the same batched
        // syncfs as the inode/content writes that consume the id — so a
        // crash loses the pool bump and those inodes together (consistent),
        // never reusing a live id.
        let blob = serde::serialize_sealed(&*pool, self.key())?;
        let mut file = AtomicFile::create_buffered(self.0.inode_pool_path.clone())?;
        file.write_all(&blob)?;
        file.save_fast()?;
        self.tick_save()?;
        Ok(Inode(res))
    }

    pub fn file_pad(&self, size: u64) -> u64 {
        size + (self
            .0
            .config
            .file_size_padding
            .map(|p| p * size as f64)
            .map(|p| p * rand::rng().random_range(0_f64..=1_f64))
            .map(|p| p as u64)
            .unwrap_or(0))
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
