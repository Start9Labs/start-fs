//! Chunked content storage with ECC parity.
//!
//! Each inode's content is split into fixed-size blocks, stored as individual
//! files on the backing filesystem. This enables:
//!
//! - **rsync/rclone efficiency**: Only changed blocks are transferred, not the
//!   entire file. This is critical for backends that don't support random writes
//!   (S3, SFTP, etc.) where rewriting a whole file is the only option.
//!
//! - **ECC parity**: Per-group Reed-Solomon parity blocks protect against
//!   corruption on unreliable storage backends.
//!
//! - **Parallel I/O**: Multiple blocks can be read/written in parallel by the
//!   worker pool when servicing large sequential reads/writes.
//!
//! ## Layout
//!
//! ```text
//! contents/{encrypted(content_id)}/
//!   manifest              — encrypted BlockManifest (block layout, checksums)
//!   {block_idx:016x}.blk  — encrypted data block
//!   p{group:08x}_{idx}.blk — encrypted parity block
//! ```
//!
//! Each block file is independently encrypted with a deterministic IV based on
//! its position, so unchanged blocks produce identical ciphertext across saves
//! — perfect for rsync's delta-transfer algorithm.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::ctrl::Controller;
use crate::ecc::{EccCodec, EccConfig};
use crate::error::BkfsResult;
use crate::inode::ContentId;
use crate::serde::{load, save};

/// Default block size: 256 KiB.
///
/// Small enough that individual block writes are fast on network filesystems,
/// large enough that metadata overhead per block is negligible. A 1 GiB file
/// uses ~4096 blocks, which is manageable on any filesystem.
pub const DEFAULT_BLOCK_SIZE: u64 = 256 * 1024;

/// Checksum of a single block (BLAKE3, 256-bit).
pub type BlockHash = [u8; 32];

/// Manifest describing a file's block layout and integrity information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockManifest {
    /// Size of each block in bytes (padding to this size on the last block).
    pub block_size: u64,
    /// Number of data blocks in the file (= ceil(file_size / block_size)).
    pub num_blocks: u64,
    /// Total file size in bytes (may be less than num_blocks * block_size).
    pub file_size: u64,
    /// ECC configuration.
    pub ecc: EccConfig,
    /// BLAKE3 hash per data block. Index = block_idx.
    pub block_hashes: Vec<BlockHash>,
    /// BLAKE3 hash per group (hash of concatenated data block hashes in group).
    pub group_hashes: Vec<BlockHash>,
}

impl BlockManifest {
    pub fn new(block_size: u64, file_size: u64, ecc: EccConfig) -> Self {
        let num_blocks = if file_size == 0 {
            0
        } else {
            file_size.div_ceil(block_size)
        };
        let num_groups = if num_blocks == 0 {
            0
        } else {
            num_blocks.div_ceil(ecc.data_shards as u64)
        };
        Self {
            block_size,
            num_blocks,
            file_size,
            ecc,
            block_hashes: vec![[0u8; 32]; num_blocks as usize],
            group_hashes: vec![[0u8; 32]; num_groups as usize],
        }
    }

    pub fn num_groups(&self) -> u64 {
        self.group_hashes.len() as u64
    }

    /// Size of the block at `block_idx` in bytes.
    pub fn block_len(&self, block_idx: u64) -> usize {
        if block_idx >= self.num_blocks {
            return 0;
        }
        let start = block_idx * self.block_size;
        let end = (start + self.block_size).min(self.file_size);
        (end - start) as usize
    }
}

/// Manages chunked storage for a single inode's content.
pub struct BlockStore {
    _content_id: ContentId,
    /// Directory containing block files: contents/{encrypted(content_id)}/
    dir: PathBuf,
    ctrl: Controller,
    /// Current manifest (loaded from disk or created fresh).
    manifest: BlockManifest,
    /// Dirty blocks that haven't been written to disk yet.
    dirty: BTreeMap<u64, Option<Vec<u8>>>,
    /// ECC codec for this store.
    codec: EccCodec,
    /// Whether the manifest has been modified.
    _manifest_dirty: bool,
}

impl BlockStore {
    /// Open an existing block store for the given content ID.
    #[allow(dead_code)]
    pub fn open(ctrl: Controller, content_id: ContentId, file_size: u64) -> BkfsResult<Self> {
        let dir = ctrl.contents_dir_path(content_id);

        // Try loading existing manifest
        let manifest_path = dir.join("manifest");
        let (manifest, codec) = if manifest_path.exists() {
            let manifest: BlockManifest = load(EncryptedFile::open(
                fs::File::open(&manifest_path)?,
                ctrl.key(),
            )?)?;
            let codec = EccCodec::new(manifest.ecc);
            (manifest, codec)
        } else {
            // Fresh manifest
            let ecc = EccConfig::default();
            let manifest = BlockManifest::new(DEFAULT_BLOCK_SIZE, file_size, ecc);
            let codec = EccCodec::new(ecc);
            (manifest, codec)
        };

        Ok(Self {
            _content_id: content_id,
            dir,
            ctrl,
            manifest,
            dirty: BTreeMap::new(),
            codec,
            _manifest_dirty: false,
        })
    }

    /// Create a new block store for a newly created file.
    #[allow(dead_code)]
    pub fn create(ctrl: Controller, content_id: ContentId) -> BkfsResult<Self> {
        let dir = ctrl.contents_dir_path(content_id);
        fs::create_dir_all(&dir)?;
        let ecc = EccConfig::default();
        let block_size = DEFAULT_BLOCK_SIZE;
        let manifest = BlockManifest::new(block_size, 0, ecc);
        let codec = EccCodec::new(ecc);
        Ok(Self {
            _content_id: content_id,
            dir,
            ctrl,
            manifest,
            dirty: BTreeMap::new(),
            codec,
            _manifest_dirty: false,
        })
    }

    #[allow(dead_code)]
    pub fn manifest(&self) -> &BlockManifest {
        &self.manifest
    }

    /// Read bytes starting at `offset` into `buf`.
    #[allow(dead_code)]
    pub fn read(&mut self, buf: &mut [u8], offset: u64) -> BkfsResult<usize> {
        if buf.is_empty() || offset >= self.manifest.file_size {
            return Ok(0);
        }
        let valid_end = offset + buf.len() as u64;
        let end = valid_end.min(self.manifest.file_size);

        let block_size = self.manifest.block_size;
        let start_block = (offset / block_size) as u64;
        let end_block = ((end.saturating_sub(1)) / block_size) as u64;

        let mut dst_offset = 0;
        for block_idx in start_block..=end_block {
            let block_start = block_idx * block_size;
            let copy_start = if block_idx == start_block {
                (offset - block_start) as usize
            } else {
                0
            };
            let copy_end = if block_idx == end_block {
                ((end - block_start) as usize).min(block_size as usize)
            } else {
                self.manifest.block_len(block_idx)
            };

            if copy_start >= copy_end {
                continue;
            }
            let copy_len = copy_end - copy_start;

            // Check dirty cache first
            if let Some(Some(data)) = self.dirty.get(&block_idx) {
                let available = data.len().min(copy_end);
                let actual = (available - copy_start).min(copy_len);
                buf[dst_offset..dst_offset + actual]
                    .copy_from_slice(&data[copy_start..copy_start + actual]);
                dst_offset += actual;
            } else {
                // Read from disk
                let block_data =
                    self.read_block_from_disk(block_idx, self.manifest.block_len(block_idx))?;
                let available = block_data.len().min(copy_end);
                let actual = (available - copy_start).min(copy_len);
                if actual > 0 && copy_start < block_data.len() {
                    buf[dst_offset..dst_offset + actual]
                        .copy_from_slice(&block_data[copy_start..copy_start + actual]);
                    dst_offset += actual;
                }
            }
        }

        Ok(dst_offset)
    }

    /// Write bytes starting at `offset` from `buf`.
    /// Dirty blocks are buffered in memory; persistence happens on flush().
    #[allow(dead_code)]
    pub fn write(&mut self, buf: &[u8], offset: u64) -> BkfsResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let block_size = self.manifest.block_size;
        let start_block = (offset / block_size) as u64;
        let end = offset + buf.len() as u64;
        let end_block = ((end.saturating_sub(1)) / block_size) as u64;

        // Update file size if write extends beyond it
        if end > self.manifest.file_size {
            self.manifest.file_size = end;
            // Recalculate num_blocks
            self.manifest.num_blocks = end.div_ceil(block_size);
            // Extend block_hashes
            while self.manifest.block_hashes.len() < self.manifest.num_blocks as usize {
                self.manifest.block_hashes.push([0u8; 32]);
            }
            // Extend group_hashes
            let num_groups =
                self.manifest
                    .num_blocks
                    .div_ceil(self.manifest.ecc.data_shards as u64);
            while self.manifest.group_hashes.len() < num_groups as usize {
                self.manifest.group_hashes.push([0u8; 32]);
            }
        }

        let mut src_offset = 0;
        for block_idx in start_block..=end_block {
            let block_start = block_idx * block_size;
            let copy_start = if block_idx == start_block {
                (offset - block_start) as usize
            } else {
                0
            };
            let copy_end = ((end - block_start) as usize).min(block_size as usize);
            let copy_len = copy_end - copy_start;

            if copy_len == 0 {
                continue;
            }

            // Get or create the block buffer
            let need_load = !self.dirty.contains_key(&block_idx);
            if need_load {
                // Try loading from disk before borrowing self.dirty mutably
                let existing =
                    self.read_block_from_disk(block_idx, self.manifest.block_len(block_idx));
                let block_data = existing
                    .map(|mut data| {
                        if data.len() < block_size as usize {
                            data.resize(block_size as usize, 0);
                        }
                        data
                    })
                    .unwrap_or_else(|_| vec![0u8; block_size as usize]);
                self.dirty.insert(block_idx, Some(block_data));
            }

            let block = self.dirty.get_mut(&block_idx).unwrap();
            let block_data = block.as_mut().unwrap();
            if block_data.len() < copy_end {
                block_data.resize(copy_end.max(block_size as usize), 0);
            }

            block_data[copy_start..copy_start + copy_len]
                .copy_from_slice(&buf[src_offset..src_offset + copy_len]);
            src_offset += copy_len;
        }

        self._manifest_dirty = true;
        Ok(src_offset)
    }

    /// Read a single block from disk. Returns the full block content.
    fn read_block_from_disk(&self, block_idx: u64, expected_len: usize) -> BkfsResult<Vec<u8>> {
        use crate::error::BkfsResultExt;
        let path = self.block_path(block_idx, false, 0);
        if !path.exists() {
            return BkfsResult::errno_notrace(libc::ENOENT);
        }
        let file = fs::File::open(&path)?;
        let mut ef = EncryptedFile::open(file, self.ctrl.key())?;
        let mut buf = vec![0u8; expected_len.max(1)];
        ef.read_exact_at(&mut buf, 0)?;
        Ok(buf)
    }

    /// Compute path for a block file.
    fn block_path(&self, block_idx: u64, is_parity: bool, parity_idx: u8) -> PathBuf {
        if is_parity {
            let group = block_idx;
            self.dir.join(format!("p{group:08x}_{parity_idx}.blk"))
        } else {
            self.dir.join(format!("{block_idx:016x}.blk"))
        }
    }

    /// Compute BLAKE3 hash of a block's data.
    fn hash_block(data: &[u8]) -> BlockHash {
        *blake3::hash(data).as_bytes()
    }

    /// Flush dirty blocks to disk (fast path, no sync_all).
    /// Computes ECC parity for modified groups.
    #[allow(dead_code)]
    pub fn flush(&mut self) -> BkfsResult<()> {
        if self.dirty.is_empty() && !self._manifest_dirty {
            return Ok(());
        }

        // Ensure directory exists
        fs::create_dir_all(&self.dir)?;

        // Find which ECC groups have dirty blocks
        let data_shards = self.manifest.ecc.data_shards as u64;
        let parity_shards = self.manifest.ecc.parity_shards;
        let mut dirty_groups: BTreeMap<u64, bool> = BTreeMap::new();
        for &block_idx in self.dirty.keys() {
            let group = block_idx / data_shards;
            dirty_groups.entry(group).or_insert(false);
        }

        // Write dirty data blocks and compute their hashes
        let mut dirty_block_hashes: BTreeMap<u64, BlockHash> = BTreeMap::new();
        for (&block_idx, data_opt) in &self.dirty {
            if let Some(data) = data_opt {
                let actual_len = self.manifest.block_len(block_idx);
                let write_data = if actual_len < data.len() {
                    &data[..actual_len]
                } else {
                    data.as_slice()
                };
                let hash = Self::hash_block(write_data);
                dirty_block_hashes.insert(block_idx, hash);

                let enc_file = EncryptedFile::create(
                    AtomicFile::create(self.block_path(block_idx, false, 0))?,
                    self.ctrl.key(),
                )?;
                save(&write_data, enc_file)?;
            }
        }

        // Recompute ECC parity for groups with dirty blocks
        let block_size = self.manifest.block_size as usize;
        for (&group, _) in &dirty_groups {
            // Collect all data blocks for this group
            let base_idx = group * data_shards;
            let mut data_blocks: Vec<Vec<u8>> = Vec::with_capacity(self.manifest.ecc.data_shards);

            for shard in 0..self.manifest.ecc.data_shards {
                let block_idx = base_idx + shard as u64;
                if block_idx >= self.manifest.num_blocks {
                    // Past end of file — use an empty block
                    data_blocks.push(vec![0u8; block_size]);
                } else if let Some(Some(data)) = self.dirty.get(&block_idx) {
                    // Use dirty data
                    let mut padded = vec![0u8; block_size];
                    let copy_len = data.len().min(block_size);
                    padded[..copy_len].copy_from_slice(&data[..copy_len]);
                    data_blocks.push(padded);
                } else {
                    // Read from disk
                    let existing = self
                        .read_block_from_disk(
                            block_idx,
                            self.manifest.block_len(block_idx) as usize,
                        )
                        .unwrap_or_else(|_| vec![0u8; block_size]);
                    let mut padded = vec![0u8; block_size];
                    let copy_len = existing.len().min(block_size);
                    padded[..copy_len].copy_from_slice(&existing[..copy_len]);
                    data_blocks.push(padded);
                }
            }

            // Encode parity
            let encoded = self.codec.encode(&data_blocks);

            // Write parity blocks
            for p_idx in 0..parity_shards {
                let enc_file = EncryptedFile::create(
                    AtomicFile::create(self.block_path(group, true, p_idx as u8))?,
                    self.ctrl.key(),
                )?;
                save(&encoded.parity_shards()[p_idx], enc_file)?;
            }
        }

        // Update block hashes in manifest
        for (block_idx, hash) in &dirty_block_hashes {
            if (*block_idx as usize) < self.manifest.block_hashes.len() {
                self.manifest.block_hashes[*block_idx as usize] = *hash;
            }
        }

        // Recompute group hashes for dirty groups
        for (&group, _) in &dirty_groups {
            if (group as usize) < self.manifest.group_hashes.len() {
                let g_base = group * data_shards;
                let mut hasher = blake3::Hasher::new();
                for shard in 0..self.manifest.ecc.data_shards {
                    let bidx = (g_base + shard as u64) as usize;
                    if bidx < self.manifest.block_hashes.len() {
                        hasher.update(&self.manifest.block_hashes[bidx]);
                    }
                }
                self.manifest.group_hashes[group as usize] = *hasher.finalize().as_bytes();
            }
        }

        // Save manifest
        let enc_file = EncryptedFile::create(
            AtomicFile::create(self.dir.join("manifest"))?,
            self.ctrl.key(),
        )?;
        save(&self.manifest, enc_file)?;

        self.dirty.clear();
        self._manifest_dirty = false;

        self.ctrl.tick_save()?;
        Ok(())
    }

    /// Validate block integrity against manifest checksums.
    /// Returns list of corrupted block indices.
    #[allow(dead_code)]
    pub fn validate(&self) -> BkfsResult<Vec<u64>> {
        let mut corrupt = Vec::new();
        for block_idx in 0..self.manifest.num_blocks {
            // Read block and check hash
            match self
                .read_block_from_disk(block_idx, self.manifest.block_len(block_idx) as usize)
            {
                Ok(data) => {
                    let hash = Self::hash_block(&data);
                    if block_idx < self.manifest.block_hashes.len() as u64
                        && hash != self.manifest.block_hashes[block_idx as usize]
                        && self.manifest.block_hashes[block_idx as usize] != [0u8; 32]
                    {
                        corrupt.push(block_idx);
                    }
                }
                Err(_) => {
                    corrupt.push(block_idx);
                }
            }
        }
        Ok(corrupt)
    }

    /// Truncate file to the given size.
    #[allow(dead_code)]
    pub fn truncate(&mut self, size: u64) -> BkfsResult<()> {
        let old_num_blocks = self.manifest.num_blocks;
        self.manifest.file_size = size;
        self.manifest.num_blocks = if size == 0 {
            0
        } else {
            size.div_ceil(self.manifest.block_size)
        };

        // Remove blocks beyond new size from dirty cache
        self.dirty
            .retain(|&block_idx, _| block_idx < self.manifest.num_blocks);

        // Shrink block_hashes
        self.manifest
            .block_hashes
            .truncate(self.manifest.num_blocks as usize);

        // Shrink group_hashes
        let num_groups =
            self.manifest
                .num_blocks
                .div_ceil(self.manifest.ecc.data_shards as u64);
        self.manifest.group_hashes.truncate(num_groups as usize);

        // Remove excess block files from disk
        for block_idx in self.manifest.num_blocks.max(1)..old_num_blocks.max(1) {
            let path = self.block_path(block_idx, false, 0);
            if path.exists() {
                let _ = fs::remove_file(&path);
            }
        }

        // If we shrank across a group boundary, remove orphan parity blocks
        let old_num_groups =
            old_num_blocks.div_ceil(self.manifest.ecc.data_shards as u64);
        for group in num_groups.max(1)..old_num_groups.max(1) {
            for p_idx in 0..self.manifest.ecc.parity_shards {
                let path = self.block_path(group, true, p_idx as u8);
                if path.exists() {
                    let _ = fs::remove_file(&path);
                }
            }
        }

        self._manifest_dirty = true;
        Ok(())
    }

    /// Remove all block files for this content. Used when the inode is deleted.
    #[allow(dead_code)]
    pub fn remove_all(&self) -> BkfsResult<()> {
        if self.dir.exists() {
            fs::remove_dir_all(&self.dir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_manifest_new() {
        let manifest = BlockManifest::new(256 * 1024, 1024 * 1024, EccConfig::default());
        assert_eq!(manifest.num_blocks, 4);
        assert_eq!(manifest.file_size, 1024 * 1024);
        assert_eq!(manifest.block_hashes.len(), 4);
        assert_eq!(manifest.group_hashes.len(), 1); // 4 blocks / 8 data_shards = 1 group
    }

    #[test]
    fn block_manifest_small_file() {
        let manifest = BlockManifest::new(256 * 1024, 100, EccConfig::default());
        assert_eq!(manifest.num_blocks, 1);
        assert_eq!(manifest.block_len(0), 100);
        assert_eq!(manifest.block_len(1), 0);
    }

    #[test]
    fn block_manifest_empty() {
        let manifest = BlockManifest::new(256 * 1024, 0, EccConfig::default());
        assert_eq!(manifest.num_blocks, 0);
        assert_eq!(manifest.block_hashes.len(), 0);
        assert_eq!(manifest.group_hashes.len(), 0);
    }
}