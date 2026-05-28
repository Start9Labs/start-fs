//! Per-file content access over the block store.
//!
//! [`Contents`] presents a regular file's byte stream on top of the
//! fixed-size sealed blocks managed by [`crate::blockstore`]. It buffers
//! dirty blocks in memory and reconciles them to disk on flush, doing
//! read-modify-write at block granularity so a partial write only ever
//! rewrites whole blocks — never a sub-region of an existing on-disk file.

use std::collections::BTreeMap;
use std::io;
use std::sync::OnceLock;

use rand::{rng, RngCore};

use crate::blockstore::{self, CHUNK_SIZE};
use crate::ctrl::Controller;
use crate::error::{BkfsResult, BkfsResultExt};
use crate::handle::Handler;
use crate::inode::{time_now, ContentId, FileData, Inode, InodeAttributes};

/// Soft cap on per-file in-memory dirty data. With `FOPEN_DIRECT_IO` the
/// kernel streams writes straight to us and never triggers a writeback, so
/// without a cap a single large sequential write would buffer the *entire*
/// file in our heap before anything reached the backing store — defeating
/// the whole point of avoiding kernel page-cache buildup, and serializing
/// all crypto/ECC/I/O into one burst at close. Once the buffer exceeds this,
/// completed low blocks are sealed and written out (fast path, batched
/// syncfs), bounding memory and pipelining I/O with the incoming writes.
/// Overridable via `BACKUPFS_WRITE_BUFFER` (bytes).
fn write_buffer_budget() -> usize {
    static BUDGET: OnceLock<usize> = OnceLock::new();
    *BUDGET.get_or_init(|| {
        std::env::var("BACKUPFS_WRITE_BUFFER")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&n| n >= CHUNK_SIZE as usize)
            .unwrap_or(16 * 1024 * 1024)
    })
}

pub struct Contents {
    pub inode: InodeAttributes,
    content_id: ContentId,
    pub(crate) changed: bool,
    /// Blocks with unpersisted modifications: block index → logical bytes
    /// (length ≤ `CHUNK_SIZE`). A block is loaded here lazily on first
    /// write that touches it (read-modify-write).
    dirty: BTreeMap<u64, Vec<u8>>,
    /// Running total of `dirty`'s block byte lengths, kept in sync so the
    /// spill threshold is an O(1) check.
    dirty_bytes: usize,
    /// Number of blocks believed to exist on disk. Initialized from the
    /// inode's size on open and updated on every flush, so flush knows
    /// which trailing blocks to delete after a shrink/truncate.
    disk_blocks: u64,
    ctrl: Controller,
}

// Contents is owned by an Arc<Mutex<_>> shared with the worker pool — keep
// the compile-time Send assertion the old design relied on.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<Contents>();
};

impl Contents {
    pub fn open(ctrl: Controller, inode: Inode) -> BkfsResult<Self> {
        let attrs: InodeAttributes = ctrl.load(inode)?;
        Self::from_attrs(ctrl, attrs, false)
    }

    /// Open with attrs already in hand — e.g. taken from the Handler's
    /// dirty cache. `changed` carries unpersisted metadata forward so the
    /// eventual flush writes it.
    pub fn open_with_attrs(
        ctrl: Controller,
        attrs: InodeAttributes,
        changed: bool,
    ) -> BkfsResult<Self> {
        Self::from_attrs(ctrl, attrs, changed)
    }

    fn from_attrs(ctrl: Controller, inode: InodeAttributes, changed: bool) -> BkfsResult<Self> {
        let content_id = match &inode.attrs.contents {
            FileData::File(a) => *a,
            FileData::Directory(_) => return BkfsResult::errno(libc::EISDIR),
            FileData::Symlink(_) => return BkfsResult::errno(libc::EINVAL),
            _ => return BkfsResult::errno(libc::EINVAL),
        };
        let disk_blocks = blockstore::block_count(inode.attrs.size);
        Ok(Self {
            inode,
            content_id,
            changed,
            dirty: BTreeMap::new(),
            dirty_bytes: 0,
            disk_blocks,
            ctrl,
        })
    }

    /// Logical valid length of block `idx` given the current file size.
    fn valid_len(&self, idx: u64) -> usize {
        let start = idx * CHUNK_SIZE;
        if start >= self.inode.attrs.size {
            0
        } else {
            ((self.inode.attrs.size - start).min(CHUNK_SIZE)) as usize
        }
    }

    /// Fetch a block's current logical bytes from the dirty cache or disk,
    /// zero-filled to its valid length. Holes (absent on disk) read as
    /// zeros.
    fn load_block(&self, idx: u64) -> BkfsResult<Vec<u8>> {
        if let Some(buf) = self.dirty.get(&idx) {
            return Ok(buf.clone());
        }
        let valid = self.valid_len(idx);
        let mut buf = blockstore::read_block(&self.ctrl, self.content_id, idx)?.unwrap_or_default();
        if buf.len() < valid {
            buf.resize(valid, 0);
        }
        Ok(buf)
    }

    pub fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> BkfsResult<()> {
        let end = offset + buf.len() as u64;
        if end > self.inode.attrs.size {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        let mut filled = 0usize;
        while filled < buf.len() {
            let pos = offset + filled as u64;
            let (idx, within) = blockstore::locate(pos);
            let block = self.load_block(idx)?;
            let take = (buf.len() - filled).min(CHUNK_SIZE as usize - within);
            let dst = &mut buf[filled..filled + take];
            let avail = block.len().saturating_sub(within);
            let copy = take.min(avail);
            dst[..copy].copy_from_slice(&block[within..within + copy]);
            // Bytes past the block's stored length are holes → already
            // zeroed in `dst` (buffers arrive zeroed from the read path).
            for b in &mut dst[copy..] {
                *b = 0;
            }
            filled += take;
        }
        self.inode.attrs.atime = time_now();
        self.changed = true;
        Ok(())
    }

    pub fn write_all_at(&mut self, buf: &[u8], offset: u64) -> BkfsResult<()> {
        self.ctrl.check_rw()?;
        let end = offset + buf.len() as u64;
        let mut written = 0usize;
        while written < buf.len() {
            let pos = offset + written as u64;
            let (idx, within) = blockstore::locate(pos);
            let take = (buf.len() - written).min(CHUNK_SIZE as usize - within);
            // Read-modify-write: pull the existing block (or a hole) into
            // the dirty cache, then overlay the new bytes.
            let mut block = match self.dirty.remove(&idx) {
                Some(b) => {
                    self.dirty_bytes -= b.len();
                    b
                }
                None => {
                    let valid = self.valid_len(idx);
                    let mut b =
                        blockstore::read_block(&self.ctrl, self.content_id, idx)?.unwrap_or_default();
                    b.truncate(valid);
                    b
                }
            };
            if block.len() < within + take {
                block.resize(within + take, 0);
            }
            block[within..within + take].copy_from_slice(&buf[written..written + take]);
            self.dirty_bytes += block.len();
            self.dirty.insert(idx, block);
            written += take;
        }
        self.inode.attrs.modified();
        if end > self.inode.attrs.size {
            self.inode.attrs.size = end;
        }
        self.changed = true;
        self.spill_to_budget()?;
        Ok(())
    }

    /// Bound in-memory dirty data: while over budget, seal and write out the
    /// lowest-indexed dirty block (fast path; durability rides the batched
    /// syncfs) and drop it from the cache. The highest block — the active
    /// write frontier — is always kept so sequential appends keep coalescing
    /// in memory. A spilled block that is touched again is transparently
    /// reloaded via read-modify-write.
    fn spill_to_budget(&mut self) -> BkfsResult<()> {
        let budget = write_buffer_budget();
        while self.dirty_bytes > budget && self.dirty.len() > 1 {
            let idx = *self.dirty.keys().next().unwrap();
            let mut block = self.dirty.remove(&idx).unwrap();
            self.dirty_bytes -= block.len();
            block.truncate(self.valid_len(idx));
            blockstore::write_block(&self.ctrl, self.content_id, idx, &block, false)?;
            self.ctrl.tick_save()?;
            self.disk_blocks = self.disk_blocks.max(idx + 1);
        }
        Ok(())
    }

    pub fn fallocate(
        &mut self,
        offset: u64,
        length: u64,
        mode: i32,
        keep_size: bool,
    ) -> BkfsResult<()> {
        self.ctrl.check_rw()?;
        let punch = mode & (libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_ZERO_RANGE) != 0;
        if punch {
            // Zero the range via read-modify-write. (We zero rather than
            // delete whole blocks so partial edges stay correct; fully
            // covered blocks are dropped lazily on the next shrink.)
            let mut remaining = length;
            let mut pos = offset;
            let zeros = vec![0u8; CHUNK_SIZE as usize];
            while remaining > 0 {
                let within = (pos % CHUNK_SIZE) as usize;
                let take = (remaining as usize).min(CHUNK_SIZE as usize - within);
                // Don't extend the file for a pure hole-punch.
                if pos < self.inode.attrs.size {
                    let cap = ((self.inode.attrs.size - pos) as usize).min(take);
                    self.write_all_at(&zeros[..cap], pos)?;
                }
                pos += take as u64;
                remaining -= take as u64;
            }
        }
        if !keep_size {
            let new_end = offset + length;
            if new_end > self.inode.attrs.size {
                self.inode.attrs.size = new_end;
            }
            self.inode.attrs.modified();
            self.changed = true;
        }
        Ok(())
    }

    /// Write all dirty blocks (fast path) and prune blocks past EOF, then
    /// persist the inode (fast). Durability is the caller's batched
    /// `syncfs` — see `Controller::tick_save`.
    pub fn flush(&mut self) -> BkfsResult<()> {
        self.flush_content_only()?;
        if self.changed {
            self.ctrl.save_fast(&self.inode)?;
            self.ctrl.tick_save()?;
            self.changed = false;
        }
        Ok(())
    }

    /// Flush content blocks (fast), prune trailing blocks after a shrink,
    /// but don't persist the inode — the caller routes that itself.
    fn flush_content_only(&mut self) -> BkfsResult<()> {
        let required = blockstore::block_count(self.inode.attrs.size);
        let dirty = std::mem::take(&mut self.dirty);
        self.dirty_bytes = 0;
        let last = required.saturating_sub(1);
        for (idx, mut block) in dirty {
            if idx >= required {
                // Block lies entirely past the (possibly shrunk) EOF; it
                // will be removed by the prune loop below.
                continue;
            }
            block.truncate(self.valid_len(idx));
            if idx == last {
                self.pad_final_block(&mut block);
            }
            blockstore::write_block(&self.ctrl, self.content_id, idx, &block, false)?;
            self.ctrl.tick_save()?;
        }
        // Remove blocks beyond the current size (truncate / shrink).
        for idx in required..self.disk_blocks {
            blockstore::remove_block(&self.ctrl, self.content_id, idx)?;
        }
        self.disk_blocks = required;
        Ok(())
    }

    /// Optionally pad the final block's stored plaintext with random bytes
    /// to obscure the exact file size (the `--file-size-padding` knob).
    /// Padding never affects logical reads, which are bounded by the inode
    /// size.
    fn pad_final_block(&self, block: &mut Vec<u8>) {
        let padded = self.ctrl.file_pad(block.len() as u64) as usize;
        if padded > block.len() {
            let start = block.len();
            block.resize(padded, 0);
            rng().fill_bytes(&mut block[start..]);
        }
    }

    /// User-requested fsync: flush everything, then `syncfs` so the whole
    /// batch reaches stable storage.
    pub fn fsync(&mut self) -> BkfsResult<()> {
        self.flush()?;
        self.ctrl.syncfs()?;
        Ok(())
    }

    pub fn close(mut self, handler: &mut Handler) -> BkfsResult<()> {
        // Write content fast, then hand the inode save to the dirty cache
        // so rsync's post-close chmod/chown/utime trio coalesces onto a
        // single disk write.
        self.flush_content_only()?;
        let attrs = self.inode.clone();
        let changed = self.changed;
        // Drop so the Weak in handler.inodes has strong_count == 0 and
        // gc_inode can collect if this was the last reference.
        drop(self);
        if !handler.gc_inode(&attrs)? && changed {
            handler.save_inode(&attrs)?;
        }
        Ok(())
    }
}
