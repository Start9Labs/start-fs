//! Per-file content access.
//!
//! [`Contents`] presents a regular file's byte stream over one of two
//! storage bodies:
//!
//! * **Inline** — a small file (≤ [`inline_threshold`]) whose bytes live
//!   directly in its inode record in the log. No separate content file at
//!   all: a tiny file costs zero extra backing-store objects.
//! * **Blocks** — a larger file split into [`CHUNK_SIZE`] sealed block files
//!   (see [`crate::blockstore`]), read-modify-written a whole block at a time
//!   so a partial write never rewrites a sub-region of an on-disk object.
//!
//! A file is created inline and transitions to block storage the first time
//! it grows past the threshold (one-way; a file that was large stays
//! block-backed even if later truncated small).

use std::collections::BTreeMap;
use std::io;
use std::sync::OnceLock;

use rand::{rng, RngCore};

use crate::blockstore::{self, CHUNK_SIZE};
use crate::ctrl::Controller;
use crate::error::{BkfsResult, BkfsResultExt};
use crate::handle::Handler;
use crate::inode::{time_now, ContentId, FileData, Inode, InodeAttributes};

/// Files at or below this size are stored inline in their inode record;
/// larger files use block storage. Default 4 KiB (one filesystem block) —
/// large enough to absorb the long tail of tiny files (dotfiles, configs,
/// symlink-ish data) where the per-object cost dominates, small enough that
/// re-appending the inode record on a metadata change stays cheap.
/// Overridable via `BACKUPFS_INLINE_MAX`; capped at `CHUNK_SIZE`.
pub fn inline_threshold() -> u64 {
    static T: OnceLock<u64> = OnceLock::new();
    *T.get_or_init(|| {
        std::env::var("BACKUPFS_INLINE_MAX")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(4096)
            .min(CHUNK_SIZE)
    })
}

/// Soft cap on per-file in-memory dirty *block* data. With `FOPEN_DIRECT_IO`
/// the kernel streams writes straight to us and never triggers a writeback,
/// so without a cap a large sequential write would buffer the entire file in
/// our heap. Once exceeded, completed low blocks are written out (fast path)
/// and dropped, bounding memory and pipelining I/O. `BACKUPFS_WRITE_BUFFER`.
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

enum Body {
    /// Whole file content, mirrored into `inode.attrs.contents` as
    /// `FileData::Inline` on flush.
    Inline(Vec<u8>),
    Blocks {
        content_id: ContentId,
        /// Block index → logical bytes (≤ `CHUNK_SIZE`), loaded lazily for RMW.
        dirty: BTreeMap<u64, Vec<u8>>,
        dirty_bytes: usize,
        /// Blocks believed to exist on disk (for trailing-block prune).
        disk_blocks: u64,
    },
}

pub struct Contents {
    pub inode: InodeAttributes,
    pub(crate) changed: bool,
    body: Body,
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
    /// dirty cache. `changed` carries unpersisted metadata forward.
    pub fn open_with_attrs(
        ctrl: Controller,
        attrs: InodeAttributes,
        changed: bool,
    ) -> BkfsResult<Self> {
        Self::from_attrs(ctrl, attrs, changed)
    }

    fn from_attrs(ctrl: Controller, inode: InodeAttributes, changed: bool) -> BkfsResult<Self> {
        let body = match &inode.attrs.contents {
            FileData::Inline(bytes) => {
                // Trim any size-obfuscation padding back to the logical size
                // so it can't accumulate across flush/remount cycles.
                let mut b = bytes.clone();
                b.truncate(inode.attrs.size as usize);
                Body::Inline(b)
            }
            FileData::File(cid) => Body::Blocks {
                content_id: *cid,
                dirty: BTreeMap::new(),
                dirty_bytes: 0,
                disk_blocks: blockstore::block_count(inode.attrs.size),
            },
            FileData::Directory(_) => return BkfsResult::errno(libc::EISDIR),
            _ => return BkfsResult::errno(libc::EINVAL),
        };
        Ok(Self { inode, changed, body, ctrl })
    }

    fn size(&self) -> u64 {
        self.inode.attrs.size
    }

    // ── reads ──────────────────────────────────────────────

    pub fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> BkfsResult<()> {
        let end = offset + buf.len() as u64;
        if end > self.size() {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        match &self.body {
            Body::Inline(data) => {
                // `off` is clamped to the stored length: bytes in
                // [data.len(), size) are holes (e.g. after a truncate-grow)
                // and read back as zeros. Clamping also avoids slicing past
                // the end (which would panic in a worker and wedge the op).
                let off = (offset as usize).min(data.len());
                let copy = buf.len().min(data.len() - off);
                buf[..copy].copy_from_slice(&data[off..off + copy]);
                for b in &mut buf[copy..] {
                    *b = 0;
                }
            }
            Body::Blocks { .. } => self.read_blocks_at(buf, offset)?,
        }
        self.inode.attrs.atime = time_now();
        self.changed = true;
        Ok(())
    }

    fn read_blocks_at(&self, buf: &mut [u8], offset: u64) -> BkfsResult<()> {
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
            for b in &mut dst[copy..] {
                *b = 0;
            }
            filled += take;
        }
        Ok(())
    }

    /// Logical valid length of block `idx` given the current file size.
    fn valid_len(&self, idx: u64) -> usize {
        let start = idx * CHUNK_SIZE;
        if start >= self.size() {
            0
        } else {
            ((self.size() - start).min(CHUNK_SIZE)) as usize
        }
    }

    fn load_block(&self, idx: u64) -> BkfsResult<Vec<u8>> {
        let Body::Blocks { content_id, dirty, .. } = &self.body else {
            return Ok(Vec::new());
        };
        if let Some(buf) = dirty.get(&idx) {
            return Ok(buf.clone());
        }
        let valid = self.valid_len(idx);
        let mut buf = blockstore::read_block(&self.ctrl, *content_id, idx)?.unwrap_or_default();
        if buf.len() < valid {
            buf.resize(valid, 0);
        }
        Ok(buf)
    }

    // ── writes ─────────────────────────────────────────────

    pub fn write_all_at(&mut self, buf: &[u8], offset: u64) -> BkfsResult<()> {
        self.ctrl.check_rw()?;
        let end = offset + buf.len() as u64;

        if let Body::Inline(_) = &self.body {
            if end <= inline_threshold() {
                let Body::Inline(data) = &mut self.body else { unreachable!() };
                if (data.len() as u64) < end {
                    data.resize(end as usize, 0);
                }
                data[offset as usize..end as usize].copy_from_slice(buf);
                self.inode.attrs.modified();
                if end > self.inode.attrs.size {
                    self.inode.attrs.size = end;
                }
                self.changed = true;
                return Ok(());
            }
            // Grows past the inline threshold → migrate to block storage,
            // then fall through to the block write path below.
            self.inline_to_blocks()?;
        }

        self.write_blocks_at(buf, offset)?;
        self.inode.attrs.modified();
        if end > self.inode.attrs.size {
            self.inode.attrs.size = end;
        }
        self.changed = true;
        self.spill_to_budget()?;
        Ok(())
    }

    fn write_blocks_at(&mut self, buf: &[u8], offset: u64) -> BkfsResult<()> {
        let content_id = match &self.body {
            Body::Blocks { content_id, .. } => *content_id,
            Body::Inline(_) => unreachable!("inline must be migrated before block write"),
        };
        let mut written = 0usize;
        while written < buf.len() {
            let pos = offset + written as u64;
            let (idx, within) = blockstore::locate(pos);
            let take = (buf.len() - written).min(CHUNK_SIZE as usize - within);
            let valid = self.valid_len(idx);
            let Body::Blocks { dirty, dirty_bytes, .. } = &mut self.body else { unreachable!() };
            let mut block = match dirty.remove(&idx) {
                Some(b) => {
                    *dirty_bytes -= b.len();
                    b
                }
                None => {
                    let mut b = blockstore::read_block(&self.ctrl, content_id, idx)?
                        .unwrap_or_default();
                    b.truncate(valid);
                    b
                }
            };
            if block.len() < within + take {
                block.resize(within + take, 0);
            }
            block[within..within + take].copy_from_slice(&buf[written..written + take]);
            let Body::Blocks { dirty, dirty_bytes, .. } = &mut self.body else { unreachable!() };
            *dirty_bytes += block.len();
            dirty.insert(idx, block);
            written += take;
        }
        Ok(())
    }

    /// Migrate an inline file to block storage, preserving its bytes as the
    /// initial dirty blocks. Content id is the (never-reused) inode number.
    fn inline_to_blocks(&mut self) -> BkfsResult<()> {
        let Body::Inline(data) = &mut self.body else { return Ok(()) };
        let data = std::mem::take(data);
        let content_id = ContentId(self.inode.inode.0);
        let mut dirty = BTreeMap::new();
        let mut dirty_bytes = 0usize;
        for (i, chunk) in data.chunks(CHUNK_SIZE as usize).enumerate() {
            dirty_bytes += chunk.len();
            dirty.insert(i as u64, chunk.to_vec());
        }
        self.body = Body::Blocks { content_id, dirty, dirty_bytes, disk_blocks: 0 };
        self.inode.attrs.contents = FileData::File(content_id);
        Ok(())
    }

    fn spill_to_budget(&mut self) -> BkfsResult<()> {
        let budget = write_buffer_budget();
        let content_id = match &self.body {
            Body::Blocks { content_id, .. } => *content_id,
            Body::Inline(_) => return Ok(()),
        };
        loop {
            let idx = {
                let Body::Blocks { dirty, dirty_bytes, .. } = &self.body else { return Ok(()) };
                if *dirty_bytes <= budget || dirty.len() <= 1 {
                    return Ok(());
                }
                *dirty.keys().next().unwrap()
            };
            let valid = self.valid_len(idx);
            let Body::Blocks { dirty, dirty_bytes, disk_blocks, .. } = &mut self.body else {
                return Ok(());
            };
            let mut block = dirty.remove(&idx).unwrap();
            *dirty_bytes -= block.len();
            *disk_blocks = (*disk_blocks).max(idx + 1);
            block.truncate(valid);
            blockstore::write_block(&self.ctrl, content_id, idx, &block, false)?;
            self.ctrl.tick_save()?;
        }
    }

    pub fn fallocate(
        &mut self,
        offset: u64,
        length: u64,
        mode: i32,
        keep_size: bool,
    ) -> BkfsResult<()> {
        self.ctrl.check_rw()?;
        if mode & (libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_ZERO_RANGE) != 0 {
            let mut remaining = length;
            let mut pos = offset;
            let zeros = vec![0u8; CHUNK_SIZE as usize];
            while remaining > 0 {
                let within = (pos % CHUNK_SIZE) as usize;
                let take = (remaining as usize).min(CHUNK_SIZE as usize - within);
                if pos < self.size() {
                    let cap = ((self.size() - pos) as usize).min(take);
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

    // ── flush / close ──────────────────────────────────────

    pub fn flush(&mut self) -> BkfsResult<()> {
        self.flush_content_only()?;
        if self.changed {
            self.ctrl.save_fast(&self.inode)?;
            self.ctrl.tick_save()?;
            self.changed = false;
        }
        Ok(())
    }

    /// Reconcile the body to disk and into `inode.attrs.contents`, but don't
    /// persist the inode record itself — the caller routes that.
    fn flush_content_only(&mut self) -> BkfsResult<()> {
        // A setattr/truncate may have changed size out from under an inline
        // body; reconcile, migrating to blocks if it grew past the threshold.
        if let Body::Inline(data) = &mut self.body {
            if self.inode.attrs.size > inline_threshold() {
                // Grew past the threshold (e.g. a truncate-grow): migrate the
                // *existing* bytes to block 0 and fall through to the block
                // flush. Bytes beyond `data` stay holes (sparse) — never
                // materialized, so a huge set_len can't OOM us.
                self.inline_to_blocks()?;
            } else {
                // size ≤ threshold, so this resize is bounded and cheap.
                // CLONE (don't drain): the inline buffer is the file's only
                // copy of its content, so a later flush (fsync then close)
                // must still find it. Draining it would persist empty bytes.
                data.resize(self.inode.attrs.size as usize, 0);
                self.inode.attrs.contents = FileData::Inline(data.clone());
                return Ok(());
            }
        }

        let required = blockstore::block_count(self.inode.attrs.size);
        let (content_id, dirty, disk_blocks) = match &mut self.body {
            Body::Blocks { content_id, dirty, dirty_bytes, disk_blocks } => {
                *dirty_bytes = 0;
                (*content_id, std::mem::take(dirty), *disk_blocks)
            }
            Body::Inline(_) => return Ok(()),
        };
        let last = required.saturating_sub(1);
        for (idx, mut block) in dirty {
            if idx >= required {
                continue; // past EOF; pruned below
            }
            block.truncate(self.valid_len(idx));
            if idx == last {
                self.pad_final_inline(&mut block);
            }
            blockstore::write_block(&self.ctrl, content_id, idx, &block, false)?;
            self.ctrl.tick_save()?;
        }
        for idx in required..disk_blocks {
            blockstore::remove_block(&self.ctrl, content_id, idx)?;
        }
        if let Body::Blocks { disk_blocks, .. } = &mut self.body {
            *disk_blocks = required;
        }
        Ok(())
    }

    /// Optionally pad stored bytes with random data to obscure the exact
    /// size (the `--file-size-padding` knob). Never affects logical reads.
    fn pad_final_inline(&self, bytes: &mut Vec<u8>) {
        let padded = self.ctrl.file_pad(bytes.len() as u64) as usize;
        if padded > bytes.len() {
            let start = bytes.len();
            bytes.resize(padded, 0);
            rng().fill_bytes(&mut bytes[start..]);
        }
    }

    pub fn fsync(&mut self) -> BkfsResult<()> {
        self.flush()?;
        self.ctrl.syncfs()?;
        Ok(())
    }

    pub fn close(mut self, handler: &mut Handler) -> BkfsResult<()> {
        self.flush_content_only()?;
        let attrs = self.inode.clone();
        let changed = self.changed;
        drop(self);
        if !handler.gc_inode(&attrs)? && changed {
            handler.save_inode(&attrs)?;
        }
        Ok(())
    }
}
