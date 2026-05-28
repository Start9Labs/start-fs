use std::backtrace::Backtrace;
use std::cmp::min;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;

use chacha20::cipher::{Iv, KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key};
use pbkdf2::hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rng, RngCore};
use sha2::Sha256;

use crate::aligned_io::BufferedDirectFile;
use crate::atomic_file::AtomicFile;
use crate::chunk::{self, ChunkId, ChunkRef, FileContents, CHUNK_SIZE};
use crate::ctrl::Controller;
use crate::error::{BkfsError, BkfsErrorKind, BkfsResult, BkfsResultExt};
use crate::handle::Handler;
use crate::inode::{time_now, FileData, Inode, InodeAttributes};

/// A seekable ChaCha20 stream wrapper used for metadata files and cryptinfo.
/// Chunk payloads use the dedicated immutable chunk format in `chunk.rs`.
pub struct EncryptedFile<F: Read + Write + Seek + FileExt = BufferedDirectFile<File>> {
    file: F,
    offset: u64,
    cipher: ChaCha20,
}
impl<F: Read + Write + Seek + FileExt> EncryptedFile<F> {
    pub fn open(mut file: F, key: &Key) -> BkfsResult<Self> {
        let mut iv = Iv::<ChaCha20>::default();
        file.read_exact(iv.as_mut_slice())?;
        let cipher = ChaCha20::new(key, &iv);
        Ok(Self {
            file,
            offset: iv.len() as u64,
            cipher,
        })
    }
    pub fn create(mut file: F, key: &Key) -> BkfsResult<Self> {
        let mut iv = Iv::<ChaCha20>::default();
        rng().fill_bytes(iv.as_mut_slice());
        file.write_all(iv.as_slice())?;
        let cipher = ChaCha20::new(key, &iv);
        Ok(Self {
            file,
            offset: iv.len() as u64,
            cipher,
        })
    }
    pub fn open_pbkdf2(mut file: F, password: &str) -> BkfsResult<Self> {
        let mut iv = Iv::<ChaCha20>::default();
        file.read_exact(iv.as_mut_slice())?;
        let mut key = Key::default();
        pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            iv.as_slice(),
            600_000,
            key.as_mut_slice(),
        )
        .map_err(|_| BkfsError {
            kind: BkfsErrorKind::BadCrypt,
            backtrace: Some(Box::new(Backtrace::capture())),
        })?;
        let cipher = ChaCha20::new(&key, &iv);
        Ok(Self {
            file,
            offset: iv.len() as u64,
            cipher,
        })
    }
    pub fn create_pbkdf2(mut file: F, password: &str) -> BkfsResult<Self> {
        let mut iv = Iv::<ChaCha20>::default();
        rng().fill_bytes(iv.as_mut_slice());
        let mut key = Key::default();
        pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            iv.as_slice(),
            600_000,
            key.as_mut_slice(),
        )
        .map_err(|_| BkfsError {
            kind: BkfsErrorKind::BadCrypt,
            backtrace: Some(Box::new(Backtrace::capture())),
        })?;
        file.write_all(iv.as_slice())?;
        let cipher = ChaCha20::new(&key, &iv);
        Ok(Self {
            file,
            offset: iv.len() as u64,
            cipher,
        })
    }
    #[allow(dead_code)]
    pub fn read_exact_at(&mut self, mut buf: &mut [u8], mut offset: u64) -> BkfsResult<()> {
        while !buf.is_empty() {
            let len = match self.file.read_at(buf, offset + self.offset) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            };
            if len == 0 {
                break;
            }
            self.cipher.seek(offset);
            self.cipher.apply_keystream(&mut buf[..len]);
            buf = &mut buf[len..];
            offset += len as u64;
        }
        if !buf.is_empty() {
            buf.fill(0);
        }
        Ok(())
    }
    #[allow(dead_code)]
    pub fn write_all_at(&mut self, buf: &mut [u8], offset: u64) -> BkfsResult<()> {
        self.cipher.seek(offset);
        self.cipher.apply_keystream(buf);
        self.file.seek(SeekFrom::Start(offset + self.offset))?;
        self.file.write_all(buf)?;
        Ok(())
    }
}
impl EncryptedFile<BufferedDirectFile<AtomicFile>> {
    pub fn save(self) -> BkfsResult<()> {
        self.file.save()
    }
    pub fn save_fast(self) -> BkfsResult<()> {
        self.file.save_fast()
    }
}
impl EncryptedFile<AtomicFile> {
    pub fn save(self) -> BkfsResult<()> {
        self.file.save()
    }
    pub fn save_fast(self) -> BkfsResult<()> {
        self.file.save_fast()
    }
}
impl<F: Read + Write + Seek + FileExt> Read for EncryptedFile<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let pos = self.file.stream_position()?;
        let n = self.file.read(buf)?;
        self.cipher.seek(pos - self.offset);
        self.cipher.apply_keystream(&mut buf[..n]);
        Ok(n)
    }
}
impl<F: Read + Write + Seek + FileExt> Seek for EncryptedFile<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(n) => self.file.seek(SeekFrom::Start(n + self.offset)),
            s => self.file.seek(s),
        }
        .map(|s| s - self.offset)
    }
}
impl<F: Read + Write + Seek + FileExt> Write for EncryptedFile<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut write_buf = buf.to_vec();
        let pos = self.file.stream_position()?;
        self.cipher.seek(pos - self.offset);
        self.cipher.apply_keystream(&mut write_buf);
        self.file.write(&write_buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

pub struct Contents {
    pub inode: InodeAttributes,
    pub(crate) changed: bool,
    /// Dirty logical chunks, indexed by chunk number. Each value contains the
    /// visible bytes for that chunk; missing suffix bytes read as zeroes.
    dirty_chunks: BTreeMap<u64, Vec<u8>>,
    ctrl: Controller,
}

// Contents is moved into worker-pool jobs behind Arc<Mutex<_>>.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<Contents>();
};

impl Contents {
    pub fn open(ctrl: Controller, inode: Inode) -> BkfsResult<Self> {
        let attrs: InodeAttributes = ctrl.load(inode)?;
        Self::from_attrs(ctrl, attrs, false)
    }

    /// Open with attrs already in hand — e.g. from Handler's dirty cache.
    pub fn open_with_attrs(
        ctrl: Controller,
        attrs: InodeAttributes,
        dirty: bool,
    ) -> BkfsResult<Self> {
        Self::from_attrs(ctrl, attrs, dirty)
    }

    fn from_attrs(ctrl: Controller, inode: InodeAttributes, changed: bool) -> BkfsResult<Self> {
        match &inode.attrs.contents {
            FileData::File(_) => Ok(Self {
                inode,
                changed,
                dirty_chunks: BTreeMap::new(),
                ctrl,
            }),
            FileData::Directory(_) => BkfsResult::errno(libc::EISDIR),
            FileData::Symlink(_) | FileData::Special(_) => BkfsResult::errno(libc::EINVAL),
        }
    }

    fn manifest(&self) -> &FileContents {
        match &self.inode.attrs.contents {
            FileData::File(contents) => contents,
            _ => unreachable!("Contents opened for non-file inode"),
        }
    }

    fn manifest_mut(&mut self) -> &mut FileContents {
        match &mut self.inode.attrs.contents {
            FileData::File(contents) => contents,
            _ => unreachable!("Contents opened for non-file inode"),
        }
    }

    fn load_chunk_visible(&self, index: u64) -> BkfsResult<Vec<u8>> {
        let Some(reference) = self.manifest().chunk(index) else {
            return Ok(Vec::new());
        };
        let stored = self.ctrl.read_chunk(reference)?;
        let mut visible = stored;
        visible.resize(reference.visible_len as usize, 0);
        Ok(visible)
    }

    fn chunk_for_write(
        &mut self,
        index: u64,
        write_start: usize,
        write_end: usize,
    ) -> BkfsResult<&mut Vec<u8>> {
        if !self.dirty_chunks.contains_key(&index) {
            let mut chunk = if write_start == 0 && write_end >= CHUNK_SIZE {
                Vec::new()
            } else {
                self.load_chunk_visible(index)?
            };
            if chunk.len() < write_end {
                chunk.resize(write_end, 0);
            }
            self.dirty_chunks.insert(index, chunk);
        }
        let chunk = self.dirty_chunks.get_mut(&index).unwrap();
        if chunk.len() < write_end {
            chunk.resize(write_end, 0);
        }
        Ok(chunk)
    }

    pub fn read_exact_at(&mut self, mut buf: &mut [u8], mut offset: u64) -> BkfsResult<()> {
        if offset + buf.len() as u64 > self.inode.attrs.size {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }

        while !buf.is_empty() {
            let index = offset / CHUNK_SIZE as u64;
            let chunk_off = (offset % CHUNK_SIZE as u64) as usize;
            let len = min(buf.len(), CHUNK_SIZE - chunk_off);
            let out = &mut buf[..len];
            out.fill(0);

            if let Some(dirty) = self.dirty_chunks.get(&index) {
                if chunk_off < dirty.len() {
                    let n = min(len, dirty.len() - chunk_off);
                    out[..n].copy_from_slice(&dirty[chunk_off..chunk_off + n]);
                }
            } else if let Some(reference) = self.manifest().chunk(index) {
                if chunk_off < reference.visible_len as usize {
                    let stored = self.ctrl.read_chunk(reference)?;
                    let available = min(
                        len,
                        (reference.visible_len as usize - chunk_off)
                            .min(stored.len().saturating_sub(chunk_off)),
                    );
                    if available > 0 {
                        out[..available].copy_from_slice(&stored[chunk_off..chunk_off + available]);
                    }
                }
            }

            buf = &mut buf[len..];
            offset += len as u64;
        }

        if !self.ctrl.config().readonly {
            self.inode.attrs.atime = time_now();
            self.changed = true;
        }
        Ok(())
    }

    pub fn write_all_at(&mut self, buf: &mut [u8], mut offset: u64) -> BkfsResult<()> {
        self.ctrl.check_rw()?;
        let mut input: &[u8] = buf;
        while !input.is_empty() {
            let index = offset / CHUNK_SIZE as u64;
            let chunk_off = (offset % CHUNK_SIZE as u64) as usize;
            let len = min(input.len(), CHUNK_SIZE - chunk_off);
            let chunk = self.chunk_for_write(index, chunk_off, chunk_off + len)?;
            chunk[chunk_off..chunk_off + len].copy_from_slice(&input[..len]);

            input = &input[len..];
            offset += len as u64;
        }

        let end = offset;
        self.inode.attrs.modified();
        if end > self.inode.attrs.size {
            self.inode.attrs.size = end;
        }
        self.changed = true;
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
        let punch = libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_ZERO_RANGE;
        if mode & !(libc::FALLOC_FL_KEEP_SIZE | punch) != 0 {
            return BkfsResult::errno(libc::EOPNOTSUPP);
        }
        let end = offset.saturating_add(length);
        if mode & punch != 0 {
            // Materialize a zero write over the requested range. This preserves
            // sparse semantics in the manifest because flush later drops chunks
            // that become all-zero after trimming.
            let original_size = self.inode.attrs.size;
            let mut remaining = length;
            let mut pos = offset;
            let zeros = vec![0_u8; 128 * 1024];
            while remaining > 0 {
                let n = min(remaining as usize, zeros.len());
                let mut slice = zeros[..n].to_vec();
                self.write_all_at(&mut slice, pos)?;
                pos += n as u64;
                remaining -= n as u64;
            }
            if keep_size {
                self.inode.attrs.size = original_size;
                self.prune_dirty_to_size();
            }
        } else if !keep_size && end > self.inode.attrs.size {
            self.inode.attrs.size = end;
            self.inode.attrs.modified();
            self.changed = true;
        }
        Ok(())
    }

    fn prune_dirty_to_size(&mut self) {
        let size = self.inode.attrs.size;
        let keep_chunks = size.div_ceil(CHUNK_SIZE as u64);
        self.dirty_chunks.retain(|idx, chunk| {
            if *idx >= keep_chunks {
                return false;
            }
            let start = *idx * CHUNK_SIZE as u64;
            let visible = min(CHUNK_SIZE as u64, size - start) as usize;
            if chunk.len() > visible {
                chunk.truncate(visible);
            }
            true
        });
    }

    /// Write dirty immutable chunks and update the in-memory inode manifest,
    /// but leave persisting the inode to the caller.
    fn flush_chunks_only(&mut self) -> BkfsResult<()> {
        self.prune_dirty_to_size();
        let size = self.inode.attrs.size;
        if self.manifest_mut().truncate_to_size(size) {
            self.changed = true;
        }

        let dirty = std::mem::take(&mut self.dirty_chunks);
        for (index, mut data) in dirty {
            let chunk_start = index * CHUNK_SIZE as u64;
            if chunk_start >= self.inode.attrs.size {
                self.manifest_mut().set_chunk(index, None);
                self.changed = true;
                continue;
            }

            let visible_len = min(CHUNK_SIZE as u64, self.inode.attrs.size - chunk_start) as usize;
            data.truncate(visible_len);
            let mut stored = data.clone();
            chunk::trim_trailing_zeroes(&mut stored);

            let new_ref = if stored.is_empty() {
                None
            } else {
                let hash = chunk::plaintext_hash(&stored);
                let existing = self.manifest().chunk(index);
                if existing.is_some_and(|old| {
                    old.stored_len as usize == stored.len()
                        && old.visible_len as usize == visible_len
                        && old.hash == hash
                }) {
                    existing.cloned()
                } else {
                    let id = ChunkId::random();
                    self.ctrl.write_chunk(id, &stored)?;
                    self.ctrl.tick_save()?;
                    Some(ChunkRef {
                        id,
                        stored_len: stored.len() as u32,
                        visible_len: visible_len as u32,
                        hash,
                    })
                }
            };

            if self.manifest().chunk(index) != new_ref.as_ref() {
                self.manifest_mut().set_chunk(index, new_ref);
                self.changed = true;
            }
        }

        let size = self.inode.attrs.size;
        if self.manifest_mut().truncate_to_size(size) {
            self.changed = true;
        }

        Ok(())
    }

    /// Persist content chunks and inode metadata through the batched fast-save
    /// path. A later syncfs/fsyncdir/destroy turns the batch durable.
    pub fn flush(&mut self) -> BkfsResult<()> {
        self.flush_chunks_only()?;
        if self.changed {
            self.ctrl.save_fast(&self.inode)?;
            self.ctrl.tick_save()?;
            self.changed = false;
        }
        Ok(())
    }

    pub fn fsync(&mut self) -> BkfsResult<()> {
        self.flush()?;
        self.ctrl.syncfs()?;
        Ok(())
    }

    pub fn truncate(&mut self, size: u64) {
        self.inode.attrs.size = size;
        if self.manifest_mut().truncate_to_size(size) {
            self.changed = true;
        }
        self.prune_dirty_to_size();
    }

    pub fn close(mut self, handler: &mut Handler) -> BkfsResult<()> {
        // Write new chunk objects now, but route the inode save through the
        // dirty cache so rsync's post-close setattr sequence coalesces.
        self.flush_chunks_only()?;
        let attrs = self.inode.clone();
        let changed = self.changed;
        drop(self);
        if !handler.gc_inode(&attrs)? && changed {
            handler.save_inode(&attrs)?;
        }
        Ok(())
    }
}
