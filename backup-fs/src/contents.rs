use std::backtrace::Backtrace;
use std::cmp::{max, min};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::PathBuf;

use chacha20::cipher::{Iv, KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key};
use itertools::Itertools;
use pbkdf2::hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rng, RngCore};
use sha2::Sha256;
use smallvec::SmallVec;

use crate::aligned_io::BufferedDirectFile;
use crate::atomic_file::AtomicFile;
use crate::ctrl::Controller;
use crate::error::{BkfsError, BkfsErrorKind, BkfsResult, BkfsResultExt};
use crate::handle::Handler;
use crate::inode::{time_now, ContentId, FileData, Inode, InodeAttributes};
use crate::open_direct;
use crate::util::RandReader;

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
            kind: crate::error::BkfsErrorKind::BadCrypt,
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
            kind: crate::error::BkfsErrorKind::BadCrypt,
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

pub struct MergedFile {
    src: EncryptedFile,
    dst: EncryptedFile<BufferedDirectFile<AtomicFile>>,
    written: BTreeMap<u64, u64>, // position, len
}
impl MergedFile {
    fn new(src: EncryptedFile, dst: PathBuf, key: &Key) -> BkfsResult<Self> {
        let dst = EncryptedFile::create(
            BufferedDirectFile::new(AtomicFile::new(
                dst,
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .truncate(true)
                    .create(true)
                    .custom_flags(libc::O_DIRECT),
            )?)?,
            key,
        )?;
        Ok(Self {
            src,
            dst,
            written: BTreeMap::new(),
        })
    }
    fn read_ranges(
        &self,
        pos: u64,
        len: u64,
    ) -> (SmallVec<[Range<u64>; 1]>, SmallVec<[Range<u64>; 1]>) {
        let end = pos + len;
        let mut src_start = pos;
        let mut src = SmallVec::new();
        let mut dst = SmallVec::new();

        if let Some(dst_end) = self
            .written
            .range(..pos)
            .rev()
            .next()
            .map(|(p, l)| *p + *l)
            .filter(|end| *end > pos)
        {
            dst.push(pos..dst_end);
            src_start = dst_end;
        }

        for (p, l) in self.written.range(pos..end) {
            if src_start < *p {
                src.push(src_start..*p);
            }
            let dst_end = min(*p + *l, end);
            dst.push(*p..dst_end);
            src_start = dst_end;
        }

        if src_start < end {
            src.push(src_start..end);
        }

        (src, dst)
    }
    fn add_written(&mut self, pos: u64, len: u64) {
        let end = pos + len;
        let to_remove = self
            .written
            .range(pos..end)
            .map(|(p, l)| (*p, *l))
            .collect_vec();
        if let Some((p, l)) = self
            .written
            .range_mut(..=pos)
            .rev()
            .next()
            .filter(|(p, l)| **p + **l >= pos)
        {
            let dst_end = *p + *l;
            if dst_end > end {
                return;
            } else {
                *l = end - *p;
                for (np, nl) in &to_remove {
                    *l = max(*l, *np + *nl - p);
                }
            }
        } else {
            let mut end = end;
            for (p, l) in &to_remove {
                end = max(end, *p + *l);
            }
            self.written.insert(pos, end - pos);
        }
        for (p, _) in to_remove {
            self.written.remove(&p);
        }
    }
    fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> BkfsResult<()> {
        let (src, dst) = self.read_ranges(offset, buf.len() as u64);
        for range in src {
            let buf_range = ((range.start - offset) as usize)..((range.end - offset) as usize);
            self.src.read_exact_at(&mut buf[buf_range], range.start)?;
        }
        for range in dst {
            let buf_range = ((range.start - offset) as usize)..((range.end - offset) as usize);
            self.dst.read_exact_at(&mut buf[buf_range], range.start)?;
        }
        Ok(())
    }
    fn write_all_at(&mut self, buf: &mut [u8], offset: u64) -> BkfsResult<()> {
        self.dst.write_all_at(buf, offset)?;
        self.add_written(offset, buf.len() as u64);
        Ok(())
    }
    /// Drain `src` into `dst`, truncate to `size`. Leaves the inner
    /// destination staged but not yet renamed into place.
    fn finalize(&mut self, size: u64) -> BkfsResult<()> {
        let mut remaining = size;
        let mut start = 0_u64;
        let mut len;
        for (p, l) in &self.written {
            if start < *p {
                len = min(*p - start, remaining);
                self.src.seek(SeekFrom::Start(start))?;
                self.dst.seek(SeekFrom::Start(start))?;
                io::copy(
                    &mut ((&mut self.src).chain(io::repeat(0)).take(len)),
                    &mut self.dst,
                )?;
            }
            start = *p + *l;
            if start >= size {
                break;
            }
            remaining = size - start;
        }
        if start < size {
            len = size - start;
            self.src.seek(SeekFrom::Start(start))?;
            self.dst.seek(SeekFrom::Start(start))?;
            io::copy(
                &mut ((&mut self.src)
                    .chain(RandReader::new_crypto(rng())) // pad with randomness
                    .take(len)),
                &mut self.dst,
            )?;
        } else if start > size {
            self.dst.file.set_len(size + self.dst.offset)?;
        }
        Ok(())
    }

    /// Drain and rename without a per-file sync_all. Durability is
    /// deferred to the caller's batched syncfs — see
    /// `Controller::tick_save` / `Controller::syncfs`.
    fn save_fast(mut self, size: u64) -> BkfsResult<()> {
        self.finalize(size)?;
        drop(self.src);
        self.dst.save_fast()?;
        Ok(())
    }
}

pub struct Contents {
    pub inode: InodeAttributes,
    content_id: ContentId,
    pub(crate) changed: bool,
    file: Option<Result<MergedFile, EncryptedFile>>,
    ctrl: Controller,
}

// Contents will be owned by an Arc<Mutex<_>> shared with the worker
// pool — if any field regresses to a !Send type we want to fail the
// build here rather than at the dispatch site.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<Contents>();
};

impl Contents {
    pub fn open(ctrl: Controller, inode: Inode) -> BkfsResult<Self> {
        let attrs: InodeAttributes = ctrl.load(inode)?;
        Self::from_attrs(ctrl, attrs, false)
    }
    /// Open with attrs already in hand — e.g. taken from Handler's dirty
    /// cache. `dirty` carries the unpersisted state forward so Contents::fsync
    /// will eventually write it.
    pub fn open_with_attrs(
        ctrl: Controller,
        attrs: InodeAttributes,
        dirty: bool,
    ) -> BkfsResult<Self> {
        Self::from_attrs(ctrl, attrs, dirty)
    }
    fn from_attrs(ctrl: Controller, inode: InodeAttributes, changed: bool) -> BkfsResult<Self> {
        let content_id = match &inode.attrs.contents {
            FileData::File(a) => *a,
            FileData::Directory(_) => return BkfsResult::errno(libc::EISDIR),
            FileData::Symlink(_) => return BkfsResult::errno(libc::EINVAL),
        };
        Ok(Self {
            inode,
            content_id,
            changed,
            file: None,
            ctrl,
        })
    }
    fn init_content_file(&self, path: &std::path::Path) -> BkfsResult<()> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let mut init = EncryptedFile::create(open_direct(path, true)?, self.ctrl.key())?;
        init.file.flush()?;
        Ok(())
    }
    pub fn readable(&mut self) -> BkfsResult<&mut Self> {
        if self.file.is_none() {
            let path = self.ctrl.resolve_contents_path(self.content_id);
            self.file = Some(Err(match open_direct(&path, false)
                .map_err(BkfsError::from)
                .and_then(|f| EncryptedFile::open(f, self.ctrl.key()))
            {
                Ok(f) => f,
                Err(e)
                    if matches!(
                        &e.kind,
                        BkfsErrorKind::Io(io) if matches!(io.kind(), io::ErrorKind::NotFound | io::ErrorKind::UnexpectedEof)
                    ) =>
                {
                    let path = self.ctrl.contents_path(self.content_id);
                    self.init_content_file(&path)?;
                    EncryptedFile::open(open_direct(&path, false)?, self.ctrl.key())?
                }
                Err(e) => return Err(e),
            }));
        }
        Ok(self)
    }
    pub fn writable(&mut self) -> BkfsResult<&mut Self> {
        self.ctrl.check_rw()?;
        if self.file.as_ref().map_or(false, |f| f.is_ok()) {
            return Ok(self);
        }
        if let Some(Err(file)) = std::mem::take(&mut self.readable()?.file) {
            self.file = Some(Ok(MergedFile::new(
                file,
                self.ctrl.contents_path(self.content_id),
                self.ctrl.key(),
            )?));
            Ok(self)
        } else {
            Ok(self)
        }
    }
    pub fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> BkfsResult<()> {
        if offset + buf.len() as u64 > self.inode.attrs.size {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        match self
            .readable()?
            .file
            .as_mut()
            .unwrap_or_else(|| unreachable!("file is uninitialized"))
        {
            Err(file) => file.read_exact_at(buf, offset)?,
            Ok(file) => file.read_exact_at(buf, offset)?,
        }
        self.inode.attrs.atime = time_now();
        self.changed = true;
        Ok(())
    }
    pub fn write_all_at(&mut self, buf: &mut [u8], offset: u64) -> BkfsResult<()> {
        let this = self.writable()?;
        let file = this
            .file
            .as_mut()
            .unwrap_or_else(|| unreachable!("file is uninitialized"))
            .as_mut()
            .unwrap_or_else(|_| unreachable!("file is readonly"));
        file.write_all_at(buf, offset)?;
        let end = offset + buf.len() as u64;
        this.inode.attrs.modified();
        if end > this.inode.attrs.size {
            this.inode.attrs.size = end;
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
        let this = self.writable()?;
        let file = this
            .file
            .as_mut()
            .unwrap_or_else(|| unreachable!("file is uninitialized"))
            .as_mut()
            .unwrap_or_else(|_| unreachable!("file is readonly"));
        let fd = file.dst.file.as_raw_fd();
        let res = unsafe { libc::fallocate64(fd, mode, offset as i64, length as i64) };
        if res != 0 {
            return Err(io::Error::from_raw_os_error(res).into());
        }
        if !keep_size {
            let end = offset + length;
            this.inode.attrs.modified();
            if end > this.inode.attrs.size {
                this.inode.attrs.size = end;
            }
            self.changed = true;
        }
        Ok(())
    }
    /// Drain pending writes to disk via the fast path (no per-file
    /// sync_all). Both the content file and the inode go through a
    /// batched syncfs — see `Controller::tick_save`. Returns the
    /// newly-saved inode attrs if a content write happened so the
    /// caller can route the metadata save appropriately.
    pub fn flush(&mut self) -> BkfsResult<()> {
        if let Some(Ok(f)) = std::mem::take(&mut self.file) {
            let size = self.ctrl.file_pad(min(
                self.inode.attrs.size,
                max(
                    f.src.file.metadata()?.len(),
                    f.written.last_key_value().map_or(0, |(p, l)| *p + *l),
                ),
            ));
            f.save_fast(size)?;
            self.ctrl.tick_save()?;
        }
        if self.changed {
            self.ctrl.save_fast(&self.inode)?;
            self.ctrl.tick_save()?;
            self.changed = false;
        }
        Ok(())
    }

    /// User-requested fsync: flush then syncfs. Forces everything
    /// accumulated across all fast saves to stable storage, not just
    /// this file — that's exactly what the kernel documentation
    /// suggests syncfs is for, and it matches what rsync / cp
    /// actually need after a large batch.
    pub fn fsync(&mut self) -> BkfsResult<()> {
        self.flush()?;
        self.ctrl.syncfs()?;
        Ok(())
    }

    pub fn truncate(&mut self, size: u64) {
        self.inode.attrs.size = size;
    }
    pub fn close(mut self, handler: &mut Handler) -> BkfsResult<()> {
        // Write the content file fast, then hand the inode save to the
        // dirty cache so subsequent setattrs (rsync's post-close
        // chmod/chown/utime trio) coalesce onto the same disk write.
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

    /// Flush content data (fast path), but don't persist the inode —
    /// the caller will route that through the dirty cache.
    fn flush_content_only(&mut self) -> BkfsResult<()> {
        if let Some(Ok(f)) = std::mem::take(&mut self.file) {
            let size = self.ctrl.file_pad(min(
                self.inode.attrs.size,
                max(
                    f.src.file.metadata()?.len(),
                    f.written.last_key_value().map_or(0, |(p, l)| *p + *l),
                ),
            ));
            f.save_fast(size)?;
            self.ctrl.tick_save()?;
        }
        Ok(())
    }
}
