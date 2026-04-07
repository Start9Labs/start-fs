use std::alloc::{self, Layout};
use std::cell::RefCell;
use std::fs::{File, Metadata};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::ptr;

use crate::atomic_file::AtomicFile;
use crate::error::BkfsResult;

const BLOCK_SIZE: usize = 4096;
const ALIGN_MASK: usize = BLOCK_SIZE - 1;
const BUF_CAP: usize = 1 << 20; // 1 MiB
const FLUSH_CHUNK: usize = 64 * 1024; // 64 KiB per SQE

// ── Aligned buffer ────────────────────────────────────

/// A buffer with guaranteed 4096-byte alignment for O_DIRECT I/O.
struct AlignedBuf {
    ptr: ptr::NonNull<u8>,
    len: usize,
}

unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    fn new(len: usize) -> Self {
        let len = (len + ALIGN_MASK) & !ALIGN_MASK;
        let len = len.max(BLOCK_SIZE);
        let layout = Layout::from_size_align(len, BLOCK_SIZE).unwrap();
        let ptr = unsafe { alloc::alloc_zeroed(layout) };
        let ptr = ptr::NonNull::new(ptr).unwrap_or_else(|| alloc::handle_alloc_error(layout));
        Self { ptr, len }
    }

    fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        let layout = Layout::from_size_align(self.len, BLOCK_SIZE).unwrap();
        unsafe { alloc::dealloc(self.ptr.as_ptr(), layout) };
    }
}

// ── Low-level aligned I/O ─────────────────────────────

fn align_down(v: u64) -> u64 {
    v & !(BLOCK_SIZE as u64 - 1)
}

/// Perform a full pread, retrying on EINTR.
fn pread_full<F: FileExt>(file: &F, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    let mut pos = 0;
    while pos < buf.len() {
        match file.read_at(&mut buf[pos..], offset + pos as u64) {
            Ok(0) => break,
            Ok(n) => pos += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(pos)
}

// ── io_uring pipelined flush ──────────────────────────

/// Submit all chunks as pwrite SQEs, then reap completions.
fn uring_pwrite_all(fd: RawFd, buf: &[u8], offset: u64) -> io::Result<()> {
    use io_uring::{opcode, types, IoUring};

    if buf.is_empty() {
        return Ok(());
    }

    let n_chunks = (buf.len() + FLUSH_CHUNK - 1) / FLUSH_CHUNK;
    let mut ring = IoUring::new(n_chunks as u32)?;

    // Submit all chunks
    {
        let mut sq = ring.submission();
        for (i, chunk) in buf.chunks(FLUSH_CHUNK).enumerate() {
            let off = offset + (i * FLUSH_CHUNK) as u64;
            let entry = opcode::Write::new(types::Fd(fd), chunk.as_ptr(), chunk.len() as u32)
                .offset(off)
                .build()
                .user_data(i as u64);
            // SAFETY: the buffer is alive for the duration of this function,
            // and we wait for all completions before returning.
            unsafe { sq.push(&entry) }.map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "io_uring submission queue full")
            })?;
        }
    }
    ring.submit_and_wait(n_chunks)?;

    // Reap completions
    let cq = ring.completion();
    let mut errors: Option<io::Error> = None;
    let mut completed = 0;
    for cqe in cq {
        completed += 1;
        let ret = cqe.result();
        if ret < 0 {
            errors.get_or_insert(io::Error::from_raw_os_error(-ret));
        }
    }
    if completed < n_chunks {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "io_uring: not all writes completed",
        ));
    }
    if let Some(e) = errors {
        return Err(e);
    }
    Ok(())
}

// ── Buffered direct-I/O file ──────────────────────────

struct BufState {
    buf: AlignedBuf,
    /// File offset that buf[0] maps to (block-aligned). u64::MAX = no window loaded.
    base: u64,
    /// Bytes in the buffer that contain valid data (from disk or writes).
    valid: usize,
    /// First dirty byte in the buffer (usize::MAX when clean).
    dirty_start: usize,
    /// One-past-last dirty byte.
    dirty_end: usize,
    /// Sequential read/write cursor (absolute file offset).
    pos: u64,
}

/// Wraps an O_DIRECT file descriptor with a 1 MiB write-back buffer.
///
/// All actual disk I/O goes through the aligned internal buffer, satisfying
/// O_DIRECT's alignment requirements for buffer address, file offset, and
/// I/O size transparently. Flushes are pipelined via io_uring.
pub struct BufferedDirectFile<F: FileExt + AsRawFd> {
    file: Option<F>,
    state: RefCell<BufState>,
}

impl<F: FileExt + AsRawFd> BufferedDirectFile<F> {
    pub fn new(file: F) -> Self {
        Self {
            file: Some(file),
            state: RefCell::new(BufState {
                buf: AlignedBuf::new(BUF_CAP),
                base: u64::MAX, // sentinel: no window loaded
                valid: 0,
                dirty_start: usize::MAX,
                dirty_end: 0,
                pos: 0,
            }),
        }
    }

    fn file(&self) -> &F {
        self.file.as_ref().unwrap()
    }

    /// Flush dirty bytes to disk via io_uring pipelined writes.
    fn flush_dirty(state: &mut BufState, file: &F) -> io::Result<()> {
        if state.dirty_start >= state.dirty_end {
            return Ok(());
        }
        let start = state.dirty_start & !ALIGN_MASK;
        let end = ((state.dirty_end + ALIGN_MASK) & !ALIGN_MASK).min(state.buf.len());
        let buf = &state.buf.as_slice()[start..end];
        uring_pwrite_all(file.as_raw_fd(), buf, state.base + start as u64)?;
        state.dirty_start = usize::MAX;
        state.dirty_end = 0;
        Ok(())
    }

    /// Load a new window starting at the block containing `offset`.
    fn load_window(state: &mut BufState, file: &F, offset: u64) -> io::Result<()> {
        state.base = align_down(offset);
        state.valid = pread_full(file, state.buf.as_mut_slice(), state.base)?;
        state.dirty_start = usize::MAX;
        state.dirty_end = 0;
        Ok(())
    }

    /// Reset window without reading from disk. Used on the write path to
    /// avoid an O_DIRECT read (which can deadlock CIFS for regions beyond EOF).
    fn reset_window(state: &mut BufState, offset: u64) {
        state.base = align_down(offset);
        state.valid = 0;
        state.dirty_start = usize::MAX;
        state.dirty_end = 0;
    }

    /// Ensure the buffer window covers `offset` for reading. Flushes and reloads.
    fn ensure_window_read(state: &mut BufState, file: &F, offset: u64) -> io::Result<()> {
        if offset >= state.base && offset - state.base < BUF_CAP as u64 {
            return Ok(());
        }
        Self::flush_dirty(state, file)?;
        Self::load_window(state, file, offset)
    }

    /// Ensure the buffer window covers `offset` for writing. Flushes dirty data
    /// but does NOT read the new window from disk.
    fn ensure_window_write(state: &mut BufState, file: &F, offset: u64) -> io::Result<()> {
        if offset >= state.base && offset - state.base < BUF_CAP as u64 {
            return Ok(());
        }
        Self::flush_dirty(state, file)?;
        Self::reset_window(state, offset);
        Ok(())
    }
}

impl<F: FileExt + AsRawFd> Drop for BufferedDirectFile<F> {
    fn drop(&mut self) {
        if let Some(file) = &self.file {
            let state = self.state.get_mut();
            let _ = Self::flush_dirty(state, file);
        }
    }
}

impl<F: FileExt + AsRawFd> FileExt for BufferedDirectFile<F> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.borrow_mut();
        Self::ensure_window_read(&mut state, self.file(), offset)?;
        let off = (offset - state.base) as usize;
        let available = state.valid.saturating_sub(off);
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&state.buf.as_slice()[off..off + n]);
        Ok(n)
    }

    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.borrow_mut();
        Self::ensure_window_write(&mut state, self.file(), offset)?;
        let off = (offset - state.base) as usize;
        let space = BUF_CAP - off;
        let n = buf.len().min(space);
        state.buf.as_mut_slice()[off..off + n].copy_from_slice(&buf[..n]);
        state.dirty_start = state.dirty_start.min(off);
        state.dirty_end = state.dirty_end.max(off + n);
        state.valid = state.valid.max(off + n);
        Ok(n)
    }
}

impl<F: FileExt + AsRawFd> Read for BufferedDirectFile<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let file = self.file.as_ref().unwrap();
        let state = self.state.get_mut();
        Self::ensure_window_read(state, file, state.pos)?;
        let off = (state.pos - state.base) as usize;
        let available = state.valid.saturating_sub(off);
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&state.buf.as_slice()[off..off + n]);
        state.pos += n as u64;
        Ok(n)
    }
}

impl<F: FileExt + AsRawFd> Write for BufferedDirectFile<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let file = self.file.as_ref().unwrap();
        let state = self.state.get_mut();
        Self::ensure_window_write(state, file, state.pos)?;
        let off = (state.pos - state.base) as usize;
        let space = BUF_CAP - off;
        let n = buf.len().min(space);
        state.buf.as_mut_slice()[off..off + n].copy_from_slice(&buf[..n]);
        state.dirty_start = state.dirty_start.min(off);
        state.dirty_end = state.dirty_end.max(off + n);
        state.valid = state.valid.max(off + n);
        state.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let file = self.file.as_ref().unwrap();
        let state = self.state.get_mut();
        Self::flush_dirty(state, file)
    }
}

impl<F: FileExt + AsRawFd> Seek for BufferedDirectFile<F> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let state = self.state.get_mut();
        state.pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(n) => {
                if n >= 0 {
                    state.pos.checked_add(n as u64)
                } else {
                    state.pos.checked_sub(n.unsigned_abs())
                }
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid seek"))?
            }
            SeekFrom::End(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "SeekFrom::End not supported on BufferedDirectFile",
                ));
            }
        };
        Ok(state.pos)
    }
}

// ── Type-specific methods ─────────────────────────────

impl BufferedDirectFile<File> {
    pub fn metadata(&self) -> io::Result<Metadata> {
        self.file().metadata()
    }
}

impl BufferedDirectFile<AtomicFile> {
    pub fn save(mut self) -> BkfsResult<()> {
        self.flush()?;
        // Take the file so Drop doesn't double-flush
        self.file.take().unwrap().save()
    }

    pub fn set_len(&mut self, size: u64) -> io::Result<()> {
        let file = self.file.as_ref().unwrap();
        let state = self.state.get_mut();
        Self::flush_dirty(state, file)?;
        // Invalidate — file geometry changed
        state.base = u64::MAX;
        state.valid = 0;
        self.file.as_ref().unwrap().set_len(size)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file().deref().as_raw_fd()
    }
}
