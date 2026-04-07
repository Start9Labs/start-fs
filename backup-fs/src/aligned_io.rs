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

/// Perform a full pwrite, retrying on EINTR.
fn pwrite_full<F: FileExt>(file: &F, buf: &[u8], offset: u64) -> io::Result<()> {
    let mut pos = 0;
    while pos < buf.len() {
        match file.write_at(&buf[pos..], offset + pos as u64) {
            Ok(0) => {
                return Err(io::Error::new(io::ErrorKind::WriteZero, "write_at returned 0"))
            }
            Ok(n) => pos += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
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
/// I/O size transparently.
pub struct BufferedDirectFile<F> {
    file: F,
    state: RefCell<BufState>,
}

impl<F: FileExt> BufferedDirectFile<F> {
    pub fn new(file: F) -> Self {
        Self {
            file,
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

    /// Flush dirty bytes to disk as a single aligned pwrite.
    fn flush_dirty(state: &mut BufState, file: &F) -> io::Result<()> {
        if state.dirty_start >= state.dirty_end {
            return Ok(());
        }
        let start = state.dirty_start & !ALIGN_MASK;
        let end = ((state.dirty_end + ALIGN_MASK) & !ALIGN_MASK).min(state.buf.len());
        pwrite_full(file, &state.buf.as_slice()[start..end], state.base + start as u64)?;
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

    /// Ensure the buffer window covers `offset`. Flushes and reloads if needed.
    fn ensure_window(state: &mut BufState, file: &F, offset: u64) -> io::Result<()> {
        if offset >= state.base && offset - state.base < BUF_CAP as u64 {
            return Ok(());
        }
        Self::flush_dirty(state, file)?;
        Self::load_window(state, file, offset)
    }
}

impl<F: FileExt> FileExt for BufferedDirectFile<F> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.borrow_mut();
        Self::ensure_window(&mut state, &self.file, offset)?;
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
        Self::ensure_window(&mut state, &self.file, offset)?;
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

impl<F: FileExt> Read for BufferedDirectFile<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let state = self.state.get_mut();
        Self::ensure_window(state, &self.file, state.pos)?;
        let off = (state.pos - state.base) as usize;
        let available = state.valid.saturating_sub(off);
        let n = buf.len().min(available);
        buf[..n].copy_from_slice(&state.buf.as_slice()[off..off + n]);
        state.pos += n as u64;
        Ok(n)
    }
}

impl<F: FileExt> Write for BufferedDirectFile<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let state = self.state.get_mut();
        Self::ensure_window(state, &self.file, state.pos)?;
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
        let state = self.state.get_mut();
        Self::flush_dirty(state, &self.file)
    }
}

impl<F: FileExt> Seek for BufferedDirectFile<F> {
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
        self.file.metadata()
    }
}

impl BufferedDirectFile<AtomicFile> {
    pub fn save(mut self) -> BkfsResult<()> {
        self.flush()?;
        self.file.save()
    }

    pub fn set_len(&mut self, size: u64) -> io::Result<()> {
        let state = self.state.get_mut();
        Self::flush_dirty(state, &self.file)?;
        // Invalidate — file geometry changed
        state.base = u64::MAX;
        state.valid = 0;
        self.file.set_len(size)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file.deref().as_raw_fd()
    }
}
