use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

pub struct AtomicFile {
    tmp_path: PathBuf,
    path: PathBuf,
    file: Option<File>,
}
impl AtomicFile {
    pub fn new(path: PathBuf, opt: &OpenOptions) -> io::Result<Self> {
        let tmp_path = path.with_extension("tmp");
        let file = opt.open(&tmp_path)?;
        Ok(Self {
            tmp_path,
            path,
            file: Some(file),
        })
    }

    pub fn create(path: PathBuf) -> io::Result<Self> {
        Self::new(
            path,
            &OpenOptions::new().write(true).truncate(true).create(true),
        )
    }

    pub fn rollback(mut self) -> io::Result<()> {
        drop(self.file.take());
        std::fs::remove_file(&self.tmp_path)?;
        Ok(())
    }

    pub fn save(mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()?;
            file.sync_all()?;
        }
        drop(self.file.take());
        std::fs::rename(&self.tmp_path, &self.path)?;
        Ok(())
    }
}
impl Deref for AtomicFile {
    type Target = File;
    fn deref(&self) -> &Self::Target {
        self.file.as_ref().unwrap()
    }
}
impl DerefMut for AtomicFile {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.file.as_mut().unwrap()
    }
}
impl Drop for AtomicFile {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            drop(file);
            let path = std::mem::take(&mut self.tmp_path);
            if let Err(e) = std::fs::remove_file(path) {
                log::error!("failed to clean up tmp file: {e}");
            }
        }
    }
}
impl Read for AtomicFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.deref_mut().read(buf)
    }
    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.deref_mut().read_vectored(bufs)
    }
    // fn read_buf(&mut self, buf: io::BorrowedCursor<'_>) -> io::Result<()> {
    //     self.deref_mut().read_buf(buf)
    // }
    // fn is_read_vectored(&self) -> bool {
    //     self.deref_mut().is_read_vectored()
    // }
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.deref_mut().read_to_end(buf)
    }
    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        self.deref_mut().read_to_string(buf)
    }
}
impl Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.deref_mut().write(buf)
    }
    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.deref_mut().write_vectored(bufs)
    }
    // fn is_write_vectored(&self) -> bool {
    //     self.deref_mut().is_write_vectored()
    // }
    fn flush(&mut self) -> io::Result<()> {
        self.deref_mut().flush()
    }
}
impl Seek for AtomicFile {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        self.deref_mut().seek(pos)
    }
}
impl FileExt for AtomicFile {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        self.deref().read_at(buf, offset)
    }
    // fn read_vectored_at(&self, bufs: &mut [io::IoSliceMut<'_>], offset: u64) -> io::Result<usize> {
    //     self.deref_mut().read_vectored_at(bufs, offset)
    // }
    fn write_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        self.deref().write_at(buf, offset)
    }
    // fn write_vectored_at(&self, bufs: &[io::IoSlice<'_>], offset: u64) -> io::Result<usize> {
    //     self.deref_mut().write_vectored_at(bufs, offset)
    // }
}
