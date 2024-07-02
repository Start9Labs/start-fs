use std::cmp::{max, min};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::{DerefMut, Range};
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use chacha20::cipher::{Iv, KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key};
use itertools::Itertools;
use pbkdf2::hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{thread_rng, RngCore};
use sha2::Sha256;
use smallvec::SmallVec;

use crate::atomic_file::AtomicFile;
use crate::ctrl::Controller;
use crate::handle::Handler;
use crate::inode::{time_now, ContentId, FileData, Inode, InodeAttributes};
use crate::util::RandReader;

pub struct EncryptedFile<F: Read + Write + Seek + FileExt = File> {
    file: F,
    offset: u64,
    cipher: ChaCha20,
}
impl<F: Read + Write + Seek + FileExt> EncryptedFile<F> {
    pub fn open(mut file: F, key: &Key) -> io::Result<Self> {
        let mut iv = Iv::<ChaCha20>::default();
        file.read_exact(iv.as_mut_slice())?;
        let cipher = ChaCha20::new(key, &iv);
        Ok(Self {
            file,
            offset: iv.len() as u64,
            cipher,
        })
    }
    pub fn create(mut file: F, key: &Key) -> io::Result<Self> {
        let mut iv = Iv::<ChaCha20>::default();
        rand::thread_rng().fill_bytes(iv.as_mut_slice());
        file.write_all(iv.as_slice())?;
        let cipher = ChaCha20::new(key, &iv);
        Ok(Self {
            file,
            offset: iv.len() as u64,
            cipher,
        })
    }
    pub fn open_pbkdf2(mut file: F, password: &str) -> io::Result<Self> {
        let mut iv = Iv::<ChaCha20>::default();
        file.read_exact(iv.as_mut_slice())?;
        let mut key = Key::default();
        pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            iv.as_slice(),
            600_000,
            key.as_mut_slice(),
        )
        .map_err(io::Error::other)?;
        let cipher = ChaCha20::new(&key, &iv);
        Ok(Self {
            file,
            offset: iv.len() as u64,
            cipher,
        })
    }
    pub fn create_pbkdf2(mut file: F, password: &str) -> io::Result<Self> {
        let mut iv = Iv::<ChaCha20>::default();
        rand::thread_rng().fill_bytes(iv.as_mut_slice());
        let mut key = Key::default();
        pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            iv.as_slice(),
            600_000,
            key.as_mut_slice(),
        )
        .map_err(io::Error::other)?;
        file.write_all(iv.as_slice())?;
        let cipher = ChaCha20::new(&key, &iv);
        Ok(Self {
            file,
            offset: iv.len() as u64,
            cipher,
        })
    }
    pub fn read_exact_at(&mut self, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
        while !buf.is_empty() {
            let len = match self.file.read_at(buf, offset + self.offset) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
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
    pub fn write_all_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.cipher.seek(offset);
        self.cipher.apply_keystream(buf);
        self.file.seek(SeekFrom::Start(offset + self.offset))?;
        self.file.write_all(buf)?;
        Ok(())
    }
}
impl EncryptedFile<AtomicFile> {
    pub fn save(self) -> io::Result<()> {
        self.file.save()
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
    dst: EncryptedFile<AtomicFile>,
    written: BTreeMap<u64, u64>, // position, len
}
impl MergedFile {
    fn new(src: EncryptedFile, dst: PathBuf, key: &Key) -> io::Result<Self> {
        let dst = EncryptedFile::create(
            AtomicFile::new(
                dst,
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .truncate(true)
                    .create(true),
            )?,
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
        if let Some((p, l)) = self.written.range_mut(..pos).rev().next() {
            let dst_end = *p + *l;
            if dst_end > pos {
                if dst_end > end {
                    return;
                } else {
                    *l = end - *p;
                    for (np, nl) in &to_remove {
                        *l = max(*l, *np + *nl - p);
                    }
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
    fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
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
    fn write_all_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        self.dst.write_all_at(buf, offset)?;
        self.add_written(offset, buf.len() as u64);
        Ok(())
    }
    fn save(mut self, size: u64) -> io::Result<()> {
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
                    .chain(RandReader::new_crypto(thread_rng())) // pad with randomness
                    .take(len)),
                &mut self.dst,
            )?;
        } else if start > size {
            self.dst.file.deref_mut().set_len(size + self.dst.offset)?;
        }
        self.dst.save()?;
        Ok(())
    }
}

pub struct Contents {
    pub inode: InodeAttributes,
    content_id: ContentId,
    changed: bool,
    file: Option<Result<MergedFile, EncryptedFile>>,
    ctrl: Controller,
}
impl Contents {
    pub fn open(ctrl: Controller, inode: Inode) -> io::Result<Self> {
        let inode: InodeAttributes = ctrl.load(inode)?;
        let content_id = match &inode.attrs.contents {
            FileData::File(a) => *a,
            FileData::Directory(_) => return Err(io::Error::from_raw_os_error(libc::EISDIR)),
            FileData::Symlink(_) => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
        };
        Ok(Self {
            inode,
            content_id,
            changed: false,
            file: None,
            ctrl,
        })
    }
    pub fn readable(&mut self) -> io::Result<&mut Self> {
        if self.file.is_none() {
            let path = self.ctrl.contents_path(self.content_id);
            if !path.exists() {
                File::create(&path)?;
            }
            self.file = Some(Err(EncryptedFile::open(
                File::open(&path)?,
                self.ctrl.key(),
            )?));
        }
        Ok(self)
    }
    pub fn writable(&mut self) -> io::Result<&mut Self> {
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
    pub fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        if offset + buf.len() as u64 > self.inode.attrs.size {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
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
    pub fn write_all_at(&mut self, buf: &mut [u8], offset: u64) -> io::Result<()> {
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
    pub fn fsync(&mut self, datasync: bool) -> io::Result<()> {
        if datasync {
            if let Some(Ok(f)) = std::mem::take(&mut self.file) {
                let size = self.ctrl.file_pad(min(
                    self.inode.attrs.size,
                    max(
                        f.src.file.metadata()?.len(),
                        f.written.last_key_value().map_or(0, |(p, l)| *p + *l),
                    ),
                ));
                f.save(size)?;
            }
        }
        if self.changed {
            self.ctrl.save(&self.inode)?;
        }
        Ok(())
    }
    pub fn truncate(&mut self, size: u64) {
        self.inode.attrs.size = size;
    }
    pub fn close(mut self, handler: &mut Handler) -> io::Result<()> {
        self.fsync(true)?;
        handler.gc_inode(&self.inode)?;
        Ok(())
    }
}
