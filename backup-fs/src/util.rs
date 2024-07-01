use std::io::{self, Read, Write};

use rand::{CryptoRng, RngCore};
use sha2::digest::Output;
use sha2::Digest;

pub struct RandReader<R: RngCore>(R);
impl<R: RngCore> RandReader<R> {
    pub fn new(rng: R) -> Self {
        Self(rng)
    }
}
impl<R: RngCore + CryptoRng> RandReader<R> {
    pub fn new_crypto(rng: R) -> Self {
        Self(rng)
    }
}
impl<R: RngCore> Read for RandReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.fill_bytes(buf);
        Ok(buf.len())
    }
}

pub struct HashIO<D: Digest, T> {
    hasher: D,
    io: T,
}
impl<D: Digest, T> HashIO<D, T> {
    pub fn new(io: T) -> Self {
        Self {
            hasher: D::new(),
            io,
        }
    }
    pub fn finalize(self) -> Output<D> {
        self.hasher.finalize()
    }
}
impl<D: Digest, T: Write> Write for HashIO<D, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.io.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.io.flush()
    }
}
impl<D: Digest, T: Read> Read for HashIO<D, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.io.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}
