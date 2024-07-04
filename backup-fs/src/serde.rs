use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::digest::Output;
use sha2::Sha256;

use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::util::HashIO;

fn bincode_to_io_err(e: bincode::Error) -> io::Error {
    match *e {
        bincode::ErrorKind::Io(e) => e,
        e => io::Error::other(e),
    }
}

pub fn load<T: DeserializeOwned>(mut from: EncryptedFile) -> io::Result<T> {
    let mut r = HashIO::<Sha256, _>::new(&mut from);
    let res = bincode::deserialize_from(&mut r).map_err(bincode_to_io_err)?;
    let actual = r.finalize();
    let mut expected = Output::<Sha256>::default();
    from.read_exact(expected.as_mut_slice())?;
    if actual != expected {
        Err(io::Error::other("checksum validation failed"))
    } else {
        Ok(res)
    }
}

pub fn save<T: Serialize>(value: &T, mut to: EncryptedFile<AtomicFile>) -> io::Result<()> {
    let mut w = HashIO::<Sha256, _>::new(&mut to);
    bincode::serialize_into(&mut w, value).map_err(bincode_to_io_err)?;
    let hash = w.finalize();
    to.write_all(hash.as_slice())?;
    to.save()?;
    Ok(())
}
