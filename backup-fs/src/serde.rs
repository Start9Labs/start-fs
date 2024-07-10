use std::io::{Read, Write};

use serde::de::DeserializeOwned;
pub use serde::{Deserialize, Serialize};
use sha2::digest::Output;
use sha2::Sha256;

use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::error::{BkfsError, BkfsErrorKind, BkfsResult};
use crate::util::HashIO;

pub fn load<T: DeserializeOwned>(mut from: EncryptedFile) -> BkfsResult<T> {
    let mut r = HashIO::<Sha256, _>::new(&mut from);
    let res = bincode::deserialize_from(&mut r)?;
    let actual = r.finalize();
    let mut expected = Output::<Sha256>::default();
    from.read_exact(expected.as_mut_slice())?;
    if actual != expected {
        Err(BkfsError {
            kind: BkfsErrorKind::BadChecksum,
            backtrace: None,
        })
    } else {
        Ok(res)
    }
}

pub fn save<T: Serialize>(value: &T, mut to: EncryptedFile<AtomicFile>) -> BkfsResult<()> {
    let mut w = HashIO::<Sha256, _>::new(&mut to);
    bincode::serialize_into(&mut w, value)?;
    let hash = w.finalize();
    to.write_all(hash.as_slice())?;
    to.save()?;
    Ok(())
}
