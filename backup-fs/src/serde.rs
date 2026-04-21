use std::io::{Read, Seek, Write};
use std::os::unix::fs::FileExt;

use serde::de::DeserializeOwned;
pub use serde::{Deserialize, Serialize};
use sha2::digest::Output;
use sha2::Sha256;

use crate::aligned_io::BufferedDirectFile;
use crate::atomic_file::AtomicFile;
use crate::contents::EncryptedFile;
use crate::error::{BkfsError, BkfsErrorKind, BkfsResult};
use crate::util::HashIO;

pub fn load<T: DeserializeOwned, F: Read + Write + Seek + FileExt>(
    mut from: EncryptedFile<F>,
) -> BkfsResult<T> {
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

/// File targets that serialize a Serialize payload with a trailing hash and
/// atomically replace their destination.
pub trait Saveable {
    fn save_durable(self) -> BkfsResult<()>;
    fn save_fast(self) -> BkfsResult<()>;
}

impl Saveable for EncryptedFile<BufferedDirectFile<AtomicFile>> {
    fn save_durable(self) -> BkfsResult<()> {
        self.save()
    }
    fn save_fast(self) -> BkfsResult<()> {
        self.save_fast()
    }
}

impl Saveable for EncryptedFile<AtomicFile> {
    fn save_durable(self) -> BkfsResult<()> {
        self.save()
    }
    fn save_fast(self) -> BkfsResult<()> {
        self.save_fast()
    }
}

fn write_hashed<T: Serialize, F: Read + Write + Seek + FileExt>(
    value: &T,
    to: &mut EncryptedFile<F>,
) -> BkfsResult<()> {
    let mut w = HashIO::<Sha256, _>::new(&mut *to);
    bincode::serialize_into(&mut w, value)?;
    let hash = w.finalize();
    to.write_all(hash.as_slice())?;
    Ok(())
}

pub fn save<T: Serialize, F: Read + Write + Seek + FileExt>(
    value: &T,
    mut to: EncryptedFile<F>,
) -> BkfsResult<()>
where
    EncryptedFile<F>: Saveable,
{
    write_hashed(value, &mut to)?;
    to.save_durable()
}

/// As `save`, but without sync_all. Caller must ensure a later syncfs
/// for durability.
pub fn save_fast<T: Serialize, F: Read + Write + Seek + FileExt>(
    value: &T,
    mut to: EncryptedFile<F>,
) -> BkfsResult<()>
where
    EncryptedFile<F>: Saveable,
{
    write_hashed(value, &mut to)?;
    Saveable::save_fast(to)
}
