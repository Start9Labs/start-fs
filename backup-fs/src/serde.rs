//! bincode (de)serialization wrapped in the [`crate::vault`] seal/open
//! pipeline. Every persistent structure — inode attributes, the inode
//! pool — is serialized to bytes, then sealed (encrypted + integrity-tagged
//! + erasure-coded) before it touches the backing store.

use chacha20::Key;
use serde::de::DeserializeOwned;
pub use serde::{Deserialize, Serialize};

use crate::error::BkfsResult;
use crate::vault;

/// Serialize `value` and seal it into a self-contained encrypted,
/// error-correcting blob ready to write whole to disk.
pub fn serialize_sealed<T: Serialize>(value: &T, key: &Key) -> BkfsResult<Vec<u8>> {
    let plain = bincode::serialize(value)?;
    Ok(vault::seal(&plain, key))
}

/// Open a blob produced by [`serialize_sealed`] (error-correcting and
/// decrypting it) and deserialize the contained value.
pub fn deserialize_sealed<T: DeserializeOwned>(blob: &[u8], key: &Key) -> BkfsResult<T> {
    let plain = vault::open(blob, key)?;
    Ok(bincode::deserialize(&plain)?)
}
