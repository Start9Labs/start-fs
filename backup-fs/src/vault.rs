//! Self-contained encrypted, integrity-checked, error-corrected blobs.
//!
//! Every persistent object in the filesystem — inode metadata, the inode
//! pool, content blocks, and the crypt header itself — is stored as a
//! *sealed* blob produced by [`seal`] and read back by [`open`]. A sealed
//! blob is the unit of durability and of corruption recovery.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//!   magic        "BKV1"   (4 bytes)
//!   version      u8       (= 1)
//!   data_shards  u8
//!   parity_shards u8
//!   _reserved    u8
//!   payload_len  u32      ciphertext length (plaintext + 32-byte tag)
//!   shard_len    u32
//!   nonce        [u8; 12] ChaCha20 nonce
//!   shards       (data+parity) repetitions of:
//!                  crc32  u32      CRC of the shard bytes
//!                  bytes  [u8; shard_len]
//! ```
//!
//! **Pipeline.** `plaintext` is concatenated with its own SHA-256 tag, the
//! pair is encrypted with ChaCha20 under a per-blob random nonce, and the
//! resulting ciphertext is split into Reed-Solomon shards (see
//! [`crate::ecc`]). ECC is computed over the *ciphertext* so corruption on
//! the medium can be repaired before decryption.
//!
//! **Recovery.** On open, every shard's CRC is checked; failing shards are
//! treated as erasures and reconstructed by Reed-Solomon as long as no more
//! than `parity_shards` are bad. The decrypted plaintext is then verified
//! against its SHA-256 tag — this both detects residual corruption and
//! rejects a wrong key/password (surfaced as [`BkfsErrorKind::BadChecksum`]).

use std::backtrace::Backtrace;
use std::sync::OnceLock;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use pbkdf2::hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ecc;
use crate::error::{BkfsError, BkfsErrorKind, BkfsResult};

const MAGIC: [u8; 4] = *b"BKV1";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 1 + 1 + 1 + 4 + 4 + 12; // = 28
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 32; // SHA-256
const PBKDF2_SALT_LEN: usize = 16;
const PBKDF2_ROUNDS: u32 = 600_000;

/// Reed-Solomon parameters for newly-written blobs. Overridable via
/// `BACKUPFS_ECC_DATA` / `BACKUPFS_ECC_PARITY`; defaults to 10 data + 2
/// parity (≈20% space overhead, tolerates any 2 corrupt shards). The
/// values are recorded in each blob's header, so reads never depend on the
/// current environment — only new writes do.
pub fn ecc_params() -> (usize, usize) {
    static PARAMS: OnceLock<(usize, usize)> = OnceLock::new();
    *PARAMS.get_or_init(|| {
        let env = |k: &str, d: usize| {
            std::env::var(k)
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&n| n > 0)
                .unwrap_or(d)
        };
        let data = env("BACKUPFS_ECC_DATA", 10);
        let parity = env("BACKUPFS_ECC_PARITY", 2);
        if data + parity > ecc::MAX_SHARDS {
            (10, 2)
        } else {
            (data, parity)
        }
    })
}

fn bad_checksum() -> BkfsError {
    BkfsError {
        kind: BkfsErrorKind::BadChecksum,
        backtrace: Some(Box::new(Backtrace::capture())),
    }
}

fn corrupt() -> BkfsError {
    BkfsError {
        kind: BkfsErrorKind::BadChecksum,
        backtrace: None,
    }
}

/// Encrypt + integrity-tag + erasure-code `plaintext` into a self-contained
/// blob using the given symmetric key and the configured ECC parameters.
pub fn seal(plaintext: &[u8], key: &Key) -> Vec<u8> {
    let (data, parity) = ecc_params();
    seal_with(plaintext, key, data, parity)
}

fn seal_with(plaintext: &[u8], key: &Key, data: usize, parity: usize) -> Vec<u8> {
    // secret = plaintext || SHA-256(plaintext)
    let mut secret = Vec::with_capacity(plaintext.len() + TAG_LEN);
    secret.extend_from_slice(plaintext);
    secret.extend_from_slice(&Sha256::digest(plaintext));

    // Encrypt in place under a fresh random nonce.
    let mut nonce = [0u8; NONCE_LEN];
    rng().fill_bytes(&mut nonce);
    let mut cipher = ChaCha20::new(key, Nonce::from_slice(&nonce));
    cipher.apply_keystream(&mut secret);
    let payload_len = secret.len();

    let shards = ecc::encode(&secret, data, parity).expect("validated ecc params");
    let shard_len = shards.first().map_or(0, Vec::len);

    let mut out = Vec::with_capacity(HEADER_LEN + shards.len() * (4 + shard_len));
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(data as u8);
    out.push(parity as u8);
    out.push(0); // reserved
    out.extend_from_slice(&(payload_len as u32).to_le_bytes());
    out.extend_from_slice(&(shard_len as u32).to_le_bytes());
    out.extend_from_slice(&nonce);
    for shard in &shards {
        out.extend_from_slice(&crc32fast::hash(shard).to_le_bytes());
        out.extend_from_slice(shard);
    }
    out
}

fn read_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// Decode, error-correct, decrypt, and integrity-verify a blob produced by
/// [`seal`]. Returns `BadChecksum` if the key is wrong or the data is
/// corrupt beyond what ECC can repair.
pub fn open(blob: &[u8], key: &Key) -> BkfsResult<Vec<u8>> {
    if blob.len() < HEADER_LEN || blob[..4] != MAGIC || blob[4] != VERSION {
        return Err(corrupt());
    }
    let data = blob[5] as usize;
    let parity = blob[6] as usize;
    let payload_len = read_u32(&blob[8..12]) as usize;
    let shard_len = read_u32(&blob[12..16]) as usize;
    let nonce = &blob[16..28];
    let total = data + parity;
    if data == 0 || parity == 0 || total > ecc::MAX_SHARDS {
        return Err(corrupt());
    }

    // Collect shards, treating any whose CRC fails (or which is truncated
    // off the end of the blob) as an erasure.
    let mut shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(total);
    let mut cursor = HEADER_LEN;
    let stride = 4 + shard_len;
    for _ in 0..total {
        if cursor + stride > blob.len() {
            shards.push(None);
            continue;
        }
        let crc = read_u32(&blob[cursor..cursor + 4]);
        let bytes = &blob[cursor + 4..cursor + stride];
        if crc32fast::hash(bytes) == crc {
            shards.push(Some(bytes.to_vec()));
        } else {
            shards.push(None);
        }
        cursor += stride;
    }

    let mut secret = ecc::decode(shards, data, parity, payload_len).map_err(|_| corrupt())?;
    if secret.len() < TAG_LEN {
        return Err(corrupt());
    }

    let mut cipher = ChaCha20::new(key, Nonce::from_slice(nonce));
    cipher.apply_keystream(&mut secret);

    let tag_start = secret.len() - TAG_LEN;
    let expected = Sha256::digest(&secret[..tag_start]);
    if expected.as_slice() != &secret[tag_start..] {
        return Err(bad_checksum());
    }
    secret.truncate(tag_start);
    Ok(secret)
}

/// Seal `plaintext` under a key derived from `password` via PBKDF2. The
/// random salt is prepended to the returned blob. Used only for the crypt
/// header, which must be readable before the master key is available.
pub fn seal_pbkdf2(plaintext: &[u8], password: &str) -> BkfsResult<Vec<u8>> {
    let mut salt = [0u8; PBKDF2_SALT_LEN];
    rng().fill_bytes(&mut salt);
    let key = derive_key(password, &salt)?;
    let mut out = Vec::with_capacity(PBKDF2_SALT_LEN + plaintext.len() + 128);
    out.extend_from_slice(&salt);
    let (data, parity) = ecc_params();
    out.extend_from_slice(&seal_with(plaintext, Key::from_slice(&*key), data, parity));
    Ok(out)
}

/// Open a blob produced by [`seal_pbkdf2`].
pub fn open_pbkdf2(blob: &[u8], password: &str) -> BkfsResult<Vec<u8>> {
    if blob.len() < PBKDF2_SALT_LEN {
        return Err(corrupt());
    }
    let (salt, rest) = blob.split_at(PBKDF2_SALT_LEN);
    let key = derive_key(password, salt)?;
    open(rest, Key::from_slice(&*key))
}

fn derive_key(password: &str, salt: &[u8]) -> BkfsResult<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ROUNDS, key.as_mut_slice())
        .map_err(|_| BkfsError {
            kind: BkfsErrorKind::BadCrypt,
            backtrace: Some(Box::new(Backtrace::capture())),
        })?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Key {
        *Key::from_slice(&[7u8; 32])
    }

    #[test]
    fn roundtrip() {
        let key = test_key();
        for len in [0usize, 1, 31, 32, 33, 4096, 100_000] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let blob = seal(&pt, &key);
            assert_eq!(open(&blob, &key).unwrap(), pt);
        }
    }

    #[test]
    fn wrong_key_is_bad_checksum() {
        let blob = seal(b"secret data", &test_key());
        let other = *Key::from_slice(&[9u8; 32]);
        match open(&blob, &other) {
            Err(e) => assert!(matches!(e.kind, BkfsErrorKind::BadChecksum)),
            Ok(_) => panic!("wrong key should not open"),
        }
    }

    #[test]
    fn recovers_from_corruption() {
        // Explicit 8 data + 3 parity for a deterministic shard layout
        // (ecc_params() is a process-global OnceLock and can't be steered
        // per-test). open() reads the params back out of the header.
        let key = test_key();
        let pt: Vec<u8> = (0..50_000u32).map(|i| (i % 257) as u8).collect();
        let mut blob = seal_with(&pt, &key, 8, 3);

        // Each shard is ceil((50000+32)/8) ≈ 6.25 KB; the per-shard stride
        // is that plus a 4-byte CRC. Flipping a contiguous ~12 KB run from
        // 100 bytes into the shard region damages 2–3 shards — within the
        // 3-shard parity budget — and must still reconstruct exactly.
        let start = HEADER_LEN + 100;
        for b in &mut blob[start..start + 12_000] {
            *b ^= 0xFF;
        }
        assert_eq!(open(&blob, &key).unwrap(), pt);
    }

    #[test]
    fn pbkdf2_roundtrip() {
        let blob = seal_pbkdf2(b"header bytes", "hunter2").unwrap();
        assert_eq!(open_pbkdf2(&blob, "hunter2").unwrap(), b"header bytes");
        assert!(matches!(
            open_pbkdf2(&blob, "wrong").unwrap_err().kind,
            BkfsErrorKind::BadChecksum
        ));
    }
}
