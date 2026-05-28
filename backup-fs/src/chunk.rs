use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key};
use rand::{rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::atomic_file::AtomicFile;
use crate::error::{BkfsError, BkfsErrorKind, BkfsResult};

/// Logical file chunk size. A 1 MiB chunk keeps large-file manifests small,
/// while still giving rsync/rclone a useful granularity for incremental
/// transfer of the encrypted backing store.
pub const CHUNK_SIZE: usize = 1024 * 1024;

/// The on-disk ECC scheme is one XOR parity shard over sixteen data shards.
/// Per-shard checksums identify a single corrupt shard; the parity shard then
/// reconstructs it. This is intentionally simple and deterministic: every
/// chunk is still a single sequentially-written backing file, so it works on
/// object/FUSE backends that reject pwrite-style random writes.
const DATA_SHARDS: usize = 16;
const PARITY_SHARDS: usize = 1;
const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

const MAGIC: &[u8; 8] = b"BKCHNK1\0";
const VERSION: u8 = 1;
const NONCE_SIZE: usize = 12;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ChunkId(pub [u8; 16]);

impl ChunkId {
    pub fn random() -> Self {
        let mut id = [0_u8; 16];
        rng().fill_bytes(&mut id);
        Self(id)
    }

    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(self.0.len() * 2);
        for b in self.0 {
            use std::fmt::Write as _;
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRef {
    pub id: ChunkId,
    /// Bytes physically stored in the chunk object after trailing-zero
    /// canonicalization.
    pub stored_len: u32,
    /// Bytes visible at this logical file offset. This may be smaller than
    /// stored_len after a truncate that cuts through a chunk; keeping the old
    /// object but lowering visible_len prevents tail data from reappearing if
    /// the file is later extended.
    pub visible_len: u32,
    /// SHA-256 of the stored plaintext bytes.
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileContents {
    chunks: Vec<Option<ChunkRef>>,
}

impl FileContents {
    pub fn new() -> Self {
        Self { chunks: Vec::new() }
    }

    pub fn chunk(&self, index: u64) -> Option<&ChunkRef> {
        self.chunks.get(index as usize).and_then(Option::as_ref)
    }

    pub fn iter_chunks(&self) -> impl Iterator<Item = &ChunkRef> {
        self.chunks.iter().filter_map(Option::as_ref)
    }

    pub fn set_chunk(&mut self, index: u64, chunk: Option<ChunkRef>) {
        let index = index as usize;
        if self.chunks.len() <= index {
            self.chunks.resize_with(index + 1, || None);
        }
        self.chunks[index] = chunk;
        while self.chunks.last().is_some_and(Option::is_none) {
            self.chunks.pop();
        }
    }

    /// Adjust the manifest for a new logical size. Returns true if any chunk
    /// reference changed. Expanding a file does not allocate chunks; reads from
    /// missing regions synthesize zeroes.
    pub fn truncate_to_size(&mut self, size: u64) -> bool {
        let needed = size.div_ceil(CHUNK_SIZE as u64) as usize;
        let mut changed = false;
        if self.chunks.len() > needed {
            self.chunks.truncate(needed);
            changed = true;
        }
        if needed > 0 {
            let last_visible = (size - ((needed - 1) as u64 * CHUNK_SIZE as u64)) as u32;
            if let Some(Some(last)) = self.chunks.get_mut(needed - 1) {
                let new_visible = last.visible_len.min(last_visible);
                if new_visible == 0 {
                    self.chunks[needed - 1] = None;
                    changed = true;
                } else if new_visible != last.visible_len {
                    last.visible_len = new_visible;
                    changed = true;
                }
            }
        }
        while self.chunks.last().is_some_and(Option::is_none) {
            self.chunks.pop();
            changed = true;
        }
        changed
    }

    pub fn live_chunk_ids(&self, out: &mut BTreeSet<ChunkId>) {
        out.extend(self.iter_chunks().map(|c| c.id));
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ChunkHeader {
    version: u8,
    plain_len: u32,
    shard_size: u32,
    shard_hashes: Vec<[u8; 32]>,
}

pub fn plaintext_hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn trim_trailing_zeroes(data: &mut Vec<u8>) {
    while data.last() == Some(&0) {
        data.pop();
    }
}

fn shard_size_for(len: usize) -> usize {
    len.max(1).div_ceil(DATA_SHARDS)
}

fn checksum_shards(shards: &[Vec<u8>]) -> Vec<[u8; 32]> {
    shards.iter().map(|s| plaintext_hash(s)).collect()
}

fn encode_shards(data: &[u8]) -> (usize, Vec<Vec<u8>>) {
    let shard_size = shard_size_for(data.len());
    let mut shards = vec![vec![0_u8; shard_size]; TOTAL_SHARDS];
    for (i, chunk) in data.chunks(shard_size).enumerate() {
        shards[i][..chunk.len()].copy_from_slice(chunk);
    }

    for i in 0..shard_size {
        let mut parity = 0_u8;
        for shard in shards.iter().take(DATA_SHARDS) {
            parity ^= shard[i];
        }
        shards[DATA_SHARDS][i] = parity;
    }

    (shard_size, shards)
}

fn reconstruct_one(shards: &mut [Vec<u8>], bad: usize) {
    let shard_size = shards[0].len();
    if bad < DATA_SHARDS {
        for i in 0..shard_size {
            let mut byte = shards[DATA_SHARDS][i];
            for (idx, shard) in shards.iter().take(DATA_SHARDS).enumerate() {
                if idx != bad {
                    byte ^= shard[i];
                }
            }
            shards[bad][i] = byte;
        }
    } else {
        for i in 0..shard_size {
            let mut parity = 0_u8;
            for shard in shards.iter().take(DATA_SHARDS) {
                parity ^= shard[i];
            }
            shards[DATA_SHARDS][i] = parity;
        }
    }
}

#[cfg(target_os = "linux")]
fn fadvise_dontneed(file: &File) {
    // Best-effort page-cache eviction. This is not a correctness boundary;
    // it simply reduces the chance that CIFS/rclone writeback consumes the
    // memory it needs to make forward progress.
    let _ = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
}

#[cfg(not(target_os = "linux"))]
fn fadvise_dontneed(_file: &File) {}

pub fn chunk_path(base: &Path, id: ChunkId) -> PathBuf {
    let hex = id.hex();
    base.join(&hex[0..2]).join(&hex[2..4]).join(hex)
}

pub fn write_chunk_file(path: PathBuf, key: &Key, data: &[u8]) -> BkfsResult<()> {
    debug_assert!(data.len() <= CHUNK_SIZE);
    let (shard_size, shards) = encode_shards(data);
    let mut nonce = [0_u8; NONCE_SIZE];
    rng().fill_bytes(&mut nonce);

    let header = ChunkHeader {
        version: VERSION,
        plain_len: data.len() as u32,
        shard_size: shard_size as u32,
        shard_hashes: checksum_shards(&shards),
    };

    let mut payload = Vec::with_capacity(shard_size * TOTAL_SHARDS);
    for shard in shards {
        payload.extend_from_slice(&shard);
    }

    // Only the magic, nonce, and encrypted-header length are plaintext. Shard
    // checksums are encrypted with the payload so small chunks do not expose a
    // plaintext dictionary oracle to the backing store.
    let mut header_bytes = bincode::serialize(&header)?;
    let mut cipher = ChaCha20::new(key, (&nonce).into());
    cipher.apply_keystream(&mut header_bytes);
    cipher.apply_keystream(&mut payload);

    let mut file = AtomicFile::create_buffered(path)?;
    file.write_all(MAGIC)?;
    file.write_all(&nonce)?;
    file.write_all(&(header_bytes.len() as u32).to_le_bytes())?;
    file.write_all(&header_bytes)?;
    file.write_all(&payload)?;
    file.flush()?;
    fadvise_dontneed(&file);
    file.save_fast()?;
    Ok(())
}

pub fn read_chunk_file(path: &Path, key: &Key) -> BkfsResult<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    fadvise_dontneed(&file);

    let min_len = MAGIC.len() + NONCE_SIZE + std::mem::size_of::<u32>();
    if bytes.len() < min_len || &bytes[..MAGIC.len()] != MAGIC {
        return Err(BkfsError {
            kind: BkfsErrorKind::BadChecksum,
            backtrace: None,
        });
    }
    let nonce_start = MAGIC.len();
    let nonce: [u8; NONCE_SIZE] = bytes[nonce_start..nonce_start + NONCE_SIZE]
        .try_into()
        .unwrap();
    let header_len_offset = nonce_start + NONCE_SIZE;
    let header_len = u32::from_le_bytes(
        bytes[header_len_offset..header_len_offset + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let header_start = header_len_offset + 4;
    let payload_start = header_start
        .checked_add(header_len)
        .ok_or_else(|| BkfsError {
            kind: BkfsErrorKind::BadChecksum,
            backtrace: None,
        })?;
    if payload_start > bytes.len() {
        return Err(BkfsError {
            kind: BkfsErrorKind::BadChecksum,
            backtrace: None,
        });
    }

    let mut cipher = ChaCha20::new(key, (&nonce).into());
    let mut header_bytes = bytes[header_start..payload_start].to_vec();
    cipher.apply_keystream(&mut header_bytes);
    let header: ChunkHeader = bincode::deserialize(&header_bytes)?;
    if header.version != VERSION
        || header.plain_len as usize > CHUNK_SIZE
        || header.shard_hashes.len() != TOTAL_SHARDS
    {
        return Err(BkfsError {
            kind: BkfsErrorKind::BadChecksum,
            backtrace: None,
        });
    }
    let shard_size = header.shard_size as usize;
    if shard_size == 0 || shard_size > shard_size_for(CHUNK_SIZE) {
        return Err(BkfsError {
            kind: BkfsErrorKind::BadChecksum,
            backtrace: None,
        });
    }
    let expected_payload = shard_size
        .checked_mul(TOTAL_SHARDS)
        .ok_or_else(|| BkfsError {
            kind: BkfsErrorKind::BadChecksum,
            backtrace: None,
        })?;
    if bytes.len() - payload_start != expected_payload {
        return Err(BkfsError {
            kind: BkfsErrorKind::BadChecksum,
            backtrace: None,
        });
    }

    let mut payload = bytes[payload_start..].to_vec();
    cipher.apply_keystream(&mut payload);

    let mut shards: Vec<Vec<u8>> = payload.chunks(shard_size).map(|s| s.to_vec()).collect();
    let bad: Vec<usize> = shards
        .iter()
        .zip(header.shard_hashes.iter())
        .enumerate()
        .filter_map(|(idx, (shard, expected))| (plaintext_hash(shard) != *expected).then_some(idx))
        .collect();

    match bad.as_slice() {
        [] => {}
        [idx] => {
            reconstruct_one(&mut shards, *idx);
            if plaintext_hash(&shards[*idx]) != header.shard_hashes[*idx] {
                return Err(BkfsError {
                    kind: BkfsErrorKind::BadChecksum,
                    backtrace: None,
                });
            }
        }
        _ => {
            return Err(BkfsError {
                kind: BkfsErrorKind::BadChecksum,
                backtrace: None,
            })
        }
    }

    let mut out = Vec::with_capacity(DATA_SHARDS * shard_size);
    for shard in shards.iter().take(DATA_SHARDS) {
        out.extend_from_slice(shard);
    }
    out.truncate(header.plain_len as usize);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn payload_start(bytes: &[u8]) -> usize {
        let header_len_offset = MAGIC.len() + NONCE_SIZE;
        let header_len = u32::from_le_bytes(
            bytes[header_len_offset..header_len_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        header_len_offset + 4 + header_len
    }

    #[test]
    fn ecc_recovers_one_corrupt_shard() {
        let dir = tempdir::TempDir::new("backupfs_chunk_ecc").unwrap();
        let key = Key::clone_from_slice(&[7_u8; 32]);
        let id = ChunkId([1_u8; 16]);
        let path = chunk_path(dir.path(), id);
        let mut data = vec![0_u8; 900_000];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(9);
        }

        write_chunk_file(path.clone(), &key, &data).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let payload = payload_start(&bytes);
        bytes[payload + 17] ^= 0x55;
        fs::write(&path, bytes).unwrap();

        assert_eq!(read_chunk_file(&path, &key).unwrap(), data);
    }

    #[test]
    fn ecc_rejects_two_corrupt_shards() {
        let dir = tempdir::TempDir::new("backupfs_chunk_ecc").unwrap();
        let key = Key::clone_from_slice(&[8_u8; 32]);
        let id = ChunkId([2_u8; 16]);
        let path = chunk_path(dir.path(), id);
        let data = vec![42_u8; 900_000];

        write_chunk_file(path.clone(), &key, &data).unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let payload = payload_start(&bytes);
        let shard = shard_size_for(data.len());
        bytes[payload + 3] ^= 0x11;
        bytes[payload + shard + 3] ^= 0x22;
        fs::write(&path, bytes).unwrap();

        assert!(read_chunk_file(&path, &key).is_err());
    }
}
