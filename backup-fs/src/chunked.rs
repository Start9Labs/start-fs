#![allow(unused)]

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ctrl::Controller;
use crate::error::{BkfsError, BkfsResult};

/// 64 KB blocks: good balance between dedup efficiency and metadata overhead.
/// rsync's default algorithm works well with this chunk size.
pub const CHUNK_SIZE: usize = 64 * 1024;
pub const CHUNK_HASH_LEN: usize = 32;

/// Nonce size for ChaCha20Poly1305
const NONCE_SIZE: usize = 12;

/// A content-addressed chunk hash (SHA-256 of plaintext)
pub type ChunkHash = [u8; CHUNK_HASH_LEN];

/// Manifest for a file: ordered list of chunk hashes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub chunks: Vec<ChunkHash>,
    pub size: u64,
}

impl FileManifest {
    pub fn new() -> Self {
        Self {
            chunks: Vec::new(),
            size: 0,
        }
    }

    pub fn total_chunks(&self) -> usize {
        self.chunks.len()
    }
}

/// Content-addressed storage backend for encrypted chunks.
/// Each unique chunk is stored once as `blocks/<hash_prefix>/<hash>`.
/// This enables rsync-like dedup: unchanged blocks are not rewritten.
pub struct ChunkStore {
    blocks_dir: PathBuf,
    ctrl: Controller,
}

impl ChunkStore {
    pub fn new(ctrl: Controller) -> Self {
        let blocks_dir = ctrl.config().data_dir.join("blocks");
        std::fs::create_dir_all(&blocks_dir).ok();
        Self { blocks_dir, ctrl }
    }

    /// Compute hash of plaintext chunk
    pub fn hash_chunk(data: &[u8]) -> ChunkHash {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Derive a per-chunk encryption key from the master key + chunk hash.
    /// This ensures identical plaintext in different files encrypts differently
    /// (defense in depth).
    fn chunk_key(&self, hash: &ChunkHash) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.ctrl.key());
        hasher.update(hash);
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Encrypt a chunk using ChaCha20Poly1305 with a derived key and random nonce
    fn encrypt_chunk(&self, plaintext: &[u8]) -> BkfsResult<Vec<u8>> {
        let hash = Self::hash_chunk(plaintext);
        let key = self.chunk_key(&hash);
        let cipher = ChaCha20Poly1305::new(&key.into());
        
        // Generate random nonce
        let nonce_bytes: [u8; NONCE_SIZE] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| BkfsError::encryption_error("chunk encryption failed"))?;
        
        // Format: nonce (12 bytes) || ciphertext
        let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a chunk
    fn decrypt_chunk(&self, encrypted: &[u8], expected_hash: &ChunkHash) -> BkfsResult<Vec<u8>> {
        if encrypted.len() < NONCE_SIZE {
            return Err(BkfsError::decryption_error("encrypted chunk too short"));
        }
        
        let key = self.chunk_key(expected_hash);
        let cipher = ChaCha20Poly1305::new(&key.into());
        
        let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
        let ciphertext = &encrypted[NONCE_SIZE..];
        
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| BkfsError::decryption_error("chunk decryption failed"))?;
        
        // Verify hash matches
        let actual_hash = Self::hash_chunk(&plaintext);
        if actual_hash != *expected_hash {
            return Err(BkfsError::decryption_error("chunk hash mismatch"));
        }
        
        Ok(plaintext)
    }

    /// Get path for a chunk hash
    fn chunk_path(&self, hash: &ChunkHash) -> PathBuf {
        let prefix = hex::encode(&hash[..2]);
        self.blocks_dir.join(prefix).join(hex::encode(hash))
    }

    /// Write a chunk if it doesn't already exist (content-addressed dedup)
    pub fn write_chunk(&self, plaintext: &[u8]) -> BkfsResult<ChunkHash> {
        let hash = Self::hash_chunk(plaintext);
        let path = self.chunk_path(&hash);
        
        // If chunk already exists, just dedupe
        if path.exists() {
            return Ok(hash);
        }
        
        // Create parent dir
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        // Encrypt and write atomically
        let encrypted = self.encrypt_chunk(plaintext)?;
        let tmp = path.with_extension("tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(libc::O_DIRECT)
                .open(&tmp)?;
            f.write_all(&encrypted)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        
        Ok(hash)
    }

    /// Read a chunk by its hash
    pub fn read_chunk(&self, hash: &ChunkHash) -> BkfsResult<Vec<u8>> {
        let path = self.chunk_path(hash);
        let mut encrypted = Vec::new();
        File::open(&path)?.read_to_end(&mut encrypted)?;
        self.decrypt_chunk(&encrypted, hash)
    }

    /// Delete a chunk (called when reference count drops to zero)
    pub fn delete_chunk(&self, hash: &ChunkHash) -> BkfsResult<()> {
        let path = self.chunk_path(hash);
        if path.exists() {
            std::fs::remove_file(&path)?;
            // Try to remove parent dir if empty
            if let Some(parent) = path.parent() {
                std::fs::remove_dir(parent).ok();
            }
        }
        Ok(())
    }
}

/// Chunked file I/O: reads/writes files in 64KB blocks, tracking which
/// chunks have been modified. Optimized for incremental backups and
/// append-only backends (CIFS, rclone mount).
pub struct ChunkedFile {
    manifest: FileManifest,
    store: ChunkStore,
    /// Dirty chunks: offset_chunk_index -> plaintext data
    dirty: HashMap<usize, Vec<u8>>,
}

impl ChunkedFile {
    pub fn new(store: ChunkStore, manifest: FileManifest) -> Self {
        Self {
            manifest,
            store,
            dirty: HashMap::new(),
        }
    }

    pub fn manifest(&self) -> &FileManifest {
        &self.manifest
    }

    pub fn size(&self) -> u64 {
        self.manifest.size
    }

    /// Read data at a given offset and length
    pub fn read_at(&self, offset: u64, len: usize) -> BkfsResult<Vec<u8>> {
        if offset >= self.manifest.size {
            return Ok(Vec::new());
        }
        
        let end = (offset + len as u64).min(self.manifest.size);
        let mut result = Vec::with_capacity(len);
        
        let start_chunk = (offset / CHUNK_SIZE as u64) as usize;
        let end_chunk = ((end - 1) / CHUNK_SIZE as u64) as usize;
        
        for chunk_idx in start_chunk..=end_chunk {
            let chunk_data = if let Some(dirty) = self.dirty.get(&chunk_idx) {
                dirty.clone()
            } else if chunk_idx < self.manifest.chunks.len() {
                self.store.read_chunk(&self.manifest.chunks[chunk_idx])?
            } else {
                vec![0u8; CHUNK_SIZE]
            };
            
            let chunk_offset = chunk_idx * CHUNK_SIZE;
            let read_start = if offset > chunk_offset as u64 {
                (offset - chunk_offset as u64) as usize
            } else {
                0
            };
            let read_end = if end > (chunk_offset + CHUNK_SIZE) as u64 {
                CHUNK_SIZE
            } else {
                (end as usize) - chunk_offset
            };
            
            if read_start < chunk_data.len() {
                result.extend_from_slice(&chunk_data[read_start..read_end.min(chunk_data.len())]);
            }
        }
        
        Ok(result)
    }

    /// Write data at a given offset. Marks affected chunks as dirty.
    /// For partial-chunk writes, performs read-modify-write.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> BkfsResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        
        let mut pos = 0;
        let mut cur_offset = offset;
        
        while pos < data.len() {
            let chunk_idx = (cur_offset / CHUNK_SIZE as u64) as usize;
            let chunk_offset = chunk_idx * CHUNK_SIZE;
            let offset_in_chunk = (cur_offset - chunk_offset as u64) as usize;
            let space_in_chunk = CHUNK_SIZE - offset_in_chunk;
            let to_write = space_in_chunk.min(data.len() - pos);
            
            // Get or create the chunk
            let chunk = self.dirty.entry(chunk_idx).or_insert_with(|| {
                // Try to load existing chunk, or create new
                if chunk_idx < self.manifest.chunks.len() {
                    self.store.read_chunk(&self.manifest.chunks[chunk_idx]).unwrap_or_default()
                } else {
                    Vec::new()
                }
            });
            
            // Extend chunk if needed
            if chunk.len() < offset_in_chunk + to_write {
                chunk.resize(offset_in_chunk + to_write, 0);
            }
            
            // Write data
            chunk[offset_in_chunk..offset_in_chunk + to_write]
                .copy_from_slice(&data[pos..pos + to_write]);
            
            pos += to_write;
            cur_offset += to_write as u64;
        }
        
        // Update manifest size
        let new_end = offset + data.len() as u64;
        if new_end > self.manifest.size {
            self.manifest.size = new_end;
        }
        
        // Ensure manifest has enough chunk slots
        let total_chunks = (self.manifest.size as usize + CHUNK_SIZE - 1) / CHUNK_SIZE;
        while self.manifest.chunks.len() < total_chunks {
            self.manifest.chunks.push([0u8; CHUNK_HASH_LEN]);
        }
        
        Ok(())
    }

    /// Flush dirty chunks to the chunk store and update manifest
    pub fn fsync(&mut self) -> BkfsResult<()> {
        // Write dirty chunks and update manifest
        let mut indices: Vec<usize> = self.dirty.keys().copied().collect();
        indices.sort();
        
        for idx in indices {
            if let Some(data) = self.dirty.remove(&idx) {
                let hash = self.store.write_chunk(&data)?;
                if idx < self.manifest.chunks.len() {
                    self.manifest.chunks[idx] = hash;
                } else {
                    self.manifest.chunks.push(hash);
                }
            }
        }
        
        Ok(())
    }

    /// Truncate file to new_size
    pub fn truncate(&mut self, new_size: u64) -> BkfsResult<()> {
        let old_size = self.manifest.size;
        
        if new_size < old_size {
            // Remove chunks beyond new_size
            let new_chunks = (new_size as usize + CHUNK_SIZE - 1) / CHUNK_SIZE;
            self.manifest.chunks.truncate(new_chunks);
            
            // Remove dirty chunks beyond new_size
            self.dirty.retain(|&idx, _| (idx * CHUNK_SIZE) < new_size as usize);
            
            // Trim the last chunk if needed
            if !self.manifest.chunks.is_empty() {
                let last_chunk_idx = self.manifest.chunks.len() - 1;
                let last_chunk_offset = last_chunk_idx * CHUNK_SIZE;
                let last_chunk_len = new_size as usize - last_chunk_offset;
                
                if let Some(dirty) = self.dirty.get_mut(&last_chunk_idx) {
                    if dirty.len() > last_chunk_len {
                        dirty.truncate(last_chunk_len);
                    }
                }
            }
        } else if new_size > old_size {
            // Extend with zeros
            let additional = new_size - old_size;
            let zeros = vec![0u8; additional as usize];
            self.write_at(old_size, &zeros)?;
        }
        
        self.manifest.size = new_size;
        Ok(())
    }
}

// Helper module for hex encoding
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

impl BkfsError {
    pub fn encryption_error(msg: &str) -> Self {
        BkfsError::wrap(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Encryption error: {}", msg),
        ))
    }
    
    pub fn decryption_error(msg: &str) -> Self {
        BkfsError::wrap(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Decryption error: {}", msg),
        ))
    }
}
