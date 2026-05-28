//! Reed-Solomon erasure coding for metadata protection.
//!
//! Critical metadata (cryptinfo, inode pool, directory manifests) is protected
//! with RS(4,2) coding: 4 data shards + 2 parity shards. Any 4 of the 6 shards
//! can reconstruct the data.
//!
//! Storage layout:
//!   - `metadata/<file>.ecc`: 6 files (<file>.0 through <file>.5)
//!   - Or inline for small metadata (cryptinfo)

#![allow(unused)]

use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;

use crate::error::{BkfsError, BkfsResult};

/// Data shards and parity shards for our RS code
const DATA_SHARDS: usize = 4;
const PARITY_SHARDS: usize = 2;
const TOTAL_SHARDS: usize = DATA_SHARDS + PARITY_SHARDS;

/// Header prepended to each shard: [shard_index: u8][shard_data...]
const SHARD_HEADER_SIZE: usize = 1;

/// ECC result: a set of shards, each with an index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EccBlock {
    /// Total bytes of original data (before padding to shard size)
    pub original_len: usize,
    /// Shard data, indexed 0..6 (0..4 data, 4..6 parity)
    pub shards: Vec<Vec<u8>>,
    /// SHA-256 of original data for verification
    pub hash: [u8; 32],
}

impl EccBlock {
    /// Encode data into ECC shards
    pub fn encode(data: &[u8]) -> BkfsResult<Self> {
        let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
            .map_err(|e| BkfsError::ecc_error(&format!("RS init failed: {:?}", e)))?;

        // Calculate hash of original data
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize().into();

        // Split data into shards (pad last if needed)
        let shard_size = (data.len() + DATA_SHARDS - 1) / DATA_SHARDS;
        let shard_size = shard_size.max(1); // At least 1 byte

        let mut shards: Vec<Vec<u8>> = Vec::new();
        
        // Data shards
        for i in 0..DATA_SHARDS {
            let start = i * shard_size;
            let end = (start + shard_size).min(data.len());
            let mut shard = vec![0u8; shard_size];
            if start < data.len() {
                let copy_len = end - start;
                shard[..copy_len].copy_from_slice(&data[start..end]);
            }
            shards.push(shard);
        }

        // Parity shards (empty, will be filled by encoder)
        for _ in 0..PARITY_SHARDS {
            shards.push(vec![0u8; shard_size]);
        }

        // Encode
        let mut shard_refs: Vec<&mut [u8]> = shards.iter_mut().map(|s| s.as_mut_slice()).collect();
        rs.encode(&mut shard_refs)
            .map_err(|e| BkfsError::ecc_error(&format!("RS encode failed: {:?}", e)))?;

        Ok(Self {
            original_len: data.len(),
            shards,
            hash,
        })
    }

    /// Decode data from shards (some may be missing/None)
    pub fn decode(shards: Vec<Option<Vec<u8>>>, original_len: usize, expected_hash: [u8; 32]) -> BkfsResult<Vec<u8>> {
        let rs = ReedSolomon::new(DATA_SHARDS, PARITY_SHARDS)
            .map_err(|e| BkfsError::ecc_error(&format!("RS init failed: {:?}", e)))?;

        // Check we have at least DATA_SHARDS non-None
        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < DATA_SHARDS {
            return Err(BkfsError::ecc_error(&format!(
                "Not enough shards: have {}, need {}",
                available, DATA_SHARDS
            )));
        }

        // Reconstruct - RS needs owned Vec<u8> shards
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards;
        rs.reconstruct(&mut shard_opts)
            .map_err(|e| BkfsError::ecc_error(&format!("RS reconstruct failed: {:?}", e)))?;

        // Extract data from reconstructed shards
        let shard_size = shard_opts[0].as_ref().map(|v| v.len()).unwrap_or(0);
        let mut result = Vec::with_capacity(DATA_SHARDS * shard_size);
        
        for i in 0..DATA_SHARDS {
            if let Some(shard) = &shard_opts[i] {
                result.extend_from_slice(shard);
            }
        }

        // Truncate to original length
        result.truncate(original_len);

        // Verify hash
        let mut hasher = Sha256::new();
        hasher.update(&result);
        let actual_hash: [u8; 32] = hasher.finalize().into();
        
        if actual_hash != expected_hash {
            return Err(BkfsError::ecc_error("Decoded data hash mismatch"));
        }

        Ok(result)
    }

    /// Decode with all shards present (fast path)
    pub fn decode_all(&self) -> BkfsResult<Vec<u8>> {
        let all_shards: Vec<Option<Vec<u8>>> = self.shards.iter()
            .map(|s| Some(s.clone()))
            .collect();
        Self::decode(all_shards, self.original_len, self.hash)
    }

    /// Get a specific shard (with index header)
    pub fn shard_with_header(&self, idx: usize) -> Vec<u8> {
        if idx >= TOTAL_SHARDS {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(SHARD_HEADER_SIZE + self.shards[idx].len());
        out.push(idx as u8);
        out.extend_from_slice(&self.shards[idx]);
        out
    }

    /// Extract shard index and data from a shard file
    pub fn parse_shard(data: &[u8]) -> Option<(u8, &[u8])> {
        if data.len() < SHARD_HEADER_SIZE {
            return None;
        }
        Some((data[0], &data[SHARD_HEADER_SIZE..]))
    }
}

/// Store an ECC block to disk as 6 separate shard files
pub fn store_ecc_block(path: &std::path::Path, block: &EccBlock) -> BkfsResult<()> {
    let parent = path.parent().ok_or_else(|| {
        BkfsError::ecc_error("No parent directory")
    })?;
    std::fs::create_dir_all(parent)?;

    // Write ECC metadata file
    let meta_path = path.with_extension("ecc.meta");
    let meta = serde_json::json!({
        "original_len": block.original_len,
        "hash": hex::encode(&block.hash),
    });
    std::fs::write(&meta_path, serde_json::to_string_pretty(&meta).map_err(|e| BkfsError::ecc_error(&e.to_string()))?)?;

    // Write each shard
    for i in 0..TOTAL_SHARDS {
        let shard_path = path.with_extension(&format!("ecc.{}", i));
        let tmp = shard_path.with_extension(format!("ecc.{}.tmp", i));
        let shard_data = block.shard_with_header(i);
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&shard_data)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &shard_path)?;
    }

    Ok(())
}

/// Load an ECC block from disk (reads all available shards, reconstructs if needed)
pub fn load_ecc_block(path: &std::path::Path) -> BkfsResult<Vec<u8>> {
    // Read metadata
    let meta_path = path.with_extension("ecc.meta");
    let meta_str = std::fs::read_to_string(&meta_path)?;
    let meta: serde_json::Value = serde_json::from_str(&meta_str).map_err(|e| BkfsError::ecc_error(&e.to_string()))?;
    
    let original_len = meta["original_len"].as_u64().ok_or_else(|| {
        BkfsError::ecc_error("Missing original_len in ECC metadata")
    })? as usize;
    
    let hash_hex = meta["hash"].as_str().ok_or_else(|| {
        BkfsError::ecc_error("Missing hash in ECC metadata")
    })?;
    let expected_hash_vec = hex::decode(hash_hex)
        .map_err(|e| BkfsError::ecc_error(&format!("Invalid hash hex: {}", e)))?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&expected_hash_vec);

    // Read available shards
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; TOTAL_SHARDS];
    
    for i in 0..TOTAL_SHARDS {
        let shard_path = path.with_extension(&format!("ecc.{}", i));
        if shard_path.exists() {
            let data = std::fs::read(&shard_path)?;
            if let Some((idx, shard_data)) = EccBlock::parse_shard(&data) {
                shards[idx as usize] = Some(shard_data.to_vec());
            }
        }
    }

    EccBlock::decode(shards, original_len, hash)
}

// Helper for hex encoding/decoding
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("Odd length hex string".to_string());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16).map_err(|e| e.to_string()))
            .collect()
    }
}

impl BkfsError {
    pub fn ecc_error(msg: &str) -> Self {
        BkfsError::wrap(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("ECC error: {}", msg),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecc_roundtrip() {
        let data = b"Hello, World! This is test data for Reed-Solomon coding.";
        let block = EccBlock::encode(data).unwrap();
        let decoded = block.decode_all().unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn ecc_survives_2_loss() {
        let data = b"Recovery test data that should survive shard loss";
        let block = EccBlock::encode(data).unwrap();

        // Lose shards 0 and 3
        let mut shards: Vec<Option<Vec<u8>>> = block.shards.iter()
            .map(|s| Some(s.clone()))
            .collect();
        shards[0] = None;
        shards[3] = None;

        let decoded = EccBlock::decode(shards, block.original_len, block.hash).unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn ecc_fails_with_too_much_loss() {
        let data = b"Cannot survive losing 3 shards";
        let block = EccBlock::encode(data).unwrap();

        // Lose shards 0, 2, and 4 (3 shards > PARITY_SHARDS)
        let mut shards: Vec<Option<Vec<u8>>> = block.shards.iter()
            .map(|s| Some(s.clone()))
            .collect();
        shards[0] = None;
        shards[2] = None;
        shards[4] = None;

        let result = EccBlock::decode(shards, block.original_len, block.hash);
        assert!(result.is_err());
    }

    #[test]
    fn ecc_disk_roundtrip() {
        let dir = tempdir::TempDir::new("ecc_test").unwrap();
        let path = dir.path().join("test_data");
        
        let data = b"Data stored on disk with ECC protection.";
        let block = EccBlock::encode(data).unwrap();
        store_ecc_block(&path, &block).unwrap();

        let loaded = load_ecc_block(&path).unwrap();
        assert_eq!(&loaded, data);
    }
}
