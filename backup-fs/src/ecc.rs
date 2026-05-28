//! Reed-Solomon error correction for data blocks.
//!
//! Uses a configurable (data, parity) scheme. Default: 8 data blocks + 2 parity
//! blocks per group, allowing recovery from up to 2 corrupted/missing blocks.

#[cfg(feature = "ecc")]
use reed_solomon_simd::ReedSolomonDecoder;
#[cfg(feature = "ecc")]
use reed_solomon_simd::ReedSolomonEncoder;
#[cfg(feature = "ecc")]
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Default ECC configuration: 8 data shards + 2 parity shards.
/// This means every group of 8 data blocks gets 2 parity blocks,
/// allowing recovery from up to 2 block losses per group.
pub const DEFAULT_DATA_SHARDS: usize = 8;
pub const DEFAULT_PARITY_SHARDS: usize = 2;

/// ECC configuration for content blocks.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EccConfig {
    pub data_shards: usize,
    pub parity_shards: usize,
    /// Total shards per group = data_shards + parity_shards
    #[serde(skip)]
    pub total_shards: usize,
    /// Block size in bytes (each shard is this size)
    pub block_size: usize,
}

impl Default for EccConfig {
    fn default() -> Self {
        Self {
            data_shards: DEFAULT_DATA_SHARDS,
            parity_shards: DEFAULT_PARITY_SHARDS,
            total_shards: DEFAULT_DATA_SHARDS + DEFAULT_PARITY_SHARDS,
            block_size: 256 * 1024, // 256 KiB blocks
        }
    }
}

impl EccConfig {
    /// Create with custom data and parity shard counts.
    pub fn new(data_shards: usize, parity_shards: usize, block_size: usize) -> Self {
        Self {
            data_shards,
            parity_shards,
            total_shards: data_shards + parity_shards,
            block_size,
        }
    }
}

/// Result from encoding a group of blocks.
#[derive(Debug, Clone)]
pub struct EncodedGroup {
    /// All shards (data + parity), each exactly block_size bytes.
    pub shards: Vec<Vec<u8>>,
    pub config: EccConfig,
}

impl EncodedGroup {
    pub fn data_shards(&self) -> &[Vec<u8>] {
        &self.shards[..self.config.data_shards]
    }

    pub fn parity_shards(&self) -> &[Vec<u8>] {
        &self.shards[self.config.data_shards..]
    }
}

/// Error correction encoder/decoder.
pub struct EccCodec {
    config: EccConfig,
}

impl EccCodec {
    /// Create a new codec with the given configuration.
    pub fn new(config: EccConfig) -> Self {
        assert!(
            config.data_shards > 0 && config.parity_shards > 0,
            "ECC requires at least 1 data shard and 1 parity shard"
        );
        assert!(
            config.total_shards <= 256,
            "reed-solomon-simd supports up to 256 total shards"
        );
        Self { config }
    }

    pub fn config(&self) -> &EccConfig {
        &self.config
    }

    /// Encode a group of data blocks, producing parity blocks.
    ///
    /// `data` must contain exactly `config.data_shards` blocks, each
    /// exactly `config.block_size` bytes. Blocks smaller than block_size
    /// should be zero-padded by the caller.
    #[cfg(feature = "ecc")]
    pub fn encode(&self, data: &[Vec<u8>]) -> EncodedGroup {
        assert_eq!(
            data.len(),
            self.config.data_shards,
            "encode requires exactly {} data blocks, got {}",
            self.config.data_shards,
            data.len()
        );

        let mut encoder = ReedSolomonEncoder::new(
            self.config.data_shards,
            self.config.parity_shards,
            self.config.block_size,
        )
        .expect("valid ECC configuration");

        // Add all original shards
        for block in data {
            encoder
                .add_original_shard(block.as_slice())
                .expect("same shard size");
        }

        let result = encoder.encode().expect("encode should not fail");

        // Collect data + parity into a single vector
        let mut shards: Vec<Vec<u8>> = data.to_vec();
        for recovery in result.recovery_iter() {
            shards.push(recovery.to_vec());
        }

        EncodedGroup {
            shards,
            config: self.config,
        }
    }

    /// No-op encode when ECC is disabled (returns just data with empty parity).
    #[cfg(not(feature = "ecc"))]
    pub fn encode(&self, data: &[Vec<u8>]) -> EncodedGroup {
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(self.config.total_shards);
        for block in data {
            let mut padded = vec![0u8; self.config.block_size];
            let copy_len = block.len().min(self.config.block_size);
            padded[..copy_len].copy_from_slice(&block[..copy_len]);
            shards.push(padded);
        }
        for _ in 0..self.config.parity_shards {
            shards.push(vec![0u8; self.config.block_size]);
        }
        EncodedGroup {
            shards,
            config: self.config,
        }
    }

    /// Decode a group of blocks, possibly repairing up to parity_shards
    /// missing blocks.
    ///
    /// `shards` must contain exactly `config.total_shards` entries.
    /// Entries for missing shards should be empty Vec<u8>.
    #[cfg(feature = "ecc")]
    pub fn decode(&self, shards: &[Vec<u8>], present: &[bool]) -> Result<Vec<Vec<u8>>, String> {
        assert_eq!(
            shards.len(),
            self.config.total_shards,
            "decode requires {} shards, got {}",
            self.config.total_shards,
            shards.len()
        );

        // Identify which original shards are present vs missing
        let present_originals: Vec<(usize, &[u8])> = (0..self.config.data_shards)
            .filter(|&i| present.get(i).copied().unwrap_or(true) && !shards[i].is_empty())
            .map(|i| (i, shards[i].as_slice()))
            .collect();

        // Identify which recovery shards are present
        let present_recovery: Vec<(usize, &[u8])> = (0..self.config.parity_shards)
            .filter(|&i| {
                let idx = self.config.data_shards + i;
                present.get(idx).copied().unwrap_or(true) && !shards[idx].is_empty()
            })
            .map(|i| (i, shards[self.config.data_shards + i].as_slice()))
            .collect();

        if present_originals.len() + present_recovery.len() < self.config.data_shards {
            return Err(format!(
                "not enough shards: {} present, need {}",
                present_originals.len() + present_recovery.len(),
                self.config.data_shards
            ));
        }

        // If all originals are present, no decoding needed
        if present_originals.len() == self.config.data_shards && present_recovery.is_empty() {
            return Ok(shards[..self.config.data_shards].to_vec());
        }

        let mut decoder = ReedSolomonDecoder::new(
            self.config.data_shards,
            self.config.parity_shards,
            self.config.block_size,
        )
        .map_err(|e| format!("ECC decode setup failed: {e}"))?;

        for (idx, data) in &present_originals {
            decoder
                .add_original_shard(*idx, *data)
                .map_err(|e| format!("add original shard {idx}: {e}"))?;
        }
        for (idx, data) in &present_recovery {
            decoder
                .add_recovery_shard(*idx, *data)
                .map_err(|e| format!("add recovery shard {idx}: {e}"))?;
        }

        let result = decoder
            .decode()
            .map_err(|e| format!("ECC decode failed: {e}"))?;

        // Build result with recovered blocks
        let mut restored: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        for (idx, data) in result.restored_original_iter() {
            restored.insert(idx, data.to_vec());
        }

        // Merge present originals and restored ones
        let mut out = shards[..self.config.data_shards].to_vec();
        for (idx, data) in restored {
            if idx < out.len() {
                out[idx] = data;
            }
        }

        Ok(out)
    }

    /// No-op decode when ECC is disabled.
    #[cfg(not(feature = "ecc"))]
    pub fn decode(&self, shards: &[Vec<u8>], _present: &[bool]) -> Result<Vec<Vec<u8>>, String> {
        Ok(shards[..self.config.data_shards].to_vec())
    }
}

/// Compute group index and shard index for a block within a file.
#[derive(Debug, Clone, Copy)]
pub struct BlockPosition {
    /// Which ECC group this block belongs to.
    pub group: u64,
    /// Index within the group (0..data_shards for data, data_shards..total_shards for parity).
    pub shard: usize,
    /// Whether this is a parity block (true) or data block (false).
    pub is_parity: bool,
}

impl BlockPosition {
    pub fn from_block_idx(block_idx: u64, config: &EccConfig) -> Self {
        let group = block_idx / config.data_shards as u64;
        let shard = (block_idx % config.data_shards as u64) as usize;
        Self {
            group,
            shard,
            is_parity: false,
        }
    }

    pub fn parity(group: u64, shard: usize, config: &EccConfig) -> Self {
        assert!(shard < config.parity_shards);
        Self {
            group,
            shard: config.data_shards + shard,
            is_parity: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "ecc")]
    fn encode_decode_roundtrip() {
        let config = EccConfig::new(4, 2, 256);
        let codec = EccCodec::new(config);

        let data: Vec<Vec<u8>> = (0..4)
            .map(|i| {
                let mut v = vec![0u8; 256];
                v[0] = i as u8;
                v[1] = (i + 1) as u8;
                v
            })
            .collect();

        let encoded = codec.encode(&data);

        // Simulate 2 shards missing
        let mut shards = encoded.shards.clone();
        let present: Vec<bool> = vec![true, true, true, false, true, false];
        shards[3].clear();
        shards[5].clear();

        let recovered = codec.decode(&shards, &present).unwrap();
        for i in 0..config.data_shards {
            assert_eq!(recovered[i][0], data[i][0], "shard {i} byte 0 mismatch");
            assert_eq!(recovered[i][1], data[i][1], "shard {i} byte 1 mismatch");
        }
    }

    #[test]
    fn block_position() {
        let config = EccConfig::new(8, 2, 256 * 1024);
        // Block 0 → group 0, shard 0
        let pos = BlockPosition::from_block_idx(0, &config);
        assert_eq!(pos.group, 0);
        assert_eq!(pos.shard, 0);
        assert!(!pos.is_parity);

        // Block 9 → group 1, shard 1
        let pos = BlockPosition::from_block_idx(9, &config);
        assert_eq!(pos.group, 1);
        assert_eq!(pos.shard, 1);
        assert!(!pos.is_parity);

        // Parity blocks
        let pos = BlockPosition::parity(0, 0, &config);
        assert_eq!(pos.group, 0);
        assert_eq!(pos.shard, 8);
        assert!(pos.is_parity);

        let pos = BlockPosition::parity(0, 1, &config);
        assert_eq!(pos.group, 0);
        assert_eq!(pos.shard, 9);
        assert!(pos.is_parity);
    }
}
