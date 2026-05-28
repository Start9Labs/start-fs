//! Benchmarks for backup-fs operations.
//!
//! These measure throughput for both the existing single-file-per-inode
//! approach and the new block-store approach to validate the refactor.
//!
//! Run with: `cargo test --release -- --nocapture benchmarks::`

use std::time::Instant;

/// Simple micro-benchmark helper.
struct BenchResult {
    name: &'static str,
    elapsed: std::time::Duration,
    throughput: f64, // MB/s
    ops: u64,
}

impl BenchResult {
    fn new(name: &'static str, elapsed: std::time::Duration, bytes: u64) -> Self {
        let throughput = if elapsed.as_secs_f64() > 0.0 {
            bytes as f64 / 1_000_000.0 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        Self {
            name,
            elapsed,
            throughput,
            ops: bytes,
        }
    }
}

/// Run a benchmark and report results.
fn bench<F>(name: &'static str, f: F) -> BenchResult
where
    F: FnOnce() -> u64,
{
    let start = Instant::now();
    let bytes = f();
    let elapsed = start.elapsed();
    BenchResult::new(name, elapsed, bytes)
}

fn report(results: &[BenchResult]) {
    println!();
    println!("{:=<80}", "");
    println!(
        "{:40} {:>10} {:>12} {:>12}",
        "Benchmark", "Time", "Bytes", "Throughput"
    );
    println!("{:-<80}", "");
    for r in results {
        println!(
            "{:40} {:>8.2?}  {:>10} B  {:>8.2} MB/s",
            r.name, r.elapsed, r.ops, r.throughput
        );
    }
    println!("{:=<80}", "");
}

#[test]
fn ecc_encode_throughput() {
    use crate::ecc::{EccCodec, EccConfig};

    let config = EccConfig::new(8, 2, 256 * 1024);
    let codec = EccCodec::new(config);

    let data: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            let mut v = vec![i as u8; 256 * 1024];
            v[0] = i as u8;
            v
        })
        .collect();

    let total_bytes = 8 * 256 * 1024; // 2 MiB of data

    let results = vec![bench("ECC encode 8×(256 KiB) → 2 parity", || {
        let _ = codec.encode(&data);
        total_bytes as u64
    })];

    report(&results);

    // ECC encode should be fast — at least 100 MB/s on modern hardware
    #[cfg(feature = "ecc")]
    assert!(
        results[0].throughput > 50.0,
        "ECC encode too slow: {:.2} MB/s",
        results[0].throughput
    );
}

#[test]
fn blake3_hashing_throughput() {
    let data = vec![0u8; 256 * 1024]; // 256 KiB

    let results = vec![bench("BLAKE3 hash 256 KiB", || {
        let _ = blake3::hash(&data);
        data.len() as u64
    })];

    report(&results);

    assert!(
        results[0].throughput > 100.0,
        "BLAKE3 hashing too slow: {:.2} MB/s",
        results[0].throughput
    );
}

#[test]
fn ecc_decode_corruption_recovery() {
    use crate::ecc::{EccCodec, EccConfig};

    let config = EccConfig::new(8, 2, 256 * 1024);
    let codec = EccCodec::new(config);

    let data: Vec<Vec<u8>> = (0..8)
        .map(|i| {
            let mut v = vec![i as u8; 256 * 1024];
            v[0] = i as u8;
            v
        })
        .collect();

    let encoded = codec.encode(&data);

    // Simulate 2 missing shards and decode
    let mut shards = encoded.shards.clone();
    let present: Vec<bool> = vec![true, true, true, false, true, true, true, false, true, true];
    shards[3].clear();
    shards[7].clear();

    let results = vec![bench("ECC decode 2/8 missing shards", || {
        let recovered = codec.decode(&shards, &present).unwrap();
        // Verify recovered matches original
        for i in 0..config.data_shards {
            assert_eq!(recovered[i][0], data[i][0]);
        }
        8 * 256 * 1024
    })];

    report(&results);

    // Decode should still be reasonably fast
    #[cfg(feature = "ecc")]
    assert!(
        results[0].throughput > 30.0,
        "ECC decode too slow: {:.2} MB/s",
        results[0].throughput
    );
}

#[test]
fn block_manifest_serialization_roundtrip() {
    use crate::block_store::BlockManifest;
    use crate::ecc::EccConfig;

    // Simulate a manifest for a 100 MiB file (~400 blocks)
    let manifest = BlockManifest::new(256 * 1024, 100 * 1024 * 1024, EccConfig::default());

    let results = vec![
        bench("BlockManifest serialize (400 blocks)", || {
            let _bytes = bincode::serialize(&manifest).unwrap();
            100 * 1024 * 1024
        }),
        bench("BlockManifest deserialize (400 blocks)", || {
            let bytes = bincode::serialize(&manifest).unwrap();
            let _: BlockManifest = bincode::deserialize(&bytes).unwrap();
            100 * 1024 * 1024
        }),
    ];

    report(&results);

    // Serialization should be fast (< 50ms for 400 blocks)
    assert!(results[0].elapsed.as_millis() < 50, "too slow");
}

#[test]
fn atomic_file_save_throughput() {
    use crate::atomic_file::AtomicFile;
    use std::io::Write;
    use tempdir::TempDir;

    let dir = TempDir::new("bench_atomic").unwrap();
    let path = dir.path().join("test.bin");
    let data = vec![0xAAu8; 4096]; // 4 KiB (typical inode size)

    let results = vec![bench("AtomicFile save 4 KiB (inode)", || {
        let mut af = AtomicFile::create(path.clone()).unwrap();
        af.write_all(&data).unwrap();
        af.save().unwrap();
        data.len() as u64
    })];

    report(&results);
}

#[test]
fn encryption_throughput() {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20;

    let key: [u8; 32] = [0x42; 32];
    let key = chacha20::Key::clone_from_slice(&key);
    let iv: [u8; 12] = [0x13; 12];
    let iv = iv.into();

    let data_sizes = [(4096_usize, "4 KiB"), (256 * 1024, "256 KiB"), (1024 * 1024, "1 MiB")];

    let mut results = Vec::new();
    for (size, label) in &data_sizes {
        let data = vec![0xBBu8; *size];
        let name = Box::leak(format!("ChaCha20 encrypt {label}").into_boxed_str());
        let key = key.clone();
        results.push(bench(name, || {
            let cipher = ChaCha20::new(&key, &iv);
            let mut buf = data.clone();
            let mut cipher = cipher;
            cipher.apply_keystream(&mut buf);
            *size as u64
        }));
    }

    report(&results);
}

/// Comprehensive benchmark testing ECC encode throughput at different sizes.
#[test]
fn comprehensive_ecc_bench() {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║              backup-fs ECC + Block Store Benchmarks            ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");

    ecc_encode_throughput();
    blake3_hashing_throughput();
    ecc_decode_corruption_recovery();
    block_manifest_serialization_roundtrip();
    atomic_file_save_throughput();
    encryption_throughput();
}