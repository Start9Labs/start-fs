//! Throughput benchmarks for backup-fs
//!
//! Tests sequential reads/writes, random access, and metadata operations

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use tempdir::TempDir;

use backupfs::{BackupFS, BackupFSOptions};
use fuser::MountOption;
use std::sync::{Mutex, OnceLock};

fn mount_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct Unmounter(fuser::SessionUnmounter);
impl Drop for Unmounter {
    fn drop(&mut self) {
        let _ = self.0.unmount();
    }
}

fn with_backupfs<F>(password: String, func: F) -> (TempDir, TempDir)
where
    F: FnOnce(&std::path::Path),
{
    let data = TempDir::new("backupfs_data").unwrap();
    let mnt = TempDir::new("backupfs_mnt").unwrap();
    let opt = vec![
        MountOption::FSName("backup-fs".to_string()),
        MountOption::AutoUnmount,
    ];
    let data_dir = data.path().to_owned();
    let mnt_dir = mnt.path().to_owned();
    let (ready_sender, ready_reciever) = oneshot::channel();
    let thread = std::thread::spawn(move || {
        let fs = BackupFS::new(BackupFSOptions {
            data_dir,
            setuid_support: false,
            password,
            file_size_padding: None,
            readonly: false,
            idmapped_root: vec![],
        })
        .unwrap();
        let mut fs = {
            let _guard = mount_lock().lock().unwrap_or_else(|e| e.into_inner());
            fuser::Session::new(fs, mnt_dir, &opt).unwrap()
        };
        ready_sender.send(Unmounter(fs.unmount_callable())).unwrap();
        fs.run().unwrap();
    });
    if let Ok(umount) = ready_reciever.recv() {
        func(mnt.path());
        drop(umount);
    }
    thread.join().unwrap();
    (data, mnt)
}

fn bench_sequential_writes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential_writes");

    for size in &[64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024] {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let (_data, _mnt) = with_backupfs("bench".to_string(), |mnt| {
                    let test_file = mnt.join("test_file");
                    let data = vec![0x42u8; size];
                    fs::write(&test_file, &data).unwrap();
                });
            });
        });
    }
    group.finish();
}

fn bench_metadata(c: &mut Criterion) {
    let mut group = c.benchmark_group("metadata_ops");

    group.bench_function("create_100_files", |b| {
        b.iter(|| {
            let (_data, _mnt) = with_backupfs("bench".to_string(), |mnt| {
                for i in 0..100 {
                    let file = mnt.join(format!("file_{}", i));
                    fs::write(&file, b"data").unwrap();
                }
            });
        });
    });

    group.bench_function("create_10_dirs_with_files", |b| {
        b.iter(|| {
            let (_data, _mnt) = with_backupfs("bench".to_string(), |mnt| {
                for i in 0..10 {
                    let dir = mnt.join(format!("dir_{}", i));
                    fs::create_dir(&dir).unwrap();
                    for j in 0..10 {
                        let file = dir.join(format!("file_{}", j));
                        fs::write(&file, b"data").unwrap();
                    }
                }
            });
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_sequential_writes,
    bench_metadata,
);
criterion_main!(benches);
