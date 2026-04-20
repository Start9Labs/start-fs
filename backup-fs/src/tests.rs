use crate::error::BkfsErrorKind;
use crate::{BackupFS, BackupFSOptions};
use fuser::MountOption;
use std::future::Future;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::{fs, io, path::Path};
use tempdir::TempDir;
use tokio::task::JoinSet;

/// Deterministic pseudorandom byte pattern keyed by absolute file offset.
/// Any misplaced byte will produce a mismatch, catching buffer ordering bugs.
fn pattern_byte(offset: u64) -> u8 {
    let mut x = offset.wrapping_mul(0x9E3779B97F4A7C15);
    x ^= x >> 27;
    x = x.wrapping_mul(0x3C79AC492BA7B653);
    x ^= x >> 33;
    (x & 0xFF) as u8
}

fn pattern_fill(offset: u64, buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b = pattern_byte(offset + i as u64);
    }
}

fn pattern_check(offset: u64, buf: &[u8]) {
    for (i, &b) in buf.iter().enumerate() {
        let expected = pattern_byte(offset + i as u64);
        assert_eq!(
            b, expected,
            "byte mismatch at offset {}: got {:#04x}, want {:#04x}",
            offset + i as u64,
            b,
            expected
        );
    }
}

fn with_backupfs(
    data: &Path,
    password: String,
    func: impl FnOnce(&Path),
    file_size_padding: Option<f64>,
) {
    struct Unmounter(fuser::SessionUnmounter);
    impl Drop for Unmounter {
        fn drop(&mut self) {
            let _ = self.0.unmount();
        }
    }

    let mnt = tempdir::TempDir::new("backupfs_mnt").unwrap();
    let opt = vec![
        MountOption::FSName("backup-fs".to_string()),
        MountOption::AutoUnmount,
    ];
    let data_dir = data.to_owned();
    let mnt_dir = mnt.path().to_owned();
    let (ready_sender, ready_reciever) = oneshot::channel();
    let thread = std::thread::spawn(move || {
        let fs = BackupFS::new(BackupFSOptions {
            data_dir,
            setuid_support: false,
            password,
            file_size_padding,
            readonly: false,
            idmapped_root: vec![],
        })
        .unwrap();
        let mut fs = fuser::Session::new(fs, mnt_dir, &opt).unwrap();
        ready_sender.send(Unmounter(fs.unmount_callable())).unwrap();
        fs.run().unwrap();
    });
    if let Ok(umount) = ready_reciever.recv() {
        func(mnt.path());
        drop(umount);
    }
    match thread.join() {
        Ok(()) => (),
        Err(err) => std::panic::resume_unwind(err),
    };
}

fn with_backupfs_async<F: Future<Output = ()> + Send + 'static>(
    data: &Path,
    password: String,
    func: impl FnOnce(PathBuf) -> F,
    file_size_padding: Option<f64>,
) {
    with_backupfs(
        data,
        password,
        move |path| {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(func(path.to_owned()))
        },
        file_size_padding,
    )
}

fn tree(path: impl AsRef<Path>, dirs: bool) -> Result<Vec<String>, io::Error> {
    let mut children = Vec::new();
    for e in fs::read_dir(path)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        if e.metadata()?.is_dir() {
            if dirs {
                children.push(name.clone());
            }
            let grandchildren = tree(e.path(), dirs)?;
            children.extend(
                grandchildren
                    .into_iter()
                    .map(|child| format!("{name}/{child}")),
            )
        } else {
            children.push(name);
        }
    }
    children.sort_unstable();
    Ok(children)
}

#[test_log::test]
fn write_file() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::write(mnt.join("a_file"), "foo bar").unwrap();
            assert!(fs::read_dir(mnt).unwrap().any(|e| e
                .as_ref()
                .unwrap()
                .file_name()
                .to_str()
                .unwrap()
                == "a_file"));
            assert_eq!(fs::read(mnt.join("a_file")).unwrap().as_slice(), b"foo bar");
        },
        None,
    );
    assert_eq!(tree(data.path().join("inodes"), false).unwrap().len(), 2);
    assert_eq!(tree(data.path().join("contents"), false).unwrap().len(), 1);
}

#[test_log::test]
fn write_directory() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::create_dir(mnt.join("a")).unwrap();
            fs::create_dir(mnt.join("a/b")).unwrap();
            fs::create_dir(mnt.join("a/c")).unwrap();
            assert_eq!(
                tree(mnt, true).unwrap(),
                vec!["a".to_owned(), "a/b".to_owned(), "a/c".to_owned()]
            )
        },
        None,
    );
    assert_eq!(tree(data.path().join("inodes"), false).unwrap().len(), 4);
}

#[test_log::test]
fn preserves_file() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::write(mnt.join("a_file"), "foo bar").unwrap();
        },
        None,
    );
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            assert_eq!(fs::read(mnt.join("a_file")).unwrap().as_slice(), b"foo bar");
        },
        None,
    );
}

#[test_log::test]
fn preserves_directory() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::create_dir(mnt.join("a")).unwrap();
            fs::create_dir(mnt.join("a/b")).unwrap();
            fs::create_dir(mnt.join("a/c")).unwrap();
        },
        None,
    );

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            assert_eq!(
                tree(mnt, true).unwrap(),
                vec!["a".to_owned(), "a/b".to_owned(), "a/c".to_owned()]
            )
        },
        None,
    );
}

#[test_log::test]
fn checksum() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(data.path(), "ohea".to_owned(), |_mnt| {}, None);
    let res = BackupFS::new(BackupFSOptions {
        data_dir: data.path().to_owned(),
        setuid_support: false,
        password: "rtns".to_owned(),
        file_size_padding: None,
        readonly: false,
        idmapped_root: vec![],
    });
    match res {
        Ok(_) => panic!(),
        Err(err) => assert!(matches!(&err.kind, BkfsErrorKind::BadChecksum)),
    }
}

#[test_log::test]
fn change_password() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::write(mnt.join("a_file"), "foo bar").unwrap();
        },
        None,
    );

    {
        let mut fs = BackupFS::new(BackupFSOptions {
            data_dir: data.path().to_owned(),
            setuid_support: false,
            password: "ohea".to_owned(),
            file_size_padding: None,
            readonly: false,
            idmapped_root: vec![],
        })
        .unwrap();
        fs.change_password("rtns").unwrap();
    }

    with_backupfs(
        data.path(),
        "rtns".to_owned(),
        |mnt| {
            assert_eq!(fs::read(mnt.join("a_file")).unwrap().as_slice(), b"foo bar");
        },
        None,
    );
}

#[test_log::test]
fn write_one_file_async() {
    use tokio::fs;
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs_async(
        data.path(),
        "ohea".to_owned(),
        |mnt| async move {
            fs::write(mnt.join("a_file"), "foo bar").await.unwrap();
            let mut contents = fs::read_dir(&mnt).await.unwrap();
            loop {
                match contents.next_entry().await.unwrap() {
                    Some(entry) => {
                        if entry.file_name() == "a_file" {
                            break;
                        }
                    }
                    None => panic!(),
                }
            }
            assert_eq!(
                fs::read(mnt.join("a_file")).await.unwrap().as_slice(),
                b"foo bar"
            );
        },
        None,
    );
    assert_eq!(tree(data.path().join("inodes"), false).unwrap().len(), 2);
    assert_eq!(tree(data.path().join("contents"), false).unwrap().len(), 1);
}

#[test_log::test]
fn write_many_files_async() {
    use tokio::fs;
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs_async(
        data.path(),
        "ohea".to_owned(),
        |mnt| async move {
            let mut tasks = JoinSet::new();
            for i in 0..100 {
                tasks.spawn(fs::write(mnt.join(format!("{i:02}")), format!("= {i}")));
            }
            while let Some(res) = tasks.join_next().await {
                res.unwrap().unwrap();
            }
            let mut count = 0;
            let mut contents = fs::read_dir(&mnt).await.unwrap();
            while let Some(entry) = contents.next_entry().await.unwrap() {
                if let Ok(i) = dbg!(entry.file_name()).to_str().unwrap().parse::<usize>() {
                    assert_eq!(
                        fs::read(entry.path()).await.unwrap().as_slice(),
                        format!("= {i}").as_bytes()
                    );
                    count += 1;
                }
            }
            assert_eq!(count, 100);
        },
        None,
    );
    assert_eq!(tree(data.path().join("inodes"), false).unwrap().len(), 101);
    assert_eq!(
        tree(data.path().join("contents"), false).unwrap().len(),
        100
    );
}

/// `stat.st_blocks` must be in 512-byte units (POSIX). du-sh relies on this.
/// Regression test for blocks being reported in 4096-byte units.
#[test_log::test]
fn stat_blocks_units() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            // Write a 1 MiB file
            let size: usize = 1024 * 1024;
            let mut buf = vec![0u8; size];
            pattern_fill(0, &mut buf);
            fs::write(mnt.join("big"), &buf).unwrap();

            let meta = fs::metadata(mnt.join("big")).unwrap();
            assert_eq!(meta.size() as usize, size);
            // st_blocks is in 512-byte units. For a 1 MiB file, expect ~2048 blocks.
            // Must be at least ceil(size / 512) and within ~2x (allowing for padding).
            let expected_min = size.div_ceil(512) as u64;
            assert!(
                meta.blocks() >= expected_min,
                "blocks={} too small for {} bytes (expected >= {})",
                meta.blocks(),
                size,
                expected_min
            );
            assert!(
                meta.blocks() <= expected_min * 4,
                "blocks={} unreasonably large for {} bytes (expected <= {})",
                meta.blocks(),
                size,
                expected_min * 4
            );
        },
        None,
    );
}

/// Write a file larger than the 1 MiB BufferedDirectFile window, read back,
/// verify every byte matches the deterministic pattern. Catches reordering,
/// truncation, and partial-flush bugs.
#[test_log::test]
fn large_file_integrity() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            // 3.5 MiB — spans 4 windows, with a partial last window
            let size: usize = 3 * 1024 * 1024 + 512 * 1024 + 7;
            let mut buf = vec![0u8; size];
            pattern_fill(0, &mut buf);
            fs::write(mnt.join("bigdata"), &buf).unwrap();

            let readback = fs::read(mnt.join("bigdata")).unwrap();
            assert_eq!(readback.len(), size);
            pattern_check(0, &readback);
        },
        None,
    );
}

/// Write in multiple chunks at varying offsets (including crossing window
/// boundaries), verify the complete file.
#[test_log::test]
fn random_access_writes() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let size: u64 = 2 * 1024 * 1024 + 500_000; // ~2.5 MiB
            let path = mnt.join("scattered");

            // Create file and write chunks in a non-sequential order
            let mut f = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            // First extend to full size
            f.set_len(size).unwrap();

            // Write in an order that forces multiple window evictions.
            // Ranges must partition [0, size) — every byte covered exactly once.
            let ranges: &[(u64, usize)] = &[
                (1_500_000, 600_000),                     // crosses window 1→2
                (0, 100_000),                             // early in window 0
                (2_100_000, size as usize - 2_100_000),   // tail
                (500_000, 1_000_000),                     // spans window 0→1
                (100_000, 400_000),                       // fills gap in window 0
            ];
            for &(offset, len) in ranges {
                let mut buf = vec![0u8; len];
                pattern_fill(offset, &mut buf);
                f.seek(SeekFrom::Start(offset)).unwrap();
                f.write_all(&buf).unwrap();
            }
            drop(f);

            let readback = fs::read(&path).unwrap();
            assert_eq!(readback.len() as u64, size);
            pattern_check(0, &readback);
        },
        None,
    );
}

/// Persist, remount, and verify data integrity — catches flush/Drop bugs.
#[test_log::test]
fn large_file_persists_across_remount() {
    let data = TempDir::new("backupfs_data").unwrap();
    let size: usize = 2 * 1024 * 1024 + 3;

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let mut buf = vec![0u8; size];
            pattern_fill(0, &mut buf);
            fs::write(mnt.join("persisted"), &buf).unwrap();
        },
        None,
    );

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let readback = fs::read(mnt.join("persisted")).unwrap();
            assert_eq!(readback.len(), size);
            pattern_check(0, &readback);
        },
        None,
    );
}

/// Partial overwrite: write a file, then rewrite a middle range. Verify
/// unchanged regions are preserved and overwritten regions have new data.
#[test_log::test]
fn partial_overwrite_preserves_surrounding_data() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let size: u64 = 3 * 1024 * 1024;
            let path = mnt.join("overwritten");

            // Initial write: pattern keyed on offset
            let mut buf = vec![0u8; size as usize];
            pattern_fill(0, &mut buf);
            fs::write(&path, &buf).unwrap();

            // Overwrite middle region with a different pattern (offset by constant)
            let overwrite_start: u64 = 800_000;
            let overwrite_len: usize = 700_000; // spans window boundary
            let overwrite_offset = 0xDEAD_BEEF_u64;
            let mut overlay = vec![0u8; overwrite_len];
            pattern_fill(overwrite_offset, &mut overlay);

            let mut f = fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.seek(SeekFrom::Start(overwrite_start)).unwrap();
            f.write_all(&overlay).unwrap();
            drop(f);

            // Read back and verify
            let readback = fs::read(&path).unwrap();
            assert_eq!(readback.len() as u64, size);

            // Prefix: original pattern
            pattern_check(0, &readback[..overwrite_start as usize]);
            // Middle: overlay pattern
            pattern_check(
                overwrite_offset,
                &readback[overwrite_start as usize..overwrite_start as usize + overwrite_len],
            );
            // Suffix: original pattern resumes at overwrite_start + overwrite_len
            pattern_check(
                overwrite_start + overwrite_len as u64,
                &readback[overwrite_start as usize + overwrite_len..],
            );
        },
        None,
    );
}
