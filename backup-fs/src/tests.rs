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

/// Serializes the fusermount3 invocation across parallel tests.
/// The helper talks to a per-user control socket and races with itself
/// under `cargo test -j N`, yielding sporadic EPERM from Session::new.
/// Holding the lock only through mount keeps the test bodies
/// themselves parallel.
fn mount_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
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

/// rm -rf should fully remove a tree from disk — no orphan inode files.
///
/// Suspected zombie-inode bug in the dirty-cache coalescing: unlink goes
/// through mutate_inode, which takes the inode out of dirty, the closure
/// calls gc_inode (which removes the disk file), but mutate_inode then
/// unconditionally re-inserts the (now parent-less) attrs back into
/// dirty. On unmount, flush_all_dirty writes the zombie back to disk as
/// a resurrected orphan.
///
/// Also: after rm-rf of a subtree, re-creating a directory with the
/// same path must work — which it won't if some intermediate ancestor
/// is in a half-deleted state.
#[test_log::test]
fn rmrf_leaves_no_orphans() {
    let data = TempDir::new("backupfs_data").unwrap();

    // Phase 1: create nested tree + files
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::create_dir(mnt.join("backup")).unwrap();
            fs::create_dir(mnt.join("backup/volumes")).unwrap();
            fs::create_dir(mnt.join("backup/volumes/main")).unwrap();
            for i in 0..10 {
                fs::write(
                    mnt.join(format!("backup/volumes/main/f{i:02}")),
                    format!("payload {i}"),
                )
                .unwrap();
            }
        },
        None,
    );

    // Snapshot inode-file count after creation.
    let inode_files_after_create =
        tree(data.path().join("inodes"), false).unwrap().len();
    let content_files_after_create =
        tree(data.path().join("contents"), false).unwrap().len();

    // Phase 2: rm -rf the whole subtree
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::remove_dir_all(mnt.join("backup")).unwrap();
        },
        None,
    );

    // Phase 3: remount, verify state is clean
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            assert!(
                !mnt.join("backup").exists(),
                "backup/ should be gone after rm-rf"
            );
            // Re-create the exact path rsync would need.
            fs::create_dir(mnt.join("backup")).unwrap();
            fs::create_dir(mnt.join("backup/volumes")).unwrap();
            fs::create_dir(mnt.join("backup/volumes/main")).unwrap();
            assert!(
                mnt.join("backup/volumes/main").is_dir(),
                "could not recreate previously-rm-rf'd path"
            );
        },
        None,
    );

    // After rm-rf we deleted 13 inodes (3 dirs + 10 files) and 10 content
    // files. After the phase-3 re-creates we add 3 inodes (3 dirs) and 0
    // content files. Net relative to phase 1: inodes -10, contents -10.
    let inodes_now = tree(data.path().join("inodes"), false).unwrap();
    let contents_now = tree(data.path().join("contents"), false).unwrap();
    let expected_inodes = inode_files_after_create - 10;
    let expected_contents = content_files_after_create - 10;
    assert_eq!(
        inodes_now.len(),
        expected_inodes,
        "orphan inode files left after rm-rf: expected {expected_inodes}, got {} — {:?}",
        inodes_now.len(),
        inodes_now
    );
    assert_eq!(
        contents_now.len(),
        expected_contents,
        "orphan content files left after rm-rf: expected {expected_contents}, got {}",
        contents_now.len()
    );
}

/// Full backup-then-delete cycle across mount boundaries. Reproduces
/// the exact shape a user sees when they run a backup, unmount,
/// remount, and `rm -rf` the backup tree: every inode lives on disk
/// from the prior session's flush.
#[test_log::test]
fn rmrf_after_remount_updates_root() {
    let data = TempDir::new("backupfs_data").unwrap();

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::create_dir(mnt.join("backup")).unwrap();
            fs::create_dir(mnt.join("backup/volumes")).unwrap();
            fs::create_dir(mnt.join("backup/volumes/main")).unwrap();
            for i in 0..5 {
                fs::write(
                    mnt.join(format!("backup/volumes/main/f{i:02}")),
                    format!("payload {i}"),
                )
                .unwrap();
            }
        },
        None,
    );

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::remove_dir_all(mnt.join("backup")).unwrap();
            let live: Vec<String> = fs::read_dir(mnt)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                !live.contains(&"backup".to_owned()),
                "root listing still shows deleted subtree: {:?}",
                live
            );
        },
        None,
    );

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let after: Vec<String> = fs::read_dir(mnt)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                !after.contains(&"backup".to_owned()),
                "remount listing still shows deleted subtree: {:?}",
                after
            );
            assert!(
                !mnt.join("backup").exists(),
                "backup/ survived remount after rm-rf"
            );
        },
        None,
    );
}

/// A crash or earlier bug can leave a parent directory whose entries
/// reference an inode file that no longer exists. `rmdir`/`unlink` of
/// the stale entry must not keep returning ENOENT forever — the user
/// has no way to recover if cleanup is impossible.
#[test_log::test]
fn rmdir_heals_stale_parent_reference() {
    let data = TempDir::new("backupfs_data").unwrap();

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::create_dir(mnt.join("parent")).unwrap();
            fs::create_dir(mnt.join("parent/keep")).unwrap();
            fs::create_dir(mnt.join("parent/stale")).unwrap();
        },
        None,
    );

    // Snapshot what's on disk, then corrupt: find the 'stale' inode's
    // on-disk file and remove it. The parent dir still references it.
    let before: std::collections::HashSet<String> = tree(data.path().join("inodes"), false)
        .unwrap()
        .into_iter()
        .collect();

    // Remove one inode file to simulate a lost write / torn unmount.
    // We don't know which file corresponds to "stale" without digging
    // into the encryption, so we open the FS and find the one whose
    // removal produces the symptom.
    //
    // Simpler: mount, look up "stale" to get its inode number, then
    // remove its inode file externally.
    let stale_inode = {
        let (tx, rx) = oneshot::channel::<Option<u64>>();
        let data_path = data.path().to_owned();
        std::thread::spawn(move || {
            with_backupfs(
                &data_path,
                "ohea".to_owned(),
                |mnt| {
                    let meta = fs::metadata(mnt.join("parent/stale")).unwrap();
                    let _ = tx.send(Some(meta.ino()));
                },
                None,
            );
        })
        .join()
        .unwrap();
        rx.recv().unwrap().unwrap()
    };

    // Now find which inode file corresponds to that inode and remove
    // it externally (this models an unclean shutdown where the
    // parent's dir entry was saved but the child's inode wasn't).
    let inode_dir = data.path().join("inodes");
    let inodes_after: std::collections::HashSet<String> = tree(&inode_dir, false)
        .unwrap()
        .into_iter()
        .collect();
    // New inodes after the lookup session are exactly the candidates.
    let _new_inodes: Vec<_> = inodes_after.difference(&before).collect();

    // Deterministic approach: peel off the Controller and call
    // resolve_inode_path directly.
    let ctrl = crate::ctrl::Controller::new(BackupFSOptions {
        data_dir: data.path().to_owned(),
        setuid_support: false,
        password: "ohea".to_owned(),
        file_size_padding: None,
        readonly: false,
        idmapped_root: vec![],
    })
    .unwrap();
    let path = ctrl.resolve_inode_path(crate::inode::Inode(stale_inode));
    assert!(path.exists(), "expected stale inode file at {:?}", path);
    fs::remove_file(&path).unwrap();
    drop(ctrl);

    // Now remount and try to clean up the stale entry.
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            // rmdir should succeed (or at worst give ENOENT, which we
            // then want to be recoverable).
            match fs::remove_dir(mnt.join("parent/stale")) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    // Recovery path: try to look up the parent and
                    // confirm listing is clean.
                }
                Err(e) => panic!("unexpected error: {e}"),
            }
            let live: Vec<String> = fs::read_dir(mnt.join("parent"))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                !live.contains(&"stale".to_owned()),
                "parent listing still shows stale entry: {:?}",
                live
            );
        },
        None,
    );
}

/// Unlink a file after remount: make sure the file disappears from
/// the parent's listing AND the content file is reaped.
#[test_log::test]
fn unlink_file_after_remount() {
    let data = TempDir::new("backupfs_data").unwrap();

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::create_dir(mnt.join("d")).unwrap();
            fs::write(mnt.join("d/keep"), b"keep").unwrap();
            fs::write(mnt.join("d/kill"), b"kill").unwrap();
        },
        None,
    );

    let content_before = tree(data.path().join("contents"), false).unwrap().len();

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::remove_file(mnt.join("d/kill")).unwrap();
            let live: Vec<String> = fs::read_dir(mnt.join("d"))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                live,
                vec!["keep".to_owned()],
                "live listing contained unlinked file: {:?}",
                live
            );
        },
        None,
    );

    assert_eq!(
        tree(data.path().join("contents"), false).unwrap().len(),
        content_before - 1,
        "unlinked file's content blob wasn't reaped"
    );
}

/// Create a subtree in one mount session, then in a *fresh* mount
/// session do the removal. Matches the pattern a user hits when they
/// mount, delete, unmount — all inode files exist on disk from the
/// prior session, so the failure mode differs from the same-session
/// case: here gc_inode should find the disk file and remove it.
#[test_log::test]
fn rmdir_after_remount_updates_parent() {
    let data = TempDir::new("backupfs_data").unwrap();

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::create_dir(mnt.join("parent")).unwrap();
            fs::create_dir(mnt.join("parent/keep")).unwrap();
            fs::create_dir(mnt.join("parent/remove")).unwrap();
        },
        None,
    );

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::remove_dir(mnt.join("parent/remove")).unwrap();
            let live: Vec<String> = fs::read_dir(mnt.join("parent"))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                live,
                vec!["keep".to_owned()],
                "live listing contained removed child: {:?}",
                live
            );
        },
        None,
    );

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let after: Vec<String> = fs::read_dir(mnt.join("parent"))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                after,
                vec!["keep".to_owned()],
                "remount after removal still listed child: {:?}",
                after
            );
        },
        None,
    );
}

/// Deleting a child must remove it from the parent's live directory
/// listing AND from the persisted copy. Regression test for a batched
/// dirty-cache save racing a stale parent snapshot.
#[test_log::test]
fn rmdir_updates_parent_listing() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::create_dir(mnt.join("parent")).unwrap();
            fs::create_dir(mnt.join("parent/keep")).unwrap();
            fs::create_dir(mnt.join("parent/remove")).unwrap();
            fs::remove_dir(mnt.join("parent/remove")).unwrap();

            let live: Vec<String> = fs::read_dir(mnt.join("parent"))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                live,
                vec!["keep".to_owned()],
                "live listing contained removed child: {:?}",
                live
            );
        },
        None,
    );

    // Remount and verify the listing was persisted.
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let after: Vec<String> = fs::read_dir(mnt.join("parent"))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert_eq!(
                after,
                vec!["keep".to_owned()],
                "remounted listing contained removed child: {:?}",
                after
            );
        },
        None,
    );
}

/// Multiple sequential writes to the same file must land in order on
/// disk, even though they're dispatched through the sharded worker
/// pool. Each write targets its own aligned region; reading back must
/// reproduce the exact pattern we wrote.
///
/// Regression guard against a pool design where different workers could
/// race on the same file's mutex and clobber each other's state.
#[test_log::test]
fn sequential_writes_preserve_order() {
    const WRITES: usize = 64;
    const BLOCK: usize = 4096;
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let path = mnt.join("file");
            let mut f = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            for i in 0..WRITES {
                let mut chunk = vec![0u8; BLOCK];
                pattern_fill((i * BLOCK) as u64, &mut chunk);
                f.write_all(&chunk).unwrap();
            }
            drop(f);
            let read = fs::read(&path).unwrap();
            assert_eq!(read.len(), WRITES * BLOCK);
            pattern_check(0, &read);
        },
        None,
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

/// Regression test for the "rename-over-existing" pattern used by
/// atomic save helpers: write to `.name.tmp`, then `rename(.name.tmp,
/// name)` to atomically replace the destination. After the rename the
/// new name must resolve — `ls` showing the entry while `cat` returns
/// ENOENT was the reported symptom.
#[test_log::test]
fn rename_over_existing_resolves() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::write(mnt.join("os-backup.json"), b"old").unwrap();
            fs::write(mnt.join(".os-backup.json.tmp"), b"new contents").unwrap();
            fs::rename(
                mnt.join(".os-backup.json.tmp"),
                mnt.join("os-backup.json"),
            )
            .unwrap();

            let live: Vec<String> = fs::read_dir(mnt)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                live.iter().any(|n| n == "os-backup.json"),
                "listing missing os-backup.json: {live:?}"
            );
            assert!(
                !live.iter().any(|n| n == ".os-backup.json.tmp"),
                "listing still has tmp after rename: {live:?}"
            );

            assert_eq!(
                fs::read(mnt.join("os-backup.json")).unwrap(),
                b"new contents"
            );
        },
        None,
    );

    // Same check after a remount — disk state has to be consistent.
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let live: Vec<String> = fs::read_dir(mnt)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                live.iter().any(|n| n == "os-backup.json"),
                "post-remount listing missing os-backup.json: {live:?}"
            );
            assert_eq!(
                fs::read(mnt.join("os-backup.json")).unwrap(),
                b"new contents"
            );
        },
        None,
    );
}

/// Real-world pattern: a backup root that also holds several sibling
/// directories (service subdirs) alongside `os-backup.json`. We write
/// the atomic-save over it, then cleanly unmount and remount, then
/// repeat the atomic save — cumulative cross-session state is what
/// users actually run into.
#[test_log::test]
fn rename_over_existing_with_siblings_across_remounts() {
    let data = TempDir::new("backupfs_data").unwrap();

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            for d in [
                "actual-budget",
                "bitcoind",
                "btcpayserver",
                "luks",
                "vaultwarden",
            ] {
                fs::create_dir(mnt.join(d)).unwrap();
            }
            fs::write(mnt.join("os-backup.json"), b"first").unwrap();
        },
        None,
    );

    for round in 0..5 {
        with_backupfs(
            data.path(),
            "ohea".to_owned(),
            |mnt| {
                let tmp = mnt.join(".os-backup.json.tmp");
                {
                    let mut f = fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&tmp)
                        .unwrap();
                    f.write_all(format!("round-{round}").as_bytes()).unwrap();
                    f.sync_all().unwrap();
                }
                fs::rename(&tmp, mnt.join("os-backup.json")).unwrap();

                let got = fs::read(mnt.join("os-backup.json")).unwrap();
                assert_eq!(got, format!("round-{round}").as_bytes());
            },
            None,
        );

        // Fresh mount: must still see os-backup.json and be able to
        // read it back. This is the exact pattern the user reported
        // failing ("ls shows it, cat says ENOENT").
        with_backupfs(
            data.path(),
            "ohea".to_owned(),
            |mnt| {
                let live: Vec<String> = fs::read_dir(mnt)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                assert!(
                    live.iter().any(|n| n == "os-backup.json"),
                    "round {round}: post-remount ls missing os-backup.json: {live:?}"
                );
                let got = fs::read(mnt.join("os-backup.json")).unwrap_or_else(|e| {
                    panic!("round {round}: post-remount cat failed: {e}")
                });
                assert_eq!(got, format!("round-{round}").as_bytes());
            },
            None,
        );
    }
}

/// Repeated rename-over-existing (the "atomic save" pattern applied
/// many times). Each round overwrites the previous version and must
/// leave exactly one resolvable entry.
#[test_log::test]
fn rename_over_existing_many_rounds() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            for i in 0..20 {
                let payload = format!("round-{i}");
                let tmp = mnt.join(".os-backup.json.tmp");
                {
                    let mut f = fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&tmp)
                        .unwrap();
                    f.write_all(payload.as_bytes()).unwrap();
                    f.sync_all().unwrap();
                }
                fs::rename(&tmp, mnt.join("os-backup.json")).unwrap();

                let got = fs::read(mnt.join("os-backup.json")).unwrap();
                assert_eq!(
                    got,
                    payload.as_bytes(),
                    "round {i}: read back wrong bytes"
                );
                let live: Vec<String> = fs::read_dir(mnt)
                    .unwrap()
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                assert!(
                    !live.iter().any(|n| n == ".os-backup.json.tmp"),
                    "round {i}: tmp still visible: {live:?}"
                );
            }
        },
        None,
    );

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            assert_eq!(
                fs::read(mnt.join("os-backup.json")).unwrap(),
                b"round-19",
                "final round not persisted"
            );
        },
        None,
    );
}

/// Mirrors start-os's AtomicFile pattern exactly: create tmp, write,
/// fsync, drop fd, rename, then immediately unmount. The user reports
/// this sequence loses data on clean unmount.
#[test_log::test]
fn rename_immediately_before_unmount() {
    let data = TempDir::new("backupfs_data").unwrap();

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::write(mnt.join("os-backup.json"), b"old").unwrap();
        },
        None,
    );

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let tmp = mnt.join(".os-backup.json.tmp");
            let dst = mnt.join("os-backup.json");
            {
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&tmp)
                    .unwrap();
                f.write_all(b"new contents").unwrap();
                f.sync_all().unwrap();
            }
            fs::rename(&tmp, &dst).unwrap();
            // Do nothing else — let Drop trigger unmount right here.
        },
        None,
    );

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let live: Vec<String> = fs::read_dir(mnt)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                live.iter().any(|n| n == "os-backup.json"),
                "post-remount listing missing os-backup.json: {live:?}"
            );
            let got = fs::read(mnt.join("os-backup.json")).unwrap_or_else(|e| {
                panic!("post-remount cat failed: {e} — listing was {live:?}")
            });
            assert_eq!(got, b"new contents");
        },
        None,
    );
}

/// As above but across a remount between the create+write+tmp and the
/// rename — models a backup process that is killed part-way through an
/// atomic save and resumes in a fresh mount.
#[test_log::test]
fn rename_over_existing_across_remount() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::write(mnt.join("os-backup.json"), b"old").unwrap();
            fs::write(mnt.join(".os-backup.json.tmp"), b"new contents").unwrap();
        },
        None,
    );

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            fs::rename(
                mnt.join(".os-backup.json.tmp"),
                mnt.join("os-backup.json"),
            )
            .unwrap();
            assert_eq!(
                fs::read(mnt.join("os-backup.json")).unwrap(),
                b"new contents"
            );
        },
        None,
    );

    with_backupfs(
        data.path(),
        "ohea".to_owned(),
        |mnt| {
            let live: Vec<String> = fs::read_dir(mnt)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                live.iter().any(|n| n == "os-backup.json"),
                "post-remount listing missing os-backup.json: {live:?}"
            );
            assert!(
                !live.iter().any(|n| n == ".os-backup.json.tmp"),
                "tmp name persisted after rename: {live:?}"
            );
            assert_eq!(
                fs::read(mnt.join("os-backup.json")).unwrap(),
                b"new contents"
            );
        },
        None,
    );
}
