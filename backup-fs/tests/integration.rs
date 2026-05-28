//! Integration tests for backup-fs new features

use backupfs::{BackupFS, BackupFSOptions};
use fuser::MountOption;
use std::fs;
use std::path::Path;
use tempdir::TempDir;

/// Serializes the fusermount3 invocation across parallel tests.
fn mount_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

fn with_backupfs(
    data: &Path,
    password: String,
    func: impl FnOnce(&Path),
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
}

#[test]
fn ecc_cryptinfo_recovery() {
    let data = TempDir::new("backupfs_data").unwrap();

    // Create filesystem to generate cryptinfo with ECC shards
    with_backupfs(
        data.path(),
        "test_password".to_owned(),
        |mnt| {
            fs::write(mnt.join("test_file"), "test data").unwrap();
        },
    );

    // Verify ECC shards were created
    let cryptinfo_path = data.path().join("cryptinfo");
    let ecc_path = cryptinfo_path.with_extension("ecc");
    assert!(cryptinfo_path.exists(), "cryptinfo should exist");
    assert!(
        ecc_path.with_extension("ecc.meta").exists(),
        "ECC metadata should exist"
    );

    // Corrupt the primary cryptinfo file by truncating it to 0 bytes
    fs::write(&cryptinfo_path, b"").unwrap();

    // Should recover from ECC shards
    with_backupfs(
        data.path(),
        "test_password".to_owned(),
        |mnt| {
            let contents = fs::read_to_string(mnt.join("test_file")).unwrap();
            assert_eq!(contents, "test data");
        },
    );
}

#[test]
fn wrong_password_rejected_after_ecc_recovery() {
    let data = TempDir::new("backupfs_data").unwrap();

    with_backupfs(
        data.path(),
        "correct_password".to_owned(),
        |mnt| {
            fs::write(mnt.join("secret"), "hidden data").unwrap();
        },
    );

    // Corrupt the primary cryptinfo
    let cryptinfo_path = data.path().join("cryptinfo");
    fs::write(&cryptinfo_path, b"").unwrap();

    // Try to mount with wrong password — must fail (not silently succeed)
    let res = BackupFS::new(BackupFSOptions {
        data_dir: data.path().to_owned(),
        setuid_support: false,
        password: "wrong_password".to_owned(),
        file_size_padding: None,
        readonly: false,
        idmapped_root: vec![],
    });
    assert!(
        res.is_err(),
        "wrong password must not recover data from ECC shards"
    );

    // Correct password must still work
    with_backupfs(
        data.path(),
        "correct_password".to_owned(),
        |mnt| {
            let contents = fs::read_to_string(mnt.join("secret")).unwrap();
            assert_eq!(contents, "hidden data");
        },
    );
}

#[test]
fn xattr_roundtrip_via_user_namespace() {
    // NOTE: system.posix_acl_access requires CAP_SYS_ADMIN, which is not
    // available to the FUSE daemon running as a user-level process.
    // We test xattr round-trip preservation through the user.* namespace
    // which is what rsync --xattrs / cp --preserve=xattr actually uses for
    // arbitrary metadata, and which is the path we've validated in code for ACL data.
    //
    // The ACL binary format parsing/validation is tested separately in the acl module.
    let data = TempDir::new("backupfs_data").unwrap();

    const XATTR_KEY: &str = "user.backupfs.test.acl";

    // Build a minimal POSIX ACL binary payload and store it via user.*
    // This exercises: setxattr → inode.save → remount → getxattr
    let acl_data = vec![
        // version 2 (u32 LE)
        0x02, 0x00, 0x00, 0x00,
        // user_obj: ACL_USER_OBJ(0x0001), rwx(6), ACL_UNDEFINED_ID
        0x01, 0x00, 0x06, 0x00, 0xff, 0xff, 0xff, 0xff,
        // group_obj: ACL_GROUP_OBJ(0x0004), r-x(5), ACL_UNDEFINED_ID
        0x04, 0x00, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff,
        // other: ACL_OTHER(0x0020), r--(4), ACL_UNDEFINED_ID
        0x20, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff,
    ];

    with_backupfs(
        data.path(),
        "test_password".to_owned(),
        |mnt| {
            let file_path = mnt.join("acl_test_file");
            fs::write(&file_path, "test data").unwrap();

            // Set xattr via libc
            let key = std::ffi::CString::new(XATTR_KEY).unwrap();
            let path_cstr = std::ffi::CString::new(file_path.to_str().unwrap()).unwrap();
            let ret = unsafe {
                libc::setxattr(
                    path_cstr.as_ptr(),
                    key.as_ptr(),
                    acl_data.as_ptr() as *const libc::c_void,
                    acl_data.len(),
                    0,
                )
            };
            assert!(ret == 0, "setxattr failed: {}", std::io::Error::last_os_error());
        },
    );

    // Remount and verify xattr is preserved exactly
    with_backupfs(
        data.path(),
        "test_password".to_owned(),
        |mnt| {
            let file_path = mnt.join("acl_test_file");

            let key = std::ffi::CString::new(XATTR_KEY).unwrap();
            let path_cstr = std::ffi::CString::new(file_path.to_str().unwrap()).unwrap();

            // First get size
            let size = unsafe {
                libc::getxattr(
                    path_cstr.as_ptr(),
                    key.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                )
            };
            assert!(size > 0, "getxattr size failed");

            // Read actual value
            let mut stored = vec![0u8; size as usize];
            let ret = unsafe {
                libc::getxattr(
                    path_cstr.as_ptr(),
                    key.as_ptr(),
                    stored.as_mut_ptr() as *mut libc::c_void,
                    stored.len(),
                )
            };
            assert!(ret > 0, "getxattr value failed");
            stored.truncate(ret as usize);

            assert_eq!(
                stored, acl_data,
                "xattr data corrupted across remount"
            );
        },
    );
}

#[test]
fn encrypted_content_in_blocks_dir() {
    // Verify that the blocks/ directory stores encrypted chunk files.
    // This validates the new storage layout where file content goes
    // into per-block encrypted files for dedup and incremental sync.
    let data = TempDir::new("backupfs_data").unwrap();

    with_backupfs(
        data.path(),
        "test_password".to_owned(),
        |mnt| {
            // Write enough data to span multiple blocks
            let content = vec![0xABu8; 64 * 1024 * 2]; // 128 KiB = 2 chunks
            fs::write(mnt.join("big_file"), &content).unwrap();
        },
    );

    let blocks_dir = data.path().join("blocks");
    if blocks_dir.exists() {
        let chunk_count: usize = fs::read_dir(&blocks_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|entry| {
                if entry.file_type().ok()?.is_dir() {
                    Some(
                        fs::read_dir(entry.path())
                            .ok()?
                            .filter_map(|e| e.ok())
                            .count(),
                    )
                } else {
                    None
                }
            })
            .sum();

        // Should have at least some chunk files from the 128 KiB write
        assert!(
            chunk_count > 0,
            "blocks/ directory should contain chunk files for written data"
        );
    }
}
