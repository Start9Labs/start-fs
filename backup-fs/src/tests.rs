use crate::{BackupFS, BackupFSOptions};
use fuser::MountOption;
use std::{fs, io, path::Path};
use tempdir::TempDir;

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
fn checksum() {
    let data = TempDir::new("backupfs_data").unwrap();
    with_backupfs(data.path(), "ohea".to_owned(), |_mnt| {}, None);
    let res = BackupFS::new(BackupFSOptions {
        data_dir: data.path().to_owned(),
        setuid_support: false,
        password: "rtns".to_owned(),
        file_size_padding: None,
        readonly: false,
    });
    match res {
        Ok(_) => panic!(),
        Err(err) => assert_eq!(&err.inner.to_string(), "checksum validation failed"),
    }
}

#[test_log::test]
fn backupfs_change_password() {
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
