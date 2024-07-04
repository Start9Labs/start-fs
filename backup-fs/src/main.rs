use backupfs::{BackupFS, BackupFSOptions};
use fuser::MountOption;
use log::{error, info};
use std::io::ErrorKind;
use std::path::PathBuf;

#[derive(clap::Parser)]
struct MountOptions {
    #[command(flatten)]
    backup_opts: BackupFSOptions,
    mountpoint: PathBuf,
}

fn main() {
    let MountOptions {
        backup_opts,
        mountpoint,
    } = clap::Parser::parse();

    env_logger::builder().format_timestamp_nanos().init();

    let mut options = vec![MountOption::FSName("fuser".to_string())];
    if backup_opts.setuid_support {
        info!("setuid bit support enabled");
        options.push(MountOption::Suid);
    } else {
        options.push(MountOption::AutoUnmount);
    }

    let result = fuser::mount2(BackupFS::new(backup_opts).unwrap(), mountpoint, &options);
    if let Err(e) = result {
        // Return a special error code for permission denied, which usually indicates that
        // "user_allow_other" is missing from /etc/fuse.conf
        if e.kind() == ErrorKind::PermissionDenied {
            error!("{}", e.to_string());
            std::process::exit(2);
        }
    }
}
