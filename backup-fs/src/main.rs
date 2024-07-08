use backupfs::{BackupFS, BackupFSOptions};
use clap::{CommandFactory, FromArgMatches, Parser};
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
    env_logger::builder()
        .format_timestamp_nanos()
        .parse_filters(std::env::var("RUST_LOG").as_deref().unwrap_or("info"))
        .init();
    if std::env::args().next().as_deref() == Some("mount.backup-fs") {
        return mount(MountOptions::parse());
    }
    let mut app = clap::command!()
        .subcommand(MountOptions::command().name("mount"))
        .subcommand(BackupFSOptions::command().name("fsck"));
    let matches = app.clone().get_matches();
    match matches.subcommand() {
        Some(("mount", sub_m)) => mount(MountOptions::from_arg_matches(sub_m).unwrap()),
        Some(("fsck", sub_m)) => fsck(BackupFSOptions::from_arg_matches(sub_m).unwrap()),
        _ => app.print_long_help().unwrap(),
    }
}

fn mount(
    MountOptions {
        backup_opts,
        mountpoint,
    }: MountOptions,
) {
    let mut options = vec![MountOption::FSName("fuser".to_string())];
    if backup_opts.setuid_support {
        info!("setuid bit support enabled");
        options.push(MountOption::Suid);
    } else {
        options.push(MountOption::AutoUnmount);
    }

    let result = fuser::Session::new(BackupFS::new(backup_opts).unwrap(), &mountpoint, &options);
    match result {
        Err(e) => {
            // Return a special error code for permission denied, which usually indicates that
            // "user_allow_other" is missing from /etc/fuse.conf
            if e.kind() == ErrorKind::PermissionDenied {
                error!("{}", e.to_string());
                std::process::exit(2);
            }
            std::process::exit(1);
        }
        Ok(mut s) => {
            nix::unistd::daemon(true, true).unwrap();
            s.run().unwrap()
        }
    }
}

fn fsck(options: BackupFSOptions) {
    backupfs::BackupFS::new(options).unwrap().fsck().unwrap()
}
