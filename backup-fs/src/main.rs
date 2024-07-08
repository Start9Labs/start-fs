use backupfs::{BackupFS, BackupFSOptions};
use clap::builder::{TypedValueParser, ValueParser};
use clap::{CommandFactory, FromArgMatches, Parser};
use fuser::MountOption;
use log::{error, info};
use std::io::ErrorKind;
use std::path::PathBuf;

#[derive(clap::Parser)]
struct MountOptions {
    #[command(flatten)]
    backup_opts: BackupFSOptions,
    #[arg(short = 'o')]
    opt: Vec<MountOption>,
    mountpoint: PathBuf,
}

#[derive(clap::Parser)]
struct ChangePasswordOptions {
    #[command(flatten)]
    backup_opts: BackupFSOptions,
    #[arg(long)]
    new_password: String,
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
        .subcommand(BackupFSOptions::command().name("fsck"))
        .subcommand(ChangePasswordOptions::command().name("change-password"));
    let matches = app.clone().get_matches();
    match matches.subcommand() {
        Some(("mount", sub_m)) => mount(MountOptions::from_arg_matches(sub_m).unwrap()),
        Some(("fsck", sub_m)) => fsck(BackupFSOptions::from_arg_matches(sub_m).unwrap()),
        Some(("change-password", sub_m)) => {
            change_password(ChangePasswordOptions::from_arg_matches(sub_m).unwrap())
        }
        _ => app.print_long_help().unwrap(),
    }
}

fn mount(
    MountOptions {
        mut backup_opts,
        mut opt,
        mountpoint,
    }: MountOptions,
) {
    opt.push(MountOption::FSName("backup-fs".to_string()));

    if backup_opts.setuid_support {
        info!("setuid bit support enabled");
        opt.push(MountOption::Suid);
    } else if opt.contains(&MountOption::Suid) {
        info!("setuid bit support enabled");
        backup_opts.setuid_support = true;
    } else {
        opt.push(MountOption::AutoUnmount);
    }

    if backup_opts.readonly {
        opt.push(MountOption::RO);
    } else if opt.contains(&MountOption::RO) {
        backup_opts.readonly = true;
    }

    let result = fuser::Session::new(BackupFS::new(backup_opts).unwrap(), &mountpoint, &opt);
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

fn change_password(
    ChangePasswordOptions {
        backup_opts,
        new_password,
    }: ChangePasswordOptions,
) {
    backupfs::BackupFS::new(backup_opts)
        .unwrap()
        .change_password(&new_password)
        .unwrap()
}
