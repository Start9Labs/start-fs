use std::io::ErrorKind;

use backupfs::{fuse_allow_other_enabled, BackupFS};
use clap::{Arg, ArgAction, Command};
use fuser::MountOption;
use log::{error, LevelFilter};

fn main() {
    let matches = Command::new("Fuser")
        // .version(crate_version!())
        .author("Christopher Berner")
        .arg(
            Arg::new("data-dir")
                .long("data-dir")
                .value_name("DIR")
                .default_value("/tmp/fuser")
                .help("Set local directory used to store data"),
        )
        .arg(
            Arg::new("mount-point")
                .long("mount-point")
                .value_name("MOUNT_POINT")
                .default_value("")
                .help("Act as a client, and mount FUSE at given path"),
        )
        .arg(
            Arg::new("direct-io")
                .long("direct-io")
                .action(ArgAction::SetTrue)
                .requires("mount-point")
                .help("Mount FUSE with direct IO"),
        )
        .arg(
            Arg::new("fsck")
                .long("fsck")
                .action(ArgAction::SetTrue)
                .help("Run a filesystem check"),
        )
        .arg(
            Arg::new("suid")
                .long("suid")
                .action(ArgAction::SetTrue)
                .help("Enable setuid support when run as root"),
        )
        .arg(
            Arg::new("v")
                .short('v')
                .action(ArgAction::Count)
                .help("Sets the level of verbosity"),
        )
        .get_matches();

    let verbosity = matches.get_count("v");
    let log_level = match verbosity {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .init();

    let mut options = vec![MountOption::FSName("fuser".to_string())];

    if matches.get_flag("suid") {
        info!("setuid bit support enabled");
        options.push(MountOption::Suid);
    } else {
        options.push(MountOption::AutoUnmount);
    }

    if let Ok(enabled) = fuse_allow_other_enabled() {
        if enabled {
            options.push(MountOption::AllowOther);
        }
    } else {
        eprintln!("Unable to read /etc/fuse.conf");
    }

    let data_dir = matches.get_one::<String>("data-dir").unwrap().to_string();

    let mountpoint: String = matches
        .get_one::<String>("mount-point")
        .unwrap()
        .to_string();

    let result = fuser::mount2(
        BackupFS::new(
            data_dir,
            matches.get_flag("direct-io"),
            matches.get_flag("suid"),
        ),
        mountpoint,
        &options,
    );
    if let Err(e) = result {
        // Return a special error code for permission denied, which usually indicates that
        // "user_allow_other" is missing from /etc/fuse.conf
        if e.kind() == ErrorKind::PermissionDenied {
            error!("{}", e.to_string());
            std::process::exit(2);
        }
    }
}
