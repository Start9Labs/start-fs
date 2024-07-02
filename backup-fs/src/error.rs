use std::io;

use libc::c_int;

pub fn to_libc_err(e: &io::Error) -> c_int {
    e.raw_os_error().unwrap_or_else(|| {
        log::error!("{e}");
        libc::EIO
    })
}
