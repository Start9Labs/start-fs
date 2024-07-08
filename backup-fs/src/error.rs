use fuser::ReplyEntry;
use libc::c_int;
use log::error;
use std::backtrace::Backtrace;
use std::fmt::{Debug, Display};
use std::io;

pub fn to_libc_err(e: &io::Error) -> c_int {
    e.raw_os_error().unwrap_or_else(|| libc::EIO)
}

pub struct IoError {
    pub inner: io::Error,
    pub backtrace: Option<Box<Backtrace>>,
}

impl IoError {
    pub fn wrap_notrace(inner: io::Error) -> Self {
        IoError {
            inner,
            backtrace: None,
        }
    }

    #[track_caller]
    pub fn wrap(inner: io::Error) -> Self {
        IoError {
            inner,
            backtrace: Some(Box::new(Backtrace::capture())),
        }
    }

    pub fn to_errno_log(&self) -> c_int {
        error!("{self:?}");
        to_libc_err(&self.inner)
    }

    pub fn to_errno(&self) -> c_int {
        to_libc_err(&self.inner)
    }

    pub fn reply(&self, entry: ReplyEntry) {
        entry.error(self.to_errno_log());
    }
}

impl Display for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <io::Error as Display>::fmt(&self.inner, f)?;
        if let Some(backtrace) = &self.backtrace {
            writeln!(f, "\nError context:")?;
            writeln!(f, "{:}", backtrace)?;
        }
        Ok(())
    }
}

impl Debug for IoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <io::Error as Debug>::fmt(&self.inner, f)?;
        if let Some(backtrace) = &self.backtrace {
            writeln!(f, "\nError context:")?;
            writeln!(f, "{:}", backtrace)?;
        }
        Ok(())
    }
}

impl std::error::Error for IoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.inner)
    }
}

impl From<io::Error> for IoError {
    #[track_caller]
    fn from(inner: io::Error) -> Self {
        Self::wrap(inner)
    }
}

impl From<IoError> for io::Error {
    fn from(this: IoError) -> Self {
        this.inner
    }
}

pub type IoResult<T> = Result<T, IoError>;

pub trait IoResultExt<T> {
    fn errno(code: i32) -> Self;
    fn errno_notrace(code: i32) -> Self;
}

impl<T> IoResultExt<T> for IoResult<T> {
    #[track_caller]
    fn errno(code: i32) -> Self {
        Err(IoError::wrap(io::Error::from_raw_os_error(code)))
    }

    fn errno_notrace(code: i32) -> Self {
        Err(IoError::wrap_notrace(io::Error::from_raw_os_error(code)))
    }
}
