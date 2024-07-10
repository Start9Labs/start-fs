use fuser::ReplyEntry;
use libc::c_int;
use log::{debug, warn};
use std::backtrace::Backtrace;
use std::fmt::{Debug, Display};
use std::io;

pub fn to_libc_err(e: &io::Error) -> c_int {
    e.raw_os_error().unwrap_or_else(|| libc::EIO)
}

#[derive(Debug)]
pub enum BkfsErrorKind {
    Io(io::Error),
    BadChecksum,
    Multiple(Vec<BkfsErrorKind>),
}

impl Display for BkfsErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            BkfsErrorKind::Io(err) => <io::Error as Display>::fmt(err, f),
            BkfsErrorKind::BadChecksum => write!(f, "bad checksum"),
            BkfsErrorKind::Multiple(errs) => {
                for err in errs {
                    <BkfsErrorKind as Display>::fmt(err, f)?;
                    write!(f, ", ")?;
                }
                Ok(())
            }
        }
    }
}

pub struct BkfsError {
    pub kind: BkfsErrorKind,
    pub backtrace: Option<Box<Backtrace>>,
}

impl BkfsError {
    pub fn wrap_notrace(inner: io::Error) -> Self {
        BkfsError {
            kind: BkfsErrorKind::Io(inner),
            backtrace: None,
        }
    }

    #[track_caller]
    pub fn wrap(inner: io::Error) -> Self {
        BkfsError {
            kind: BkfsErrorKind::Io(inner),
            backtrace: Some(Box::new(Backtrace::capture())),
        }
    }

    pub fn to_errno_log(&self) -> c_int {
        let no = self.to_errno();
        if no == libc::ENOENT {
            debug!("{self:?}");
        } else {
            warn!("{self:?}");
        }
        no
    }

    pub fn to_errno(&self) -> c_int {
        match &self.kind {
            BkfsErrorKind::Io(err) => to_libc_err(err),
            BkfsErrorKind::BadChecksum => libc::EIO,
            BkfsErrorKind::Multiple(_) => todo!(),
        }
    }

    pub fn reply(&self, entry: ReplyEntry) {
        entry.error(self.to_errno_log());
    }
}

impl Display for BkfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <BkfsErrorKind as Display>::fmt(&self.kind, f)?;
        if let Some(backtrace) = &self.backtrace {
            writeln!(f, "\nError context:")?;
            writeln!(f, "{:}", backtrace)?;
        }
        Ok(())
    }
}

impl Debug for BkfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        <BkfsErrorKind as Debug>::fmt(&self.kind, f)?;
        if let Some(backtrace) = &self.backtrace {
            writeln!(f, "\nError context:")?;
            writeln!(f, "{:}", backtrace)?;
        }
        Ok(())
    }
}

impl std::error::Error for BkfsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            BkfsErrorKind::Io(err) => Some(err),
            BkfsErrorKind::BadChecksum => None,
            BkfsErrorKind::Multiple(_) => None,
        }
    }
}

impl From<io::Error> for BkfsError {
    #[track_caller]
    fn from(inner: io::Error) -> Self {
        Self::wrap(inner)
    }
}

impl From<BkfsError> for io::Error {
    fn from(this: BkfsError) -> Self {
        match this.kind {
            BkfsErrorKind::Io(err) => err,
            kind => io::Error::other(kind.to_string()),
        }
    }
}

pub type BkfsResult<T> = Result<T, BkfsError>;

pub trait BkfsResultExt<T> {
    fn errno(code: i32) -> Self;
    fn errno_notrace(code: i32) -> Self;
    fn multiple(ok: T, errs: impl IntoIterator<Item = BkfsError>) -> Self;
}

impl<T> BkfsResultExt<T> for BkfsResult<T> {
    #[track_caller]
    fn errno(code: i32) -> Self {
        Err(BkfsError::wrap(io::Error::from_raw_os_error(code)))
    }

    fn errno_notrace(code: i32) -> Self {
        Err(BkfsError::wrap_notrace(io::Error::from_raw_os_error(code)))
    }

    fn multiple(ok: T, errs: impl IntoIterator<Item = BkfsError>) -> Self {
        let mut backtrace = None;
        let mut kinds = Vec::new();
        for err in errs {
            kinds.push(err.kind);
            if backtrace.is_none() {
                backtrace = err.backtrace;
            }
        }
        if kinds.is_empty() {
            Ok(ok)
        } else {
            Err(BkfsError {
                kind: BkfsErrorKind::Multiple(kinds),
                backtrace,
            })
        }
    }
}
