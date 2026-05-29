//! Per-file content compression, applied to content bytes *before*
//! encryption (ciphertext doesn't compress).
//!
//! The codec (whether to compress, and the zstd level) is chosen from the
//! file's extension by [`codec_for_name`]: already-compressed/media formats
//! are stored raw (no wasted CPU), highly-compressible text/structured
//! formats get a high level, and unknown extensions default to zstd level 2.
//! The choice is also **adaptive**: if compression doesn't actually shrink a
//! given chunk it's stored raw, so a misclassified or incompressible file
//! never bloats.
//!
//! Each stored chunk (a content block or a packed extent) is independently
//! `compress`-ed and carries a 1-byte algorithm tag, so it can be
//! `decompress`-ed on its own and a per-block edit recompresses only that
//! block (preserving the rsync-incremental property). Compression is applied
//! to packed extents and content blocks; tiny inline content (≤ the inline
//! threshold, stored in the inode record) is left as-is.

use std::ffi::OsStr;
use std::path::Path;

use crate::error::{BkfsError, BkfsResult};

const TAG_RAW: u8 = 0;
const TAG_ZSTD: u8 = 1;

/// Compression decision for a file: skip, or zstd at a level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    None,
    Zstd(i32),
}

/// Choose a codec from a file's name (its extension, case-insensitive).
pub fn codec_for_name(name: &OsStr) -> Codec {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    match ext.as_deref() {
        // Already compressed / encrypted / media — compression only burns CPU.
        Some(
            "zst" | "zstd" | "gz" | "tgz" | "bz2" | "tbz" | "xz" | "txz" | "lz4" | "zip" | "7z"
            | "rar" | "br" | "lzma" | "jpg" | "jpeg" | "png" | "gif" | "webp" | "heic" | "avif"
            | "mp4" | "m4v" | "m4a" | "mkv" | "mov" | "avi" | "webm" | "mp3" | "aac" | "ogg"
            | "oga" | "opus" | "flac" | "woff" | "woff2" | "apk" | "jar" | "deb" | "rpm" | "dmg"
            | "iso" | "gpg" | "age" | "pgp",
        ) => Codec::None,
        // Highly compressible text / structured / source — spend more.
        Some(
            "log" | "txt" | "text" | "json" | "ndjson" | "jsonl" | "csv" | "tsv" | "xml" | "html"
            | "htm" | "yaml" | "yml" | "toml" | "ini" | "conf" | "cfg" | "md" | "rst" | "sql"
            | "js" | "mjs" | "ts" | "tsx" | "jsx" | "css" | "scss" | "c" | "h" | "cc" | "cpp"
            | "hpp" | "rs" | "py" | "go" | "java" | "kt" | "rb" | "php" | "sh" | "bash" | "pl"
            | "lua" | "svg" | "tar" | "dat" | "db" | "sqlite" | "wal",
        ) => Codec::Zstd(9),
        // Everything else (unknown extension): the requested default.
        _ => Codec::Zstd(2),
    }
}

/// Compress `plain` per `codec`, prefixing a 1-byte algorithm tag. Falls back
/// to storing raw if compression is disabled, errors, or fails to shrink the
/// data (so an incompressible chunk never grows beyond +1 tag byte).
pub fn compress(plain: &[u8], codec: Codec) -> Vec<u8> {
    if let Codec::Zstd(level) = codec {
        if let Ok(c) = zstd::stream::encode_all(plain, level) {
            if c.len() + 1 < plain.len() {
                let mut out = Vec::with_capacity(c.len() + 1);
                out.push(TAG_ZSTD);
                out.extend_from_slice(&c);
                return out;
            }
        }
    }
    let mut out = Vec::with_capacity(plain.len() + 1);
    out.push(TAG_RAW);
    out.extend_from_slice(plain);
    out
}

/// Inverse of [`compress`].
pub fn decompress(stored: &[u8]) -> BkfsResult<Vec<u8>> {
    match stored.split_first() {
        Some((&TAG_RAW, rest)) => Ok(rest.to_vec()),
        Some((&TAG_ZSTD, rest)) => zstd::stream::decode_all(rest)
            .map_err(|e| BkfsError::wrap(std::io::Error::new(std::io::ErrorKind::InvalidData, e))),
        _ => Err(BkfsError::wrap(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "missing/unknown compression tag",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_raw_and_zstd() {
        let text = vec![b'a'; 10_000]; // very compressible
        let zc = compress(&text, Codec::Zstd(9));
        assert!(zc.len() < text.len(), "compressible data should shrink");
        assert_eq!(decompress(&zc).unwrap(), text);

        let none = compress(&text, Codec::None);
        assert_eq!(none[0], TAG_RAW);
        assert_eq!(decompress(&none).unwrap(), text);
    }

    #[test]
    fn incompressible_stored_raw() {
        use rand::RngCore;
        let mut data = vec![0u8; 65536];
        rand::rng().fill_bytes(&mut data); // genuinely incompressible
        let c = compress(&data, Codec::Zstd(9));
        assert_eq!(c[0], TAG_RAW, "incompressible data must fall back to raw");
        assert_eq!(decompress(&c).unwrap(), data);
    }

    #[test]
    fn empty_roundtrips() {
        for codec in [Codec::None, Codec::Zstd(2)] {
            let c = compress(&[], codec);
            assert_eq!(decompress(&c).unwrap(), Vec::<u8>::new());
        }
    }

    #[test]
    fn extension_policy() {
        use std::ffi::OsString;
        assert_eq!(codec_for_name(&OsString::from("a.log")), Codec::Zstd(9));
        assert_eq!(codec_for_name(&OsString::from("a.JSON")), Codec::Zstd(9));
        assert_eq!(codec_for_name(&OsString::from("a.jpg")), Codec::None);
        assert_eq!(codec_for_name(&OsString::from("a.bin")), Codec::Zstd(2));
        assert_eq!(codec_for_name(&OsString::from("noext")), Codec::Zstd(2));
    }
}
