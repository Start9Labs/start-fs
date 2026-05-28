//! POSIX ACL support for backup-fs.
//!
//! ACLs are stored as extended attributes (xattrs) under `system.posix_acl_access`
//! and `system.posix_acl_default` keys. This module provides parsing and validation
//! of the Linux ACL binary format.

#![allow(unused)]

use serde::{Deserialize, Serialize};

/// Linux ACL entry tag types (from <uapi/linux/posix_acl.h>)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AclTag {
    UserObj = 0x01,
    User = 0x02,
    GroupObj = 0x04,
    Group = 0x08,
    Mask = 0x10,
    Other = 0x20,
}

impl TryFrom<u16> for AclTag {
    type Error = ();
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AclTag::UserObj),
            0x02 => Ok(AclTag::User),
            0x04 => Ok(AclTag::GroupObj),
            0x08 => Ok(AclTag::Group),
            0x10 => Ok(AclTag::Mask),
            0x20 => Ok(AclTag::Other),
            _ => Err(()),
        }
    }
}

/// Permission bits in an ACL entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclPerm(pub u16);

impl AclPerm {
    pub const READ: u16 = 0x04;
    pub const WRITE: u16 = 0x02;
    pub const EXEC: u16 = 0x01;

    pub fn new(perm: u16) -> Self {
        Self(perm & 0x07)
    }

    pub fn from_mode(mode: u16) -> Self {
        Self::new(mode & 0x07)
    }
}

/// A single ACL entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntry {
    pub tag: AclTag,
    pub perm: AclPerm,
    /// User or group ID (only valid for User and Group tags)
    pub id: u32,
}

/// Linux POSIX ACL binary format version
const POSIX_ACL_VERSION: u32 = 2;

/// Parse Linux ACL binary format (from xattr value)
///
/// Format (from <uapi/linux/posix_acl.h>):
/// ```text
/// struct posix_acl_xattr_header {
///     __le32 a_version;
/// };
/// struct posix_acl_xattr_entry {
///     __le16 e_tag;
///     __le16 e_perm;
///     __le32 e_id;
/// };
/// ```
pub fn parse_posix_acl(data: &[u8]) -> Option<Vec<AclEntry>> {
    if data.len() < 4 {
        return None;
    }

    let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if version != POSIX_ACL_VERSION {
        return None;
    }

    let mut entries = Vec::new();
    let mut offset = 4;

    while offset + 8 <= data.len() {
        let e_tag = u16::from_le_bytes([data[offset], data[offset + 1]]);
        let e_perm = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
        let e_id = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        let tag = match AclTag::try_from(e_tag) {
            Ok(t) => t,
            Err(_) => return None,
        };

        entries.push(AclEntry {
            tag,
            perm: AclPerm::new(e_perm),
            id: e_id,
        });

        offset += 8;
    }

    if entries.is_empty() {
        return None;
    }

    Some(entries)
}

/// Serialize ACL entries to Linux ACL binary format
pub fn encode_posix_acl(entries: &[AclEntry]) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + entries.len() * 8);

    // Version header
    data.extend_from_slice(&POSIX_ACL_VERSION.to_le_bytes());

    // Entries
    for entry in entries {
        data.extend_from_slice(&(entry.tag as u16).to_le_bytes());
        data.extend_from_slice(&entry.perm.0.to_le_bytes());
        data.extend_from_slice(&entry.id.to_le_bytes());
    }

    data
}

/// Validate that an ACL is well-formed
pub fn validate_acl(entries: &[AclEntry]) -> Result<(), String> {
    let mut has_user_obj = false;
    let mut has_group_obj = false;
    let mut has_other = false;
    let mut has_mask = false;

    for entry in entries {
        match entry.tag {
            AclTag::UserObj => {
                if has_user_obj {
                    return Err("Duplicate user_obj entry".to_string());
                }
                has_user_obj = true;
            }
            AclTag::User => {
                // Multiple user entries allowed
            }
            AclTag::GroupObj => {
                if has_group_obj {
                    return Err("Duplicate group_obj entry".to_string());
                }
                has_group_obj = true;
            }
            AclTag::Group => {
                // Multiple group entries allowed
            }
            AclTag::Mask => {
                if has_mask {
                    return Err("Duplicate mask entry".to_string());
                }
                has_mask = true;
            }
            AclTag::Other => {
                if has_other {
                    return Err("Duplicate other entry".to_string());
                }
                has_other = true;
            }
        }
    }

    // Minimal ACL must have user_obj, group_obj, other
    if !has_user_obj {
        return Err("Missing user_obj entry".to_string());
    }
    if !has_group_obj {
        return Err("Missing group_obj entry".to_string());
    }
    if !has_other {
        return Err("Missing other entry".to_string());
    }

    // Extended ACLs (with named user/group entries) must have a mask
    let has_named = entries.iter().any(|e| matches!(e.tag, AclTag::User | AclTag::Group));
    if has_named && !has_mask {
        return Err("Extended ACL missing mask entry".to_string());
    }

    Ok(())
}

/// Calculate the effective mode from an ACL
/// Returns the mode bits that correspond to the ACL
pub fn acl_to_mode(entries: &[AclEntry]) -> u16 {
    let mut mode = 0u16;

    for entry in entries {
        match entry.tag {
            AclTag::UserObj => {
                mode |= (entry.perm.0 & 0x07) << 6; // Owner perms
            }
            AclTag::GroupObj => {
                mode |= (entry.perm.0 & 0x07) << 3; // Group perms
            }
            AclTag::Other => {
                mode |= entry.perm.0 & 0x07; // Other perms
            }
            _ => {}
        }
    }

    mode
}

/// Create a minimal ACL from mode bits
pub fn mode_to_acl(mode: u16, uid: u32, gid: u32) -> Vec<AclEntry> {
    vec![
        AclEntry {
            tag: AclTag::UserObj,
            perm: AclPerm::new((mode >> 6) & 0x07),
            id: u32::MAX, // ACL_UNDEFINED_ID
        },
        AclEntry {
            tag: AclTag::User,
            perm: AclPerm::new((mode >> 6) & 0x07),
            id: uid,
        },
        AclEntry {
            tag: AclTag::GroupObj,
            perm: AclPerm::new((mode >> 3) & 0x07),
            id: u32::MAX, // ACL_UNDEFINED_ID
        },
        AclEntry {
            tag: AclTag::Mask,
            perm: AclPerm::new((mode >> 3) & 0x07),
            id: u32::MAX, // ACL_UNDEFINED_ID
        },
        AclEntry {
            tag: AclTag::Other,
            perm: AclPerm::new(mode & 0x07),
            id: u32::MAX, // ACL_UNDEFINED_ID
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_encode_roundtrip() {
        let acl = vec![
            AclEntry {
                tag: AclTag::UserObj,
                perm: AclPerm::new(7),
                id: u32::MAX,
            },
            AclEntry {
                tag: AclTag::GroupObj,
                perm: AclPerm::new(5),
                id: u32::MAX,
            },
            AclEntry {
                tag: AclTag::Other,
                perm: AclPerm::new(0),
                id: u32::MAX,
            },
        ];

        let encoded = encode_posix_acl(&acl);
        let decoded = parse_posix_acl(&encoded).unwrap();
        
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].tag, AclTag::UserObj);
        assert_eq!(decoded[0].perm.0, 7);
        assert_eq!(decoded[1].tag, AclTag::GroupObj);
        assert_eq!(decoded[1].perm.0, 5);
        assert_eq!(decoded[2].tag, AclTag::Other);
        assert_eq!(decoded[2].perm.0, 0);
    }

    #[test]
    fn validate_minimal_acl() {
        let acl = vec![
            AclEntry {
                tag: AclTag::UserObj,
                perm: AclPerm::new(7),
                id: u32::MAX,
            },
            AclEntry {
                tag: AclTag::GroupObj,
                perm: AclPerm::new(7),
                id: u32::MAX,
            },
            AclEntry {
                tag: AclTag::Other,
                perm: AclPerm::new(5),
                id: u32::MAX,
            },
        ];

        assert!(validate_acl(&acl).is_ok());
    }

    #[test]
    fn acl_mode_conversion() {
        let entries = mode_to_acl(0o750, 1000, 1000);
        let mode = acl_to_mode(&entries);
        assert_eq!(mode, 0o750);
    }
}
