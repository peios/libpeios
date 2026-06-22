// SECURITY_DESCRIPTOR, ACL, and ACE — MS-DTYP § 2.4.5, 2.4.5.1, 2.4.4.
//
// The wire codec lives here in libp-sd (mirroring libp-go, where the SD
// family lives in the `sd` package). Constant *values* are sourced from
// the generated `peios-uapi` crate (`KACS_*`), so the kernel ABI has a
// single source of truth; the byte-level parsers are hand-written.
//
// Self-relative SD layout (20-byte header):
//   u8  Revision      (always 1)
//   u8  Sbz1
//   u16 Control       (see SE_* below)
//   u32 OwnerOffset   (0 = absent, else byte offset from SD start to owner SID)
//   u32 GroupOffset   (same)
//   u32 SaclOffset    (same)
//   u32 DaclOffset    (same)
//
// ACL header (8 bytes):
//   u8  AclRevision
//   u8  Sbz1
//   u16 AclSize       (total bytes including header)
//   u16 AceCount
//   u16 Sbz2
//
// ACE header (4 bytes):
//   u8  AceType
//   u8  AceFlags
//   u16 AceSize       (total bytes including header)
//
// Parser shapes:
//
//   `SecurityDescriptor<'a>` — borrowed view, lazy submembers.
//   `Acl<'a>`                — borrowed view, lazy ACE iteration.
//   `AceRef<'a>`             — borrowed ACE view (body as `&[u8]`).
//   `Ace`                    — owned ACE (body as `Vec<u8>`); built via
//                              `AceRef::to_owned()` when ownership is needed.

use alloc::vec::Vec;
use crate::security::sddl::wire::ParseError;
use crate::security::sddl::wire::{Sid, SidRef};

// ---------------------------------------------------------------------------
// SECURITY_INFORMATION bits (caller-side info-selector for kacs_get_sd /
// kacs_set_sd).
// ---------------------------------------------------------------------------

pub const OWNER_SECURITY_INFORMATION: u32 = peios_uapi::KACS_SECINFO_OWNER;
pub const GROUP_SECURITY_INFORMATION: u32 = peios_uapi::KACS_SECINFO_GROUP;
pub const DACL_SECURITY_INFORMATION: u32 = peios_uapi::KACS_SECINFO_DACL;
pub const SACL_SECURITY_INFORMATION: u32 = peios_uapi::KACS_SECINFO_SACL;
pub const LABEL_SECURITY_INFORMATION: u32 = peios_uapi::KACS_SECINFO_LABEL;

// ---------------------------------------------------------------------------
// SECURITY_DESCRIPTOR_CONTROL bits.
// ---------------------------------------------------------------------------

pub const SE_OWNER_DEFAULTED: u16 = peios_uapi::KACS_SD_OWNER_DEFAULTED as u16;
pub const SE_GROUP_DEFAULTED: u16 = peios_uapi::KACS_SD_GROUP_DEFAULTED as u16;
pub const SE_DACL_PRESENT: u16 = peios_uapi::KACS_SD_DACL_PRESENT as u16;
pub const SE_DACL_DEFAULTED: u16 = peios_uapi::KACS_SD_DACL_DEFAULTED as u16;
pub const SE_SACL_PRESENT: u16 = peios_uapi::KACS_SD_SACL_PRESENT as u16;
pub const SE_SACL_DEFAULTED: u16 = peios_uapi::KACS_SD_SACL_DEFAULTED as u16;
pub const SE_DACL_AUTO_INHERITED: u16 = peios_uapi::KACS_SD_DACL_AUTO_INHERITED as u16;
pub const SE_SACL_AUTO_INHERITED: u16 = peios_uapi::KACS_SD_SACL_AUTO_INHERITED as u16;
pub const SE_DACL_PROTECTED: u16 = peios_uapi::KACS_SD_DACL_PROTECTED as u16;
pub const SE_SACL_PROTECTED: u16 = peios_uapi::KACS_SD_SACL_PROTECTED as u16;
pub const SE_RM_CONTROL_VALID: u16 = peios_uapi::KACS_SD_RM_CONTROL_VALID as u16;
pub const SE_SELF_RELATIVE: u16 = peios_uapi::KACS_SD_SELF_RELATIVE as u16;

pub const SD_HEADER_BYTES: usize = peios_uapi::KACS_SD_HEADER_BYTES as usize;

/// Decoded control bits as a list of names; falls back to empty if none of
/// the known bits are present.
pub fn control_bit_names(c: u16) -> Vec<&'static str> {
    let pairs = [
        (SE_OWNER_DEFAULTED, "OWNER_DEFAULTED"),
        (SE_GROUP_DEFAULTED, "GROUP_DEFAULTED"),
        (SE_DACL_PRESENT, "DACL_PRESENT"),
        (SE_DACL_DEFAULTED, "DACL_DEFAULTED"),
        (SE_SACL_PRESENT, "SACL_PRESENT"),
        (SE_SACL_DEFAULTED, "SACL_DEFAULTED"),
        (SE_DACL_AUTO_INHERITED, "DACL_AUTO_INHERITED"),
        (SE_SACL_AUTO_INHERITED, "SACL_AUTO_INHERITED"),
        (SE_DACL_PROTECTED, "DACL_PROTECTED"),
        (SE_SACL_PROTECTED, "SACL_PROTECTED"),
        (SE_RM_CONTROL_VALID, "RM_CONTROL_VALID"),
        (SE_SELF_RELATIVE, "SELF_RELATIVE"),
    ];
    pairs
        .iter()
        .filter(|(b, _)| c & *b != 0)
        .map(|(_, n)| *n)
        .collect()
}

// ---------------------------------------------------------------------------
// Access mask bits (MS-DTYP § 2.4.3) and decode.
// ---------------------------------------------------------------------------

pub const ACCESS_DELETE: u32 = peios_uapi::KACS_ACCESS_DELETE;
pub const ACCESS_READ_CONTROL: u32 = peios_uapi::KACS_ACCESS_READ_CONTROL;
pub const ACCESS_WRITE_DAC: u32 = peios_uapi::KACS_ACCESS_WRITE_DAC;
pub const ACCESS_WRITE_OWNER: u32 = peios_uapi::KACS_ACCESS_WRITE_OWNER;
pub const ACCESS_SYNCHRONIZE: u32 = peios_uapi::KACS_ACCESS_SYNCHRONIZE;
pub const ACCESS_SYSTEM_SECURITY: u32 = peios_uapi::KACS_ACCESS_ACCESS_SYSTEM_SECURITY;
pub const ACCESS_MAXIMUM_ALLOWED: u32 = peios_uapi::KACS_ACCESS_MAXIMUM_ALLOWED;
pub const ACCESS_GENERIC_ALL: u32 = peios_uapi::KACS_ACCESS_GENERIC_ALL;
pub const ACCESS_GENERIC_EXECUTE: u32 = peios_uapi::KACS_ACCESS_GENERIC_EXECUTE;
pub const ACCESS_GENERIC_WRITE: u32 = peios_uapi::KACS_ACCESS_GENERIC_WRITE;
pub const ACCESS_GENERIC_READ: u32 = peios_uapi::KACS_ACCESS_GENERIC_READ;

pub const DELETE: u32 = ACCESS_DELETE;
pub const READ_CONTROL: u32 = ACCESS_READ_CONTROL;
pub const WRITE_DAC: u32 = ACCESS_WRITE_DAC;
pub const WRITE_OWNER: u32 = ACCESS_WRITE_OWNER;
pub const SYNCHRONIZE: u32 = ACCESS_SYNCHRONIZE;
pub const MAXIMUM_ALLOWED: u32 = ACCESS_MAXIMUM_ALLOWED;
pub const GENERIC_ALL: u32 = ACCESS_GENERIC_ALL;
pub const GENERIC_EXECUTE: u32 = ACCESS_GENERIC_EXECUTE;
pub const GENERIC_WRITE: u32 = ACCESS_GENERIC_WRITE;
pub const GENERIC_READ: u32 = ACCESS_GENERIC_READ;

/// Object-class-specific mapping from the four generic access bits
/// (READ/WRITE/EXECUTE/ALL) to concrete object-specific rights. The C-ABI
/// shape; also the builder-facing form passed to [`crate::AccessCheckRequest`].
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GenericMapping {
    pub read: u32,
    pub write: u32,
    pub execute: u32,
    pub all: u32,
}

const ACCESS_MASK_NAMES: &[(u32, &str)] = &[
    (ACCESS_DELETE, "DELETE"),
    (ACCESS_READ_CONTROL, "READ_CONTROL"),
    (ACCESS_WRITE_DAC, "WRITE_DAC"),
    (ACCESS_WRITE_OWNER, "WRITE_OWNER"),
    (ACCESS_SYNCHRONIZE, "SYNCHRONIZE"),
    (ACCESS_SYSTEM_SECURITY, "ACCESS_SYSTEM_SECURITY"),
    (ACCESS_MAXIMUM_ALLOWED, "MAXIMUM_ALLOWED"),
    (ACCESS_GENERIC_ALL, "GENERIC_ALL"),
    (ACCESS_GENERIC_EXECUTE, "GENERIC_EXECUTE"),
    (ACCESS_GENERIC_WRITE, "GENERIC_WRITE"),
    (ACCESS_GENERIC_READ, "GENERIC_READ"),
];

/// Decode the standard / generic bits of an access mask. The low 16 bits are
/// object-class-specific and rendered as ":specific" if any are set.
pub fn access_mask_names(m: u32) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = ACCESS_MASK_NAMES
        .iter()
        .filter(|(b, _)| m & *b != 0)
        .map(|(_, n)| *n)
        .collect();
    if m & 0x0000_FFFF != 0 {
        out.push(":specific");
    }
    out
}

// ---------------------------------------------------------------------------
// ACE types (MS-DTYP § 2.4.4.1).
// ---------------------------------------------------------------------------

pub const ACE_TYPE_ACCESS_ALLOWED: u8 = peios_uapi::KACS_ACE_TYPE_ACCESS_ALLOWED as u8;
pub const ACE_TYPE_ACCESS_DENIED: u8 = peios_uapi::KACS_ACE_TYPE_ACCESS_DENIED as u8;
pub const ACE_TYPE_SYSTEM_AUDIT: u8 = peios_uapi::KACS_ACE_TYPE_SYSTEM_AUDIT as u8;
pub const ACE_TYPE_SYSTEM_ALARM: u8 = peios_uapi::KACS_ACE_TYPE_SYSTEM_ALARM as u8;
pub const ACE_TYPE_ACCESS_ALLOWED_COMPOUND: u8 =
    peios_uapi::KACS_ACE_TYPE_ACCESS_ALLOWED_COMPOUND as u8;
pub const ACE_TYPE_ACCESS_ALLOWED_OBJECT: u8 =
    peios_uapi::KACS_ACE_TYPE_ACCESS_ALLOWED_OBJECT as u8;
pub const ACE_TYPE_ACCESS_DENIED_OBJECT: u8 = peios_uapi::KACS_ACE_TYPE_ACCESS_DENIED_OBJECT as u8;
pub const ACE_TYPE_SYSTEM_AUDIT_OBJECT: u8 = peios_uapi::KACS_ACE_TYPE_SYSTEM_AUDIT_OBJECT as u8;
pub const ACE_TYPE_SYSTEM_ALARM_OBJECT: u8 = peios_uapi::KACS_ACE_TYPE_SYSTEM_ALARM_OBJECT as u8;
pub const ACE_TYPE_ACCESS_ALLOWED_CALLBACK: u8 =
    peios_uapi::KACS_ACE_TYPE_ACCESS_ALLOWED_CALLBACK as u8;
pub const ACE_TYPE_ACCESS_DENIED_CALLBACK: u8 =
    peios_uapi::KACS_ACE_TYPE_ACCESS_DENIED_CALLBACK as u8;
pub const ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT: u8 =
    peios_uapi::KACS_ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT as u8;
pub const ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT: u8 =
    peios_uapi::KACS_ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT as u8;
pub const ACE_TYPE_SYSTEM_AUDIT_CALLBACK: u8 =
    peios_uapi::KACS_ACE_TYPE_SYSTEM_AUDIT_CALLBACK as u8;
pub const ACE_TYPE_SYSTEM_ALARM_CALLBACK: u8 =
    peios_uapi::KACS_ACE_TYPE_SYSTEM_ALARM_CALLBACK as u8;
pub const ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT: u8 =
    peios_uapi::KACS_ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT as u8;
pub const ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT: u8 =
    peios_uapi::KACS_ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT as u8;
pub const ACE_TYPE_SYSTEM_MANDATORY_LABEL: u8 =
    peios_uapi::KACS_ACE_TYPE_SYSTEM_MANDATORY_LABEL as u8;
pub const ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE: u8 =
    peios_uapi::KACS_ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE as u8;
pub const ACE_TYPE_SYSTEM_SCOPED_POLICY_ID: u8 =
    peios_uapi::KACS_ACE_TYPE_SYSTEM_SCOPED_POLICY_ID as u8;
pub const ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL: u8 =
    peios_uapi::KACS_ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL as u8;
pub const ACE_TYPE_SYSTEM_ACCESS_FILTER: u8 = peios_uapi::KACS_ACE_TYPE_SYSTEM_ACCESS_FILTER as u8;

pub fn ace_type_name(t: u8) -> &'static str {
    match t {
        ACE_TYPE_ACCESS_ALLOWED => "ACCESS_ALLOWED",
        ACE_TYPE_ACCESS_DENIED => "ACCESS_DENIED",
        ACE_TYPE_SYSTEM_AUDIT => "SYSTEM_AUDIT",
        ACE_TYPE_SYSTEM_ALARM => "SYSTEM_ALARM",
        ACE_TYPE_ACCESS_ALLOWED_COMPOUND => "ACCESS_ALLOWED_COMPOUND",
        ACE_TYPE_ACCESS_ALLOWED_OBJECT => "ACCESS_ALLOWED_OBJECT",
        ACE_TYPE_ACCESS_DENIED_OBJECT => "ACCESS_DENIED_OBJECT",
        ACE_TYPE_SYSTEM_AUDIT_OBJECT => "SYSTEM_AUDIT_OBJECT",
        ACE_TYPE_SYSTEM_ALARM_OBJECT => "SYSTEM_ALARM_OBJECT",
        ACE_TYPE_ACCESS_ALLOWED_CALLBACK => "ACCESS_ALLOWED_CALLBACK",
        ACE_TYPE_ACCESS_DENIED_CALLBACK => "ACCESS_DENIED_CALLBACK",
        ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT => "ACCESS_ALLOWED_CALLBACK_OBJECT",
        ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT => "ACCESS_DENIED_CALLBACK_OBJECT",
        ACE_TYPE_SYSTEM_AUDIT_CALLBACK => "SYSTEM_AUDIT_CALLBACK",
        ACE_TYPE_SYSTEM_ALARM_CALLBACK => "SYSTEM_ALARM_CALLBACK",
        ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT => "SYSTEM_AUDIT_CALLBACK_OBJECT",
        ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT => "SYSTEM_ALARM_CALLBACK_OBJECT",
        ACE_TYPE_SYSTEM_MANDATORY_LABEL => "SYSTEM_MANDATORY_LABEL",
        ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE => "SYSTEM_RESOURCE_ATTRIBUTE",
        ACE_TYPE_SYSTEM_SCOPED_POLICY_ID => "SYSTEM_SCOPED_POLICY_ID",
        ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL => "SYSTEM_PROCESS_TRUST_LABEL",
        ACE_TYPE_SYSTEM_ACCESS_FILTER => "SYSTEM_ACCESS_FILTER",
        _ => "UNKNOWN",
    }
}

/// True for ACE types whose body layout is "u32 mask, then SID" (no
/// object-GUIDs). Caller uses this to know it can decode mask+SID.
pub fn ace_type_is_simple_mask_sid(t: u8) -> bool {
    matches!(
        t,
        ACE_TYPE_ACCESS_ALLOWED
            | ACE_TYPE_ACCESS_DENIED
            | ACE_TYPE_SYSTEM_AUDIT
            | ACE_TYPE_ACCESS_ALLOWED_CALLBACK
            | ACE_TYPE_ACCESS_DENIED_CALLBACK
            | ACE_TYPE_SYSTEM_AUDIT_CALLBACK
            | ACE_TYPE_SYSTEM_MANDATORY_LABEL
            | ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE
    )
}

// ---------------------------------------------------------------------------
// ACE flags.
// ---------------------------------------------------------------------------

pub const ACE_FLAG_OBJECT_INHERIT: u8 = peios_uapi::KACS_ACE_FLAG_OBJECT_INHERIT as u8;
pub const ACE_FLAG_CONTAINER_INHERIT: u8 = peios_uapi::KACS_ACE_FLAG_CONTAINER_INHERIT as u8;
pub const ACE_FLAG_NO_PROPAGATE_INHERIT: u8 = peios_uapi::KACS_ACE_FLAG_NO_PROPAGATE_INHERIT as u8;
pub const ACE_FLAG_INHERIT_ONLY: u8 = peios_uapi::KACS_ACE_FLAG_INHERIT_ONLY as u8;
pub const ACE_FLAG_INHERITED: u8 = peios_uapi::KACS_ACE_FLAG_INHERITED as u8;
pub const ACE_FLAG_SUCCESSFUL_ACCESS: u8 = peios_uapi::KACS_ACE_FLAG_SUCCESSFUL_ACCESS as u8;
pub const ACE_FLAG_FAILED_ACCESS: u8 = peios_uapi::KACS_ACE_FLAG_FAILED_ACCESS as u8;

pub fn ace_flag_names(f: u8) -> Vec<&'static str> {
    const NAMES: &[(u8, &str)] = &[
        (ACE_FLAG_OBJECT_INHERIT, "OBJECT_INHERIT"),
        (ACE_FLAG_CONTAINER_INHERIT, "CONTAINER_INHERIT"),
        (ACE_FLAG_NO_PROPAGATE_INHERIT, "NO_PROPAGATE_INHERIT"),
        (ACE_FLAG_INHERIT_ONLY, "INHERIT_ONLY"),
        (ACE_FLAG_INHERITED, "INHERITED"),
        (ACE_FLAG_SUCCESSFUL_ACCESS, "SUCCESSFUL_ACCESS"),
        (ACE_FLAG_FAILED_ACCESS, "FAILED_ACCESS"),
    ];
    NAMES
        .iter()
        .filter(|(b, _)| f & *b != 0)
        .map(|(_, n)| *n)
        .collect()
}

// ---------------------------------------------------------------------------
// Object-ACE `Flags` field bits — the `u32` at body offset 8 of an object
// ACE, distinct from the 1-byte `AceFlags` header field above.
// ---------------------------------------------------------------------------

/// The object-ACE body carries an `ObjectType` GUID.
pub const ACE_OBJECT_TYPE_PRESENT: u32 = peios_uapi::KACS_ACE_OBJECT_TYPE_PRESENT;
/// The object-ACE body carries an `InheritedObjectType` GUID.
pub const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 =
    peios_uapi::KACS_ACE_INHERITED_OBJECT_TYPE_PRESENT;

// ---------------------------------------------------------------------------
// Parsed structures.
// ---------------------------------------------------------------------------

/// Borrowed view over a single ACE on the wire. Zero allocation.
#[derive(Clone, Copy)]
pub struct AceRef<'a> {
    pub ace_type: u8,
    pub flags: u8,
    pub size: u16,
    /// Raw body bytes (everything after the 4-byte ACE header).
    pub body: &'a [u8],
}

/// Owned ACE. Produced via `AceRef::to_owned()` when the caller needs to
/// retain the ACE beyond the lifetime of the parent buffer.
#[derive(Clone)]
pub struct Ace {
    pub ace_type: u8,
    pub flags: u8,
    pub size: u16,
    pub body: Vec<u8>,
}

impl<'a> AceRef<'a> {
    /// Promote into an owned [`Ace`]. Allocates `body`.
    pub fn to_owned(&self) -> Ace {
        Ace {
            ace_type: self.ace_type,
            flags: self.flags,
            size: self.size,
            body: self.body.to_vec(),
        }
    }

    /// Decode this ACE as the common "u32 mask, then SID" layout. Returns
    /// `None` for ACE types that don't use this layout. The borrowed SID
    /// view shares the ACE's body lifetime.
    pub fn as_mask_sid(&self) -> Option<(u32, SidRef<'a>)> {
        if !ace_type_is_simple_mask_sid(self.ace_type) {
            return None;
        }
        if self.body.len() < 4 {
            return None;
        }
        let mask = u32::from_le_bytes([self.body[0], self.body[1], self.body[2], self.body[3]]);
        let (sid, _) = SidRef::parse(&self.body[4..]).ok()?;
        Some((mask, sid))
    }

    /// Owned variant of [`AceRef::as_mask_sid`]. Allocates the SID's
    /// subauthority vector.
    pub fn as_mask_sid_owned(&self) -> Option<(u32, Sid)> {
        self.as_mask_sid().map(|(m, s)| (m, s.to_owned()))
    }
}

impl Ace {
    /// Decode this ACE as the common "u32 mask, then SID" layout, returning
    /// the owned-SID form. See [`AceRef::as_mask_sid`] for the zero-alloc
    /// variant.
    pub fn as_mask_sid(&self) -> Option<(u32, Sid)> {
        AceRef {
            ace_type: self.ace_type,
            flags: self.flags,
            size: self.size,
            body: &self.body,
        }
        .as_mask_sid_owned()
    }
}

/// Parsed ACL. Lazy iteration over ACEs via [`Acl::aces_iter`].
pub struct Acl<'a> {
    pub revision: u8,
    pub size: u16,
    pub ace_count: u16,
    /// Raw bytes of the ACL, starting at the ACL header.
    pub bytes: &'a [u8],
}

impl<'a> Acl<'a> {
    /// Parse the ACL header at the start of `bytes`. Returns the ACL view; the
    /// header bounds-checks `size` against `bytes.len()`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < 8 {
            return Err(ParseError::AclHeaderTruncated);
        }
        let revision = bytes[0];
        let size = u16::from_le_bytes([bytes[2], bytes[3]]);
        let ace_count = u16::from_le_bytes([bytes[4], bytes[5]]);
        if (size as usize) > bytes.len() {
            return Err(ParseError::AclSizeOutOfBounds);
        }
        Ok(Self {
            revision,
            size,
            ace_count,
            bytes: &bytes[..size as usize],
        })
    }

    /// Iterate over ACEs in declaration order. Yields borrowed [`AceRef`]
    /// views; callers can `.to_owned()` per-ACE if needed.
    pub fn aces_iter(&self) -> AceIter<'a> {
        AceIter {
            bytes: &self.bytes[8..],
            remaining: self.ace_count as usize,
        }
    }
}

pub struct AceIter<'a> {
    bytes: &'a [u8],
    remaining: usize,
}

impl<'a> Iterator for AceIter<'a> {
    type Item = Result<AceRef<'a>, ParseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        if self.bytes.len() < 4 {
            self.remaining = 0;
            return Some(Err(ParseError::AceHeaderTruncated));
        }
        let ace_type = self.bytes[0];
        let flags = self.bytes[1];
        let size = u16::from_le_bytes([self.bytes[2], self.bytes[3]]);
        if (size as usize) < 4 || self.bytes.len() < size as usize {
            self.remaining = 0;
            return Some(Err(ParseError::AceSizeInvalid));
        }
        let body = &self.bytes[4..size as usize];
        self.bytes = &self.bytes[size as usize..];
        self.remaining -= 1;
        Some(Ok(AceRef {
            ace_type,
            flags,
            size,
            body,
        }))
    }
}

/// Top-level parsed SECURITY_DESCRIPTOR (self-relative). Borrowed view.
pub struct SecurityDescriptor<'a> {
    pub revision: u8,
    pub sbz1: u8,
    pub control: u16,
    pub owner_off: u32,
    pub group_off: u32,
    pub sacl_off: u32,
    pub dacl_off: u32,
    pub bytes: &'a [u8],
}

impl<'a> SecurityDescriptor<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < SD_HEADER_BYTES {
            return Err(ParseError::SdHeaderTruncated);
        }
        let revision = bytes[0];
        let sbz1 = bytes[1];
        let control = u16::from_le_bytes([bytes[2], bytes[3]]);
        let owner_off = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let group_off = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let sacl_off = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let dacl_off = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        Ok(Self {
            revision,
            sbz1,
            control,
            owner_off,
            group_off,
            sacl_off,
            dacl_off,
            bytes,
        })
    }

    fn sid_at(&self, off: u32) -> Option<SidRef<'a>> {
        if off == 0 {
            return None;
        }
        let start = off as usize;
        if start >= self.bytes.len() {
            return None;
        }
        SidRef::parse(&self.bytes[start..]).ok().map(|(s, _)| s)
    }

    /// Borrowed-SID accessor for owner. Returns `None` if owner is absent
    /// or the offset is out of bounds.
    pub fn owner_ref(&self) -> Option<SidRef<'a>> {
        self.sid_at(self.owner_off)
    }

    /// Owned-SID accessor for owner. Allocates if present.
    pub fn owner(&self) -> Option<Sid> {
        self.owner_ref().map(|s| s.to_owned())
    }

    /// Borrowed-SID accessor for group.
    pub fn group_ref(&self) -> Option<SidRef<'a>> {
        self.sid_at(self.group_off)
    }

    /// Owned-SID accessor for group.
    pub fn group(&self) -> Option<Sid> {
        self.group_ref().map(|s| s.to_owned())
    }

    pub fn dacl(&self) -> Option<Result<Acl<'_>, ParseError>> {
        if self.control & SE_DACL_PRESENT == 0 || self.dacl_off == 0 {
            return None;
        }
        let start = self.dacl_off as usize;
        if start >= self.bytes.len() {
            return Some(Err(ParseError::SdOffsetOutOfBounds));
        }
        Some(Acl::parse(&self.bytes[start..]))
    }

    pub fn sacl(&self) -> Option<Result<Acl<'_>, ParseError>> {
        if self.control & SE_SACL_PRESENT == 0 || self.sacl_off == 0 {
            return None;
        }
        let start = self.sacl_off as usize;
        if start >= self.bytes.len() {
            return Some(Err(ParseError::SdOffsetOutOfBounds));
        }
        Some(Acl::parse(&self.bytes[start..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn control_decode() {
        let names = control_bit_names(SE_DACL_PRESENT | SE_SELF_RELATIVE);
        assert_eq!(names, vec!["DACL_PRESENT", "SELF_RELATIVE"]);
    }

    #[test]
    fn access_decode_generic_all() {
        let names = access_mask_names(ACCESS_GENERIC_ALL);
        assert_eq!(names, vec!["GENERIC_ALL"]);
    }

    #[test]
    fn access_decode_with_specific() {
        let names = access_mask_names(ACCESS_DELETE | 0x0F);
        assert!(names.contains(&"DELETE"));
        assert!(names.contains(&":specific"));
    }

    #[test]
    fn standard_and_generic_aliases_match_psd_004() {
        assert_eq!(DELETE, 0x0001_0000);
        assert_eq!(READ_CONTROL, 0x0002_0000);
        assert_eq!(WRITE_DAC, 0x0004_0000);
        assert_eq!(WRITE_OWNER, 0x0008_0000);
        assert_eq!(SYNCHRONIZE, 0x0010_0000);
        assert_eq!(ACCESS_SYSTEM_SECURITY, 0x0100_0000);
        assert_eq!(MAXIMUM_ALLOWED, 0x0200_0000);
        assert_eq!(GENERIC_ALL, 0x1000_0000);
        assert_eq!(GENERIC_EXECUTE, 0x2000_0000);
        assert_eq!(GENERIC_WRITE, 0x4000_0000);
        assert_eq!(GENERIC_READ, 0x8000_0000);
    }

    #[test]
    fn generic_mapping_is_c_abi_shape() {
        assert_eq!(core::mem::size_of::<GenericMapping>(), 16);
        assert_eq!(core::mem::offset_of!(GenericMapping, read), 0);
        assert_eq!(core::mem::offset_of!(GenericMapping, write), 4);
        assert_eq!(core::mem::offset_of!(GenericMapping, execute), 8);
        assert_eq!(core::mem::offset_of!(GenericMapping, all), 12);
    }

    #[test]
    fn ace_type_lookup() {
        assert_eq!(ace_type_name(ACE_TYPE_ACCESS_ALLOWED), "ACCESS_ALLOWED");
        assert_eq!(
            ace_type_name(ACE_TYPE_SYSTEM_MANDATORY_LABEL),
            "SYSTEM_MANDATORY_LABEL"
        );
        assert_eq!(ace_type_name(0xFE), "UNKNOWN");
    }
}
