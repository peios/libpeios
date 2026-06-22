// Security Identifier (SID) — Peios uses the Windows binary SID layout
// verbatim (MS-DTYP § 2.4.2 / 2.4.2.2).
//
// Binary layout (variable length):
//   u8  Revision               (always 1)
//   u8  SubAuthorityCount      (0..=15)
//   u8[6] IdentifierAuthority  (big-endian 48-bit)
//   u32 SubAuthority[count]    (little-endian, one per subauthority)
//
// Text form: "S-<rev>-<authority>-<sub1>-<sub2>-...".
//
// Two parse shapes are exposed:
//
//   - `SidRef::parse(&bytes)` — zero-alloc borrowed view over the wire
//     bytes. Use this in hot paths (KMES event walking, SD enumeration).
//   - `Sid::parse(&bytes)`    — convenience owned-form. Internally
//     parses to `SidRef` then `to_owned()`s. Allocates one `Vec<u32>`.

use crate::security::sddl::wire_error::ParseError;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// SID_AND_ATTRIBUTES group attribute bits.
//
// A typed newtype over the `KACS_SID_GROUP_*` values from the generated
// uapi crate. SID-and-attributes is a SID-level concept, so it lives with
// the SID primitive (libp-go scatters these into its token/sd packages;
// libp-rs keeps them with the wire SID — same capability, idiomatic shape).
// ---------------------------------------------------------------------------

/// SID group-attribute flags (`SID_AND_ATTRIBUTES.Attributes`).
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct GroupAttributes(pub u32);

impl GroupAttributes {
    /// The group is mandatory: it cannot be disabled and is always used in
    /// access checks.
    pub const MANDATORY: Self = Self(peios_uapi::KACS_SID_GROUP_MANDATORY);
    /// The group is enabled by default.
    pub const ENABLED_BY_DEFAULT: Self = Self(peios_uapi::KACS_SID_GROUP_ENABLED_BY_DEFAULT);
    /// The group is enabled for access checks.
    pub const ENABLED: Self = Self(peios_uapi::KACS_SID_GROUP_ENABLED);
    /// The group identifies the owner of the object.
    pub const OWNER: Self = Self(peios_uapi::KACS_SID_GROUP_OWNER);
    /// The group is a deny-only group: it can only deny, never grant.
    pub const USE_FOR_DENY_ONLY: Self = Self(peios_uapi::KACS_SID_GROUP_USE_FOR_DENY_ONLY);
    /// The group is a mandatory integrity-level SID.
    pub const INTEGRITY: Self = Self(peios_uapi::KACS_SID_GROUP_INTEGRITY);
    /// The integrity-level SID is enabled.
    pub const INTEGRITY_ENABLED: Self = Self(peios_uapi::KACS_SID_GROUP_INTEGRITY_ENABLED);
    /// The group identifies a domain-local (resource) group.
    pub const RESOURCE: Self = Self(peios_uapi::KACS_SID_GROUP_RESOURCE);
    /// The group is a logon-session SID.
    pub const LOGON_ID: Self = Self(peios_uapi::KACS_SID_GROUP_LOGON_ID);

    /// The raw attribute bits.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// True if every bit set in `other` is also set in `self`.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for GroupAttributes {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for GroupAttributes {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

/// A parsed/owned Security Identifier. Allocates one `Vec<u32>` to hold
/// the subauthorities. Use [`SidRef`] for zero-alloc parsing.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    pub revision: u8,
    pub authority: u64, // 48-bit value
    pub sub_authorities: Vec<u32>,
}

/// A borrowed view over a SID's wire bytes. Zero allocation.
///
/// Subauthorities are decoded lazily via [`SidRef::sub_authority`] and
/// [`SidRef::sub_authorities_iter`]. Call [`SidRef::to_owned`] to
/// promote into an owned [`Sid`].
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SidRef<'a> {
    pub revision: u8,
    pub authority: u64,
    /// Subauthority payload: `4 * sub_authority_count` bytes,
    /// little-endian u32s back-to-back.
    sub_authorities_bytes: &'a [u8],
}

/// Length-in-bytes of a SID structure given its subauthority count.
pub const fn sid_byte_len(sub_authority_count: u8) -> usize {
    8 + 4 * (sub_authority_count as usize)
}

impl<'a> SidRef<'a> {
    /// Parse the leading SID from `bytes`. Returns the borrowed view plus
    /// the number of bytes consumed.
    pub fn parse(bytes: &'a [u8]) -> Result<(Self, usize), ParseError> {
        if bytes.len() < 8 {
            return Err(ParseError::SidHeaderTruncated);
        }
        let revision = bytes[0];
        let count = bytes[1] as usize;
        let need = 8 + 4 * count;
        if bytes.len() < need {
            return Err(ParseError::SidSubAuthoritiesTruncated);
        }
        let mut authority: u64 = 0;
        for &b in &bytes[2..8] {
            authority = (authority << 8) | b as u64;
        }
        Ok((
            Self {
                revision,
                authority,
                sub_authorities_bytes: &bytes[8..need],
            },
            need,
        ))
    }

    /// Number of subauthorities declared in the header.
    #[inline]
    pub fn sub_authority_count(&self) -> u8 {
        (self.sub_authorities_bytes.len() / 4) as u8
    }

    /// Subauthority at the given index, or `None` if out of range.
    pub fn sub_authority(&self, i: usize) -> Option<u32> {
        let start = 4 * i;
        let end = start + 4;
        if end > self.sub_authorities_bytes.len() {
            return None;
        }
        let slice = &self.sub_authorities_bytes[start..end];
        Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    }

    /// Iterate over subauthorities in declaration order.
    pub fn sub_authorities_iter(&self) -> SubAuthorityIter<'a> {
        SubAuthorityIter {
            bytes: self.sub_authorities_bytes,
        }
    }

    /// Number of bytes this SID occupies on the wire.
    pub fn encoded_len(&self) -> usize {
        8 + self.sub_authorities_bytes.len()
    }

    /// Promote into an owned [`Sid`]. Allocates the subauthority vector.
    pub fn to_owned(&self) -> Sid {
        Sid {
            revision: self.revision,
            authority: self.authority,
            sub_authorities: self.sub_authorities_iter().collect(),
        }
    }

    /// Human-readable label for well-known SIDs, or `""` for unknown.
    /// Labels include leading ` (` so they can be concatenated after the
    /// SID text form.
    pub fn well_known_label(&self) -> &'static str {
        // The `ToString` impl (via `Display`) formats canonically.
        let s: String = (*self).to_string();
        well_known_label(&s)
    }
}

pub struct SubAuthorityIter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for SubAuthorityIter<'a> {
    type Item = u32;
    fn next(&mut self) -> Option<u32> {
        if self.bytes.len() < 4 {
            return None;
        }
        let v = u32::from_le_bytes([self.bytes[0], self.bytes[1], self.bytes[2], self.bytes[3]]);
        self.bytes = &self.bytes[4..];
        Some(v)
    }
}

impl Sid {
    /// Construct an owned SID from explicit field values.
    pub fn new(revision: u8, authority: u64, sub_authorities: Vec<u32>) -> Self {
        Self {
            revision,
            authority,
            sub_authorities,
        }
    }

    /// Parse the leading SID from `bytes`. Returns (sid, bytes_consumed).
    /// Convenience wrapper over [`SidRef::parse`] that allocates.
    pub fn parse(bytes: &[u8]) -> Result<(Self, usize), ParseError> {
        let (sref, used) = SidRef::parse(bytes)?;
        Ok((sref.to_owned(), used))
    }

    /// Number of bytes this SID occupies on the wire.
    pub fn encoded_len(&self) -> usize {
        sid_byte_len(self.sub_authorities.len() as u8)
    }

    /// Serialize to the canonical binary SID layout: revision,
    /// subauthority count, 48-bit big-endian authority, then
    /// little-endian u32 subauthorities. Inverse of [`Sid::parse`].
    pub fn encode(&self) -> Vec<u8> {
        let count = self.sub_authorities.len() as u8;
        let mut out = Vec::with_capacity(sid_byte_len(count));
        out.push(self.revision);
        out.push(count);
        // 48-bit authority, big-endian (top 2 bytes of the u64 dropped).
        let auth = self.authority.to_be_bytes();
        out.extend_from_slice(&auth[2..8]);
        for sa in &self.sub_authorities {
            out.extend_from_slice(&sa.to_le_bytes());
        }
        out
    }

    /// Human-readable label for well-known SIDs, or `""` for unknown.
    pub fn well_known_label(&self) -> &'static str {
        let s: String = self.to_string();
        well_known_label(&s)
    }
}

impl core::fmt::Display for Sid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "S-{}-{}", self.revision, self.authority)?;
        for sa in &self.sub_authorities {
            write!(f, "-{sa}")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for Sid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sid({self})")
    }
}

impl<'a> core::fmt::Display for SidRef<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "S-{}-{}", self.revision, self.authority)?;
        for sa in self.sub_authorities_iter() {
            write!(f, "-{sa}")?;
        }
        Ok(())
    }
}

impl<'a> core::fmt::Debug for SidRef<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SidRef({self})")
    }
}

/// Look up a label for a canonical-form SID string. Returns `""` for
/// unknown. Labels are formatted with leading ` (` and trailing `)` so
/// they can be concatenated directly after the SID text.
pub fn well_known_label(sid: &str) -> &'static str {
    match sid {
        "S-1-0-0" => " (Null)",
        "S-1-1-0" => " (World/Everyone)",
        "S-1-5-7" => " (Anonymous)",
        "S-1-5-11" => " (Authenticated Users)",
        "S-1-5-18" => " (LocalSystem)",
        "S-1-5-19" => " (LocalService)",
        "S-1-5-20" => " (NetworkService)",
        "S-1-5-32-544" => " (BUILTIN\\Administrators)",
        "S-1-5-32-545" => " (BUILTIN\\Users)",
        "S-1-16-0" => " (Untrusted IL)",
        "S-1-16-4096" => " (Low IL)",
        "S-1-16-8192" => " (Medium IL)",
        "S-1-16-8448" => " (Medium-Plus IL)",
        "S-1-16-12288" => " (High IL)",
        "S-1-16-16384" => " (System IL)",
        "S-1-16-20480" => " (Protected-Process IL)",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn group_attribute_constants_match_psd_004() {
        assert_eq!(GroupAttributes::MANDATORY.bits(), 0x0000_0001);
        assert_eq!(GroupAttributes::ENABLED_BY_DEFAULT.bits(), 0x0000_0002);
        assert_eq!(GroupAttributes::ENABLED.bits(), 0x0000_0004);
        assert_eq!(GroupAttributes::OWNER.bits(), 0x0000_0008);
        assert_eq!(GroupAttributes::USE_FOR_DENY_ONLY.bits(), 0x0000_0010);
        assert_eq!(GroupAttributes::INTEGRITY.bits(), 0x0000_0020);
        assert_eq!(GroupAttributes::INTEGRITY_ENABLED.bits(), 0x0000_0040);
        assert_eq!(GroupAttributes::RESOURCE.bits(), 0x2000_0000);
        assert_eq!(GroupAttributes::LOGON_ID.bits(), 0xC000_0000);
    }

    #[test]
    fn group_attributes_compose_and_test() {
        let combo = GroupAttributes::MANDATORY | GroupAttributes::ENABLED;
        assert!(combo.contains(GroupAttributes::MANDATORY));
        assert!(combo.contains(GroupAttributes::ENABLED));
        assert!(!combo.contains(GroupAttributes::OWNER));
    }

    // S-1-5-18 (LocalSystem): rev=1, count=1, auth=5, sub=[18].
    const LOCAL_SYSTEM_BYTES: &[u8] = &[
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn parse_local_system_owned() {
        let (sid, used) = Sid::parse(LOCAL_SYSTEM_BYTES).unwrap();
        assert_eq!(used, 12);
        assert_eq!(sid.revision, 1);
        assert_eq!(sid.authority, 5);
        assert_eq!(sid.sub_authorities, vec![18]);
        assert_eq!(alloc::format!("{sid}"), "S-1-5-18");
        assert_eq!(sid.well_known_label(), " (LocalSystem)");
    }

    #[test]
    fn parse_local_system_borrowed() {
        let (sref, used) = SidRef::parse(LOCAL_SYSTEM_BYTES).unwrap();
        assert_eq!(used, 12);
        assert_eq!(sref.revision, 1);
        assert_eq!(sref.authority, 5);
        assert_eq!(sref.sub_authority_count(), 1);
        assert_eq!(sref.sub_authority(0), Some(18));
        assert_eq!(sref.sub_authority(1), None);
        let owned = sref.to_owned();
        assert_eq!(owned.sub_authorities, vec![18]);
    }

    #[test]
    fn sub_authority_iter() {
        // S-1-5-32-544 (BUILTIN\Administrators): two subauthorities.
        let bytes: &[u8] = &[
            0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // header
            0x20, 0x00, 0x00, 0x00, // 32
            0x20, 0x02, 0x00, 0x00, // 544
        ];
        let (sref, _) = SidRef::parse(bytes).unwrap();
        let collected: Vec<u32> = sref.sub_authorities_iter().collect();
        assert_eq!(collected, vec![32, 544]);
    }

    #[test]
    fn builtin_admins_label() {
        assert_eq!(
            well_known_label("S-1-5-32-544"),
            " (BUILTIN\\Administrators)"
        );
    }

    #[test]
    fn unknown_sid_has_no_label() {
        assert_eq!(well_known_label("S-1-5-21-1234-5678"), "");
    }

    #[test]
    fn rejects_truncated_header() {
        assert_eq!(
            SidRef::parse(&[0x01, 0x01]),
            Err(ParseError::SidHeaderTruncated)
        );
        assert_eq!(
            Sid::parse(&[0x01, 0x01]),
            Err(ParseError::SidHeaderTruncated)
        );
    }

    #[test]
    fn rejects_truncated_subauths() {
        assert_eq!(
            SidRef::parse(&LOCAL_SYSTEM_BYTES[..10]),
            Err(ParseError::SidSubAuthoritiesTruncated)
        );
    }

    #[test]
    fn encode_roundtrips_through_parse() {
        let original = Sid::new(1, 5, vec![32, 544]);
        let bytes = original.encode();
        let (parsed, used) = Sid::parse(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(parsed, original);
    }

    #[test]
    fn encode_matches_known_local_system_bytes() {
        let sid = Sid::new(1, 5, vec![18]);
        assert_eq!(sid.encode(), LOCAL_SYSTEM_BYTES);
    }
}
