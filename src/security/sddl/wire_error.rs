// Parse errors for the Peios on-wire formats: SID, SECURITY_DESCRIPTOR,
// ACL, ACE, and the KMES event header. One shared type lets libp consumers
// write a single `From<ParseError>` impl.
//
// msgpack decode errors are deliberately NOT here — the `msgpack` crate is
// a standalone general codec with its own `msgpack::Error`.

use core::fmt;

/// Errors produced by any on-wire parser in libp-rs.
///
/// Variants are deliberately granular so callers can pattern-match on the
/// specific failure mode if they care; the common case is to treat any of
/// them as a malformed-input error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    // ---- SID ----
    /// The byte slice was too short to contain even a SID header.
    SidHeaderTruncated,
    /// The slice ended before the declared subauthorities did.
    SidSubAuthoritiesTruncated,

    // ---- SD / ACL / ACE ----
    /// The byte slice was too short to contain an SD header.
    SdHeaderTruncated,
    /// `OwnerOffset` / `GroupOffset` / `SaclOffset` / `DaclOffset` ran past
    /// the SD's byte slice.
    SdOffsetOutOfBounds,
    /// The SD's control word lacks `SE_SELF_RELATIVE` — it is an absolute
    /// descriptor (pointers, not offsets) and cannot be processed as a
    /// flat byte blob.
    SdNotSelfRelative,
    /// ACL header was truncated.
    AclHeaderTruncated,
    /// ACL's self-declared size ran past the buffer.
    AclSizeOutOfBounds,
    /// ACE header was truncated.
    AceHeaderTruncated,
    /// ACE's self-declared size was below the 4-byte header minimum or ran
    /// past the buffer.
    AceSizeInvalid,

    // ---- KMES ----
    /// The KMES event header was truncated.
    EventHeaderTruncated,
    /// `event_size` or `event_type_len` produced an inconsistent layout.
    EventSizeInvalid,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::SidHeaderTruncated => f.write_str("SID header truncated"),
            ParseError::SidSubAuthoritiesTruncated => f.write_str("SID subauthorities truncated"),
            ParseError::SdHeaderTruncated => f.write_str("SD header truncated"),
            ParseError::SdOffsetOutOfBounds => f.write_str("SD offset out of bounds"),
            ParseError::SdNotSelfRelative => {
                f.write_str("security descriptor is not self-relative")
            }
            ParseError::AclHeaderTruncated => f.write_str("ACL header truncated"),
            ParseError::AclSizeOutOfBounds => f.write_str("ACL size runs past buffer"),
            ParseError::AceHeaderTruncated => f.write_str("ACE header truncated"),
            ParseError::AceSizeInvalid => f.write_str("ACE size invalid or truncated"),
            ParseError::EventHeaderTruncated => f.write_str("event header truncated"),
            ParseError::EventSizeInvalid => f.write_str("event size or type-length invalid"),
        }
    }
}

impl core::error::Error for ParseError {}
