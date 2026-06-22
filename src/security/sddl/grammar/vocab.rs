// SDDL vocabulary tables (MS-DTYP §2.5.1.1).
//
// All public-facing functions are exported here as `pub(super)` so the
// rest of the SDDL module can read them without these tables leaking
// out of the crate.

use crate::security::sddl::codec::{
    ACCESS_DELETE, ACCESS_GENERIC_ALL, ACCESS_GENERIC_EXECUTE, ACCESS_GENERIC_READ,
    ACCESS_GENERIC_WRITE, ACCESS_READ_CONTROL, ACCESS_WRITE_DAC, ACCESS_WRITE_OWNER,
    ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_FAILED_ACCESS, ACE_FLAG_INHERIT_ONLY, ACE_FLAG_INHERITED,
    ACE_FLAG_NO_PROPAGATE_INHERIT, ACE_FLAG_OBJECT_INHERIT, ACE_FLAG_SUCCESSFUL_ACCESS,
    ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
    ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT, ACE_TYPE_ACCESS_ALLOWED_OBJECT,
    ACE_TYPE_ACCESS_DENIED, ACE_TYPE_ACCESS_DENIED_CALLBACK,
    ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT, ACE_TYPE_ACCESS_DENIED_OBJECT, ACE_TYPE_SYSTEM_AUDIT,
    ACE_TYPE_SYSTEM_AUDIT_CALLBACK, ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT,
    ACE_TYPE_SYSTEM_AUDIT_OBJECT, ACE_TYPE_SYSTEM_MANDATORY_LABEL,
    ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE, ACE_TYPE_SYSTEM_SCOPED_POLICY_ID,
};
use crate::security::sddl::wire::Sid;

use crate::security::sddl::wellknown::WellKnownSid;

// ---------------------------------------------------------------------------
// ACE type codes
// ---------------------------------------------------------------------------

const ACE_TYPE_CODES: &[(&str, u8)] = &[
    ("A", ACE_TYPE_ACCESS_ALLOWED),
    ("D", ACE_TYPE_ACCESS_DENIED),
    ("AU", ACE_TYPE_SYSTEM_AUDIT),
    ("OA", ACE_TYPE_ACCESS_ALLOWED_OBJECT),
    ("OD", ACE_TYPE_ACCESS_DENIED_OBJECT),
    ("OU", ACE_TYPE_SYSTEM_AUDIT_OBJECT),
    ("XA", ACE_TYPE_ACCESS_ALLOWED_CALLBACK),
    ("XD", ACE_TYPE_ACCESS_DENIED_CALLBACK),
    ("XU", ACE_TYPE_SYSTEM_AUDIT_CALLBACK),
    ("ZA", ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT),
    ("ZD", ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT),
    ("ZU", ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT),
    ("ML", ACE_TYPE_SYSTEM_MANDATORY_LABEL),
    ("RA", ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE),
    ("SP", ACE_TYPE_SYSTEM_SCOPED_POLICY_ID),
];

pub(super) fn ace_type_from_code(code: &str) -> Option<u8> {
    ACE_TYPE_CODES
        .iter()
        .find_map(|&(c, v)| if c == code { Some(v) } else { None })
}

pub(super) fn ace_code_from_type(t: u8) -> Option<&'static str> {
    ACE_TYPE_CODES
        .iter()
        .find_map(|&(c, v)| if v == t { Some(c) } else { None })
}

// ---------------------------------------------------------------------------
// ACE flag codes
// ---------------------------------------------------------------------------

/// Ordered for formatter output — matches the SDDL convention of
/// `CIOI`-style ordering (container before object) and audit-success
/// before audit-failure.
const ACE_FLAG_CODES: &[(&str, u8)] = &[
    ("CI", ACE_FLAG_CONTAINER_INHERIT),
    ("OI", ACE_FLAG_OBJECT_INHERIT),
    ("NP", ACE_FLAG_NO_PROPAGATE_INHERIT),
    ("IO", ACE_FLAG_INHERIT_ONLY),
    ("ID", ACE_FLAG_INHERITED),
    ("SA", ACE_FLAG_SUCCESSFUL_ACCESS),
    ("FA", ACE_FLAG_FAILED_ACCESS),
];

pub(super) fn ace_flag_from_code(code: &str) -> Option<u8> {
    ACE_FLAG_CODES
        .iter()
        .find_map(|&(c, v)| if c == code { Some(v) } else { None })
}

pub(super) fn ace_flag_format_order() -> &'static [(&'static str, u8)] {
    ACE_FLAG_CODES
}

// ---------------------------------------------------------------------------
// Access rights vocab
// ---------------------------------------------------------------------------
//
// Two tables:
//   * `RIGHTS_PARSE`     — text → mask, used by the parser. Includes
//                           everything we recognise (composites, generic,
//                           standard, object-specific, mandatory label).
//   * `RIGHTS_FORMAT`    — ordered text/mask pairs for the formatter.
//                           Composites first (so a multi-bit code wins
//                           over its components); the ambiguous object-
//                           specific bits (CC, DC, …) and mandatory-label
//                           bits (NW, NR, NX) are intentionally absent
//                           from the formatter — they share bit positions
//                           with each other and would over-emit. The
//                           parser still accepts them.

const RIGHTS_PARSE: &[(&str, u32)] = &[
    // Generic
    ("GA", ACCESS_GENERIC_ALL),
    ("GR", ACCESS_GENERIC_READ),
    ("GW", ACCESS_GENERIC_WRITE),
    ("GX", ACCESS_GENERIC_EXECUTE),
    // Standard
    ("SD", ACCESS_DELETE),
    ("RC", ACCESS_READ_CONTROL),
    ("WD", ACCESS_WRITE_DAC),
    ("WO", ACCESS_WRITE_OWNER),
    // File composites
    ("FA", 0x001F_01FF),
    ("FR", 0x0012_0089),
    ("FW", 0x0012_0116),
    ("FX", 0x0012_00A0),
    // Registry-key composites
    ("KA", 0x000F_003F),
    ("KR", 0x0002_0019),
    ("KW", 0x0002_0006),
    ("KX", 0x0002_0019),
    // Directory-object specifics
    ("CC", 0x0000_0001),
    ("DC", 0x0000_0002),
    ("LC", 0x0000_0004),
    ("SW", 0x0000_0008),
    ("RP", 0x0000_0010),
    ("WP", 0x0000_0020),
    ("DT", 0x0000_0040),
    ("LO", 0x0000_0080),
    ("CR", 0x0000_0100),
    // Mandatory-label policy bits
    ("NW", 0x0000_0001),
    ("NR", 0x0000_0002),
    ("NX", 0x0000_0004),
];

pub(super) fn right_from_code(code: &str) -> Option<u32> {
    RIGHTS_PARSE
        .iter()
        .find_map(|&(c, v)| if c == code { Some(v) } else { None })
}

/// Formatter order: composites first (longest-match wins for the
/// greedy decomposition), then generic, then standard. Object-specific
/// and mandatory-label codes are excluded — emitting one without ACL
/// context would silently change meaning.
const RIGHTS_FORMAT: &[(&str, u32)] = &[
    // File composites
    ("FA", 0x001F_01FF),
    ("FR", 0x0012_0089),
    ("FW", 0x0012_0116),
    ("FX", 0x0012_00A0),
    // Registry-key composites
    ("KA", 0x000F_003F),
    ("KR", 0x0002_0019),
    ("KW", 0x0002_0006),
    // Generic
    ("GA", ACCESS_GENERIC_ALL),
    ("GR", ACCESS_GENERIC_READ),
    ("GW", ACCESS_GENERIC_WRITE),
    ("GX", ACCESS_GENERIC_EXECUTE),
    // Standard
    ("SD", ACCESS_DELETE),
    ("RC", ACCESS_READ_CONTROL),
    ("WD", ACCESS_WRITE_DAC),
    ("WO", ACCESS_WRITE_OWNER),
];

pub(super) fn rights_format_order() -> &'static [(&'static str, u32)] {
    RIGHTS_FORMAT
}

// ---------------------------------------------------------------------------
// SID aliases
// ---------------------------------------------------------------------------

const SID_ALIASES: &[(&str, WellKnownSid)] = &[
    ("WD", WellKnownSid::Everyone),
    ("AN", WellKnownSid::Anonymous),
    ("AU", WellKnownSid::AuthenticatedUsers),
    ("SY", WellKnownSid::LocalSystem),
    ("LS", WellKnownSid::LocalService),
    ("NS", WellKnownSid::NetworkService),
    ("BA", WellKnownSid::BuiltinAdministrators),
    ("BU", WellKnownSid::BuiltinUsers),
    ("LW", WellKnownSid::LowIl),
    ("ME", WellKnownSid::MediumIl),
    ("MP", WellKnownSid::MediumPlusIl),
    ("HI", WellKnownSid::HighIl),
    ("SI", WellKnownSid::SystemIl),
    // S-1-0-0 has no canonical SDDL alias; emit/parse as S-1-0-0.
];

pub(super) fn sid_from_alias(alias: &str) -> Option<Sid> {
    SID_ALIASES
        .iter()
        .find_map(|&(a, w)| if a == alias { Some(w.to_sid()) } else { None })
}

pub(super) fn alias_from_sid(sid: &Sid) -> Option<&'static str> {
    SID_ALIASES
        .iter()
        .find_map(|&(a, w)| if w.matches(sid) { Some(a) } else { None })
}

/// Domain-relative aliases (MS-DTYP §2.5.1.1). We recognise them so the
/// parser can return a clear error; we can't resolve them until Peios
/// has a domain SID model.
const DOMAIN_RELATIVE: &[&str] = &[
    "DA", "DG", "DU", "DD", "DC", "LA", "LG", "SA", "EA", "RO", "CA", "PA", "CN", "RS", "RU",
];

pub(super) fn is_domain_relative_alias(alias: &str) -> bool {
    DOMAIN_RELATIVE.contains(&alias)
}
