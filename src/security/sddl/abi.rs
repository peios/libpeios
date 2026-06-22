// Claim-attribute value-type discriminants (the `@Local` claims array),
// sourced from the generated `peios-uapi` crate. Used by `claims` when
// encoding a `SYSTEM_RESOURCE_ATTRIBUTE` ACE payload.

pub const CLAIM_TYPE_INT64: u16 = peios_uapi::KACS_CLAIM_TYPE_INT64 as u16;
pub const CLAIM_TYPE_UINT64: u16 = peios_uapi::KACS_CLAIM_TYPE_UINT64 as u16;
pub const CLAIM_TYPE_STRING: u16 = peios_uapi::KACS_CLAIM_TYPE_STRING as u16;
pub const CLAIM_TYPE_SID: u16 = peios_uapi::KACS_CLAIM_TYPE_SID as u16;
pub const CLAIM_TYPE_BOOLEAN: u16 = peios_uapi::KACS_CLAIM_TYPE_BOOLEAN as u16;
pub const CLAIM_TYPE_OCTET: u16 = peios_uapi::KACS_CLAIM_TYPE_OCTET as u16;
