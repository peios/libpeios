//! Token-spec builder — `peios_token_builder_*` (`<peios/token.h>`).
//!
//! Assembles the `kacs_create_token` wire format: a fixed 192-byte header of
//! scalar fields (patched in place at the `KACS_TOKEN_SPEC_OFF_*` offsets)
//! followed by a data area of variable-length sections, each pointed at by an
//! offset/(count|len) pair in the header. Heap-backed and sticky-error, like the
//! security builders.
//!
//! Wire format of the data area (little-endian; sections may appear in any order;
//! offset 0 + count/len 0 means absent):
//!   - USER SID / CONFINEMENT SID: raw binary SID bytes.
//!   - SID-and-attributes arrays (groups, device groups, restricted SIDs):
//!     `[sid_len:u32][sid][attrs:u32]` repeated `count` times, no leading count.
//!   - DEFAULT DACL: raw self-relative ACL bytes of length `len`.
//!   - SUPP GIDS: `count` contiguous `u32` values.
//!
//! There is no userspace token-spec *decoder* (only the kernel decodes), so
//! unlike the SD/ACL builders this one validates per field at set time (SIDs and
//! the DACL are parse-checked) rather than re-parsing the whole spec; the full
//! round-trip is a Provium test against the live kernel.
#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;
use core::slice;

use alloc::vec::Vec;

use crate::abi::{cstr_bytes, raw_free, raw_new, to_vec, try_extend, u32_len};
use crate::error::set_errno;
use crate::security::{acl_valid, sid_valid};

// Header layout (all from the generated uapi).
const HEADER: usize = peios_uapi::KACS_TOKEN_SPEC_HEADER_BYTES as usize;
const MAX: usize = peios_uapi::KACS_TOKEN_SPEC_MAX_BYTES as usize;
const VERSION: u32 = peios_uapi::KACS_TOKEN_SPEC_VERSION;
const SOURCE_NAME_BYTES: usize = peios_uapi::KACS_TOKEN_SPEC_SOURCE_NAME_BYTES as usize;

const OFF_VERSION: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_VERSION as usize;
const OFF_TOKEN_TYPE: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_TOKEN_TYPE as usize;
const OFF_IMPERSONATION_LEVEL: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_IMPERSONATION_LEVEL as usize;
const OFF_INTEGRITY_RID: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_INTEGRITY_RID as usize;
const OFF_MANDATORY_POLICY: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_MANDATORY_POLICY as usize;
const OFF_PRIVS_PRESENT: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_PRIVS_PRESENT as usize;
const OFF_PRIVS_ENABLED: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_PRIVS_ENABLED as usize;
const OFF_PROJECTED_UID: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_PROJECTED_UID as usize;
const OFF_PROJECTED_GID: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_PROJECTED_GID as usize;
const OFF_AUDIT_POLICY: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_AUDIT_POLICY as usize;
const OFF_EXPIRATION: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_EXPIRATION as usize;
const OFF_SESSION_ID: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_SESSION_ID as usize;
const OFF_OWNER_SID_INDEX: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_OWNER_SID_INDEX as usize;
const OFF_PRIMARY_GROUP_INDEX: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_PRIMARY_GROUP_INDEX as usize;
const OFF_SOURCE_NAME: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_SOURCE_NAME as usize;
const OFF_SOURCE_ID: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_SOURCE_ID as usize;
const OFF_USER_SID_OFFSET: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_USER_SID_OFFSET as usize;
const OFF_GROUPS_OFFSET: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_GROUPS_OFFSET as usize;
const OFF_GROUPS_COUNT: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_GROUPS_COUNT as usize;
const OFF_DEFAULT_DACL_OFFSET: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_DEFAULT_DACL_OFFSET as usize;
const OFF_DEFAULT_DACL_LEN: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_DEFAULT_DACL_LEN as usize;
const OFF_DEVICE_GROUPS_OFFSET: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_DEVICE_GROUPS_OFFSET as usize;
const OFF_DEVICE_GROUPS_COUNT: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_DEVICE_GROUPS_COUNT as usize;
const OFF_RESTRICTED_SIDS_OFFSET: usize =
    peios_uapi::KACS_TOKEN_SPEC_OFF_RESTRICTED_SIDS_OFFSET as usize;
const OFF_RESTRICTED_SIDS_COUNT: usize =
    peios_uapi::KACS_TOKEN_SPEC_OFF_RESTRICTED_SIDS_COUNT as usize;
const OFF_CONFINEMENT_SID_OFFSET: usize =
    peios_uapi::KACS_TOKEN_SPEC_OFF_CONFINEMENT_SID_OFFSET as usize;
const OFF_CONFINEMENT_SID_LEN: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_CONFINEMENT_SID_LEN as usize;
const OFF_SUPP_GIDS_OFFSET: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_SUPP_GIDS_OFFSET as usize;
const OFF_SUPP_GIDS_COUNT: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_SUPP_GIDS_COUNT as usize;
const OFF_USER_CLAIMS_OFFSET: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_USER_CLAIMS_OFFSET as usize;
const OFF_USER_CLAIMS_LEN: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_USER_CLAIMS_LEN as usize;
const OFF_DEVICE_CLAIMS_OFFSET: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_DEVICE_CLAIMS_OFFSET as usize;
const OFF_DEVICE_CLAIMS_LEN: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_DEVICE_CLAIMS_LEN as usize;
const OFF_LCS_CREDENTIALS_OFFSET: usize =
    peios_uapi::KACS_TOKEN_SPEC_OFF_LCS_CREDENTIALS_OFFSET as usize;
const OFF_WRITE_RESTRICTED: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_WRITE_RESTRICTED as usize;
const OFF_USER_DENY_ONLY: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_USER_DENY_ONLY as usize;
const OFF_ISOLATION_BOUNDARY: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_ISOLATION_BOUNDARY as usize;
const OFF_CONFINEMENT_EXEMPT: usize = peios_uapi::KACS_TOKEN_SPEC_OFF_CONFINEMENT_EXEMPT as usize;

/// `struct peios_token_flags` — the four token-spec boolean flags.
#[repr(C)]
pub struct peios_token_flags {
    pub write_restricted: bool,
    pub user_deny_only: bool,
    pub isolation_boundary: bool,
    pub confinement_exempt: bool,
}

/// `struct peios_token_claim_value` — one value of a claim; the active member is
/// selected by the owning claim's `value_type`.
#[repr(C)]
pub struct peios_token_claim_value {
    pub scalar: u64,
    pub bytes: *const c_void,
    pub len: usize,
}

/// `struct peios_token_claim` — a named, typed, multi-valued security attribute.
#[repr(C)]
pub struct peios_token_claim {
    pub name: *const c_char,
    pub value_type: u16,
    pub flags: u32,
    pub values: *const peios_token_claim_value,
    pub value_count: c_uint,
}

/// `struct peios_token_lcs_credentials` — the LCS registry-credentials extension.
#[repr(C)]
pub struct peios_token_lcs_credentials {
    pub scope_guids: *const [u8; 16],
    pub scope_count: c_uint,
    pub private_layers: *const *const c_char,
    pub private_layer_count: c_uint,
}

/// An accumulating SID-and-attributes array section.
#[derive(Default)]
struct SidAttrs {
    data: Vec<u8>,
    count: u32,
}

impl SidAttrs {
    fn push(&mut self, sid: &[u8], attrs: u32) -> Result<(), ()> {
        try_extend(&mut self.data, &(sid.len() as u32).to_le_bytes())?;
        try_extend(&mut self.data, sid)?;
        try_extend(&mut self.data, &attrs.to_le_bytes())?;
        self.count += 1;
        Ok(())
    }
}

/// Which SID-and-attributes section an add targets.
enum Section {
    Groups,
    DeviceGroups,
    RestrictedSids,
}

/// `peios_token_builder` — opaque, heap-allocated.
pub struct peios_token_builder {
    /// The 192-byte fixed header; scalars are patched in place, section
    /// offset/count fields are (re)computed at materialize.
    header: [u8; HEADER],
    user_sid: Option<Vec<u8>>,
    groups: SidAttrs,
    device_groups: SidAttrs,
    restricted_sids: SidAttrs,
    default_dacl: Option<Vec<u8>>,
    confinement_sid: Option<Vec<u8>>,
    supp_gids: Vec<u8>,
    supp_gids_count: u32,
    /// Concatenated `[entry_len:u32][claim entry]` records (no leading count).
    user_claims: Vec<u8>,
    device_claims: Vec<u8>,
    /// The fully-encoded LCS extension, emitted as the final spec section.
    lcs_credentials: Option<Vec<u8>>,
    error: libc::c_int,
    built: Vec<u8>,
}

impl peios_token_builder {
    fn new() -> Self {
        let mut header = [0u8; HEADER];
        header[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&VERSION.to_le_bytes());
        Self {
            header,
            user_sid: None,
            groups: SidAttrs::default(),
            device_groups: SidAttrs::default(),
            restricted_sids: SidAttrs::default(),
            default_dacl: None,
            confinement_sid: None,
            supp_gids: Vec::new(),
            supp_gids_count: 0,
            user_claims: Vec::new(),
            device_claims: Vec::new(),
            lcs_credentials: None,
            error: 0,
            built: Vec::new(),
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }

    fn latch(&mut self, errno: libc::c_int) {
        if self.error == 0 {
            self.error = errno;
        }
    }

    fn put_u8(&mut self, off: usize, v: u8) {
        self.header[off] = v;
    }
    fn put_u32(&mut self, off: usize, v: u32) {
        self.header[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u64(&mut self, off: usize, v: u64) {
        self.header[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    /// Validate and copy a SID into an owned Vec, latching on failure.
    fn take_sid(&mut self, sid: &[u8]) -> Option<Vec<u8>> {
        if !sid_valid(sid) {
            self.latch(libc::EINVAL);
            return None;
        }
        match to_vec(sid) {
            Ok(v) => Some(v),
            Err(()) => {
                self.latch(libc::ENOMEM);
                None
            }
        }
    }

    fn add_sid_attrs(&mut self, section: Section, sid: &[u8], attrs: u32) {
        if self.error != 0 {
            return;
        }
        if !sid_valid(sid) {
            self.latch(libc::EINVAL);
            return;
        }
        let target = match section {
            Section::Groups => &mut self.groups,
            Section::DeviceGroups => &mut self.device_groups,
            Section::RestrictedSids => &mut self.restricted_sids,
        };
        if target.push(sid, attrs).is_err() {
            self.latch(libc::ENOMEM);
        }
    }

    fn materialize(&mut self) -> Result<(), libc::c_int> {
        if self.error != 0 {
            return Err(self.error);
        }
        let oom = |_| libc::ENOMEM;
        let base = HEADER as u32;
        let mut data: Vec<u8> = Vec::new();

        // Append a section to the data area; return its absolute offset (0 if the
        // section is absent/empty).
        macro_rules! place {
            ($present:expr, $bytes:expr) => {
                if $present {
                    let off = base + data.len() as u32;
                    try_extend(&mut data, $bytes).map_err(oom)?;
                    off
                } else {
                    0
                }
            };
        }

        let user_off = place!(self.user_sid.is_some(), self.user_sid.as_deref().unwrap_or(&[]));
        let groups_off = place!(self.groups.count > 0, &self.groups.data);
        let dacl_off = place!(self.default_dacl.is_some(), self.default_dacl.as_deref().unwrap_or(&[]));
        let dacl_len = self.default_dacl.as_ref().map_or(0, Vec::len) as u32;
        let dgroups_off = place!(self.device_groups.count > 0, &self.device_groups.data);
        let rsids_off = place!(self.restricted_sids.count > 0, &self.restricted_sids.data);
        let conf_off = place!(self.confinement_sid.is_some(), self.confinement_sid.as_deref().unwrap_or(&[]));
        let conf_len = self.confinement_sid.as_ref().map_or(0, Vec::len) as u32;
        let supp_off = place!(self.supp_gids_count > 0, &self.supp_gids);
        let uclaims_off = place!(!self.user_claims.is_empty(), &self.user_claims);
        let uclaims_len = self.user_claims.len() as u32;
        let dclaims_off = place!(!self.device_claims.is_empty(), &self.device_claims);
        let dclaims_len = self.device_claims.len() as u32;
        // The LCS extension carries no length field — the kernel bounds it by the
        // end of the buffer, so it MUST be the final section appended here.
        let lcs_off = place!(
            self.lcs_credentials.is_some(),
            self.lcs_credentials.as_deref().unwrap_or(&[])
        );

        if HEADER + data.len() > MAX {
            return Err(libc::EINVAL);
        }

        // Patch the section offset/count|len fields into the header.
        self.put_u32(OFF_USER_SID_OFFSET, user_off);
        self.put_u32(OFF_GROUPS_OFFSET, groups_off);
        self.put_u32(OFF_GROUPS_COUNT, self.groups.count);
        self.put_u32(OFF_DEFAULT_DACL_OFFSET, dacl_off);
        self.put_u32(OFF_DEFAULT_DACL_LEN, dacl_len);
        self.put_u32(OFF_DEVICE_GROUPS_OFFSET, dgroups_off);
        self.put_u32(OFF_DEVICE_GROUPS_COUNT, self.device_groups.count);
        self.put_u32(OFF_RESTRICTED_SIDS_OFFSET, rsids_off);
        self.put_u32(OFF_RESTRICTED_SIDS_COUNT, self.restricted_sids.count);
        self.put_u32(OFF_CONFINEMENT_SID_OFFSET, conf_off);
        self.put_u32(OFF_CONFINEMENT_SID_LEN, conf_len);
        self.put_u32(OFF_SUPP_GIDS_OFFSET, supp_off);
        self.put_u32(OFF_SUPP_GIDS_COUNT, self.supp_gids_count);
        self.put_u32(OFF_USER_CLAIMS_OFFSET, uclaims_off);
        self.put_u32(OFF_USER_CLAIMS_LEN, uclaims_len);
        self.put_u32(OFF_DEVICE_CLAIMS_OFFSET, dclaims_off);
        self.put_u32(OFF_DEVICE_CLAIMS_LEN, dclaims_len);
        self.put_u32(OFF_LCS_CREDENTIALS_OFFSET, lcs_off);

        self.built.clear();
        try_extend(&mut self.built, &self.header).map_err(oom)?;
        try_extend(&mut self.built, &data).map_err(oom)?;
        Ok(())
    }
}

/// View a SID pointer/len as a slice (`None` if NULL).
unsafe fn sid_slice<'a>(sid: *const c_void, len: usize) -> Option<&'a [u8]> {
    (!sid.is_null()).then(|| slice::from_raw_parts(sid as *const u8, len))
}

// ----------------------------------------------------------------------------
// Lifecycle
// ----------------------------------------------------------------------------

/// `peios_token_builder_new` — allocate a builder, or NULL on OOM.
#[no_mangle]
pub extern "C" fn peios_token_builder_new() -> *mut peios_token_builder {
    unsafe { raw_new(peios_token_builder::new()) }
}

/// `peios_token_builder_free` — destroy a builder (NULL-safe).
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_free(b: *mut peios_token_builder) {
    raw_free(b);
}

/// `peios_token_builder_reset` — clear all fields and the sticky error.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_reset(b: *mut peios_token_builder) {
    if let Some(b) = b.as_mut() {
        b.reset();
    }
}

// ----------------------------------------------------------------------------
// Core fields
// ----------------------------------------------------------------------------

/// `peios_token_builder_user` — set the user SID.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_user(
    b: *mut peios_token_builder,
    sid: *const c_void,
    len: usize,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    match sid_slice(sid, len) {
        Some(s) => {
            if let Some(v) = b.take_sid(s) {
                b.user_sid = Some(v);
            }
        }
        None => b.latch(libc::EINVAL),
    }
}

/// `peios_token_builder_add_group` — append a group (SID + attributes).
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_add_group(
    b: *mut peios_token_builder,
    sid: *const c_void,
    len: usize,
    attrs: u32,
) {
    let Some(b) = b.as_mut() else { return };
    match sid_slice(sid, len) {
        Some(s) => b.add_sid_attrs(Section::Groups, s, attrs),
        None => b.latch(libc::EINVAL),
    }
}

/// `peios_token_builder_privileges` — set the present/enabled privilege words.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_privileges(
    b: *mut peios_token_builder,
    present: u64,
    enabled: u64,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    b.put_u64(OFF_PRIVS_PRESENT, present);
    b.put_u64(OFF_PRIVS_ENABLED, enabled);
}

/// `peios_token_builder_type` — set token type + impersonation level.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_type(
    b: *mut peios_token_builder,
    token_type: u8,
    imp_level: u8,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    b.put_u8(OFF_TOKEN_TYPE, token_type);
    b.put_u8(OFF_IMPERSONATION_LEVEL, imp_level);
}

/// `peios_token_builder_integrity` — set the integrity-level RID.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_integrity(b: *mut peios_token_builder, rid: u32) {
    if let Some(b) = b.as_mut() {
        if b.error == 0 {
            b.put_u32(OFF_INTEGRITY_RID, rid);
        }
    }
}

/// `peios_token_builder_session` — set the session id.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_session(b: *mut peios_token_builder, session_id: u64) {
    if let Some(b) = b.as_mut() {
        if b.error == 0 {
            b.put_u64(OFF_SESSION_ID, session_id);
        }
    }
}

/// `peios_token_builder_owner_index` — set the owner SID index.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_owner_index(b: *mut peios_token_builder, index: u32) {
    if let Some(b) = b.as_mut() {
        if b.error == 0 {
            b.put_u32(OFF_OWNER_SID_INDEX, index);
        }
    }
}

/// `peios_token_builder_primary_group_index` — set the primary-group index.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_primary_group_index(
    b: *mut peios_token_builder,
    index: u32,
) {
    if let Some(b) = b.as_mut() {
        if b.error == 0 {
            b.put_u32(OFF_PRIMARY_GROUP_INDEX, index);
        }
    }
}

/// `peios_token_builder_default_dacl` — set the default DACL from ACL bytes.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_default_dacl(
    b: *mut peios_token_builder,
    acl: *const c_void,
    len: usize,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    match sid_slice(acl, len) {
        Some(a) if acl_valid(a) => match to_vec(a) {
            Ok(v) => b.default_dacl = Some(v),
            Err(()) => b.latch(libc::ENOMEM),
        },
        _ => b.latch(libc::EINVAL),
    }
}

// ----------------------------------------------------------------------------
// Additional fields
// ----------------------------------------------------------------------------

/// `peios_token_builder_mandatory_policy` — set the mandatory-policy bits.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_mandatory_policy(
    b: *mut peios_token_builder,
    bits: u32,
) {
    if let Some(b) = b.as_mut() {
        if b.error == 0 {
            b.put_u32(OFF_MANDATORY_POLICY, bits);
        }
    }
}

/// `peios_token_builder_projected_ids` — set the projected uid/gid.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_projected_ids(
    b: *mut peios_token_builder,
    uid: u32,
    gid: u32,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    b.put_u32(OFF_PROJECTED_UID, uid);
    b.put_u32(OFF_PROJECTED_GID, gid);
}

/// `peios_token_builder_expiration` — set the expiration timestamp.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_expiration(b: *mut peios_token_builder, when: u64) {
    if let Some(b) = b.as_mut() {
        if b.error == 0 {
            b.put_u64(OFF_EXPIRATION, when);
        }
    }
}

/// `peios_token_builder_source` — set the 8-byte source name and source id.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_source(
    b: *mut peios_token_builder,
    name: *const c_char,
    source_id: u64,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    if name.is_null() {
        b.latch(libc::EINVAL);
        return;
    }
    let src = slice::from_raw_parts(name as *const u8, SOURCE_NAME_BYTES);
    b.header[OFF_SOURCE_NAME..OFF_SOURCE_NAME + SOURCE_NAME_BYTES].copy_from_slice(src);
    b.put_u64(OFF_SOURCE_ID, source_id);
}

/// `peios_token_builder_audit_policy` — set the audit-policy bits.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_audit_policy(b: *mut peios_token_builder, bits: u32) {
    if let Some(b) = b.as_mut() {
        if b.error == 0 {
            b.put_u32(OFF_AUDIT_POLICY, bits);
        }
    }
}

/// `peios_token_builder_add_restricted_sid` — append a restricting SID.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_add_restricted_sid(
    b: *mut peios_token_builder,
    sid: *const c_void,
    len: usize,
    attrs: u32,
) {
    let Some(b) = b.as_mut() else { return };
    match sid_slice(sid, len) {
        Some(s) => b.add_sid_attrs(Section::RestrictedSids, s, attrs),
        None => b.latch(libc::EINVAL),
    }
}

/// `peios_token_builder_add_device_group` — append a device group.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_add_device_group(
    b: *mut peios_token_builder,
    sid: *const c_void,
    len: usize,
    attrs: u32,
) {
    let Some(b) = b.as_mut() else { return };
    match sid_slice(sid, len) {
        Some(s) => b.add_sid_attrs(Section::DeviceGroups, s, attrs),
        None => b.latch(libc::EINVAL),
    }
}

/// `peios_token_builder_confinement` — set the confinement SID.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_confinement(
    b: *mut peios_token_builder,
    sid: *const c_void,
    len: usize,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    match sid_slice(sid, len) {
        Some(s) => {
            if let Some(v) = b.take_sid(s) {
                b.confinement_sid = Some(v);
            }
        }
        None => b.latch(libc::EINVAL),
    }
}

/// `peios_token_builder_supp_gids` — set the projected supplementary GIDs.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_supp_gids(
    b: *mut peios_token_builder,
    gids: *const u32,
    count: c_uint,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    if count > 0 && gids.is_null() {
        b.latch(libc::EINVAL);
        return;
    }
    let gids = slice::from_raw_parts(gids, count as usize);
    if b.supp_gids.try_reserve(gids.len() * 4).is_err() {
        b.latch(libc::ENOMEM);
        return;
    }
    for &gid in gids {
        b.supp_gids.extend_from_slice(&gid.to_le_bytes());
    }
    b.supp_gids_count += count;
}

/// `peios_token_builder_flags` — set the four token-spec boolean flags.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_flags(
    b: *mut peios_token_builder,
    f: *const peios_token_flags,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    let Some(f) = f.as_ref() else {
        b.latch(libc::EINVAL);
        return;
    };
    b.put_u8(OFF_WRITE_RESTRICTED, f.write_restricted as u8);
    b.put_u8(OFF_USER_DENY_ONLY, f.user_deny_only as u8);
    b.put_u8(OFF_ISOLATION_BOUNDARY, f.isolation_boundary as u8);
    b.put_u8(OFF_CONFINEMENT_EXEMPT, f.confinement_exempt as u8);
}

// ----------------------------------------------------------------------------
// Claims & LCS credentials [adv]
// ----------------------------------------------------------------------------

/// Transcode a UTF-8 byte string to a NUL-terminated UTF-16LE buffer, the wire
/// form claim names and string values use. Rejects invalid UTF-8 and any embedded
/// U+0000 (which would forge a premature terminator).
fn utf16le_cstr(s: &[u8]) -> Result<Vec<u8>, c_int> {
    let st = core::str::from_utf8(s).map_err(|_| libc::EINVAL)?;
    if st.contains('\0') {
        return Err(libc::EINVAL);
    }
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u16; 2];
    for ch in st.chars() {
        for &unit in ch.encode_utf16(&mut buf).iter() {
            out.try_reserve(2).map_err(|_| libc::ENOMEM)?;
            out.extend_from_slice(&unit.to_le_bytes());
        }
    }
    out.try_reserve(2).map_err(|_| libc::ENOMEM)?;
    out.extend_from_slice(&[0, 0]); // UTF-16 NUL terminator
    Ok(out)
}

/// Encode one claim into a claim-attribute entry payload (the bytes a
/// `[entry_len]` prefix would precede), then validate it through `kacs-core`'s
/// own parser — the exact code the kernel runs — so only kernel-acceptable bytes
/// are ever accepted.
///
/// Layout (all offsets relative to the payload start):
/// `[name_off:u32][type:u16][reserved:u16=0][flags:u32][count:u32]`
/// `[value_off:u32 × count][slots…][pointer data…][name: UTF-16LE NUL-terminated]`.
/// `value_off[i]` points at value `i`'s slot. A scalar slot (INT64/UINT64/BOOLEAN)
/// holds the 8-byte LE value directly; a pointer slot (STRING/SID/OCTET) holds a
/// u32 offset to the value's bytes in the data region — STRING is UTF-16LE, SID is
/// raw SID bytes, OCTET is `[len:u32][bytes]`. Slots are uniform within a claim
/// since all its values share `value_type`.
///
/// # Safety
/// `claim` must be a valid `peios_token_claim`; `name` and each value's pointer
/// must be valid for their stated lengths.
unsafe fn encode_claim(claim: &peios_token_claim) -> Result<Vec<u8>, c_int> {
    use peios_uapi::{
        KACS_CLAIM_TYPE_BOOLEAN, KACS_CLAIM_TYPE_INT64, KACS_CLAIM_TYPE_OCTET, KACS_CLAIM_TYPE_SID,
        KACS_CLAIM_TYPE_STRING, KACS_CLAIM_TYPE_UINT64,
    };
    let oom = |_| libc::ENOMEM;

    if claim.name.is_null() {
        return Err(libc::EINVAL);
    }
    let name = utf16le_cstr(cstr_bytes(claim.name, MAX).ok_or(libc::EINVAL)?)?;

    let vt = claim.value_type as u32;
    if !matches!(
        vt,
        KACS_CLAIM_TYPE_INT64
            | KACS_CLAIM_TYPE_UINT64
            | KACS_CLAIM_TYPE_STRING
            | KACS_CLAIM_TYPE_SID
            | KACS_CLAIM_TYPE_BOOLEAN
            | KACS_CLAIM_TYPE_OCTET
    ) {
        return Err(libc::EINVAL);
    }

    let count = claim.value_count as usize;
    let values: &[peios_token_claim_value] = if count > 0 {
        if claim.values.is_null() {
            return Err(libc::EINVAL);
        }
        slice::from_raw_parts(claim.values, count)
    } else {
        &[]
    };

    // Scalars store their 8-byte value in the slot; pointer types store a u32
    // offset into a trailing data region. Slot width is uniform per claim.
    let is_scalar = matches!(
        vt,
        KACS_CLAIM_TYPE_INT64 | KACS_CLAIM_TYPE_UINT64 | KACS_CLAIM_TYPE_BOOLEAN
    );
    let slot_size = if is_scalar { 8 } else { 4 };
    let slots0 = 16 + 4 * count; // value-offset array end
    let data0 = slots0 + count * slot_size; // pointer-data region start
    let mut value_offsets: Vec<u32> = Vec::new();
    value_offsets.try_reserve(count).map_err(|_| libc::ENOMEM)?;
    let mut slots: Vec<u8> = Vec::new();
    let mut data: Vec<u8> = Vec::new();
    for (i, v) in values.iter().enumerate() {
        value_offsets.push(u32_len(slots0 + i * slot_size)?);
        if is_scalar {
            try_extend(&mut slots, &v.scalar.to_le_bytes()).map_err(oom)?;
            continue;
        }
        // Pointer types: the slot is a u32 offset to the bytes in the data region.
        if v.bytes.is_null() && v.len != 0 {
            return Err(libc::EINVAL);
        }
        let b: &[u8] = if v.bytes.is_null() {
            &[]
        } else {
            slice::from_raw_parts(v.bytes as *const u8, v.len)
        };
        try_extend(&mut slots, &u32_len(data0 + data.len())?.to_le_bytes()).map_err(oom)?;
        if vt == KACS_CLAIM_TYPE_STRING {
            let encoded = utf16le_cstr(b)?;
            try_extend(&mut data, &encoded).map_err(oom)?;
        } else if vt == KACS_CLAIM_TYPE_SID {
            if !sid_valid(b) {
                return Err(libc::EINVAL);
            }
            try_extend(&mut data, b).map_err(oom)?;
        } else {
            // OCTET: [len:u32][bytes].
            try_extend(&mut data, &u32_len(b.len())?.to_le_bytes()).map_err(oom)?;
            try_extend(&mut data, b).map_err(oom)?;
        }
    }

    let name_off = u32_len(data0 + data.len())?;
    let mut s: Vec<u8> = Vec::new();
    try_extend(&mut s, &name_off.to_le_bytes()).map_err(oom)?;
    try_extend(&mut s, &claim.value_type.to_le_bytes()).map_err(oom)?;
    try_extend(&mut s, &0u16.to_le_bytes()).map_err(oom)?; // reserved
    try_extend(&mut s, &claim.flags.to_le_bytes()).map_err(oom)?;
    try_extend(&mut s, &(count as u32).to_le_bytes()).map_err(oom)?;
    for off in &value_offsets {
        try_extend(&mut s, &off.to_le_bytes()).map_err(oom)?;
    }
    try_extend(&mut s, &slots).map_err(oom)?;
    try_extend(&mut s, &data).map_err(oom)?;
    try_extend(&mut s, &name).map_err(oom)?;

    // Gold-standard validation: the kernel decodes claims with this exact parser.
    if kacs_core::parse_claim_attribute_entry(&s).is_err() {
        return Err(libc::EINVAL);
    }
    Ok(s)
}

/// Append a claim to a section as `[entry_len:u32][payload]`, latching on error.
unsafe fn add_claim(b: &mut peios_token_builder, device: bool, claim: *const peios_token_claim) {
    if b.error != 0 {
        return;
    }
    let Some(claim) = claim.as_ref() else {
        b.latch(libc::EINVAL);
        return;
    };
    let payload = match encode_claim(claim) {
        Ok(payload) => payload,
        Err(errno) => {
            b.latch(errno);
            return;
        }
    };
    let entry_len = match u32_len(payload.len()) {
        Ok(len) => len,
        Err(errno) => {
            b.latch(errno);
            return;
        }
    };
    let section = if device {
        &mut b.device_claims
    } else {
        &mut b.user_claims
    };
    if try_extend(section, &entry_len.to_le_bytes()).is_err() || try_extend(section, &payload).is_err()
    {
        b.latch(libc::ENOMEM);
    }
}

/// `peios_token_builder_add_user_claim` — append a user claim.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_add_user_claim(
    b: *mut peios_token_builder,
    claim: *const peios_token_claim,
) {
    if let Some(b) = b.as_mut() {
        add_claim(b, false, claim);
    }
}

/// `peios_token_builder_add_device_claim` — append a device claim.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_add_device_claim(
    b: *mut peios_token_builder,
    claim: *const peios_token_claim,
) {
    if let Some(b) = b.as_mut() {
        add_claim(b, true, claim);
    }
}

/// Encode the LCS registry-credentials extension and validate it against the
/// kernel decoder's rules (non-nil & unique scope GUIDs; 1..255-byte UTF-8 layer
/// names free of `/`/`\` and case-insensitively unique).
///
/// Layout: `[version:u32=1][reserved:u32=0][scope_count:u32][layer_count:u32]`
/// `[scope GUID × 16 bytes…][name_len:u32 × layer_count][names concatenated]`.
///
/// # Safety
/// `creds` arrays must be valid for their stated counts.
unsafe fn encode_lcs(creds: &peios_token_lcs_credentials) -> Result<Vec<u8>, c_int> {
    use peios_uapi::{
        KACS_TOKEN_LCS_EXT_VERSION, KACS_TOKEN_LCS_MAX_LAYER_NAME_BYTES,
        KACS_TOKEN_LCS_MAX_PRIVATE_LAYERS, KACS_TOKEN_LCS_MAX_SCOPE_GUIDS,
    };
    let oom = |_| libc::ENOMEM;
    let scope_count = creds.scope_count as usize;
    let layer_count = creds.private_layer_count as usize;
    if scope_count > KACS_TOKEN_LCS_MAX_SCOPE_GUIDS as usize
        || layer_count > KACS_TOKEN_LCS_MAX_PRIVATE_LAYERS as usize
    {
        return Err(libc::EINVAL);
    }

    let guids: &[[u8; 16]] = if scope_count > 0 {
        if creds.scope_guids.is_null() {
            return Err(libc::EINVAL);
        }
        slice::from_raw_parts(creds.scope_guids, scope_count)
    } else {
        &[]
    };
    for (i, g) in guids.iter().enumerate() {
        if g.iter().all(|&x| x == 0) || guids[..i].contains(g) {
            return Err(libc::EINVAL); // nil or duplicate GUID
        }
    }

    let layer_ptrs: &[*const c_char] = if layer_count > 0 {
        if creds.private_layers.is_null() {
            return Err(libc::EINVAL);
        }
        slice::from_raw_parts(creds.private_layers, layer_count)
    } else {
        &[]
    };
    let max_name = KACS_TOKEN_LCS_MAX_LAYER_NAME_BYTES as usize;
    let mut names: Vec<&[u8]> = Vec::new();
    names.try_reserve(layer_count).map_err(|_| libc::ENOMEM)?;
    for &p in layer_ptrs {
        if p.is_null() {
            return Err(libc::EINVAL);
        }
        let name = cstr_bytes(p, max_name + 1).ok_or(libc::EINVAL)?;
        if name.is_empty()
            || name.len() > max_name
            || core::str::from_utf8(name).is_err()
            || name.iter().any(|&c| c == b'/' || c == b'\\')
            || names.iter().any(|m| m.eq_ignore_ascii_case(name))
        {
            return Err(libc::EINVAL);
        }
        names.push(name);
    }

    let mut ext: Vec<u8> = Vec::new();
    try_extend(&mut ext, &KACS_TOKEN_LCS_EXT_VERSION.to_le_bytes()).map_err(oom)?;
    try_extend(&mut ext, &0u32.to_le_bytes()).map_err(oom)?; // reserved
    try_extend(&mut ext, &(scope_count as u32).to_le_bytes()).map_err(oom)?;
    try_extend(&mut ext, &(layer_count as u32).to_le_bytes()).map_err(oom)?;
    for g in guids {
        try_extend(&mut ext, g).map_err(oom)?;
    }
    for name in &names {
        try_extend(&mut ext, &(name.len() as u32).to_le_bytes()).map_err(oom)?;
    }
    for name in &names {
        try_extend(&mut ext, name).map_err(oom)?;
    }
    Ok(ext)
}

/// `peios_token_builder_lcs_credentials` — set the LCS registry-credentials
/// extension (replaces any prior).
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_lcs_credentials(
    b: *mut peios_token_builder,
    creds: *const peios_token_lcs_credentials,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    let Some(creds) = creds.as_ref() else {
        b.latch(libc::EINVAL);
        return;
    };
    match encode_lcs(creds) {
        Ok(ext) => b.lcs_credentials = Some(ext),
        Err(errno) => b.latch(errno),
    }
}

// ----------------------------------------------------------------------------
// Output
// ----------------------------------------------------------------------------

/// `peios_token_builder_bytes` — serialize and borrow the spec; returns the
/// length (or -1 + errno) and sets `*out` to a pointer valid until the next
/// mutating call.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_bytes(
    b: *mut peios_token_builder,
    out: *mut *const c_void,
) -> isize {
    let set_out = |p: *const c_void| {
        if !out.is_null() {
            *out = p;
        }
    };
    let Some(b) = b.as_mut() else {
        set_out(ptr::null());
        set_errno(libc::EINVAL);
        return -1;
    };
    match b.materialize() {
        Ok(()) => {
            set_out(b.built.as_ptr() as *const c_void);
            b.built.len() as isize
        }
        Err(errno) => {
            b.latch(errno);
            set_out(ptr::null());
            set_errno(errno);
            -1
        }
    }
}

/// `peios_token_builder_create` — serialize and mint the token in one step,
/// returning the new token fd (or `-1` + errno). Forwards the materialized spec
/// to `kacs_create_token`; the sticky error is surfaced before any syscall.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_create(b: *mut peios_token_builder) -> libc::c_int {
    let Some(b) = b.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match b.materialize() {
        Ok(()) => {
            crate::token::ops::create_token_raw(b.built.as_ptr() as *const c_void, b.built.len())
        }
        Err(errno) => {
            b.latch(errno);
            set_errno(errno);
            -1
        }
    }
}

/// `peios_token_builder_error` — the latched errno, or 0 if healthy.
#[no_mangle]
pub unsafe extern "C" fn peios_token_builder_error(b: *const peios_token_builder) -> libc::c_int {
    match b.as_ref() {
        Some(b) => b.error,
        None => libc::EINVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(authority: u64, subs: &[u32]) -> Vec<u8> {
        let mut v = vec![1u8, subs.len() as u8];
        v.extend_from_slice(&authority.to_be_bytes()[2..8]);
        for s in subs {
            v.extend_from_slice(&s.to_le_bytes());
        }
        v
    }

    fn empty_dacl() -> Vec<u8> {
        // ACL_REVISION, sbz1, size=8, count=0, sbz2.
        vec![2, 0, 8, 0, 0, 0, 0, 0]
    }

    fn errno() -> libc::c_int {
        unsafe { *libc::__errno_location() }
    }

    // --- a minimal independent re-decoder for the produced spec. ---

    fn u32_at(b: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
    }
    fn u64_at(b: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
    }

    /// Decode a `[sid_len][sid][attrs]` array of `count` entries at `off`.
    fn sid_attrs_at(b: &[u8], off: usize, count: u32) -> Vec<(Vec<u8>, u32)> {
        let mut out = Vec::new();
        let mut p = off;
        for _ in 0..count {
            let sl = u32_at(b, p) as usize;
            p += 4;
            let sid = b[p..p + sl].to_vec();
            p += sl;
            let attrs = u32_at(b, p);
            p += 4;
            out.push((sid, attrs));
        }
        out
    }

    unsafe fn bytes(b: *mut peios_token_builder) -> Vec<u8> {
        let mut out = ptr::null::<c_void>();
        let n = peios_token_builder_bytes(b, &mut out);
        assert!(n > 0, "bytes failed, errno={}", errno());
        slice::from_raw_parts(out as *const u8, n as usize).to_vec()
    }

    #[test]
    fn full_spec_roundtrip() {
        unsafe {
            let b = peios_token_builder_new();
            assert!(!b.is_null());
            let user = sid(5, &[21, 1, 2, 3, 1000]);
            let g1 = sid(5, &[32, 544]);
            let g2 = sid(5, &[11]);
            let dacl = empty_dacl();

            peios_token_builder_user(b, user.as_ptr() as *const c_void, user.len());
            peios_token_builder_type(b, 1, 0); // primary
            peios_token_builder_integrity(b, 8192);
            peios_token_builder_session(b, 0x1234_5678_9abc);
            peios_token_builder_privileges(b, 0xFF, 0x0F);
            peios_token_builder_add_group(b, g1.as_ptr() as *const c_void, g1.len(), 0x7);
            peios_token_builder_add_group(b, g2.as_ptr() as *const c_void, g2.len(), 0x4);
            peios_token_builder_default_dacl(b, dacl.as_ptr() as *const c_void, dacl.len());
            let gids = [1000u32, 1001, 1002];
            peios_token_builder_supp_gids(b, gids.as_ptr(), gids.len() as c_uint);
            let flags = peios_token_flags {
                write_restricted: true,
                user_deny_only: false,
                isolation_boundary: true,
                confinement_exempt: false,
            };
            peios_token_builder_flags(b, &flags);
            assert_eq!(peios_token_builder_error(b), 0);

            let spec = bytes(b);
            assert!(spec.len() >= HEADER);
            // Header scalars.
            assert_eq!(u32_at(&spec, OFF_VERSION), VERSION);
            assert_eq!(spec[OFF_TOKEN_TYPE], 1);
            assert_eq!(u32_at(&spec, OFF_INTEGRITY_RID), 8192);
            assert_eq!(u64_at(&spec, OFF_SESSION_ID), 0x1234_5678_9abc);
            assert_eq!(u64_at(&spec, OFF_PRIVS_PRESENT), 0xFF);
            assert_eq!(u64_at(&spec, OFF_PRIVS_ENABLED), 0x0F);
            assert_eq!(spec[OFF_WRITE_RESTRICTED], 1);
            assert_eq!(spec[OFF_ISOLATION_BOUNDARY], 1);
            assert_eq!(spec[OFF_USER_DENY_ONLY], 0);

            // User SID section.
            let uoff = u32_at(&spec, OFF_USER_SID_OFFSET) as usize;
            assert!(uoff >= HEADER);
            assert_eq!(&spec[uoff..uoff + user.len()], &user[..]);

            // Groups section.
            assert_eq!(u32_at(&spec, OFF_GROUPS_COUNT), 2);
            let goff = u32_at(&spec, OFF_GROUPS_OFFSET) as usize;
            let groups = sid_attrs_at(&spec, goff, 2);
            assert_eq!(groups, vec![(g1.clone(), 0x7), (g2.clone(), 0x4)]);

            // Default DACL section.
            let doff = u32_at(&spec, OFF_DEFAULT_DACL_OFFSET) as usize;
            let dlen = u32_at(&spec, OFF_DEFAULT_DACL_LEN) as usize;
            assert_eq!(&spec[doff..doff + dlen], &dacl[..]);

            // Supp GIDs section.
            assert_eq!(u32_at(&spec, OFF_SUPP_GIDS_COUNT), 3);
            let soff = u32_at(&spec, OFF_SUPP_GIDS_OFFSET) as usize;
            for (i, want) in gids.iter().enumerate() {
                assert_eq!(u32_at(&spec, soff + i * 4), *want);
            }

            // Absent sections stay zero.
            assert_eq!(u32_at(&spec, OFF_RESTRICTED_SIDS_OFFSET), 0);
            assert_eq!(u32_at(&spec, OFF_RESTRICTED_SIDS_COUNT), 0);
            assert_eq!(u32_at(&spec, OFF_CONFINEMENT_SID_OFFSET), 0);

            peios_token_builder_free(b);
        }
    }

    #[test]
    fn empty_spec_is_just_the_header() {
        unsafe {
            let b = peios_token_builder_new();
            let spec = bytes(b);
            assert_eq!(spec.len(), HEADER);
            assert_eq!(u32_at(&spec, OFF_VERSION), VERSION);
            assert_eq!(u32_at(&spec, OFF_USER_SID_OFFSET), 0);
            assert_eq!(u32_at(&spec, OFF_GROUPS_COUNT), 0);
            peios_token_builder_free(b);
        }
    }

    #[test]
    fn invalid_sid_latches() {
        unsafe {
            let b = peios_token_builder_new();
            let bad = [1u8, 2, 3];
            peios_token_builder_user(b, bad.as_ptr() as *const c_void, bad.len());
            assert_eq!(peios_token_builder_error(b), libc::EINVAL);
            let mut out = ptr::null::<c_void>();
            assert_eq!(peios_token_builder_bytes(b, &mut out), -1);
            assert!(out.is_null());
            // reset recovers.
            peios_token_builder_reset(b);
            assert_eq!(peios_token_builder_error(b), 0);
            peios_token_builder_free(b);
        }
    }

    /// The UTF-16LE code units at `off`, up to (excluding) the NUL terminator.
    fn utf16_units(b: &[u8], off: usize) -> Vec<u16> {
        let mut out = Vec::new();
        let mut p = off;
        loop {
            let u = u16::from_le_bytes([b[p], b[p + 1]]);
            if u == 0 {
                break;
            }
            out.push(u);
            p += 2;
        }
        out
    }

    #[test]
    fn claims_roundtrip() {
        unsafe {
            let b = peios_token_builder_new();

            // A user STRING claim "Department" = "Engineering".
            let eng = b"Engineering";
            let uval = peios_token_claim_value {
                scalar: 0,
                bytes: eng.as_ptr() as *const c_void,
                len: eng.len(),
            };
            let uname = b"Department\0";
            let uclaim = peios_token_claim {
                name: uname.as_ptr() as *const c_char,
                value_type: peios_uapi::KACS_CLAIM_TYPE_STRING as u16,
                flags: 0,
                values: &uval,
                value_count: 1,
            };
            peios_token_builder_add_user_claim(b, &uclaim);

            // A device UINT64 claim "Level" = 42.
            let dval = peios_token_claim_value {
                scalar: 42,
                bytes: ptr::null(),
                len: 0,
            };
            let dname = b"Level\0";
            let dclaim = peios_token_claim {
                name: dname.as_ptr() as *const c_char,
                value_type: peios_uapi::KACS_CLAIM_TYPE_UINT64 as u16,
                flags: 0,
                values: &dval,
                value_count: 1,
            };
            peios_token_builder_add_device_claim(b, &dclaim);
            assert_eq!(peios_token_builder_error(b), 0);

            let spec = bytes(b);

            // User claims section: parses via the kernel's own parser, one claim.
            let uoff = u32_at(&spec, OFF_USER_CLAIMS_OFFSET) as usize;
            let ulen = u32_at(&spec, OFF_USER_CLAIMS_LEN) as usize;
            let usec = &spec[uoff..uoff + ulen];
            assert_eq!(
                kacs_core::parse_claim_attribute_array(usec).unwrap().len(),
                1
            );
            // Byte-decode the entry: name, and the STRING value via slot → data.
            let elen = u32_at(usec, 0) as usize;
            let s = &usec[4..4 + elen];
            let name_off = u32_at(s, 0) as usize;
            assert_eq!(u16::from_le_bytes([s[4], s[5]]) as u32, peios_uapi::KACS_CLAIM_TYPE_STRING);
            assert_eq!(u32_at(s, 12), 1); // value_count
            let slot = u32_at(s, 16) as usize; // value_offsets[0] → the slot
            let str_off = u32_at(s, slot) as usize; // pointer slot → string bytes
            assert_eq!(
                utf16_units(s, name_off),
                "Department".encode_utf16().collect::<Vec<u16>>()
            );
            assert_eq!(
                utf16_units(s, str_off),
                "Engineering".encode_utf16().collect::<Vec<u16>>()
            );

            // Device claims section: the UINT64 scalar lives in the slot directly.
            let doff = u32_at(&spec, OFF_DEVICE_CLAIMS_OFFSET) as usize;
            let dlen = u32_at(&spec, OFF_DEVICE_CLAIMS_LEN) as usize;
            let dsec = &spec[doff..doff + dlen];
            assert_eq!(
                kacs_core::parse_claim_attribute_array(dsec).unwrap().len(),
                1
            );
            let ds = &dsec[4..4 + u32_at(dsec, 0) as usize];
            let dslot = u32_at(ds, 16) as usize;
            assert_eq!(u64_at(ds, dslot), 42);

            peios_token_builder_free(b);
        }
    }

    #[test]
    fn claim_bad_name_and_sid_latch() {
        unsafe {
            // Invalid UTF-8 claim name.
            let b = peios_token_builder_new();
            let bad_name = [0xFFu8, 0xFE, 0x00];
            let claim = peios_token_claim {
                name: bad_name.as_ptr() as *const c_char,
                value_type: peios_uapi::KACS_CLAIM_TYPE_UINT64 as u16,
                flags: 0,
                values: ptr::null(),
                value_count: 0,
            };
            peios_token_builder_add_user_claim(b, &claim);
            assert_eq!(peios_token_builder_error(b), libc::EINVAL);
            peios_token_builder_free(b);

            // A SID-typed value with malformed SID bytes.
            let b = peios_token_builder_new();
            let bad_sid = [1u8, 2, 3];
            let val = peios_token_claim_value {
                scalar: 0,
                bytes: bad_sid.as_ptr() as *const c_void,
                len: bad_sid.len(),
            };
            let name = b"S\0";
            let claim = peios_token_claim {
                name: name.as_ptr() as *const c_char,
                value_type: peios_uapi::KACS_CLAIM_TYPE_SID as u16,
                flags: 0,
                values: &val,
                value_count: 1,
            };
            peios_token_builder_add_user_claim(b, &claim);
            assert_eq!(peios_token_builder_error(b), libc::EINVAL);
            peios_token_builder_free(b);
        }
    }

    #[test]
    fn lcs_credentials_roundtrip() {
        unsafe {
            let b = peios_token_builder_new();
            let guid: [u8; 16] = [
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
                0xFF, 0x01,
            ];
            let guids = [guid];
            let layer = b"mylayer\0";
            let layers = [layer.as_ptr() as *const c_char];
            let creds = peios_token_lcs_credentials {
                scope_guids: guids.as_ptr(),
                scope_count: 1,
                private_layers: layers.as_ptr(),
                private_layer_count: 1,
            };
            peios_token_builder_lcs_credentials(b, &creds);
            assert_eq!(peios_token_builder_error(b), 0);

            let spec = bytes(b);
            let lcs_off = u32_at(&spec, OFF_LCS_CREDENTIALS_OFFSET) as usize;
            assert!(lcs_off >= HEADER);
            let ext = &spec[lcs_off..]; // runs to EOF
            assert_eq!(u32_at(ext, 0), peios_uapi::KACS_TOKEN_LCS_EXT_VERSION);
            assert_eq!(u32_at(ext, 4), 0); // reserved
            assert_eq!(u32_at(ext, 8), 1); // scope_count
            assert_eq!(u32_at(ext, 12), 1); // layer_count
            assert_eq!(&ext[16..32], &guid[..]); // the GUID
            let nlen = u32_at(ext, 32) as usize;
            assert_eq!(nlen, b"mylayer".len());
            assert_eq!(&ext[36..36 + nlen], b"mylayer");
            // The extension consumes exactly to EOF (16 hdr + 16 guid + 4 len + name).
            assert_eq!(ext.len(), 36 + nlen);

            peios_token_builder_free(b);
        }
    }

    #[test]
    fn lcs_nil_guid_and_bad_name_latch() {
        unsafe {
            // A nil (all-zero) scope GUID is rejected.
            let b = peios_token_builder_new();
            let guids = [[0u8; 16]];
            let creds = peios_token_lcs_credentials {
                scope_guids: guids.as_ptr(),
                scope_count: 1,
                private_layers: ptr::null(),
                private_layer_count: 0,
            };
            peios_token_builder_lcs_credentials(b, &creds);
            assert_eq!(peios_token_builder_error(b), libc::EINVAL);
            peios_token_builder_free(b);

            // A layer name containing '/' is rejected.
            let b = peios_token_builder_new();
            let guid = [1u8; 16];
            let guids = [guid];
            let bad = b"a/b\0";
            let layers = [bad.as_ptr() as *const c_char];
            let creds = peios_token_lcs_credentials {
                scope_guids: guids.as_ptr(),
                scope_count: 1,
                private_layers: layers.as_ptr(),
                private_layer_count: 1,
            };
            peios_token_builder_lcs_credentials(b, &creds);
            assert_eq!(peios_token_builder_error(b), libc::EINVAL);
            peios_token_builder_free(b);
        }
    }
}
