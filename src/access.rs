//! `<peios/access.h>` — the KACS AccessCheck pipeline.
//!
//! [`peios_access_check`] evaluates a token against a security descriptor and a
//! desired-access mask; [`peios_access_check_list`] is the
//! object-type-result-list variant. Both are advisory — they evaluate, they do
//! not enforce. libpeios owns the versioned `kacs_access_check_args` (it stamps
//! `caller_size` and zeroes the reserved fields); the caller fills a flat
//! [`peios_access_request`]. Optional pointer/length pairs must be NULL/zero or
//! valid for the stated length/count.
//!
//! [`peios_audit_context_encode`] builds the request's audit context, the PGSS
//! §6.7 map naming the object a daemon guards, and
//! [`peios_audit_context_validate`] checks one against the kernel's rules; both
//! checks run again on the request before the syscall.
//!
//! These cross the kernel boundary (syscalls 1023 / 1024), so they are exercised
//! live under Provium; `cargo test` covers the pure arg-packing in
//! [`build_args`] and the audit-context encoder and validator.
//!
//! ## Verdict plumbing
//!
//! The scalar syscall carries its verdict in the *return value*: a non-negative
//! granted mask on grant, `-EACCES` on a clean denial, any other `-errno` on a
//! hard error. A granted mask is a `u32`, so widened to `c_long` it is always
//! non-negative and never collides with libc's `[-4095, -1]` errno window — the
//! sign of the return is an unambiguous grant/deny bit. We re-shape that into the
//! libc contract: `0` if every desired right is granted, `-1`/`EACCES` on denial.
//! The list syscall instead returns `0` and writes a per-node verdict into each
//! `kacs_node_result.status` (`0` granted, `-EACCES` denied), so it is a plain
//! pass-through.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_void};

use alloc::vec::Vec;

use peios_uapi::{
    kacs_access_check_args, kacs_generic_mapping, kacs_node_result, kacs_object_type_entry,
    KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN, KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT,
    SYS_KACS_ACCESS_CHECK, SYS_KACS_ACCESS_CHECK_LIST,
};

use crate::abi::{cstr_bytes, emit_bytes, try_extend, u32_len};
use crate::error::{get_errno, set_errno};
use crate::msgpack::peios_mp_validate;
use crate::sys::{ret_int, syscall1, syscall3};

/// `caller_size` for the version of `kacs_access_check_args` libpeios was built
/// against — the full struct, every `[adv]` field present. The kernel reads this
/// from offset 0 to know how many bytes to copy in. Tied to the uapi struct's
/// own size so it can never drift from the layout we actually send.
const ARGS_SIZE: u32 = core::mem::size_of::<kacs_access_check_args>() as u32;

// The uapi struct is the wire format verbatim (`#[repr(C)]` with explicit pad
// fields); pin its size so a uapi layout change is caught here, not in the field.
const _: () = assert!(core::mem::size_of::<kacs_access_check_args>() == 136);

fn ptr_len_valid<T>(ptr: *const T, len: usize) -> bool {
    len == 0 || !ptr.is_null()
}

fn validate_request(req: &peios_access_request, require_object_tree: bool) -> Result<(), c_int> {
    if req.sd.is_null() || req.sd_len == 0 {
        return Err(libc::EINVAL);
    }
    if !ptr_len_valid(req.self_sid, req.self_sid_len)
        || !ptr_len_valid(req.local_claims, req.local_claims_len)
        || !ptr_len_valid(req.audit_context, req.audit_context_len)
        || !ptr_len_valid(req.object_tree, req.object_tree_count as usize)
    {
        return Err(libc::EINVAL);
    }
    if require_object_tree && req.object_tree_count == 0 {
        return Err(libc::EINVAL);
    }
    // An audit context is refused here by the kernel's own rules, so a caller
    // learns of a malformed one before the syscall rather than from it. A
    // non-NULL pointer with a zero length is refused too, as the kernel does.
    if !req.audit_context.is_null() {
        if req.audit_context_len == 0 || req.audit_context_len > AUDIT_CONTEXT_MAX_LEN {
            return Err(libc::EINVAL);
        }
        // SAFETY: the caller guarantees `audit_context` is valid for its length,
        // which is bounded above.
        let bytes = unsafe {
            core::slice::from_raw_parts(req.audit_context as *const u8, req.audit_context_len)
        };
        if !audit_context_valid(bytes) {
            return Err(libc::EINVAL);
        }
    }
    Ok(())
}

/// An access-check request. Mirrors `struct peios_access_request` in
/// `<peios/access.h>` field-for-field (`#[repr(C)]`). Only the first block is
/// needed for an ordinary check; the `[adv]` tail may be left zero/NULL.
#[repr(C)]
pub struct peios_access_request {
    /// Token to check, or `-1` for the caller's effective token.
    pub token_fd: c_int,
    /// Security descriptor bytes (mandatory).
    pub sd: *const c_void,
    pub sd_len: usize,
    /// Desired access mask (may carry `MAXIMUM_ALLOWED`).
    pub desired: u32,
    /// The object class's generic-rights mapping, passed by value.
    pub mapping: kacs_generic_mapping,

    // ---- [adv] ----
    /// `PRINCIPAL_SELF` substitution SID; NULL to leave unset.
    pub self_sid: *const c_void,
    pub self_sid_len: usize,
    /// Backup/restore privilege intent bits.
    pub privilege_intent: u32,
    /// Object-type tree (mandatory for [`peios_access_check_list`]).
    pub object_tree: *const kacs_object_type_entry,
    pub object_tree_count: u32,
    /// `@Local` claim array.
    pub local_claims: *const c_void,
    pub local_claims_len: usize,
    /// Policy-information-point overrides; `0` uses the subject's PSB.
    pub pip_type: u32,
    pub pip_trust: u32,
    /// The guarded object's identity for the check's audit records: one PGSS
    /// §6.7 map, `{kind: "<k>", "<k>": {...}}`, typically from
    /// [`peios_audit_context_encode`]. NULL/0 for none.
    pub audit_context: *const c_void,
    pub audit_context_len: usize,
}

/// Audit outputs `[adv]`, filled when a non-NULL `audit` is supplied. Mirrors
/// `struct peios_access_audit`.
#[repr(C)]
pub struct peios_access_audit {
    /// OR of matching continuous-audit alarm masks.
    pub continuous_audit: u32,
    /// `1` if the staged CAAP result differs from the live verdict.
    pub staging_mismatch: c_int,
}

// ----------------------------------------------------------------------------
// Audit context (PGSS §6.7)
// ----------------------------------------------------------------------------
//
// A daemon that guards objects of its own passes the object's identity with
// its check, as one MessagePack map: `{kind: "<k>", "<k>": {<field>: ...}}`.
// The kernel copies it into its audit record as `object.kind` and
// `object.<k>.*`, and refuses any other shape with EINVAL.
//
// The pinned kacs-core predates the kernel's parser (`parse_audit_context_map`),
// so its rules are restated here rather than round-tripped through it:
//
// - the map holds a string `kind`, one PGSS §6.3 segment
//   (`[a-z][a-z0-9]*(-[a-z0-9]+)*`), and at most one other key, equal to the
//   kind, whose value is a non-empty map with segment keys;
// - nothing else, and no trailing bytes;
// - the whole buffer is well-formed MessagePack (UTF-8 strings, no 0xc1) and
//   nests no deeper than the emit limit less one, because it lands one level
//   below the record's payload root;
// - at most `KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN` bytes.
//
// [`audit_context_valid`] is exactly those rules. The encoder
// ([`peios_audit_context_encode`]) is stricter, by design: a field value is a
// scalar in one of the PGSS §6.5 wire forms (string, unsigned or signed
// integer, boolean, binary), never nil, a float or a container, and a field
// name appears once, because a repeated name would make `object.<k>.<name>`
// ambiguous.

/// Largest audit context the kernel accepts.
const AUDIT_CONTEXT_MAX_LEN: usize = KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN as usize;

/// The nesting the kernel allows an audit context: the emit limit less the one
/// level of the record's `object` map it is spliced beneath.
const AUDIT_CONTEXT_MAX_DEPTH: u32 = KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT - 1;

// `enum peios_audit_value_type` (`<peios/access.h>`): which member of a
// [`peios_audit_field`] carries its value.
const PEIOS_AUDIT_STR: u32 = 0;
const PEIOS_AUDIT_UINT: u32 = 1;
const PEIOS_AUDIT_INT: u32 = 2;
const PEIOS_AUDIT_BOOL: u32 = 3;
const PEIOS_AUDIT_BIN: u32 = 4;

/// One identifying field of an audited object. Mirrors
/// `struct peios_audit_field` in `<peios/access.h>`.
///
/// `value_type` selects the member: `PEIOS_AUDIT_UINT` reads `scalar`,
/// `PEIOS_AUDIT_INT` reads `scalar` as a two's-complement `int64_t`,
/// `PEIOS_AUDIT_BOOL` reads `scalar` as 0 or 1, and `PEIOS_AUDIT_STR` /
/// `PEIOS_AUDIT_BIN` read `bytes`/`len` (a string is UTF-8, not
/// NUL-terminated).
#[repr(C)]
pub struct peios_audit_field {
    /// The field name, NUL-terminated: one PGSS §6.3 segment.
    pub key: *const c_char,
    /// `enum peios_audit_value_type`.
    pub value_type: u32,
    pub scalar: u64,
    pub bytes: *const c_void,
    pub len: usize,
}

/// PGSS §6.3's segment grammar, `[a-z][a-z0-9]*(-[a-z0-9]+)*`.
fn is_segment(segment: &[u8]) -> bool {
    let Some((&first, rest)) = segment.split_first() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    let mut previous = first;
    for &byte in rest {
        let ok = byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || (byte == b'-' && previous != b'-');
        if !ok {
            return false;
        }
        previous = byte;
    }
    previous != b'-'
}

// ---- the structural reader (a port of the kernel's) ------------------------

fn mp_take<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(len)?;
    let chunk = bytes.get(*pos..end)?;
    *pos = end;
    Some(chunk)
}

fn mp_be(bytes: &[u8], pos: &mut usize, width: usize) -> Option<usize> {
    let mut value = 0usize;
    for &byte in mp_take(bytes, pos, width)? {
        value = value.checked_mul(256)?.checked_add(usize::from(byte))?;
    }
    Some(value)
}

fn mp_map_len(bytes: &[u8], pos: &mut usize) -> Option<usize> {
    let tag = *mp_take(bytes, pos, 1)?.first()?;
    match tag {
        0x80..=0x8f => Some(usize::from(tag & 0x0f)),
        0xde => mp_be(bytes, pos, 2),
        0xdf => mp_be(bytes, pos, 4),
        _ => None,
    }
}

fn mp_str<'a>(bytes: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let tag = *mp_take(bytes, pos, 1)?.first()?;
    let len = match tag {
        0xa0..=0xbf => usize::from(tag & 0x1f),
        0xd9 => mp_be(bytes, pos, 1)?,
        0xda => mp_be(bytes, pos, 2)?,
        0xdb => mp_be(bytes, pos, 4)?,
        _ => return None,
    };
    let value = mp_take(bytes, pos, len)?;
    core::str::from_utf8(value).ok()?;
    Some(value)
}

/// Steps over one complete value, iteratively.
fn mp_skip_value(bytes: &[u8], pos: &mut usize) -> Option<()> {
    let mut pending = 1usize;
    while pending > 0 {
        pending -= 1;
        let tag = *mp_take(bytes, pos, 1)?.first()?;
        let (skip, children) = match tag {
            0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => (0, 0),
            0x80..=0x8f => (0, usize::from(tag & 0x0f).checked_mul(2)?),
            0x90..=0x9f => (0, usize::from(tag & 0x0f)),
            0xa0..=0xbf => (usize::from(tag & 0x1f), 0),
            0xc4 | 0xd9 => (mp_be(bytes, pos, 1)?, 0),
            0xc5 | 0xda => (mp_be(bytes, pos, 2)?, 0),
            0xc6 | 0xdb => (mp_be(bytes, pos, 4)?, 0),
            0xc7 => (mp_be(bytes, pos, 1)?.checked_add(1)?, 0),
            0xc8 => (mp_be(bytes, pos, 2)?.checked_add(1)?, 0),
            0xc9 => (mp_be(bytes, pos, 4)?.checked_add(1)?, 0),
            0xca => (4, 0),
            0xcb => (8, 0),
            0xcc | 0xd0 => (1, 0),
            0xcd | 0xd1 => (2, 0),
            0xce | 0xd2 => (4, 0),
            0xcf | 0xd3 => (8, 0),
            0xd4 => (2, 0),
            0xd5 => (3, 0),
            0xd6 => (5, 0),
            0xd7 => (9, 0),
            0xd8 => (17, 0),
            0xdc => (0, mp_be(bytes, pos, 2)?),
            0xdd => (0, mp_be(bytes, pos, 4)?),
            0xde => (0, mp_be(bytes, pos, 2)?.checked_mul(2)?),
            0xdf => (0, mp_be(bytes, pos, 4)?.checked_mul(2)?),
            _ => return None,
        };
        mp_take(bytes, pos, skip)?;
        pending = pending.checked_add(children)?;
        if pending > bytes.len() - *pos {
            return None;
        }
    }
    Some(())
}

/// The body: a non-empty map whose keys are segments.
fn audit_body_valid(body: &[u8]) -> Option<()> {
    let mut pos = 0usize;
    let entries = mp_map_len(body, &mut pos)?;
    if entries == 0 {
        return None;
    }
    for _ in 0..entries {
        if !is_segment(mp_str(body, &mut pos)?) {
            return None;
        }
        mp_skip_value(body, &mut pos)?;
    }
    (pos == body.len()).then_some(())
}

/// The shape check of the kernel's `parse_audit_context_map`.
fn audit_context_shape(bytes: &[u8]) -> Option<()> {
    let mut pos = 0usize;
    let entries = mp_map_len(bytes, &mut pos)?;
    if entries == 0 || entries > 2 {
        return None;
    }
    let mut kind: Option<&[u8]> = None;
    let mut other: Option<(&[u8], &[u8])> = None;
    for _ in 0..entries {
        let key = mp_str(bytes, &mut pos)?;
        let start = pos;
        mp_skip_value(bytes, &mut pos)?;
        let value = &bytes[start..pos];
        if key == b"kind" {
            if kind.is_some() {
                return None;
            }
            let mut value_pos = 0usize;
            let kind_value = mp_str(value, &mut value_pos)?;
            if value_pos != value.len() || !is_segment(kind_value) {
                return None;
            }
            kind = Some(kind_value);
        } else {
            other = Some((key, value));
        }
    }
    if pos != bytes.len() {
        return None;
    }
    let kind = kind?;
    match other {
        None => Some(()),
        Some((key, value)) if key == kind => audit_body_valid(value),
        Some(_) => None,
    }
}

/// Whether `bytes` is an audit context the kernel accepts.
fn audit_context_valid(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.len() > AUDIT_CONTEXT_MAX_LEN {
        return false;
    }
    if audit_context_shape(bytes).is_none() {
        return false;
    }
    // SAFETY: (ptr, len) come from a live slice.
    let r = unsafe {
        peios_mp_validate(
            bytes.as_ptr() as *const c_void,
            bytes.len(),
            AUDIT_CONTEXT_MAX_DEPTH,
        )
    };
    r == 0
}

// ---- the encoder ------------------------------------------------------------

fn enc_push(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<(), c_int> {
    try_extend(buf, bytes).map_err(|()| libc::ENOMEM)
}

fn enc_map(buf: &mut Vec<u8>, n: usize) -> Result<(), c_int> {
    if n <= 15 {
        enc_push(buf, &[0x80 | n as u8])
    } else if let Ok(n) = u16::try_from(n) {
        enc_push(buf, &[0xde])?;
        enc_push(buf, &n.to_be_bytes())
    } else {
        Err(libc::EINVAL)
    }
}

/// A `str` (`bin` when `bin`), in its smallest form. Anything above 64 KiB
/// could never fit an audit context, so the 32-bit forms are not needed.
fn enc_blob(buf: &mut Vec<u8>, bytes: &[u8], bin: bool) -> Result<(), c_int> {
    let n = bytes.len();
    if !bin && n <= 31 {
        enc_push(buf, &[0xa0 | n as u8])?;
    } else if let Ok(n8) = u8::try_from(n) {
        enc_push(buf, &[if bin { 0xc4 } else { 0xd9 }, n8])?;
    } else if let Ok(n16) = u16::try_from(n) {
        enc_push(buf, &[if bin { 0xc5 } else { 0xda }])?;
        enc_push(buf, &n16.to_be_bytes())?;
    } else {
        return Err(libc::EINVAL);
    }
    enc_push(buf, bytes)
}

fn enc_uint(buf: &mut Vec<u8>, v: u64) -> Result<(), c_int> {
    if v < 0x80 {
        enc_push(buf, &[v as u8])
    } else if let Ok(v) = u8::try_from(v) {
        enc_push(buf, &[0xcc, v])
    } else if let Ok(v) = u16::try_from(v) {
        enc_push(buf, &[0xcd])?;
        enc_push(buf, &v.to_be_bytes())
    } else if let Ok(v) = u32::try_from(v) {
        enc_push(buf, &[0xce])?;
        enc_push(buf, &v.to_be_bytes())
    } else {
        enc_push(buf, &[0xcf])?;
        enc_push(buf, &v.to_be_bytes())
    }
}

fn enc_int(buf: &mut Vec<u8>, v: i64) -> Result<(), c_int> {
    if v >= 0 {
        return enc_uint(buf, v as u64);
    }
    if v >= -32 {
        enc_push(buf, &[v as u8])
    } else if let Ok(v) = i8::try_from(v) {
        enc_push(buf, &[0xd0, v as u8])
    } else if let Ok(v) = i16::try_from(v) {
        enc_push(buf, &[0xd1])?;
        enc_push(buf, &v.to_be_bytes())
    } else if let Ok(v) = i32::try_from(v) {
        enc_push(buf, &[0xd2])?;
        enc_push(buf, &v.to_be_bytes())
    } else {
        enc_push(buf, &[0xd3])?;
        enc_push(buf, &v.to_be_bytes())
    }
}

/// A NUL-terminated name that must be one segment.
///
/// # Safety
/// `ptr` must be NULL or a NUL-terminated string.
unsafe fn segment_arg<'a>(ptr: *const c_char) -> Result<&'a [u8], c_int> {
    if ptr.is_null() {
        return Err(libc::EINVAL);
    }
    match cstr_bytes(ptr, AUDIT_CONTEXT_MAX_LEN) {
        Some(name) if is_segment(name) => Ok(name),
        _ => Err(libc::EINVAL),
    }
}

/// Encode `{kind: <kind>, <kind>: {<field>: <value>, ...}}`, or `{kind: <kind>}`
/// when there are no fields, enforcing the encoder's rules.
///
/// # Safety
/// As [`peios_audit_context_encode`].
unsafe fn encode_audit_context(
    kind: *const c_char,
    fields: *const peios_audit_field,
    count: usize,
) -> Result<Vec<u8>, c_int> {
    let kind = segment_arg(kind)?;
    if count != 0 && fields.is_null() {
        return Err(libc::EINVAL);
    }
    let fields: &[peios_audit_field] = if count == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(fields, count)
    };

    let mut buf = Vec::new();
    enc_map(&mut buf, if fields.is_empty() { 1 } else { 2 })?;
    enc_blob(&mut buf, b"kind", false)?;
    enc_blob(&mut buf, kind, false)?;
    if fields.is_empty() {
        return Ok(buf);
    }
    enc_blob(&mut buf, kind, false)?;
    enc_map(&mut buf, fields.len())?;

    for (i, field) in fields.iter().enumerate() {
        let key = segment_arg(field.key)?;
        for earlier in &fields[..i] {
            if segment_arg(earlier.key)? == key {
                return Err(libc::EINVAL);
            }
        }
        enc_blob(&mut buf, key, false)?;
        match field.value_type {
            PEIOS_AUDIT_UINT => enc_uint(&mut buf, field.scalar)?,
            PEIOS_AUDIT_INT => enc_int(&mut buf, field.scalar as i64)?,
            PEIOS_AUDIT_BOOL => match field.scalar {
                0 => enc_push(&mut buf, &[0xc2])?,
                1 => enc_push(&mut buf, &[0xc3])?,
                _ => return Err(libc::EINVAL),
            },
            PEIOS_AUDIT_STR | PEIOS_AUDIT_BIN => {
                if field.bytes.is_null() && field.len != 0 {
                    return Err(libc::EINVAL);
                }
                if field.len > AUDIT_CONTEXT_MAX_LEN {
                    return Err(libc::EINVAL);
                }
                let bytes: &[u8] = if field.len == 0 {
                    &[]
                } else {
                    core::slice::from_raw_parts(field.bytes as *const u8, field.len)
                };
                let bin = field.value_type == PEIOS_AUDIT_BIN;
                if !bin && core::str::from_utf8(bytes).is_err() {
                    return Err(libc::EINVAL);
                }
                enc_blob(&mut buf, bytes, bin)?;
            }
            _ => return Err(libc::EINVAL),
        }
        if buf.len() > AUDIT_CONTEXT_MAX_LEN {
            return Err(libc::EINVAL);
        }
    }

    // What the encoder wrote must be what the kernel accepts.
    if !audit_context_valid(&buf) {
        return Err(libc::EINVAL);
    }
    Ok(buf)
}

/// `peios_audit_context_encode` — encode a PGSS §6.7 audit context naming an
/// object of kind `kind` by `fields`, getxattr-style.
///
/// Returns the encoded length, or `-1` with `errno`: `EINVAL` for anything the
/// kernel would refuse or the encoder's stricter rules forbid (see the module
/// notes above), `ENOMEM`, or the usual probe/`ERANGE` contract.
///
/// # Safety
/// `kind` must be NULL or NUL-terminated; `fields` must be NULL (with `count`
/// 0) or valid for `count` entries, each `key` NUL-terminated and each
/// `bytes` valid for `len`; `buf` must be valid for `cap` bytes when `cap != 0`.
#[no_mangle]
pub unsafe extern "C" fn peios_audit_context_encode(
    kind: *const c_char,
    fields: *const peios_audit_field,
    count: usize,
    buf: *mut c_void,
    cap: usize,
) -> isize {
    match encode_audit_context(kind, fields, count) {
        Ok(encoded) => emit_bytes(&encoded, buf as *mut u8, cap),
        Err(errno) => {
            set_errno(errno);
            -1
        }
    }
}

/// `peios_audit_context_validate` — `0` if `buf`/`len` is an audit context the
/// kernel accepts; `-1` with `EINVAL` otherwise (including NULL or empty).
///
/// # Safety
/// `buf` must be NULL or valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn peios_audit_context_validate(buf: *const c_void, len: usize) -> c_int {
    if buf.is_null() || len == 0 || len > AUDIT_CONTEXT_MAX_LEN {
        set_errno(libc::EINVAL);
        return -1;
    }
    let bytes = core::slice::from_raw_parts(buf as *const u8, len);
    if audit_context_valid(bytes) {
        0
    } else {
        set_errno(libc::EINVAL);
        -1
    }
}

/// Pack a [`peios_access_request`] into the versioned syscall args struct.
///
/// Pure and total over a validated request: copies the scalar fields, flattens
/// the by-value generic mapping into its four `u32` slots, and stamps
/// `caller_size`. The three output pointers and any caller-supplied buffers are
/// left zero for the entry point to wire up. Pointer/NULL validation lives in
/// the callers; this only guards the length narrowing.
fn build_args(req: &peios_access_request) -> Result<kacs_access_check_args, c_int> {
    Ok(kacs_access_check_args {
        caller_size: ARGS_SIZE,
        token_fd: req.token_fd,
        sd_ptr: req.sd as usize as u64,
        sd_len: u32_len(req.sd_len)?,
        desired_access: req.desired,
        mapping_read: req.mapping.read,
        mapping_write: req.mapping.write,
        mapping_execute: req.mapping.execute,
        mapping_all: req.mapping.all,
        self_sid_ptr: req.self_sid as usize as u64,
        self_sid_len: u32_len(req.self_sid_len)?,
        privilege_intent: req.privilege_intent,
        object_tree_ptr: req.object_tree as usize as u64,
        object_tree_count: req.object_tree_count,
        local_claims_ptr: req.local_claims as usize as u64,
        local_claims_len: u32_len(req.local_claims_len)?,
        pip_type: req.pip_type,
        pip_trust: req.pip_trust,
        audit_context_ptr: req.audit_context as usize as u64,
        audit_context_len: u32_len(req.audit_context_len)?,
        ..Default::default()
    })
}

/// `peios_access_check` — run the scalar AccessCheck pipeline.
///
/// Returns `0` if every desired right is granted; `-1` with `errno == EACCES` if
/// any is denied; `-1` with another `errno` on error. `granted`, if non-NULL,
/// always receives the granted mask — including on denial. `audit`, if non-NULL,
/// receives the audit outputs.
///
/// # Safety
/// `req` must point to a valid `peios_access_request` whose pointer/length pairs
/// are each NULL/zero or valid for their stated lengths. `granted`/`audit` must
/// be NULL or valid for writing.
#[no_mangle]
pub unsafe extern "C" fn peios_access_check(
    req: *const peios_access_request,
    granted: *mut u32,
    audit: *mut peios_access_audit,
) -> c_int {
    let Some(req) = req.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if let Err(errno) = validate_request(req, false) {
        set_errno(errno);
        return -1;
    }
    let mut args = match build_args(req) {
        Ok(args) => args,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };

    // The kernel writes the granted mask here on both grant and denial, so we can
    // report it uniformly regardless of the verdict.
    let mut granted_out: u32 = 0;
    args.granted_out_ptr = &mut granted_out as *mut u32 as usize as u64;
    let mut continuous_audit: u32 = 0;
    let mut staging_mismatch: u32 = 0;
    if !audit.is_null() {
        args.continuous_audit_out_ptr = &mut continuous_audit as *mut u32 as usize as u64;
        args.staging_mismatch_out_ptr = &mut staging_mismatch as *mut u32 as usize as u64;
    }

    let r = syscall1(
        SYS_KACS_ACCESS_CHECK,
        &args as *const kacs_access_check_args as usize as c_long,
    );
    if r < 0 {
        // libc set errno from the kernel's negative return. EACCES is a clean
        // denial — the kernel wrote the outputs, so surface them; any other code
        // is a hard error with the outputs left untouched.
        if get_errno() == libc::EACCES {
            copy_outputs(
                granted,
                audit,
                granted_out,
                continuous_audit,
                staging_mismatch,
            );
        }
        return -1;
    }
    copy_outputs(
        granted,
        audit,
        granted_out,
        continuous_audit,
        staging_mismatch,
    );
    0
}

/// Fan the kernel-written outputs out to the caller's optional buffers.
///
/// # Safety
/// `granted`/`audit` must be NULL or valid for writing.
#[inline]
unsafe fn copy_outputs(
    granted: *mut u32,
    audit: *mut peios_access_audit,
    granted_out: u32,
    continuous_audit: u32,
    staging_mismatch: u32,
) {
    if !granted.is_null() {
        *granted = granted_out;
    }
    if !audit.is_null() {
        (*audit).continuous_audit = continuous_audit;
        (*audit).staging_mismatch = staging_mismatch as c_int;
    }
}

/// `peios_access_check_list` — the AccessCheckByTypeResultList variant.
///
/// `req->object_tree` is mandatory and `count` must equal `object_tree_count`;
/// `results` receives one `kacs_node_result` per node (its `.status` is `0` for a
/// granted node, `-EACCES` for a denied one). Returns `0` on success, `-1` with
/// `errno` on error.
///
/// # Safety
/// `req` must point to a valid request whose pointer/length pairs are each
/// NULL/zero or valid for their stated lengths; `results` must be valid for
/// `count` `kacs_node_result` writes.
#[no_mangle]
pub unsafe extern "C" fn peios_access_check_list(
    req: *const peios_access_request,
    results: *mut kacs_node_result,
    count: u32,
) -> c_int {
    let Some(req) = req.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if let Err(errno) = validate_request(req, true) {
        set_errno(errno);
        return -1;
    }
    if count != req.object_tree_count || results.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let args = match build_args(req) {
        Ok(args) => args,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };
    ret_int(syscall3(
        SYS_KACS_ACCESS_CHECK_LIST,
        &args as *const kacs_access_check_args as usize as c_long,
        results as usize as c_long,
        count as c_long,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::get_errno;

    fn mapping() -> kacs_generic_mapping {
        kacs_generic_mapping {
            read: 0x1001,
            write: 0x1002,
            execute: 0x1004,
            all: 0x1007,
        }
    }

    /// A request over fixed byte buffers, so the packed pointers/lengths are
    /// real and checkable.
    fn request(sd: &[u8], tree: &[kacs_object_type_entry]) -> peios_access_request {
        peios_access_request {
            token_fd: -1,
            sd: sd.as_ptr() as *const c_void,
            sd_len: sd.len(),
            desired: 0x120089,
            mapping: mapping(),
            self_sid: core::ptr::null(),
            self_sid_len: 0,
            privilege_intent: 0,
            object_tree: tree.as_ptr(),
            object_tree_count: tree.len() as u32,
            local_claims: core::ptr::null(),
            local_claims_len: 0,
            pip_type: 0,
            pip_trust: 0,
            audit_context: core::ptr::null(),
            audit_context_len: 0,
        }
    }

    #[test]
    fn args_size_is_136() {
        assert_eq!(ARGS_SIZE, 136);
        assert_eq!(core::mem::size_of::<kacs_access_check_args>(), 136);
    }

    #[test]
    fn build_args_packs_fields_and_flattens_mapping() {
        let sd = [0xAAu8; 20];
        let tree = [kacs_object_type_entry::default(); 2];
        let req = request(&sd, &tree);
        let a = build_args(&req).unwrap();

        assert_eq!(a.caller_size, 136);
        assert_eq!(a.token_fd, -1);
        assert_eq!(a.sd_ptr, sd.as_ptr() as usize as u64);
        assert_eq!(a.sd_len, 20);
        assert_eq!(a.desired_access, 0x120089);
        // The by-value generic mapping is flattened into four u32 slots.
        assert_eq!(a.mapping_read, 0x1001);
        assert_eq!(a.mapping_write, 0x1002);
        assert_eq!(a.mapping_execute, 0x1004);
        assert_eq!(a.mapping_all, 0x1007);
        assert_eq!(a.object_tree_ptr, tree.as_ptr() as usize as u64);
        assert_eq!(a.object_tree_count, 2);
        // Output pointers and the reserved pads stay zero — the entry point owns them.
        assert_eq!(a.granted_out_ptr, 0);
        assert_eq!(a.continuous_audit_out_ptr, 0);
        assert_eq!(a.staging_mismatch_out_ptr, 0);
        assert_eq!(a._pad0, 0);
        assert_eq!(a._pad1, 0);
        assert_eq!(a._pad2, 0);
    }

    #[test]
    fn build_args_unset_adv_fields_are_zero() {
        let sd = [0u8; 4];
        let req = request(&sd, &[]);
        let a = build_args(&req).unwrap();
        assert_eq!(a.self_sid_ptr, 0);
        assert_eq!(a.self_sid_len, 0);
        assert_eq!(a.local_claims_ptr, 0);
        assert_eq!(a.local_claims_len, 0);
        assert_eq!(a.audit_context_ptr, 0);
        assert_eq!(a.pip_type, 0);
        assert_eq!(a.pip_trust, 0);
        // An empty object tree packs as a null/zero-count pair.
        assert_eq!(a.object_tree_count, 0);
    }

    #[test]
    fn build_args_rejects_oversized_length() {
        let sd = [0u8; 4];
        let mut req = request(&sd, &[]);
        // A length that cannot fit the wire format's u32 is a clean EINVAL.
        req.sd_len = (u32::MAX as usize) + 1;
        assert!(matches!(build_args(&req), Err(e) if e == libc::EINVAL));
    }

    #[test]
    fn access_check_rejects_null_optional_pointer_with_length() {
        let sd = [0u8; 4];
        let mut req = request(&sd, &[]);
        req.self_sid = core::ptr::null();
        req.self_sid_len = 1;

        let r = unsafe { peios_access_check(&req, core::ptr::null_mut(), core::ptr::null_mut()) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn access_check_rejects_null_object_tree_with_count() {
        let sd = [0u8; 4];
        let mut req = request(&sd, &[]);
        req.object_tree = core::ptr::null();
        req.object_tree_count = 1;

        let r = unsafe { peios_access_check(&req, core::ptr::null_mut(), core::ptr::null_mut()) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    // ---- audit context (PGSS §6.7) ------------------------------------------

    fn field(
        key: &core::ffi::CStr,
        value_type: u32,
        scalar: u64,
        bytes: &[u8],
    ) -> peios_audit_field {
        peios_audit_field {
            key: key.as_ptr(),
            value_type,
            scalar,
            bytes: if bytes.is_empty() {
                core::ptr::null()
            } else {
                bytes.as_ptr() as *const c_void
            },
            len: bytes.len(),
        }
    }

    fn str_field(key: &core::ffi::CStr, value: &str) -> peios_audit_field {
        field(key, PEIOS_AUDIT_STR, 0, value.as_bytes())
    }

    /// Encode through the C entry point's two-call path.
    fn encode(kind: &core::ffi::CStr, fields: &[peios_audit_field]) -> Result<Vec<u8>, c_int> {
        unsafe {
            let need = peios_audit_context_encode(
                kind.as_ptr(),
                fields.as_ptr(),
                fields.len(),
                core::ptr::null_mut(),
                0,
            );
            if need < 0 {
                return Err(get_errno());
            }
            let mut buf = vec![0u8; need as usize];
            let n = peios_audit_context_encode(
                kind.as_ptr(),
                fields.as_ptr(),
                fields.len(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
            );
            assert_eq!(n, need);
            Ok(buf)
        }
    }

    fn validate(bytes: &[u8]) -> bool {
        unsafe { peios_audit_context_validate(bytes.as_ptr() as *const c_void, bytes.len()) == 0 }
    }

    /// msgpack fixstr.
    fn s(text: &str) -> Vec<u8> {
        let mut v = vec![0xa0 | text.len() as u8];
        v.extend_from_slice(text.as_bytes());
        v
    }

    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn audit_context_encodes_the_service_example() {
        let bytes = encode(c"service", &[str_field(c"name", "jellyfin")]).unwrap();
        let expected = cat(&[
            &[0x82],
            &s("kind"),
            &s("service"),
            &s("service"),
            &[0x81],
            &s("name"),
            &s("jellyfin"),
        ]);
        assert_eq!(bytes, expected);
        assert!(validate(&bytes));
    }

    #[test]
    fn audit_context_without_fields_is_kind_alone() {
        let bytes = encode(c"system", &[]).unwrap();
        assert_eq!(bytes, cat(&[&[0x81], &s("kind"), &s("system")]));
        assert!(validate(&bytes));
        // A NULL field array with a zero count is the same.
        let n = unsafe {
            peios_audit_context_encode(
                c"system".as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(n as usize, bytes.len());
    }

    #[test]
    fn audit_context_encodes_every_scalar_type_in_smallest_form() {
        let bin = [0xde, 0xad];
        let fields = [
            field(c"count", PEIOS_AUDIT_UINT, 300, &[]),
            field(c"delta", PEIOS_AUDIT_INT, (-5i64) as u64, &[]),
            field(c"wide", PEIOS_AUDIT_INT, (-200i64) as u64, &[]),
            field(c"enabled", PEIOS_AUDIT_BOOL, 1, &[]),
            field(c"digest", PEIOS_AUDIT_BIN, 0, &bin),
            str_field(c"label", ""),
        ];
        let bytes = encode(c"job", &fields).unwrap();
        let expected = cat(&[
            &[0x82],
            &s("kind"),
            &s("job"),
            &s("job"),
            &[0x86],
            &s("count"),
            &[0xcd, 0x01, 0x2c],
            &s("delta"),
            &[0xfb],
            &s("wide"),
            &[0xd1, 0xff, 0x38],
            &s("enabled"),
            &[0xc3],
            &s("digest"),
            &[0xc4, 0x02, 0xde, 0xad],
            &s("label"),
            &[0xa0],
        ]);
        assert_eq!(bytes, expected);
        assert!(validate(&bytes));
    }

    #[test]
    fn audit_context_encodes_long_strings_and_many_fields() {
        let long = "x".repeat(300);
        let keys: Vec<std::ffi::CString> = (0..20)
            .map(|i| std::ffi::CString::new(format!("f{i}")).unwrap())
            .collect();
        let mut fields: Vec<peios_audit_field> = keys
            .iter()
            .map(|k| field(k, PEIOS_AUDIT_UINT, 1, &[]))
            .collect();
        fields.push(str_field(c"path", &long));
        let bytes = encode(c"event-namespace", &fields).unwrap();
        assert!(validate(&bytes));
        // 21 fields need map16; a 300-byte string needs str16.
        let body = bytes.iter().position(|&b| b == 0xde).unwrap();
        assert_eq!(&bytes[body..body + 3], &[0xde, 0x00, 21]);
        let tail = bytes.len() - 300 - 3;
        assert_eq!(&bytes[tail..tail + 3], &[0xda, 0x01, 0x2c]);
    }

    #[test]
    fn audit_context_probe_and_erange() {
        let fields = [str_field(c"name", "jellyfin")];
        let need = unsafe {
            peios_audit_context_encode(
                c"service".as_ptr(),
                fields.as_ptr(),
                1,
                core::ptr::null_mut(),
                0,
            )
        };
        assert!(need > 0);
        let mut small = vec![0u8; need as usize - 1];
        let r = unsafe {
            peios_audit_context_encode(
                c"service".as_ptr(),
                fields.as_ptr(),
                1,
                small.as_mut_ptr() as *mut c_void,
                small.len(),
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::ERANGE);
    }

    #[test]
    fn audit_context_encoder_refuses_what_the_kernel_would() {
        let name = [str_field(c"name", "x")];
        // The kind and every field name are one kebab-case segment.
        for kind in [
            c"", c"Service", c"9lives", c"a--b", c"-a", c"a-", c"a.b", c"a_b",
        ] {
            assert_eq!(encode(kind, &name), Err(libc::EINVAL), "{kind:?}");
        }
        for key in [c"", c"Name", c"na me", c"a.b"] {
            assert_eq!(
                encode(c"service", &[str_field(key, "x")]),
                Err(libc::EINVAL),
                "{key:?}"
            );
        }
        let n = unsafe {
            peios_audit_context_encode(
                core::ptr::null(),
                name.as_ptr(),
                1,
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!((n, get_errno()), (-1, libc::EINVAL));
        // NULL fields with a count; NULL bytes with a length.
        let n = unsafe {
            peios_audit_context_encode(
                c"service".as_ptr(),
                core::ptr::null(),
                1,
                core::ptr::null_mut(),
                0,
            )
        };
        assert_eq!((n, get_errno()), (-1, libc::EINVAL));
        let mut bad = str_field(c"name", "x");
        bad.bytes = core::ptr::null();
        assert_eq!(encode(c"service", &[bad]), Err(libc::EINVAL));
        // A string is UTF-8.
        let latin1 = [0xe9u8];
        assert_eq!(
            encode(c"service", &[field(c"name", PEIOS_AUDIT_STR, 0, &latin1)]),
            Err(libc::EINVAL)
        );
        // The whole context fits KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN.
        let big = "x".repeat(4096);
        assert_eq!(
            encode(c"service", &[str_field(c"name", &big)]),
            Err(libc::EINVAL)
        );
        let fits = "x".repeat(4096 - 40);
        assert!(encode(c"service", &[str_field(c"name", &fits)]).is_ok());
    }

    #[test]
    fn audit_context_encoder_is_stricter_than_the_kernel() {
        // A repeated field name would make object.<kind>.<name> ambiguous.
        let twice = [str_field(c"name", "a"), str_field(c"name", "b")];
        assert_eq!(encode(c"service", &twice), Err(libc::EINVAL));
        // Only the scalar types; a boolean is 0 or 1.
        assert_eq!(
            encode(c"service", &[field(c"name", 5, 0, &[])]),
            Err(libc::EINVAL)
        );
        assert_eq!(
            encode(c"service", &[field(c"up", PEIOS_AUDIT_BOOL, 2, &[])]),
            Err(libc::EINVAL)
        );
    }

    #[test]
    fn audit_context_validator_matches_the_kernel() {
        let kind = |k: &str| cat(&[&s("kind"), &s(k)]);
        // Accepted: kind alone, kind with its body (either order), and a body
        // the kernel takes though the encoder would not write it (nil, nested).
        assert!(validate(&cat(&[&[0x81], &kind("service")])));
        assert!(validate(&cat(&[
            &[0x82],
            &s("service"),
            &[0x81],
            &s("name"),
            &s("a"),
            &kind("service")
        ])));
        assert!(validate(&cat(&[
            &[0x82],
            &kind("service"),
            &s("service"),
            &[0x81],
            &s("name"),
            &[0xc0]
        ])));
        assert!(validate(&cat(&[
            &[0x82],
            &kind("service"),
            &s("service"),
            &[0x81],
            &s("ids"),
            &[0x91, 0x01]
        ])));
        // Refused.
        let refused: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x80],                                                   // empty map
            vec![0xc0],                                                   // not a map
            cat(&[&[0x81], &s("kind"), &[0x01]]),                         // kind not a string
            cat(&[&[0x81], &kind("Service")]),                            // kind not a segment
            cat(&[&[0x82], &kind("a"), &kind("a")]),                      // kind twice
            cat(&[&[0x81], &s("service"), &[0x81], &s("name"), &s("a")]), // no kind
            cat(&[
                &[0x82],
                &kind("service"),
                &s("job"),
                &[0x81],
                &s("name"),
                &s("a"),
            ]), // body under another key
            cat(&[&[0x82], &kind("service"), &s("service"), &[0x80]]),    // empty body
            cat(&[&[0x82], &kind("service"), &s("service"), &s("x")]),    // body not a map
            cat(&[
                &[0x82],
                &kind("service"),
                &s("service"),
                &[0x81],
                &s("Name"),
                &s("a"),
            ]), // body key not a segment
            cat(&[
                &[0x83],
                &kind("service"),
                &s("service"),
                &[0x81],
                &s("n"),
                &s("a"),
                &s("x"),
                &[0x01],
            ]), // a third key
            cat(&[&[0x81], &kind("service"), &[0x00]]),                   // trailing bytes
            cat(&[
                &[0x82],
                &kind("service"),
                &s("service"),
                &[0x81],
                &s("n"),
                &[0xa1, 0xff],
            ]), // non-UTF-8 value
            cat(&[
                &[0x82],
                &kind("service"),
                &s("service"),
                &[0x81],
                &s("n"),
                &[0xc1],
            ]), // reserved byte
        ];
        for bytes in &refused {
            assert!(!validate(bytes), "{bytes:02x?}");
        }
        let n = unsafe { peios_audit_context_validate(core::ptr::null(), 0) };
        assert_eq!((n, get_errno()), (-1, libc::EINVAL));
    }

    #[test]
    fn audit_context_validator_bounds_nesting_one_below_the_emit_limit() {
        // The top map and the body are two containers; a value of `arrays`
        // nested arrays brings the total to 2 + arrays. The kernel allows
        // KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT - 1 = 31 levels, so 28 arrays.
        let nested = |arrays: usize| {
            let mut v = cat(&[&[0x82], &s("kind"), &s("k"), &s("k"), &[0x81], &s("v")]);
            v.extend(std::iter::repeat_n(0x91, arrays));
            v.push(0x01);
            v
        };
        assert!(validate(&nested(28)));
        assert!(!validate(&nested(29)));
    }

    #[test]
    fn audit_context_validator_bounds_the_length() {
        let pad = |n: usize| {
            let mut v = cat(&[
                &[0x82],
                &s("kind"),
                &s("k"),
                &s("k"),
                &[0x81],
                &s("v"),
                &[0xc5],
            ]);
            let header = v.len() + 2;
            let body = n - header;
            v.extend_from_slice(&(body as u16).to_be_bytes());
            v.extend(std::iter::repeat_n(0u8, body));
            v
        };
        assert!(validate(&pad(4096)));
        assert!(!validate(&pad(4097)));
    }

    #[test]
    fn access_check_refuses_a_malformed_audit_context_before_the_syscall() {
        let sd = [0u8; 4];
        let mut req = request(&sd, &[]);
        let not_a_map = [0xc0u8];
        req.audit_context = not_a_map.as_ptr() as *const c_void;
        req.audit_context_len = not_a_map.len();
        let r = unsafe { peios_access_check(&req, core::ptr::null_mut(), core::ptr::null_mut()) };
        assert_eq!((r, get_errno()), (-1, libc::EINVAL));

        // A non-NULL pointer with no length is refused, as the kernel refuses it.
        req.audit_context_len = 0;
        let r = unsafe { peios_access_check(&req, core::ptr::null_mut(), core::ptr::null_mut()) };
        assert_eq!((r, get_errno()), (-1, libc::EINVAL));

        let tree = [kacs_object_type_entry::default()];
        let mut req = request(&sd, &tree);
        req.audit_context = not_a_map.as_ptr() as *const c_void;
        req.audit_context_len = not_a_map.len();
        let mut results = [kacs_node_result {
            granted: 0,
            status: 0,
        }];
        let r = unsafe { peios_access_check_list(&req, results.as_mut_ptr(), 1) };
        assert_eq!((r, get_errno()), (-1, libc::EINVAL));
    }

    #[test]
    fn build_args_carries_an_audit_context() {
        let sd = [0u8; 4];
        let ctx = encode(c"service", &[str_field(c"name", "jellyfin")]).unwrap();
        let mut req = request(&sd, &[]);
        req.audit_context = ctx.as_ptr() as *const c_void;
        req.audit_context_len = ctx.len();
        assert!(validate_request(&req, false).is_ok());
        let a = build_args(&req).unwrap();
        assert_eq!(a.audit_context_ptr, ctx.as_ptr() as usize as u64);
        assert_eq!(a.audit_context_len as usize, ctx.len());
    }
}
