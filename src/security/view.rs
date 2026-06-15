//! Zero-copy parse views — `peios_sd_*` / `peios_acl_*` / `peios_ace_*`
//! (`<peios/security.h>`).
//!
//! A view borrows the caller's buffer; the C side stack-allocates the opaque
//! `peios_*_view` storage and we record, inside it, just the `(ptr, len)` of the
//! sub-slice this view spans. Every accessor re-derives the kacs-core type from
//! that slice on demand. Re-parsing per call trades a few microseconds (security
//! descriptors are bounded to 64 KiB and usually well under a kilobyte) for two
//! properties worth far more: the opaque storage carries no borrowed lifetime to
//! smuggle through `extern "C"`, and `parse` validates the whole structure up
//! front — including every ACE — so the accessors are total and never surface a
//! mid-walk error to C.
#![allow(non_camel_case_types)]

use core::ffi::{c_int, c_uint, c_void};
use core::slice;

use kacs_core::{Ace, AceKind, Acl, SecurityDescriptor};

use super::sid_valid;
use crate::error::set_errno;

// ----------------------------------------------------------------------------
// Opaque view storage
// ----------------------------------------------------------------------------

/// What actually lives in the opaque `_opaque[N]` storage: the borrowed slice.
#[repr(C)]
#[derive(Clone, Copy)]
struct SliceView {
    ptr: *const u8,
    len: usize,
}

/// `peios_sd_view` — opaque, 64 bytes (matches `<peios/security.h>`).
#[repr(C)]
#[allow(dead_code)] // storage is accessed via pointer reinterpretation, not by field.
pub struct peios_sd_view {
    pub(crate) _opaque: [u64; 8],
}

/// `peios_acl_view` — opaque, 32 bytes.
#[repr(C)]
#[allow(dead_code)]
pub struct peios_acl_view {
    pub(crate) _opaque: [u64; 4],
}

/// `peios_ace_view` — opaque, 32 bytes.
#[repr(C)]
#[allow(dead_code)]
pub struct peios_ace_view {
    pub(crate) _opaque: [u64; 4],
}

/// `peios_sid_array_view` — opaque, 32 bytes.
#[repr(C)]
#[allow(dead_code)]
pub struct peios_sid_array_view {
    pub(crate) _opaque: [u64; 4],
}

const _: () = assert!(core::mem::size_of::<peios_sd_view>() == 64);
const _: () = assert!(core::mem::size_of::<peios_acl_view>() == 32);
const _: () = assert!(core::mem::size_of::<peios_ace_view>() == 32);
const _: () = assert!(core::mem::size_of::<peios_sid_array_view>() == 32);
// Every view must have room for the borrowed slice, at its natural alignment.
const _: () = assert!(core::mem::size_of::<SliceView>() <= 32);
const _: () = assert!(core::mem::align_of::<SliceView>() <= 8);

/// Record `s`'s `(ptr, len)` into a view's opaque storage.
///
/// # Safety
/// `view` must point at storage of at least `size_of::<SliceView>()` bytes,
/// 8-aligned (every `peios_*_view` is).
unsafe fn store(view: *mut c_void, s: &[u8]) {
    (view as *mut SliceView).write(SliceView {
        ptr: s.as_ptr(),
        len: s.len(),
    });
}

/// Recover the slice recorded by [`store`].
///
/// # Safety
/// `view` must have been populated by a successful parse and the borrowed buffer
/// must still be alive and unmodified.
unsafe fn load<'a>(view: *const c_void) -> &'a [u8] {
    let sv = (view as *const SliceView).read();
    slice::from_raw_parts(sv.ptr, sv.len)
}

/// Write a `(ptr, len)` pair back through two optional out-params, in the
/// convention shared by the SID-yielding accessors.
unsafe fn yield_slice(s: &[u8], out: *mut *const c_void, len: *mut usize) {
    if !out.is_null() {
        *out = s.as_ptr() as *const c_void;
    }
    if !len.is_null() {
        *len = s.len();
    }
}

/// Every ACE in `acl` parses cleanly. An empty ACL (a present-but-empty DACL) is
/// vacuously valid.
fn acl_fully_valid(acl: &Acl) -> bool {
    acl.entries().all(|entry| entry.is_ok())
}

// ----------------------------------------------------------------------------
// Security descriptor
// ----------------------------------------------------------------------------

/// `peios_sd_parse` — validate a self-relative SD and populate `out`.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_parse(
    sd: *const c_void,
    len: usize,
    out: *mut peios_sd_view,
) -> c_int {
    if sd.is_null() || out.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let bytes = slice::from_raw_parts(sd as *const u8, len);
    let parsed = match SecurityDescriptor::parse(bytes) {
        Ok(parsed) => parsed,
        Err(_) => {
            set_errno(libc::EINVAL);
            return -1;
        }
    };
    // Validate the ACLs eagerly so the view accessors are infallible.
    let acls_ok = parsed.dacl().is_none_or(|d| acl_fully_valid(&d))
        && parsed.sacl().is_none_or(|s| acl_fully_valid(&s));
    if !acls_ok {
        set_errno(libc::EINVAL);
        return -1;
    }
    store(out as *mut c_void, parsed.bytes());
    0
}

/// `peios_sd_view_control` — the SD control word.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_view_control(v: *const peios_sd_view) -> u16 {
    SecurityDescriptor::parse(load(v as *const c_void))
        .map(|sd| sd.control())
        .unwrap_or(0)
}

/// `peios_sd_view_owner` — the owner SID, or `-1` if absent.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_view_owner(
    v: *const peios_sd_view,
    sid: *mut *const c_void,
    len: *mut usize,
) -> c_int {
    match SecurityDescriptor::parse(load(v as *const c_void)).ok().and_then(|sd| {
        sd.owner().map(|o| {
            let b = o.as_bytes();
            (b.as_ptr(), b.len())
        })
    }) {
        Some((ptr, n)) => {
            yield_slice(slice::from_raw_parts(ptr, n), sid, len);
            0
        }
        None => -1,
    }
}

/// `peios_sd_view_group` — the primary-group SID, or `-1` if absent.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_view_group(
    v: *const peios_sd_view,
    sid: *mut *const c_void,
    len: *mut usize,
) -> c_int {
    match SecurityDescriptor::parse(load(v as *const c_void)).ok().and_then(|sd| {
        sd.group().map(|g| {
            let b = g.as_bytes();
            (b.as_ptr(), b.len())
        })
    }) {
        Some((ptr, n)) => {
            yield_slice(slice::from_raw_parts(ptr, n), sid, len);
            0
        }
        None => -1,
    }
}

/// `peios_sd_view_dacl` — the DACL, or `-1` if absent or NULL.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_view_dacl(
    v: *const peios_sd_view,
    out: *mut peios_acl_view,
) -> c_int {
    sd_acl(v, out, |sd| sd.dacl())
}

/// `peios_sd_view_sacl` — the SACL, or `-1` if absent.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_view_sacl(
    v: *const peios_sd_view,
    out: *mut peios_acl_view,
) -> c_int {
    sd_acl(v, out, |sd| sd.sacl())
}

/// Shared body of the DACL/SACL accessors.
unsafe fn sd_acl(
    v: *const peios_sd_view,
    out: *mut peios_acl_view,
    pick: impl for<'a> Fn(&SecurityDescriptor<'a>) -> Option<Acl<'a>>,
) -> c_int {
    if out.is_null() {
        return -1;
    }
    let sd = match SecurityDescriptor::parse(load(v as *const c_void)) {
        Ok(sd) => sd,
        Err(_) => return -1,
    };
    match pick(&sd) {
        Some(acl) => {
            store(out as *mut c_void, acl.bytes());
            0
        }
        None => -1,
    }
}

// ----------------------------------------------------------------------------
// ACL
// ----------------------------------------------------------------------------

/// `peios_acl_parse` — validate a bare ACL and populate `out`.
#[no_mangle]
pub unsafe extern "C" fn peios_acl_parse(
    acl: *const c_void,
    len: usize,
    out: *mut peios_acl_view,
) -> c_int {
    if acl.is_null() || out.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let bytes = slice::from_raw_parts(acl as *const u8, len);
    let parsed = match Acl::parse(bytes) {
        Ok(parsed) if acl_fully_valid(&parsed) => parsed,
        _ => {
            set_errno(libc::EINVAL);
            return -1;
        }
    };
    store(out as *mut c_void, parsed.bytes());
    0
}

/// `peios_acl_view_count` — the number of ACEs.
#[no_mangle]
pub unsafe extern "C" fn peios_acl_view_count(a: *const peios_acl_view) -> c_uint {
    Acl::parse(load(a as *const c_void))
        .map(|acl| c_uint::from(acl.ace_count()))
        .unwrap_or(0)
}

/// `peios_acl_view_ace` — populate `out` for ACE `i`, or `-1` (`ERANGE`).
#[no_mangle]
pub unsafe extern "C" fn peios_acl_view_ace(
    a: *const peios_acl_view,
    i: c_uint,
    out: *mut peios_ace_view,
) -> c_int {
    if out.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let acl = match Acl::parse(load(a as *const c_void)) {
        Ok(acl) => acl,
        Err(_) => {
            set_errno(libc::EINVAL);
            return -1;
        }
    };
    match acl.entries().nth(i as usize) {
        Some(Ok(ace)) => {
            store(out as *mut c_void, ace.bytes());
            0
        }
        _ => {
            set_errno(libc::ERANGE);
            -1
        }
    }
}

// ----------------------------------------------------------------------------
// ACE
// ----------------------------------------------------------------------------

/// Parse the ACE recorded in a view; `None` only on the (validated-away) error.
unsafe fn ace_of<'a>(e: *const peios_ace_view) -> Option<Ace<'a>> {
    Ace::parse(load(e as *const c_void)).ok()
}

/// `peios_ace_view_type` — the ACE type byte.
#[no_mangle]
pub unsafe extern "C" fn peios_ace_view_type(e: *const peios_ace_view) -> u8 {
    ace_of(e).map(|a| a.ace_type()).unwrap_or(0)
}

/// `peios_ace_view_flags` — the ACE flags byte.
#[no_mangle]
pub unsafe extern "C" fn peios_ace_view_flags(e: *const peios_ace_view) -> u8 {
    ace_of(e).map(|a| a.ace_flags()).unwrap_or(0)
}

/// `peios_ace_view_mask` — the access mask (0 for an opaque ACE).
#[no_mangle]
pub unsafe extern "C" fn peios_ace_view_mask(e: *const peios_ace_view) -> u32 {
    match ace_of(e).map(|a| a.kind()) {
        Some(
            AceKind::SingleSid { mask, .. }
            | AceKind::Object { mask, .. }
            | AceKind::Callback { mask, .. }
            | AceKind::CallbackObject { mask, .. }
            | AceKind::ResourceAttribute { mask, .. },
        ) => mask,
        _ => 0,
    }
}

/// `peios_ace_view_sid` — the trustee SID, or `-1` for an opaque ACE.
#[no_mangle]
pub unsafe extern "C" fn peios_ace_view_sid(
    e: *const peios_ace_view,
    sid: *mut *const c_void,
    len: *mut usize,
) -> c_int {
    let kind = match ace_of(e) {
        Some(ace) => ace.kind(),
        None => return -1,
    };
    let trustee = match kind {
        AceKind::SingleSid { sid: s, .. }
        | AceKind::Object { sid: s, .. }
        | AceKind::Callback { sid: s, .. }
        | AceKind::CallbackObject { sid: s, .. }
        | AceKind::ResourceAttribute { sid: s, .. } => s,
        AceKind::Opaque => return -1,
    };
    yield_slice(trustee.as_bytes(), sid, len);
    0
}

/// `peios_ace_view_object_type` — the object-type GUID, or `-1` if absent.
#[no_mangle]
pub unsafe extern "C" fn peios_ace_view_object_type(
    e: *const peios_ace_view,
    guid16: *mut *const u8,
) -> c_int {
    object_guid(e, guid16, |kind| match kind {
        AceKind::Object {
            object_type, ..
        }
        | AceKind::CallbackObject {
            object_type, ..
        } => object_type,
        _ => None,
    })
}

/// `peios_ace_view_inherited_object_type` — the inherited object-type GUID.
#[no_mangle]
pub unsafe extern "C" fn peios_ace_view_inherited_object_type(
    e: *const peios_ace_view,
    guid16: *mut *const u8,
) -> c_int {
    object_guid(e, guid16, |kind| match kind {
        AceKind::Object {
            inherited_object_type,
            ..
        }
        | AceKind::CallbackObject {
            inherited_object_type,
            ..
        } => inherited_object_type,
        _ => None,
    })
}

/// Shared body of the two object-GUID accessors.
unsafe fn object_guid(
    e: *const peios_ace_view,
    guid16: *mut *const u8,
    pick: impl for<'a> Fn(AceKind<'a>) -> Option<&'a [u8; 16]>,
) -> c_int {
    match ace_of(e).and_then(|ace| pick(ace.kind())) {
        Some(guid) => {
            if !guid16.is_null() {
                *guid16 = guid.as_ptr();
            }
            0
        }
        None => -1,
    }
}

/// `peios_ace_view_app_data` — trailing callback / resource-attribute data.
#[no_mangle]
pub unsafe extern "C" fn peios_ace_view_app_data(
    e: *const peios_ace_view,
    data: *mut *const c_void,
    len: *mut usize,
) -> c_int {
    let kind = match ace_of(e) {
        Some(ace) => ace.kind(),
        None => return -1,
    };
    let app = match kind {
        AceKind::Callback {
            application_data, ..
        }
        | AceKind::CallbackObject {
            application_data, ..
        }
        | AceKind::ResourceAttribute {
            application_data, ..
        } => application_data,
        _ => return -1,
    };
    yield_slice(app, data, len);
    0
}

// ----------------------------------------------------------------------------
// SID-and-attributes arrays
// ----------------------------------------------------------------------------

/// The entry count from a sid-array blob (0 if truncated).
fn sid_array_count_of(blob: &[u8]) -> u32 {
    if blob.len() < 4 {
        0
    } else {
        u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]])
    }
}

/// Validate a `[count][sid_len][sid][attrs]…` blob: every entry is in bounds,
/// every SID is structurally valid, and the entries consume the buffer exactly.
fn sid_array_valid(blob: &[u8]) -> bool {
    if blob.len() < 4 {
        return false;
    }
    let mut off = 4usize;
    for _ in 0..sid_array_count_of(blob) {
        if off + 4 > blob.len() {
            return false;
        }
        let sid_len =
            u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]) as usize;
        off += 4;
        let Some(end) = off.checked_add(sid_len) else {
            return false;
        };
        if end > blob.len() || !sid_valid(&blob[off..end]) {
            return false;
        }
        off = end;
        if off + 4 > blob.len() {
            return false;
        }
        off += 4;
    }
    off == blob.len()
}

/// `peios_sid_array_parse` — validate a SID-and-attributes blob, populate `out`.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_array_parse(
    blob: *const c_void,
    len: usize,
    out: *mut peios_sid_array_view,
) -> c_int {
    if blob.is_null() || out.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let bytes = slice::from_raw_parts(blob as *const u8, len);
    if !sid_array_valid(bytes) {
        set_errno(libc::EINVAL);
        return -1;
    }
    store(out as *mut c_void, bytes);
    0
}

/// `peios_sid_array_count` — the number of entries.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_array_count(a: *const peios_sid_array_view) -> c_uint {
    sid_array_count_of(load(a as *const c_void))
}

/// `peios_sid_array_get` — the SID, length, and attributes of entry `i`.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_array_get(
    a: *const peios_sid_array_view,
    i: c_uint,
    sid: *mut *const c_void,
    len: *mut usize,
    attrs: *mut u32,
) -> c_int {
    let blob = load(a as *const c_void);
    if i >= sid_array_count_of(blob) {
        set_errno(libc::ERANGE);
        return -1;
    }
    // Validated at parse, so the walk stays in bounds.
    let mut off = 4usize;
    for _ in 0..i {
        let sid_len =
            u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]) as usize;
        off += 4 + sid_len + 4;
    }
    let sid_len =
        u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]) as usize;
    off += 4;
    let entry = &blob[off..off + sid_len];
    off += sid_len;
    let entry_attrs = u32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]);
    yield_slice(entry, sid, len);
    if !attrs.is_null() {
        *attrs = entry_attrs;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    // --- hand-built MS-DTYP fixtures (independent of the not-yet-built encoders).

    fn sid(authority: u64, subs: &[u32]) -> Vec<u8> {
        let mut v = vec![1u8, subs.len() as u8];
        v.extend_from_slice(&authority.to_be_bytes()[2..8]);
        for s in subs {
            v.extend_from_slice(&s.to_le_bytes());
        }
        v
    }

    fn allow_ace(trustee: &[u8], mask: u32) -> Vec<u8> {
        let size = 8 + trustee.len();
        let mut v = vec![0u8, 0]; // ACCESS_ALLOWED_ACE_TYPE, no flags
        v.extend_from_slice(&(size as u16).to_le_bytes());
        v.extend_from_slice(&mask.to_le_bytes());
        v.extend_from_slice(trustee);
        v
    }

    fn acl(aces: &[Vec<u8>]) -> Vec<u8> {
        let body: usize = aces.iter().map(Vec::len).sum();
        let mut v = vec![2u8, 0]; // ACL_REVISION, sbz1
        v.extend_from_slice(&((8 + body) as u16).to_le_bytes());
        v.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        v.extend_from_slice(&[0, 0]); // sbz2
        for a in aces {
            v.extend_from_slice(a);
        }
        v
    }

    /// Self-relative SD with components laid out after the 20-byte header.
    fn sd(owner: Option<&[u8]>, group: Option<&[u8]>, dacl: Option<&[u8]>, control: u16) -> Vec<u8> {
        let base = 20u32;
        let mut body = Vec::new();
        let mut place = |opt: Option<&[u8]>| -> u32 {
            match opt {
                Some(c) => {
                    let off = base + body.len() as u32;
                    body.extend_from_slice(c);
                    off
                }
                None => 0,
            }
        };
        let off_owner = place(owner);
        let off_group = place(group);
        let off_dacl = place(dacl);

        let mut v = vec![1u8, 0]; // revision, sbz1
        v.extend_from_slice(&(control | 0x8000).to_le_bytes()); // SE_SELF_RELATIVE
        v.extend_from_slice(&off_owner.to_le_bytes());
        v.extend_from_slice(&off_group.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // sacl
        v.extend_from_slice(&off_dacl.to_le_bytes());
        v.extend_from_slice(&body);
        v
    }

    fn errno() -> c_int {
        unsafe { *libc::__errno_location() }
    }

    unsafe fn read(ptr: *const c_void, len: usize) -> Vec<u8> {
        slice::from_raw_parts(ptr as *const u8, len).to_vec()
    }

    #[test]
    fn sd_views_roundtrip() {
        unsafe {
            let owner = sid(5, &[18]);
            let group = sid(5, &[11]);
            let trustee = sid(5, &[32, 544]);
            let dacl = acl(&[allow_ace(&trustee, 0x1F01FF)]);
            let buf = sd(Some(&owner), Some(&group), Some(&dacl), 0x0004); // DACL_PRESENT

            let mut v = peios_sd_view { _opaque: [0; 8] };
            assert_eq!(peios_sd_parse(buf.as_ptr() as *const c_void, buf.len(), &mut v), 0);
            assert_eq!(peios_sd_view_control(&v) & 0x8000, 0x8000);

            let (mut p, mut l) = (ptr::null::<c_void>(), 0usize);
            assert_eq!(peios_sd_view_owner(&v, &mut p, &mut l), 0);
            assert_eq!(read(p, l), owner);
            assert_eq!(peios_sd_view_group(&v, &mut p, &mut l), 0);
            assert_eq!(read(p, l), group);

            let mut av = peios_acl_view { _opaque: [0; 4] };
            assert_eq!(peios_sd_view_dacl(&v, &mut av), 0);
            assert_eq!(peios_acl_view_count(&av), 1);
            // No SACL present.
            let mut sv = peios_acl_view { _opaque: [0; 4] };
            assert_eq!(peios_sd_view_sacl(&v, &mut sv), -1);

            let mut ev = peios_ace_view { _opaque: [0; 4] };
            assert_eq!(peios_acl_view_ace(&av, 0, &mut ev), 0);
            assert_eq!(peios_ace_view_type(&ev), 0);
            assert_eq!(peios_ace_view_flags(&ev), 0);
            assert_eq!(peios_ace_view_mask(&ev), 0x1F01FF);
            let (mut sp, mut sl) = (ptr::null::<c_void>(), 0usize);
            assert_eq!(peios_ace_view_sid(&ev, &mut sp, &mut sl), 0);
            assert_eq!(read(sp, sl), trustee);

            // A plain allow ACE has no object GUID or app data.
            let mut guid = ptr::null::<u8>();
            assert_eq!(peios_ace_view_object_type(&ev, &mut guid), -1);
            assert_eq!(peios_ace_view_app_data(&ev, &mut sp, &mut sl), -1);

            // Out-of-range ACE index.
            assert_eq!(peios_acl_view_ace(&av, 1, &mut ev), -1);
            assert_eq!(errno(), libc::ERANGE);
        }
    }

    #[test]
    fn absent_components() {
        unsafe {
            let owner = sid(5, &[18]);
            let buf = sd(Some(&owner), None, None, 0);
            let mut v = peios_sd_view { _opaque: [0; 8] };
            assert_eq!(peios_sd_parse(buf.as_ptr() as *const c_void, buf.len(), &mut v), 0);

            let (mut p, mut l) = (ptr::null::<c_void>(), 0usize);
            assert_eq!(peios_sd_view_owner(&v, &mut p, &mut l), 0);
            assert_eq!(peios_sd_view_group(&v, &mut p, &mut l), -1);
            let mut av = peios_acl_view { _opaque: [0; 4] };
            assert_eq!(peios_sd_view_dacl(&v, &mut av), -1);
        }
    }

    #[test]
    fn bare_acl_parse_and_malformed() {
        unsafe {
            let trustee = sid(5, &[11]);
            let bytes = acl(&[allow_ace(&trustee, 0x120089)]);
            let mut av = peios_acl_view { _opaque: [0; 4] };
            assert_eq!(peios_acl_parse(bytes.as_ptr() as *const c_void, bytes.len(), &mut av), 0);
            assert_eq!(peios_acl_view_count(&av), 1);

            // Truncated ACL header.
            assert_eq!(peios_acl_parse(bytes.as_ptr() as *const c_void, 4, &mut av), -1);
            assert_eq!(errno(), libc::EINVAL);
            // NULL out.
            assert_eq!(
                peios_acl_parse(bytes.as_ptr() as *const c_void, bytes.len(), ptr::null_mut()),
                -1
            );
        }
    }

    #[test]
    fn malformed_sd_rejected() {
        unsafe {
            let mut v = peios_sd_view { _opaque: [0; 8] };
            // A DACL claiming an ACE that runs off the end must fail validation.
            let bad_ace = {
                let mut a = vec![0u8, 0];
                a.extend_from_slice(&64u16.to_le_bytes()); // ace_size 64, but body is short
                a.extend_from_slice(&0u32.to_le_bytes());
                a.extend_from_slice(&sid(5, &[18]));
                a
            };
            let dacl = acl(&[bad_ace]);
            let buf = sd(None, None, Some(&dacl), 0x0004);
            assert_eq!(peios_sd_parse(buf.as_ptr() as *const c_void, buf.len(), &mut v), -1);
            assert_eq!(errno(), libc::EINVAL);
        }
    }

    /// Build a `[count][sid_len][sid][attrs]…` blob.
    fn sid_array(entries: &[(&[u8], u32)]) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (s, attrs) in entries {
            blob.extend_from_slice(&(s.len() as u32).to_le_bytes());
            blob.extend_from_slice(s);
            blob.extend_from_slice(&attrs.to_le_bytes());
        }
        blob
    }

    #[test]
    fn sid_array_roundtrip() {
        unsafe {
            let s1 = sid(5, &[18]);
            let s2 = sid(5, &[32, 544]);
            let blob = sid_array(&[(&s1, 0x7), (&s2, 0xC000_0000)]);

            let mut v = peios_sid_array_view { _opaque: [0; 4] };
            assert_eq!(peios_sid_array_parse(blob.as_ptr() as *const c_void, blob.len(), &mut v), 0);
            assert_eq!(peios_sid_array_count(&v), 2);

            let (mut p, mut l, mut at) = (ptr::null::<c_void>(), 0usize, 0u32);
            assert_eq!(peios_sid_array_get(&v, 0, &mut p, &mut l, &mut at), 0);
            assert_eq!(read(p, l), s1);
            assert_eq!(at, 0x7);
            assert_eq!(peios_sid_array_get(&v, 1, &mut p, &mut l, &mut at), 0);
            assert_eq!(read(p, l), s2);
            assert_eq!(at, 0xC000_0000);

            assert_eq!(peios_sid_array_get(&v, 2, &mut p, &mut l, &mut at), -1);
            assert_eq!(errno(), libc::ERANGE);
        }
    }

    #[test]
    fn sid_array_empty_and_malformed() {
        unsafe {
            let mut v = peios_sid_array_view { _opaque: [0; 4] };
            // A well-formed zero-entry array.
            let empty = sid_array(&[]);
            assert_eq!(peios_sid_array_parse(empty.as_ptr() as *const c_void, empty.len(), &mut v), 0);
            assert_eq!(peios_sid_array_count(&v), 0);
            // count=1 but the SID runs off the end.
            let bad = {
                let mut b = 1u32.to_le_bytes().to_vec();
                b.extend_from_slice(&12u32.to_le_bytes()); // sid_len 12, no sid follows
                b
            };
            assert_eq!(peios_sid_array_parse(bad.as_ptr() as *const c_void, bad.len(), &mut v), -1);
            assert_eq!(errno(), libc::EINVAL);
            // Trailing slop after the declared entries.
            let mut slop = sid_array(&[(&sid(5, &[11]), 0)]);
            slop.push(0xAB);
            assert_eq!(peios_sid_array_parse(slop.as_ptr() as *const c_void, slop.len(), &mut v), -1);
        }
    }
}
