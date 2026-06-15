//! Security-descriptor builder — `peios_sd_builder_*` (`<peios/security.h>`).
//!
//! Same heap-backed, sticky-error shape as the ACL builder. Owner/group SIDs and
//! the DACL/SACL are each validated as they are set (a bad SID or a malformed
//! ACL latches immediately), the builder owns `SE_SELF_RELATIVE` and the
//! DACL/SACL `PRESENT` control bits, and the finished buffer is round-tripped
//! through `kacs_core::SecurityDescriptor::parse` before it is handed out.
#![allow(non_camel_case_types)]

use core::ffi::c_void;
use core::ptr;
use core::slice;

use alloc::vec::Vec;

use kacs_core::SecurityDescriptor;

use crate::abi::{emit_bytes, raw_free, raw_new, to_vec, try_extend};
use crate::error::set_errno;
use crate::security::{acl_valid, sid_valid};

const SELF_RELATIVE: u16 = peios_uapi::KACS_SD_SELF_RELATIVE as u16;
const DACL_PRESENT: u16 = peios_uapi::KACS_SD_DACL_PRESENT as u16;
const SACL_PRESENT: u16 = peios_uapi::KACS_SD_SACL_PRESENT as u16;
const MANAGED_CONTROL: u16 = SELF_RELATIVE | DACL_PRESENT | SACL_PRESENT;

const SD_HEADER: usize = peios_uapi::KACS_SD_HEADER_BYTES as usize; // 20
const SD_MAX: usize = 65535;

/// `peios_sd_builder` — opaque, heap-allocated.
pub struct peios_sd_builder {
    owner: Option<Vec<u8>>,
    group: Option<Vec<u8>>,
    /// The DACL ACL bytes, when a present DACL was set. KACS has no NULL-DACL
    /// (`DACL_PRESENT` + null pointer) encoding — its parser rejects
    /// `DACL_PRESENT` with offset 0 — so the "grant everyone" intent of
    /// `dacl_null()` is represented as an *absent* DACL (`DACL_PRESENT` clear),
    /// which is the only grant-all form the kernel accepts.
    dacl: Option<Vec<u8>>,
    sacl: Option<Vec<u8>>,
    /// Caller-supplied control bits (the managed bits are masked out at build).
    control_user: u16,
    error: libc::c_int,
    built: Vec<u8>,
}

impl peios_sd_builder {
    fn new() -> Self {
        Self {
            owner: None,
            group: None,
            dacl: None,
            sacl: None,
            control_user: 0,
            error: 0,
            built: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.owner = None;
        self.group = None;
        self.dacl = None;
        self.sacl = None;
        self.control_user = 0;
        self.error = 0;
        self.built.clear();
    }

    fn latch(&mut self, errno: libc::c_int) {
        if self.error == 0 {
            self.error = errno;
        }
    }

    /// Validate `bytes` with `check`, copy it, and hand the owned Vec to `set`.
    fn set_component(
        &mut self,
        bytes: &[u8],
        check: impl Fn(&[u8]) -> bool,
        set: impl FnOnce(&mut Self, Vec<u8>),
    ) {
        if self.error != 0 {
            return;
        }
        if !check(bytes) {
            self.latch(libc::EINVAL);
            return;
        }
        match to_vec(bytes) {
            Ok(v) => set(self, v),
            Err(()) => self.latch(libc::ENOMEM),
        }
    }

    fn materialize(&mut self) -> Result<(), libc::c_int> {
        if self.error != 0 {
            return Err(self.error);
        }
        let oom = |_| libc::ENOMEM;

        let mut control = self.control_user & !MANAGED_CONTROL;
        control |= SELF_RELATIVE;
        if self.dacl.is_some() {
            control |= DACL_PRESENT;
        }
        if self.sacl.is_some() {
            control |= SACL_PRESENT;
        }

        // Lay the components out after the header; offset 0 means absent.
        let base = SD_HEADER as u32;
        let mut body: Vec<u8> = Vec::new();
        let place = |body: &mut Vec<u8>, bytes: &[u8]| -> Result<u32, libc::c_int> {
            let off = base + body.len() as u32;
            try_extend(body, bytes).map_err(oom)?;
            Ok(off)
        };
        let off_owner = match &self.owner {
            Some(o) => place(&mut body, o)?,
            None => 0,
        };
        let off_group = match &self.group {
            Some(g) => place(&mut body, g)?,
            None => 0,
        };
        let off_sacl = match &self.sacl {
            Some(s) => place(&mut body, s)?,
            None => 0,
        };
        let off_dacl = match &self.dacl {
            Some(d) => place(&mut body, d)?,
            None => 0,
        };

        if SD_HEADER + body.len() > SD_MAX {
            return Err(libc::EINVAL);
        }

        self.built.clear();
        try_extend(&mut self.built, &[1, 0]).map_err(oom)?; // revision, sbz1
        try_extend(&mut self.built, &control.to_le_bytes()).map_err(oom)?;
        try_extend(&mut self.built, &off_owner.to_le_bytes()).map_err(oom)?;
        try_extend(&mut self.built, &off_group.to_le_bytes()).map_err(oom)?;
        try_extend(&mut self.built, &off_sacl.to_le_bytes()).map_err(oom)?;
        try_extend(&mut self.built, &off_dacl.to_le_bytes()).map_err(oom)?;
        try_extend(&mut self.built, &body).map_err(oom)?;

        // Belt-and-suspenders: the assembled SD must parse.
        if SecurityDescriptor::parse(&self.built).is_err() {
            return Err(libc::EINVAL);
        }
        Ok(())
    }
}

// ----------------------------------------------------------------------------
// Lifecycle
// ----------------------------------------------------------------------------

/// `peios_sd_builder_new` — allocate a builder, or NULL on OOM.
#[no_mangle]
pub extern "C" fn peios_sd_builder_new() -> *mut peios_sd_builder {
    unsafe { raw_new(peios_sd_builder::new()) }
}

/// `peios_sd_builder_free` — destroy a builder (NULL-safe).
#[no_mangle]
pub unsafe extern "C" fn peios_sd_builder_free(b: *mut peios_sd_builder) {
    raw_free(b);
}

/// `peios_sd_builder_reset` — clear all components and the sticky error.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_builder_reset(b: *mut peios_sd_builder) {
    if let Some(b) = b.as_mut() {
        b.reset();
    }
}

// ----------------------------------------------------------------------------
// Components
// ----------------------------------------------------------------------------

unsafe fn as_slice<'a>(ptr: *const c_void, len: usize) -> Option<&'a [u8]> {
    (!ptr.is_null()).then(|| slice::from_raw_parts(ptr as *const u8, len))
}

/// `peios_sd_builder_owner` — set the owner SID.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_builder_owner(
    b: *mut peios_sd_builder,
    sid: *const c_void,
    len: usize,
) {
    let Some(b) = b.as_mut() else { return };
    match as_slice(sid, len) {
        Some(s) => b.set_component(s, sid_valid, |b, v| b.owner = Some(v)),
        None => b.latch(libc::EINVAL),
    }
}

/// `peios_sd_builder_group` — set the primary-group SID.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_builder_group(
    b: *mut peios_sd_builder,
    sid: *const c_void,
    len: usize,
) {
    let Some(b) = b.as_mut() else { return };
    match as_slice(sid, len) {
        Some(s) => b.set_component(s, sid_valid, |b, v| b.group = Some(v)),
        None => b.latch(libc::EINVAL),
    }
}

/// `peios_sd_builder_control` — set/clear caller-controllable control bits.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_builder_control(b: *mut peios_sd_builder, set: u16, clear: u16) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    b.control_user = (b.control_user | set) & !clear;
}

/// `peios_sd_builder_dacl` — set a present DACL from ACL bytes.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_builder_dacl(
    b: *mut peios_sd_builder,
    acl: *const c_void,
    len: usize,
) {
    let Some(b) = b.as_mut() else { return };
    match as_slice(acl, len) {
        Some(a) => b.set_component(a, acl_valid, |b, v| b.dacl = Some(v)),
        None => b.latch(libc::EINVAL),
    }
}

/// `peios_sd_builder_dacl_null` — request a grant-everyone DACL.
///
/// KACS has no NULL-DACL (`DACL_PRESENT` + null pointer) encoding, so this clears
/// any previously set DACL: the built SD leaves `DACL_PRESENT` clear, which is
/// KACS's grant-all form.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_builder_dacl_null(b: *mut peios_sd_builder) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    b.dacl = None;
}

/// `peios_sd_builder_sacl` — set the SACL from ACL bytes.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_builder_sacl(
    b: *mut peios_sd_builder,
    acl: *const c_void,
    len: usize,
) {
    let Some(b) = b.as_mut() else { return };
    match as_slice(acl, len) {
        Some(a) => b.set_component(a, acl_valid, |b, v| b.sacl = Some(v)),
        None => b.latch(libc::EINVAL),
    }
}

// ----------------------------------------------------------------------------
// Output
// ----------------------------------------------------------------------------

/// `peios_sd_builder_bytes` — borrow the serialized SD (NULL if errored).
#[no_mangle]
pub unsafe extern "C" fn peios_sd_builder_bytes(
    b: *mut peios_sd_builder,
    len_out: *mut usize,
) -> *const c_void {
    let set_len = |n: usize| {
        if !len_out.is_null() {
            *len_out = n;
        }
    };
    let Some(b) = b.as_mut() else {
        set_len(0);
        return ptr::null();
    };
    match b.materialize() {
        Ok(()) => {
            set_len(b.built.len());
            b.built.as_ptr() as *const c_void
        }
        Err(errno) => {
            b.latch(errno);
            set_len(0);
            ptr::null()
        }
    }
}

/// `peios_sd_builder_finish` — copy the serialized SD out, getxattr-style.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_builder_finish(
    b: *mut peios_sd_builder,
    buf: *mut c_void,
    cap: usize,
) -> isize {
    let Some(b) = b.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match b.materialize() {
        Ok(()) => emit_bytes(&b.built, buf as *mut u8, cap),
        Err(errno) => {
            b.latch(errno);
            set_errno(errno);
            -1
        }
    }
}

/// `peios_sd_builder_error` — the latched errno, or 0 if healthy.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_builder_error(b: *const peios_sd_builder) -> libc::c_int {
    match b.as_ref() {
        Some(b) => b.error,
        None => libc::EINVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::view::{
        peios_acl_view, peios_sd_parse, peios_sd_view, peios_sd_view_control, peios_sd_view_dacl,
        peios_sd_view_group, peios_sd_view_owner,
    };
    use core::ptr;

    fn sid(authority: u64, subs: &[u32]) -> Vec<u8> {
        let mut v = vec![1u8, subs.len() as u8];
        v.extend_from_slice(&authority.to_be_bytes()[2..8]);
        for s in subs {
            v.extend_from_slice(&s.to_le_bytes());
        }
        v
    }

    /// A minimal one-ACE DACL (ACCESS_ALLOWED for `trustee`).
    fn dacl_for(trustee: &[u8]) -> Vec<u8> {
        let ace_size = 8 + trustee.len();
        let mut ace = vec![0u8, 0];
        ace.extend_from_slice(&(ace_size as u16).to_le_bytes());
        ace.extend_from_slice(&0x1F01FFu32.to_le_bytes());
        ace.extend_from_slice(trustee);
        let mut acl = vec![2u8, 0];
        acl.extend_from_slice(&((8 + ace.len()) as u16).to_le_bytes());
        acl.extend_from_slice(&1u16.to_le_bytes());
        acl.extend_from_slice(&[0, 0]);
        acl.extend_from_slice(&ace);
        acl
    }

    fn errno() -> libc::c_int {
        unsafe { *libc::__errno_location() }
    }

    unsafe fn finish(b: *mut peios_sd_builder) -> Vec<u8> {
        let need = peios_sd_builder_finish(b, ptr::null_mut(), 0);
        assert!(need > 0, "finish probe failed, errno={}", errno());
        let mut v = vec![0u8; need as usize];
        assert_eq!(peios_sd_builder_finish(b, v.as_mut_ptr() as *mut c_void, v.len()), need);
        v
    }

    unsafe fn read(ptr: *const c_void, len: usize) -> Vec<u8> {
        slice::from_raw_parts(ptr as *const u8, len).to_vec()
    }

    #[test]
    fn full_sd_roundtrip() {
        unsafe {
            let owner = sid(5, &[18]);
            let group = sid(5, &[11]);
            let trustee = sid(5, &[32, 544]);
            let dacl = dacl_for(&trustee);

            let b = peios_sd_builder_new();
            assert!(!b.is_null());
            peios_sd_builder_owner(b, owner.as_ptr() as *const c_void, owner.len());
            peios_sd_builder_group(b, group.as_ptr() as *const c_void, group.len());
            peios_sd_builder_dacl(b, dacl.as_ptr() as *const c_void, dacl.len());
            peios_sd_builder_control(b, 0x1000, 0); // DACL_PROTECTED
            assert_eq!(peios_sd_builder_error(b), 0);

            let sd = finish(b);
            let mut v = peios_sd_view { _opaque: [0; 8] };
            assert_eq!(peios_sd_parse(sd.as_ptr() as *const c_void, sd.len(), &mut v), 0);

            let control = peios_sd_view_control(&v);
            assert_eq!(control & SELF_RELATIVE, SELF_RELATIVE);
            assert_eq!(control & DACL_PRESENT, DACL_PRESENT);
            assert_eq!(control & 0x1000, 0x1000); // user-set DACL_PROTECTED preserved

            let (mut p, mut l) = (ptr::null::<c_void>(), 0usize);
            assert_eq!(peios_sd_view_owner(&v, &mut p, &mut l), 0);
            assert_eq!(read(p, l), owner);
            assert_eq!(peios_sd_view_group(&v, &mut p, &mut l), 0);
            assert_eq!(read(p, l), group);
            let mut av = peios_acl_view { _opaque: [0; 4] };
            assert_eq!(peios_sd_view_dacl(&v, &mut av), 0);

            peios_sd_builder_free(b);
        }
    }

    #[test]
    fn dacl_null_is_grant_all_absent() {
        unsafe {
            let b = peios_sd_builder_new();
            peios_sd_builder_dacl_null(b);
            let sd = finish(b);
            let mut v = peios_sd_view { _opaque: [0; 8] };
            assert_eq!(peios_sd_parse(sd.as_ptr() as *const c_void, sd.len(), &mut v), 0);
            // KACS rejects the NULL-DACL form, so grant-all is an absent DACL.
            assert_eq!(peios_sd_view_control(&v) & DACL_PRESENT, 0);
            let mut av = peios_acl_view { _opaque: [0; 4] };
            assert_eq!(peios_sd_view_dacl(&v, &mut av), -1);
            peios_sd_builder_free(b);
        }
    }

    #[test]
    fn dacl_null_clears_a_prior_dacl() {
        unsafe {
            let b = peios_sd_builder_new();
            let dacl = dacl_for(&sid(5, &[32, 544]));
            peios_sd_builder_dacl(b, dacl.as_ptr() as *const c_void, dacl.len());
            peios_sd_builder_dacl_null(b); // last call wins -> grant all
            let sd = finish(b);
            let mut v = peios_sd_view { _opaque: [0; 8] };
            assert_eq!(peios_sd_parse(sd.as_ptr() as *const c_void, sd.len(), &mut v), 0);
            assert_eq!(peios_sd_view_control(&v) & DACL_PRESENT, 0);
            peios_sd_builder_free(b);
        }
    }

    #[test]
    fn empty_sd_is_valid() {
        unsafe {
            let b = peios_sd_builder_new();
            let sd = finish(b);
            assert_eq!(sd.len(), SD_HEADER);
            let mut v = peios_sd_view { _opaque: [0; 8] };
            assert_eq!(peios_sd_parse(sd.as_ptr() as *const c_void, sd.len(), &mut v), 0);
            assert_eq!(peios_sd_view_control(&v) & DACL_PRESENT, 0);
            peios_sd_builder_free(b);
        }
    }

    #[test]
    fn invalid_owner_latches() {
        unsafe {
            let b = peios_sd_builder_new();
            let bad = [1u8, 2, 3]; // too short to be a SID
            peios_sd_builder_owner(b, bad.as_ptr() as *const c_void, bad.len());
            assert_eq!(peios_sd_builder_error(b), libc::EINVAL);
            let mut len = 9usize;
            assert!(peios_sd_builder_bytes(b, &mut len).is_null());
            assert_eq!(len, 0);
            peios_sd_builder_free(b);
        }
    }

    #[test]
    fn malformed_dacl_latches() {
        unsafe {
            let b = peios_sd_builder_new();
            let bad_acl = [2u8, 0, 0, 0]; // truncated ACL header
            peios_sd_builder_dacl(b, bad_acl.as_ptr() as *const c_void, bad_acl.len());
            assert_eq!(peios_sd_builder_error(b), libc::EINVAL);
            peios_sd_builder_free(b);
        }
    }
}
