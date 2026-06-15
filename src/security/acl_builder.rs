//! ACL builder — `peios_acl_builder_*` (`<peios/security.h>`).
//!
//! A heap-backed, sticky-error encoder. The `void` adders never fail inline: the
//! first problem latches an errno, every later add is a no-op, and the error
//! surfaces at `_error()` or when the bytes are taken. Each ACE is assembled into
//! a scratch buffer and then *round-tripped through `kacs_core::Ace::parse`*
//! before it is accepted — so a built ACL is valid by construction (bad SID, bad
//! mask, malformed object/claim payloads are all rejected here, exactly as the
//! kernel would reject them), and the ACL revision is raised to whatever the
//! richest ACE requires.
#![allow(non_camel_case_types)]

use core::ffi::c_void;
use core::ptr;
use core::slice;

use alloc::vec::Vec;

use kacs_core::{
    minimum_acl_revision_for_ace_type, Ace, Acl, ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_OBJECT_ACE_TYPE, ACCESS_DENIED_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
    ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACL_REVISION,
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_ALARM_OBJECT_ACE_TYPE,
    SYSTEM_AUDIT_ACE_TYPE, SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE, SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE,
};

use crate::abi::{emit_bytes, raw_free, raw_new, try_extend};
use crate::error::{errno_for, set_errno};

/// `struct peios_ace_spec` — the general ACE description (`<peios/security.h>`).
#[repr(C)]
pub struct peios_ace_spec {
    pub type_: u8,
    pub flags: u8,
    pub mask: u32,
    pub sid: *const c_void,
    pub sid_len: usize,
    pub object_type: *const u8,
    pub inherited_object_type: *const u8,
    pub app_data: *const c_void,
    pub app_data_len: usize,
}

/// `peios_acl_builder` — opaque, heap-allocated.
#[allow(non_camel_case_types)]
pub struct peios_acl_builder {
    /// Concatenated ACE bytes (the ACL body).
    aces: Vec<u8>,
    /// Number of accumulated ACEs (bounded to `u16`).
    count: u32,
    /// Running maximum required ACL revision.
    revision: u8,
    /// Sticky errno; 0 while healthy.
    error: libc::c_int,
    /// Scratch for the materialized ACL, kept so `_bytes()` can hand out a
    /// pointer that stays valid until the next mutating call.
    built: Vec<u8>,
}

/// True for the object ACE families (those carrying an object-flags word and
/// optional GUIDs before the SID).
fn is_object_ace(ace_type: u8) -> bool {
    matches!(
        ace_type,
        ACCESS_ALLOWED_OBJECT_ACE_TYPE
            | ACCESS_DENIED_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_OBJECT_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
            | SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
    )
}

impl peios_acl_builder {
    fn new() -> Self {
        Self {
            aces: Vec::new(),
            count: 0,
            revision: ACL_REVISION,
            error: 0,
            built: Vec::new(),
        }
    }

    fn reset(&mut self) {
        self.aces.clear();
        self.built.clear();
        self.count = 0;
        self.revision = ACL_REVISION;
        self.error = 0;
    }

    fn latch(&mut self, errno: libc::c_int) {
        if self.error == 0 {
            self.error = errno;
        }
    }

    /// Encode, validate, and append one ACE; latch on the first failure.
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        ace_type: u8,
        flags: u8,
        mask: u32,
        sid: &[u8],
        object_type: Option<&[u8; 16]>,
        inherited_object_type: Option<&[u8; 16]>,
        app_data: &[u8],
    ) {
        if self.error != 0 {
            return;
        }
        if let Err(errno) =
            self.encode(ace_type, flags, mask, sid, object_type, inherited_object_type, app_data)
        {
            self.latch(errno);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn encode(
        &mut self,
        ace_type: u8,
        flags: u8,
        mask: u32,
        sid: &[u8],
        object_type: Option<&[u8; 16]>,
        inherited_object_type: Option<&[u8; 16]>,
        app_data: &[u8],
    ) -> Result<(), libc::c_int> {
        let mut ace: Vec<u8> = Vec::new();
        let oom = |_| libc::ENOMEM;

        // Header: type, flags, size placeholder, mask.
        try_extend(&mut ace, &[ace_type, flags, 0, 0]).map_err(oom)?;
        try_extend(&mut ace, &mask.to_le_bytes()).map_err(oom)?;

        if is_object_ace(ace_type) {
            let mut object_flags = 0u32;
            if object_type.is_some() {
                object_flags |= ACE_OBJECT_TYPE_PRESENT;
            }
            if inherited_object_type.is_some() {
                object_flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
            }
            try_extend(&mut ace, &object_flags.to_le_bytes()).map_err(oom)?;
            if let Some(guid) = object_type {
                try_extend(&mut ace, guid).map_err(oom)?;
            }
            if let Some(guid) = inherited_object_type {
                try_extend(&mut ace, guid).map_err(oom)?;
            }
        }

        try_extend(&mut ace, sid).map_err(oom)?;
        try_extend(&mut ace, app_data).map_err(oom)?;

        // Patch in the encoded size; ACE sizes are u16 and 4-aligned.
        let size = ace.len();
        if size > u16::MAX as usize || size % 4 != 0 {
            return Err(libc::EINVAL);
        }
        ace[2..4].copy_from_slice(&(size as u16).to_le_bytes());

        // Reject anything the kernel's own parser would reject.
        Ace::parse(&ace).map_err(|e| errno_for(&e))?;

        // ACL-level bounds: count and total size are both u16 fields.
        if self.count >= u16::MAX as u32 {
            return Err(libc::EINVAL);
        }
        if Acl::HEADER_SIZE + self.aces.len() + ace.len() > u16::MAX as usize {
            return Err(libc::EINVAL);
        }

        try_extend(&mut self.aces, &ace).map_err(oom)?;
        self.count += 1;
        self.revision = self.revision.max(minimum_acl_revision_for_ace_type(ace_type));
        Ok(())
    }

    /// Render the full ACL (header + body) into `self.built`.
    fn materialize(&mut self) -> Result<(), libc::c_int> {
        if self.error != 0 {
            return Err(self.error);
        }
        let total = Acl::HEADER_SIZE + self.aces.len();
        if total > u16::MAX as usize {
            return Err(libc::EINVAL);
        }
        let oom = |_| libc::ENOMEM;
        self.built.clear();
        try_extend(&mut self.built, &[self.revision, 0]).map_err(oom)?;
        try_extend(&mut self.built, &(total as u16).to_le_bytes()).map_err(oom)?;
        try_extend(&mut self.built, &(self.count as u16).to_le_bytes()).map_err(oom)?;
        try_extend(&mut self.built, &[0u8, 0]).map_err(oom)?; // sbz2
        try_extend(&mut self.built, &self.aces).map_err(oom)?;
        Ok(())
    }
}

/// Build an integrity-label SID `S-1-16-<rid>` on the stack (12 bytes).
fn integrity_sid(rid: u32) -> [u8; 12] {
    let mut sid = [0u8; 12];
    sid[0] = 1; // revision
    sid[1] = 1; // one sub-authority
    sid[2..8].copy_from_slice(&16u64.to_be_bytes()[2..8]); // authority 16, big-endian
    sid[8..12].copy_from_slice(&rid.to_le_bytes());
    sid
}

/// View a trustee SID pointer/len as a slice (`None` if NULL).
unsafe fn sid_slice<'a>(sid: *const c_void, len: usize) -> Option<&'a [u8]> {
    (!sid.is_null()).then(|| slice::from_raw_parts(sid as *const u8, len))
}

/// View a 16-byte GUID pointer (`None` if NULL).
unsafe fn guid_opt<'a>(p: *const u8) -> Option<&'a [u8; 16]> {
    (!p.is_null()).then(|| &*(p as *const [u8; 16]))
}

// ----------------------------------------------------------------------------
// Lifecycle
// ----------------------------------------------------------------------------

/// `peios_acl_builder_new` — allocate a builder, or NULL on OOM.
#[no_mangle]
pub extern "C" fn peios_acl_builder_new() -> *mut peios_acl_builder {
    unsafe { raw_new(peios_acl_builder::new()) }
}

/// `peios_acl_builder_free` — destroy a builder (NULL-safe).
#[no_mangle]
pub unsafe extern "C" fn peios_acl_builder_free(b: *mut peios_acl_builder) {
    raw_free(b);
}

/// `peios_acl_builder_reset` — drop accumulated ACEs and clear the sticky error.
#[no_mangle]
pub unsafe extern "C" fn peios_acl_builder_reset(b: *mut peios_acl_builder) {
    if let Some(b) = b.as_mut() {
        b.reset();
    }
}

// ----------------------------------------------------------------------------
// Adders
// ----------------------------------------------------------------------------

/// Shared body of the single-SID convenience adders.
unsafe fn add_single(
    b: *mut peios_acl_builder,
    ace_type: u8,
    flags: u8,
    mask: u32,
    sid: *const c_void,
    len: usize,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    match sid_slice(sid, len) {
        Some(sid) => b.add(ace_type, flags, mask, sid, None, None, &[]),
        None => b.latch(libc::EINVAL),
    }
}

/// `peios_acl_builder_allow` — append an access-allowed ACE.
#[no_mangle]
pub unsafe extern "C" fn peios_acl_builder_allow(
    b: *mut peios_acl_builder,
    sid: *const c_void,
    len: usize,
    mask: u32,
    flags: u8,
) {
    add_single(b, ACCESS_ALLOWED_ACE_TYPE, flags, mask, sid, len);
}

/// `peios_acl_builder_deny` — append an access-denied ACE.
#[no_mangle]
pub unsafe extern "C" fn peios_acl_builder_deny(
    b: *mut peios_acl_builder,
    sid: *const c_void,
    len: usize,
    mask: u32,
    flags: u8,
) {
    add_single(b, ACCESS_DENIED_ACE_TYPE, flags, mask, sid, len);
}

/// `peios_acl_builder_audit` — append a system-audit ACE.
#[no_mangle]
pub unsafe extern "C" fn peios_acl_builder_audit(
    b: *mut peios_acl_builder,
    sid: *const c_void,
    len: usize,
    mask: u32,
    flags: u8,
) {
    add_single(b, SYSTEM_AUDIT_ACE_TYPE, flags, mask, sid, len);
}

/// `peios_acl_builder_label` — append a mandatory-label ACE for `S-1-16-<rid>`.
#[no_mangle]
pub unsafe extern "C" fn peios_acl_builder_label(
    b: *mut peios_acl_builder,
    integrity_rid: u32,
    policy_mask: u32,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    let sid = integrity_sid(integrity_rid);
    b.add(SYSTEM_MANDATORY_LABEL_ACE_TYPE, 0, policy_mask, &sid, None, None, &[]);
}

/// `peios_acl_builder_add` — append an arbitrary ACE from a spec.
#[no_mangle]
pub unsafe extern "C" fn peios_acl_builder_add(
    b: *mut peios_acl_builder,
    ace: *const peios_ace_spec,
) {
    let Some(b) = b.as_mut() else { return };
    if b.error != 0 {
        return;
    }
    let Some(spec) = ace.as_ref() else {
        b.latch(libc::EINVAL);
        return;
    };
    let Some(sid) = sid_slice(spec.sid, spec.sid_len) else {
        b.latch(libc::EINVAL);
        return;
    };
    let app_data = if spec.app_data.is_null() || spec.app_data_len == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(spec.app_data as *const u8, spec.app_data_len)
    };
    b.add(
        spec.type_,
        spec.flags,
        spec.mask,
        sid,
        guid_opt(spec.object_type),
        guid_opt(spec.inherited_object_type),
        app_data,
    );
}

// ----------------------------------------------------------------------------
// Output
// ----------------------------------------------------------------------------

/// `peios_acl_builder_bytes` — borrow the serialized ACL (NULL if errored).
#[no_mangle]
pub unsafe extern "C" fn peios_acl_builder_bytes(
    b: *mut peios_acl_builder,
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

/// `peios_acl_builder_finish` — copy the serialized ACL out, getxattr-style.
#[no_mangle]
pub unsafe extern "C" fn peios_acl_builder_finish(
    b: *mut peios_acl_builder,
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

/// `peios_acl_builder_error` — the latched errno, or 0 if healthy.
#[no_mangle]
pub unsafe extern "C" fn peios_acl_builder_error(b: *const peios_acl_builder) -> libc::c_int {
    match b.as_ref() {
        Some(b) => b.error,
        None => libc::EINVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::view::{
        peios_acl_parse, peios_acl_view, peios_acl_view_ace, peios_acl_view_count, peios_ace_view,
        peios_ace_view_mask, peios_ace_view_sid, peios_ace_view_type,
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

    fn errno() -> libc::c_int {
        unsafe { *libc::__errno_location() }
    }

    /// Materialize a builder into an owned Vec via the getxattr two-call path.
    unsafe fn finish(b: *mut peios_acl_builder) -> Vec<u8> {
        let need = peios_acl_builder_finish(b, ptr::null_mut(), 0);
        assert!(need > 0, "finish probe failed, errno={}", errno());
        let mut v = vec![0u8; need as usize];
        assert_eq!(peios_acl_builder_finish(b, v.as_mut_ptr() as *mut c_void, v.len()), need);
        v
    }

    unsafe fn parse_view(acl: &[u8]) -> peios_acl_view {
        let mut av = peios_acl_view { _opaque: [0; 4] };
        assert_eq!(peios_acl_parse(acl.as_ptr() as *const c_void, acl.len(), &mut av), 0);
        av
    }

    #[test]
    fn allow_deny_roundtrip() {
        unsafe {
            let b = peios_acl_builder_new();
            assert!(!b.is_null());
            let admins = sid(5, &[32, 544]);
            let users = sid(5, &[11]);
            // Deny first (canonical order), then allow.
            peios_acl_builder_deny(b, users.as_ptr() as *const c_void, users.len(), 0x10000, 0);
            peios_acl_builder_allow(b, admins.as_ptr() as *const c_void, admins.len(), 0x1F01FF, 0);
            assert_eq!(peios_acl_builder_error(b), 0);

            let acl = finish(b);
            assert_eq!(acl[0], ACL_REVISION); // basic ACEs -> revision 2
            let av = parse_view(&acl);
            assert_eq!(peios_acl_view_count(&av), 2);

            let mut ev = peios_ace_view { _opaque: [0; 4] };
            assert_eq!(peios_acl_view_ace(&av, 0, &mut ev), 0);
            assert_eq!(peios_ace_view_type(&ev), ACCESS_DENIED_ACE_TYPE);
            assert_eq!(peios_ace_view_mask(&ev), 0x10000);
            let (mut p, mut l) = (ptr::null::<c_void>(), 0usize);
            assert_eq!(peios_ace_view_sid(&ev, &mut p, &mut l), 0);
            assert_eq!(slice::from_raw_parts(p as *const u8, l), &users[..]);

            assert_eq!(peios_acl_view_ace(&av, 1, &mut ev), 0);
            assert_eq!(peios_ace_view_type(&ev), ACCESS_ALLOWED_ACE_TYPE);
            assert_eq!(peios_ace_view_mask(&ev), 0x1F01FF);

            peios_acl_builder_free(b);
        }
    }

    #[test]
    fn object_ace_raises_revision() {
        unsafe {
            let b = peios_acl_builder_new();
            let admins = sid(5, &[32, 544]);
            let guid = [0xABu8; 16];
            let spec = peios_ace_spec {
                type_: ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                flags: 0,
                mask: 0x1,
                sid: admins.as_ptr() as *const c_void,
                sid_len: admins.len(),
                object_type: guid.as_ptr(),
                inherited_object_type: ptr::null(),
                app_data: ptr::null(),
                app_data_len: 0,
            };
            peios_acl_builder_add(b, &spec);
            assert_eq!(peios_acl_builder_error(b), 0);
            let acl = finish(b);
            assert_eq!(acl[0], 0x04); // ACL_REVISION_DS for object ACEs
            peios_acl_builder_free(b);
        }
    }

    #[test]
    fn label_ace() {
        unsafe {
            let b = peios_acl_builder_new();
            peios_acl_builder_label(b, 8192, 0x1); // medium IL, NO_WRITE_UP
            let acl = finish(b);
            let av = parse_view(&acl);
            let mut ev = peios_ace_view { _opaque: [0; 4] };
            assert_eq!(peios_acl_view_ace(&av, 0, &mut ev), 0);
            assert_eq!(peios_ace_view_type(&ev), SYSTEM_MANDATORY_LABEL_ACE_TYPE);
            assert_eq!(peios_ace_view_mask(&ev), 0x1);
            let (mut p, mut l) = (ptr::null::<c_void>(), 0usize);
            assert_eq!(peios_ace_view_sid(&ev, &mut p, &mut l), 0);
            assert_eq!(slice::from_raw_parts(p as *const u8, l), &integrity_sid(8192)[..]);
            peios_acl_builder_free(b);
        }
    }

    #[test]
    fn empty_acl_is_valid() {
        unsafe {
            let b = peios_acl_builder_new();
            let acl = finish(b);
            assert_eq!(acl.len(), Acl::HEADER_SIZE);
            assert_eq!(parse_view_count(&acl), 0);
            peios_acl_builder_free(b);
        }
    }

    unsafe fn parse_view_count(acl: &[u8]) -> u32 {
        peios_acl_view_count(&parse_view(acl))
    }

    #[test]
    fn sticky_error_latches() {
        unsafe {
            let b = peios_acl_builder_new();
            let admins = sid(5, &[32, 544]);
            // NULL SID -> EINVAL latched.
            peios_acl_builder_allow(b, ptr::null(), 0, 0x1, 0);
            assert_eq!(peios_acl_builder_error(b), libc::EINVAL);
            // Subsequent adds are no-ops; the error persists.
            peios_acl_builder_allow(b, admins.as_ptr() as *const c_void, admins.len(), 0x1, 0);
            assert_eq!(peios_acl_builder_error(b), libc::EINVAL);
            // bytes() yields NULL, finish() yields -1 + errno.
            let mut len = 123usize;
            assert!(peios_acl_builder_bytes(b, &mut len).is_null());
            assert_eq!(len, 0);
            assert_eq!(peios_acl_builder_finish(b, ptr::null_mut(), 0), -1);
            assert_eq!(errno(), libc::EINVAL);
            // reset() recovers the builder.
            peios_acl_builder_reset(b);
            assert_eq!(peios_acl_builder_error(b), 0);
            peios_acl_builder_free(b);
        }
    }

    #[test]
    fn reserved_mask_bits_rejected() {
        unsafe {
            let b = peios_acl_builder_new();
            let admins = sid(5, &[32, 544]);
            // 0x0CE00000 are reserved; validate_ace_mask rejects them.
            peios_acl_builder_allow(b, admins.as_ptr() as *const c_void, admins.len(), 0x0400_0000, 0);
            assert_eq!(peios_acl_builder_error(b), libc::EINVAL);
            peios_acl_builder_free(b);
        }
    }

    #[test]
    fn finish_erange() {
        unsafe {
            let b = peios_acl_builder_new();
            let admins = sid(5, &[32, 544]);
            peios_acl_builder_allow(b, admins.as_ptr() as *const c_void, admins.len(), 0x1, 0);
            let need = peios_acl_builder_finish(b, ptr::null_mut(), 0);
            let mut small = vec![0u8; (need - 1) as usize];
            assert_eq!(
                peios_acl_builder_finish(b, small.as_mut_ptr() as *mut c_void, small.len()),
                -1
            );
            assert_eq!(errno(), libc::ERANGE);
            peios_acl_builder_free(b);
        }
    }
}
