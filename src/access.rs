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
//! These cross the kernel boundary (syscalls 1023 / 1024), so they are exercised
//! live under Provium; `cargo test` covers only the pure arg-packing in
//! [`build_args`].
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

use core::ffi::{c_int, c_long, c_void};

use peios_uapi::{
    kacs_access_check_args, kacs_generic_mapping, kacs_node_result, kacs_object_type_entry,
    SYS_KACS_ACCESS_CHECK, SYS_KACS_ACCESS_CHECK_LIST,
};

use crate::abi::u32_len;
use crate::error::{get_errno, set_errno};
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
    /// Opaque object id threaded into audit events.
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
}
