//! Token transform / adjust operations — the action ioctls of `<peios/token.h>`.
//!
//! Each issues a `KACS_IOC_*` ioctl on a token fd. Operations that mint a new
//! token (`duplicate`, `restrict`, `get_linked`) return the new fd through the
//! args struct's `result_fd` field, not the ioctl return value. The reset
//! helpers synthesize the kernel's sentinel entries. Provium-tested; the only
//! unit-testable piece is `restrict`'s payload packing.
#![allow(non_camel_case_types)]

use core::ffi::{c_int, c_uint, c_ulong, c_void};

use alloc::vec::Vec;

use peios_uapi::{
    kacs_adjust_default_args, kacs_adjust_groups_args, kacs_adjust_privs_args, kacs_duplicate_args,
    kacs_get_linked_token_args, kacs_group_entry, kacs_link_tokens_args, kacs_priv_entry,
    kacs_restrict_args, KACS_IOC_ADJUST_DEFAULT, KACS_IOC_ADJUST_GROUPS, KACS_IOC_ADJUST_PRIVS,
    KACS_IOC_ADJUST_SESSIONID, KACS_IOC_DUPLICATE, KACS_IOC_GET_LINKED_TOKEN, KACS_IOC_IMPERSONATE,
    KACS_IOC_INSTALL, KACS_IOC_LINK_TOKENS, KACS_IOC_RESTRICT, KACS_PRIVILEGE_RESET_ALL_DEFAULTS,
    KACS_TOKEN_GROUP_MASK_WORDS,
};

use crate::abi::try_extend;
use crate::error::set_errno;
use crate::sys::ioctl;

/// `struct peios_token_restrict` — the filtered-token recipe.
#[repr(C)]
pub struct peios_token_restrict {
    pub privs_to_delete: u64,
    pub deny_group_indices: *const u32,
    pub deny_count: c_uint,
    pub restrict_sids: *const *const c_void,
    pub restrict_sid_lens: *const usize,
    pub restrict_count: c_uint,
    pub flags: u32,
}

/// Issue `request` on `fd` with `arg`; 0 on success, -1 on failure (errno set).
#[inline]
unsafe fn ioc<T>(fd: c_int, request: c_ulong, arg: *mut T) -> c_int {
    ioctl(fd, request, arg.cast())
}

fn adjust_default_args(
    dacl: *const c_void,
    len: usize,
    owner_index: u16,
    group_index: u16,
) -> Result<kacs_adjust_default_args, c_int> {
    let dacl_len = if dacl.is_null() {
        0
    } else {
        u32::try_from(len).map_err(|_| libc::EINVAL)?
    };
    Ok(kacs_adjust_default_args {
        dacl_ptr: dacl as usize as u64,
        dacl_len,
        owner_index,
        group_index,
    })
}

// ----------------------------------------------------------------------------
// Privileges / groups
// ----------------------------------------------------------------------------

/// `peios_token_adjust_privileges` — apply an array of privilege adjustments.
#[no_mangle]
pub unsafe extern "C" fn peios_token_adjust_privileges(
    fd: c_int,
    entries: *const kacs_priv_entry,
    count: c_uint,
    prev_enabled: *mut u64,
) -> c_int {
    let mut args = kacs_adjust_privs_args {
        count,
        _pad: 0,
        data_ptr: entries as usize as u64,
        previous_enabled: 0,
    };
    if ioc(fd, KACS_IOC_ADJUST_PRIVS as c_ulong, &mut args) < 0 {
        return -1;
    }
    if !prev_enabled.is_null() {
        *prev_enabled = args.previous_enabled;
    }
    0
}

/// `peios_token_reset_privileges` — restore enabled := enabled-by-default.
#[no_mangle]
pub unsafe extern "C" fn peios_token_reset_privileges(fd: c_int) -> c_int {
    let entry = kacs_priv_entry {
        luid: 0,
        attributes: KACS_PRIVILEGE_RESET_ALL_DEFAULTS,
    };
    let mut args = kacs_adjust_privs_args {
        count: 1,
        _pad: 0,
        data_ptr: &entry as *const kacs_priv_entry as usize as u64,
        previous_enabled: 0,
    };
    if ioc(fd, KACS_IOC_ADJUST_PRIVS as c_ulong, &mut args) < 0 {
        return -1;
    }
    0
}

/// `peios_token_adjust_groups` — apply an array of group adjustments.
#[no_mangle]
pub unsafe extern "C" fn peios_token_adjust_groups(
    fd: c_int,
    entries: *const kacs_group_entry,
    count: c_uint,
    prev_state: *mut u64,
) -> c_int {
    let mut args = kacs_adjust_groups_args {
        count,
        _pad: 0,
        data_ptr: entries as usize as u64,
        previous_state: [0; KACS_TOKEN_GROUP_MASK_WORDS as usize],
    };
    if ioc(fd, KACS_IOC_ADJUST_GROUPS as c_ulong, &mut args) < 0 {
        return -1;
    }
    if !prev_state.is_null() {
        // The caller provides KACS_TOKEN_GROUP_MASK_WORDS u64 words.
        core::ptr::copy_nonoverlapping(
            args.previous_state.as_ptr(),
            prev_state,
            KACS_TOKEN_GROUP_MASK_WORDS as usize,
        );
    }
    0
}

/// `peios_token_reset_groups` — restore the creation-time group state.
#[no_mangle]
pub unsafe extern "C" fn peios_token_reset_groups(fd: c_int) -> c_int {
    let entry = kacs_group_entry {
        index: u32::MAX, // reset sentinel
        enable: 0,
    };
    let mut args = kacs_adjust_groups_args {
        count: 1,
        _pad: 0,
        data_ptr: &entry as *const kacs_group_entry as usize as u64,
        previous_state: [0; KACS_TOKEN_GROUP_MASK_WORDS as usize],
    };
    if ioc(fd, KACS_IOC_ADJUST_GROUPS as c_ulong, &mut args) < 0 {
        return -1;
    }
    0
}

// ----------------------------------------------------------------------------
// Transform
// ----------------------------------------------------------------------------

/// `peios_token_duplicate` — deep-clone this token; returns the new fd.
#[no_mangle]
pub unsafe extern "C" fn peios_token_duplicate(
    fd: c_int,
    access: u32,
    token_type: u8,
    imp_level: u8,
) -> c_int {
    let mut args = kacs_duplicate_args {
        access_mask: access,
        token_type: token_type as u32,
        impersonation_level: imp_level as u32,
        result_fd: -1,
    };
    if ioc(fd, KACS_IOC_DUPLICATE as c_ulong, &mut args) < 0 {
        return -1;
    }
    args.result_fd
}

/// Pack a restrict payload: the deny indices (`u32` LE) followed by the
/// restricting SIDs concatenated. Unit-testable (the rest is the live ioctl).
fn pack_restrict(deny: &[u32], sids: &[&[u8]]) -> Result<Vec<u8>, ()> {
    let mut payload = Vec::new();
    for &index in deny {
        try_extend(&mut payload, &index.to_le_bytes())?;
    }
    for sid in sids {
        try_extend(&mut payload, sid)?;
    }
    Ok(payload)
}

/// `peios_token_restrict` — create a filtered token; returns the new fd.
#[no_mangle]
pub unsafe extern "C" fn peios_token_restrict(
    fd: c_int,
    spec: *const peios_token_restrict,
) -> c_int {
    let Some(spec) = spec.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };

    let deny: &[u32] = if spec.deny_count == 0 {
        &[]
    } else if spec.deny_group_indices.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    } else {
        core::slice::from_raw_parts(spec.deny_group_indices, spec.deny_count as usize)
    };

    let sid_count = spec.restrict_count as usize;
    if sid_count > 0 && (spec.restrict_sids.is_null() || spec.restrict_sid_lens.is_null()) {
        set_errno(libc::EINVAL);
        return -1;
    }
    let mut sids: Vec<&[u8]> = Vec::new();
    if sids.try_reserve(sid_count).is_err() {
        set_errno(libc::ENOMEM);
        return -1;
    }
    for i in 0..sid_count {
        let ptr = *spec.restrict_sids.add(i);
        let len = *spec.restrict_sid_lens.add(i);
        if ptr.is_null() {
            set_errno(libc::EINVAL);
            return -1;
        }
        sids.push(core::slice::from_raw_parts(ptr as *const u8, len));
    }

    let payload = match pack_restrict(deny, &sids) {
        Ok(payload) => payload,
        Err(()) => {
            set_errno(libc::ENOMEM);
            return -1;
        }
    };
    if payload.len() > u32::MAX as usize {
        set_errno(libc::EINVAL);
        return -1;
    }

    let mut args = kacs_restrict_args {
        privs_to_delete: spec.privs_to_delete,
        num_deny_indices: spec.deny_count,
        num_restrict_sids: spec.restrict_count,
        data_len: payload.len() as u32,
        flags: spec.flags,
        data_ptr: payload.as_ptr() as usize as u64,
        result_fd: -1,
        _pad: 0,
    };
    if ioc(fd, KACS_IOC_RESTRICT as c_ulong, &mut args) < 0 {
        return -1;
    }
    args.result_fd
}

/// `peios_token_install` — commit this primary token on the calling process.
#[no_mangle]
pub unsafe extern "C" fn peios_token_install(fd: c_int) -> c_int {
    if ioctl(fd, KACS_IOC_INSTALL as c_ulong, core::ptr::null_mut()) < 0 {
        return -1;
    }
    0
}

/// `peios_token_impersonate` — impersonate this token on the calling thread.
#[no_mangle]
pub unsafe extern "C" fn peios_token_impersonate(fd: c_int) -> c_int {
    if ioctl(fd, KACS_IOC_IMPERSONATE as c_ulong, core::ptr::null_mut()) < 0 {
        return -1;
    }
    0
}

/// `peios_token_link` — link an elevated + filtered pair on `session_id`.
#[no_mangle]
pub unsafe extern "C" fn peios_token_link(
    elevated_fd: c_int,
    filtered_fd: c_int,
    session_id: u64,
) -> c_int {
    let mut args = kacs_link_tokens_args {
        elevated_fd,
        filtered_fd,
        session_id,
    };
    // The kernel resolves both tokens from the args; issue on the elevated fd
    // (consistent with args.elevated_fd) to reach the token-fd ioctl handler.
    if ioc(elevated_fd, KACS_IOC_LINK_TOKENS as c_ulong, &mut args) < 0 {
        return -1;
    }
    0
}

/// `peios_token_get_linked` — open this token's linked partner; returns its fd.
#[no_mangle]
pub unsafe extern "C" fn peios_token_get_linked(fd: c_int) -> c_int {
    let mut args = kacs_get_linked_token_args { result_fd: -1 };
    if ioc(fd, KACS_IOC_GET_LINKED_TOKEN as c_ulong, &mut args) < 0 {
        return -1;
    }
    args.result_fd
}

/// `peios_token_adjust_default` — replace the default DACL and/or owner/group
/// indices. A null `dacl` leaves the DACL unchanged; `dacl != NULL` with
/// `len == 0` clears it; an index of `0xFFFF` leaves that index unchanged.
#[no_mangle]
pub unsafe extern "C" fn peios_token_adjust_default(
    fd: c_int,
    dacl: *const c_void,
    len: usize,
    owner_index: u16,
    group_index: u16,
) -> c_int {
    let mut args = match adjust_default_args(dacl, len, owner_index, group_index) {
        Ok(args) => args,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };
    if ioc(fd, KACS_IOC_ADJUST_DEFAULT as c_ulong, &mut args) < 0 {
        return -1;
    }
    0
}

/// `peios_token_set_session_id` — change the interactive session id.
#[no_mangle]
pub unsafe extern "C" fn peios_token_set_session_id(fd: c_int, session_id: u32) -> c_int {
    let mut value = session_id;
    if ioc(fd, KACS_IOC_ADJUST_SESSIONID as c_ulong, &mut value) < 0 {
        return -1;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restrict_payload_packs_indices_then_sids() {
        let deny = [3u32, 7];
        let s1 = [1u8, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]; // S-1-1-0
        let s2 = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]; // S-1-5-18
        let sids = [s1.as_slice(), s2.as_slice()];

        let payload = pack_restrict(&deny, &sids).unwrap();

        let mut expect = Vec::new();
        expect.extend_from_slice(&3u32.to_le_bytes());
        expect.extend_from_slice(&7u32.to_le_bytes());
        expect.extend_from_slice(&s1);
        expect.extend_from_slice(&s2);
        assert_eq!(payload, expect);
    }

    #[test]
    fn restrict_payload_empty() {
        assert_eq!(pack_restrict(&[], &[]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn adjust_default_null_dacl_ignores_len() {
        let args = adjust_default_args(core::ptr::null(), usize::MAX, 0xFFFF, 0xFFFF).unwrap();
        assert_eq!(args.dacl_ptr, 0);
        assert_eq!(args.dacl_len, 0);
        assert_eq!(args.owner_index, 0xFFFF);
        assert_eq!(args.group_index, 0xFFFF);
    }

    #[test]
    fn adjust_default_non_null_dacl_checks_len() {
        let dacl = core::ptr::dangling::<c_void>();

        let clear = adjust_default_args(dacl, 0, 1, 2).unwrap();
        assert_eq!(clear.dacl_ptr, dacl as usize as u64);
        assert_eq!(clear.dacl_len, 0);
        assert_eq!(clear.owner_index, 1);
        assert_eq!(clear.group_index, 2);

        assert!(matches!(
            adjust_default_args(dacl, u32::MAX as usize + 1, 0xFFFF, 0xFFFF),
            Err(errno) if errno == libc::EINVAL
        ));
    }
}
