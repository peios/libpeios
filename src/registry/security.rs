//! Registry key security descriptors — read and modify a key's SD, as key-fd
//! ioctls.
//!
//! A `security_info` mask (`OWNER_SECURITY_INFORMATION` … `SACL_SECURITY_INFORMATION`,
//! up to `REG_VALID_SECURITY_INFORMATION`) selects which SD components are read or
//! written. The descriptor is the standard KACS binary security-descriptor format —
//! the same bytes the `<peios/security.h>` builders produce and `<peios/file.h>`'s
//! SD calls exchange — so the kernel parses and validates it directly; libpeios
//! passes a caller-supplied SD straight through (mirroring [`crate::file`]'s
//! `set_sd`). The read uses the registry-wide fill-or-`ERANGE` contract: a
//! zero-capacity buffer probes the required size.
//!
//! Note: SD changes are direct (not layer-qualified) and affect only opens after
//! the change — an existing key fd keeps the access mask it was granted at open.

#![allow(non_camel_case_types)]

use core::ffi::{c_int, c_void};

use peios_uapi::{reg_get_security_args, reg_set_security_args, REG_IOC_GET_SECURITY, REG_IOC_SET_SECURITY};

use crate::error::{get_errno, set_errno};

use super::ioctl_struct;

// Pin the wire-struct sizes.
const _: () = assert!(core::mem::size_of::<reg_get_security_args>() == 16);
const _: () = assert!(core::mem::size_of::<reg_set_security_args>() == 24);

/// `peios_reg_get_security` — read the `security_info` components of the key's SD.
///
/// Copies the selected SD components (KACS binary format) into `sd` and writes the
/// length to `*sd_len_out` (if non-NULL). A too-small buffer returns `-1` / `ERANGE`
/// with the required size in `*sd_len_out`, so a zero `cap` probes the size.
/// Reading owner/group/DACL needs `READ_CONTROL`; the SACL needs
/// `ACCESS_SYSTEM_SECURITY`. Returns 0, or `-1` with `errno` (`ERANGE`, `EACCES`,
/// `EFAULT`).
///
/// # Safety
/// `sd` valid for `cap` bytes when `cap != 0`; `sd_len_out` NULL or valid for a
/// `u32` write.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_get_security(
    key_fd: c_int,
    security_info: u32,
    sd: *mut c_void,
    cap: u32,
    sd_len_out: *mut u32,
) -> c_int {
    let mut a = reg_get_security_args::default();
    a.security_info = security_info;
    a.sd_len = cap; // in: capacity (overwritten with the written/required length)
    a.sd_ptr = sd as usize as u64;
    let r = ioctl_struct(key_fd, REG_IOC_GET_SECURITY, &mut a);
    if r == 0 || get_errno() == libc::ERANGE {
        if !sd_len_out.is_null() {
            *sd_len_out = a.sd_len;
        }
    }
    r
}

/// `peios_reg_set_security` — apply the `security_info` components of `sd` to the
/// key's SD, merging them with the rest.
///
/// `sd` is a KACS binary security descriptor carrying the components named by
/// `security_info`; the kernel parses and validates it (a malformed SD is `EINVAL`).
/// Modifying the DACL needs `WRITE_DAC`, the owner `WRITE_OWNER`, the SACL
/// `ACCESS_SYSTEM_SECURITY`. `txn_fd` enlists a transaction (`-1` to apply
/// immediately) — transactions give atomicity here, not layer qualification.
/// Returns 0, or `-1` with `errno` (`EINVAL`, `EACCES`, `EFAULT`).
///
/// # Safety
/// `sd` must be valid for `sd_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_set_security(
    key_fd: c_int,
    security_info: u32,
    sd: *const c_void,
    sd_len: u32,
    txn_fd: c_int,
) -> c_int {
    // The kernel rejects an empty/NULL SD; reject it here too (as file::set_sd does)
    // so the caller error surfaces before the ioctl.
    if sd.is_null() || sd_len == 0 {
        set_errno(libc::EINVAL);
        return -1;
    }
    let mut a = reg_set_security_args::default();
    a.security_info = security_info;
    a.sd_len = sd_len;
    a.sd_ptr = sd as usize as u64;
    a.txn_fd = txn_fd;
    ioctl_struct(key_fd, REG_IOC_SET_SECURITY, &mut a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::get_errno as errno;

    #[test]
    fn struct_sizes_pinned() {
        assert_eq!(core::mem::size_of::<reg_get_security_args>(), 16);
        assert_eq!(core::mem::size_of::<reg_set_security_args>(), 24);
    }

    #[test]
    fn set_security_rejects_empty_sd() {
        // NULL SD or zero length is EINVAL before any ioctl.
        let r = unsafe { peios_reg_set_security(-1, 0x4, core::ptr::null(), 0, -1) };
        assert_eq!(r, -1);
        assert_eq!(errno(), libc::EINVAL);
    }
}
