//! Token information-class queries — `peios_token_query` and the typed helpers
//! (`<peios/token.h>`).
//!
//! All go through `KACS_IOC_QUERY` with `kacs_query_args`, whose `buf_len` is the
//! in/out length and `buf_ptr == 0` requests a size probe — which maps exactly
//! onto libpeios's getxattr `ssize_t` contract. SID-array and ACL classes are
//! read raw and parsed with the views in `<peios/security.h>`; the typed helpers
//! here cover the fixed-shape scalar classes. Provium-tested (live kernel).
#![allow(non_camel_case_types)]

use core::ffi::{c_int, c_ulong, c_void};

use peios_uapi::{
    kacs_query_args, KACS_IOC_QUERY, KACS_TOKEN_CLASS_INTEGRITY_LEVEL, KACS_TOKEN_CLASS_PRIVILEGES,
    KACS_TOKEN_CLASS_SESSION_ID, KACS_TOKEN_CLASS_STATISTICS, KACS_TOKEN_CLASS_TYPE,
    KACS_TOKEN_CLASS_USER,
};

use crate::error::set_errno;
use crate::sys::ioctl;

/// `struct peios_privilege_set` — the four words of `KACS_TOKEN_CLASS_PRIVILEGES`.
#[repr(C)]
pub struct peios_privilege_set {
    pub present: u64,
    pub enabled: u64,
    pub enabled_by_default: u64,
    pub used: u64,
}

/// `struct peios_token_statistics` — the fixed 40-byte
/// `KACS_TOKEN_CLASS_STATISTICS` result.
#[repr(C)]
pub struct peios_token_statistics {
    pub token_id: u64,
    pub auth_id: u64,
    pub modified_id: u64,
    pub token_type: u32,
    pub reserved: u32,
    pub expiration: u64,
}

/// `peios_token_query` — read an information class, getxattr-style.
#[no_mangle]
pub unsafe extern "C" fn peios_token_query(
    fd: c_int,
    info_class: u32,
    buf: *mut c_void,
    cap: usize,
) -> isize {
    if cap > u32::MAX as usize {
        set_errno(libc::EINVAL);
        return -1;
    }
    // getxattr contract (see `peios_cabi::abi::emit_bytes`): `cap == 0` is a size
    // probe and may pass a NULL buffer; a non-zero `cap` with a NULL buffer is a
    // caller error — EINVAL, not a silent probe.
    if cap != 0 && buf.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let mut args = kacs_query_args {
        token_class: info_class,
        buf_len: cap as u32,
        // `cap == 0` leaves buf_ptr 0, which the kernel treats as a size probe —
        // returning the required size in buf_len.
        buf_ptr: buf as usize as u64,
    };
    if ioctl(
        fd,
        KACS_IOC_QUERY as c_ulong,
        (&mut args as *mut kacs_query_args).cast(),
    ) < 0
    {
        return -1; // errno set (ERANGE when a non-empty buffer is too small)
    }
    args.buf_len as isize
}

/// Read a fixed-size class into a stack scalar.
///
/// # Safety
/// `out` must be writable for `T`.
unsafe fn query_into<T>(fd: c_int, class: u32, out: *mut T) -> c_int {
    if out.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    let n = peios_token_query(
        fd,
        class,
        value.as_mut_ptr().cast(),
        core::mem::size_of::<T>(),
    );
    if n < 0 {
        return -1;
    }
    if n as usize != core::mem::size_of::<T>() {
        // The class returned an unexpected shape for this typed helper.
        set_errno(libc::EINVAL);
        return -1;
    }
    *out = value.assume_init();
    0
}

/// `peios_token_user` — the user SID (`KACS_TOKEN_CLASS_USER`), getxattr-style.
#[no_mangle]
pub unsafe extern "C" fn peios_token_user(fd: c_int, sid_buf: *mut c_void, cap: usize) -> isize {
    peios_token_query(fd, KACS_TOKEN_CLASS_USER, sid_buf, cap)
}

/// `peios_token_type` — the token type (`KACS_TOKEN_CLASS_TYPE`).
#[no_mangle]
pub unsafe extern "C" fn peios_token_type(fd: c_int, out: *mut u32) -> c_int {
    query_into(fd, KACS_TOKEN_CLASS_TYPE, out)
}

/// `peios_token_interactivity_scope` — the interactive environment scope
/// (`KACS_TOKEN_CLASS_SESSION_ID`, renamed INTERACTIVITY_SCOPE in the current
/// UAPI). This is not the token's LogonSession LUID / `auth_id`.
#[no_mangle]
pub unsafe extern "C" fn peios_token_interactivity_scope(fd: c_int, out: *mut u32) -> c_int {
    query_into(fd, KACS_TOKEN_CLASS_SESSION_ID, out)
}

/// Compatibility alias for the historical, ambiguous API name. The queried
/// value is an interactivity scope, not a LogonSession id.
#[no_mangle]
pub unsafe extern "C" fn peios_token_session_id(fd: c_int, out: *mut u32) -> c_int {
    unsafe { peios_token_interactivity_scope(fd, out) }
}

/// `peios_token_statistics` — token ids, including the LogonSession LUID in
/// `auth_id` (`KACS_TOKEN_CLASS_STATISTICS`).
#[no_mangle]
pub unsafe extern "C" fn peios_token_statistics(
    fd: c_int,
    out: *mut peios_token_statistics,
) -> c_int {
    query_into(fd, KACS_TOKEN_CLASS_STATISTICS, out)
}

/// `peios_token_integrity` — the integrity-level RID
/// (`KACS_TOKEN_CLASS_INTEGRITY_LEVEL`).
///
/// Unlike the scalar classes, `INTEGRITY_LEVEL` is SID-valued: the kernel
/// returns the mandatory-label SID `S-1-16-<rid>` (12 bytes — an 8-byte SID
/// header with identifier authority 16, plus one u32 sub-authority that is the
/// integrity RID), the same shape as the OWNER/PRIMARY_GROUP SID classes. This
/// helper reads that SID and hands back its trailing RID, so a 4-byte
/// `query_into::<u32>` would (correctly) get -ERANGE from the kernel's size
/// probe. Always exactly 12 bytes: an integrity SID never has more than one
/// sub-authority.
#[no_mangle]
pub unsafe extern "C" fn peios_token_integrity(fd: c_int, level_rid_out: *mut u32) -> c_int {
    if level_rid_out.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let mut sid = [0u8; 12];
    let n = peios_token_query(
        fd,
        KACS_TOKEN_CLASS_INTEGRITY_LEVEL,
        sid.as_mut_ptr().cast(),
        sid.len(),
    );
    if n < 0 {
        return -1;
    }
    if n as usize != sid.len() {
        set_errno(libc::EINVAL);
        return -1;
    }
    // The RID is the single sub-authority: the last 4 bytes, little-endian.
    *level_rid_out = u32::from_le_bytes([sid[8], sid[9], sid[10], sid[11]]);
    0
}

/// `peios_token_privileges` — the privilege words (`KACS_TOKEN_CLASS_PRIVILEGES`).
#[no_mangle]
pub unsafe extern "C" fn peios_token_privileges(fd: c_int, out: *mut peios_privilege_set) -> c_int {
    query_into(fd, KACS_TOKEN_CLASS_PRIVILEGES, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errno() -> libc::c_int {
        unsafe { *libc::__errno_location() }
    }

    #[test]
    fn typed_queries_reject_null_output_before_ioctl() {
        unsafe {
            *libc::__errno_location() = 0;
            assert_eq!(peios_token_type(-1, core::ptr::null_mut()), -1);
            assert_eq!(errno(), libc::EINVAL);

            *libc::__errno_location() = 0;
            assert_eq!(
                peios_token_interactivity_scope(-1, core::ptr::null_mut()),
                -1
            );
            assert_eq!(errno(), libc::EINVAL);

            *libc::__errno_location() = 0;
            assert_eq!(peios_token_session_id(-1, core::ptr::null_mut()), -1);
            assert_eq!(errno(), libc::EINVAL);

            *libc::__errno_location() = 0;
            assert_eq!(peios_token_statistics(-1, core::ptr::null_mut()), -1);
            assert_eq!(errno(), libc::EINVAL);

            *libc::__errno_location() = 0;
            assert_eq!(peios_token_integrity(-1, core::ptr::null_mut()), -1);
            assert_eq!(errno(), libc::EINVAL);

            *libc::__errno_location() = 0;
            assert_eq!(peios_token_privileges(-1, core::ptr::null_mut()), -1);
            assert_eq!(errno(), libc::EINVAL);
        }
    }

    #[test]
    fn token_statistics_matches_the_kacs_wire_shape() {
        assert_eq!(core::mem::size_of::<peios_token_statistics>(), 40);
        assert_eq!(core::mem::offset_of!(peios_token_statistics, token_id), 0);
        assert_eq!(core::mem::offset_of!(peios_token_statistics, auth_id), 8);
        assert_eq!(
            core::mem::offset_of!(peios_token_statistics, modified_id),
            16
        );
        assert_eq!(
            core::mem::offset_of!(peios_token_statistics, token_type),
            24
        );
        assert_eq!(core::mem::offset_of!(peios_token_statistics, reserved), 28);
        assert_eq!(
            core::mem::offset_of!(peios_token_statistics, expiration),
            32
        );
        assert_eq!(KACS_TOKEN_CLASS_SESSION_ID, 0x08);
        assert_eq!(KACS_TOKEN_CLASS_STATISTICS, 0x0b);
    }
}
