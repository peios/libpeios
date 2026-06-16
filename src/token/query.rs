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
    KACS_TOKEN_CLASS_SESSION_ID, KACS_TOKEN_CLASS_TYPE, KACS_TOKEN_CLASS_USER,
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
    if ioctl(fd, KACS_IOC_QUERY as c_ulong, (&mut args as *mut kacs_query_args).cast()) < 0 {
        return -1; // errno set (ERANGE when a non-empty buffer is too small)
    }
    args.buf_len as isize
}

/// Read a fixed-size class into a stack scalar.
///
/// # Safety
/// `out` may be null; otherwise it must be writable for `T`.
unsafe fn query_into<T>(fd: c_int, class: u32, out: *mut T) -> c_int {
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
    if !out.is_null() {
        *out = value.assume_init();
    }
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

/// `peios_token_session_id` — the session id (`KACS_TOKEN_CLASS_SESSION_ID`).
#[no_mangle]
pub unsafe extern "C" fn peios_token_session_id(fd: c_int, out: *mut u32) -> c_int {
    query_into(fd, KACS_TOKEN_CLASS_SESSION_ID, out)
}

/// `peios_token_integrity` — the integrity-level RID
/// (`KACS_TOKEN_CLASS_INTEGRITY_LEVEL`).
#[no_mangle]
pub unsafe extern "C" fn peios_token_integrity(fd: c_int, level_rid_out: *mut u32) -> c_int {
    query_into(fd, KACS_TOKEN_CLASS_INTEGRITY_LEVEL, level_rid_out)
}

/// `peios_token_privileges` — the privilege words (`KACS_TOKEN_CLASS_PRIVILEGES`).
#[no_mangle]
pub unsafe extern "C" fn peios_token_privileges(
    fd: c_int,
    out: *mut peios_privilege_set,
) -> c_int {
    query_into(fd, KACS_TOKEN_CLASS_PRIVILEGES, out)
}
