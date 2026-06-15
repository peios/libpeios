//! Syscall-backed token operations — the fd-returning open/create calls of
//! `<peios/token.h>` (and `peios_session_destroy_empty`).
//!
//! Each is a thin wrapper over a `SYS_KACS_*` syscall; the returned token fd
//! carries `O_CLOEXEC` (set unconditionally by the kernel). These cross the
//! kernel boundary, so they are exercised live under Provium, not in
//! `cargo test`. The ioctl-backed actions (query/adjust/duplicate/…) land in a
//! later slice.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_uint, c_void};

use alloc::vec::Vec;

use peios_uapi::{
    KACS_SESSION_SPEC_MAX_BYTES, SYS_KACS_CREATE_SESSION, SYS_KACS_CREATE_TOKEN,
    SYS_KACS_DESTROY_EMPTY_SESSION, SYS_KACS_OPEN_PEER_TOKEN, SYS_KACS_OPEN_PROCESS_TOKEN,
    SYS_KACS_OPEN_SELF_TOKEN, SYS_KACS_OPEN_THREAD_TOKEN,
};

use crate::abi::{cstr_bytes, try_extend};
use crate::error::set_errno;
use crate::security::sid_valid;
use crate::sys::{ret_int, syscall1, syscall2, syscall3};

/// Mint a token from a spec buffer at `ptr`/`len`. Shared by
/// `peios_token_create_raw` and `peios_token_builder_create`; the kernel
/// validates the buffer (a null pointer or bad length faults/`EINVAL`s there).
pub(crate) unsafe fn create_token_raw(ptr: *const c_void, len: usize) -> c_int {
    ret_int(syscall2(
        SYS_KACS_CREATE_TOKEN,
        ptr as usize as c_long,
        len as c_long,
    ))
}

/// `peios_token_open_self` — open the calling thread's token.
#[no_mangle]
pub unsafe extern "C" fn peios_token_open_self(flags: c_uint, access: u32) -> c_int {
    ret_int(syscall2(
        SYS_KACS_OPEN_SELF_TOKEN,
        flags as c_long,
        access as c_long,
    ))
}

/// `peios_token_open_process` — open a process's primary token by pidfd.
#[no_mangle]
pub unsafe extern "C" fn peios_token_open_process(pidfd: c_int, access: u32) -> c_int {
    ret_int(syscall2(
        SYS_KACS_OPEN_PROCESS_TOKEN,
        pidfd as c_long,
        access as c_long,
    ))
}

/// `peios_token_open_thread` — open a thread's impersonation token (or the
/// process primary token if the thread is not impersonating).
#[no_mangle]
pub unsafe extern "C" fn peios_token_open_thread(pidfd: c_int, tid: c_int, access: u32) -> c_int {
    ret_int(syscall3(
        SYS_KACS_OPEN_THREAD_TOKEN,
        pidfd as c_long,
        tid as c_long,
        access as c_long,
    ))
}

/// `peios_token_open_peer` — open a Unix-socket peer's identity token.
#[no_mangle]
pub unsafe extern "C" fn peios_token_open_peer(conn_fd: c_int) -> c_int {
    ret_int(syscall1(SYS_KACS_OPEN_PEER_TOKEN, conn_fd as c_long))
}

/// `peios_token_create_raw` — mint a token from a pre-built spec buffer.
#[no_mangle]
pub unsafe extern "C" fn peios_token_create_raw(spec: *const c_void, len: usize) -> c_int {
    create_token_raw(spec, len)
}

/// `peios_session_destroy_empty` — destroy a logon session with no live tokens.
#[no_mangle]
pub unsafe extern "C" fn peios_session_destroy_empty(session_id: u64) -> c_int {
    ret_int(syscall1(SYS_KACS_DESTROY_EMPTY_SESSION, session_id as c_long))
}

/// `struct peios_session_spec` — inputs to `peios_session_create`.
#[repr(C)]
pub struct peios_session_spec {
    pub logon_type: u8,
    pub auth_package: *const c_char,
    pub user_sid: *const c_void,
    pub user_sid_len: usize,
}

/// Encode the `kacs_create_session` wire format:
/// `[logon_type:u8][auth_pkg_len:u16][auth_pkg][user_sid_len:u32][user_sid]`,
/// consumed exactly. Pure and unit-testable; the syscall is Provium-tested.
fn encode_session_spec(
    logon_type: u8,
    auth_pkg: &[u8],
    user_sid: &[u8],
) -> Result<Vec<u8>, libc::c_int> {
    if auth_pkg.len() > u16::MAX as usize || user_sid.len() > u32::MAX as usize {
        return Err(libc::EINVAL);
    }
    // 7 fixed bytes (u8 + u16 + u32) + the two variable sections.
    if 7 + auth_pkg.len() + user_sid.len() > KACS_SESSION_SPEC_MAX_BYTES as usize {
        return Err(libc::EINVAL);
    }
    let oom = |_| libc::ENOMEM;
    let mut spec = Vec::new();
    try_extend(&mut spec, &[logon_type]).map_err(oom)?;
    try_extend(&mut spec, &(auth_pkg.len() as u16).to_le_bytes()).map_err(oom)?;
    try_extend(&mut spec, auth_pkg).map_err(oom)?;
    try_extend(&mut spec, &(user_sid.len() as u32).to_le_bytes()).map_err(oom)?;
    try_extend(&mut spec, user_sid).map_err(oom)?;
    Ok(spec)
}

/// `peios_session_create` — create a logon session; the id is returned via
/// `id_out`. Requires `SeTcbPrivilege`.
#[no_mangle]
pub unsafe extern "C" fn peios_session_create(
    spec: *const peios_session_spec,
    id_out: *mut u64,
) -> c_int {
    let Some(spec) = spec.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if spec.auth_package.is_null() || spec.user_sid.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let Some(auth_pkg) = cstr_bytes(spec.auth_package, KACS_SESSION_SPEC_MAX_BYTES as usize) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let user_sid = core::slice::from_raw_parts(spec.user_sid as *const u8, spec.user_sid_len);
    if !sid_valid(user_sid) {
        set_errno(libc::EINVAL);
        return -1;
    }
    let buf = match encode_session_spec(spec.logon_type, auth_pkg, user_sid) {
        Ok(buf) => buf,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };
    let r = syscall2(
        SYS_KACS_CREATE_SESSION,
        buf.as_ptr() as usize as c_long,
        buf.len() as c_long,
    );
    if r < 0 {
        return -1; // errno set by libc
    }
    if !id_out.is_null() {
        *id_out = r as u64;
    }
    0
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

    #[test]
    fn session_spec_encodes_exactly() {
        let user = sid(5, &[21, 7, 8, 9]);
        let auth = b"Negotiate";
        let spec = encode_session_spec(2, auth, &user).unwrap();

        let mut expect = Vec::new();
        expect.push(2u8); // logon_type
        expect.extend_from_slice(&(auth.len() as u16).to_le_bytes());
        expect.extend_from_slice(auth);
        expect.extend_from_slice(&(user.len() as u32).to_le_bytes());
        expect.extend_from_slice(&user);
        assert_eq!(spec, expect);
        // 7 fixed bytes + auth + sid, consumed exactly.
        assert_eq!(spec.len(), 7 + auth.len() + user.len());
    }

    #[test]
    fn session_spec_empty_auth_package() {
        let user = sid(5, &[18]);
        let spec = encode_session_spec(5, b"", &user).unwrap();
        assert_eq!(spec.len(), 7 + user.len());
        assert_eq!(&spec[1..3], &0u16.to_le_bytes()); // auth_pkg_len == 0
    }

    #[test]
    fn session_spec_too_large_is_einval() {
        let user = sid(5, &[18]);
        let big = vec![b'x'; KACS_SESSION_SPEC_MAX_BYTES as usize];
        assert_eq!(encode_session_spec(2, &big, &user), Err(libc::EINVAL));
    }
}
