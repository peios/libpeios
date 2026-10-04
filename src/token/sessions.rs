//! Listing logon sessions — `peios_logon_sessions_*`, over securityfs's
//! `kacs/sessions`.
//!
//! The kernel writes one line per live session:
//!
//! ```text
//! logon_session_id=<u64> user_sid=<hex> logon_type=<u32> auth_package=<hex> created_at=<u64>
//! ```
//!
//! The reader takes the whole listing at open, so a walk sees one moment, and
//! decodes a line at a time on `next`. Reading it needs Administrators or
//! SYSTEM; the file is checked on read, so a refusal comes from `open`.

#![allow(non_camel_case_types)]

use alloc::vec::Vec;
use core::ffi::{c_char, c_int};

use peios_cabi::abi::{raw_free, raw_new};

use crate::error::set_errno;
use crate::kfile::{decimal, field, hex_into, read_whole};

const SESSIONS_PATH: &[u8] = b"/sys/kernel/security/kacs/sessions\0";

/// `struct peios_logon_session` — one session, as `next` fills it. The
/// pointers are into the reader and valid until its next call.
#[repr(C)]
#[derive(Debug)]
pub struct peios_logon_session {
    /// The session's id, its LUID; a token's `auth_id`.
    pub logon_session_id: u64,
    /// When the session was made, in seconds since the Unix epoch.
    pub created_at: u64,
    /// `KACS_LOGON_TYPE_*`.
    pub logon_type: u32,
    /// Length of `user_sid`.
    pub user_sid_len: u32,
    /// The session's user, as a binary SID.
    pub user_sid: *const u8,
    /// The authentication package's name: UTF-8, not NUL-terminated.
    pub auth_package: *const c_char,
    /// Length of `auth_package`.
    pub auth_package_len: u32,
    /// Zero.
    pub reserved: u32,
}

/// `peios_logon_sessions` — a listing taken at open, walked by `next`.
pub struct peios_logon_sessions {
    text: Vec<u8>,
    at: usize,
    sid: Vec<u8>,
    package: Vec<u8>,
}

/// One line's fields, decoded into the reader's buffers.
struct Line {
    id: u64,
    created_at: u64,
    logon_type: u32,
}

/// Decode `line` into `sid` and `package`. `None` if a known field is missing
/// or malformed, `Some(Err)` for out of memory.
fn parse_line(line: &[u8], sid: &mut Vec<u8>, package: &mut Vec<u8>) -> Option<Result<Line, ()>> {
    sid.clear();
    package.clear();
    if let Err(()) = hex_into(field(line, b"user_sid")?, sid)? {
        return Some(Err(()));
    }
    if let Err(()) = hex_into(field(line, b"auth_package")?, package)? {
        return Some(Err(()));
    }
    Some(Ok(Line {
        id: decimal(field(line, b"logon_session_id")?)?,
        created_at: decimal(field(line, b"created_at")?)?,
        logon_type: u32::try_from(decimal(field(line, b"logon_type")?)?).ok()?,
    }))
}

impl peios_logon_sessions {
    /// The next non-empty line, or `None` at the end.
    fn next_line(&mut self) -> Option<(usize, usize)> {
        while self.at < self.text.len() {
            let start = self.at;
            let end = self.text[start..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(self.text.len(), |n| start + n);
            self.at = end + 1;
            if end > start {
                return Some((start, end));
            }
        }
        None
    }
}

/// `peios_logon_sessions_open` — take the kernel's listing of live logon
/// sessions. NULL with errno on failure: `EACCES` without Administrators or
/// SYSTEM, `ENOENT` where securityfs is not mounted, `ENOMEM`.
#[no_mangle]
pub extern "C" fn peios_logon_sessions_open() -> *mut peios_logon_sessions {
    // SAFETY: SESSIONS_PATH is NUL-terminated.
    let text = match unsafe { read_whole(SESSIONS_PATH.as_ptr() as *const c_char) } {
        Ok(text) => text,
        Err(errno) => {
            set_errno(errno);
            return core::ptr::null_mut();
        }
    };
    // SAFETY: paired with raw_free in peios_logon_sessions_close.
    let reader = unsafe {
        raw_new(peios_logon_sessions { text, at: 0, sid: Vec::new(), package: Vec::new() })
    };
    if reader.is_null() {
        set_errno(libc::ENOMEM);
    }
    reader
}

/// `peios_logon_sessions_next` — fill `out` with the next session. Returns 1
/// (filled), 0 (no more), or `-1` with errno: `EPROTO` for a line this library
/// cannot read, `ENOMEM`, `EINVAL` for a NULL argument.
///
/// # Safety
/// `sessions` must be open; `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn peios_logon_sessions_next(
    sessions: *mut peios_logon_sessions,
    out: *mut peios_logon_session,
) -> c_int {
    let Some(reader) = sessions.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if out.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let Some((start, end)) = reader.next_line() else {
        return 0;
    };
    let line = &reader.text[start..end];
    match parse_line(line, &mut reader.sid, &mut reader.package) {
        None => {
            set_errno(libc::EPROTO);
            -1
        }
        Some(Err(())) => {
            set_errno(libc::ENOMEM);
            -1
        }
        Some(Ok(parsed)) => {
            out.write(peios_logon_session {
                logon_session_id: parsed.id,
                created_at: parsed.created_at,
                logon_type: parsed.logon_type,
                user_sid_len: reader.sid.len() as u32,
                user_sid: reader.sid.as_ptr(),
                auth_package: reader.package.as_ptr() as *const c_char,
                auth_package_len: reader.package.len() as u32,
                reserved: 0,
            });
            1
        }
    }
}

/// `peios_logon_sessions_close` — free the reader. NULL is a no-op.
///
/// # Safety
/// `sessions` must be NULL or a reader from `peios_logon_sessions_open` not
/// already closed.
#[no_mangle]
pub unsafe extern "C" fn peios_logon_sessions_close(sessions: *mut peios_logon_sessions) {
    raw_free(sessions);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(text: &[u8]) -> peios_logon_sessions {
        peios_logon_sessions { text: text.to_vec(), at: 0, sid: Vec::new(), package: Vec::new() }
    }

    #[test]
    fn walks_the_listing_a_session_at_a_time() {
        // SYSTEM's session, then a person's: S-1-5-21-1-2-3-1000 by "lpsd".
        let mut r = reader(
            b"logon_session_id=999 user_sid=010100000000000512000000 logon_type=5 \
              auth_package= created_at=1791100000\n\
              logon_session_id=1007 user_sid=0105000000000005150000000100000002000000\
              03000000e8030000 logon_type=10 auth_package=6c707364 created_at=1791103220\n",
        );
        let mut out = core::mem::MaybeUninit::<peios_logon_session>::uninit();
        unsafe {
            assert_eq!(peios_logon_sessions_next(&mut r, out.as_mut_ptr()), 1);
            let s = out.assume_init_read();
            assert_eq!(s.logon_session_id, 999);
            assert_eq!(s.logon_type, 5);
            assert_eq!(s.user_sid_len, 12);
            assert_eq!(*s.user_sid.add(8), 18);
            assert_eq!(s.auth_package_len, 0);

            assert_eq!(peios_logon_sessions_next(&mut r, out.as_mut_ptr()), 1);
            let s = out.assume_init_read();
            assert_eq!(s.logon_session_id, 1007);
            assert_eq!(s.logon_type, 10);
            assert_eq!(s.created_at, 1791103220);
            assert_eq!(s.user_sid_len, 28);
            let package = core::slice::from_raw_parts(s.auth_package as *const u8, 4);
            assert_eq!(package, b"lpsd");

            assert_eq!(peios_logon_sessions_next(&mut r, out.as_mut_ptr()), 0);
        }
    }

    #[test]
    fn a_line_missing_a_field_is_eproto_and_the_walk_goes_on() {
        let mut r = reader(
            b"logon_session_id=1 logon_type=2 auth_package= created_at=1\n\
              logon_session_id=2 user_sid=010100000000000512000000 logon_type=2 \
              auth_package= created_at=1 later=x\n",
        );
        let mut out = core::mem::MaybeUninit::<peios_logon_session>::uninit();
        unsafe {
            assert_eq!(peios_logon_sessions_next(&mut r, out.as_mut_ptr()), -1);
            assert_eq!(peios_logon_sessions_next(&mut r, out.as_mut_ptr()), 1);
            assert_eq!(out.assume_init_read().logon_session_id, 2);
        }
    }
}
