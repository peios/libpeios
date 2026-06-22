//! SDDL codec + SD inheritance C ABI — `peios_sddl_*` / `peios_sd_*`
//! (`<peios/security.h>`).
//!
//! Thin `extern "C"` shims over the vendored pure-Rust [`super::sddl`] logic.
//! Every byte-returning entry follows libpeios's size-probe contract via
//! [`crate::abi::emit_bytes`] / [`emit_str`]: pass `cap == 0` (or a NULL
//! buffer) to probe for the required length, then call again with a buffer
//! that large; a too-small non-zero buffer fails with `ERANGE` and writes
//! nothing. Malformed input fails with `EINVAL`.

use core::ffi::{c_char, c_int, c_void};
use core::slice;

use crate::abi::{cstr_bytes, emit_bytes, emit_str};
use crate::error::set_errno;
use crate::security::sddl::codec::SecurityDescriptor;
use crate::security::sddl::{grammar, inherit};

/// Upper bound on an accepted SDDL / conditional-expression string. A full
/// descriptor with a large DACL is well under this; anything longer or
/// unterminated within the window is rejected.
const MAX_SDDL_TEXT: usize = 65536;

/// Borrow `len` bytes at `ptr`, or `None` if `ptr` is NULL. A zero-length
/// view of a NULL pointer is treated as invalid (the codec needs real input).
unsafe fn input(ptr: *const c_void, len: usize) -> Option<&'static [u8]> {
    if ptr.is_null() {
        return None;
    }
    Some(slice::from_raw_parts(ptr as *const u8, len))
}

/// Parse SDDL text into self-relative SECURITY_DESCRIPTOR wire bytes.
#[no_mangle]
pub unsafe extern "C" fn peios_sddl_parse_sd(
    out: *mut c_void,
    cap: usize,
    sddl: *const c_char,
) -> isize {
    let Some(bytes) = (if sddl.is_null() { None } else { cstr_bytes(sddl, MAX_SDDL_TEXT) }) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let Ok(s) = core::str::from_utf8(bytes) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match grammar::parse(s).ok().and_then(|b| b.build().ok()) {
        Some(v) => emit_bytes(&v, out as *mut u8, cap),
        None => {
            set_errno(libc::EINVAL);
            -1
        }
    }
}

/// Render a self-relative SECURITY_DESCRIPTOR to NUL-terminated SDDL text.
/// Returns the string length excluding the NUL (so allocate `len + 1`).
#[no_mangle]
pub unsafe extern "C" fn peios_sddl_format_sd(
    out: *mut c_char,
    cap: usize,
    sd: *const c_void,
    sd_len: usize,
) -> isize {
    let Some(bytes) = input(sd, sd_len) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let Ok(parsed) = SecurityDescriptor::parse(bytes) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match grammar::format(&parsed) {
        Ok(s) => emit_str(s.as_bytes(), out, cap),
        Err(_) => {
            set_errno(libc::EINVAL);
            -1
        }
    }
}

/// Parse an SDDL conditional expression to its `"artx"` callback-ACE bytecode.
#[no_mangle]
pub unsafe extern "C" fn peios_sddl_parse_condition(
    out: *mut c_void,
    cap: usize,
    expr: *const c_char,
) -> isize {
    let Some(bytes) = (if expr.is_null() { None } else { cstr_bytes(expr, MAX_SDDL_TEXT) }) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let Ok(s) = core::str::from_utf8(bytes) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match grammar::parse_condition_to_artx(s) {
        Ok(artx) => emit_bytes(&artx, out as *mut u8, cap),
        Err(_) => {
            set_errno(libc::EINVAL);
            -1
        }
    }
}

/// Render `"artx"` callback-ACE bytecode back to NUL-terminated SDDL
/// conditional-expression text (no outer parens).
#[no_mangle]
pub unsafe extern "C" fn peios_sddl_format_condition(
    out: *mut c_char,
    cap: usize,
    artx: *const c_void,
    len: usize,
) -> isize {
    let Some(bytes) = input(artx, len) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match grammar::format_condition_from_artx(bytes) {
        Ok(s) => emit_str(s.as_bytes(), out, cap),
        Err(_) => {
            set_errno(libc::EINVAL);
            -1
        }
    }
}

/// Reinherit a child SD from a parent SD: strip the child DACL's inherited
/// ACEs, recompute and append them from the parent DACL, pass owner/group/
/// SACL and the control bits through. Both inputs self-relative; output
/// self-relative. `is_container != 0` for a container child.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_reinherit(
    out: *mut c_void,
    cap: usize,
    parent_sd: *const c_void,
    parent_len: usize,
    child_sd: *const c_void,
    child_len: usize,
    is_container: c_int,
) -> isize {
    let (Some(parent), Some(child)) = (input(parent_sd, parent_len), input(child_sd, child_len))
    else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match inherit::reinherit(parent, child, is_container != 0) {
        Ok(v) => emit_bytes(&v, out as *mut u8, cap),
        Err(_) => {
            set_errno(libc::EINVAL);
            -1
        }
    }
}

/// Drop ACEs carrying `ACE_FLAG_INHERITED` from the ACLs selected by `info`
/// (a mask of `*_SECURITY_INFORMATION` bits; DACL/SACL honored, others
/// ignored; neither selected → input copied verbatim). Output self-relative.
#[no_mangle]
pub unsafe extern "C" fn peios_sd_strip_inherited(
    out: *mut c_void,
    cap: usize,
    sd: *const c_void,
    sd_len: usize,
    info: u32,
) -> isize {
    let Some(bytes) = input(sd, sd_len) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match inherit::strip_inherited_aces(bytes, info) {
        Ok(v) => emit_bytes(&v, out as *mut u8, cap),
        Err(_) => {
            set_errno(libc::EINVAL);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::sddl::codec::DACL_SECURITY_INFORMATION;
    use std::ffi::CString;

    /// Two-call size-probe harness for the byte-returning entries.
    unsafe fn collect_bytes(f: impl Fn(*mut c_void, usize) -> isize) -> Vec<u8> {
        let need = f(core::ptr::null_mut(), 0);
        assert!(need >= 0, "probe returned {need}");
        let mut buf = vec![0u8; need as usize];
        let got = f(buf.as_mut_ptr() as *mut c_void, buf.len());
        assert_eq!(got, need, "fill length disagreed with probe");
        buf
    }

    /// Two-call size-probe harness for the string-returning entries.
    unsafe fn collect_str(f: impl Fn(*mut c_char, usize) -> isize) -> String {
        let need = f(core::ptr::null_mut(), 0);
        assert!(need >= 0, "probe returned {need}");
        let mut buf = vec![0u8; need as usize + 1];
        let got = f(buf.as_mut_ptr() as *mut c_char, buf.len());
        assert_eq!(got, need, "fill length disagreed with probe");
        String::from_utf8(buf[..need as usize].to_vec()).unwrap()
    }

    #[test]
    fn sddl_sd_round_trips_through_the_abi() {
        let sddl = CString::new("O:SYG:BAD:(A;;FA;;;BA)(A;;FR;;;BU)").unwrap();
        let sd = unsafe { collect_bytes(|o, c| peios_sddl_parse_sd(o, c, sddl.as_ptr())) };
        assert!(!sd.is_empty());

        let text = unsafe {
            collect_str(|o, c| peios_sddl_format_sd(o, c, sd.as_ptr() as *const c_void, sd.len()))
        };
        assert!(text.starts_with("O:SYG:BA"), "got {text:?}");

        // Re-parsing the formatted text yields identical wire bytes.
        let reparse = CString::new(text).unwrap();
        let sd2 = unsafe { collect_bytes(|o, c| peios_sddl_parse_sd(o, c, reparse.as_ptr())) };
        assert_eq!(sd, sd2, "format/parse not a fixed point");
    }

    #[test]
    fn condition_round_trips_through_the_abi() {
        let expr = CString::new("@User.Title == \"PM\"").unwrap();
        let artx = unsafe { collect_bytes(|o, c| peios_sddl_parse_condition(o, c, expr.as_ptr())) };
        assert!(artx.starts_with(b"artx"), "artx magic missing");
        let back = unsafe {
            collect_str(|o, c| {
                peios_sddl_format_condition(o, c, artx.as_ptr() as *const c_void, artx.len())
            })
        };
        assert!(back.contains("Title"), "got {back:?}");
    }

    #[test]
    fn reinherit_and_strip_accept_a_valid_sd() {
        let sddl = CString::new("O:SYG:BAD:(A;;FA;;;BA)").unwrap();
        let sd = unsafe { collect_bytes(|o, c| peios_sddl_parse_sd(o, c, sddl.as_ptr())) };

        let parent = sd.as_ptr() as *const c_void;
        let child = sd.as_ptr() as *const c_void;
        let reinherited = unsafe {
            collect_bytes(|o, c| peios_sd_reinherit(o, c, parent, sd.len(), child, sd.len(), 1))
        };
        assert!(!reinherited.is_empty());

        let stripped = unsafe {
            collect_bytes(|o, c| {
                peios_sd_strip_inherited(
                    o,
                    c,
                    sd.as_ptr() as *const c_void,
                    sd.len(),
                    DACL_SECURITY_INFORMATION,
                )
            })
        };
        assert!(!stripped.is_empty());
    }

    #[test]
    fn malformed_input_is_einval_and_small_buffer_is_erange() {
        let garbage = CString::new("definitely not sddl").unwrap();
        let r = unsafe { peios_sddl_parse_sd(core::ptr::null_mut(), 0, garbage.as_ptr()) };
        assert_eq!(r, -1);
        assert_eq!(crate::error::get_errno(), libc::EINVAL);

        let sddl = CString::new("O:SYG:BAD:(A;;FA;;;BA)").unwrap();
        let sd = unsafe { collect_bytes(|o, c| peios_sddl_parse_sd(o, c, sddl.as_ptr())) };
        let need =
            unsafe { peios_sddl_format_sd(core::ptr::null_mut(), 0, sd.as_ptr() as *const c_void, sd.len()) };
        assert!(need > 1);
        let mut tiny = vec![0u8; 1];
        let r = unsafe {
            peios_sddl_format_sd(tiny.as_mut_ptr() as *mut c_char, 1, sd.as_ptr() as *const c_void, sd.len())
        };
        assert_eq!(r, -1);
        assert_eq!(crate::error::get_errno(), libc::ERANGE);
    }
}
