//! `<peios/file.h>` — KACS native file objects.
//!
//! [`peios_file_open`] is the NtCreateFile-shaped native open (syscall 1020,
//! marshalling a `kacs_open_how`); it returns an ordinary Linux fd whose granted
//! mask is fixed for the fd's lifetime. The SD calls read/write a file's security
//! descriptor by path (1021/1022) or by fd, and the mount-policy calls (1026/1027)
//! govern superblocks without native SD storage. The `peios_file_generic_mapping`
//! data symbol is the canonical generic→specific mapping for the file class.
//!
//! All of these cross the kernel boundary, so they are exercised live under
//! Provium; `cargo test` covers only the pure marshalling
//! ([`build_open_how`], [`emit_len`], and the generic-mapping constant).
//!
//! ## fd-targeted SD via `AT_EMPTY_PATH`
//!
//! KACS exposes no distinct fd-targeted SD syscalls — [`peios_fd_get_sd`] /
//! [`peios_fd_set_sd`] reuse the path syscalls with the target fd as `dirfd`, an
//! empty path, and `AT_EMPTY_PATH` (the standard Linux `*at()` idiom; the kernel
//! requires that bit for an empty path and rejects it for a non-empty one).
//!
//! ## get_sd is adapted to the strict getxattr contract
//!
//! The kernel's `get_sd` returns the *needed* length and copies only when the
//! buffer fits — a too-small non-zero buffer comes back as a length, not an
//! error. libpeios tightens that to the getxattr contract the header promises:
//! `cap == 0` probes, a too-small buffer is `ERANGE` with nothing written (the
//! kernel already declined to copy), never a truncated SD. See [`emit_len`].

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_void};

use peios_uapi::{
    kacs_generic_mapping, kacs_mount_policy_args, kacs_open_how, KACS_ACCESS_DELETE,
    KACS_ACCESS_READ_CONTROL, KACS_ACCESS_SYNCHRONIZE, KACS_ACCESS_WRITE_DAC,
    KACS_ACCESS_WRITE_OWNER, KACS_FILE_APPEND_DATA, KACS_FILE_DELETE_CHILD, KACS_FILE_EXECUTE,
    KACS_FILE_READ_ATTRIBUTES, KACS_FILE_READ_DATA, KACS_FILE_READ_EA, KACS_FILE_WRITE_ATTRIBUTES,
    KACS_FILE_WRITE_DATA, KACS_FILE_WRITE_EA, SYS_KACS_GET_MOUNT_POLICY, SYS_KACS_GET_SD,
    SYS_KACS_OPEN, SYS_KACS_SET_MOUNT_POLICY, SYS_KACS_SET_SD,
};

use crate::abi::u32_len;
use crate::error::set_errno;
use crate::sys::{ret_int, syscall3, syscall5, syscall6};

/// `AT_EMPTY_PATH` — operate on `dirfd` itself when the path is empty. The kernel
/// uses the fixed asm-generic value; we pin it here rather than depend on a libc
/// feature exposing it (confirmed `0x1000` against the KACS handler).
const AT_EMPTY_PATH: u32 = 0x1000;

/// An empty NUL-terminated C string, for the `AT_EMPTY_PATH` fd-targeted calls.
const EMPTY_PATH: &[u8] = b"\0";

// The uapi argument structs are the wire format verbatim; pin their sizes so a
// layout change is caught here, not silently sent as a wrong `howsize`/`argsize`.
const _: () = assert!(core::mem::size_of::<kacs_open_how>() == 32);
const _: () = assert!(core::mem::size_of::<kacs_mount_policy_args>() == 32);

// ----------------------------------------------------------------------------
// peios_file_generic_mapping
// ----------------------------------------------------------------------------

/// Composed from the named uapi rights, mirroring the kernel's file generic
/// mapping (`pkm_kacs_map_file_generic_access_mask`). Kept as named-constant
/// unions and pinned by the asserts below so the exported symbol can never drift
/// from the kernel's mapping — a wrong value here would corrupt access decisions.
const FILE_READ: u32 = KACS_FILE_READ_DATA
    | KACS_FILE_READ_ATTRIBUTES
    | KACS_FILE_READ_EA
    | KACS_ACCESS_READ_CONTROL
    | KACS_ACCESS_SYNCHRONIZE;
const FILE_WRITE: u32 = KACS_FILE_WRITE_DATA
    | KACS_FILE_APPEND_DATA
    | KACS_FILE_WRITE_ATTRIBUTES
    | KACS_FILE_WRITE_EA
    | KACS_ACCESS_READ_CONTROL
    | KACS_ACCESS_SYNCHRONIZE;
const FILE_EXECUTE: u32 = KACS_FILE_EXECUTE
    | KACS_FILE_READ_ATTRIBUTES
    | KACS_ACCESS_READ_CONTROL
    | KACS_ACCESS_SYNCHRONIZE;
const FILE_ALL: u32 = KACS_FILE_READ_DATA
    | KACS_FILE_WRITE_DATA
    | KACS_FILE_APPEND_DATA
    | KACS_FILE_READ_EA
    | KACS_FILE_WRITE_EA
    | KACS_FILE_EXECUTE
    | KACS_FILE_DELETE_CHILD
    | KACS_FILE_READ_ATTRIBUTES
    | KACS_FILE_WRITE_ATTRIBUTES
    | KACS_ACCESS_DELETE
    | KACS_ACCESS_READ_CONTROL
    | KACS_ACCESS_WRITE_DAC
    | KACS_ACCESS_WRITE_OWNER
    | KACS_ACCESS_SYNCHRONIZE;

const _: () = {
    assert!(FILE_READ == 0x0012_0089);
    assert!(FILE_WRITE == 0x0012_0116);
    assert!(FILE_EXECUTE == 0x0012_00A0);
    assert!(FILE_ALL == 0x001F_01FF);
};

/// `peios_file_generic_mapping` — the canonical KACS generic mapping for the file
/// object class, exported as a read-only data symbol (mirrors the kernel).
#[no_mangle]
pub static peios_file_generic_mapping: kacs_generic_mapping = kacs_generic_mapping {
    read: FILE_READ,
    write: FILE_WRITE,
    execute: FILE_EXECUTE,
    all: FILE_ALL,
};

// ----------------------------------------------------------------------------
// peios_file_open
// ----------------------------------------------------------------------------

/// Parameters for [`peios_file_open`]. Mirrors `struct peios_open_params`.
#[repr(C)]
pub struct peios_open_params {
    /// `KACS_FILE_*` | standard | generic (strict-mode) rights.
    pub desired_access: u32,
    /// `KACS_DISPOSITION_*`.
    pub disposition: u32,
    /// `KACS_CREATE_OPT_*`.
    pub options: u32,
    /// `AT_SYMLINK_NOFOLLOW` | `KACS_BACKUP_INTENT` | `KACS_RESTORE_INTENT`.
    pub flags: u32,
    /// Creator security descriptor on create, else NULL.
    pub sd: *const c_void,
    pub sd_len: usize,
}

/// Marshal a [`peios_open_params`] into a `kacs_open_how`. Pure and unit-testable:
/// copies the four masks, sets the creator-SD pointer/length, and rejects a
/// NULL-SD-with-non-zero-length inconsistency (and an over-`u32` length) with
/// `EINVAL`. The kernel reads the size from a separate `howsize` syscall arg, so
/// there is no `caller_size` field to stamp here.
fn build_open_how(p: &peios_open_params) -> Result<kacs_open_how, c_int> {
    if p.sd.is_null() && p.sd_len != 0 {
        return Err(libc::EINVAL);
    }
    Ok(kacs_open_how {
        desired_access: p.desired_access,
        create_disposition: p.disposition,
        create_options: p.options,
        flags: p.flags,
        sd_ptr: p.sd as usize as u64,
        sd_len: u32_len(p.sd_len)?,
        ..Default::default()
    })
}

/// `peios_file_open` — native KACS open of `path` relative to `dirfd`.
///
/// Returns a file fd, or `-1` with `errno`. `status_out`, if non-NULL, receives
/// the `KACS_STATUS_*` disposition (opened / created / …).
///
/// # Safety
/// `path` must be a valid NUL-terminated string; `p` a valid `peios_open_params`
/// whose `sd` is valid for `sd_len` bytes when non-NULL; `status_out` NULL or
/// valid for a `u32` write.
#[no_mangle]
pub unsafe extern "C" fn peios_file_open(
    dirfd: c_int,
    path: *const c_char,
    p: *const peios_open_params,
    status_out: *mut u32,
) -> c_int {
    let Some(p) = p.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if path.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let how = match build_open_how(p) {
        Ok(how) => how,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };
    // The kernel guards `status_out` against NULL itself, so it passes straight
    // through; `howsize` is the full struct we were built against.
    ret_int(syscall5(
        SYS_KACS_OPEN,
        dirfd as c_long,
        path as usize as c_long,
        &how as *const kacs_open_how as usize as c_long,
        core::mem::size_of::<kacs_open_how>() as c_long,
        status_out as usize as c_long,
    ))
}

// ----------------------------------------------------------------------------
// SD get / set (path- and fd-targeted)
// ----------------------------------------------------------------------------

/// Reshape the kernel's `get_sd` return into the getxattr contract.
///
/// `ret` is the non-negative needed length the kernel reports (it copies only
/// when the buffer fits). `cap == 0` is a probe — return the length. A non-zero
/// `cap` smaller than the length means the kernel declined to copy: surface
/// `ERANGE` with nothing written. Otherwise the kernel copied, so return the
/// length.
fn emit_len(ret: c_long, cap: usize) -> isize {
    let need = ret as usize;
    if cap != 0 && need > cap {
        set_errno(libc::ERANGE);
        return -1;
    }
    ret as isize
}

/// Shared body for the path- and fd-targeted SD reads. The kernel copies into
/// `buf` directly; we only validate the NULL-buffer / length cases and reshape
/// the returned length.
///
/// # Safety
/// `path` valid NUL-terminated; `buf` valid for `cap` bytes when `cap != 0`.
unsafe fn get_sd_via_syscall(
    dirfd: c_int,
    path: *const c_char,
    secinfo: u32,
    buf: *mut c_void,
    cap: usize,
    flags: u32,
) -> isize {
    if cap != 0 && buf.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let cap32 = match u32_len(cap) {
        Ok(cap32) => cap32,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };
    let r = syscall6(
        SYS_KACS_GET_SD,
        dirfd as c_long,
        path as usize as c_long,
        secinfo as c_long,
        buf as usize as c_long,
        cap32 as c_long,
        flags as c_long,
    );
    if r < 0 {
        -1
    } else {
        emit_len(r, cap)
    }
}

/// Shared body for the path- and fd-targeted SD writes.
///
/// # Safety
/// `path` valid NUL-terminated; `sd` valid for `len` bytes.
unsafe fn set_sd_via_syscall(
    dirfd: c_int,
    path: *const c_char,
    secinfo: u32,
    sd: *const c_void,
    len: usize,
    flags: u32,
) -> c_int {
    if sd.is_null() || len == 0 {
        set_errno(libc::EINVAL);
        return -1;
    }
    let len32 = match u32_len(len) {
        Ok(len32) => len32,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };
    ret_int(syscall6(
        SYS_KACS_SET_SD,
        dirfd as c_long,
        path as usize as c_long,
        secinfo as c_long,
        sd as usize as c_long,
        len32 as c_long,
        flags as c_long,
    ))
}

/// `peios_file_get_sd` — read a file's security descriptor by path. getxattr-style
/// (`cap == 0` probes; too-small → `ERANGE`, nothing written). `secinfo` selects
/// components (`KACS_SECINFO_*`); `at_flags` accepts `AT_SYMLINK_NOFOLLOW`.
///
/// # Safety
/// See [`get_sd_via_syscall`].
#[no_mangle]
pub unsafe extern "C" fn peios_file_get_sd(
    dirfd: c_int,
    path: *const c_char,
    secinfo: u32,
    buf: *mut c_void,
    cap: usize,
    at_flags: u32,
) -> isize {
    if path.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    get_sd_via_syscall(dirfd, path, secinfo, buf, cap, at_flags)
}

/// `peios_file_set_sd` — write the `secinfo` components of `sd` onto a file by
/// path, preserving the rest.
///
/// # Safety
/// See [`set_sd_via_syscall`].
#[no_mangle]
pub unsafe extern "C" fn peios_file_set_sd(
    dirfd: c_int,
    path: *const c_char,
    secinfo: u32,
    sd: *const c_void,
    len: usize,
    at_flags: u32,
) -> c_int {
    if path.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    set_sd_via_syscall(dirfd, path, secinfo, sd, len, at_flags)
}

/// `peios_fd_get_sd` — read the SD of the object `fd` already refers to (empty
/// path + `AT_EMPTY_PATH`). getxattr-style, like [`peios_file_get_sd`].
///
/// # Safety
/// `buf` valid for `cap` bytes when `cap != 0`.
#[no_mangle]
pub unsafe extern "C" fn peios_fd_get_sd(
    fd: c_int,
    secinfo: u32,
    buf: *mut c_void,
    cap: usize,
) -> isize {
    get_sd_via_syscall(
        fd,
        EMPTY_PATH.as_ptr() as *const c_char,
        secinfo,
        buf,
        cap,
        AT_EMPTY_PATH,
    )
}

/// `peios_fd_set_sd` — write the `secinfo` components of `sd` onto the object `fd`
/// refers to (empty path + `AT_EMPTY_PATH`).
///
/// # Safety
/// `sd` valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn peios_fd_set_sd(
    fd: c_int,
    secinfo: u32,
    sd: *const c_void,
    len: usize,
) -> c_int {
    set_sd_via_syscall(
        fd,
        EMPTY_PATH.as_ptr() as *const c_char,
        secinfo,
        sd,
        len,
        AT_EMPTY_PATH,
    )
}

// ----------------------------------------------------------------------------
// Mount policy
// ----------------------------------------------------------------------------

/// Mount policy for the superblock an fd lives on. Mirrors
/// `struct peios_mount_policy`.
#[repr(C)]
pub struct peios_mount_policy {
    /// `KACS_MOUNT_POLICY_*`.
    pub policy: u32,
    pub flags: u32,
    pub generation: u32,
    /// On get, points into the caller's template buffer when the template fits,
    /// else NULL (no template, or buffer too small — see `template_sd_len`).
    pub template_sd: *const c_void,
    pub template_sd_len: usize,
}

/// `peios_mount_get_policy` — read the mount policy for the superblock `fd` lives
/// on (`SeTcbPrivilege`). The template SD is copied into `tmpl_buf` getxattr-style
/// on that buffer: `out->template_sd` points into it when the whole template fits,
/// otherwise it is NULL while `out->template_sd_len` still reports the true length
/// (0 = no template) so the caller can size a retry.
///
/// # Safety
/// `out` valid for writing; `tmpl_buf` valid for `tmpl_cap` bytes when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn peios_mount_get_policy(
    fd: c_int,
    out: *mut peios_mount_policy,
    tmpl_buf: *mut c_void,
    tmpl_cap: usize,
) -> c_int {
    let Some(out) = out.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if tmpl_cap != 0 && tmpl_buf.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let cap32 = match u32_len(tmpl_cap) {
        Ok(cap32) => cap32,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };
    // Offer the template buffer; the kernel fills the rest in-place and reports
    // the true template length whether or not it copied.
    let mut args = kacs_mount_policy_args {
        template_sd_ptr: tmpl_buf as usize as u64,
        template_sd_len: cap32,
        ..Default::default()
    };
    let r = syscall3(
        SYS_KACS_GET_MOUNT_POLICY,
        fd as c_long,
        &mut args as *mut kacs_mount_policy_args as usize as c_long,
        core::mem::size_of::<kacs_mount_policy_args>() as c_long,
    );
    if r < 0 {
        return -1;
    }
    out.policy = args.policy;
    out.flags = args.flags;
    out.generation = args.generation;
    out.template_sd_len = args.template_sd_len as usize;
    // The kernel copied the template iff it exists, the buffer is real, and it
    // fits; only then does `template_sd` point into the caller's buffer.
    out.template_sd = if args.template_sd_len != 0
        && !tmpl_buf.is_null()
        && tmpl_cap >= args.template_sd_len as usize
    {
        tmpl_buf as *const c_void
    } else {
        core::ptr::null()
    };
    0
}

/// `peios_mount_set_policy` — set the mount policy for the superblock `fd` lives
/// on (`SeTcbPrivilege`). `flags` and `generation` must be zero (the kernel
/// manages the generation and rejects a non-zero input); they are passed through
/// faithfully so that contract violation surfaces as the kernel's `EINVAL`.
///
/// # Safety
/// `p` valid; `p->template_sd` valid for `template_sd_len` bytes when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn peios_mount_set_policy(fd: c_int, p: *const peios_mount_policy) -> c_int {
    let Some(p) = p.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if p.template_sd_len != 0 && p.template_sd.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let template_sd_len = match u32_len(p.template_sd_len) {
        Ok(len) => len,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };
    let args = kacs_mount_policy_args {
        policy: p.policy,
        flags: p.flags,
        generation: p.generation,
        template_sd_ptr: p.template_sd as usize as u64,
        template_sd_len,
        ..Default::default()
    };
    ret_int(syscall3(
        SYS_KACS_SET_MOUNT_POLICY,
        fd as c_long,
        &args as *const kacs_mount_policy_args as usize as c_long,
        core::mem::size_of::<kacs_mount_policy_args>() as c_long,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::get_errno;

    #[test]
    fn file_generic_mapping_matches_kernel() {
        // The values the kernel's pkm_kacs_map_file_generic_access_mask computes.
        assert_eq!(peios_file_generic_mapping.read, 0x0012_0089);
        assert_eq!(peios_file_generic_mapping.write, 0x0012_0116);
        assert_eq!(peios_file_generic_mapping.execute, 0x0012_00A0);
        assert_eq!(peios_file_generic_mapping.all, 0x001F_01FF);
    }

    #[test]
    fn struct_sizes_pinned() {
        assert_eq!(core::mem::size_of::<kacs_open_how>(), 32);
        assert_eq!(core::mem::size_of::<kacs_mount_policy_args>(), 32);
    }

    #[test]
    fn build_open_how_packs_fields() {
        let sd = [0xCCu8; 24];
        let p = peios_open_params {
            desired_access: 0x0012_0089,
            disposition: 2,
            options: 1,
            flags: 0x100,
            sd: sd.as_ptr() as *const c_void,
            sd_len: sd.len(),
        };
        let how = build_open_how(&p).unwrap();
        assert_eq!(how.desired_access, 0x0012_0089);
        assert_eq!(how.create_disposition, 2);
        assert_eq!(how.create_options, 1);
        assert_eq!(how.flags, 0x100);
        assert_eq!(how.sd_ptr, sd.as_ptr() as usize as u64);
        assert_eq!(how.sd_len, 24);
        assert_eq!(how.__pad, 0);
    }

    #[test]
    fn build_open_how_no_sd_is_zeroed() {
        let p = peios_open_params {
            desired_access: 1,
            disposition: 1,
            options: 0,
            flags: 0,
            sd: core::ptr::null(),
            sd_len: 0,
        };
        let how = build_open_how(&p).unwrap();
        assert_eq!(how.sd_ptr, 0);
        assert_eq!(how.sd_len, 0);
    }

    #[test]
    fn build_open_how_null_sd_with_length_is_einval() {
        let p = peios_open_params {
            desired_access: 1,
            disposition: 1,
            options: 0,
            flags: 0,
            sd: core::ptr::null(),
            sd_len: 16,
        };
        assert!(matches!(build_open_how(&p), Err(e) if e == libc::EINVAL));
    }

    #[test]
    fn mount_get_rejects_null_template_buffer_with_capacity() {
        unsafe {
            let mut out = peios_mount_policy {
                policy: 0,
                flags: 0,
                generation: 0,
                template_sd: core::ptr::null(),
                template_sd_len: 0,
            };

            assert_eq!(
                peios_mount_get_policy(-1, &mut out, core::ptr::null_mut(), 1),
                -1
            );
            assert_eq!(get_errno(), libc::EINVAL);
        }
    }

    #[test]
    fn mount_set_rejects_null_template_with_length() {
        unsafe {
            let p = peios_mount_policy {
                policy: 0,
                flags: 0,
                generation: 0,
                template_sd: core::ptr::null(),
                template_sd_len: 1,
            };

            assert_eq!(peios_mount_set_policy(-1, &p), -1);
            assert_eq!(get_errno(), libc::EINVAL);
        }
    }

    #[test]
    fn emit_len_probe_returns_size() {
        // cap == 0 is a size probe: return the length, write nothing.
        assert_eq!(emit_len(40, 0), 40);
    }

    #[test]
    fn emit_len_fits_returns_size() {
        assert_eq!(emit_len(40, 64), 40);
        assert_eq!(emit_len(40, 40), 40); // exact fit
    }

    #[test]
    fn emit_len_too_small_is_erange() {
        assert_eq!(emit_len(40, 16), -1);
        assert_eq!(get_errno(), libc::ERANGE);
    }
}
