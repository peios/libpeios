//! `<peios/process.h>` — Peios process security context.
//!
//! The home of the process security block (PSB): turning on mitigations with
//! `peios_process_set_mitigations` over `kacs_set_psb` (syscall 1005), and
//! reading a process's PSB with `peios_process_psb` from `/proc/<pid>/psb`.
//! The set is a passthrough syscall exercised live under Provium; the read's
//! parser is unit-tested here.

use core::ffi::{c_char, c_int, c_long};

use peios_uapi::{
    kacs_generic_mapping, KACS_ACCESS_READ_CONTROL, KACS_ACCESS_WRITE_DAC,
    KACS_ACCESS_WRITE_OWNER, KACS_PROCESS_DUP_HANDLE, KACS_PROCESS_QUERY_INFORMATION,
    KACS_PROCESS_QUERY_LIMITED, KACS_PROCESS_SET_INFORMATION, KACS_PROCESS_SIGNAL,
    KACS_PROCESS_SUSPEND_RESUME, KACS_PROCESS_TERMINATE, KACS_PROCESS_VM_READ,
    KACS_PROCESS_VM_WRITE, SYS_KACS_SET_PSB,
};

use crate::error::set_errno;
use crate::kfile::{decimal, field, hex_into, read_whole};
use crate::sys::{ret_int, syscall2};

// ----------------------------------------------------------------------------
// peios_process_generic_mapping
// ----------------------------------------------------------------------------

/// Composed from the named uapi rights, mirroring the kernel's process generic
/// mapping (`kacs_core::access_mask::PROCESS_GENERIC_MAPPING`) and pinned by
/// the asserts below, so that a program asking what a process's descriptor
/// grants it maps the generic rights as the kernel will.
const PROCESS_READ: u32 =
    KACS_PROCESS_QUERY_INFORMATION | KACS_PROCESS_VM_READ | KACS_ACCESS_READ_CONTROL;
const PROCESS_WRITE: u32 =
    KACS_PROCESS_SET_INFORMATION | KACS_PROCESS_VM_WRITE | KACS_ACCESS_WRITE_DAC;
const PROCESS_EXECUTE: u32 =
    KACS_PROCESS_TERMINATE | KACS_PROCESS_SUSPEND_RESUME | KACS_PROCESS_QUERY_LIMITED;
const PROCESS_ALL: u32 = KACS_PROCESS_TERMINATE
    | KACS_PROCESS_SIGNAL
    | KACS_PROCESS_SUSPEND_RESUME
    | KACS_PROCESS_VM_READ
    | KACS_PROCESS_VM_WRITE
    | KACS_PROCESS_DUP_HANDLE
    | KACS_PROCESS_SET_INFORMATION
    | KACS_PROCESS_QUERY_INFORMATION
    | KACS_PROCESS_QUERY_LIMITED
    | KACS_ACCESS_READ_CONTROL
    | KACS_ACCESS_WRITE_DAC
    | KACS_ACCESS_WRITE_OWNER;

const _: () = {
    assert!(PROCESS_READ == 0x0002_0410);
    assert!(PROCESS_WRITE == 0x0004_0220);
    assert!(PROCESS_EXECUTE == 0x0000_1801);
    assert!(PROCESS_ALL == 0x000E_1E73);
};

/// `peios_process_generic_mapping` — the canonical KACS generic mapping for
/// the process object class, exported as a read-only data symbol (mirrors the
/// kernel).
#[no_mangle]
pub static peios_process_generic_mapping: kacs_generic_mapping = kacs_generic_mapping {
    read: PROCESS_READ,
    write: PROCESS_WRITE,
    execute: PROCESS_EXECUTE,
    all: PROCESS_ALL,
};

/// `struct peios_psb` — a process's PSB as `/proc/<pid>/psb` gives it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct peios_psb {
    /// PIP type: 0 for none, 512 for Protected.
    pub pip_type: u32,
    /// PIP trust within the type: 8192 for PeiosTcb.
    pub pip_trust: u32,
    /// The committed `KACS_MIT_*` bits.
    pub mitigations: u32,
    /// The process's GUID, 16 bytes in the order the kernel prints them.
    pub process_guid: [u8; 16],
}

/// Parse one `/proc/<pid>/psb` line. `None` if a known field is missing or
/// malformed; unknown fields are ignored.
fn parse_psb(text: &[u8]) -> Option<peios_psb> {
    let line = text.split(|&b| b == b'\n').next()?;
    let u32_of = |key: &[u8]| decimal(field(line, key)?).and_then(|n| u32::try_from(n).ok());
    let mitigations = field(line, b"mitigations")?.strip_prefix(b"0x")?;
    if mitigations.is_empty() || mitigations.len() > 8 {
        return None;
    }
    let mitigations = mitigations.iter().try_fold(0u32, |n, &b| {
        Some(n << 4 | (b as char).to_digit(16)?)
    })?;
    let guid_text: alloc::vec::Vec<u8> = field(line, b"process_guid")?
        .iter()
        .copied()
        .filter(|&b| b != b'-')
        .collect();
    let mut guid = alloc::vec::Vec::new();
    hex_into(&guid_text, &mut guid)?.ok()?;
    Some(peios_psb {
        pip_type: u32_of(b"pip_type")?,
        pip_trust: u32_of(b"pip_trust")?,
        mitigations,
        process_guid: guid.try_into().ok()?,
    })
}

/// `peios_process_psb` — read process `pid`'s PSB into `*out`.
///
/// `pid <= 0` reads the caller's own. Another process's needs
/// `PROCESS_QUERY_LIMITED` on its descriptor and not PIP dominance, so a
/// protected process's PIP is readable when nothing else about it is.
///
/// Returns 0, or `-1` with errno: whatever opening or reading the file said
/// (`ENOENT` for a process that is gone, `EACCES` when refused), `EPROTO` for
/// a line this library cannot read, `EINVAL` for a NULL `out`.
///
/// # Safety
/// `out` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn peios_process_psb(pid: c_int, out: *mut peios_psb) -> c_int {
    if out.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    // "/proc/" + up to 10 digits + "/psb" + NUL, or "/proc/self/psb".
    let mut path = [0u8; 32];
    let mut len = 0;
    let mut push = |bytes: &[u8]| {
        path[len..len + bytes.len()].copy_from_slice(bytes);
        len += bytes.len();
    };
    push(b"/proc/");
    if pid <= 0 {
        push(b"self");
    } else {
        let mut digits = [0u8; 10];
        let mut n = pid as u32;
        let mut i = digits.len();
        loop {
            i -= 1;
            digits[i] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        push(&digits[i..]);
    }
    push(b"/psb\0");
    let text = match read_whole(path.as_ptr() as *const c_char) {
        Ok(text) => text,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };
    match parse_psb(&text) {
        Some(psb) => {
            out.write(psb);
            0
        }
        None => {
            set_errno(libc::EPROTO);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_kernels_line() {
        let psb = parse_psb(
            b"pip_type=512 pip_trust=8192 mitigations=0x105 \
              process_guid=3f2c9a1e-6b0d-4c8e-9a41-2d7e5f10b6c3\n",
        )
        .unwrap();
        assert_eq!(psb.pip_type, 512);
        assert_eq!(psb.pip_trust, 8192);
        assert_eq!(psb.mitigations, 0x105);
        assert_eq!(psb.process_guid[0], 0x3f);
        assert_eq!(psb.process_guid[15], 0xc3);
    }

    #[test]
    fn ignores_fields_it_does_not_know_and_refuses_missing_ones() {
        assert!(parse_psb(
            b"pip_type=0 later=1 pip_trust=0 mitigations=0x000 \
              process_guid=00000000-0000-0000-0000-000000000000\n"
        )
        .is_some());
        assert!(parse_psb(b"pip_type=0 pip_trust=0 mitigations=0x000\n").is_none());
        assert!(parse_psb(
            b"pip_type=0 pip_trust=0 mitigations=105 \
              process_guid=00000000-0000-0000-0000-000000000000\n"
        )
        .is_none());
        assert!(parse_psb(
            b"pip_type=0 pip_trust=0 mitigations=0x0 process_guid=0011\n"
        )
        .is_none());
    }
}

/// `peios_process_set_mitigations` — turn on process mitigation bits.
///
/// One-way: bits can only be set, never cleared. `mitigations` is a mask of
/// `KACS_MIT_*` bits (`<pkm/psb.h>`); `pidfd == -1` targets the calling process,
/// otherwise it is a real pidfd (targeting another process needs
/// `PROCESS_SET_INFORMATION` on it plus PIP dominance). The call is
/// activation-backed — a requested protection that cannot be activated fails
/// closed without mutating anything — and the kernel validates the mask against
/// `KACS_MIT_ALL` (and expands the `KACS_MIT_CFI` legacy alias). The mask is
/// therefore passed straight through: client-side filtering would only risk
/// diverging from the kernel's authoritative valid-bit set.
///
/// Returns 0 on success, `-1` with `errno` on failure (`EINVAL` for bits outside
/// `KACS_MIT_ALL`, `ENODEV` when the requested CFI hardware is absent,
/// `EACCES` / `ESRCH` for an inaccessible or missing target, …).
///
/// # Safety
/// Crosses the syscall boundary but dereferences no userspace memory; `pidfd`
/// must be `-1` or a valid pidfd.
#[no_mangle]
pub unsafe extern "C" fn peios_process_set_mitigations(pidfd: c_int, mitigations: u32) -> c_int {
    ret_int(syscall2(
        SYS_KACS_SET_PSB,
        pidfd as c_long,
        mitigations as c_long,
    ))
}
