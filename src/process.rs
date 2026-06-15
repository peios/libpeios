//! `<peios/process.h>` — Peios process security context.
//!
//! Currently the home of the process-security-block (PSB) mitigation control:
//! `peios_process_set_mitigations` over `kacs_set_psb` (syscall 1005). It crosses
//! the kernel boundary and packs no argument struct (a direct two-argument
//! syscall), so there is nothing to unit-test — it is exercised live under
//! Provium, like the other fd-returning / passthrough syscall wrappers.

use core::ffi::{c_int, c_long};

use peios_uapi::SYS_KACS_SET_PSB;

use crate::sys::{ret_int, syscall2};

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
