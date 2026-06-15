//! KACS error → POSIX `errno` translation.
//!
//! The errno slot itself lives in [`peios_cabi::error`]; this module re-exports the
//! setter/getter (so the rest of libpeios keeps reaching them through `crate::error`)
//! and adds the `kacs_core::KacsError` mapping the KACS entry points use. The C ABI
//! reports failure the C-library way: a sentinel return (`-1`, a null pointer, or an
//! `ERANGE`-style code) with the reason left in `errno`; this module is the single
//! chokepoint that turns a `KacsError` into that code.

use kacs_core::KacsError;

pub(crate) use peios_cabi::error::{get_errno, set_errno};

/// Map a `KacsError` to the `errno` value libpeios reports for it.
///
/// Only three classes carry a code more specific than `EINVAL`: out-of-memory
/// (`ENOMEM`), a denied access check (`EACCES`), and a fault while touching
/// caller-supplied memory (`EFAULT`). Everything else is a malformed or
/// inconsistent input — one `EINVAL` bucket — which the kernel re-validates
/// authoritatively on the real syscall regardless. The catch-all is deliberate:
/// `KacsError` is not `#[non_exhaustive]`, but new structural variants should
/// map to `EINVAL` without forcing a churn here.
pub(crate) fn errno_for(err: &KacsError) -> libc::c_int {
    match err {
        KacsError::AllocationFailure => libc::ENOMEM,
        KacsError::AccessDenied => libc::EACCES,
        KacsError::UserMemoryFault { .. } => libc::EFAULT,
        _ => libc::EINVAL,
    }
}

/// Set `errno` from a `KacsError` and return the `int` failure sentinel `-1`.
#[inline]
#[allow(dead_code)] // Consumed by the int-returning access/check entry points.
pub(crate) fn fail(err: &KacsError) -> libc::c_int {
    set_errno(errno_for(err));
    -1
}
