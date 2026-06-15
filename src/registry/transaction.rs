//! Registry transactions — begin, commit, and status, over transaction fds.
//!
//! [`peios_reg_begin_transaction`] (1102) allocates a transaction fd; mutating key
//! operations enlist in it by passing its fd as their `txn_fd`, giving atomic
//! multi-operation commits with read-your-own-writes isolation. The transaction
//! binds to a single source/hive on first use (cross-hive use is `EXDEV`).
//!
//! [`peios_reg_commit`] atomically commits everything enlisted; on success the fd
//! enters the terminal `COMMITTED` state and further operations on it return
//! `EINVAL`. Closing a transaction fd without committing aborts it.
//! [`peios_reg_txn_status`] reads the fd's current `REG_TXN_*` state and, for a
//! terminal failure state, the errno that ended it.

#![allow(non_camel_case_types)]

use core::ffi::c_int;

use peios_uapi::{reg_txn_status_args, REG_IOC_COMMIT, REG_IOC_TXN_STATUS, SYS_REG_BEGIN_TRANSACTION};

use crate::sys::{ioctl, ret_int, syscall0};

// The status struct is the wire format verbatim; pin its size.
const _: () = assert!(core::mem::size_of::<reg_txn_status_args>() == 8);

/// `peios_reg_begin_transaction` — start a new registry transaction.
///
/// Returns a transaction fd, or `-1` with `errno` (`ENOMEM`). The fd is initially
/// unbound; it binds to a source on its first enlisted operation. Pass the fd as
/// the `txn_fd` argument of key creates and the mutating value/key ioctls to
/// enlist them, then [`peios_reg_commit`] to apply atomically (or `close()` to
/// abort).
#[no_mangle]
pub extern "C" fn peios_reg_begin_transaction() -> c_int {
    // SAFETY: argument-less syscall with no userspace pointers.
    ret_int(unsafe { syscall0(SYS_REG_BEGIN_TRANSACTION) })
}

/// `peios_reg_commit` — atomically commit all operations enlisted in `txn_fd`.
///
/// Returns 0 on commit, or `-1` with `errno`: `EINVAL` (already committed, or never
/// bound to a source), `EBUSY` (write-lock contention — the transaction stays
/// active, retry), `EIO` (source failure — stays active), `ETIMEDOUT`. After a
/// successful commit the fd is terminal; close it.
///
/// # Safety
/// `txn_fd` must be a transaction fd from [`peios_reg_begin_transaction`].
#[no_mangle]
pub unsafe extern "C" fn peios_reg_commit(txn_fd: c_int) -> c_int {
    // REG_IOC_COMMIT is an argument-less `_IO` code.
    ioctl(txn_fd, REG_IOC_COMMIT as core::ffi::c_ulong, core::ptr::null_mut())
}

/// `peios_reg_txn_status` — read the state of a transaction fd.
///
/// Writes the `REG_TXN_*` state to `*state_out` (if non-NULL) and, for a terminal
/// failure state (`REG_TXN_ABORTED` / `TIMED_OUT` / `SOURCE_DOWN`), the ending
/// errno to `*terminal_errno_out` (if non-NULL; 0 while active or on a clean
/// `COMMITTED`). Returns 0, or `-1` with `errno`.
///
/// # Safety
/// `txn_fd` must be a transaction fd; `state_out` / `terminal_errno_out` each NULL
/// or valid for a `u32` / `int` write respectively.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_txn_status(
    txn_fd: c_int,
    state_out: *mut u32,
    terminal_errno_out: *mut c_int,
) -> c_int {
    let mut args = reg_txn_status_args::default();
    let r = super::ioctl_struct(txn_fd, REG_IOC_TXN_STATUS, &mut args);
    if r < 0 {
        return -1;
    }
    if !state_out.is_null() {
        *state_out = args.state;
    }
    if !terminal_errno_out.is_null() {
        *terminal_errno_out = args.terminal_errno;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txn_status_args_size_pinned() {
        assert_eq!(core::mem::size_of::<reg_txn_status_args>(), 8);
    }

    #[test]
    fn commit_ioctl_code_is_io_encoded() {
        // _IO('R', 16): dir=0, size=0, type=0x52, nr=16 → 0x00005210 = 21008.
        assert_eq!(REG_IOC_COMMIT, 21008);
    }

    #[test]
    fn txn_status_ioctl_code_is_ior_encoded() {
        // _IOR('R', 17, reg_txn_status_args=8): dir=2, size=8, type=0x52, nr=17
        // → 0x80085211 = 2148028945.
        assert_eq!(REG_IOC_TXN_STATUS, 2148028945);
    }
}
