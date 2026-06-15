//! `<peios/registry.h>` — LCS, the Peios registry (Layered Configuration Subsystem).
//!
//! LCS is Peios's kernel-mediated, access-controlled configuration store, modelled
//! on the Windows registry: a hierarchy of **keys** (identified by immutable GUIDs,
//! secured by KACS security descriptors) holding typed **values**, with every write
//! tagged by a precedence-ordered **layer** so the effective view is resolved from
//! the highest-precedence entry. This module is the **registry client** surface —
//! opening keys, reading/writing values, enumerating, watching, and transactions.
//!
//! It deliberately does **not** cover the registry *source* (storage-backend) side:
//! `REG_SRC_REGISTER` and the RSI (Registry Source Interface) framed protocol live
//! in a future separate `librsi`. A client never speaks RSI; it speaks syscalls and
//! key/transaction-fd ioctls.
//!
//! ## Kernel entry shape
//!
//! Three syscalls create fds — [`key::peios_reg_open_key`] (1100),
//! [`key::peios_reg_create_key`] (1101), and
//! [`transaction::peios_reg_begin_transaction`] (1102). Everything else is an ioctl
//! on a key fd or a transaction fd (type byte `'R'`); the encoded command numbers
//! come verbatim from the kernel's own `REG_IOC_*` constants in `peios_uapi`, so the
//! `_IOC(dir, size, …)` encoding can never drift. Each ioctl maps to a required
//! access right that the kernel checks against the fd's open-time granted mask.
//!
//! The kernel returns `-errno` directly and libc translates it, so — as with every
//! other libpeios kernel path — the errno passes straight through to the caller
//! (`int` = fd/0/`-1`; the buffer-returning `_IOWR` ops reshape sizes into the
//! getxattr/`ERANGE` contract). All cross-boundary paths are exercised live under
//! Provium; `cargo test` covers the pure marshalling.
//!
//! Wire constants — value types (`REG_SZ`…`REG_QWORD`), key access rights
//! (`KEY_*`), open/create flags, transaction states (`REG_TXN_*`), watch filters
//! (`REG_NOTIFY_*`), and security-info bits — come from `<pkm/lcs.h>`.

use core::ffi::{c_int, c_ulong, c_void};

pub mod backup;
pub mod key;
pub mod security;
pub mod transaction;
pub mod value;

/// Issue a key- or transaction-fd ioctl whose argument is a `&mut T` struct: the
/// kernel reads it and, for the `_IOWR` codes, writes results back into it. The
/// encoded `request` is one of the uapi `REG_IOC_*` constants. Returns 0, or `-1`
/// with `errno` set (libc translates the kernel's `-errno`).
///
/// # Safety
/// `fd` must be the fd kind `request` expects, and `T` must be exactly the
/// `reg_*_args` struct that ioctl reads/writes.
pub(crate) unsafe fn ioctl_struct<T>(fd: c_int, request: u64, args: &mut T) -> c_int {
    crate::sys::ioctl(fd, request as c_ulong, args as *mut T as *mut c_void)
}
