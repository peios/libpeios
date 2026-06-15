//! Registry backup and restore — export or replace a key subtree through an fd.
//!
//! Both are privileged whole-subtree operations keyed off an open key fd: backup
//! streams the key and everything beneath it to a caller-provided fd, and restore
//! reads such a stream back, replacing the subtree inside one transaction. The
//! stream format (magic `"PEIOSREG"`, typed records) is the kernel's; libpeios just
//! hands the fds across. These are thin passthroughs — the kernel does all the work
//! and owns every error.

#![allow(non_camel_case_types)]

use core::ffi::c_int;

use peios_uapi::{reg_backup_args, reg_restore_args, REG_IOC_BACKUP, REG_IOC_RESTORE};

use super::ioctl_struct;

// Pin the (single-fd) wire-struct sizes.
const _: () = assert!(core::mem::size_of::<reg_backup_args>() == 4);
const _: () = assert!(core::mem::size_of::<reg_restore_args>() == 4);

/// `peios_reg_backup` — export the key and its entire subtree to `output_fd`
/// (`SeBackupPrivilege`).
///
/// Takes a read-only snapshot and writes the subtree to `output_fd` in the registry
/// backup format; there is no per-key access check (the privilege stands in). Returns
/// 0, or `-1` with `errno`: `EPERM`/`EACCES` (no privilege), `EBADF` (`output_fd` not
/// writable), `ENOENT` (orphaned key), `ENOTSUP` (source has no read-only snapshots),
/// `EBUSY`.
///
/// # Safety
/// `key_fd` must be a registry key fd; `output_fd` an fd open for writing.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_backup(key_fd: c_int, output_fd: c_int) -> c_int {
    let mut a = reg_backup_args::default();
    a.output_fd = output_fd;
    ioctl_struct(key_fd, REG_IOC_BACKUP, &mut a)
}

/// `peios_reg_restore` — replace the key and its entire subtree from `input_fd`
/// (`SeRestorePrivilege`).
///
/// Reads a backup stream from `input_fd` and applies it within a single read-write
/// transaction (rejecting layer records with precedence > 0 unless the caller holds
/// `SeTcbPrivilege`). Returns 0, or `-1` with `errno`: `EPERM`/`EACCES` (no
/// privilege), `EBADF` (`input_fd` not readable), `EINVAL` (malformed stream),
/// `EEXIST` (GUID collision), `EOVERFLOW`.
///
/// # Safety
/// `key_fd` must be a registry key fd; `input_fd` an fd open for reading.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_restore(key_fd: c_int, input_fd: c_int) -> c_int {
    let mut a = reg_restore_args::default();
    a.input_fd = input_fd;
    ioctl_struct(key_fd, REG_IOC_RESTORE, &mut a)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_sizes_pinned() {
        assert_eq!(core::mem::size_of::<reg_backup_args>(), 4);
        assert_eq!(core::mem::size_of::<reg_restore_args>(), 4);
    }
}
