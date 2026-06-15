//! Registry keys — opening, creation, and the key-identity ioctls.
//!
//! [`peios_reg_open_key`] (1100) opens an existing key; [`peios_reg_create_key`]
//! (1101) opens-or-creates one and reports which happened. Both return an ordinary
//! Linux fd whose granted access mask is fixed for the fd's lifetime (a capability,
//! computed once by the kernel's `AccessCheck` at open time). The remaining
//! operations here act on that fd: enumerate subkeys, query metadata, delete/hide
//! the key in a layer, arm change watches, and flush. Values live in
//! [`super::value`]; security descriptors in [`super::security`].
//!
//! Paths (and the create `layer`) are NUL-terminated — `reg_create_key_args`
//! carries a bare `layer_ptr` with no length, unlike the length-counted layer the
//! delete/hide ioctls take. A NULL/empty `layer` selects the reserved base layer
//! (precedence 0; for the length-counted ioctls, base is `layer == NULL` with
//! `layer_len == 0`). The buffer-returning reads ([`peios_reg_enum_subkey`],
//! [`peios_reg_query_key_info`]) use the registry-wide fill-or-`ERANGE` contract
//! (see [`super::value`]): a zero-capacity name buffer probes the required length.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_void};

use peios_uapi::{
    reg_create_key_args, reg_delete_key_args, reg_enum_subkey_args, reg_hide_key_args,
    reg_notify_args, reg_query_key_info_args, REG_IOC_DELETE_KEY, REG_IOC_ENUM_SUBKEYS,
    REG_IOC_FLUSH, REG_IOC_HIDE_KEY, REG_IOC_NOTIFY, REG_IOC_QUERY_KEY_INFO, SYS_REG_CREATE_KEY,
    SYS_REG_OPEN_KEY,
};

use crate::error::{get_errno, set_errno};
use crate::sys::{ioctl, ret_int, syscall1, syscall4};

use super::ioctl_struct;

// The argument structs are the wire format verbatim; pin their sizes so a layout
// change is caught here rather than sent to the kernel as a wrong-length struct.
const _: () = assert!(core::mem::size_of::<reg_create_key_args>() == 48);
const _: () = assert!(core::mem::size_of::<reg_enum_subkey_args>() == 40);
const _: () = assert!(core::mem::size_of::<reg_query_key_info_args>() == 64);
const _: () = assert!(core::mem::size_of::<reg_delete_key_args>() == 24);
const _: () = assert!(core::mem::size_of::<reg_hide_key_args>() == 24);
const _: () = assert!(core::mem::size_of::<reg_notify_args>() == 8);

/// `peios_reg_open_key` — open an existing registry key.
///
/// Resolves `path` (relative to the key `parent_fd`, or absolute when
/// `parent_fd < 0`), follows symlinks unless `REG_OPEN_LINK` is set in `flags`, and
/// evaluates `AccessCheck` for `desired_access` (`KEY_*` rights) against the key's
/// security descriptor. Returns the key fd, or `-1` with `errno` (`ENOENT`,
/// `EACCES`, `EINVAL`, `ELOOP`, `ENAMETOOLONG`, …).
///
/// # Safety
/// `path` must be a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_open_key(
    parent_fd: c_int,
    path: *const c_char,
    desired_access: u32,
    flags: u32,
) -> c_int {
    if path.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    ret_int(syscall4(
        SYS_REG_OPEN_KEY,
        parent_fd as c_long,
        path as usize as c_long,
        desired_access as c_long,
        flags as c_long,
    ))
}

/// Pack the create-key arguments. Pure and unit-testable: copies the scalars and
/// pointer addresses into the wire struct, leaving the `_pad*` fields zero (the
/// kernel rejects a non-zero pad). No validation beyond what the caller's entry
/// point performs — the kernel owns path/layer/access validation.
fn build_create_key_args(
    parent_fd: c_int,
    path: *const c_char,
    desired_access: u32,
    flags: u32,
    layer: *const c_char,
    txn_fd: c_int,
    disposition_out: *mut u32,
) -> reg_create_key_args {
    let mut args = reg_create_key_args::default();
    args.parent_fd = parent_fd;
    args.path_ptr = path as usize as u64;
    args.desired_access = desired_access;
    args.flags = flags;
    args.layer_ptr = layer as usize as u64;
    args.txn_fd = txn_fd;
    args.disposition_ptr = disposition_out as usize as u64;
    args
}

/// `peios_reg_create_key` — open or create a registry key.
///
/// Opens `path` if it already exists (subject to `AccessCheck` for
/// `desired_access`), else creates it under its parent (subject to
/// `KEY_CREATE_SUB_KEY` and layer-write authorization), assigning a fresh GUID and
/// inheriting a security descriptor. `flags` accepts `REG_OPTION_VOLATILE` /
/// `REG_OPTION_CREATE_LINK`. `layer` is the target layer name, or NULL for the base
/// layer. `txn_fd` enlists the operation in a transaction, or `-1` to auto-commit.
/// `disposition_out`, if non-NULL, receives `REG_CREATED_NEW` or
/// `REG_OPENED_EXISTING`.
///
/// Returns the key fd, or `-1` with `errno`.
///
/// # Safety
/// `path` must be a valid NUL-terminated string; `layer` NULL or a valid
/// NUL-terminated string; `disposition_out` NULL or valid for a `u32` write.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_create_key(
    parent_fd: c_int,
    path: *const c_char,
    desired_access: u32,
    flags: u32,
    layer: *const c_char,
    txn_fd: c_int,
    disposition_out: *mut u32,
) -> c_int {
    if path.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let args = build_create_key_args(
        parent_fd,
        path,
        desired_access,
        flags,
        layer,
        txn_fd,
        disposition_out,
    );
    // The kernel reads the fixed-size struct and guards `disposition_ptr` against
    // NULL itself, so the pointer passes straight through.
    ret_int(syscall1(
        SYS_REG_CREATE_KEY,
        &args as *const reg_create_key_args as usize as c_long,
    ))
}

// ----------------------------------------------------------------------------
// enum_subkey
// ----------------------------------------------------------------------------

/// Descriptor for [`peios_reg_enum_subkey`]: the caller's name buffer (in) and the
/// child key's metadata (out). Mirrors `struct peios_reg_subkey`. A NULL name buffer
/// with zero capacity probes the required name length.
#[repr(C)]
pub struct peios_reg_subkey {
    /// In: buffer receiving the child key's name (NULL to probe its size).
    pub name: *mut c_void,
    /// Out: the child's last-write time (ns since the Unix epoch).
    pub last_write_time: u64,
    /// In: `name` capacity in bytes.
    pub name_cap: u32,
    /// Out: actual name length (or the required length on `ERANGE`).
    pub name_len: u32,
    /// Out: the child's subkey count.
    pub subkey_count: u32,
    /// Out: the child's value count.
    pub value_count: u32,
}

/// `peios_reg_enum_subkey` — read the child key at position `index`.
///
/// Indices are dense over the key's effective (visibility-resolved) children; walk
/// from 0 until `ENOENT`. `txn_fd` enlists a transaction (`-1` for none). There is
/// no per-child access check. On success the name and metadata are written into
/// `*v`; a too-small name buffer returns `ERANGE` with the required `name_len`.
/// Returns 0, or `-1` with `errno` (`ENOENT` past the end, `ERANGE`, `EACCES`, …).
///
/// # Safety
/// `v` valid for writing, with `v->name` valid for `v->name_cap` bytes when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_enum_subkey(
    key_fd: c_int,
    index: u32,
    txn_fd: c_int,
    v: *mut peios_reg_subkey,
) -> c_int {
    let Some(v) = v.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let mut a = reg_enum_subkey_args::default();
    a.index = index;
    a.name_len = v.name_cap; // in: capacity (overwritten with the actual length)
    a.name_ptr = v.name as usize as u64;
    a.txn_fd = txn_fd;
    let r = ioctl_struct(key_fd, REG_IOC_ENUM_SUBKEYS, &mut a);
    if r == 0 {
        v.name_len = a.name_len;
        v.last_write_time = a.last_write_time;
        v.subkey_count = a.subkey_count;
        v.value_count = a.value_count;
        return 0;
    }
    if get_errno() == libc::ERANGE {
        v.name_len = a.name_len;
    }
    -1
}

// ----------------------------------------------------------------------------
// query_key_info
// ----------------------------------------------------------------------------

/// Descriptor for [`peios_reg_query_key_info`]: the caller's name buffer (in) and
/// the key's metadata (out). Mirrors `struct peios_reg_key_info`. The kernel reports
/// metadata only once the name fits, so size the name buffer first (a zero-capacity
/// probe returns `ERANGE` with the required `name_len`).
#[repr(C)]
pub struct peios_reg_key_info {
    /// In: buffer receiving the key's leaf name (NULL to probe its size).
    pub name: *mut c_void,
    /// Out: last-write time (ns since the Unix epoch).
    pub last_write_time: u64,
    /// Out: per-hive change epoch (bumped on every committed mutation).
    pub hive_generation: u64,
    /// In: `name` capacity in bytes.
    pub name_cap: u32,
    /// Out: actual name length (or the required length on `ERANGE`).
    pub name_len: u32,
    /// Out: number of subkeys.
    pub subkey_count: u32,
    /// Out: number of values.
    pub value_count: u32,
    /// Out: longest subkey-name length.
    pub max_subkey_name_len: u32,
    /// Out: longest value-name length.
    pub max_value_name_len: u32,
    /// Out: largest value-data size.
    pub max_value_data_size: u32,
    /// Out: security-descriptor size in bytes.
    pub sd_size: u32,
    /// Out: 1 if the key is volatile.
    pub volatile_key: u8,
    /// Out: 1 if the key is a symlink.
    pub symlink: u8,
}

/// `peios_reg_query_key_info` — read metadata about the key (`READ_CONTROL`).
///
/// Writes the key's leaf name and counts/sizes/flags into `*v`. The kernel reports
/// metadata only when the name buffer is large enough, so a too-small (or
/// zero-capacity) name buffer returns `ERANGE` with the required `name_len`; size it
/// and call again to obtain the metadata. Returns 0, or `-1` with `errno`.
///
/// # Safety
/// `v` valid for writing, with `v->name` valid for `v->name_cap` bytes when non-NULL.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_query_key_info(
    key_fd: c_int,
    v: *mut peios_reg_key_info,
) -> c_int {
    let Some(v) = v.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let mut a = reg_query_key_info_args::default();
    a.name_len = v.name_cap; // in: capacity (overwritten with the actual length)
    a.name_ptr = v.name as usize as u64;
    let r = ioctl_struct(key_fd, REG_IOC_QUERY_KEY_INFO, &mut a);
    if r == 0 {
        v.name_len = a.name_len;
        v.last_write_time = a.last_write_time;
        v.hive_generation = a.hive_generation;
        v.subkey_count = a.subkey_count;
        v.value_count = a.value_count;
        v.max_subkey_name_len = a.max_subkey_name_len;
        v.max_value_name_len = a.max_value_name_len;
        v.max_value_data_size = a.max_value_data_size;
        v.sd_size = a.sd_size;
        v.volatile_key = a.volatile_key;
        v.symlink = a.symlink;
        return 0;
    }
    // On ERANGE only the required name length is meaningful; the caller resizes and
    // retries to obtain the metadata.
    if get_errno() == libc::ERANGE {
        v.name_len = a.name_len;
    }
    -1
}

// ----------------------------------------------------------------------------
// delete_key / hide_key
// ----------------------------------------------------------------------------

/// `peios_reg_delete_key` — remove this key's path entry in a layer.
///
/// Acts on the named layer (NULL/0 = base); lower-precedence path entries re-emerge.
/// Cannot delete a hive root (`EINVAL`) or a key with visible children
/// (`ENOTEMPTY`). `txn_fd` enlists a transaction (`-1` to auto-commit). Returns 0,
/// or `-1` with `errno` (`DELETE` access required).
///
/// # Safety
/// `layer` valid for `layer_len` bytes (or NULL when 0).
#[no_mangle]
pub unsafe extern "C" fn peios_reg_delete_key(
    key_fd: c_int,
    layer: *const c_void,
    layer_len: u32,
    txn_fd: c_int,
) -> c_int {
    let mut a = reg_delete_key_args::default();
    a.layer_len = layer_len;
    a.layer_ptr = layer as usize as u64;
    a.txn_fd = txn_fd;
    ioctl_struct(key_fd, REG_IOC_DELETE_KEY, &mut a)
}

/// `peios_reg_hide_key` — create a HIDDEN path entry masking this key in a layer.
///
/// Unlike delete, this writes a tombstone in the named layer (NULL/0 = base):
/// removing that layer makes the lower-precedence key reappear. Cannot hide a hive
/// root (`EINVAL`). `txn_fd` enlists a transaction (`-1` to auto-commit). Returns 0,
/// or `-1` with `errno` (`DELETE` access required).
///
/// # Safety
/// `layer` valid for `layer_len` bytes (or NULL when 0).
#[no_mangle]
pub unsafe extern "C" fn peios_reg_hide_key(
    key_fd: c_int,
    layer: *const c_void,
    layer_len: u32,
    txn_fd: c_int,
) -> c_int {
    let mut a = reg_hide_key_args::default();
    a.layer_len = layer_len;
    a.layer_ptr = layer as usize as u64;
    a.txn_fd = txn_fd;
    ioctl_struct(key_fd, REG_IOC_HIDE_KEY, &mut a)
}

// ----------------------------------------------------------------------------
// notify / flush
// ----------------------------------------------------------------------------

/// `peios_reg_notify` — arm (or, with `filter == 0`, disarm) change watches on the
/// key fd (`KEY_NOTIFY`).
///
/// `filter` is a mask of `REG_NOTIFY_VALUE` / `REG_NOTIFY_SUBKEY` / `REG_NOTIFY_SD`
/// (`REG_NOTIFY_ALL` for all). `subtree` (0 or 1) extends watching to descendants.
/// Once armed the fd is pollable (`EPOLLIN` = events pending) and `read()` returns
/// the change records. Returns 0, or `-1` with `errno` (`ENOENT` on an orphaned key,
/// `EINVAL` on a bad filter/subtree, `EACCES`).
///
/// # Safety
/// `key_fd` must be a registry key fd.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_notify(key_fd: c_int, filter: u32, subtree: c_int) -> c_int {
    let mut a = reg_notify_args::default();
    a.filter = filter;
    a.subtree = subtree as u8;
    ioctl_struct(key_fd, REG_IOC_NOTIFY, &mut a)
}

/// `peios_reg_flush` — force the source to persist this key's hive's pending writes
/// (`KEY_SET_VALUE`). Returns when persistence is confirmed. Returns 0, or `-1` with
/// `errno`.
///
/// # Safety
/// `key_fd` must be a registry key fd.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_flush(key_fd: c_int) -> c_int {
    // REG_IOC_FLUSH is an argument-less `_IO` code.
    ioctl(key_fd, REG_IOC_FLUSH as core::ffi::c_ulong, core::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;
    use peios_uapi::REG_OPTION_VOLATILE;

    #[test]
    fn struct_sizes_pinned() {
        assert_eq!(core::mem::size_of::<reg_create_key_args>(), 48);
        assert_eq!(core::mem::size_of::<reg_enum_subkey_args>(), 40);
        assert_eq!(core::mem::size_of::<reg_query_key_info_args>(), 64);
        assert_eq!(core::mem::size_of::<reg_delete_key_args>(), 24);
        assert_eq!(core::mem::size_of::<reg_hide_key_args>(), 24);
        assert_eq!(core::mem::size_of::<reg_notify_args>(), 8);
    }

    #[test]
    fn build_create_key_args_packs_fields() {
        let path = b"Machine\\Software\\App\0";
        let layer = b"base\0";
        let mut disp: u32 = 0;
        let args = build_create_key_args(
            -1,
            path.as_ptr() as *const c_char,
            0x0002_0019, // KEY_READ
            REG_OPTION_VOLATILE,
            layer.as_ptr() as *const c_char,
            7,
            &mut disp as *mut u32,
        );
        assert_eq!(args.parent_fd, -1);
        assert_eq!(args.path_ptr, path.as_ptr() as usize as u64);
        assert_eq!(args.desired_access, 0x0002_0019);
        assert_eq!(args.flags, REG_OPTION_VOLATILE);
        assert_eq!(args.layer_ptr, layer.as_ptr() as usize as u64);
        assert_eq!(args.txn_fd, 7);
        assert_eq!(args.disposition_ptr, &mut disp as *mut u32 as usize as u64);
        // Padding must stay zero — the kernel rejects a non-zero pad.
        assert_eq!(args._pad0, 0);
        assert_eq!(args._pad1, 0);
    }

    #[test]
    fn build_create_key_args_null_layer_is_zero_ptr() {
        let path = b"Machine\\X\0";
        let args = build_create_key_args(
            -1,
            path.as_ptr() as *const c_char,
            1,
            0,
            core::ptr::null(),
            -1,
            core::ptr::null_mut(),
        );
        assert_eq!(args.layer_ptr, 0);
        assert_eq!(args.disposition_ptr, 0);
        assert_eq!(args.txn_fd, -1);
    }
}
