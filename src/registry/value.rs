//! Registry value operations — read, write, delete, and enumerate values, as
//! key-fd ioctls.
//!
//! A value is named (length-counted; the empty name is a key's default value),
//! typed (`REG_*`), and written into a specific layer. Reads resolve the effective
//! value across all active layers; writes/deletes/tombstones act on one named
//! layer. Throughout, a **base-layer** target is `layer == NULL` with `layer_len ==
//! 0` (a non-NULL pointer with a zero length is rejected by the kernel as
//! `EINVAL`); any other layer is its length-counted UTF-8 name.
//!
//! ## Buffer-returning reads use the kernel's fill-or-`ERANGE` contract
//!
//! [`peios_reg_query_value`], [`peios_reg_query_values_batch`], and
//! [`peios_reg_enum_value`] copy into caller buffers and return 0 on success with
//! the actual length(s) reported. If a buffer is too small the call returns `-1` /
//! `ERANGE` and writes the *required* length into the corresponding `*_len` field,
//! so the caller can resize and retry; a zero-capacity buffer is therefore a valid
//! size probe (it comes back `ERANGE` with the needed sizes). A NULL buffer with a
//! nonzero capacity is rejected locally with `EINVAL`. For the two-buffer ops,
//! `ERANGE` is returned if *either* buffer is too small and *both* required lengths
//! are reported. This mirrors the `_IOWR` handlers exactly — no reshaping.
//!
//! Only the argument marshalling is `cargo test`-covered; the ioctls themselves are
//! exercised live under Provium.

#![allow(non_camel_case_types)]

use core::ffi::{c_int, c_void};

use peios_uapi::{
    reg_blanket_tombstone_args, reg_delete_value_args, reg_enum_value_args, reg_query_value_args,
    reg_query_values_batch_args, reg_set_value_args, REG_IOC_BLANKET_TOMBSTONE,
    REG_IOC_DELETE_VALUE, REG_IOC_ENUM_VALUES, REG_IOC_QUERY_VALUE, REG_IOC_QUERY_VALUES_BATCH,
    REG_IOC_SET_VALUE,
};

use crate::error::{get_errno, set_errno};

use super::ioctl_struct;

// The wire structs are the ABI verbatim; pin their sizes so a layout change is
// caught here rather than sent to the kernel as a wrong-length struct.
const _: () = assert!(core::mem::size_of::<reg_query_value_args>() == 64);
const _: () = assert!(core::mem::size_of::<reg_set_value_args>() == 64);
const _: () = assert!(core::mem::size_of::<reg_delete_value_args>() == 40);
const _: () = assert!(core::mem::size_of::<reg_blanket_tombstone_args>() == 24);
const _: () = assert!(core::mem::size_of::<reg_query_values_batch_args>() == 24);
const _: () = assert!(core::mem::size_of::<reg_enum_value_args>() == 40);

fn out_buf_valid(ptr: *const c_void, cap: u32) -> bool {
    cap == 0 || !ptr.is_null()
}

// ----------------------------------------------------------------------------
// query_value
// ----------------------------------------------------------------------------

/// Descriptor for [`peios_reg_query_value`]: the caller's data and layer-name
/// buffers (in) and the resolved value's metadata (out). Mirrors
/// `struct peios_reg_value`. A NULL buffer with a zero capacity probes that field's
/// size.
#[repr(C)]
pub struct peios_reg_value {
    /// Out: the effective entry's global sequence number.
    pub sequence: u64,
    /// In: buffer receiving the value data (NULL to probe its size).
    pub data: *mut c_void,
    /// In: buffer receiving the effective layer name (NULL to probe / skip).
    pub layer: *mut c_void,
    /// Out: the value type (`REG_*`).
    pub type_: u32,
    /// In: `data` capacity in bytes.
    pub data_cap: u32,
    /// Out: actual data length (or the required length on `ERANGE`).
    pub data_len: u32,
    /// In: `layer` capacity in bytes.
    pub layer_cap: u32,
    /// Out: actual layer-name length (or the required length on `ERANGE`).
    pub layer_len: u32,
}

/// Pack the query-value arguments. Pure: copies the name, txn, and the descriptor's
/// in-buffers/capacities into the wire struct (pads stay zero).
fn build_query_value_args(
    name: *const c_void,
    name_len: u32,
    txn_fd: c_int,
    v: &peios_reg_value,
) -> reg_query_value_args {
    reg_query_value_args {
        name_len,
        name_ptr: name as usize as u64,
        data_ptr: v.data as usize as u64,
        data_len: v.data_cap, // in: capacity (overwritten with the actual length)
        layer_ptr: v.layer as usize as u64,
        layer_buf_len: v.layer_cap, // in: capacity
        txn_fd,
        ..Default::default()
    }
}

/// `peios_reg_query_value` — read the effective value named `name` on the key.
///
/// `name` is length-counted (`name_len == 0` is the key's default value). `txn_fd`
/// enlists a transaction (`-1` for none). On success the resolved type, sequence,
/// data, and effective layer name are written into `*v`; see the module docs for
/// the `ERANGE` size-probe contract. Returns 0, or `-1` with `errno` (`ENOENT` —
/// no effective value or it is a tombstone, `ERANGE`, `EACCES`, `EINVAL`, …).
///
/// # Safety
/// `name` valid for `name_len` bytes (or NULL when `name_len == 0`); `v` valid for
/// writing, with `v->data` / `v->layer` valid for their capacities when nonzero.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_query_value(
    key_fd: c_int,
    name: *const c_void,
    name_len: u32,
    txn_fd: c_int,
    v: *mut peios_reg_value,
) -> c_int {
    let Some(v) = v.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if !out_buf_valid(v.data, v.data_cap) || !out_buf_valid(v.layer, v.layer_cap) {
        set_errno(libc::EINVAL);
        return -1;
    }
    let mut a = build_query_value_args(name, name_len, txn_fd, v);
    let r = ioctl_struct(key_fd, REG_IOC_QUERY_VALUE, &mut a);
    if r == 0 {
        v.type_ = a.type_;
        v.sequence = a.sequence;
        v.data_len = a.data_len;
        v.layer_len = a.layer_len;
        return 0;
    }
    // On ERANGE the kernel wrote the required sizes back; surface them for a retry.
    if get_errno() == libc::ERANGE {
        v.data_len = a.data_len;
        v.layer_len = a.layer_len;
    }
    -1
}

// ----------------------------------------------------------------------------
// set_value / delete_value / blanket_tombstone
// ----------------------------------------------------------------------------

struct SetValueInput {
    name: *const c_void,
    name_len: u32,
    type_: u32,
    data: *const c_void,
    data_len: u32,
    layer: *const c_void,
    layer_len: u32,
    txn_fd: c_int,
    expected_seq: u64,
}

/// Pack the set-value arguments. Pure.
fn build_set_value_args(input: SetValueInput) -> reg_set_value_args {
    reg_set_value_args {
        name_len: input.name_len,
        name_ptr: input.name as usize as u64,
        type_: input.type_,
        data_len: input.data_len,
        data_ptr: input.data as usize as u64,
        layer_len: input.layer_len,
        layer_ptr: input.layer as usize as u64,
        txn_fd: input.txn_fd,
        expected_seq: input.expected_seq,
        ..Default::default()
    }
}

/// `peios_reg_set_value` — write the value `name` in a specific layer.
///
/// `type` is a `REG_*` type, or `REG_TOMBSTONE` to write a per-value tombstone that
/// masks lower layers. `layer`/`layer_len` name the target layer (NULL/0 = base
/// layer). `expected_seq` is a compare-and-swap guard: `0` disables it; otherwise
/// the write succeeds only if the value's current sequence matches, else `EAGAIN`.
/// `txn_fd` enlists a transaction (`-1` to auto-commit). Returns 0, or `-1` with
/// `errno` (`EINVAL`, `EAGAIN`, `ENOSPC`, `ENAMETOOLONG`, `EPERM`, `EACCES`, …).
///
/// # Safety
/// `name` valid for `name_len` bytes (or NULL when 0); `data` valid for `data_len`
/// bytes (or NULL when 0); `layer` valid for `layer_len` bytes (or NULL when 0).
#[no_mangle]
pub unsafe extern "C" fn peios_reg_set_value(
    key_fd: c_int,
    name: *const c_void,
    name_len: u32,
    type_: u32,
    data: *const c_void,
    data_len: u32,
    layer: *const c_void,
    layer_len: u32,
    txn_fd: c_int,
    expected_seq: u64,
) -> c_int {
    let mut a = build_set_value_args(SetValueInput {
        name,
        name_len,
        type_,
        data,
        data_len,
        layer,
        layer_len,
        txn_fd,
        expected_seq,
    });
    ioctl_struct(key_fd, REG_IOC_SET_VALUE, &mut a)
}

/// Pack the delete-value arguments. Pure.
fn build_delete_value_args(
    name: *const c_void,
    name_len: u32,
    layer: *const c_void,
    layer_len: u32,
    txn_fd: c_int,
) -> reg_delete_value_args {
    reg_delete_value_args {
        name_len,
        name_ptr: name as usize as u64,
        layer_len,
        layer_ptr: layer as usize as u64,
        txn_fd,
        ..Default::default()
    }
}

/// `peios_reg_delete_value` — remove a layer's entry for the value `name`.
///
/// Acts only on the named layer (NULL/0 = base); lower layers re-emerge. Idempotent.
/// `txn_fd` enlists a transaction (`-1` to auto-commit). Returns 0, or `-1` with
/// `errno`.
///
/// # Safety
/// `name` valid for `name_len` bytes (or NULL when 0); `layer` valid for
/// `layer_len` bytes (or NULL when 0).
#[no_mangle]
pub unsafe extern "C" fn peios_reg_delete_value(
    key_fd: c_int,
    name: *const c_void,
    name_len: u32,
    layer: *const c_void,
    layer_len: u32,
    txn_fd: c_int,
) -> c_int {
    let mut a = build_delete_value_args(name, name_len, layer, layer_len, txn_fd);
    ioctl_struct(key_fd, REG_IOC_DELETE_VALUE, &mut a)
}

/// Pack the blanket-tombstone arguments. Pure. `set` is passed through as its low
/// byte; the kernel rejects values other than 0/1 with `EINVAL`.
fn build_blanket_tombstone_args(
    layer: *const c_void,
    layer_len: u32,
    set: c_int,
    txn_fd: c_int,
) -> reg_blanket_tombstone_args {
    reg_blanket_tombstone_args {
        layer_len,
        layer_ptr: layer as usize as u64,
        set: set as u8,
        txn_fd,
        ..Default::default()
    }
}

/// `peios_reg_blanket_tombstone` — set (`set != 0`) or clear (`set == 0`) a blanket
/// tombstone on a layer, masking *all* lower-precedence values of this key on that
/// layer in one stroke.
///
/// `layer`/`layer_len` name the layer (NULL/0 = base). `txn_fd` enlists a
/// transaction (`-1` to auto-commit). Returns 0, or `-1` with `errno` (`EINVAL` if
/// `set` is not 0/1, `EACCES`, …).
///
/// # Safety
/// `layer` valid for `layer_len` bytes (or NULL when 0).
#[no_mangle]
pub unsafe extern "C" fn peios_reg_blanket_tombstone(
    key_fd: c_int,
    layer: *const c_void,
    layer_len: u32,
    set: c_int,
    txn_fd: c_int,
) -> c_int {
    if set != 0 && set != 1 {
        crate::error::set_errno(libc::EINVAL);
        return -1;
    }
    let mut a = build_blanket_tombstone_args(layer, layer_len, set, txn_fd);
    ioctl_struct(key_fd, REG_IOC_BLANKET_TOMBSTONE, &mut a)
}

// ----------------------------------------------------------------------------
// query_values_batch
// ----------------------------------------------------------------------------

/// `peios_reg_query_values_batch` — read every effective value of the key into one
/// buffer.
///
/// On success `*len_out` (if non-NULL) receives the bytes written and `*count_out`
/// (if non-NULL) the number of records; on `ERANGE`, `*len_out` receives the
/// required buffer size (a zero `cap` thus probes the size). Each record is packed
/// as `[name_len: u32 LE][name][type: u32 LE][data_len: u32 LE][data]`, little-
/// endian, `count` records back to back. Returns 0, or `-1` with `errno`.
///
/// # Safety
/// `buf` valid for `cap` bytes when `cap != 0`; `len_out` / `count_out` each NULL or
/// valid for a `u32` write.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_query_values_batch(
    key_fd: c_int,
    txn_fd: c_int,
    buf: *mut c_void,
    cap: u32,
    len_out: *mut u32,
    count_out: *mut u32,
) -> c_int {
    if !out_buf_valid(buf, cap) {
        set_errno(libc::EINVAL);
        return -1;
    }
    let mut a = reg_query_values_batch_args {
        buf_len: cap, // in: capacity (overwritten with the written/required length)
        buf_ptr: buf as usize as u64,
        txn_fd,
        ..Default::default()
    };
    let r = ioctl_struct(key_fd, REG_IOC_QUERY_VALUES_BATCH, &mut a);
    // The kernel writes buf_len/count back on success and the required length on
    // ERANGE; surface both in either case.
    if r == 0 || get_errno() == libc::ERANGE {
        if !len_out.is_null() {
            *len_out = a.buf_len;
        }
        if !count_out.is_null() {
            *count_out = a.count;
        }
    }
    r
}

// ----------------------------------------------------------------------------
// enum_value
// ----------------------------------------------------------------------------

/// Descriptor for [`peios_reg_enum_value`]: the caller's name and data buffers (in)
/// and the value at the requested index (out). Mirrors `struct peios_reg_enum_value`.
#[repr(C)]
pub struct peios_reg_enum_value {
    /// In: buffer receiving the value name (NULL to probe its size).
    pub name: *mut c_void,
    /// In: buffer receiving the value data (NULL to probe its size).
    pub data: *mut c_void,
    /// Out: the value type (`REG_*`).
    pub type_: u32,
    /// In: `name` capacity in bytes.
    pub name_cap: u32,
    /// Out: actual name length (or the required length on `ERANGE`).
    pub name_len: u32,
    /// In: `data` capacity in bytes.
    pub data_cap: u32,
    /// Out: actual data length (or the required length on `ERANGE`).
    pub data_len: u32,
}

/// Pack the enum-value arguments. Pure.
fn build_enum_value_args(
    index: u32,
    txn_fd: c_int,
    v: &peios_reg_enum_value,
) -> reg_enum_value_args {
    reg_enum_value_args {
        index,
        name_len: v.name_cap, // in: capacity (overwritten with the actual length)
        name_ptr: v.name as usize as u64,
        data_len: v.data_cap, // in: capacity
        data_ptr: v.data as usize as u64,
        txn_fd,
        ..Default::default()
    }
}

/// `peios_reg_enum_value` — read the effective value at position `index`.
///
/// Indices are dense over the key's effective (tombstone-resolved) values; walk
/// from 0 until `ENOENT` (index past the end). `txn_fd` enlists a transaction
/// (`-1` for none). On success the name, type, and data are written into `*v`; see
/// the module docs for the `ERANGE` size-probe contract. Returns 0, or `-1` with
/// `errno` (`ENOENT`, `ERANGE`, …).
///
/// # Safety
/// `v` valid for writing, with `v->name` / `v->data` valid for their capacities
/// when nonzero.
#[no_mangle]
pub unsafe extern "C" fn peios_reg_enum_value(
    key_fd: c_int,
    index: u32,
    txn_fd: c_int,
    v: *mut peios_reg_enum_value,
) -> c_int {
    let Some(v) = v.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if !out_buf_valid(v.name, v.name_cap) || !out_buf_valid(v.data, v.data_cap) {
        set_errno(libc::EINVAL);
        return -1;
    }
    let mut a = build_enum_value_args(index, txn_fd, v);
    let r = ioctl_struct(key_fd, REG_IOC_ENUM_VALUES, &mut a);
    if r == 0 {
        v.type_ = a.type_;
        v.name_len = a.name_len;
        v.data_len = a.data_len;
        return 0;
    }
    if get_errno() == libc::ERANGE {
        v.name_len = a.name_len;
        v.data_len = a.data_len;
    }
    -1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::get_errno;
    use peios_uapi::{REG_SZ, REG_TOMBSTONE};

    #[test]
    fn struct_sizes_pinned() {
        assert_eq!(core::mem::size_of::<reg_query_value_args>(), 64);
        assert_eq!(core::mem::size_of::<reg_set_value_args>(), 64);
        assert_eq!(core::mem::size_of::<reg_delete_value_args>(), 40);
        assert_eq!(core::mem::size_of::<reg_blanket_tombstone_args>(), 24);
        assert_eq!(core::mem::size_of::<reg_query_values_batch_args>(), 24);
        assert_eq!(core::mem::size_of::<reg_enum_value_args>(), 40);
    }

    #[test]
    fn query_value_args_pack_capacities_as_lengths() {
        let name = b"Color";
        let mut databuf = [0u8; 32];
        let mut layerbuf = [0u8; 16];
        let v = peios_reg_value {
            sequence: 0,
            data: databuf.as_mut_ptr() as *mut c_void,
            layer: layerbuf.as_mut_ptr() as *mut c_void,
            type_: 0,
            data_cap: databuf.len() as u32,
            data_len: 0,
            layer_cap: layerbuf.len() as u32,
            layer_len: 0,
        };
        let a = build_query_value_args(name.as_ptr() as *const c_void, name.len() as u32, -1, &v);
        assert_eq!(a.name_len, 5);
        assert_eq!(a.name_ptr, name.as_ptr() as usize as u64);
        assert_eq!(a.data_ptr, databuf.as_ptr() as usize as u64);
        assert_eq!(a.data_len, 32); // capacity goes into data_len
        assert_eq!(a.layer_ptr, layerbuf.as_ptr() as usize as u64);
        assert_eq!(a.layer_buf_len, 16); // capacity goes into layer_buf_len
        assert_eq!(a.txn_fd, -1);
        assert_eq!(a._pad0, 0);
        assert_eq!(a._pad1, 0);
    }

    #[test]
    fn query_value_rejects_null_buffer_with_capacity() {
        let mut v = peios_reg_value {
            sequence: 0,
            data: core::ptr::null_mut(),
            layer: core::ptr::null_mut(),
            type_: 0,
            data_cap: 1,
            data_len: 0,
            layer_cap: 0,
            layer_len: 0,
        };

        let r = unsafe { peios_reg_query_value(-1, core::ptr::null(), 0, -1, &mut v) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn set_value_args_pack_fields_and_tombstone_type() {
        let name = b"K";
        let data = [1u8, 2, 3, 4];
        let layer = b"overlay";
        let a = build_set_value_args(SetValueInput {
            name: name.as_ptr() as *const c_void,
            name_len: name.len() as u32,
            type_: REG_SZ,
            data: data.as_ptr() as *const c_void,
            data_len: data.len() as u32,
            layer: layer.as_ptr() as *const c_void,
            layer_len: layer.len() as u32,
            txn_fd: 9,
            expected_seq: 42,
        });
        assert_eq!(a.name_len, 1);
        assert_eq!(a.type_, REG_SZ);
        assert_eq!(a.data_len, 4);
        assert_eq!(a.data_ptr, data.as_ptr() as usize as u64);
        assert_eq!(a.layer_len, 7);
        assert_eq!(a.layer_ptr, layer.as_ptr() as usize as u64);
        assert_eq!(a.txn_fd, 9);
        assert_eq!(a.expected_seq, 42);
        assert_eq!(a._pad0, 0);
        assert_eq!(a._pad1, 0);
        assert_eq!(a._pad2, 0);

        // A tombstone write is just type == REG_TOMBSTONE.
        let t = build_set_value_args(SetValueInput {
            name: core::ptr::null(),
            name_len: 0,
            type_: REG_TOMBSTONE,
            data: core::ptr::null(),
            data_len: 0,
            layer: core::ptr::null(),
            layer_len: 0,
            txn_fd: -1,
            expected_seq: 0,
        });
        assert_eq!(t.type_, REG_TOMBSTONE);
        assert_eq!(t.name_ptr, 0);
        assert_eq!(t.layer_ptr, 0); // base layer
    }

    #[test]
    fn base_layer_is_null_ptr_zero_len() {
        // The kernel reads (layer_len == 0 && layer_ptr == NULL) as the base layer.
        let d =
            build_delete_value_args(b"x".as_ptr() as *const c_void, 1, core::ptr::null(), 0, -1);
        assert_eq!(d.layer_len, 0);
        assert_eq!(d.layer_ptr, 0);
        let b = build_blanket_tombstone_args(core::ptr::null(), 0, 1, -1);
        assert_eq!(b.layer_len, 0);
        assert_eq!(b.layer_ptr, 0);
        assert_eq!(b.set, 1);
    }

    #[test]
    fn blanket_tombstone_rejects_non_boolean_set() {
        let r = unsafe { peios_reg_blanket_tombstone(-1, core::ptr::null(), 0, 256, -1) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn query_values_batch_rejects_null_buffer_with_capacity() {
        let r = unsafe {
            peios_reg_query_values_batch(
                -1,
                -1,
                core::ptr::null_mut(),
                1,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }

    #[test]
    fn enum_value_args_pack_capacities_as_lengths() {
        let mut namebuf = [0u8; 64];
        let mut databuf = [0u8; 128];
        let v = peios_reg_enum_value {
            name: namebuf.as_mut_ptr() as *mut c_void,
            data: databuf.as_mut_ptr() as *mut c_void,
            type_: 0,
            name_cap: namebuf.len() as u32,
            name_len: 0,
            data_cap: databuf.len() as u32,
            data_len: 0,
        };
        let a = build_enum_value_args(3, -1, &v);
        assert_eq!(a.index, 3);
        assert_eq!(a.name_len, 64); // capacity goes into name_len
        assert_eq!(a.name_ptr, namebuf.as_ptr() as usize as u64);
        assert_eq!(a.data_len, 128); // capacity goes into data_len
        assert_eq!(a.data_ptr, databuf.as_ptr() as usize as u64);
        assert_eq!(a.txn_fd, -1);
        assert_eq!(a._pad, 0);
    }

    #[test]
    fn enum_value_rejects_null_buffer_with_capacity() {
        let mut v = peios_reg_enum_value {
            name: core::ptr::null_mut(),
            data: core::ptr::null_mut(),
            type_: 0,
            name_cap: 1,
            name_len: 0,
            data_cap: 0,
            data_len: 0,
        };

        let r = unsafe { peios_reg_enum_value(-1, 0, -1, &mut v) };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
    }
}
