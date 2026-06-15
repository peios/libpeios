//! Event emission — `peios_event_emit` / `peios_event_emit_batch`
//! (`<peios/event.h>`), the producer side of KMES.
//!
//! `kmes_emit` (syscall 1090) is a thin 4-argument passthrough; the kernel is the
//! authority on validation (it requires `SeAuditPrivilege`, rejects a zero-length
//! type or malformed MessagePack, enforces the size caps and the per-process rate
//! limit), so its `-errno` passes straight through. `kmes_emit_batch` (1092)
//! takes an array of `kmes_emit_entry`; that struct has reserved padding the
//! kernel expects zeroed, so we marshal each caller entry into a zeroed uapi
//! struct rather than forwarding a caller array with indeterminate padding.
//!
//! These cross the kernel boundary, so they are exercised live under Provium;
//! `cargo test` covers only the pure batch marshalling.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::slice;

use alloc::vec::Vec;

use peios_uapi::{kmes_emit_entry, KMES_BATCH_MAX_ENTRIES, SYS_KMES_EMIT, SYS_KMES_EMIT_BATCH};

use crate::error::set_errno;
use crate::sys::{ret_int, syscall3, syscall4};

/// `struct peios_event_entry` — one entry of a batch emit. Native pointers, so
/// it is ergonomic for C; it is marshalled into the uapi `kmes_emit_entry` before
/// the syscall.
#[repr(C)]
pub struct peios_event_entry {
    pub event_type: *const c_char,
    pub event_type_len: u16,
    pub payload: *const c_void,
    pub payload_len: u32,
}

// `peios_event_entry` happens to share the uapi struct's 32-byte layout, but we
// marshal rather than rely on that — the kernel requires the reserved bytes zero.
const _: () = assert!(core::mem::size_of::<peios_event_entry>() == 32);
const _: () = assert!(core::mem::size_of::<kmes_emit_entry>() == 32);

/// `peios_event_emit` — emit a single event. `event_type` is a length-counted
/// UTF-8 string; `payload` is `payload_len` bytes of MessagePack. Returns 0, or
/// `-1` with errno (`EPERM` without `SeAuditPrivilege`, `EINVAL` on a zero-length
/// type or malformed payload, `ENOSPC` past the size caps, `EAGAIN` if
/// rate-limited, `EFAULT` on a bad pointer) — all set by the kernel.
///
/// # Safety
/// `event_type` / `payload` must be valid for their stated lengths.
#[no_mangle]
pub unsafe extern "C" fn peios_event_emit(
    event_type: *const c_char,
    event_type_len: u16,
    payload: *const c_void,
    payload_len: u32,
) -> c_int {
    ret_int(syscall4(
        SYS_KMES_EMIT,
        event_type as usize as c_long,
        event_type_len as c_long,
        payload as usize as c_long,
        payload_len as c_long,
    ))
}

/// Marshal caller entries into zeroed uapi `kmes_emit_entry` structs (pointers
/// widened to `u64`, reserved padding cleared). Pure — it only reads the pointer
/// *values*, never dereferences them — so it is unit-testable.
fn marshal_entries(src: &[peios_event_entry]) -> Result<Vec<kmes_emit_entry>, c_int> {
    let mut out: Vec<kmes_emit_entry> = Vec::new();
    out.try_reserve(src.len()).map_err(|_| libc::ENOMEM)?;
    for e in src {
        out.push(kmes_emit_entry {
            event_type: e.event_type as usize as u64,
            event_type_len: e.event_type_len,
            _pad0: [0; 6],
            payload: e.payload as usize as u64,
            payload_len: e.payload_len,
            _pad1: [0; 4],
        });
    }
    Ok(out)
}

/// `peios_event_emit_batch` — emit up to `KMES_BATCH_MAX_ENTRIES` events in one
/// call. `count` must be in `[1, KMES_BATCH_MAX_ENTRIES]`. `emitted_out` (may be
/// NULL) receives the number actually emitted. Returns 0 if all `count` were
/// emitted, else `-1` with the errno of the first failing entry (and
/// `*emitted_out` set to how many preceded it).
///
/// # Safety
/// `entries` must point to `count` valid `peios_event_entry`; each entry's
/// pointers must be valid for their lengths; `emitted_out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn peios_event_emit_batch(
    entries: *const peios_event_entry,
    count: u32,
    emitted_out: *mut u32,
) -> c_int {
    if count == 0 || count > KMES_BATCH_MAX_ENTRIES || entries.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let src = slice::from_raw_parts(entries, count as usize);
    let buf = match marshal_entries(src) {
        Ok(buf) => buf,
        Err(errno) => {
            set_errno(errno);
            return -1;
        }
    };
    // The kernel writes the emitted count and faults on a NULL out-pointer; give
    // it a throwaway slot so callers may pass NULL when they don't want it.
    let mut local: u32 = 0;
    let emitted = if emitted_out.is_null() {
        &mut local as *mut u32
    } else {
        emitted_out
    };
    ret_int(syscall3(
        SYS_KMES_EMIT_BATCH,
        buf.as_ptr() as usize as c_long,
        count as c_long,
        emitted as usize as c_long,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_sizes_match_abi() {
        assert_eq!(core::mem::size_of::<peios_event_entry>(), 32);
        assert_eq!(core::mem::size_of::<kmes_emit_entry>(), 32);
    }

    #[test]
    fn marshal_copies_fields_and_zeroes_padding() {
        let et = b"my.event";
        let pl = [0x81u8, 0xa1, b'a', 0x01]; // {"a":1}
        let entries = [peios_event_entry {
            event_type: et.as_ptr() as *const c_char,
            event_type_len: et.len() as u16,
            payload: pl.as_ptr() as *const c_void,
            payload_len: pl.len() as u32,
        }];
        let out = marshal_entries(&entries).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].event_type, et.as_ptr() as usize as u64);
        assert_eq!(out[0].event_type_len, 8);
        assert_eq!(out[0].payload, pl.as_ptr() as usize as u64);
        assert_eq!(out[0].payload_len, 4);
        // The reserved bytes the kernel requires zeroed must be zero, not the
        // indeterminate padding a caller's struct would carry.
        assert_eq!(out[0]._pad0, [0u8; 6]);
        assert_eq!(out[0]._pad1, [0u8; 4]);
    }

    #[test]
    fn marshal_empty_is_empty() {
        assert!(marshal_entries(&[]).unwrap().is_empty());
    }
}
