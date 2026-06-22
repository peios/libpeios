//! `<peios/msgpack.h>` — an in-house MessagePack codec.
//!
//! KMES event payloads are MessagePack (`<peios/event.h>`); the kernel only
//! *structurally validates* them on emit, so userspace owns the encode/decode.
//! This is a from-scratch, `no_std` codec — a heap-backed [`peios_mp_writer`]
//! (encoder), a stack-allocatable [`peios_mp_reader`] cursor (decoder), and a
//! [`peios_mp_validate`] entry point whose acceptance is bug-for-bug matched to
//! the kernel's `kmes_validate` (so a payload this codec produces and validates
//! is accepted by `kmes_emit`).
//!
//! Wire facts: all multi-byte integers/lengths are **big-endian** (the
//! MessagePack spec — the opposite of the little-endian KACS formats); `str` must
//! be valid UTF-8 while `bin`/`ext` are arbitrary bytes; a valid payload is
//! exactly one top-level value consuming every byte, and an empty buffer is not
//! valid. Integers encode in their smallest form.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_void};
use core::slice;

use alloc::vec::Vec;

use crate::abi::{raw_free, raw_new, try_extend};
use crate::error::set_errno;

/// The hard nesting ceiling, mirroring the kernel's `MAX_VALIDATION_DEPTH`. The
/// writer validates structure at this ceiling; the emit-time limit (default
/// `KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT` = 32) is a caller-supplied argument to
/// [`peios_mp_validate`].
const MAX_DEPTH: u32 = 256;

// Value-type tags returned by `peios_mp_peek`, mirroring `enum peios_mp_type`.
const MP_NIL: c_int = 0;
const MP_BOOL: c_int = 1;
const MP_INT: c_int = 2;
const MP_FLOAT: c_int = 3;
const MP_STR: c_int = 4;
const MP_BIN: c_int = 5;
const MP_ARRAY: c_int = 6;
const MP_MAP: c_int = 7;
const MP_EXT: c_int = 8;

// ----------------------------------------------------------------------------
// Encoder core (append one value to a byte buffer)
// ----------------------------------------------------------------------------

fn put(buf: &mut Vec<u8>, b: u8) -> Result<(), c_int> {
    try_extend(buf, &[b]).map_err(|_| libc::ENOMEM)
}
fn put_bytes(buf: &mut Vec<u8>, b: &[u8]) -> Result<(), c_int> {
    try_extend(buf, b).map_err(|_| libc::ENOMEM)
}

fn enc_u64(buf: &mut Vec<u8>, v: u64) -> Result<(), c_int> {
    if v < 0x80 {
        put(buf, v as u8)
    } else if v <= u8::MAX as u64 {
        put(buf, 0xcc)?;
        put(buf, v as u8)
    } else if v <= u16::MAX as u64 {
        put(buf, 0xcd)?;
        put_bytes(buf, &(v as u16).to_be_bytes())
    } else if v <= u32::MAX as u64 {
        put(buf, 0xce)?;
        put_bytes(buf, &(v as u32).to_be_bytes())
    } else {
        put(buf, 0xcf)?;
        put_bytes(buf, &v.to_be_bytes())
    }
}

fn enc_i64(buf: &mut Vec<u8>, v: i64) -> Result<(), c_int> {
    if v >= 0 {
        return enc_u64(buf, v as u64);
    }
    if v >= -32 {
        return put(buf, (v as i8) as u8); // negative fixint
    }
    if v >= i8::MIN as i64 {
        put(buf, 0xd0)?;
        put(buf, (v as i8) as u8)
    } else if v >= i16::MIN as i64 {
        put(buf, 0xd1)?;
        put_bytes(buf, &(v as i16).to_be_bytes())
    } else if v >= i32::MIN as i64 {
        put(buf, 0xd2)?;
        put_bytes(buf, &(v as i32).to_be_bytes())
    } else {
        put(buf, 0xd3)?;
        put_bytes(buf, &v.to_be_bytes())
    }
}

fn enc_str(buf: &mut Vec<u8>, s: &[u8]) -> Result<(), c_int> {
    let n = u32::try_from(s.len()).map_err(|_| libc::EINVAL)?;
    if n <= 31 {
        put(buf, 0xa0 | n as u8)?;
    } else if n <= u8::MAX as u32 {
        put(buf, 0xd9)?;
        put(buf, n as u8)?;
    } else if n <= u16::MAX as u32 {
        put(buf, 0xda)?;
        put_bytes(buf, &(n as u16).to_be_bytes())?;
    } else {
        put(buf, 0xdb)?;
        put_bytes(buf, &n.to_be_bytes())?;
    }
    put_bytes(buf, s)
}

fn enc_bin(buf: &mut Vec<u8>, s: &[u8]) -> Result<(), c_int> {
    let n = u32::try_from(s.len()).map_err(|_| libc::EINVAL)?;
    if n <= u8::MAX as u32 {
        put(buf, 0xc4)?;
        put(buf, n as u8)?;
    } else if n <= u16::MAX as u32 {
        put(buf, 0xc5)?;
        put_bytes(buf, &(n as u16).to_be_bytes())?;
    } else {
        put(buf, 0xc6)?;
        put_bytes(buf, &n.to_be_bytes())?;
    }
    put_bytes(buf, s)
}

fn enc_array(buf: &mut Vec<u8>, n: u32) -> Result<(), c_int> {
    if n <= 15 {
        put(buf, 0x90 | n as u8)
    } else if n <= u16::MAX as u32 {
        put(buf, 0xdc)?;
        put_bytes(buf, &(n as u16).to_be_bytes())
    } else {
        put(buf, 0xdd)?;
        put_bytes(buf, &n.to_be_bytes())
    }
}

fn enc_map(buf: &mut Vec<u8>, n: u32) -> Result<(), c_int> {
    if n <= 15 {
        put(buf, 0x80 | n as u8)
    } else if n <= u16::MAX as u32 {
        put(buf, 0xde)?;
        put_bytes(buf, &(n as u16).to_be_bytes())
    } else {
        put(buf, 0xdf)?;
        put_bytes(buf, &n.to_be_bytes())
    }
}

fn enc_ext(buf: &mut Vec<u8>, ty: i8, s: &[u8]) -> Result<(), c_int> {
    let n = u32::try_from(s.len()).map_err(|_| libc::EINVAL)?;
    match n {
        1 => put(buf, 0xd4)?,
        2 => put(buf, 0xd5)?,
        4 => put(buf, 0xd6)?,
        8 => put(buf, 0xd7)?,
        16 => put(buf, 0xd8)?,
        _ if n <= u8::MAX as u32 => {
            put(buf, 0xc7)?;
            put(buf, n as u8)?;
        }
        _ if n <= u16::MAX as u32 => {
            put(buf, 0xc8)?;
            put_bytes(buf, &(n as u16).to_be_bytes())?;
        }
        _ => {
            put(buf, 0xc9)?;
            put_bytes(buf, &n.to_be_bytes())?;
        }
    }
    put(buf, ty as u8)?;
    put_bytes(buf, s)
}

// ----------------------------------------------------------------------------
// Decoder cursor (shared by the reader and the structural walkers)
// ----------------------------------------------------------------------------

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek_byte(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }
    fn take1(&mut self) -> Option<u8> {
        let b = self.peek_byte()?;
        self.pos += 1;
        Some(b)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn be_u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }
    fn be_u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn be_u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn read_nil(&mut self) -> Result<(), ()> {
        match self.peek_byte() {
            Some(0xc0) => {
                self.pos += 1;
                Ok(())
            }
            _ => Err(()),
        }
    }
    fn read_bool(&mut self) -> Result<bool, ()> {
        match self.peek_byte() {
            Some(0xc2) => {
                self.pos += 1;
                Ok(false)
            }
            Some(0xc3) => {
                self.pos += 1;
                Ok(true)
            }
            _ => Err(()),
        }
    }

    /// Decode any integer encoding to `i128` (lossless), consuming on success.
    fn read_int(&mut self) -> Option<i128> {
        let b = self.peek_byte()?;
        match b {
            0x00..=0x7f => {
                self.pos += 1;
                Some(b as i128)
            }
            0xe0..=0xff => {
                self.pos += 1;
                Some((b as i8) as i128)
            }
            0xcc => {
                self.pos += 1;
                Some(self.take1()? as i128)
            }
            0xcd => {
                self.pos += 1;
                Some(self.be_u16()? as i128)
            }
            0xce => {
                self.pos += 1;
                Some(self.be_u32()? as i128)
            }
            0xcf => {
                self.pos += 1;
                Some(self.be_u64()? as i128)
            }
            0xd0 => {
                self.pos += 1;
                Some((self.take1()? as i8) as i128)
            }
            0xd1 => {
                self.pos += 1;
                Some((self.be_u16()? as i16) as i128)
            }
            0xd2 => {
                self.pos += 1;
                Some((self.be_u32()? as i32) as i128)
            }
            0xd3 => {
                self.pos += 1;
                Some((self.be_u64()? as i64) as i128)
            }
            _ => None,
        }
    }
    fn read_i64(&mut self) -> Result<i64, ()> {
        let save = self.pos;
        match self.read_int().and_then(|v| i64::try_from(v).ok()) {
            Some(v) => Ok(v),
            None => {
                self.pos = save;
                Err(())
            }
        }
    }
    fn read_u64(&mut self) -> Result<u64, ()> {
        let save = self.pos;
        match self.read_int().and_then(|v| u64::try_from(v).ok()) {
            Some(v) => Ok(v),
            None => {
                self.pos = save;
                Err(())
            }
        }
    }
    fn read_f64(&mut self) -> Result<f64, ()> {
        let save = self.pos;
        let r = match self.peek_byte() {
            Some(0xca) => {
                self.pos += 1;
                self.take(4)
                    .and_then(|s| s.try_into().ok())
                    .map(|a| f32::from_be_bytes(a) as f64)
            }
            Some(0xcb) => {
                self.pos += 1;
                self.take(8)
                    .and_then(|s| s.try_into().ok())
                    .map(f64::from_be_bytes)
            }
            _ => None,
        };
        match r {
            Some(v) => Ok(v),
            None => {
                self.pos = save;
                Err(())
            }
        }
    }

    fn try_read_str(&mut self) -> Option<&'a [u8]> {
        let b = self.peek_byte()?;
        let n = match b {
            0xa0..=0xbf => {
                self.pos += 1;
                (b & 0x1f) as usize
            }
            0xd9 => {
                self.pos += 1;
                self.take1()? as usize
            }
            0xda => {
                self.pos += 1;
                self.be_u16()? as usize
            }
            0xdb => {
                self.pos += 1;
                self.be_u32()? as usize
            }
            _ => return None,
        };
        self.take(n)
    }
    fn read_str(&mut self) -> Result<&'a [u8], ()> {
        let save = self.pos;
        match self.try_read_str() {
            Some(s) if core::str::from_utf8(s).is_ok() => Ok(s),
            Some(_) => {
                self.pos = save;
                Err(())
            }
            None => {
                self.pos = save;
                Err(())
            }
        }
    }

    fn try_read_bin(&mut self) -> Option<&'a [u8]> {
        let b = self.peek_byte()?;
        let n = match b {
            0xc4 => {
                self.pos += 1;
                self.take1()? as usize
            }
            0xc5 => {
                self.pos += 1;
                self.be_u16()? as usize
            }
            0xc6 => {
                self.pos += 1;
                self.be_u32()? as usize
            }
            _ => return None,
        };
        self.take(n)
    }
    fn read_bin(&mut self) -> Result<&'a [u8], ()> {
        let save = self.pos;
        match self.try_read_bin() {
            Some(s) => Ok(s),
            None => {
                self.pos = save;
                Err(())
            }
        }
    }

    fn read_array(&mut self) -> Result<u32, ()> {
        let save = self.pos;
        let r = match self.peek_byte() {
            Some(b @ 0x90..=0x9f) => {
                self.pos += 1;
                Some((b & 0x0f) as u32)
            }
            Some(0xdc) => {
                self.pos += 1;
                self.be_u16().map(|n| n as u32)
            }
            Some(0xdd) => {
                self.pos += 1;
                self.be_u32()
            }
            _ => None,
        };
        match r {
            Some(n) => Ok(n),
            None => {
                self.pos = save;
                Err(())
            }
        }
    }
    fn read_map(&mut self) -> Result<u32, ()> {
        let save = self.pos;
        let r = match self.peek_byte() {
            Some(b @ 0x80..=0x8f) => {
                self.pos += 1;
                Some((b & 0x0f) as u32)
            }
            Some(0xde) => {
                self.pos += 1;
                self.be_u16().map(|n| n as u32)
            }
            Some(0xdf) => {
                self.pos += 1;
                self.be_u32()
            }
            _ => None,
        };
        match r {
            Some(n) => Ok(n),
            None => {
                self.pos = save;
                Err(())
            }
        }
    }

    fn try_read_ext(&mut self) -> Option<(i8, &'a [u8])> {
        let b = self.peek_byte()?;
        let n = match b {
            0xd4 => {
                self.pos += 1;
                1
            }
            0xd5 => {
                self.pos += 1;
                2
            }
            0xd6 => {
                self.pos += 1;
                4
            }
            0xd7 => {
                self.pos += 1;
                8
            }
            0xd8 => {
                self.pos += 1;
                16
            }
            0xc7 => {
                self.pos += 1;
                self.take1()? as usize
            }
            0xc8 => {
                self.pos += 1;
                self.be_u16()? as usize
            }
            0xc9 => {
                self.pos += 1;
                self.be_u32()? as usize
            }
            _ => return None,
        };
        let ty = self.take1()? as i8;
        let data = self.take(n)?;
        Some((ty, data))
    }
    fn read_ext(&mut self) -> Result<(i8, &'a [u8]), ()> {
        let save = self.pos;
        match self.try_read_ext() {
            Some(v) => Ok(v),
            None => {
                self.pos = save;
                Err(())
            }
        }
    }

    /// Skip exactly one complete value (descending into containers). Restores the
    /// position on malformed input.
    fn skip(&mut self) -> Result<(), ()> {
        let save = self.pos;
        let mut remaining: u64 = 1;
        while remaining > 0 {
            remaining -= 1;
            match value_step(self) {
                Some(children) => {
                    remaining = match remaining.checked_add(children) {
                        Some(r) => r,
                        None => {
                            self.pos = save;
                            return Err(());
                        }
                    }
                }
                None => {
                    self.pos = save;
                    return Err(());
                }
            }
        }
        Ok(())
    }
}

/// Consume one value's header and leaf bytes at the cursor, returning the count
/// of child values that follow it (0 for a leaf; `n` for an array; `2n` for a
/// map). `None` on a malformed, truncated, bad-UTF-8 (`str`), or reserved (`0xc1`)
/// value. The single point of truth for structure, shared by `skip` and
/// [`validate`].
fn value_step(cur: &mut Cursor) -> Option<u64> {
    let b = cur.peek_byte()?;
    cur.pos += 1; // consume lead byte
    match b {
        0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => Some(0),
        0xcc | 0xd0 => cur.take(1).map(|_| 0),
        0xcd | 0xd1 => cur.take(2).map(|_| 0),
        0xce | 0xd2 | 0xca => cur.take(4).map(|_| 0),
        0xcf | 0xd3 | 0xcb => cur.take(8).map(|_| 0),
        0xa0..=0xbf => str_leaf(cur, (b & 0x1f) as usize),
        0xd9 => {
            let n = cur.take1()? as usize;
            str_leaf(cur, n)
        }
        0xda => {
            let n = cur.be_u16()? as usize;
            str_leaf(cur, n)
        }
        0xdb => {
            let n = cur.be_u32()? as usize;
            str_leaf(cur, n)
        }
        0xc4 => {
            let n = cur.take1()? as usize;
            cur.take(n).map(|_| 0)
        }
        0xc5 => {
            let n = cur.be_u16()? as usize;
            cur.take(n).map(|_| 0)
        }
        0xc6 => {
            let n = cur.be_u32()? as usize;
            cur.take(n).map(|_| 0)
        }
        0x90..=0x9f => Some((b & 0x0f) as u64),
        0xdc => Some(cur.be_u16()? as u64),
        0xdd => Some(cur.be_u32()? as u64),
        0x80..=0x8f => Some(((b & 0x0f) as u64) * 2),
        0xde => Some((cur.be_u16()? as u64) * 2),
        0xdf => Some((cur.be_u32()? as u64) * 2),
        0xd4 => cur.take(1 + 1).map(|_| 0), // fixext: type byte + data
        0xd5 => cur.take(1 + 2).map(|_| 0),
        0xd6 => cur.take(1 + 4).map(|_| 0),
        0xd7 => cur.take(1 + 8).map(|_| 0),
        0xd8 => cur.take(1 + 16).map(|_| 0),
        0xc7 => {
            let n = cur.take1()? as usize;
            cur.take(1 + n).map(|_| 0)
        }
        0xc8 => {
            let n = cur.be_u16()? as usize;
            cur.take(1 + n).map(|_| 0)
        }
        0xc9 => {
            let n = cur.be_u32()? as usize;
            cur.take(1 + n).map(|_| 0)
        }
        // 0xc1 (reserved) and any byte not handled above are invalid.
        _ => None,
    }
}

fn str_leaf(cur: &mut Cursor, n: usize) -> Option<u64> {
    let s = cur.take(n)?;
    if core::str::from_utf8(s).is_err() {
        return None;
    }
    Some(0)
}

/// Structural validation matching the kernel's `kmes_validate`: exactly one
/// top-level value consuming every byte, `str` UTF-8, nesting bounded by
/// `max_depth` (top level = depth 1; a non-empty container's children sit one
/// level deeper; empty containers never deepen). An empty buffer is invalid.
fn validate(bytes: &[u8], max_depth: u32) -> bool {
    if bytes.is_empty() || max_depth == 0 || max_depth > MAX_DEPTH {
        return false;
    }
    let max_depth = max_depth as usize;
    let mut stack = [0u64; MAX_DEPTH as usize];
    let mut depth: usize = 1;
    stack[0] = 1; // one top-level value to consume
    let mut cur = Cursor { buf: bytes, pos: 0 };
    loop {
        while depth > 0 && stack[depth - 1] == 0 {
            depth -= 1;
        }
        if depth == 0 {
            break;
        }
        stack[depth - 1] -= 1;
        let children = match value_step(&mut cur) {
            Some(c) => c,
            None => return false,
        };
        if children > 0 {
            if depth >= max_depth {
                return false;
            }
            stack[depth] = children;
            depth += 1;
        }
    }
    cur.pos == bytes.len()
}

fn classify(b: u8) -> Option<c_int> {
    Some(match b {
        0x00..=0x7f | 0xe0..=0xff | 0xcc..=0xcf | 0xd0..=0xd3 => MP_INT,
        0xc0 => MP_NIL,
        0xc2 | 0xc3 => MP_BOOL,
        0xca | 0xcb => MP_FLOAT,
        0xa0..=0xbf | 0xd9..=0xdb => MP_STR,
        0xc4..=0xc6 => MP_BIN,
        0x90..=0x9f | 0xdc | 0xdd => MP_ARRAY,
        0x80..=0x8f | 0xde | 0xdf => MP_MAP,
        0xc7..=0xc9 | 0xd4..=0xd8 => MP_EXT,
        _ => return None, // 0xc1 (reserved)
    })
}

// ----------------------------------------------------------------------------
// Writer (encoder) C ABI
// ----------------------------------------------------------------------------

/// `peios_mp_writer` — opaque, heap-allocated; sticky-error like the KACS builders.
pub struct peios_mp_writer {
    buf: Vec<u8>,
    error: c_int,
}

impl peios_mp_writer {
    fn run(&mut self, r: Result<(), c_int>) {
        if self.error == 0 {
            if let Err(e) = r {
                self.error = e;
            }
        }
    }
}

/// View a `(ptr, len)` pair as a slice, or `Err` if NULL with a non-zero length.
unsafe fn opt_slice<'a>(ptr: *const c_void, len: usize) -> Result<&'a [u8], c_int> {
    if ptr.is_null() {
        if len != 0 {
            return Err(libc::EINVAL);
        }
        Ok(&[])
    } else {
        Ok(slice::from_raw_parts(ptr as *const u8, len))
    }
}

/// `peios_mp_writer_new` — allocate a writer, or NULL on OOM.
#[no_mangle]
pub extern "C" fn peios_mp_writer_new() -> *mut peios_mp_writer {
    unsafe {
        raw_new(peios_mp_writer {
            buf: Vec::new(),
            error: 0,
        })
    }
}

/// `peios_mp_writer_free` — destroy a writer (NULL-safe).
#[no_mangle]
pub unsafe extern "C" fn peios_mp_writer_free(w: *mut peios_mp_writer) {
    raw_free(w);
}

/// `peios_mp_writer_reset` — clear the buffer and the sticky error.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_writer_reset(w: *mut peios_mp_writer) {
    if let Some(w) = w.as_mut() {
        w.buf.clear();
        w.error = 0;
    }
}

/// `peios_mp_write_nil`.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_write_nil(w: *mut peios_mp_writer) {
    if let Some(w) = w.as_mut() {
        if w.error == 0 {
            let r = put(&mut w.buf, 0xc0);
            w.run(r);
        }
    }
}

/// `peios_mp_write_bool`.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_write_bool(w: *mut peios_mp_writer, v: bool) {
    if let Some(w) = w.as_mut() {
        if w.error == 0 {
            let r = put(&mut w.buf, if v { 0xc3 } else { 0xc2 });
            w.run(r);
        }
    }
}

/// `peios_mp_write_int` — a signed integer (smallest encoding).
#[no_mangle]
pub unsafe extern "C" fn peios_mp_write_int(w: *mut peios_mp_writer, v: i64) {
    if let Some(w) = w.as_mut() {
        if w.error == 0 {
            let r = enc_i64(&mut w.buf, v);
            w.run(r);
        }
    }
}

/// `peios_mp_write_uint` — an unsigned integer (smallest encoding).
#[no_mangle]
pub unsafe extern "C" fn peios_mp_write_uint(w: *mut peios_mp_writer, v: u64) {
    if let Some(w) = w.as_mut() {
        if w.error == 0 {
            let r = enc_u64(&mut w.buf, v);
            w.run(r);
        }
    }
}

/// `peios_mp_write_float` — a 64-bit float.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_write_float(w: *mut peios_mp_writer, v: f64) {
    if let Some(w) = w.as_mut() {
        if w.error == 0 {
            let r = put(&mut w.buf, 0xcb).and_then(|()| put_bytes(&mut w.buf, &v.to_be_bytes()));
            w.run(r);
        }
    }
}

/// `peios_mp_write_str` — a UTF-8 string (rejected with EINVAL if not UTF-8).
#[no_mangle]
pub unsafe extern "C" fn peios_mp_write_str(w: *mut peios_mp_writer, s: *const c_char, len: usize) {
    if let Some(w) = w.as_mut() {
        if w.error != 0 {
            return;
        }
        let r = (|| {
            let bytes = opt_slice(s as *const c_void, len)?;
            if core::str::from_utf8(bytes).is_err() {
                return Err(libc::EINVAL);
            }
            enc_str(&mut w.buf, bytes)
        })();
        w.run(r);
    }
}

/// `peios_mp_write_bin` — an opaque binary blob.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_write_bin(w: *mut peios_mp_writer, b: *const c_void, len: usize) {
    if let Some(w) = w.as_mut() {
        if w.error != 0 {
            return;
        }
        let r = opt_slice(b, len).and_then(|bytes| enc_bin(&mut w.buf, bytes));
        w.run(r);
    }
}

/// `peios_mp_write_array` — an array header; the caller then writes `count` values.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_write_array(w: *mut peios_mp_writer, count: u32) {
    if let Some(w) = w.as_mut() {
        if w.error == 0 {
            let r = enc_array(&mut w.buf, count);
            w.run(r);
        }
    }
}

/// `peios_mp_write_map` — a map header; the caller then writes `count` key/value pairs.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_write_map(w: *mut peios_mp_writer, count: u32) {
    if let Some(w) = w.as_mut() {
        if w.error == 0 {
            let r = enc_map(&mut w.buf, count);
            w.run(r);
        }
    }
}

/// `peios_mp_write_ext` — an extension value with a signed type id.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_write_ext(
    w: *mut peios_mp_writer,
    ext_type: i8,
    b: *const c_void,
    len: usize,
) {
    if let Some(w) = w.as_mut() {
        if w.error != 0 {
            return;
        }
        let r = opt_slice(b, len).and_then(|bytes| enc_ext(&mut w.buf, ext_type, bytes));
        w.run(r);
    }
}

/// `peios_mp_write_raw` — append pre-encoded MessagePack bytes verbatim (the
/// escape hatch). The whole buffer is still structurally validated at `_bytes`.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_write_raw(w: *mut peios_mp_writer, b: *const c_void, len: usize) {
    if let Some(w) = w.as_mut() {
        if w.error != 0 {
            return;
        }
        let r = opt_slice(b, len).and_then(|bytes| put_bytes(&mut w.buf, bytes));
        w.run(r);
    }
}

/// `peios_mp_writer_bytes` — borrow the encoded buffer (valid until the next
/// mutating call) and return its length, after confirming it is exactly one
/// well-formed top-level value. `-1` + errno on a sticky error or malformed
/// structure (e.g. an under-filled array/map).
#[no_mangle]
pub unsafe extern "C" fn peios_mp_writer_bytes(
    w: *mut peios_mp_writer,
    out: *mut *const c_void,
) -> isize {
    let set_out = |p: *const c_void| {
        if !out.is_null() {
            *out = p;
        }
    };
    let Some(w) = w.as_mut() else {
        set_out(core::ptr::null());
        set_errno(libc::EINVAL);
        return -1;
    };
    if w.error != 0 {
        set_out(core::ptr::null());
        set_errno(w.error);
        return -1;
    }
    if !validate(&w.buf, MAX_DEPTH) {
        w.error = libc::EINVAL;
        set_out(core::ptr::null());
        set_errno(libc::EINVAL);
        return -1;
    }
    set_out(w.buf.as_ptr() as *const c_void);
    w.buf.len() as isize
}

/// `peios_mp_writer_error` — the latched errno, or 0 if healthy.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_writer_error(w: *const peios_mp_writer) -> c_int {
    match w.as_ref() {
        Some(w) => w.error,
        None => libc::EINVAL,
    }
}

// ----------------------------------------------------------------------------
// Reader (decoder) C ABI
// ----------------------------------------------------------------------------

/// `peios_mp_reader` — a stack-allocatable decode cursor over a borrowed buffer.
/// Opaque storage holds `(ptr, len, pos, error)`.
#[repr(C)]
pub struct peios_mp_reader {
    _opaque: [u64; 4],
}

const _: () = assert!(core::mem::size_of::<peios_mp_reader>() == 32);

impl peios_mp_reader {
    fn error(&self) -> c_int {
        self._opaque[3] as c_int
    }
    unsafe fn cursor(&self) -> Cursor<'static> {
        let ptr = self._opaque[0] as usize as *const u8;
        let len = self._opaque[1] as usize;
        let buf: &'static [u8] = if ptr.is_null() || len == 0 {
            &[]
        } else {
            slice::from_raw_parts(ptr, len)
        };
        Cursor {
            buf,
            pos: self._opaque[2] as usize,
        }
    }
    fn commit(&mut self, pos: usize) {
        self._opaque[2] = pos as u64;
    }
}

/// `peios_mp_reader_init` — point a reader at `buf`/`len`. `buf == NULL` with a
/// nonzero `len` latches `EINVAL` for later reader operations.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_reader_init(
    r: *mut peios_mp_reader,
    buf: *const c_void,
    len: usize,
) {
    if let Some(r) = r.as_mut() {
        let error = if buf.is_null() && len != 0 {
            libc::EINVAL as u64
        } else {
            0
        };
        r._opaque = [buf as usize as u64, len as u64, 0, error];
    }
}

/// `peios_mp_reader_remaining` — unconsumed bytes left in the buffer.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_reader_remaining(r: *const peios_mp_reader) -> usize {
    match r.as_ref() {
        Some(r) => {
            if r.error() != 0 {
                return 0;
            }
            let cur = r.cursor();
            cur.buf.len().saturating_sub(cur.pos)
        }
        None => 0,
    }
}

/// `peios_mp_peek` — the `peios_mp_type` of the next value without consuming it,
/// or `-1` at end-of-input or on an invalid lead byte.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_peek(r: *const peios_mp_reader) -> c_int {
    let Some(r) = r.as_ref() else { return -1 };
    if r.error() != 0 {
        set_errno(r.error());
        return -1;
    }
    r.cursor().peek_byte().and_then(classify).unwrap_or(-1)
}

/// Run a cursor read, committing the new position on success or setting `errno`
/// and leaving the reader untouched on failure.
unsafe fn reader_read<T>(
    r: *mut peios_mp_reader,
    f: impl FnOnce(&mut Cursor<'static>) -> Result<T, ()>,
) -> Result<T, ()> {
    let Some(r) = r.as_mut() else {
        set_errno(libc::EINVAL);
        return Err(());
    };
    if r.error() != 0 {
        set_errno(r.error());
        return Err(());
    }
    let mut cur = r.cursor();
    match f(&mut cur) {
        Ok(v) => {
            r.commit(cur.pos);
            Ok(v)
        }
        Err(()) => {
            set_errno(libc::EINVAL);
            Err(())
        }
    }
}

/// `peios_mp_read_nil` — 0 on success, `-1`+EINVAL on a type mismatch.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_read_nil(r: *mut peios_mp_reader) -> c_int {
    match reader_read(r, |c| c.read_nil()) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

/// `peios_mp_read_bool`.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_read_bool(r: *mut peios_mp_reader, out: *mut bool) -> c_int {
    match reader_read(r, |c| c.read_bool()) {
        Ok(v) => {
            if !out.is_null() {
                *out = v;
            }
            0
        }
        Err(()) => -1,
    }
}

/// `peios_mp_read_int` — any integer that fits `int64_t`.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_read_int(r: *mut peios_mp_reader, out: *mut i64) -> c_int {
    match reader_read(r, |c| c.read_i64()) {
        Ok(v) => {
            if !out.is_null() {
                *out = v;
            }
            0
        }
        Err(()) => -1,
    }
}

/// `peios_mp_read_uint` — any non-negative integer that fits `uint64_t`.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_read_uint(r: *mut peios_mp_reader, out: *mut u64) -> c_int {
    match reader_read(r, |c| c.read_u64()) {
        Ok(v) => {
            if !out.is_null() {
                *out = v;
            }
            0
        }
        Err(()) => -1,
    }
}

/// `peios_mp_read_float` — a float32 or float64, widened to `double`.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_read_float(r: *mut peios_mp_reader, out: *mut f64) -> c_int {
    match reader_read(r, |c| c.read_f64()) {
        Ok(v) => {
            if !out.is_null() {
                *out = v;
            }
            0
        }
        Err(()) => -1,
    }
}

/// `peios_mp_read_str` — borrow a string's bytes (a pointer into the reader's
/// buffer); returns its length, or `-1`+EINVAL. Not NUL-terminated; use the length.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_read_str(
    r: *mut peios_mp_reader,
    out: *mut *const c_char,
) -> isize {
    match reader_read(r, |c| c.read_str()) {
        Ok(s) => {
            if !out.is_null() {
                *out = s.as_ptr() as *const c_char;
            }
            s.len() as isize
        }
        Err(()) => {
            if !out.is_null() {
                *out = core::ptr::null();
            }
            -1
        }
    }
}

/// `peios_mp_read_bin` — borrow a binary blob's bytes; returns its length, or `-1`.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_read_bin(
    r: *mut peios_mp_reader,
    out: *mut *const c_void,
) -> isize {
    match reader_read(r, |c| c.read_bin()) {
        Ok(s) => {
            if !out.is_null() {
                *out = s.as_ptr() as *const c_void;
            }
            s.len() as isize
        }
        Err(()) => {
            if !out.is_null() {
                *out = core::ptr::null();
            }
            -1
        }
    }
}

/// `peios_mp_read_array` — consume an array header; returns the element count, or
/// `-1`. The caller then reads that many values.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_read_array(r: *mut peios_mp_reader) -> isize {
    match reader_read(r, |c| c.read_array()) {
        Ok(n) => n as isize,
        Err(()) => -1,
    }
}

/// `peios_mp_read_map` — consume a map header; returns the key/value PAIR count,
/// or `-1`. The caller then reads `2 × count` values (key, value, …).
#[no_mangle]
pub unsafe extern "C" fn peios_mp_read_map(r: *mut peios_mp_reader) -> isize {
    match reader_read(r, |c| c.read_map()) {
        Ok(n) => n as isize,
        Err(()) => -1,
    }
}

/// `peios_mp_read_ext` — borrow an extension value's bytes and report its signed
/// type id via `type_out`; returns the data length, or `-1`.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_read_ext(
    r: *mut peios_mp_reader,
    type_out: *mut i8,
    out: *mut *const c_void,
) -> isize {
    match reader_read(r, |c| c.read_ext()) {
        Ok((ty, s)) => {
            if !type_out.is_null() {
                *type_out = ty;
            }
            if !out.is_null() {
                *out = s.as_ptr() as *const c_void;
            }
            s.len() as isize
        }
        Err(()) => {
            if !out.is_null() {
                *out = core::ptr::null();
            }
            -1
        }
    }
}

/// `peios_mp_skip` — skip exactly one complete value (including nested
/// containers). 0 on success, `-1`+EINVAL on malformed input.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_skip(r: *mut peios_mp_reader) -> c_int {
    match reader_read(r, |c| c.skip()) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

// ----------------------------------------------------------------------------
// Validator C ABI
// ----------------------------------------------------------------------------

/// `peios_mp_validate` — confirm `buf`/`len` is exactly one well-formed
/// MessagePack value (UTF-8 strings, nesting ≤ `max_depth`, no trailing bytes,
/// non-empty), matching the kernel's emit-time check. 0 if valid, `-1`+EINVAL
/// otherwise. Pass `KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT` (32) for the default
/// emit limit.
#[no_mangle]
pub unsafe extern "C" fn peios_mp_validate(
    buf: *const c_void,
    len: usize,
    max_depth: u32,
) -> c_int {
    let bytes = match opt_slice(buf, len) {
        Ok(bytes) => bytes,
        Err(e) => {
            set_errno(e);
            return -1;
        }
    };
    if validate(bytes, max_depth) {
        0
    } else {
        set_errno(libc::EINVAL);
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT_DEPTH: u32 = 32;

    fn enc(f: impl FnOnce(*mut peios_mp_writer)) -> Vec<u8> {
        unsafe {
            let w = peios_mp_writer_new();
            assert!(!w.is_null());
            f(w);
            let mut out = core::ptr::null::<c_void>();
            let n = peios_mp_writer_bytes(w, &mut out);
            assert!(n >= 0, "encode failed: errno={}", *libc::__errno_location());
            let bytes = slice::from_raw_parts(out as *const u8, n as usize).to_vec();
            peios_mp_writer_free(w);
            bytes
        }
    }

    #[test]
    fn scalars_roundtrip() {
        // uint
        let b = enc(|w| unsafe { peios_mp_write_uint(w, 300) });
        assert_eq!(b, vec![0xcd, 0x01, 0x2c]); // uint16 big-endian
        assert_eq!(
            unsafe { peios_mp_validate(b.as_ptr() as *const c_void, b.len(), DEFAULT_DEPTH) },
            0
        );
        unsafe {
            let mut r = peios_mp_reader { _opaque: [0; 4] };
            peios_mp_reader_init(&mut r, b.as_ptr() as *const c_void, b.len());
            assert_eq!(peios_mp_peek(&r), MP_INT);
            let mut v = 0u64;
            assert_eq!(peios_mp_read_uint(&mut r, &mut v), 0);
            assert_eq!(v, 300);
            assert_eq!(peios_mp_reader_remaining(&r), 0);
        }

        // negative int → smallest form
        assert_eq!(enc(|w| unsafe { peios_mp_write_int(w, -1) }), vec![0xff]);
        assert_eq!(
            enc(|w| unsafe { peios_mp_write_int(w, -33) }),
            vec![0xd0, 0xdf]
        );
        // positive fixint
        assert_eq!(enc(|w| unsafe { peios_mp_write_int(w, 7) }), vec![0x07]);

        // bool / nil
        assert_eq!(enc(|w| unsafe { peios_mp_write_bool(w, true) }), vec![0xc3]);
        assert_eq!(enc(|w| unsafe { peios_mp_write_nil(w) }), vec![0xc0]);
    }

    #[test]
    fn float_roundtrip() {
        let b = enc(|w| unsafe { peios_mp_write_float(w, 1.5) });
        assert_eq!(b[0], 0xcb);
        unsafe {
            let mut r = peios_mp_reader { _opaque: [0; 4] };
            peios_mp_reader_init(&mut r, b.as_ptr() as *const c_void, b.len());
            assert_eq!(peios_mp_peek(&r), MP_FLOAT);
            let mut v = 0f64;
            assert_eq!(peios_mp_read_float(&mut r, &mut v), 0);
            assert_eq!(v, 1.5);
        }
    }

    #[test]
    fn str_and_bin_roundtrip() {
        let s = b"hello";
        let b = enc(|w| unsafe { peios_mp_write_str(w, s.as_ptr() as *const c_char, s.len()) });
        assert_eq!(b[0], 0xa5); // fixstr len 5
        unsafe {
            let mut r = peios_mp_reader { _opaque: [0; 4] };
            peios_mp_reader_init(&mut r, b.as_ptr() as *const c_void, b.len());
            assert_eq!(peios_mp_peek(&r), MP_STR);
            let mut out = core::ptr::null::<c_char>();
            let n = peios_mp_read_str(&mut r, &mut out);
            assert_eq!(n, 5);
            assert_eq!(slice::from_raw_parts(out as *const u8, 5), s);
        }

        let blob = [0u8, 1, 2, 0xff];
        let b =
            enc(|w| unsafe { peios_mp_write_bin(w, blob.as_ptr() as *const c_void, blob.len()) });
        assert_eq!(b[0], 0xc4); // bin8
        unsafe {
            let mut r = peios_mp_reader { _opaque: [0; 4] };
            peios_mp_reader_init(&mut r, b.as_ptr() as *const c_void, b.len());
            assert_eq!(peios_mp_peek(&r), MP_BIN);
            let mut out = core::ptr::null::<c_void>();
            let n = peios_mp_read_bin(&mut r, &mut out);
            assert_eq!(n, 4);
            assert_eq!(slice::from_raw_parts(out as *const u8, 4), &blob);
        }
    }

    #[test]
    fn read_str_rejects_invalid_utf8_without_consuming() {
        let b = [0xa1u8, 0xff];
        unsafe {
            let mut r = peios_mp_reader { _opaque: [0; 4] };
            peios_mp_reader_init(&mut r, b.as_ptr() as *const c_void, b.len());
            let mut out = core::ptr::null::<c_char>();

            assert_eq!(peios_mp_read_str(&mut r, &mut out), -1);
            assert!(out.is_null());
            assert_eq!(peios_mp_reader_remaining(&r), b.len());
        }
    }

    #[test]
    fn map_roundtrip_and_decode() {
        // {"id": 42, "ok": true}
        let b = enc(|w| unsafe {
            peios_mp_write_map(w, 2);
            peios_mp_write_str(w, b"id".as_ptr() as *const c_char, 2);
            peios_mp_write_uint(w, 42);
            peios_mp_write_str(w, b"ok".as_ptr() as *const c_char, 2);
            peios_mp_write_bool(w, true);
        });
        assert_eq!(
            unsafe { peios_mp_validate(b.as_ptr() as *const c_void, b.len(), DEFAULT_DEPTH) },
            0
        );
        unsafe {
            let mut r = peios_mp_reader { _opaque: [0; 4] };
            peios_mp_reader_init(&mut r, b.as_ptr() as *const c_void, b.len());
            assert_eq!(peios_mp_peek(&r), MP_MAP);
            assert_eq!(peios_mp_read_map(&mut r), 2);
            // key "id"
            let mut k = core::ptr::null::<c_char>();
            assert_eq!(peios_mp_read_str(&mut r, &mut k), 2);
            let mut v = 0u64;
            assert_eq!(peios_mp_read_uint(&mut r, &mut v), 0);
            assert_eq!(v, 42);
            // skip the rest of the pair (key "ok", value true)
            assert_eq!(peios_mp_skip(&mut r), 0); // key
            let mut bo = false;
            assert_eq!(peios_mp_read_bool(&mut r, &mut bo), 0);
            assert!(bo);
            assert_eq!(peios_mp_reader_remaining(&r), 0);
        }
    }

    #[test]
    fn nested_array_and_skip() {
        // [1, [2, 3], "x"]
        let b = enc(|w| unsafe {
            peios_mp_write_array(w, 3);
            peios_mp_write_uint(w, 1);
            peios_mp_write_array(w, 2);
            peios_mp_write_uint(w, 2);
            peios_mp_write_uint(w, 3);
            peios_mp_write_str(w, b"x".as_ptr() as *const c_char, 1);
        });
        assert_eq!(
            unsafe { peios_mp_validate(b.as_ptr() as *const c_void, b.len(), DEFAULT_DEPTH) },
            0
        );
        unsafe {
            let mut r = peios_mp_reader { _opaque: [0; 4] };
            peios_mp_reader_init(&mut r, b.as_ptr() as *const c_void, b.len());
            assert_eq!(peios_mp_read_array(&mut r), 3);
            let mut v = 0u64;
            assert_eq!(peios_mp_read_uint(&mut r, &mut v), 0);
            assert_eq!(v, 1);
            // skip the inner array as one value
            assert_eq!(peios_mp_skip(&mut r), 0);
            let mut out = core::ptr::null::<c_char>();
            assert_eq!(peios_mp_read_str(&mut r, &mut out), 1);
            assert_eq!(peios_mp_reader_remaining(&r), 0);
        }
    }

    #[test]
    fn ext_roundtrip() {
        let data = [9u8, 8, 7];
        let b = enc(|w| unsafe {
            peios_mp_write_ext(w, -1, data.as_ptr() as *const c_void, data.len())
        });
        assert_eq!(b[0], 0xc7); // ext8 (len 3 is not a fixext size)
        unsafe {
            let mut r = peios_mp_reader { _opaque: [0; 4] };
            peios_mp_reader_init(&mut r, b.as_ptr() as *const c_void, b.len());
            assert_eq!(peios_mp_peek(&r), MP_EXT);
            let mut ty = 0i8;
            let mut out = core::ptr::null::<c_void>();
            let n = peios_mp_read_ext(&mut r, &mut ty, &mut out);
            assert_eq!(n, 3);
            assert_eq!(ty, -1);
            assert_eq!(slice::from_raw_parts(out as *const u8, 3), &data);
        }
        // fixext sizes pick the fixext lead bytes.
        assert_eq!(
            enc(|w| unsafe { peios_mp_write_ext(w, 5, [1u8].as_ptr() as *const c_void, 1) })[0],
            0xd4
        );
    }

    #[test]
    fn validate_rejects_malformed() {
        unsafe {
            // empty buffer
            assert_eq!(peios_mp_validate(core::ptr::null(), 0, DEFAULT_DEPTH), -1);
            // reserved 0xc1
            let bad = [0xc1u8];
            assert_eq!(
                peios_mp_validate(bad.as_ptr() as *const c_void, 1, DEFAULT_DEPTH),
                -1
            );
            // trailing garbage after a complete value
            let trailing = [0x01u8, 0x02];
            assert_eq!(
                peios_mp_validate(trailing.as_ptr() as *const c_void, 2, DEFAULT_DEPTH),
                -1
            );
            // truncated str (fixstr len 5, only 1 byte follows)
            let trunc = [0xa5u8, b'h'];
            assert_eq!(
                peios_mp_validate(trunc.as_ptr() as *const c_void, 2, DEFAULT_DEPTH),
                -1
            );
            // invalid UTF-8 in a str
            let bad_utf8 = [0xa1u8, 0xff];
            assert_eq!(
                peios_mp_validate(bad_utf8.as_ptr() as *const c_void, 2, DEFAULT_DEPTH),
                -1
            );
            // a bin with the same bytes is fine (no UTF-8 requirement)
            let ok_bin = [0xc4u8, 0x01, 0xff];
            assert_eq!(
                peios_mp_validate(ok_bin.as_ptr() as *const c_void, 3, DEFAULT_DEPTH),
                0
            );
        }
    }

    #[test]
    fn validate_depth_limit() {
        // [[[1]]] — three nested non-empty arrays at depths 1, 2, 3. The kernel
        // rejects descending into a container when depth >= max_depth (depth
        // starts at 1), so the innermost descent at depth 3 needs max_depth >= 4.
        let b = enc(|w| unsafe {
            peios_mp_write_array(w, 1);
            peios_mp_write_array(w, 1);
            peios_mp_write_array(w, 1);
            peios_mp_write_uint(w, 1);
        });
        unsafe {
            assert_eq!(
                peios_mp_validate(b.as_ptr() as *const c_void, b.len(), 4),
                0
            );
            assert_eq!(
                peios_mp_validate(b.as_ptr() as *const c_void, b.len(), 3),
                -1
            );
        }
    }

    #[test]
    fn empty_writer_is_invalid() {
        unsafe {
            let w = peios_mp_writer_new();
            let mut out = core::ptr::null::<c_void>();
            assert_eq!(peios_mp_writer_bytes(w, &mut out), -1); // empty payload
            peios_mp_writer_free(w);
        }
    }

    #[test]
    fn underfilled_map_is_caught_at_bytes() {
        unsafe {
            let w = peios_mp_writer_new();
            peios_mp_write_map(w, 2); // promises 2 pairs
            peios_mp_write_str(w, b"k".as_ptr() as *const c_char, 1);
            peios_mp_write_uint(w, 1); // only one pair written
            let mut out = core::ptr::null::<c_void>();
            assert_eq!(peios_mp_writer_bytes(w, &mut out), -1);
            assert_eq!(peios_mp_writer_error(w), libc::EINVAL);
            peios_mp_writer_free(w);
        }
    }

    #[test]
    fn non_utf8_str_latches() {
        unsafe {
            let w = peios_mp_writer_new();
            let bad = [0xffu8, 0xfe];
            peios_mp_write_str(w, bad.as_ptr() as *const c_char, bad.len());
            assert_eq!(peios_mp_writer_error(w), libc::EINVAL);
            peios_mp_writer_free(w);
        }
    }

    #[test]
    fn raw_escape_hatch() {
        // Build {"a":1} via raw bytes appended through write_raw.
        let raw = [0x81u8, 0xa1, b'a', 0x01];
        let b = enc(|w| unsafe { peios_mp_write_raw(w, raw.as_ptr() as *const c_void, raw.len()) });
        assert_eq!(b, raw);
        assert_eq!(
            unsafe { peios_mp_validate(b.as_ptr() as *const c_void, b.len(), DEFAULT_DEPTH) },
            0
        );
    }

    // ---- Decoder hardening: hostile / truncated / oversized inputs ----
    //
    // The reader operates on caller-supplied (potentially untrusted) bytes, so it
    // must reject every malformed shape with `-1`+EINVAL and never read out of
    // bounds, abort, or advance the cursor on failure. These drive the reader API
    // directly against raw byte buffers rather than the encoder's well-formed output.

    /// Build a reader over a raw byte buffer.
    unsafe fn reader_over(buf: &[u8]) -> peios_mp_reader {
        let mut r = peios_mp_reader { _opaque: [0; 4] };
        peios_mp_reader_init(&mut r, buf.as_ptr() as *const c_void, buf.len());
        r
    }

    #[test]
    fn reader_rejects_null_buffer_with_nonzero_length() {
        unsafe {
            let mut r = peios_mp_reader { _opaque: [0; 4] };
            peios_mp_reader_init(&mut r, core::ptr::null(), 1);

            *libc::__errno_location() = 0;
            assert_eq!(peios_mp_peek(&r), -1);
            assert_eq!(*libc::__errno_location(), libc::EINVAL);
            assert_eq!(peios_mp_reader_remaining(&r), 0);

            *libc::__errno_location() = 0;
            assert_eq!(peios_mp_read_nil(&mut r), -1);
            assert_eq!(*libc::__errno_location(), libc::EINVAL);
        }
    }

    #[test]
    fn reader_rejects_truncated_str_and_leaves_cursor_put() {
        // fixstr promising 5 bytes, only 2 present.
        let buf = [0xa5u8, b'h', b'i'];
        unsafe {
            let mut r = reader_over(&buf);
            assert_eq!(peios_mp_peek(&r), MP_STR);
            let mut out = core::ptr::null::<c_char>();
            *libc::__errno_location() = 0;
            assert_eq!(peios_mp_read_str(&mut r, &mut out), -1);
            assert_eq!(*libc::__errno_location(), libc::EINVAL);
            assert!(out.is_null());
            // The failed read consumed nothing — the lead byte is still there.
            assert_eq!(peios_mp_reader_remaining(&r), buf.len());
            assert_eq!(peios_mp_peek(&r), MP_STR);
        }
    }

    #[test]
    fn reader_rejects_oversized_length_prefix_without_reading_oob() {
        // str32 declaring ~4 GiB of payload with none present.
        let buf = [0xdbu8, 0xff, 0xff, 0xff, 0xff];
        unsafe {
            let mut r = reader_over(&buf);
            let mut out = core::ptr::null::<c_char>();
            assert_eq!(peios_mp_read_str(&mut r, &mut out), -1);
            assert_eq!(peios_mp_reader_remaining(&r), buf.len());
            // Same for an oversized bin32.
            let bin = [0xc6u8, 0xff, 0xff, 0xff, 0xff];
            let mut rb = reader_over(&bin);
            let mut bout = core::ptr::null::<c_void>();
            assert_eq!(peios_mp_read_bin(&mut rb, &mut bout), -1);
            assert_eq!(peios_mp_reader_remaining(&rb), bin.len());
        }
    }

    #[test]
    fn reader_rejects_truncated_bin_and_ext() {
        unsafe {
            // bin8 len 16, one byte present.
            let bin = [0xc4u8, 0x10, 0x00];
            let mut rb = reader_over(&bin);
            let mut bout = core::ptr::null::<c_void>();
            assert_eq!(peios_mp_read_bin(&mut rb, &mut bout), -1);
            assert_eq!(peios_mp_reader_remaining(&rb), bin.len());
            // ext8 len 4 (so 1 type + 4 data = 5 needed), only type + 1 present.
            let ext = [0xc7u8, 0x04, 0x01, 0xaa];
            let mut re = reader_over(&ext);
            let mut ty = 0i8;
            let mut eout = core::ptr::null::<c_void>();
            assert_eq!(peios_mp_read_ext(&mut re, &mut ty, &mut eout), -1);
            assert_eq!(peios_mp_reader_remaining(&re), ext.len());
        }
    }

    #[test]
    fn max_width_headers_decode_when_well_formed() {
        unsafe {
            // str16 length 5.
            let s16 = [0xdau8, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
            let mut r = reader_over(&s16);
            let mut out = core::ptr::null::<c_char>();
            assert_eq!(peios_mp_read_str(&mut r, &mut out), 5);
            assert_eq!(slice::from_raw_parts(out as *const u8, 5), b"hello");

            // array32 of one element.
            let a32 = [0xddu8, 0x00, 0x00, 0x00, 0x01, 0x07];
            let mut ra = reader_over(&a32);
            assert_eq!(peios_mp_read_array(&mut ra), 1);
            let mut v = 0u64;
            assert_eq!(peios_mp_read_uint(&mut ra, &mut v), 0);
            assert_eq!(v, 7);

            // map32 of one pair.
            let m32 = [0xdfu8, 0x00, 0x00, 0x00, 0x01, 0x07, 0xc0];
            let mut rm = reader_over(&m32);
            assert_eq!(peios_mp_read_map(&mut rm), 1);
            assert_eq!(peios_mp_read_uint(&mut rm, &mut v), 0);
            assert_eq!(peios_mp_read_nil(&mut rm), 0);
            assert_eq!(peios_mp_reader_remaining(&rm), 0);
        }
    }

    #[test]
    fn array_header_consumed_but_missing_elements_fail_on_read() {
        // array32 promising 2 elements with none present: the header parses (the
        // reader reports the count), but reading an element then fails cleanly.
        let buf = [0xddu8, 0x00, 0x00, 0x00, 0x02];
        unsafe {
            let mut r = reader_over(&buf);
            assert_eq!(peios_mp_read_array(&mut r), 2);
            assert_eq!(peios_mp_reader_remaining(&r), 0);
            let mut v = 0u64;
            assert_eq!(peios_mp_read_uint(&mut r, &mut v), -1);
            // And the whole buffer is not a valid single value.
            assert_eq!(
                peios_mp_validate(buf.as_ptr() as *const c_void, buf.len(), DEFAULT_DEPTH),
                -1
            );
        }
    }

    #[test]
    fn skip_handles_deep_nesting_and_restores_on_truncation() {
        // 50 nested single-element arrays wrapping a fixint — `skip` flattens the
        // pending count rather than recursing, so depth is bounded only by bytes.
        let mut deep = vec![0x91u8; 50];
        deep.push(0x00);
        unsafe {
            let mut r = reader_over(&deep);
            assert_eq!(peios_mp_skip(&mut r), 0);
            assert_eq!(peios_mp_reader_remaining(&r), 0);

            // A nested array whose inner element is missing: skip fails and the
            // cursor is left untouched.
            let truncated = [0x91u8, 0x91];
            let mut rt = reader_over(&truncated);
            assert_eq!(peios_mp_skip(&mut rt), -1);
            assert_eq!(peios_mp_reader_remaining(&rt), truncated.len());
        }
    }

    #[test]
    fn read_int_rejects_out_of_range_and_restores_pos() {
        // uint64 == u64::MAX does not fit i64: read_int must fail and leave the
        // cursor so read_uint still succeeds on the same bytes.
        let buf = [0xcfu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        unsafe {
            let mut r = reader_over(&buf);
            let mut i = 0i64;
            assert_eq!(peios_mp_read_int(&mut r, &mut i), -1);
            assert_eq!(peios_mp_reader_remaining(&r), buf.len());
            let mut u = 0u64;
            assert_eq!(peios_mp_read_uint(&mut r, &mut u), 0);
            assert_eq!(u, u64::MAX);
        }
    }

    #[test]
    fn reserved_and_empty_reads_fail() {
        unsafe {
            // 0xc1 is reserved — peek classifies it as invalid, reads fail.
            let bad = [0xc1u8];
            let mut r = reader_over(&bad);
            assert_eq!(peios_mp_peek(&r), -1);
            let mut v = 0u64;
            assert_eq!(peios_mp_read_uint(&mut r, &mut v), -1);
            // Empty buffer: peek and every read report end-of-input.
            let empty: [u8; 0] = [];
            let mut re = reader_over(&empty);
            assert_eq!(peios_mp_peek(&re), -1);
            assert_eq!(peios_mp_read_nil(&mut re), -1);
        }
    }
}
