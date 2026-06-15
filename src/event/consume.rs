//! Event consumption — `peios_event_attach` + the ring-buffer drain
//! (`<peios/event.h>`), the consumer side of KMES.
//!
//! KMES delivers events through per-CPU, lock-free, shared-memory ring buffers:
//! `kmes_attach(cpu_id)` (syscall 1091) returns a per-CPU fd, which the consumer
//! `mmap`s (`8192 + 2*capacity` bytes: a read-only producer metadata page, a
//! read-write consumer page, then the data region mapped **twice** back-to-back
//! so an event that wraps the capacity boundary reads contiguously). The consumer
//! then drains it, synchronising with the kernel purely through memory barriers
//! and a futex.
//!
//! Two surfaces (the caller chooses):
//!   - **High-level** [`peios_event_reader`]: owns the mmap, the read position,
//!     the acquire/release barriers, lapping + sequence-gap (lost-event) tracking,
//!     buffer-generation/resize handling, and the futex wait. Just loop
//!     `next()` / `wait()`.
//!   - **Low-level** [`peios_event_ring`]: map/unmap + barrier-correct metadata
//!     accessors + per-position event parse + the futex wait, for callers who
//!     drive their own loop.
//!
//! Only the pure event-header parsing ([`parse_event`]) is `cargo test`-able; the
//! live drain (mmap + barriers + futex) is exercised under Provium.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_long, c_void};
use core::slice;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use peios_uapi::{
    KMES_CONSUMER_NEED_WAKE_OFFSET, KMES_EVENT_HEADER_BASE_SIZE, KMES_MAPPING_CONSUMER_OFFSET,
    KMES_MAPPING_DATA_OFFSET, KMES_METADATA_TOTAL_SIZE, KMES_PRODUCER_CAPACITY_OFFSET,
    KMES_PRODUCER_FUTEX_COUNTER_OFFSET, KMES_PRODUCER_GENERATION_OFFSET,
    KMES_PRODUCER_TAIL_POS_OFFSET, KMES_PRODUCER_VERSION_OFFSET, KMES_PRODUCER_WRITE_POS_OFFSET,
    KMES_RING_MAGIC, KMES_RING_VERSION, SYS_KMES_ATTACH,
};

use crate::abi::{raw_free, raw_new};
use crate::error::set_errno;
use crate::sys::{ret_int, syscall2};

const HEADER_BASE: usize = KMES_EVENT_HEADER_BASE_SIZE as usize; // 77
const META_TOTAL: usize = KMES_METADATA_TOTAL_SIZE as usize; // 8192

// ----------------------------------------------------------------------------
// Pure event-header parsing
// ----------------------------------------------------------------------------

fn rd_u16(w: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([w[i], w[i + 1]])
}
fn rd_u32(w: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([w[i], w[i + 1], w[i + 2], w[i + 3]])
}
fn rd_u64(w: &[u8], i: usize) -> u64 {
    u64::from_le_bytes([
        w[i],
        w[i + 1],
        w[i + 2],
        w[i + 3],
        w[i + 4],
        w[i + 5],
        w[i + 6],
        w[i + 7],
    ])
}
fn rd_guid(w: &[u8], i: usize) -> [u8; 16] {
    let mut g = [0u8; 16];
    g.copy_from_slice(&w[i..i + 16]);
    g
}

/// The decoded fields of one event, with type/payload as offsets relative to the
/// event start. Pure over a byte window beginning at the event.
struct EventFields {
    event_size: u32,
    timestamp: u64,
    sequence: u64,
    cpu_id: u16,
    origin_class: u8,
    eff_guid: [u8; 16],
    true_guid: [u8; 16],
    proc_guid: [u8; 16],
    type_off: usize,
    type_len: usize,
    payload_off: usize,
    payload_len: usize,
}

/// Parse and validate one event at the start of `w` (the readable window from the
/// event onward — in the live path the double mapping guarantees `event_size`
/// contiguous bytes). Mirrors the kernel's layout and the spec's corruption
/// guards (`event_size > 0`, `event_size >= header_size`, `header_size == 77 +
/// type_len`, the whole event within bounds, and `event_size <= capacity`).
fn parse_event(w: &[u8], capacity: u64) -> Option<EventFields> {
    if w.len() < HEADER_BASE {
        return None;
    }
    let event_size = rd_u32(w, 0);
    let header_size = rd_u32(w, 4);
    if event_size == 0 || u64::from(event_size) > capacity {
        return None;
    }
    if header_size < KMES_EVENT_HEADER_BASE_SIZE || header_size > event_size {
        return None;
    }
    let type_len = rd_u16(w, 75) as usize;
    if header_size as usize != HEADER_BASE + type_len {
        return None;
    }
    if (event_size as usize) > w.len() {
        return None;
    }
    let payload_off = header_size as usize;
    Some(EventFields {
        event_size,
        timestamp: rd_u64(w, 8),
        sequence: rd_u64(w, 16),
        cpu_id: rd_u16(w, 24),
        origin_class: w[26],
        eff_guid: rd_guid(w, 27),
        true_guid: rd_guid(w, 43),
        proc_guid: rd_guid(w, 59),
        type_off: HEADER_BASE,
        type_len,
        payload_off,
        payload_len: event_size as usize - payload_off,
    })
}

// ----------------------------------------------------------------------------
// struct peios_event
// ----------------------------------------------------------------------------

/// A parsed event. The kernel-stamped header fields are copied by value; the
/// `event_type` and `payload` pointers borrow into the ring mapping and are valid
/// only until the next `next()` / read advance (and only if the slot has not been
/// overwritten). Mirrors `struct peios_event`.
#[repr(C)]
pub struct peios_event {
    pub timestamp: u64,
    pub sequence: u64,
    pub cpu_id: u16,
    pub origin_class: u8,
    pub effective_token_guid: [u8; 16],
    pub true_token_guid: [u8; 16],
    pub process_guid: [u8; 16],
    pub event_type: *const c_char,
    pub event_type_len: u16,
    pub payload: *const c_void,
    pub payload_len: u32,
}

// ----------------------------------------------------------------------------
// Internal ring representation
// ----------------------------------------------------------------------------

/// Barrier-correct atomic load at a metadata offset (the kernel stores these with
/// release; we load with acquire). The offset is naturally aligned in the page.
#[inline]
unsafe fn load_u64_acq(base: *const u8, off: u32) -> u64 {
    (*(base.add(off as usize) as *const AtomicU64)).load(Ordering::Acquire)
}
#[inline]
unsafe fn load_u32_acq(base: *const u8, off: u32) -> u32 {
    (*(base.add(off as usize) as *const AtomicU32)).load(Ordering::Acquire)
}

#[derive(Clone, Copy)]
struct Ring {
    base: *mut u8,
    capacity: u64,
    map_len: usize,
}

/// What a futex/poll wait concluded.
enum Wait {
    /// Events are (or became) available — drain.
    Ready,
    /// The wait timed out or was interrupted with nothing new.
    Idle,
    /// A hard error (errno set).
    Error,
}

impl Ring {
    fn producer(&self) -> *const u8 {
        self.base
    }
    fn consumer(&self) -> *mut u8 {
        unsafe { self.base.add(KMES_MAPPING_CONSUMER_OFFSET as usize) }
    }
    fn data(&self) -> *const u8 {
        unsafe { self.base.add(KMES_MAPPING_DATA_OFFSET as usize) }
    }

    fn write_pos(&self) -> u64 {
        unsafe { load_u64_acq(self.producer(), KMES_PRODUCER_WRITE_POS_OFFSET) }
    }
    fn tail_pos(&self) -> u64 {
        unsafe { load_u64_acq(self.producer(), KMES_PRODUCER_TAIL_POS_OFFSET) }
    }
    fn generation(&self) -> u64 {
        unsafe { load_u64_acq(self.producer(), KMES_PRODUCER_GENERATION_OFFSET) }
    }
    fn futex_counter(&self) -> u32 {
        unsafe { load_u32_acq(self.producer(), KMES_PRODUCER_FUTEX_COUNTER_OFFSET) }
    }

    /// Set the advisory `need_wake` flag: release when arming (so the kernel sees
    /// it before we sleep), relaxed when clearing (a spurious wake is harmless).
    fn set_need_wake(&self, on: bool) {
        let p = unsafe { self.consumer().add(KMES_CONSUMER_NEED_WAKE_OFFSET as usize) };
        let cell = unsafe { &*(p as *const AtomicU8) };
        cell.store(u8::from(on), if on { Ordering::Release } else { Ordering::Relaxed });
    }

    /// Parse the event at `read_pos` into `out` (pointers into the mapping);
    /// returns its `event_size` (to advance `read_pos`), or `None` if corrupt.
    unsafe fn event_at(&self, read_pos: u64, out: *mut peios_event) -> Option<u64> {
        let off = (read_pos & (self.capacity - 1)) as usize;
        // From the event start to the end of the (double-mapped) data region.
        let avail = self.map_len - META_TOTAL - off;
        let evstart = self.data().add(off);
        let w = slice::from_raw_parts(evstart, avail);
        let f = parse_event(w, self.capacity)?;
        if let Some(out) = out.as_mut() {
            out.timestamp = f.timestamp;
            out.sequence = f.sequence;
            out.cpu_id = f.cpu_id;
            out.origin_class = f.origin_class;
            out.effective_token_guid = f.eff_guid;
            out.true_token_guid = f.true_guid;
            out.process_guid = f.proc_guid;
            out.event_type = evstart.add(f.type_off) as *const c_char;
            out.event_type_len = f.type_len as u16;
            out.payload = evstart.add(f.payload_off) as *const c_void;
            out.payload_len = f.payload_len as u32;
        }
        Some(u64::from(f.event_size))
    }

    /// Block until events past `read_pos` may be available, or the timeout fires.
    /// Implements the spec's notification-wait: arm `need_wake`, re-check
    /// `write_pos` to close the race, then `FUTEX_WAIT` on the counter.
    fn wait(&self, read_pos: u64, timeout_ms: c_int) -> Wait {
        self.set_need_wake(true);
        if self.write_pos() != read_pos {
            self.set_need_wake(false);
            return Wait::Ready; // raced — events appeared
        }
        let observed = self.futex_counter();
        let r = unsafe { futex_wait(self.futex_ptr(), observed, timeout_ms) };
        self.set_need_wake(false);
        if r == 0 {
            return Wait::Ready; // woken
        }
        match crate::error::get_errno() {
            // The counter already moved (events arrived before we slept), or a
            // benign interruption — tell the caller to drain.
            libc::EAGAIN => Wait::Ready,
            libc::EINTR | libc::ETIMEDOUT => Wait::Idle,
            _ => Wait::Error,
        }
    }

    fn futex_ptr(&self) -> *const u32 {
        unsafe { self.producer().add(KMES_PRODUCER_FUTEX_COUNTER_OFFSET as usize) as *const u32 }
    }

    unsafe fn unmap(&self) {
        if !self.base.is_null() {
            libc::munmap(self.base as *mut c_void, self.map_len);
        }
    }
}

/// `FUTEX_WAIT` on a shared futex word (the mapping is `MAP_SHARED`, so this is
/// not a private futex). Returns 0 when woken, `-1` with errno otherwise.
unsafe fn futex_wait(addr: *const u32, expected: u32, timeout_ms: c_int) -> c_int {
    let ts;
    let ts_ptr = if timeout_ms < 0 {
        core::ptr::null::<libc::timespec>()
    } else {
        ts = libc::timespec {
            tv_sec: (timeout_ms / 1000) as libc::time_t,
            tv_nsec: ((timeout_ms % 1000) * 1_000_000) as _,
        };
        &ts as *const libc::timespec
    };
    libc::syscall(
        libc::SYS_futex,
        addr as usize as c_long,
        libc::FUTEX_WAIT as c_long,
        expected as c_long,
        ts_ptr as usize as c_long,
        0 as c_long,
        0 as c_long,
    ) as c_int
}

/// mmap a ring fd and validate its magic/version/capacity. `Err(errno)` on
/// failure (the mapping, if any, is released).
unsafe fn map_ring(fd: c_int, capacity: u64) -> Result<Ring, c_int> {
    let Some(map_len) = (capacity as usize)
        .checked_mul(2)
        .and_then(|d| d.checked_add(META_TOTAL))
    else {
        return Err(libc::EINVAL);
    };
    let p = libc::mmap(
        core::ptr::null_mut(),
        map_len,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_SHARED,
        fd,
        0,
    );
    if p == libc::MAP_FAILED {
        return Err(crate::error::get_errno());
    }
    let base = p as *mut u8;
    let ring = Ring {
        base,
        capacity,
        map_len,
    };
    // Validate the producer page: magic, version, and that the advertised
    // capacity matches what we mapped.
    let magic = slice::from_raw_parts(base, KMES_RING_MAGIC.len());
    let version = load_u32_acq(base, KMES_PRODUCER_VERSION_OFFSET);
    let page_cap = load_u64_acq(base, KMES_PRODUCER_CAPACITY_OFFSET);
    if magic != KMES_RING_MAGIC || version != KMES_RING_VERSION || page_cap != capacity {
        ring.unmap();
        return Err(libc::EINVAL);
    }
    Ok(ring)
}

// ----------------------------------------------------------------------------
// peios_event_attach
// ----------------------------------------------------------------------------

/// `peios_event_attach` — attach to CPU `cpu_id`'s ring buffer, returning a fd
/// and writing the data-region capacity to `capacity_out`. Returns `-1` with
/// errno (`EINVAL` once `cpu_id` is past the last CPU — the idiom for discovering
/// the CPU count — `EPERM` without `SeSecurityPrivilege`). Requires
/// `SeSecurityPrivilege`.
///
/// # Safety
/// `capacity_out` must be NULL or valid for a `u64` write.
#[no_mangle]
pub unsafe extern "C" fn peios_event_attach(cpu_id: u32, capacity_out: *mut u64) -> c_int {
    ret_int(syscall2(
        SYS_KMES_ATTACH,
        cpu_id as c_long,
        capacity_out as usize as c_long,
    ))
}

// ----------------------------------------------------------------------------
// Low-level ring surface (peios_event_ring)
// ----------------------------------------------------------------------------

/// `peios_event_ring` — a mapped ring buffer; opaque storage holds the base
/// pointer, capacity, and mapping length.
#[repr(C)]
pub struct peios_event_ring {
    _opaque: [u64; 4],
}

const _: () = assert!(core::mem::size_of::<peios_event_ring>() == 32);

impl peios_event_ring {
    fn load(&self) -> Ring {
        Ring {
            base: self._opaque[0] as usize as *mut u8,
            capacity: self._opaque[1],
            map_len: self._opaque[2] as usize,
        }
    }
    fn store(&mut self, r: Ring) {
        self._opaque = [r.base as usize as u64, r.capacity, r.map_len as u64, 0];
    }
}

/// `peios_event_ring_map` — mmap and validate a ring fd into `ring`. `capacity`
/// is the value from `peios_event_attach`. Returns 0, or `-1` with errno.
///
/// # Safety
/// `ring` must be valid for writing; `fd` a ring fd from `peios_event_attach`.
#[no_mangle]
pub unsafe extern "C" fn peios_event_ring_map(
    fd: c_int,
    capacity: u64,
    ring: *mut peios_event_ring,
) -> c_int {
    let Some(ring) = ring.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match map_ring(fd, capacity) {
        Ok(r) => {
            ring.store(r);
            0
        }
        Err(errno) => {
            set_errno(errno);
            -1
        }
    }
}

/// `peios_event_ring_unmap` — release a mapping (NULL-safe; idempotent fields are
/// zeroed).
#[no_mangle]
pub unsafe extern "C" fn peios_event_ring_unmap(ring: *mut peios_event_ring) {
    if let Some(ring) = ring.as_mut() {
        ring.load().unmap();
        ring._opaque = [0; 4];
    }
}

/// `peios_event_ring_capacity` — the data-region capacity in bytes.
#[no_mangle]
pub unsafe extern "C" fn peios_event_ring_capacity(ring: *const peios_event_ring) -> u64 {
    match ring.as_ref() {
        Some(r) => r.load().capacity,
        None => 0,
    }
}

/// `peios_event_ring_write_pos` — the producer's write position (acquire load).
#[no_mangle]
pub unsafe extern "C" fn peios_event_ring_write_pos(ring: *const peios_event_ring) -> u64 {
    match ring.as_ref() {
        Some(r) => r.load().write_pos(),
        None => 0,
    }
}

/// `peios_event_ring_tail_pos` — the oldest surviving position (acquire load).
#[no_mangle]
pub unsafe extern "C" fn peios_event_ring_tail_pos(ring: *const peios_event_ring) -> u64 {
    match ring.as_ref() {
        Some(r) => r.load().tail_pos(),
        None => 0,
    }
}

/// `peios_event_ring_generation` — the buffer generation (bumped on resize).
#[no_mangle]
pub unsafe extern "C" fn peios_event_ring_generation(ring: *const peios_event_ring) -> u64 {
    match ring.as_ref() {
        Some(r) => r.load().generation(),
        None => 0,
    }
}

/// `peios_event_ring_set_need_wake` — arm (`set != 0`) or clear the advisory
/// wake flag.
#[no_mangle]
pub unsafe extern "C" fn peios_event_ring_set_need_wake(ring: *const peios_event_ring, set: c_int) {
    if let Some(r) = ring.as_ref() {
        r.load().set_need_wake(set != 0);
    }
}

/// `peios_event_ring_event_at` — parse the event at `read_pos` into `out`;
/// returns its byte size (advance `read_pos` by it), or `-1` if the slot is
/// corrupt. The caller is responsible for the empty (`write_pos`) and lapping
/// (`tail_pos`) checks.
///
/// # Safety
/// `ring` must be a mapped ring; `out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn peios_event_ring_event_at(
    ring: *const peios_event_ring,
    read_pos: u64,
    out: *mut peios_event,
) -> isize {
    let Some(ring) = ring.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match ring.load().event_at(read_pos, out) {
        Some(size) => size as isize,
        None => {
            set_errno(libc::EINVAL);
            -1
        }
    }
}

/// `peios_event_ring_wait` — block until events past `read_pos` may be available
/// or `timeout_ms` elapses (negative = forever). Returns 1 (drain now), 0
/// (timeout / interrupted), or `-1` on error.
///
/// # Safety
/// `ring` must be a mapped ring.
#[no_mangle]
pub unsafe extern "C" fn peios_event_ring_wait(
    ring: *const peios_event_ring,
    read_pos: u64,
    timeout_ms: c_int,
) -> c_int {
    let Some(ring) = ring.as_ref() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match ring.load().wait(read_pos, timeout_ms) {
        Wait::Ready => 1,
        Wait::Idle => 0,
        Wait::Error => -1,
    }
}

// ----------------------------------------------------------------------------
// High-level reader (peios_event_reader)
// ----------------------------------------------------------------------------

/// `peios_event_reader` — owns a ring mapping plus the drain state.
pub struct peios_event_reader {
    ring: Ring,
    fd: c_int,
    cpu_id: u32,
    read_pos: u64,
    last_seq: u64,
    lost: u64,
    generation: u64,
}

/// Attach + map CPU `cpu_id`, starting the read position at the oldest surviving
/// event. `Err(errno)` on failure.
unsafe fn attach_and_map(cpu_id: u32) -> Result<(c_int, Ring, u64, u64), c_int> {
    let mut capacity: u64 = 0;
    let fd = ret_int(syscall2(
        SYS_KMES_ATTACH,
        cpu_id as c_long,
        &mut capacity as *mut u64 as usize as c_long,
    ));
    if fd < 0 {
        return Err(crate::error::get_errno());
    }
    match map_ring(fd, capacity) {
        Ok(ring) => {
            let start = ring.tail_pos();
            let gen = ring.generation();
            Ok((fd, ring, start, gen))
        }
        Err(errno) => {
            libc::close(fd);
            Err(errno)
        }
    }
}

impl peios_event_reader {
    /// Re-attach after a generation change (resize): drop the old mapping/fd and
    /// map the new buffer, resuming at its oldest event. Cross-resize loss is
    /// still caught by sequence gaps (the counter is per-CPU, per-boot monotonic).
    unsafe fn reattach(&mut self) -> Result<(), c_int> {
        let (fd, ring, start, gen) = attach_and_map(self.cpu_id)?;
        self.ring.unmap();
        libc::close(self.fd);
        self.ring = ring;
        self.fd = fd;
        self.read_pos = start;
        self.generation = gen;
        Ok(())
    }

    /// One drain step. `Ok(true)` filled `out`; `Ok(false)` means nothing
    /// available; `Err(errno)` is a hard error (a re-attach failure).
    unsafe fn next(&mut self, out: *mut peios_event) -> Result<bool, c_int> {
        loop {
            if self.ring.generation() != self.generation {
                self.reattach()?;
                continue;
            }
            let write_pos = self.ring.write_pos();
            if write_pos == self.read_pos {
                return Ok(false);
            }
            let tail = self.ring.tail_pos();
            if self.read_pos < tail {
                self.read_pos = tail; // lapped — skip to the oldest survivor
                continue;
            }
            let saved_tail = tail;
            let Some(size) = self.ring.event_at(self.read_pos, out) else {
                // Corrupt slot: resynchronise to the tail and retry.
                self.read_pos = self.ring.tail_pos();
                continue;
            };
            // Torn-read guard: if the tail advanced past us while we read, the
            // bytes may have been overwritten — discard and retry.
            let tail2 = self.ring.tail_pos();
            if tail2 > saved_tail && self.read_pos < tail2 {
                continue;
            }
            if let Some(out) = out.as_ref() {
                if self.last_seq != 0 && out.sequence > self.last_seq + 1 {
                    self.lost += out.sequence - self.last_seq - 1;
                }
                self.last_seq = out.sequence;
            }
            self.read_pos += size;
            return Ok(true);
        }
    }
}

/// `peios_event_reader_open` — attach to CPU `cpu_id` and map its ring, ready to
/// drain. Returns NULL with errno on failure (`EPERM` without
/// `SeSecurityPrivilege`, `EINVAL` for an out-of-range CPU, `ENOMEM` on OOM).
#[no_mangle]
pub unsafe extern "C" fn peios_event_reader_open(cpu_id: u32) -> *mut peios_event_reader {
    let (fd, ring, start, gen) = match attach_and_map(cpu_id) {
        Ok(v) => v,
        Err(errno) => {
            set_errno(errno);
            return core::ptr::null_mut();
        }
    };
    let reader = raw_new(peios_event_reader {
        ring,
        fd,
        cpu_id,
        read_pos: start,
        last_seq: 0,
        lost: 0,
        generation: gen,
    });
    if reader.is_null() {
        ring.unmap();
        libc::close(fd);
        set_errno(libc::ENOMEM);
    }
    reader
}

/// `peios_event_reader_close` — unmap the ring, close the fd, free the reader
/// (NULL-safe).
#[no_mangle]
pub unsafe extern "C" fn peios_event_reader_close(reader: *mut peios_event_reader) {
    if let Some(r) = reader.as_mut() {
        r.ring.unmap();
        libc::close(r.fd);
    }
    raw_free(reader);
}

/// `peios_event_reader_next` — fetch the next event into `out`. Returns 1 (event
/// filled), 0 (none available — consider `peios_event_reader_wait`), or `-1` with
/// errno. Lapping, sequence-gap loss, and buffer resizes are handled internally;
/// the `out` pointers are valid until the next call.
///
/// # Safety
/// `reader` must be open; `out` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn peios_event_reader_next(
    reader: *mut peios_event_reader,
    out: *mut peios_event,
) -> c_int {
    let Some(reader) = reader.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    match reader.next(out) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(errno) => {
            set_errno(errno);
            -1
        }
    }
}

/// `peios_event_reader_wait` — block until events are available or `timeout_ms`
/// elapses (negative = forever). Returns 1 (call `next`), 0 (timeout /
/// interrupted), or `-1` on error.
///
/// # Safety
/// `reader` must be open.
#[no_mangle]
pub unsafe extern "C" fn peios_event_reader_wait(
    reader: *mut peios_event_reader,
    timeout_ms: c_int,
) -> c_int {
    let Some(reader) = reader.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    // A resize could have happened while idle; refresh before sleeping.
    if reader.ring.generation() != reader.generation {
        if let Err(errno) = reader.reattach() {
            set_errno(errno);
            return -1;
        }
        return 1;
    }
    match reader.ring.wait(reader.read_pos, timeout_ms) {
        Wait::Ready => 1,
        Wait::Idle => 0,
        Wait::Error => -1,
    }
}

/// `peios_event_reader_lost` — the cumulative count of events lost (overwritten
/// or dropped), inferred from per-CPU sequence gaps.
#[no_mangle]
pub unsafe extern "C" fn peios_event_reader_lost(reader: *const peios_event_reader) -> u64 {
    match reader.as_ref() {
        Some(r) => r.lost,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Build one event's bytes: header + type + payload.
    fn event(seq: u64, ts: u64, cpu: u16, origin: u8, etype: &[u8], payload: &[u8]) -> Vec<u8> {
        let header_size = HEADER_BASE + etype.len();
        let event_size = header_size + payload.len();
        let mut e = Vec::new();
        e.extend_from_slice(&(event_size as u32).to_le_bytes()); // 0
        e.extend_from_slice(&(header_size as u32).to_le_bytes()); // 4
        e.extend_from_slice(&ts.to_le_bytes()); // 8
        e.extend_from_slice(&seq.to_le_bytes()); // 16
        e.extend_from_slice(&cpu.to_le_bytes()); // 24
        e.push(origin); // 26
        e.extend_from_slice(&[0xA1; 16]); // 27 effective guid
        e.extend_from_slice(&[0xB2; 16]); // 43 true guid
        e.extend_from_slice(&[0xC3; 16]); // 59 process guid
        e.extend_from_slice(&(etype.len() as u16).to_le_bytes()); // 75 type_len
        e.extend_from_slice(etype); // 77
        e.extend_from_slice(payload);
        assert_eq!(e.len(), event_size);
        e
    }

    #[test]
    fn parse_valid_event() {
        let et = b"net.connect";
        let pl = [0x81u8, 0xa1, b'a', 0x01]; // {"a":1}
        let bytes = event(7, 123_456, 2, 0, et, &pl);
        let f = parse_event(&bytes, 1 << 20).unwrap();
        assert_eq!(f.event_size as usize, bytes.len());
        assert_eq!(f.timestamp, 123_456);
        assert_eq!(f.sequence, 7);
        assert_eq!(f.cpu_id, 2);
        assert_eq!(f.origin_class, 0);
        assert_eq!(f.eff_guid, [0xA1; 16]);
        assert_eq!(f.true_guid, [0xB2; 16]);
        assert_eq!(f.proc_guid, [0xC3; 16]);
        assert_eq!(f.type_off, 77);
        assert_eq!(f.type_len, et.len());
        assert_eq!(&bytes[f.type_off..f.type_off + f.type_len], et);
        assert_eq!(f.payload_len, pl.len());
        assert_eq!(&bytes[f.payload_off..f.payload_off + f.payload_len], &pl);
    }

    #[test]
    fn parse_zero_payload_event() {
        // A kernel-emitted event may have no payload (event_size == header_size).
        let bytes = event(1, 1, 0, 1, b"kmes.up", &[]);
        let f = parse_event(&bytes, 1 << 20).unwrap();
        assert_eq!(f.payload_len, 0);
        assert_eq!(f.type_len, 7);
    }

    #[test]
    fn parse_rejects_corruption() {
        let good = event(1, 1, 0, 0, b"x", &[0xc0]);
        // event_size == 0
        let mut z = good.clone();
        z[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse_event(&z, 1 << 20).is_none());
        // header_size > event_size
        let mut h = good.clone();
        h[4..8].copy_from_slice(&9999u32.to_le_bytes());
        assert!(parse_event(&h, 1 << 20).is_none());
        // header_size != 77 + type_len (tamper type_len)
        let mut t = good.clone();
        t[75..77].copy_from_slice(&5u16.to_le_bytes());
        assert!(parse_event(&t, 1 << 20).is_none());
        // event_size larger than capacity
        assert!(parse_event(&good, 4).is_none());
        // truncated buffer (declared bigger than provided)
        assert!(parse_event(&good[..good.len() - 1], 1 << 20).is_none());
        // header-only-too-short
        assert!(parse_event(&good[..10], 1 << 20).is_none());
    }

    #[test]
    fn reader_struct_is_sized() {
        assert_eq!(core::mem::size_of::<peios_event_ring>(), 32);
        // peios_event carries the kernel header by value plus two borrowed pointers.
        assert!(core::mem::size_of::<peios_event>() >= 8 + 8 + 2 + 1 + 48 + 8 + 2 + 8 + 4);
    }
}
