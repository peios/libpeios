//! The emission policy — `peios_event_policy_*` (`<peios/event.h>`), PGSS §6.9.
//!
//! Before an emitter builds an event's payload it asks whether the event's type
//! is switched on. The answer comes from the registry tree under
//! `Machine\Generic\Events`: one key per segment of the type, each optionally
//! holding an `Enabled` `REG_DWORD` of 0 or 1. The deepest `Enabled` on the
//! type's path wins; with none, the tier decides (standard on, verbose and debug
//! off). Essential types never consult the tree.
//!
//! This is a separate query rather than a check inside `peios_event_emit`
//! because the point is to skip *building* the payload, and by the time emit is
//! called the payload is built. Emit itself is unchanged.
//!
//! A `peios_event_policy` handle caches each type's resolved setting and keeps
//! the cache current with a registry watch:
//!
//! - **Root present.** `Events` is opened `KEY_READ` and armed with a subtree
//!   watch (values and subkeys). Every decision first drains the watch fd
//!   (non-blocking); any record clears the cache, so a committed change applies
//!   to the very next decision. `KEY_DELETED` on `Events` itself, or a read
//!   failure, drops the handle back to establishing.
//! - **Root absent** (`ENOENT`). The nearest existing ancestor
//!   (`Machine\Generic`, else `Machine`) is watched for subkey changes; any
//!   record re-establishes. Every type resolves by tier alone meanwhile.
//! - **Nothing watchable** (no LCS source yet, access denied, a watch that
//!   cannot be armed). Decisions use whatever could be read, and the handle
//!   clears its cache and re-establishes once a second. That is the one-second
//!   bound PGSS §6.9 sets.
//!
//! Registry trouble never fails a decision: an unreadable policy is decided by
//! tier (PGSS §6.9). Only caller error (`EINVAL`) returns `-1`.
//!
//! A handle is not thread-safe, and must not be used on both sides of a
//! `fork()`: the child shares the parent's watch fd, and draining it would steal
//! the parent's notifications. A child opens its own handle.

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_void};
use core::slice;

use alloc::boxed::Box;
use alloc::vec::Vec;

use peios_uapi::{
    KEY_NOTIFY, KEY_QUERY_VALUE, KEY_READ, REG_DWORD, REG_NOTIFY_SUBKEY, REG_NOTIFY_VALUE,
    REG_WATCH_EVENT_MIN_SIZE, REG_WATCH_EVENT_NAME_LEN_OFFSET, REG_WATCH_EVENT_NAME_OFFSET,
    REG_WATCH_EVENT_TOTAL_LEN_OFFSET, REG_WATCH_EVENT_TYPE_OFFSET, REG_WATCH_KEY_DELETED,
};

use crate::abi::{raw_free, raw_new};
use crate::error::{get_errno, set_errno};
use crate::registry::key::{peios_reg_notify, peios_reg_open_key};
use crate::registry::value::{peios_reg_query_value, peios_reg_value};

/// `PEIOS_EVENT_TIER_ESSENTIAL` — never switched off; never consults the policy.
pub const PEIOS_EVENT_TIER_ESSENTIAL: u32 = 0;
/// `PEIOS_EVENT_TIER_STANDARD` — on unless the policy switches it off.
pub const PEIOS_EVENT_TIER_STANDARD: u32 = 1;
/// `PEIOS_EVENT_TIER_VERBOSE` — off unless the policy switches it on.
pub const PEIOS_EVENT_TIER_VERBOSE: u32 = 2;
/// `PEIOS_EVENT_TIER_DEBUG` — off unless the policy switches it on.
pub const PEIOS_EVENT_TIER_DEBUG: u32 = 3;

/// The policy root, and the ancestors watched while it does not exist.
const ROOT_PATH: &[u8] = b"Machine\\Generic\\Events\0";
const ANCESTOR_PATHS: [&[u8]; 2] = [b"Machine\\Generic\0", b"Machine\0"];
const ENABLED: &[u8] = b"Enabled";

/// How long an unwatched handle trusts what it has read (PGSS §6.9's bound).
const UNWATCHED_TTL_NS: u64 = 1_000_000_000;
/// Cached types per handle; a full cache is cleared, not evicted piecemeal.
const CACHE_MAX: usize = 4096;
/// One watch `read()`. A record that does not fit fails `EINVAL`, which tears the
/// watch down and re-establishes it with an empty queue.
const WATCH_BUF: usize = 64 * 1024;

// ----------------------------------------------------------------------------
// Pure resolution (unit-tested)
// ----------------------------------------------------------------------------

/// Split an event type into its segments, or `None` if it is malformed: empty,
/// not UTF-8, with an empty segment, or with a byte no registry key name may
/// hold (`\` or NUL).
fn segments(event_type: &[u8]) -> Option<Vec<&[u8]>> {
    if event_type.is_empty() || core::str::from_utf8(event_type).is_err() {
        return None;
    }
    let mut out = Vec::new();
    for seg in event_type.split(|&b| b == b'.') {
        if seg.is_empty() || seg.iter().any(|&b| b == b'\\' || b == 0) {
            return None;
        }
        out.try_reserve(1).ok()?;
        out.push(seg);
    }
    Some(out)
}

/// Interpret an `Enabled` value: a `REG_DWORD` of 0 or 1 is a setting; anything
/// else is ignored (PGSS *events.policy.other-enabled-values-are-ignored).
fn interpret_enabled(value_type: u32, data: &[u8]) -> Option<bool> {
    if value_type != REG_DWORD || data.len() != 4 {
        return None;
    }
    match u32::from_le_bytes([data[0], data[1], data[2], data[3]]) {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

/// The registry as the walk sees it. `None` from `root`/`child` is a key that is
/// missing or may not be read; either ends the walk.
trait PolicyTree {
    type Key;
    fn root(&mut self) -> Option<Self::Key>;
    fn child(&mut self, parent: &Self::Key, segment: &[u8]) -> Option<Self::Key>;
    /// The key's `Enabled` setting, already interpreted.
    fn enabled(&mut self, key: &Self::Key) -> Option<bool>;
}

/// Walk `Events` and one key per segment; the deepest setting wins. `None` means
/// nothing on the path is set, and the tier decides.
fn resolve<T: PolicyTree>(tree: &mut T, segs: &[&[u8]]) -> Option<bool> {
    let mut setting = None;
    let mut key = tree.root()?;
    let mut depth = 0;
    loop {
        if let Some(s) = tree.enabled(&key) {
            setting = Some(s);
        }
        let Some(seg) = segs.get(depth) else {
            return setting;
        };
        match tree.child(&key, seg) {
            Some(next) => key = next,
            None => return setting,
        }
        depth += 1;
    }
}

/// Combine the resolved setting with the tier. `None` for an unknown tier.
fn decide(tier: u32, setting: Option<bool>) -> Option<bool> {
    match tier {
        PEIOS_EVENT_TIER_ESSENTIAL => Some(true),
        PEIOS_EVENT_TIER_STANDARD => Some(setting.unwrap_or(true)),
        PEIOS_EVENT_TIER_VERBOSE | PEIOS_EVENT_TIER_DEBUG => Some(setting.unwrap_or(false)),
        _ => None,
    }
}

/// What a drained batch of watch records says.
#[derive(Debug, Default, PartialEq, Eq)]
struct WatchNews {
    /// At least one record arrived: the cache is stale.
    changed: bool,
    /// The watched key itself became invisible: the watch must be re-established.
    gone: bool,
}

fn le_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

/// Classify the records of one `read()`. Advances by `total_len`; a record is a
/// `KEY_DELETED` for the watched key itself when it is the bare form or its
/// `path_depth` is 0 (Kernel TRM §5.6.2). A malformed buffer counts as `gone`,
/// so the watch is rebuilt rather than trusted.
fn classify_records(buf: &[u8]) -> WatchNews {
    let min = REG_WATCH_EVENT_MIN_SIZE as usize;
    let mut news = WatchNews::default();
    let mut off = 0usize;
    while off < buf.len() {
        let rec = &buf[off..];
        let Some(total) = le_u32(rec, REG_WATCH_EVENT_TOTAL_LEN_OFFSET as usize) else {
            news.gone = true;
            break;
        };
        let total = total as usize;
        if total < min || total > rec.len() {
            news.gone = true;
            break;
        }
        let rec = &rec[..total];
        news.changed = true;
        let ty = le_u16(rec, REG_WATCH_EVENT_TYPE_OFFSET as usize).unwrap_or(0);
        if u32::from(ty) == REG_WATCH_KEY_DELETED {
            let name_len = le_u16(rec, REG_WATCH_EVENT_NAME_LEN_OFFSET as usize).unwrap_or(0);
            let depth_at = REG_WATCH_EVENT_NAME_OFFSET as usize + name_len as usize;
            if le_u16(rec, depth_at).unwrap_or(0) == 0 {
                news.gone = true;
            }
        }
        off += total;
    }
    news
}

// ----------------------------------------------------------------------------
// Registry I/O
// ----------------------------------------------------------------------------

/// An owned registry key fd, closed on drop.
struct KeyFd(c_int);

impl Drop for KeyFd {
    fn drop(&mut self) {
        // SAFETY: we own the fd.
        unsafe { libc::close(self.0) };
    }
}

/// Open `path` (NUL-terminated) relative to `parent` (or absolute when `< 0`).
fn open_key(parent: c_int, path: &[u8], access: u32) -> Result<KeyFd, c_int> {
    // SAFETY: `path` is NUL-terminated by every caller.
    let fd = unsafe { peios_reg_open_key(parent, path.as_ptr() as *const c_char, access, 0) };
    if fd < 0 {
        Err(get_errno())
    } else {
        Ok(KeyFd(fd))
    }
}

/// Arm a watch and make the fd non-blocking, so a drain never waits.
fn arm(fd: c_int, filter: u32, subtree: bool) -> bool {
    // SAFETY: `fd` is an open registry key fd.
    unsafe {
        if peios_reg_notify(fd, filter, subtree as c_int) != 0 {
            return false;
        }
        let flags = libc::fcntl(fd, libc::F_GETFL);
        flags >= 0 && libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0
    }
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is writable. COARSE is a vDSO read: no syscall per decision.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut ts) } != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

/// The live registry, walked from the open `Events` fd by relative opens (LCS
/// does no access check on a relative open's parent).
struct LiveTree {
    root: c_int,
}

impl PolicyTree for LiveTree {
    // A borrowed root fd, or an owned fd beneath it.
    type Key = (c_int, Option<KeyFd>);

    fn root(&mut self) -> Option<Self::Key> {
        Some((self.root, None))
    }

    fn child(&mut self, parent: &Self::Key, segment: &[u8]) -> Option<Self::Key> {
        let mut path: Vec<u8> = Vec::new();
        path.try_reserve(segment.len() + 1).ok()?;
        path.extend_from_slice(segment);
        path.push(0);
        let fd = open_key(parent.0, &path, KEY_QUERY_VALUE).ok()?;
        Some((fd.0, Some(fd)))
    }

    fn enabled(&mut self, key: &Self::Key) -> Option<bool> {
        // A 4-byte data buffer: a REG_DWORD fits, and anything larger is ERANGE,
        // which is not a setting anyway. The layer buffer must hold the effective
        // layer's name or the whole read is ERANGE; 256 covers any layer name.
        let mut data = [0u8; 4];
        let mut layer = [0u8; 256];
        let mut v = peios_reg_value {
            sequence: 0,
            data: data.as_mut_ptr() as *mut c_void,
            layer: layer.as_mut_ptr() as *mut c_void,
            type_: 0,
            data_cap: data.len() as u32,
            data_len: 0,
            layer_cap: layer.len() as u32,
            layer_len: 0,
        };
        // SAFETY: the name and both buffers are live for the call.
        let r = unsafe {
            peios_reg_query_value(
                key.0,
                ENABLED.as_ptr() as *const c_void,
                ENABLED.len() as u32,
                -1,
                &mut v,
            )
        };
        if r != 0 {
            return None;
        }
        interpret_enabled(v.type_, data.get(..v.data_len as usize)?)
    }
}

// ----------------------------------------------------------------------------
// The handle
// ----------------------------------------------------------------------------

/// `peios_event_policy` — a cached, watched view of the emission policy.
pub struct peios_event_policy {
    /// `Events`, opened `KEY_READ`, when it exists and could be opened.
    root: Option<KeyFd>,
    /// Whether `root` carries an armed subtree watch.
    root_watched: bool,
    /// A watched ancestor, while `Events` does not exist.
    ancestor: Option<KeyFd>,
    /// When nothing is watched: when to drop the cache and try again.
    retry_at: u64,
    /// The read buffer for watch records, allocated with the first watch.
    buf: Option<Box<[u8]>>,
    /// Resolved settings by event type, sorted by type for binary search.
    cache: Vec<(Box<[u8]>, Option<bool>)>,
}

impl peios_event_policy {
    fn new() -> Self {
        peios_event_policy {
            root: None,
            root_watched: false,
            ancestor: None,
            retry_at: 0,
            buf: None,
            cache: Vec::new(),
        }
    }

    fn teardown(&mut self) {
        self.root = None;
        self.root_watched = false;
        self.ancestor = None;
        self.cache.clear();
    }

    fn ensure_buf(&mut self) -> bool {
        if self.buf.is_none() {
            let mut v: Vec<u8> = Vec::new();
            if v.try_reserve_exact(WATCH_BUF).is_err() {
                return false;
            }
            v.resize(WATCH_BUF, 0);
            self.buf = Some(v.into_boxed_slice());
        }
        true
    }

    /// Open and watch what exists. Leaves the cache empty.
    fn establish(&mut self, now: u64) {
        self.teardown();
        // Twice at most: once more if `Events` appeared while an ancestor watch
        // was being armed, so that creation is not missed.
        for _ in 0..2 {
            match open_key(-1, ROOT_PATH, KEY_READ) {
                Ok(fd) => {
                    self.root_watched = self.ensure_buf()
                        && arm(fd.0, REG_NOTIFY_VALUE | REG_NOTIFY_SUBKEY, true);
                    self.root = Some(fd);
                    self.ancestor = None;
                    break;
                }
                Err(e) if e == libc::ENOENT && self.ancestor.is_none() => {
                    for path in ANCESTOR_PATHS {
                        if let Ok(fd) = open_key(-1, path, KEY_NOTIFY) {
                            if self.ensure_buf() && arm(fd.0, REG_NOTIFY_SUBKEY, false) {
                                self.ancestor = Some(fd);
                                break;
                            }
                        }
                    }
                    if self.ancestor.is_none() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if !self.root_watched && self.ancestor.is_none() {
            self.retry_at = now.saturating_add(UNWATCHED_TTL_NS);
        }
    }

    /// Drain the watch fd. `None` when nothing is watched.
    fn drain(&mut self) -> Option<WatchNews> {
        let fd = match (&self.root, self.root_watched, &self.ancestor) {
            (Some(root), true, _) => root.0,
            (_, _, Some(anc)) => anc.0,
            _ => return None,
        };
        let buf = self.buf.as_mut()?;
        let mut news = WatchNews::default();
        loop {
            // SAFETY: `buf` is writable for its length; `fd` is non-blocking.
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len()) };
            if n > 0 {
                let got = classify_records(&buf[..n as usize]);
                news.changed |= got.changed;
                news.gone |= got.gone;
                if news.gone {
                    break;
                }
                continue;
            }
            if n < 0 {
                match get_errno() {
                    libc::EAGAIN => {}
                    libc::EINTR => continue,
                    _ => {
                        news.changed = true;
                        news.gone = true;
                    }
                }
            }
            break;
        }
        Some(news)
    }

    /// Bring the cache up to date before a decision.
    fn refresh(&mut self) {
        match self.drain() {
            Some(news) => {
                // An ancestor watch only says "look again"; a root watch says the
                // cache is stale, and that `Events` itself is gone if `gone`.
                if news.gone || (news.changed && self.ancestor.is_some()) {
                    self.establish(monotonic_ns());
                } else if news.changed {
                    self.cache.clear();
                }
            }
            None => {
                let now = monotonic_ns();
                if now >= self.retry_at {
                    self.establish(now);
                }
            }
        }
    }

    fn setting(&mut self, event_type: &[u8], segs: &[&[u8]]) -> Option<bool> {
        let root = self.root.as_ref()?.0;
        let found = self
            .cache
            .binary_search_by(|(k, _)| (**k).cmp(event_type));
        if let Ok(i) = found {
            return self.cache[i].1;
        }
        let setting = resolve(&mut LiveTree { root }, segs);
        self.remember(event_type, setting);
        setting
    }

    fn remember(&mut self, event_type: &[u8], setting: Option<bool>) {
        if self.cache.len() >= CACHE_MAX {
            self.cache.clear();
        }
        let mut key: Vec<u8> = Vec::new();
        if key.try_reserve_exact(event_type.len()).is_err() || self.cache.try_reserve(1).is_err() {
            return; // out of memory: decide uncached
        }
        key.extend_from_slice(event_type);
        let at = self
            .cache
            .binary_search_by(|(k, _)| (**k).cmp(event_type))
            .unwrap_or_else(|i| i);
        self.cache.insert(at, (key.into_boxed_slice(), setting));
    }

    fn enabled(&mut self, event_type: &[u8], tier: u32) -> Result<bool, c_int> {
        let segs = segments(event_type).ok_or(libc::EINVAL)?;
        if tier == PEIOS_EVENT_TIER_ESSENTIAL {
            return Ok(true);
        }
        if decide(tier, None).is_none() {
            return Err(libc::EINVAL);
        }
        self.refresh();
        let setting = self.setting(event_type, &segs);
        decide(tier, setting).ok_or(libc::EINVAL)
    }
}

/// `peios_event_policy_open` — open a view of the emission policy. Never fails
/// for want of a registry: with none, every decision is by tier until one
/// appears. Returns NULL with errno only on `ENOMEM`.
#[no_mangle]
pub extern "C" fn peios_event_policy_open() -> *mut peios_event_policy {
    let mut p = peios_event_policy::new();
    p.establish(monotonic_ns());
    // SAFETY: ownership passes to the caller, released by peios_event_policy_close.
    let raw = unsafe { raw_new(p) };
    if raw.is_null() {
        set_errno(libc::ENOMEM);
    }
    raw
}

/// `peios_event_policy_close` — close the watch fds and free the handle
/// (NULL-safe).
///
/// # Safety
/// `policy` must be NULL or a handle from `peios_event_policy_open`, not yet
/// closed.
#[no_mangle]
pub unsafe extern "C" fn peios_event_policy_close(policy: *mut peios_event_policy) {
    raw_free(policy);
}

/// `peios_event_policy_enabled` — is `event_type` at `tier` switched on?
/// Returns 1 (on: build and emit), 0 (off: build nothing), or `-1` with errno
/// `EINVAL` for a NULL handle or type, a malformed type (empty, not UTF-8, an
/// empty segment, or a `\` or NUL in a segment), or an unknown tier. Never
/// fails on account of the registry.
///
/// # Safety
/// `policy` must be an open handle used by one thread at a time; `event_type`
/// valid for `event_type_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn peios_event_policy_enabled(
    policy: *mut peios_event_policy,
    event_type: *const c_char,
    event_type_len: u16,
    tier: u32,
) -> c_int {
    let Some(policy) = policy.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if event_type.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let ty = slice::from_raw_parts(event_type as *const u8, event_type_len as usize);
    match policy.enabled(ty, tier) {
        Ok(on) => on as c_int,
        Err(errno) => {
            set_errno(errno);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::string::String;
    use std::vec;

    /// An in-memory tree: key path ("" for `Events`, "kacs\audit" beneath it) to
    /// its raw `Enabled` value, if it has one.
    #[derive(Default)]
    struct FakeTree {
        root_exists: bool,
        keys: BTreeMap<String, Option<(u32, Vec<u8>)>>,
        reads: usize,
    }

    impl FakeTree {
        fn new() -> Self {
            let mut t = FakeTree {
                root_exists: true,
                ..Default::default()
            };
            t.keys.insert(String::new(), None);
            t
        }
        /// Create a key (and its ancestors), optionally with a DWORD.
        fn key(mut self, path: &str, dword: Option<u32>) -> Self {
            let mut acc = String::new();
            for seg in path.split('\\') {
                if !acc.is_empty() {
                    acc.push('\\');
                }
                acc.push_str(seg);
                self.keys.entry(acc.clone()).or_insert(None);
            }
            self.keys.insert(
                path.into(),
                dword.map(|d| (REG_DWORD, d.to_le_bytes().to_vec())),
            );
            self
        }
        fn raw(mut self, path: &str, ty: u32, data: &[u8]) -> Self {
            self = self.key(path, None);
            self.keys.insert(path.into(), Some((ty, data.to_vec())));
            self
        }
        fn root_value(mut self, dword: u32) -> Self {
            self.keys
                .insert(String::new(), Some((REG_DWORD, dword.to_le_bytes().to_vec())));
            self
        }
    }

    impl PolicyTree for FakeTree {
        type Key = String;
        fn root(&mut self) -> Option<String> {
            self.root_exists.then(String::new)
        }
        fn child(&mut self, parent: &String, segment: &[u8]) -> Option<String> {
            let seg = core::str::from_utf8(segment).unwrap();
            let p = if parent.is_empty() {
                seg.into()
            } else {
                std::format!("{parent}\\{seg}")
            };
            self.keys.contains_key(&p).then_some(p)
        }
        fn enabled(&mut self, key: &String) -> Option<bool> {
            self.reads += 1;
            let (ty, data) = self.keys.get(key)?.as_ref()?;
            interpret_enabled(*ty, data)
        }
    }

    const E: u32 = PEIOS_EVENT_TIER_ESSENTIAL;
    const S: u32 = PEIOS_EVENT_TIER_STANDARD;
    const V: u32 = PEIOS_EVENT_TIER_VERBOSE;
    const D: u32 = PEIOS_EVENT_TIER_DEBUG;

    fn on(tree: &mut FakeTree, ty: &str, tier: u32) -> bool {
        if tier == E {
            return true; // essential never walks (asserted separately)
        }
        let segs = segments(ty.as_bytes()).unwrap();
        decide(tier, resolve(tree, &segs)).unwrap()
    }

    #[test]
    fn empty_tree_uses_tier_defaults() {
        let mut t = FakeTree::new();
        assert!(on(&mut t, "kacs.token.created", S));
        assert!(!on(&mut t, "kacs.token.created", V));
        assert!(!on(&mut t, "kacs.token.created", D));
        assert!(on(&mut t, "kacs.token.created", E));
    }

    #[test]
    fn absent_root_uses_tier_defaults() {
        let mut t = FakeTree::new().root_value(0);
        t.root_exists = false;
        assert!(on(&mut t, "a.b.c", S));
        assert!(!on(&mut t, "a.b.c", V));
    }

    #[test]
    fn root_setting_covers_everything() {
        let mut t = FakeTree::new().root_value(1);
        assert!(on(&mut t, "a.b.c", D));
        assert!(on(&mut t, "a.b.c", V));
        let mut t = FakeTree::new().root_value(0);
        assert!(!on(&mut t, "a.b.c", S));
    }

    /// The PGSS §6.9 example table.
    #[test]
    fn spec_example_table() {
        let mut t = FakeTree::new().key("kacs", Some(0)).key("kacs\\audit", Some(1));
        assert!(on(&mut t, "lcs.config.value.rejected", S));
        assert!(!on(&mut t, "kacs.caap.staging.diverged", S));
        assert!(on(&mut t, "kacs.audit.handle.used", S));
        assert!(on(&mut t, "kacs.audit.access.checked", E));
        // A verbose type in the first place is off; in the third, on.
        assert!(!on(&mut t, "lcs.config.value.rejected", V));
        assert!(on(&mut t, "kacs.audit.handle.used", V));

        let mut t = t.root_value(0);
        assert!(!on(&mut t, "lcs.config.value.rejected", S));
        assert!(!on(&mut t, "kacs.caap.staging.diverged", S));
        assert!(on(&mut t, "kacs.audit.handle.used", S));
    }

    #[test]
    fn deepest_setting_wins_both_ways() {
        let mut t = FakeTree::new()
            .root_value(0)
            .key("a", Some(1))
            .key("a\\b", Some(0))
            .key("a\\b\\c", Some(1));
        assert!(on(&mut t, "a.b.c", S));
        assert!(!on(&mut t, "a.b.d", S));
        assert!(on(&mut t, "a.x.y", S));
        assert!(!on(&mut t, "z.y.x", V));
    }

    #[test]
    fn the_types_own_key_counts() {
        let mut t = FakeTree::new().key("a\\b\\c", Some(1));
        assert!(on(&mut t, "a.b.c", D));
        assert!(!on(&mut t, "a.b.cc", D));
        let mut t = FakeTree::new().key("a\\b\\c", Some(0));
        assert!(!on(&mut t, "a.b.c", S));
    }

    #[test]
    fn missing_intermediate_key_keeps_what_was_found() {
        let mut t = FakeTree::new().key("a", Some(1));
        // a\b does not exist: a's setting stands.
        assert!(on(&mut t, "a.b.c", V));
        let mut t = FakeTree::new().key("a", None);
        assert!(!on(&mut t, "a.b.c", V));
    }

    #[test]
    fn a_key_without_a_value_does_not_reset() {
        let mut t = FakeTree::new().key("a", Some(0)).key("a\\b", None);
        assert!(!on(&mut t, "a.b.c", S));
    }

    #[test]
    fn package_root_splits_per_segment() {
        let mut t = FakeTree::new()
            .key("org\\jellyfin", Some(0))
            .key("org\\jellyfin\\server\\playback", Some(1));
        assert!(!on(&mut t, "org.jellyfin.server.library.scanned", S));
        assert!(on(&mut t, "org.jellyfin.server.playback.started", V));
        assert!(on(&mut t, "org.other.app.thing.done", S));
    }

    #[test]
    fn malformed_values_are_ignored_and_keep_the_earlier_setting() {
        for (ty, data) in [
            (REG_DWORD, 2u32.to_le_bytes().to_vec()),
            (REG_DWORD, u32::MAX.to_le_bytes().to_vec()),
            (peios_uapi::REG_SZ, b"1\0".to_vec()),
            (peios_uapi::REG_QWORD, 1u64.to_le_bytes().to_vec()),
            (peios_uapi::REG_DWORD_BIG_ENDIAN, 1u32.to_be_bytes().to_vec()),
            (REG_DWORD, vec![1, 0]),
            (peios_uapi::REG_BINARY, vec![1, 0, 0, 0]),
        ] {
            let mut t = FakeTree::new().key("a", Some(0)).raw("a\\b", ty, &data);
            assert!(!on(&mut t, "a.b.c", S), "type {ty} data {data:?}");
            let mut t = FakeTree::new().key("a", Some(1)).raw("a\\b", ty, &data);
            assert!(on(&mut t, "a.b.c", V), "type {ty} data {data:?}");
            let mut t = FakeTree::new().raw("a", ty, &data);
            assert!(on(&mut t, "a.b.c", S));
            assert!(!on(&mut t, "a.b.c", D));
        }
    }

    #[test]
    fn walk_stops_at_the_type_and_reads_each_key_once() {
        let mut t = FakeTree::new()
            .key("a\\b\\c", Some(1))
            .key("a\\b\\c\\d", Some(0));
        assert!(on(&mut t, "a.b.c", V)); // a\b\c\d is below the type: not read
        assert_eq!(t.reads, 4); // Events, a, a\b, a\b\c
    }

    #[test]
    fn essential_does_not_walk() {
        let mut p = peios_event_policy::new();
        // No registry calls happen for essential: no root, no refresh.
        assert_eq!(p.enabled(b"kacs.audit.access.checked", E), Ok(true));
    }

    #[test]
    fn interpret_enabled_accepts_only_dword_zero_or_one() {
        assert_eq!(interpret_enabled(REG_DWORD, &1u32.to_le_bytes()), Some(true));
        assert_eq!(interpret_enabled(REG_DWORD, &0u32.to_le_bytes()), Some(false));
        assert_eq!(interpret_enabled(REG_DWORD, &2u32.to_le_bytes()), None);
        assert_eq!(interpret_enabled(REG_DWORD, &[1, 0, 0]), None);
        assert_eq!(interpret_enabled(peios_uapi::REG_DWORD_BIG_ENDIAN, &[0, 0, 0, 1]), None);
    }

    #[test]
    fn segments_validates_the_type() {
        assert_eq!(segments(b"a.b.c").unwrap(), vec![&b"a"[..], b"b", b"c"]);
        assert_eq!(segments(b"single").unwrap().len(), 1);
        assert!(segments(b"").is_none());
        assert!(segments(b"a..b").is_none());
        assert!(segments(b".a").is_none());
        assert!(segments(b"a.").is_none());
        assert!(segments(b"a.b\\c.d").is_none());
        assert!(segments(b"a.b\0.d").is_none());
        assert!(segments(b"a.\xff.d").is_none());
        // A package-name segment the grammar does not admit is still a key name.
        assert!(segments(b"org.c++.app.thing.done").is_some());
    }

    #[test]
    fn decide_rejects_unknown_tiers() {
        assert_eq!(decide(4, None), None);
        assert_eq!(decide(u32::MAX, Some(true)), None);
    }

    #[test]
    fn enabled_rejects_bad_arguments() {
        let mut p = peios_event_policy::new();
        assert_eq!(p.enabled(b"", S), Err(libc::EINVAL));
        assert_eq!(p.enabled(b"a..b", E), Err(libc::EINVAL));
        assert_eq!(p.enabled(b"a.b.c", 9), Err(libc::EINVAL));
        let r = unsafe {
            peios_event_policy_enabled(core::ptr::null_mut(), b"a".as_ptr() as *const c_char, 1, S)
        };
        assert_eq!(r, -1);
        assert_eq!(get_errno(), libc::EINVAL);
        let r = unsafe { peios_event_policy_enabled(&mut p, core::ptr::null(), 0, S) };
        assert_eq!(r, -1);
    }

    #[test]
    fn unreadable_registry_falls_back_to_tier() {
        // Off a Peios kernel every registry call fails: the handle has nothing
        // to read or watch, and decides by tier.
        let p = peios_event_policy_open();
        assert!(!p.is_null());
        let check = |ty: &[u8], tier| unsafe {
            peios_event_policy_enabled(p, ty.as_ptr() as *const c_char, ty.len() as u16, tier)
        };
        assert_eq!(check(b"a.b.c", S), 1);
        assert_eq!(check(b"a.b.c", V), 0);
        assert_eq!(check(b"a.b.c", D), 0);
        assert_eq!(check(b"a.b.c", E), 1);
        unsafe { peios_event_policy_close(p) };
        unsafe { peios_event_policy_close(core::ptr::null_mut()) };
    }

    fn record(ty: u32, name: &[u8], path: Option<&[&[u8]]>) -> Vec<u8> {
        let mut r = vec![0u8; 8];
        r[4..6].copy_from_slice(&(ty as u16).to_le_bytes());
        r[6..8].copy_from_slice(&(name.len() as u16).to_le_bytes());
        r.extend_from_slice(name);
        if let Some(path) = path {
            r.extend_from_slice(&(path.len() as u16).to_le_bytes());
            for c in path {
                r.extend_from_slice(&(c.len() as u16).to_le_bytes());
                r.extend_from_slice(c);
            }
        }
        let total = r.len() as u32;
        r[0..4].copy_from_slice(&total.to_le_bytes());
        r
    }

    #[test]
    fn classify_value_and_subkey_records_as_changes() {
        let mut buf = record(peios_uapi::REG_WATCH_VALUE_SET, b"Enabled", Some(&[b"kacs"]));
        buf.extend(record(peios_uapi::REG_WATCH_SUBKEY_CREATED, b"audit", Some(&[])));
        assert_eq!(
            classify_records(&buf),
            WatchNews {
                changed: true,
                gone: false
            }
        );
        assert_eq!(classify_records(&[]), WatchNews::default());
    }

    #[test]
    fn classify_overflow_is_a_change_not_a_loss() {
        let buf = record(peios_uapi::REG_WATCH_OVERFLOW, b"", None);
        assert_eq!(
            classify_records(&buf),
            WatchNews {
                changed: true,
                gone: false
            }
        );
    }

    #[test]
    fn classify_key_deleted_only_at_depth_zero_is_gone() {
        let bare = record(REG_WATCH_KEY_DELETED, b"", None);
        assert!(classify_records(&bare).gone);
        let own = record(REG_WATCH_KEY_DELETED, b"", Some(&[]));
        assert!(classify_records(&own).gone);
        let below = record(REG_WATCH_KEY_DELETED, b"", Some(&[b"kacs"]));
        let news = classify_records(&below);
        assert!(news.changed && !news.gone);
    }

    #[test]
    fn classify_malformed_buffer_is_gone() {
        assert!(classify_records(&[1, 2, 3]).gone);
        let mut r = record(peios_uapi::REG_WATCH_VALUE_SET, b"x", None);
        r[0..4].copy_from_slice(&1000u32.to_le_bytes());
        assert!(classify_records(&r).gone);
        r[0..4].copy_from_slice(&4u32.to_le_bytes());
        assert!(classify_records(&r).gone);
    }

    #[test]
    fn cache_remembers_and_clears_when_full() {
        let mut p = peios_event_policy::new();
        p.remember(b"b.b.b", Some(true));
        p.remember(b"a.a.a", Some(false));
        p.remember(b"c.c.c", None);
        let keys: Vec<&[u8]> = p.cache.iter().map(|(k, _)| &**k).collect();
        assert_eq!(keys, vec![&b"a.a.a"[..], b"b.b.b", b"c.c.c"]);
        for i in 0..CACHE_MAX {
            p.remember(std::format!("t.{i}.x").as_bytes(), None);
        }
        assert!(p.cache.len() <= CACHE_MAX);
    }
}
