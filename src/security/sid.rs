//! SID helpers — `peios_sid_*` (`<peios/security.h>`).
//!
//! A binary SID is the MS-DTYP `SID` structure: a 1-byte revision (always 1), a
//! 1-byte sub-authority count, a 6-byte identifier authority (big-endian), then
//! `count` little-endian 32-bit sub-authorities. The encoders here assemble that
//! layout into a caller buffer; the inspectors lean on `kacs-core`'s validating
//! `Sid` parser so libpeios and the kernel agree byte-for-byte on what a valid
//! SID is.

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::fmt::Write as _;
use core::slice;

use kacs_core::Sid;

use crate::abi::{cstr_bytes, emit_bytes, emit_str, StackWriter};
use crate::error::set_errno;

/// Largest encoded SID: `8 + 4 * MAX_SUB_AUTHORITIES`. Matches the header's
/// `PEIOS_SID_MAX_BYTES` and `kacs_core::Sid::MAX_SIZE`.
const SID_MAX_BYTES: usize = 8 + 4 * (peios_uapi::KACS_SID_MAX_SUB_AUTHORITIES as usize);
const _: () = assert!(SID_MAX_BYTES == 68);

/// The identifier authority is a 48-bit big-endian field.
const MAX_AUTHORITY: u64 = (1u64 << 48) - 1;

/// Upper bound on an accepted SDDL string (longest real SID string is ~184
/// bytes); anything longer or unterminated within this window is rejected.
const MAX_SDDL_LEN: usize = 256;

/// Assemble a SID into `buf` and return its encoded length. `subs.len()` must be
/// `<= MAX_SUB_AUTHORITIES` and `authority <= MAX_AUTHORITY` (callers validate).
fn encode_sid(authority: u64, subs: &[u32], buf: &mut [u8; SID_MAX_BYTES]) -> usize {
    buf[0] = 1; // revision
    buf[1] = subs.len() as u8;
    // Identifier authority: low 6 bytes of the big-endian u64.
    buf[2..8].copy_from_slice(&authority.to_be_bytes()[2..8]);
    let mut off = 8;
    for &s in subs {
        buf[off..off + 4].copy_from_slice(&s.to_le_bytes());
        off += 4;
    }
    off
}

/// Parse `S-1-<authority>-<sub>-<sub>…` into `(authority, sub-authorities)`.
fn parse_sddl(s: &[u8]) -> Option<(u64, [u32; 15], usize)> {
    let mut fields = s.split(|&c| c == b'-');

    let prefix = fields.next()?;
    if prefix.len() != 1 || (prefix[0] != b'S' && prefix[0] != b's') {
        return None;
    }
    let revision = fields.next()?;
    if revision.len() != 1 || revision[0] != b'1' {
        return None;
    }
    let authority = parse_authority(fields.next()?)?;

    let mut subs = [0u32; 15];
    let mut count = 0;
    for field in fields {
        if count >= subs.len() {
            return None; // too many sub-authorities
        }
        subs[count] = parse_u32_dec(field)?;
        count += 1;
    }
    Some((authority, subs, count))
}

/// Identifier authority: decimal, or `0x…` hex (the SDDL form for values that
/// don't fit a decimal `u32`). Bounded to 48 bits.
fn parse_authority(field: &[u8]) -> Option<u64> {
    let value = if field.len() > 2 && field[0] == b'0' && (field[1] == b'x' || field[1] == b'X') {
        parse_u64_radix(&field[2..], 16)?
    } else {
        parse_u64_radix(field, 10)?
    };
    (value <= MAX_AUTHORITY).then_some(value)
}

fn parse_u64_radix(field: &[u8], radix: u64) -> Option<u64> {
    if field.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &c in field {
        let digit = match c {
            b'0'..=b'9' => (c - b'0') as u64,
            b'a'..=b'f' if radix == 16 => (c - b'a' + 10) as u64,
            b'A'..=b'F' if radix == 16 => (c - b'A' + 10) as u64,
            _ => return None,
        };
        if digit >= radix {
            return None;
        }
        acc = acc.checked_mul(radix)?.checked_add(digit)?;
    }
    Some(acc)
}

fn parse_u32_dec(field: &[u8]) -> Option<u32> {
    let value = parse_u64_radix(field, 10)?;
    (value <= u32::MAX as u64).then_some(value as u32)
}

/// Encode `(authority, subs)` into a stack buffer and copy it out.
///
/// # Safety
/// `out` must be valid for `cap` bytes when `cap != 0`.
unsafe fn emit_sid(authority: u64, subs: &[u32], out: *mut c_void, cap: usize) -> isize {
    let mut buf = [0u8; SID_MAX_BYTES];
    let len = encode_sid(authority, subs, &mut buf);
    emit_bytes(&buf[..len], out as *mut u8, cap)
}

// ----------------------------------------------------------------------------
// Encoders
// ----------------------------------------------------------------------------

/// `peios_sid_build` — encode a binary SID from its parts.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_build(
    out: *mut c_void,
    cap: usize,
    id_authority: u64,
    sub_auths: *const u32,
    count: c_uint,
) -> isize {
    let count = count as usize;
    if count > peios_uapi::KACS_SID_MAX_SUB_AUTHORITIES as usize || id_authority > MAX_AUTHORITY {
        set_errno(libc::EINVAL);
        return -1;
    }
    if count > 0 && sub_auths.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let subs = if count == 0 {
        &[][..]
    } else {
        slice::from_raw_parts(sub_auths, count)
    };
    emit_sid(id_authority, subs, out, cap)
}

/// `peios_sid_parse_string` — parse a SID from its string form into binary.
///
/// Accepts both the numeric `S-1-…` literal and the two-letter SDDL aliases
/// (`BA`, `SY`, `WD`, `BU`, the integrity labels, …) — the latter resolved
/// through the SDDL SID-alias table. Domain-relative aliases that need a
/// machine/domain SID prefix are rejected with `EINVAL`.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_parse_string(
    out: *mut c_void,
    cap: usize,
    sddl: *const c_char,
) -> isize {
    let bytes = if sddl.is_null() {
        None
    } else {
        cstr_bytes(sddl, MAX_SDDL_LEN)
    };
    if let Some((authority, subs, count)) = bytes.and_then(parse_sddl) {
        return emit_sid(authority, &subs[..count], out, cap);
    }
    // Fall back to the SDDL alias table (BA/SY/WD/…); `parse_sddl` above is the
    // sole, strict path for the numeric `S-1-…` literal, so a string that looks
    // like one but didn't parse is malformed — don't let the (more lenient)
    // alias parser rescue it. Aliases are short letter codes, never `S-`.
    let alias = bytes
        .and_then(|b| core::str::from_utf8(b).ok())
        .filter(|s| !s.trim_start().starts_with("S-") && !s.trim_start().starts_with("s-"))
        .and_then(|s| crate::security::sddl::grammar::parse_sid(s).ok());
    match alias {
        Some(sid) => emit_bytes(&sid.encode(), out as *mut u8, cap),
        None => {
            set_errno(libc::EINVAL);
            -1
        }
    }
}

/// `peios_sid_format` — format a binary SID as its SDDL string.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_format(
    sid: *const c_void,
    len: usize,
    out: *mut c_char,
    cap: usize,
) -> isize {
    if sid.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let bytes = slice::from_raw_parts(sid as *const u8, len);
    let parsed = match Sid::parse(bytes) {
        Ok(sid) => sid,
        Err(_) => {
            set_errno(libc::EINVAL);
            return -1;
        }
    };
    let mut writer = StackWriter::new();
    if write!(writer, "{parsed}").is_err() {
        set_errno(libc::EINVAL);
        return -1;
    }
    emit_str(writer.as_bytes(), out, cap)
}

/// `peios_sid_integrity` — construct an integrity-label SID `S-1-16-<rid>`.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_integrity(
    out: *mut c_void,
    cap: usize,
    level_rid: u32,
) -> isize {
    emit_sid(16, &[level_rid], out, cap)
}

/// `peios_sid_logon` — construct a logon SID `S-1-5-5-<hi>-<lo>`.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_logon(out: *mut c_void, cap: usize, session_id: u64) -> isize {
    let hi = (session_id >> 32) as u32;
    let lo = session_id as u32;
    emit_sid(5, &[5, hi, lo], out, cap)
}

/// `peios_sid_well_known` — construct a well-known SID (see `enum peios_wks`).
///
/// `which` is the C `enum peios_wks` value (an `int`); out-of-range yields
/// `EINVAL`.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_well_known(out: *mut c_void, cap: usize, which: c_int) -> isize {
    let (authority, subs): (u64, &[u32]) = match which {
        0 => (0, &[0]),        // PEIOS_WKS_NULL                S-1-0-0
        1 => (1, &[0]),        // PEIOS_WKS_EVERYONE            S-1-1-0
        2 => (2, &[0]),        // PEIOS_WKS_LOCAL               S-1-2-0
        3 => (3, &[0]),        // PEIOS_WKS_CREATOR_OWNER       S-1-3-0
        4 => (3, &[1]),        // PEIOS_WKS_CREATOR_GROUP       S-1-3-1
        5 => (3, &[4]),        // PEIOS_WKS_OWNER_RIGHTS        S-1-3-4
        6 => (5, &[7]),        // PEIOS_WKS_ANONYMOUS           S-1-5-7
        7 => (5, &[10]),       // PEIOS_WKS_SELF                S-1-5-10
        8 => (5, &[11]),       // PEIOS_WKS_AUTHENTICATED_USERS S-1-5-11
        9 => (5, &[18]),       // PEIOS_WKS_SYSTEM              S-1-5-18
        10 => (5, &[19]),      // PEIOS_WKS_LOCAL_SERVICE       S-1-5-19
        11 => (5, &[20]),      // PEIOS_WKS_NETWORK_SERVICE     S-1-5-20
        12 => (5, &[32, 544]), // PEIOS_WKS_ADMINISTRATORS      S-1-5-32-544
        _ => {
            set_errno(libc::EINVAL);
            return -1;
        }
    };
    emit_sid(authority, subs, out, cap)
}

// ----------------------------------------------------------------------------
// Inspectors
// ----------------------------------------------------------------------------

/// `peios_sid_valid` — structurally valid SID of exactly `len` bytes?
#[no_mangle]
pub unsafe extern "C" fn peios_sid_valid(sid: *const c_void, len: usize) -> bool {
    if sid.is_null() {
        return false;
    }
    let bytes = slice::from_raw_parts(sid as *const u8, len);
    // Enforce that the SID consumes the whole buffer, not just a valid prefix.
    Sid::parse(bytes).is_ok_and(|s| s.as_bytes().len() == len)
}

/// `peios_sid_length` — encoded length from the sub-authority count byte.
///
/// Unlike the other inspectors this takes no length: it reads only the
/// sub-authority-count byte at offset 1 and returns `8 + 4 * count`, never
/// touching the sub-authority data.
///
/// # Safety
/// `sid` must be NULL or point to at least 2 readable bytes (the SID revision and
/// sub-authority-count bytes). The caller is responsible for having validated
/// `sid` (e.g. via [`peios_sid_valid`]) or bounded it to `PEIOS_SID_MAX_BYTES`.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_length(sid: *const c_void) -> usize {
    if sid.is_null() {
        return 0;
    }
    let count = *(sid as *const u8).add(1) as usize;
    8 + 4 * count
}

/// `peios_sid_equal` — exact binary equality.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_equal(
    a: *const c_void,
    alen: usize,
    b: *const c_void,
    blen: usize,
) -> bool {
    if alen != blen {
        return false;
    }
    if alen == 0 {
        return true;
    }
    if a.is_null() || b.is_null() {
        return false;
    }
    slice::from_raw_parts(a as *const u8, alen) == slice::from_raw_parts(b as *const u8, blen)
}

/// `peios_sid_rid` — the RID (last sub-authority) of `sid`, or 0 if it has none.
#[no_mangle]
pub unsafe extern "C" fn peios_sid_rid(sid: *const c_void, len: usize) -> u32 {
    if sid.is_null() {
        return 0;
    }
    let bytes = slice::from_raw_parts(sid as *const u8, len);
    match Sid::parse(bytes) {
        Ok(sid) => sid.relative_identifier().unwrap_or(0),
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    fn errno() -> c_int {
        unsafe { *libc::__errno_location() }
    }

    /// Two-call encode into an exactly-sized Vec via any `emit`-style entry.
    unsafe fn collect(f: impl Fn(*mut c_void, usize) -> isize) -> Result<Vec<u8>, c_int> {
        let need = f(ptr::null_mut(), 0);
        if need < 0 {
            return Err(errno());
        }
        let mut v = vec![0u8; need as usize];
        let got = f(v.as_mut_ptr() as *mut c_void, v.len());
        assert_eq!(got, need);
        Ok(v)
    }

    unsafe fn well_known(which: c_int) -> Vec<u8> {
        collect(|o, c| peios_sid_well_known(o, c, which)).unwrap()
    }

    unsafe fn build(auth: u64, subs: &[u32]) -> Vec<u8> {
        collect(|o, c| peios_sid_build(o, c, auth, subs.as_ptr(), subs.len() as c_uint)).unwrap()
    }

    unsafe fn format(sid: &[u8]) -> String {
        let need = peios_sid_format(sid.as_ptr() as *const c_void, sid.len(), ptr::null_mut(), 0);
        assert!(need >= 0, "format probe failed, errno={}", errno());
        let mut buf = vec![0u8; need as usize + 1];
        let got = peios_sid_format(
            sid.as_ptr() as *const c_void,
            sid.len(),
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        );
        assert_eq!(got, need);
        assert_eq!(buf[need as usize], 0, "missing NUL terminator");
        String::from_utf8(buf[..need as usize].to_vec()).unwrap()
    }

    unsafe fn parse_string(sddl: &str) -> Result<Vec<u8>, c_int> {
        let mut c = sddl.as_bytes().to_vec();
        c.push(0);
        collect(|o, cap| peios_sid_parse_string(o, cap, c.as_ptr() as *const c_char))
    }

    #[test]
    fn build_layout_and_roundtrip() {
        unsafe {
            let sid = build(5, &[21, 1, 2, 3]);
            assert_eq!(sid.len(), 8 + 4 * 4);
            assert_eq!(sid[0], 1); // revision
            assert_eq!(sid[1], 4); // sub-authority count
            assert_eq!(&sid[2..8], &[0, 0, 0, 0, 0, 5]); // authority big-endian
            assert_eq!(&sid[8..12], &21u32.to_le_bytes()); // first sub-authority LE
            assert_eq!(format(&sid), "S-1-5-21-1-2-3");
        }
    }

    #[test]
    fn well_known_strings() {
        let expected = [
            (0, "S-1-0-0"),
            (1, "S-1-1-0"),
            (2, "S-1-2-0"),
            (3, "S-1-3-0"),
            (4, "S-1-3-1"),
            (5, "S-1-3-4"),
            (6, "S-1-5-7"),
            (7, "S-1-5-10"),
            (8, "S-1-5-11"),
            (9, "S-1-5-18"),
            (10, "S-1-5-19"),
            (11, "S-1-5-20"),
            (12, "S-1-5-32-544"),
        ];
        unsafe {
            for (which, text) in expected {
                assert_eq!(format(&well_known(which)), text, "wks {which}");
            }
        }
    }

    #[test]
    fn integrity_and_logon() {
        unsafe {
            assert_eq!(
                format(&collect(|o, c| peios_sid_integrity(o, c, 8192)).unwrap()),
                "S-1-16-8192"
            );
            // session 0x0000_0003_0000_03E7 -> hi=3, lo=999
            let session = (3u64 << 32) | 999;
            assert_eq!(
                format(&collect(|o, c| peios_sid_logon(o, c, session)).unwrap()),
                "S-1-5-5-3-999"
            );
        }
    }

    #[test]
    fn parse_string_roundtrips_format() {
        unsafe {
            for text in [
                "S-1-0-0",
                "S-1-5-18",
                "S-1-5-32-544",
                "S-1-16-12288",
                "S-1-5-5-3-999",
            ] {
                let sid = parse_string(text).unwrap();
                assert_eq!(format(&sid), text);
            }
        }
    }

    #[test]
    fn parse_string_accepts_hex_authority() {
        unsafe {
            // "0x20" == 32 (< 2^32) -> formats back in decimal.
            assert_eq!(parse_string("S-1-0x20-5").unwrap(), build(32, &[5]));
            // A >32-bit authority round-trips through the 0x form.
            let big = parse_string("S-1-0x100000000-1").unwrap();
            assert_eq!(big, build(0x1_0000_0000, &[1]));
            assert_eq!(format(&big), "S-1-0x000100000000-1");
        }
    }

    #[test]
    fn parse_string_accepts_sddl_aliases() {
        unsafe {
            // BA = BUILTIN\Administrators = S-1-5-32-544
            assert_eq!(parse_string("BA").unwrap(), build(5, &[32, 544]));
            // SY = LocalSystem = S-1-5-18
            assert_eq!(parse_string("SY").unwrap(), build(5, &[18]));
            // WD = Everyone = S-1-1-0
            assert_eq!(parse_string("WD").unwrap(), build(1, &[0]));
        }
    }

    #[test]
    fn parse_string_rejects_malformed() {
        unsafe {
            for bad in [
                "garbage",
                "S-2-5",                                        // wrong revision
                "S-1-",                                         // empty authority
                "S-1-5-",                                       // trailing empty sub-authority
                "S-1-5-99999999999",                            // sub-authority overflows u32
                "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16", // too many subs
            ] {
                assert_eq!(
                    parse_string(bad),
                    Err(libc::EINVAL),
                    "expected EINVAL for {bad:?}"
                );
            }
        }
    }

    #[test]
    fn inspectors() {
        unsafe {
            let sid = build(5, &[32, 544]);
            assert!(peios_sid_valid(sid.as_ptr() as *const c_void, sid.len()));
            // A buffer with trailing slop is not "valid of exactly len bytes".
            let mut padded = sid.clone();
            padded.push(0);
            assert!(!peios_sid_valid(
                padded.as_ptr() as *const c_void,
                padded.len()
            ));
            // Truncated.
            assert!(!peios_sid_valid(
                sid.as_ptr() as *const c_void,
                sid.len() - 1
            ));

            assert_eq!(peios_sid_length(sid.as_ptr() as *const c_void), sid.len());
            assert_eq!(peios_sid_rid(sid.as_ptr() as *const c_void, sid.len()), 544);

            let same = build(5, &[32, 544]);
            let other = build(5, &[32, 545]);
            let p = |v: &[u8]| (v.as_ptr() as *const c_void, v.len());
            assert!(peios_sid_equal(
                p(&sid).0,
                p(&sid).1,
                p(&same).0,
                p(&same).1
            ));
            assert!(!peios_sid_equal(
                p(&sid).0,
                p(&sid).1,
                p(&other).0,
                p(&other).1
            ));
        }
    }

    #[test]
    fn probe_erange_and_bad_args() {
        unsafe {
            // Probe returns the needed size.
            let need = peios_sid_well_known(ptr::null_mut(), 0, 9);
            assert_eq!(need, 12);
            // Present-but-too-small buffer -> ERANGE, nothing written.
            let mut small = [0u8; 4];
            assert_eq!(
                peios_sid_well_known(small.as_mut_ptr() as *mut c_void, small.len(), 9),
                -1
            );
            assert_eq!(errno(), libc::ERANGE);
            // Non-zero cap with NULL buffer -> EINVAL.
            assert_eq!(peios_sid_well_known(ptr::null_mut(), 8, 9), -1);
            assert_eq!(errno(), libc::EINVAL);
            // Bad sub-authority count -> EINVAL.
            assert_eq!(peios_sid_build(ptr::null_mut(), 0, 5, ptr::null(), 16), -1);
            assert_eq!(errno(), libc::EINVAL);
            // Unknown well-known selector -> EINVAL.
            assert_eq!(peios_sid_well_known(ptr::null_mut(), 0, 99), -1);
            assert_eq!(errno(), libc::EINVAL);
        }
    }
}
