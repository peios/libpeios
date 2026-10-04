//! Reading the kernel's small text files whole: `/proc/<pid>/psb` and
//! securityfs's `kacs/sessions`. Each is generated afresh by the kernel on
//! open and read, and is a few kilobytes at most, so it is read in one pass
//! into a buffer and parsed from there.

use alloc::vec::Vec;
use core::ffi::{c_char, c_int};

use peios_cabi::abi::try_extend;

/// Read the file at `path` (a NUL-terminated path) to its end. `Err` carries
/// the errno: whatever `open(2)` or `read(2)` said, or `ENOMEM`.
///
/// # Safety
/// `path` must point to a NUL-terminated string.
pub(crate) unsafe fn read_whole(path: *const c_char) -> Result<Vec<u8>, c_int> {
    let fd = libc::open(path, libc::O_RDONLY | libc::O_CLOEXEC);
    if fd < 0 {
        return Err(crate::error::get_errno());
    }
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    let result = loop {
        let n = libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len());
        if n < 0 {
            let errno = crate::error::get_errno();
            if errno == libc::EINTR {
                continue;
            }
            break Err(errno);
        }
        if n == 0 {
            break Ok(());
        }
        if try_extend(&mut out, &chunk[..n as usize]).is_err() {
            break Err(libc::ENOMEM);
        }
    };
    libc::close(fd);
    result.map(|()| out)
}

/// The value of `key=` in a line of space-separated `key=value` pairs.
/// Unknown keys are skipped, so the kernel may add fields.
pub(crate) fn field<'a>(line: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    line.split(|&b| b == b' ').find_map(|pair| {
        let eq = pair.iter().position(|&b| b == b'=')?;
        (&pair[..eq] == key).then(|| &pair[eq + 1..])
    })
}

/// A decimal number with no sign, as the kernel writes it.
pub(crate) fn decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u64, |n, &b| {
        let d = (b as char).to_digit(10)?;
        n.checked_mul(10)?.checked_add(u64::from(d))
    })
}

/// Lowercase or uppercase hexadecimal digits, two to a byte, appended to `out`.
/// `None` for an odd length or a non-hex digit; `Err` for out of memory.
pub(crate) fn hex_into(digits: &[u8], out: &mut Vec<u8>) -> Option<Result<(), ()>> {
    if digits.len() % 2 != 0 {
        return None;
    }
    if out.try_reserve(digits.len() / 2).is_err() {
        return Some(Err(()));
    }
    for pair in digits.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_finds_a_key_among_others_and_ignores_unknown_ones() {
        let line = b"a=1 future=x b=22";
        assert_eq!(field(line, b"b"), Some(&b"22"[..]));
        assert_eq!(field(line, b"a"), Some(&b"1"[..]));
        assert_eq!(field(line, b"c"), None);
        // A key is matched whole, not as a prefix.
        assert_eq!(field(b"ab=1", b"a"), None);
    }

    #[test]
    fn decimal_rejects_empty_signed_and_overflowing_input() {
        assert_eq!(decimal(b"999"), Some(999));
        assert_eq!(decimal(b""), None);
        assert_eq!(decimal(b"-1"), None);
        assert_eq!(decimal(b"18446744073709551615"), Some(u64::MAX));
        assert_eq!(decimal(b"18446744073709551616"), None);
    }

    #[test]
    fn hex_decodes_pairs_and_rejects_odd_or_bad_digits() {
        let mut out = Vec::new();
        assert_eq!(hex_into(b"0105aF", &mut out), Some(Ok(())));
        assert_eq!(out, [0x01, 0x05, 0xaf]);
        assert_eq!(hex_into(b"abc", &mut Vec::new()), None);
        assert_eq!(hex_into(b"zz", &mut Vec::new()), None);
    }
}
