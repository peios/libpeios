//! Per-message identity and descriptors on a Unix socket — the
//! `peios_socket_send_message` / `peios_socket_recv_message` pair of
//! `<peios/token.h>`, and `peios_socket_peer_pidfd`.
//!
//! A message on a Unix socket can carry, as ancillary data, a token the kernel
//! attests the sender could act as (`KACS_SCM_TOKEN`, level `SOL_KACS`) and a
//! set of file descriptors (`SCM_RIGHTS`, level `SOL_SOCKET`). Building and
//! walking the control buffer by hand is the same twenty lines in every
//! program that does it, and getting `CMSG_ALIGN` wrong is silent; these two
//! calls do it once. They cross the kernel boundary, so they are exercised
//! live under Provium; the control-buffer layout is unit-tested here.

use core::ffi::{c_int, c_long, c_uint, c_void};
use core::mem::{size_of, MaybeUninit};

use alloc::vec::Vec;

use crate::error::set_errno;
use crate::sys::{ret_int, syscall3, syscall5};

// `<pkm/socket.h>` — mirrored here as in `ops.rs` until the `peios-uapi` pin
// carries the header.
const SOL_KACS: c_int = 4096;
const KACS_SCM_TOKEN: c_int = 1;

/// The largest descriptor count one `SCM_RIGHTS` message may carry
/// (`SCM_MAX_FD` in the kernel). A larger `fd_cap` is capped here so the
/// control buffer cannot be asked to describe more than the kernel delivers.
const SCM_MAX_FD: c_uint = 253;

/// Enough stack storage for one KACS token and the kernel's maximum
/// `SCM_RIGHTS` payload. Receive callers choose a prefix of this array from
/// their advertised descriptor capacity, so the common token-only path uses
/// 24 bytes without touching the allocator.
const RECEIVE_CONTROL_MAX: usize =
    cmsg_space(size_of::<c_int>()) + cmsg_space(SCM_MAX_FD as usize * size_of::<c_int>());

/// `PEIOS_SOCKET_MSG_TRUNCATED` — the data did not fit in the caller's buffer
/// (`MSG_TRUNC`). On a `SOCK_SEQPACKET` socket the tail is gone.
pub const PEIOS_SOCKET_MSG_TRUNCATED: c_uint = 0x1;
/// `PEIOS_SOCKET_MSG_CTRUNCATED` — ancillary data did not fit (`MSG_CTRUNC`):
/// more descriptors than `fd_cap`, or a token with no room. The kernel has
/// already closed whatever it could not deliver.
pub const PEIOS_SOCKET_MSG_CTRUNCATED: c_uint = 0x2;

/// `struct peios_socket_message` — what a received message carried alongside
/// its bytes. `fds`/`fd_cap` are inputs; `token_fd`, `fd_count` and `flags`
/// are outputs.
#[repr(C)]
pub struct peios_socket_message {
    /// The attached token fd (`TOKEN_QUERY | TOKEN_IMPERSONATE |
    /// TOKEN_DUPLICATE`, `O_CLOEXEC`), or `-1` if the message conveyed no
    /// identity distinct from the register's.
    pub token_fd: c_int,
    /// Caller-owned array receiving `SCM_RIGHTS` descriptors, each `O_CLOEXEC`.
    /// May be null when `fd_cap` is 0.
    pub fds: *mut c_int,
    /// Capacity of `fds`.
    pub fd_cap: c_uint,
    /// How many of `fds` were filled.
    pub fd_count: c_uint,
    /// `PEIOS_SOCKET_MSG_*`.
    pub flags: c_uint,
}

/// `CMSG_ALIGN` for Linux: round up to the `size_t` boundary.
const fn cmsg_align(len: usize) -> usize {
    (len + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}

/// `CMSG_SPACE(len)`: the bytes one control message of `len` data occupies.
const fn cmsg_space(len: usize) -> usize {
    cmsg_align(size_of::<libc::cmsghdr>()) + cmsg_align(len)
}

/// `CMSG_LEN(len)`: the `cmsg_len` field for `len` bytes of data.
const fn cmsg_len(len: usize) -> usize {
    cmsg_align(size_of::<libc::cmsghdr>()) + len
}

/// Append one control message to `buf`, which must have been sized with
/// [`cmsg_space`] for everything it will hold.
fn push_cmsg(buf: &mut Vec<u8>, level: c_int, kind: c_int, data: &[u8]) {
    let start = buf.len();
    buf.resize(start + cmsg_space(data.len()), 0);
    let header = libc::cmsghdr {
        cmsg_len: cmsg_len(data.len()),
        cmsg_level: level,
        cmsg_type: kind,
    };
    // SAFETY: `buf` has room for the header at `start`; a byte copy of a
    // `repr(C)` header with no padding-sensitive fields.
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(header) as *const u8,
            buf.as_mut_ptr().add(start),
            size_of::<libc::cmsghdr>(),
        );
    }
    let data_at = start + cmsg_align(size_of::<libc::cmsghdr>());
    buf[data_at..data_at + data.len()].copy_from_slice(data);
}

/// Build the control buffer for a send: a `KACS_SCM_TOKEN` when `token_fd`
/// is non-negative, then an `SCM_RIGHTS` for `fds` when non-empty. Pure.
fn build_send_control(token_fd: c_int, fds: &[c_int]) -> Vec<u8> {
    let mut control = Vec::new();
    if token_fd >= 0 {
        push_cmsg(
            &mut control,
            SOL_KACS,
            KACS_SCM_TOKEN,
            &token_fd.to_ne_bytes(),
        );
    }
    if !fds.is_empty() {
        let mut data = Vec::with_capacity(fds.len() * size_of::<c_int>());
        for fd in fds {
            data.extend_from_slice(&fd.to_ne_bytes());
        }
        push_cmsg(&mut control, libc::SOL_SOCKET, libc::SCM_RIGHTS, &data);
    }
    control
}

/// One parsed control message.
struct ParsedCmsg<'a> {
    level: c_int,
    kind: c_int,
    data: &'a [u8],
}

/// Walk a received control buffer of `len` valid bytes, yielding each
/// well-formed message and stopping at the first malformed one. Pure.
fn parse_control(buf: &[u8]) -> impl Iterator<Item = ParsedCmsg<'_>> {
    let header_len = size_of::<libc::cmsghdr>();
    let mut offset = 0usize;
    core::iter::from_fn(move || {
        if buf.len() < offset + header_len {
            return None;
        }
        // SAFETY: `offset + header_len <= buf.len()`; an unaligned read of a
        // plain-old-data header.
        let header: libc::cmsghdr =
            unsafe { core::ptr::read_unaligned(buf.as_ptr().add(offset) as *const libc::cmsghdr) };
        let cmsg_len = header.cmsg_len;
        if cmsg_len < header_len || offset + cmsg_len > buf.len() {
            return None;
        }
        let data_at = offset + cmsg_align(header_len);
        let data_end = offset + cmsg_len;
        let data = if data_at <= data_end {
            &buf[data_at..data_end]
        } else {
            &[][..]
        };
        offset += cmsg_align(cmsg_len);
        Some(ParsedCmsg {
            level: header.cmsg_level,
            kind: header.cmsg_type,
            data,
        })
    })
}

/// What [`parse_control`] found on one message, applied to the caller's
/// output struct. Every descriptor the kernel delivered is either handed to
/// the caller or closed here — nothing leaks on any path.
unsafe fn deliver_control(buf: &[u8], msg: &mut peios_socket_message) {
    msg.token_fd = -1;
    msg.fd_count = 0;
    for cmsg in parse_control(buf) {
        let ints = cmsg.data.chunks_exact(size_of::<c_int>());
        match (cmsg.level, cmsg.kind) {
            (SOL_KACS, KACS_SCM_TOKEN) => {
                for bytes in ints {
                    let fd = c_int::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    if msg.token_fd < 0 {
                        msg.token_fd = fd;
                    } else {
                        // At most one per message by the kernel's contract; a
                        // second is not ours to keep.
                        libc::close(fd);
                    }
                }
            }
            (libc::SOL_SOCKET, libc::SCM_RIGHTS) => {
                for bytes in ints {
                    let fd = c_int::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    if msg.fd_count < msg.fd_cap && !msg.fds.is_null() {
                        *msg.fds.add(msg.fd_count as usize) = fd;
                        msg.fd_count += 1;
                    } else {
                        libc::close(fd);
                    }
                }
            }
            _ => {}
        }
    }
}

/// `peios_socket_send_message` — send `len` bytes from `buf` on `sock_fd`,
/// attaching `token_fd` as a `KACS_SCM_TOKEN` when it is non-negative and
/// `fds[0..fd_count]` as `SCM_RIGHTS` when `fd_count` is non-zero. `flags`
/// are `sendmsg(2)` flags. Returns the byte count sent, or -1 with errno.
///
/// The kernel gates the token attach as if the sender were impersonating it:
/// `EACCES` if the fd lacks `TOKEN_IMPERSONATE`, `EPERM` if attaching would
/// lower the token's level. The descriptors are duplicated into the receiver
/// on delivery; the caller keeps its own.
#[no_mangle]
pub unsafe extern "C" fn peios_socket_send_message(
    sock_fd: c_int,
    buf: *const c_void,
    len: usize,
    token_fd: c_int,
    fds: *const c_int,
    fd_count: c_uint,
    flags: c_int,
) -> isize {
    if (buf.is_null() && len != 0) || (fds.is_null() && fd_count != 0) {
        set_errno(libc::EINVAL);
        return -1;
    }
    if fd_count > SCM_MAX_FD {
        set_errno(libc::EINVAL);
        return -1;
    }
    let fds: &[c_int] = if fd_count == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(fds, fd_count as usize)
    };
    let control = build_send_control(token_fd, fds);
    let mut iov = libc::iovec {
        iov_base: buf as *mut c_void,
        iov_len: len,
    };
    let mut hdr: libc::msghdr = core::mem::zeroed();
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    if !control.is_empty() {
        hdr.msg_control = control.as_ptr() as *mut c_void;
        hdr.msg_controllen = control.len();
    }
    let r = syscall3(
        libc::SYS_sendmsg as u32,
        sock_fd as c_long,
        core::ptr::addr_of!(hdr) as usize as c_long,
        flags as c_long,
    );
    if r < 0 {
        return -1;
    }
    r as isize
}

/// `peios_socket_recv_message` — receive one message from `sock_fd` into
/// `buf`/`cap`, with room for one attached token and `msg->fd_cap`
/// descriptors. `MSG_CMSG_CLOEXEC` is always added to `flags`. Returns the
/// byte count received (0 at end of stream), or -1 with errno; on -1 nothing
/// was consumed and `*msg` is untouched.
///
/// On success every descriptor the kernel delivered is either in `*msg` or
/// already closed: a token beyond the first, or a descriptor beyond `fd_cap`,
/// is closed rather than leaked. `msg->flags` reports truncation; a caller
/// that cannot accept a truncated message closes what it was handed.
#[no_mangle]
pub unsafe extern "C" fn peios_socket_recv_message(
    sock_fd: c_int,
    buf: *mut c_void,
    cap: usize,
    msg: *mut peios_socket_message,
    flags: c_int,
) -> isize {
    let Some(msg) = msg.as_mut() else {
        set_errno(libc::EINVAL);
        return -1;
    };
    if (buf.is_null() && cap != 0) || (msg.fds.is_null() && msg.fd_cap != 0) {
        set_errno(libc::EINVAL);
        return -1;
    }
    let fd_cap = msg.fd_cap.min(SCM_MAX_FD) as usize;
    let control_len = cmsg_space(size_of::<c_int>())
        + if fd_cap > 0 {
            cmsg_space(fd_cap * size_of::<c_int>())
        } else {
            0
        };
    let mut control = [MaybeUninit::<u8>::uninit(); RECEIVE_CONTROL_MAX];
    // `recvmsg` writes the control messages but may leave alignment padding
    // untouched. Initialise only the advertised prefix so parsing that
    // padding is defined without clearing the maximum 1 KiB buffer for a
    // token-only receive.
    // SAFETY: `control_len` is bounded by the array and this writes bytes into
    // uninitialised storage without reading them.
    unsafe { core::ptr::write_bytes(control.as_mut_ptr().cast::<u8>(), 0, control_len) };
    let mut iov = libc::iovec {
        iov_base: buf,
        iov_len: cap,
    };
    let mut hdr: libc::msghdr = core::mem::zeroed();
    hdr.msg_iov = &mut iov;
    hdr.msg_iovlen = 1;
    hdr.msg_control = control.as_mut_ptr() as *mut c_void;
    hdr.msg_controllen = control_len;
    let r = syscall3(
        libc::SYS_recvmsg as u32,
        sock_fd as c_long,
        core::ptr::addr_of_mut!(hdr) as usize as c_long,
        (flags | libc::MSG_CMSG_CLOEXEC) as c_long,
    );
    if r < 0 {
        return -1;
    }
    let delivered = hdr.msg_controllen.min(control_len);
    // SAFETY: the advertised prefix was initialised above and `delivered` is
    // capped to that prefix.
    let delivered_control =
        unsafe { core::slice::from_raw_parts(control.as_ptr().cast::<u8>(), delivered) };
    deliver_control(delivered_control, msg);
    msg.flags = 0;
    if hdr.msg_flags & libc::MSG_TRUNC != 0 {
        msg.flags |= PEIOS_SOCKET_MSG_TRUNCATED;
    }
    if hdr.msg_flags & libc::MSG_CTRUNC != 0 {
        msg.flags |= PEIOS_SOCKET_MSG_CTRUNCATED;
    }
    r as isize
}

/// `peios_socket_peer_pidfd` — a pidfd for the process on the other end of a
/// connected Unix socket: `getsockopt(sock_fd, SOL_SOCKET, SO_PEERPIDFD)`.
/// Returns the new fd (`O_CLOEXEC`), or -1 with errno. The handle refers to
/// the process that connected (or that this end was paired with), which is
/// what a service opens the peer's primary token through — never a PID the
/// peer names.
#[no_mangle]
pub unsafe extern "C" fn peios_socket_peer_pidfd(sock_fd: c_int) -> c_int {
    let mut fd: c_int = -1;
    let mut len: libc::socklen_t = size_of::<c_int>() as libc::socklen_t;
    let r = syscall5(
        libc::SYS_getsockopt as u32,
        sock_fd as c_long,
        libc::SOL_SOCKET as c_long,
        libc::SO_PEERPIDFD as c_long,
        core::ptr::addr_of_mut!(fd) as usize as c_long,
        core::ptr::addr_of_mut!(len) as usize as c_long,
    );
    if r < 0 {
        return -1;
    }
    ret_int(fd as c_long)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alignment_matches_the_kernel_macros() {
        assert_eq!(cmsg_align(1), size_of::<usize>());
        assert_eq!(cmsg_align(size_of::<usize>()), size_of::<usize>());
        assert_eq!(cmsg_space(4), 16 + 8);
        assert_eq!(cmsg_len(4), 16 + 4);
    }

    #[test]
    fn send_control_carries_token_then_rights() {
        let control = build_send_control(7, &[3, 4]);
        let parsed: Vec<_> = parse_control(&control)
            .map(|c| (c.level, c.kind, c.data.to_vec()))
            .collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, SOL_KACS);
        assert_eq!(parsed[0].1, KACS_SCM_TOKEN);
        assert_eq!(parsed[0].2, 7i32.to_ne_bytes().to_vec());
        assert_eq!(parsed[1].0, libc::SOL_SOCKET);
        assert_eq!(parsed[1].1, libc::SCM_RIGHTS);
        let mut rights = Vec::new();
        rights.extend_from_slice(&3i32.to_ne_bytes());
        rights.extend_from_slice(&4i32.to_ne_bytes());
        assert_eq!(parsed[1].2, rights);
    }

    #[test]
    fn send_control_is_empty_with_nothing_to_attach() {
        assert!(build_send_control(-1, &[]).is_empty());
    }

    #[test]
    fn parse_control_stops_at_a_short_header() {
        let mut control = build_send_control(7, &[]);
        control.truncate(size_of::<libc::cmsghdr>() - 1);
        assert_eq!(parse_control(&control).count(), 0);
    }

    #[test]
    fn parse_control_rejects_a_length_past_the_buffer() {
        let mut control = build_send_control(7, &[]);
        // Corrupt cmsg_len to claim more than the buffer holds.
        let bogus = (control.len() + 8).to_ne_bytes();
        control[..size_of::<usize>()].copy_from_slice(&bogus);
        assert_eq!(parse_control(&control).count(), 0);
    }
}
