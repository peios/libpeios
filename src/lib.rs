//! libpeios — the Peios userspace C ABI library.
//!
//! A `no_std`, `panic = "abort"` cdylib/staticlib: thin `extern "C"` shims layered on
//! the shared C-ABI substrate `peios-cabi`, over `kacs-core` (`pkm-core`),
//! `peios-uapi`, and `libc`, exposing the Peios kernel↔userspace boundary as
//! `<peios/*.h>`. The surface spans all three
//! subsystems — KACS access control (`<peios/{security,token,access,file,
//! process}.h>`), KMES events (`<peios/{msgpack,event}.h>`), and the LCS registry
//! (`<peios/registry.h>`) — each a slice-by-slice module below.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

// The allocator, errno slot, syscall/ioctl wrappers, and getxattr/builder helpers
// live in the shared `peios-cabi` substrate; re-export the two plumbing modules so
// the domain modules keep reaching them as `crate::abi` / `crate::sys`. (`error`
// stays local — it adds the `KacsError` mapping on top of the substrate's errno slot.)
pub(crate) use peios_cabi::{abi, sys};

mod access;
mod error;
mod event;
mod file;
mod msgpack;
mod process;
mod registry;
mod security;
mod token;

/// Install the shared malloc-backed global allocator (`peios_cabi::LibcAllocator`).
/// Declared here in the cdylib — not the substrate crate — so it is gated out of
/// `cfg(test)` builds, where std supplies its own global allocator.
#[cfg(not(test))]
#[global_allocator]
static GLOBAL: peios_cabi::LibcAllocator = peios_cabi::LibcAllocator;

#[cfg(not(test))]
extern "C" {
    /// libc `abort(3)`; resolved against the system C library at link time.
    fn abort() -> !;
}

/// Nothing may unwind across the C ABI boundary — abort the process on panic.
///
/// `kacs-core` is panic-free on malformed input (the kernel runs the same
/// parsers on untrusted bytes), so a panic here can only mean a genuine
/// internal bug, for which aborting loudly is the correct fail-safe. Gated out
/// of `cfg(test)` builds, where std supplies the panic runtime and test harness.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: `abort` never returns and performs no Rust unwinding.
    unsafe { abort() }
}
