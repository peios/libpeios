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

// Satisfy the EH-unwinding references that remain in a no-std cdylib even under
// `panic = "abort"`: the precompiled sysroot `alloc` is built `panic = "unwind"`,
// so its error paths leave dangling `rust_eh_personality` / `_Unwind_Resume`
// relocations. Nothing resolves them in a std-less link — invisible to Rust
// consumers (cargo drags in std's definitions) but fatal the instant a C program
// loads libpeios.so (`symbol lookup error`). Define both as hidden assembler
// stubs so they satisfy local relocations without joining the public dynamic ABI.
// Nothing in libpeios may unwind; reaching either is a fatal internal bug, so the
// personality reports a fatal error and `_Unwind_Resume` aborts. Mirrors librsi.
#[cfg(all(not(test), target_arch = "x86_64"))]
core::arch::global_asm!(
    ".hidden rust_eh_personality",
    ".globl rust_eh_personality",
    ".type rust_eh_personality, @function",
    "rust_eh_personality:",
    "endbr64",
    "mov eax, 3",
    "ret",
    ".size rust_eh_personality, . - rust_eh_personality",

    ".hidden _Unwind_Resume",
    ".globl _Unwind_Resume",
    ".type _Unwind_Resume, @function",
    "_Unwind_Resume:",
    "endbr64",
    "call abort",
    ".size _Unwind_Resume, . - _Unwind_Resume",
);
