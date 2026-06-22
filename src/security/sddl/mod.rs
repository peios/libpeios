//! Vendored, pure-Rust SDDL text codec + ACE conditions + SD inheritance.
//!
//! This subtree implements the userspace-only security-descriptor facilities
//! that are *not* in the kernel/KACS binary ABI: the SDDL string grammar
//! (parse text → self-relative SD wire bytes, and the inverse), the
//! conditional-expression text ⇄ `"artx"` bytecode codec, and SD inheritance
//! (`reinherit` / `strip_inherited_aces`). All of it is self-contained byte
//! logic — no syscalls — sitting on the same `peios-uapi` constants the rest
//! of libpeios uses.
//!
//! It is exposed to C through the `peios_sddl_*` / `peios_sd_*` entry points
//! in [`super::sddl_ffi`]. The modules here are crate-private implementation
//! detail (lifted from the historical `libp-sd` Rust crate); they deal in
//! raw SD/ACL/ACE/SID wire bytes and never cross the C ABI as Rust types.
//!
//! The full SD codec surface is carried verbatim (the complete `ACCESS_*` /
//! `ACE_TYPE_*` vocabulary, claim encoders, and fragment-level builders),
//! so not every item is reachable from the six FFI entry points yet; the
//! round-trip test corpus exercises the rest. Keep it intact rather than
//! prune — `allow(dead_code)` covers the currently-unwired surface.
#![allow(dead_code)]

pub(crate) mod abi;
pub(crate) mod build;
pub(crate) mod claims;
pub(crate) mod codec;
pub(crate) mod condition;
pub(crate) mod grammar;
pub(crate) mod inherit;
pub(crate) mod wellknown;
pub(crate) mod wire_error;
pub(crate) mod wire_sid;

/// The on-wire SID primitive (lifted from the historical `libp-wire` crate),
/// re-exported under one path so the vendored modules import it uniformly.
pub(crate) mod wire {
    pub(crate) use super::wire_error::ParseError;
    pub(crate) use super::wire_sid::*;
}

/// Internal error for the vendored byte logic. The C ABI layer maps every
/// variant to `EINVAL` (malformed input); the textual detail is only used
/// inside the codec (e.g. nested errors stringified into an `SddlError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Error {
    /// An SD / ACL / ACE / SID blob couldn't be parsed.
    Parse(wire_error::ParseError),
    /// A builder was handed an input that can't be encoded (e.g. an ACL
    /// with more ACEs than the 16-bit count field allows).
    Encode(&'static str),
    /// SDDL text couldn't be parsed, or a binary SD couldn't be formatted.
    Sddl(grammar::SddlError),
}

pub(crate) type Result<T> = core::result::Result<T, Error>;

impl From<wire_error::ParseError> for Error {
    fn from(e: wire_error::ParseError) -> Self {
        Error::Parse(e)
    }
}

impl From<grammar::SddlError> for Error {
    fn from(e: grammar::SddlError) -> Self {
        Error::Sddl(e)
    }
}
