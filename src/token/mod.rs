//! KACS access tokens — realises `<peios/token.h>`.
//!
//! This module has two halves. The token-spec [`builder`] is pure userspace byte
//! assembly (the 192-byte-header wire format consumed by `kacs_create_token`) and
//! is unit-tested here. The fd-returning calls (open/query/adjust/duplicate/…)
//! are syscall-backed and land once the KACS invocation layer exists; they are
//! exercised live under Provium rather than in `cargo test`.

#![allow(non_upper_case_globals)]

pub mod actions;
pub mod builder;
pub mod ops;
pub mod query;

use peios_uapi::{
    kacs_generic_mapping, KACS_ACCESS_READ_CONTROL, KACS_ACCESS_WRITE_DAC,
    KACS_TOKEN_ADJUST_DEFAULT, KACS_TOKEN_ADJUST_GROUPS, KACS_TOKEN_ADJUST_PRIVS,
    KACS_TOKEN_ALL_ACCESS, KACS_TOKEN_IMPERSONATE, KACS_TOKEN_QUERY,
};

/// `peios_token_generic_mapping` — the canonical KACS generic mapping for the
/// token object class (mirrors the kernel's `TOKEN_GENERIC_MAPPING`).
#[no_mangle]
pub static peios_token_generic_mapping: kacs_generic_mapping = kacs_generic_mapping {
    read: KACS_ACCESS_READ_CONTROL | KACS_TOKEN_QUERY,
    write: KACS_TOKEN_ADJUST_PRIVS
        | KACS_TOKEN_ADJUST_GROUPS
        | KACS_TOKEN_ADJUST_DEFAULT
        | KACS_ACCESS_WRITE_DAC,
    execute: KACS_TOKEN_IMPERSONATE,
    all: KACS_TOKEN_ALL_ACCESS,
};
