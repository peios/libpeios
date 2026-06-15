//! KACS security-descriptor vocabulary — realises `<peios/security.h>`.
//!
//! The module splits along the header's sections: [`sid`] covers the SID
//! helpers (build / parse-string / format / well-known / integrity / logon and
//! the inspectors). ACL and security-descriptor builders and the zero-copy
//! views land in sibling modules as they are implemented.

pub mod acl_builder;
pub mod mapping;
pub mod sd_builder;
pub mod sid;
pub mod view;

use kacs_core::{Acl, Sid};

/// A structurally valid SID occupying exactly `bytes` (no trailing slop).
pub(crate) fn sid_valid(bytes: &[u8]) -> bool {
    Sid::parse(bytes).is_ok_and(|s| s.as_bytes().len() == bytes.len())
}

/// A structurally valid ACL whose declared ACEs all parse.
pub(crate) fn acl_valid(bytes: &[u8]) -> bool {
    Acl::parse(bytes)
        .map(|acl| acl.entries().all(|entry| entry.is_ok()))
        .unwrap_or(false)
}
