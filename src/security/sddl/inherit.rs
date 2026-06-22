// ACE inheritance derivation (MS-DTYP §2.5.3.4).
//
// `compute_inherited_aces` is the parsed-ACL primitive — given a parent
// DACL and whether the child is a container, returns the ACEs the child
// inherits. `reinherit` is the wire-bytes sugar that strips inherited
// ACEs from a child SD and appends freshly-derived ones from a parent SD.
//
// Used by the `sd propagate` walk in the userspace `sd` tool, and by
// anything else that needs to push parent inheritance down a hierarchy
// (registry, future eventd object trees). Kernel exposes no
// reinheritance primitive — this is the canonical userspace shape.

use crate::security::sddl::Result;
use crate::security::sddl::build::{AceBuilder, AclBuilder, SdBuilder};
use crate::security::sddl::Error;
use alloc::vec::Vec;
use crate::security::sddl::codec::{
    ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_INHERIT_ONLY, ACE_FLAG_INHERITED,
    ACE_FLAG_NO_PROPAGATE_INHERIT, ACE_FLAG_OBJECT_INHERIT, Acl, DACL_SECURITY_INFORMATION,
    SACL_SECURITY_INFORMATION, SD_HEADER_BYTES, SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED,
    SE_SACL_AUTO_INHERITED, SE_SACL_PROTECTED, SE_SELF_RELATIVE, SecurityDescriptor,
};
use crate::security::sddl::wire::{ParseError, SidRef};
use alloc::vec;

/// All four inheritance-control flags as one mask — cleared on a child
/// copy when the ACE is "consumed" (file child, or NP).
const ALL_INHERIT_FLAGS: u8 = ACE_FLAG_OBJECT_INHERIT
    | ACE_FLAG_CONTAINER_INHERIT
    | ACE_FLAG_NO_PROPAGATE_INHERIT
    | ACE_FLAG_INHERIT_ONLY;

/// Compute the ACEs a child inherits from `parent_dacl`. Implements
/// MS-DTYP §2.5.3.4.1 `ComputeInheritedACEsFromACE`:
///
/// - A parent ACE with neither `OBJECT_INHERIT` (OI) nor `CONTAINER_INHERIT`
///   (CI) is not inheritable and produces nothing.
/// - For a **file** child (`child_is_container = false`):
///   - OI set → one inherited ACE with all four inheritance flags cleared
///     (the ACE applies to the file; files don't propagate further).
///   - OI not set → nothing.
/// - For a **container** child:
///   - CI set:
///     - `NO_PROPAGATE_INHERIT` (NP) set → one ACE with all inheritance
///       flags cleared (applies here, doesn't further propagate).
///     - NP not set → one ACE with NP and `INHERIT_ONLY` cleared, OI and
///       CI preserved (applies here AND continues propagation).
///   - CI not set, OI set:
///     - NP set → nothing (OI doesn't apply to containers, NP stops
///       further propagation, so the child sees nothing).
///     - NP not set → one ACE with `INHERIT_ONLY` set and OI preserved
///       (doesn't apply to this container, but propagates to files
///       within and OI-inheritable to deeper containers).
///
/// All returned ACEs have `ACE_FLAG_INHERITED` set. Non-inheritance
/// flags (audit `SA`/`FA`, the parent's own `INHERITED` bit) are
/// preserved.
///
/// Parser errors in `parent_dacl` are silently skipped — a malformed
/// ACE doesn't propagate (and the caller can validate the parent SD
/// independently if needed).
pub fn compute_inherited_aces(parent_dacl: &Acl<'_>, child_is_container: bool) -> Vec<AceBuilder> {
    let mut out = Vec::new();
    for ace_result in parent_dacl.aces_iter() {
        let Ok(ace) = ace_result else { continue };
        let f = ace.flags;
        let oi = f & ACE_FLAG_OBJECT_INHERIT != 0;
        let ci = f & ACE_FLAG_CONTAINER_INHERIT != 0;
        let np = f & ACE_FLAG_NO_PROPAGATE_INHERIT != 0;

        if !oi && !ci {
            continue;
        }

        let new_flags: u8 = if !child_is_container {
            if !oi {
                continue;
            }
            (f & !ALL_INHERIT_FLAGS) | ACE_FLAG_INHERITED
        } else if np {
            if ci {
                (f & !ALL_INHERIT_FLAGS) | ACE_FLAG_INHERITED
            } else {
                continue;
            }
        } else if ci {
            (f & !(ACE_FLAG_NO_PROPAGATE_INHERIT | ACE_FLAG_INHERIT_ONLY)) | ACE_FLAG_INHERITED
        } else {
            // OI alone, no NP, container child.
            (f & !ACE_FLAG_NO_PROPAGATE_INHERIT) | ACE_FLAG_INHERIT_ONLY | ACE_FLAG_INHERITED
        };

        out.push(AceBuilder::from_ace_ref(&ace).flags(new_flags));
    }
    out
}

/// Reinherit a child SD from its parent. Strips ACEs with
/// `ACE_FLAG_INHERITED` from the child's DACL, then appends the
/// freshly-computed inherited set from `parent_sd`.
///
/// Both inputs must be self-relative; output is self-relative. Owner,
/// group, and SACL of the child pass through verbatim. Control bits
/// `SE_DACL_AUTO_INHERITED` / `SE_DACL_PROTECTED` /
/// `SE_SACL_AUTO_INHERITED` / `SE_SACL_PROTECTED` are preserved from
/// the child; this function does NOT honour protection itself — a
/// caller who wants to respect `SE_DACL_PROTECTED` should check it
/// before calling.
///
/// If the parent has no DACL, the child's inherited ACEs are stripped
/// and no new ones are added.
///
/// ACE order in the output DACL is: child's explicit (non-inherited)
/// ACEs in declaration order, then the new inherited ACEs in
/// declaration order — the canonical "explicit before inherited"
/// shape per MS-DTYP §2.5.2.1.
///
/// # Errors
/// [`Error::Parse`] if either input is malformed or not self-relative.
pub fn reinherit(parent_sd: &[u8], child_sd: &[u8], child_is_container: bool) -> Result<Vec<u8>> {
    let parent = SecurityDescriptor::parse(parent_sd)?;
    let child = SecurityDescriptor::parse(child_sd)?;
    if child.control & SE_SELF_RELATIVE == 0 {
        return Err(Error::Parse(ParseError::SdNotSelfRelative));
    }

    let new_inherited = match parent.dacl() {
        Some(Ok(d)) => compute_inherited_aces(&d, child_is_container),
        Some(Err(e)) => return Err(Error::Parse(e)),
        None => Vec::new(),
    };

    let (had_dacl, mut dacl_builder) = match child.dacl() {
        Some(Ok(dacl)) => {
            let mut b = AclBuilder::new();
            for ace_r in dacl.aces_iter() {
                let ace = ace_r?;
                if ace.flags & ACE_FLAG_INHERITED == 0 {
                    b = b.ace(AceBuilder::from_ace_ref(&ace));
                }
            }
            (true, b)
        }
        Some(Err(e)) => return Err(Error::Parse(e)),
        None => (false, AclBuilder::new()),
    };
    for ace in new_inherited {
        dacl_builder = dacl_builder.ace(ace);
    }

    let mut out = SdBuilder::new();
    if let Some(owner) = child.owner() {
        out = out.owner(owner);
    }
    if let Some(group) = child.group() {
        out = out.group(group);
    }
    match child.sacl() {
        Some(Ok(sacl)) => {
            let mut sb = AclBuilder::new();
            for ace_r in sacl.aces_iter() {
                sb = sb.ace(AceBuilder::from_ace_ref(&ace_r?));
            }
            out = out.sacl(sb);
        }
        Some(Err(e)) => return Err(Error::Parse(e)),
        None => {}
    }
    if had_dacl || !dacl_builder.is_empty() {
        out = out.dacl(dacl_builder);
    }
    let extra = child.control
        & (SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_SACL_AUTO_INHERITED | SE_SACL_PROTECTED);
    if extra != 0 {
        out = out.control(extra);
    }
    out.build()
}

/// Strip ACEs carrying `ACE_FLAG_INHERITED` from the ACLs selected by
/// `info` (a mask of `*_SECURITY_INFORMATION` bits).
///
/// - `DACL_SECURITY_INFORMATION` in `info` → strip inherited ACEs from the
///   DACL. `SACL_SECURITY_INFORMATION` → strip from the SACL. Other bits
///   are ignored. `info` selecting neither → returns `sd_bytes` verbatim.
///
/// Owner SID, group SID, and the control word pass through verbatim
/// (including the `SE_*_AUTO_INHERITED` bits — this filters ACEs, it does
/// not re-derive inheritance metadata). A filtered ACL keeps its revision
/// and `Sbz1`; its `AceCount` / `AclSize` and the SD offsets are
/// recomputed. The output is self-relative.
pub fn strip_inherited_aces(sd_bytes: &[u8], info: u32) -> Result<Vec<u8>> {
    let sd = SecurityDescriptor::parse(sd_bytes)?;
    if sd.control & SE_SELF_RELATIVE == 0 {
        return Err(Error::Parse(ParseError::SdNotSelfRelative));
    }

    let strip_dacl = info & DACL_SECURITY_INFORMATION != 0;
    let strip_sacl = info & SACL_SECURITY_INFORMATION != 0;
    if !strip_dacl && !strip_sacl {
        // Nothing selected — hand the input straight back.
        return Ok(sd_bytes.to_vec());
    }

    // Resolve the four referenced components into owned byte buffers.
    let owner = verbatim_sid(sd_bytes, sd.owner_off)?;
    let group = verbatim_sid(sd_bytes, sd.group_off)?;
    let sacl = resolve_acl(sd.sacl(), strip_sacl)?;
    let dacl = resolve_acl(sd.dacl(), strip_dacl)?;

    // Reassemble: 20-byte header, then owner, group, SACL, DACL.
    let mut out = vec![0u8; SD_HEADER_BYTES];
    let mut owner_off = 0u32;
    let mut group_off = 0u32;
    let mut sacl_off = 0u32;
    let mut dacl_off = 0u32;
    if let Some(b) = &owner {
        owner_off = out.len() as u32;
        out.extend_from_slice(b);
    }
    if let Some(b) = &group {
        group_off = out.len() as u32;
        out.extend_from_slice(b);
    }
    if let Some(b) = &sacl {
        sacl_off = out.len() as u32;
        out.extend_from_slice(b);
    }
    if let Some(b) = &dacl {
        dacl_off = out.len() as u32;
        out.extend_from_slice(b);
    }

    out[0] = sd.revision;
    out[1] = sd.sbz1;
    out[2..4].copy_from_slice(&sd.control.to_le_bytes());
    out[4..8].copy_from_slice(&owner_off.to_le_bytes());
    out[8..12].copy_from_slice(&group_off.to_le_bytes());
    out[12..16].copy_from_slice(&sacl_off.to_le_bytes());
    out[16..20].copy_from_slice(&dacl_off.to_le_bytes());
    Ok(out)
}

/// Copy the SID at byte offset `off` verbatim. `off == 0` → absent.
fn verbatim_sid(sd_bytes: &[u8], off: u32) -> Result<Option<Vec<u8>>> {
    if off == 0 {
        return Ok(None);
    }
    let start = off as usize;
    if start > sd_bytes.len() {
        return Err(Error::Parse(ParseError::SdOffsetOutOfBounds));
    }
    let (_, used) = SidRef::parse(&sd_bytes[start..])?;
    Ok(Some(sd_bytes[start..start + used].to_vec()))
}

/// Resolve one ACL into the bytes to emit. `None` → absent and stays
/// absent. A selected ACL is filtered; an unselected one is copied verbatim.
fn resolve_acl(
    acl: core::option::Option<core::result::Result<Acl<'_>, ParseError>>,
    strip: bool,
) -> Result<Option<Vec<u8>>> {
    match acl {
        None => Ok(None),
        Some(Err(e)) => Err(Error::Parse(e)),
        Some(Ok(acl)) => {
            // A well-formed ACL is at least its 8-byte header.
            if (acl.size as usize) < 8 {
                return Err(Error::Parse(ParseError::AclSizeOutOfBounds));
            }
            if strip {
                Ok(Some(filter_acl(&acl)?))
            } else {
                Ok(Some(acl.bytes.to_vec()))
            }
        }
    }
}

/// Rebuild an ACL keeping only the ACEs without `ACE_FLAG_INHERITED`.
fn filter_acl(acl: &Acl<'_>) -> Result<Vec<u8>> {
    let mut ace_bytes: Vec<u8> = Vec::new();
    let mut kept: u16 = 0;
    for ace in acl.aces_iter() {
        let ace = ace?;
        if ace.flags & ACE_FLAG_INHERITED != 0 {
            continue;
        }
        // Re-emit the ACE verbatim: [type][flags][size:u16le][body].
        ace_bytes.push(ace.ace_type);
        ace_bytes.push(ace.flags);
        ace_bytes.extend_from_slice(&ace.size.to_le_bytes());
        ace_bytes.extend_from_slice(ace.body);
        kept += 1; // bounded by the source AceCount, itself a u16
    }
    let total = 8 + ace_bytes.len();
    if total > u16::MAX as usize {
        return Err(Error::Encode("filtered ACL exceeds 65535 bytes"));
    }
    let mut out = Vec::with_capacity(total);
    out.push(acl.revision); // AclRevision — copied
    out.push(acl.bytes[1]); // Sbz1 — copied
    out.extend_from_slice(&(total as u16).to_le_bytes()); // AclSize — recomputed
    out.extend_from_slice(&kept.to_le_bytes()); // AceCount — recomputed
    out.extend_from_slice(&0u16.to_le_bytes()); // Sbz2 — zeroed
    out.extend_from_slice(&ace_bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::sddl::wellknown::WellKnownSid;
    use alloc::vec;
    use crate::security::sddl::codec::{ACCESS_GENERIC_ALL, ACCESS_GENERIC_READ};

    fn build_parent_dacl(aces: Vec<AceBuilder>) -> Vec<u8> {
        let mut b = AclBuilder::new();
        for a in aces {
            b = b.ace(a);
        }
        b.build().unwrap()
    }

    fn parse_dacl(bytes: &[u8]) -> Acl<'_> {
        Acl::parse(bytes).unwrap()
    }

    // ---- compute_inherited_aces ----

    #[test]
    fn no_inherit_flags_emits_nothing() {
        let bytes = build_parent_dacl(vec![AceBuilder::allow(
            WellKnownSid::Everyone,
            ACCESS_GENERIC_READ,
        )]);
        let acl = parse_dacl(&bytes);
        assert!(compute_inherited_aces(&acl, true).is_empty());
        assert!(compute_inherited_aces(&acl, false).is_empty());
    }

    #[test]
    fn oi_only_to_file_clears_all_inherit_flags() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_OBJECT_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, false);
        assert_eq!(out.len(), 1);
        let built = out[0].build();
        let f = built[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert_eq!(f & ALL_INHERIT_FLAGS, 0);
    }

    #[test]
    fn oi_only_to_container_keeps_oi_sets_io() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_OBJECT_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, true);
        assert_eq!(out.len(), 1);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert!(f & ACE_FLAG_OBJECT_INHERIT != 0);
        assert!(f & ACE_FLAG_INHERIT_ONLY != 0);
        assert_eq!(f & ACE_FLAG_CONTAINER_INHERIT, 0);
        assert_eq!(f & ACE_FLAG_NO_PROPAGATE_INHERIT, 0);
    }

    #[test]
    fn ci_only_to_file_emits_nothing() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_CONTAINER_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        assert!(compute_inherited_aces(&acl, false).is_empty());
    }

    #[test]
    fn ci_only_to_container_keeps_ci_clears_io() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_CONTAINER_INHERIT | ACE_FLAG_INHERIT_ONLY),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, true);
        assert_eq!(out.len(), 1);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert!(f & ACE_FLAG_CONTAINER_INHERIT != 0);
        assert_eq!(f & ACE_FLAG_INHERIT_ONLY, 0);
        assert_eq!(f & ACE_FLAG_OBJECT_INHERIT, 0);
    }

    #[test]
    fn ci_oi_to_container_keeps_both_clears_io() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_CONTAINER_INHERIT | ACE_FLAG_OBJECT_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, true);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert!(f & ACE_FLAG_CONTAINER_INHERIT != 0);
        assert!(f & ACE_FLAG_OBJECT_INHERIT != 0);
        assert_eq!(f & ACE_FLAG_INHERIT_ONLY, 0);
    }

    #[test]
    fn np_collapses_to_one_level_on_container() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ).flags(
                ACE_FLAG_CONTAINER_INHERIT
                    | ACE_FLAG_OBJECT_INHERIT
                    | ACE_FLAG_NO_PROPAGATE_INHERIT,
            ),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, true);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert_eq!(f & ALL_INHERIT_FLAGS, 0);
    }

    #[test]
    fn np_with_oi_only_to_container_emits_nothing() {
        // OI alone says "applies to files only"; NP says "don't propagate
        // beyond the immediate child." A container child with this combo
        // sees nothing — the ACE doesn't apply (no CI) and won't propagate.
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_NO_PROPAGATE_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        assert!(compute_inherited_aces(&acl, true).is_empty());
    }

    #[test]
    fn np_with_oi_to_file_emits_one_terminal_ace() {
        // File child of an OI+NP ACE: still inherits, no further propagation.
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_NO_PROPAGATE_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, false);
        assert_eq!(out.len(), 1);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert_eq!(f & ALL_INHERIT_FLAGS, 0);
    }

    #[test]
    fn parent_inherited_flag_preserved_on_child() {
        // Parent ACE has INHERITED set (from grandparent). Child copy
        // also has INHERITED set — same bit, just confirms we OR rather
        // than overwrite.
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_INHERITED),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, false);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
    }

    // ---- reinherit ----

    #[test]
    fn reinherit_drops_old_inherited_and_appends_new() {
        let parent = SdBuilder::new()
            .owner(WellKnownSid::LocalSystem)
            .dacl(
                AclBuilder::new().ace(
                    AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                        .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT),
                ),
            )
            .build()
            .unwrap();
        // Child file with stale inherited ACE and one explicit ACE.
        let child = SdBuilder::new()
            .dacl(
                AclBuilder::new()
                    .ace(AceBuilder::allow(
                        WellKnownSid::Anonymous,
                        ACCESS_GENERIC_ALL,
                    ))
                    .ace(
                        AceBuilder::allow(WellKnownSid::AuthenticatedUsers, ACCESS_GENERIC_READ)
                            .flags(ACE_FLAG_INHERITED),
                    ),
            )
            .build()
            .unwrap();

        let out = reinherit(&parent, &child, false).unwrap();
        let parsed = SecurityDescriptor::parse(&out).unwrap();
        let dacl = parsed.dacl().unwrap().unwrap();
        assert_eq!(dacl.ace_count, 2, "explicit + freshly inherited");
        let aces: Vec<_> = dacl.aces_iter().collect();
        let a0 = aces[0].as_ref().unwrap();
        let a1 = aces[1].as_ref().unwrap();
        // First ACE is the explicit one (Anonymous, no INHERITED flag).
        assert_eq!(a0.flags & ACE_FLAG_INHERITED, 0);
        let (_, sid0) = a0.as_mask_sid().unwrap();
        assert_eq!(sid0.to_owned(), WellKnownSid::Anonymous.to_sid());
        // Second ACE is the freshly inherited one — Everyone from parent.
        assert!(a1.flags & ACE_FLAG_INHERITED != 0);
        let (_, sid1) = a1.as_mask_sid().unwrap();
        assert_eq!(sid1.to_owned(), WellKnownSid::Everyone.to_sid());
    }

    #[test]
    fn reinherit_preserves_owner_group_sacl() {
        let parent = SdBuilder::new().build().unwrap();
        let child = SdBuilder::new()
            .owner(WellKnownSid::LocalSystem)
            .group(WellKnownSid::BuiltinAdministrators)
            .sacl(AclBuilder::new().ace(AceBuilder::audit(
                WellKnownSid::Everyone,
                ACCESS_GENERIC_READ,
            )))
            .dacl(AclBuilder::new().ace(AceBuilder::allow(
                WellKnownSid::Anonymous,
                ACCESS_GENERIC_ALL,
            )))
            .build()
            .unwrap();
        let out = reinherit(&parent, &child, true).unwrap();
        let parsed = SecurityDescriptor::parse(&out).unwrap();
        assert_eq!(parsed.owner().unwrap(), WellKnownSid::LocalSystem.to_sid());
        assert_eq!(
            parsed.group().unwrap(),
            WellKnownSid::BuiltinAdministrators.to_sid()
        );
        assert_eq!(parsed.sacl().unwrap().unwrap().ace_count, 1);
        assert_eq!(parsed.dacl().unwrap().unwrap().ace_count, 1);
    }

    #[test]
    fn reinherit_preserves_protection_bit() {
        let parent = SdBuilder::new()
            .dacl(
                AclBuilder::new().ace(
                    AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                        .flags(ACE_FLAG_OBJECT_INHERIT),
                ),
            )
            .build()
            .unwrap();
        let child = SdBuilder::new()
            .dacl(AclBuilder::new().ace(AceBuilder::allow(
                WellKnownSid::Anonymous,
                ACCESS_GENERIC_ALL,
            )))
            .control(SE_DACL_PROTECTED)
            .build()
            .unwrap();
        let out = reinherit(&parent, &child, false).unwrap();
        let parsed = SecurityDescriptor::parse(&out).unwrap();
        assert!(parsed.control & SE_DACL_PROTECTED != 0);
    }

    #[test]
    fn reinherit_with_parent_no_dacl_just_strips() {
        let parent = SdBuilder::new().build().unwrap();
        let child = SdBuilder::new()
            .dacl(
                AclBuilder::new()
                    .ace(AceBuilder::allow(
                        WellKnownSid::Anonymous,
                        ACCESS_GENERIC_ALL,
                    ))
                    .ace(
                        AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                            .flags(ACE_FLAG_INHERITED),
                    ),
            )
            .build()
            .unwrap();
        let out = reinherit(&parent, &child, false).unwrap();
        let parsed = SecurityDescriptor::parse(&out).unwrap();
        let dacl = parsed.dacl().unwrap().unwrap();
        assert_eq!(dacl.ace_count, 1, "only the explicit ACE remains");
    }

    #[test]
    fn reinherit_rejects_non_self_relative_child() {
        let parent = SdBuilder::new().build().unwrap();
        let mut child = [0u8; 20];
        child[0] = 1; // revision; no SE_SELF_RELATIVE bit
        assert!(matches!(
            reinherit(&parent, &child, false),
            Err(Error::Parse(ParseError::SdNotSelfRelative))
        ));
    }

    #[test]
    fn reinherit_container_chain_keeps_propagating_flags() {
        // Parent has CI+OI ACE. Reinherit into a container child: the
        // resulting inherited ACE should still carry CI+OI so a further
        // reinherit picks it up for grandchildren.
        let parent = SdBuilder::new()
            .dacl(
                AclBuilder::new().ace(
                    AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                        .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT),
                ),
            )
            .build()
            .unwrap();
        let child = SdBuilder::new().build().unwrap();
        let out = reinherit(&parent, &child, true).unwrap();
        let parsed = SecurityDescriptor::parse(&out).unwrap();
        let dacl = parsed.dacl().unwrap().unwrap();
        let aces: Vec<_> = dacl.aces_iter().collect();
        let ace = aces[0].as_ref().unwrap();
        assert!(ace.flags & ACE_FLAG_CONTAINER_INHERIT != 0);
        assert!(ace.flags & ACE_FLAG_OBJECT_INHERIT != 0);
        assert!(ace.flags & ACE_FLAG_INHERITED != 0);
    }
}
