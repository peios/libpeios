// ACE inheritance derivation (PCDS §5.6; MS-DTYP §2.5.3.4).
//
// `inherited_aces` is the parsed-ACL primitive: given a parent ACL and
// what the child is (a container or not, its owner and group, its
// object's generic mapping), the ACEs the child inherits, as KACS gives
// them to a child it creates. `reinherit_with` is the wire-bytes form for
// re-propagation (PCDS §5.6, Re-propagation): it drops a child's
// inherited ACEs from the lists selected, skipping a list the child
// protects, and appends freshly derived ones from the parent.
// `compute_inherited_aces` and `reinherit` are the older forms, with no
// owner, group or mapping, and the DACL alone.
//
// Used by the `sd propagate` walk in the userspace `sd` tool, by the
// permissions editor, and by anything else that pushes a parent's
// inheritance down a hierarchy. The kernel has no re-propagation
// primitive; this is the canonical userspace shape, and it MUST agree with
// what the kernel does on creation.

use crate::security::sddl::Result;
use crate::security::sddl::build::{AceBuilder, AclBuilder, SdBuilder};
use crate::security::sddl::Error;
use alloc::vec::Vec;
use crate::security::sddl::codec::{
    ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_INHERIT_ONLY, ACE_FLAG_INHERITED,
    ACE_FLAG_NO_PROPAGATE_INHERIT, ACE_FLAG_OBJECT_INHERIT, Acl, DACL_SECURITY_INFORMATION,
    GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, GenericMapping,
    SACL_SECURITY_INFORMATION, SD_HEADER_BYTES, SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED,
    SE_SACL_AUTO_INHERITED, SE_SACL_PROTECTED, SE_SELF_RELATIVE, SecurityDescriptor,
};
use crate::security::sddl::wire::{ParseError, SidRef};
use alloc::vec;

/// CREATOR OWNER (S-1-3-0) and CREATOR GROUP (S-1-3-1), as they are encoded.
const CREATOR_OWNER: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
const CREATOR_GROUP: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 3, 1, 0, 0, 0];

/// The four generic access bits.
const GENERIC_BITS: u32 = GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ;

/// What a child is, for working out what it inherits.
#[derive(Clone, Copy, Debug, Default)]
pub struct Child<'a> {
    /// Whether it is a container, which ACEs go on from.
    pub container: bool,
    /// Its owner and primary group, encoded, which CREATOR OWNER and
    /// CREATOR GROUP resolve to. Absent, they are left as written.
    pub owner: Option<&'a [u8]>,
    pub group: Option<&'a [u8]>,
    /// Its object type's generic mapping, which generic rights are mapped
    /// through where they apply. Absent, they are left as written.
    pub mapping: Option<GenericMapping>,
}

/// All four inheritance-control flags as one mask — cleared on a child
/// copy when the ACE is "consumed" (file child, or NP).
const ALL_INHERIT_FLAGS: u8 = ACE_FLAG_OBJECT_INHERIT
    | ACE_FLAG_CONTAINER_INHERIT
    | ACE_FLAG_NO_PROPAGATE_INHERIT
    | ACE_FLAG_INHERIT_ONLY;

/// The ACEs a child inherits from `parent_acl`, a DACL or a SACL, as
/// PCDS §5.6 gives them (MS-DTYP §2.5.3.4.4):
///
/// - A parent ACE passes to a container if it has CI, or OI without NP,
///   and to any other object if it has OI. `INHERIT_ONLY` on the parent
///   ACE is no part of the decision.
/// - The copy is marked `INHERITED`, with `INHERIT_ONLY` cleared, except
///   that an ACE with OI and neither CI nor NP reaches a container as
///   inherit-only, on its way to the objects inside. NP clears OI, CI and
///   NP from the copy, and a non-container's copy has no inheritance flags.
/// - An ACE that names CREATOR OWNER or CREATOR GROUP, or carries generic
///   rights, is resolved where it applies: the SID becomes the child's
///   owner or group, and the generic rights are mapped through the child's
///   mapping. Where such an ACE both applies to a container and goes on
///   from it, the container gets two: the resolved ACE with no inheritance
///   flags, and an inherit-only copy left as written, so that each object
///   further down resolves it for itself.
/// - Any other ACE is copied as it is, with its new flags. Other flags
///   (audit `SA`/`FA`) are kept, and an ACE of a type with no mask or SID
///   to rewrite is copied byte for byte apart from its flags.
///
/// A malformed parent ACE is skipped.
pub fn inherited_aces(parent_acl: &Acl<'_>, child: &Child<'_>) -> Vec<AceBuilder> {
    let mut out = Vec::new();
    for ace in parent_acl.aces_iter().flatten() {
        let f = ace.flags;
        let oi = f & ACE_FLAG_OBJECT_INHERIT != 0;
        let ci = f & ACE_FLAG_CONTAINER_INHERIT != 0;
        let np = f & ACE_FLAG_NO_PROPAGATE_INHERIT != 0;
        if !(oi || (ci && child.container)) {
            continue;
        }
        // OI alone is for the objects inside; with NP it stops before them.
        if child.container && !ci && np {
            continue;
        }
        let mut flags = (f | ACE_FLAG_INHERITED) & !ACE_FLAG_INHERIT_ONLY;
        if child.container && oi && !ci && !np {
            flags |= ACE_FLAG_INHERIT_ONLY;
        }
        if np || !child.container {
            flags &= !ALL_INHERIT_FLAGS;
        }
        let applies = flags & ACE_FLAG_INHERIT_ONLY == 0;
        let goes_on = flags & (ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT) != 0;
        if resolvable(&ace, child) {
            if applies {
                out.push(copy(&ace, flags & !ALL_INHERIT_FLAGS, Some(child)));
            }
            if goes_on {
                out.push(copy(&ace, flags | ACE_FLAG_INHERIT_ONLY, None));
            }
        } else {
            out.push(copy(&ace, flags, None));
        }
    }
    out
}

/// [`inherited_aces`] with nothing known of the child but whether it is a
/// container: CREATOR OWNER and CREATOR GROUP stay as written, and generic
/// rights are not mapped.
pub fn compute_inherited_aces(parent_dacl: &Acl<'_>, child_is_container: bool) -> Vec<AceBuilder> {
    inherited_aces(parent_dacl, &Child { container: child_is_container, ..Child::default() })
}

/// Where an ACE's SID is in its body, as (offset, length), for a type with
/// a mask first and a SID to rewrite. `None` for any other type, or a body
/// too short for its type.
fn sid_at(ace_type: u8, body: &[u8]) -> Option<(usize, usize)> {
    let start = match ace_type {
        // Mask, SID, and for the callback types and resource attributes,
        // application data.
        0x00..=0x03 | 0x09 | 0x0A | 0x0D | 0x0E | 0x11..=0x14 => 4,
        // Mask, object flags, the GUIDs they say are present, SID, and for
        // the callback types, application data.
        0x05..=0x08 | 0x0B | 0x0C | 0x0F | 0x10 => {
            let flags = u32::from_le_bytes(body.get(4..8)?.try_into().ok()?);
            8 + if flags & 1 != 0 { 16 } else { 0 } + if flags & 2 != 0 { 16 } else { 0 }
        }
        _ => return None,
    };
    let (_, len) = SidRef::parse(body.get(start..)?).ok()?;
    Some((start, len))
}

/// Whether an ACE would change when resolved for `child`: it names a
/// creator SID, or has generic rights and the child has a mapping.
fn resolvable(ace: &crate::security::sddl::codec::AceRef<'_>, child: &Child<'_>) -> bool {
    let Some((at, len)) = sid_at(ace.ace_type, ace.body) else { return false };
    let sid = &ace.body[at..at + len];
    let mask = u32::from_le_bytes([ace.body[0], ace.body[1], ace.body[2], ace.body[3]]);
    sid == CREATOR_OWNER || sid == CREATOR_GROUP || (child.mapping.is_some() && mask & GENERIC_BITS != 0)
}

/// `mask` with its generic rights replaced by what `mapping` says they are.
fn map_mask(mask: u32, mapping: &GenericMapping) -> u32 {
    let mut out = mask & !GENERIC_BITS;
    for (bit, to) in [(GENERIC_READ, mapping.read), (GENERIC_WRITE, mapping.write), (GENERIC_EXECUTE, mapping.execute), (GENERIC_ALL, mapping.all)] {
        if mask & bit != 0 {
            out |= to;
        }
    }
    out
}

/// A copy of `ace` with `flags`, resolved for `child` when one is given:
/// its creator SID replaced and its generic rights mapped. Application data
/// is copied verbatim (PCDS §5.6).
fn copy(ace: &crate::security::sddl::codec::AceRef<'_>, flags: u8, child: Option<&Child<'_>>) -> AceBuilder {
    let verbatim = || AceBuilder::from_ace_ref(ace).flags(flags);
    let (Some(child), Some((at, len))) = (child, sid_at(ace.ace_type, ace.body)) else { return verbatim() };
    let mask = u32::from_le_bytes([ace.body[0], ace.body[1], ace.body[2], ace.body[3]]);
    let mask = child.mapping.as_ref().map_or(mask, |m| map_mask(mask, m));
    let sid = &ace.body[at..at + len];
    let sid = match sid {
        s if s == CREATOR_OWNER => child.owner.unwrap_or(s),
        s if s == CREATOR_GROUP => child.group.unwrap_or(s),
        s => s,
    };
    let mut body = Vec::with_capacity(ace.body.len() + 64);
    body.extend_from_slice(&mask.to_le_bytes());
    body.extend_from_slice(&ace.body[4..at]);
    body.extend_from_slice(sid);
    body.extend_from_slice(&ace.body[at + len..]);
    AceBuilder::raw(ace.ace_type, body).map_or_else(|_| verbatim(), |b| b.flags(flags))
}

/// Re-propagate to a child SD from its parent SD (PCDS §5.6,
/// Re-propagation). For each list `info` selects (`DACL_SECURITY_INFORMATION`,
/// `SACL_SECURITY_INFORMATION`):
///
/// - If the child protects it (`SE_DACL_PROTECTED`, `SE_SACL_PROTECTED`),
///   it is left exactly as it is.
/// - Otherwise the child's inherited ACEs are dropped, its explicit ACEs
///   kept in their order, and what the parent's list passes to it
///   ([`inherited_aces`], resolved against the child's own owner and group
///   and through `mapping`) appended after them, and the list is marked
///   auto-inherited. A parent with no such list passes nothing; a child
///   with no such list gets one only if something is passed to it.
///
/// Lists not selected, the owner and group, and the protection and
/// auto-inherited bits of the child pass through. Both inputs must be
/// self-relative; so is the output.
///
/// # Errors
/// [`Error::Parse`] if either input is malformed or not self-relative.
pub fn reinherit_with(
    parent_sd: &[u8],
    child_sd: &[u8],
    child_is_container: bool,
    mapping: Option<GenericMapping>,
    info: u32,
) -> Result<Vec<u8>> {
    let parent = SecurityDescriptor::parse(parent_sd)?;
    let child = SecurityDescriptor::parse(child_sd)?;
    if child.control & SE_SELF_RELATIVE == 0 {
        return Err(Error::Parse(ParseError::SdNotSelfRelative));
    }
    let owner = verbatim_sid(child_sd, child.owner_off)?;
    let group = verbatim_sid(child_sd, child.group_off)?;
    let facts = Child { container: child_is_container, owner: owner.as_deref(), group: group.as_deref(), mapping };
    let redo_dacl = info & DACL_SECURITY_INFORMATION != 0 && child.control & SE_DACL_PROTECTED == 0;
    let redo_sacl = info & SACL_SECURITY_INFORMATION != 0 && child.control & SE_SACL_PROTECTED == 0;

    let mut out = SdBuilder::new();
    if let Some(owner) = child.owner() {
        out = out.owner(owner);
    }
    if let Some(group) = child.group() {
        out = out.group(group);
    }
    if let Some(sacl) = list(child.sacl(), parent.sacl(), redo_sacl, &facts)? {
        out = out.sacl(sacl);
    }
    if let Some(dacl) = list(child.dacl(), parent.dacl(), redo_dacl, &facts)? {
        out = out.dacl(dacl);
    }
    let mut extra = child.control
        & (SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_SACL_AUTO_INHERITED | SE_SACL_PROTECTED);
    if redo_dacl {
        extra |= SE_DACL_AUTO_INHERITED;
    }
    if redo_sacl {
        extra |= SE_SACL_AUTO_INHERITED;
    }
    out.control(extra).build()
}

/// One of the child's lists as re-propagation leaves it: as it is, or,
/// when `redo`, its explicit ACEs and then what the parent's list passes on.
fn list(
    child: Option<core::result::Result<Acl<'_>, ParseError>>,
    parent: Option<core::result::Result<Acl<'_>, ParseError>>,
    redo: bool,
    facts: &Child<'_>,
) -> Result<Option<AclBuilder>> {
    let child = child.transpose().map_err(Error::Parse)?;
    if !redo {
        let Some(child) = child else { return Ok(None) };
        let mut b = AclBuilder::new();
        for ace in child.aces_iter() {
            b = b.ace(AceBuilder::from_ace_ref(&ace?));
        }
        return Ok(Some(b));
    }
    let passed = match parent.transpose().map_err(Error::Parse)? {
        Some(p) => inherited_aces(&p, facts),
        None => Vec::new(),
    };
    if child.is_none() && passed.is_empty() {
        return Ok(None);
    }
    let mut b = AclBuilder::new();
    if let Some(child) = child {
        for ace in child.aces_iter() {
            let ace = ace?;
            if ace.flags & ACE_FLAG_INHERITED == 0 {
                b = b.ace(AceBuilder::from_ace_ref(&ace));
            }
        }
    }
    for ace in passed {
        b = b.ace(ace);
    }
    Ok(Some(b))
}

/// [`reinherit_with`] for the DACL alone, with no generic mapping: generic
/// rights stay as written.
///
/// # Errors
/// [`Error::Parse`] if either input is malformed or not self-relative.
pub fn reinherit(parent_sd: &[u8], child_sd: &[u8], child_is_container: bool) -> Result<Vec<u8>> {
    reinherit_with(parent_sd, child_sd, child_is_container, None, DACL_SECURITY_INFORMATION)
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

    // ---- re-propagation, as KACS creates ----

    const FILE: GenericMapping = GenericMapping { read: 0x120089, write: 0x120116, execute: 0x1200a0, all: 0x1f01ff };
    const ME: &str = "S-1-5-21-1-2-3-1000";

    fn sd(text: &str) -> Vec<u8> {
        crate::security::sddl::grammar::parse(text).unwrap().build().unwrap()
    }

    fn text(bytes: &[u8]) -> String {
        crate::security::sddl::grammar::format(&SecurityDescriptor::parse(bytes).unwrap()).unwrap()
    }

    /// What a folder made inside the parent gets, and a file: CREATOR OWNER
    /// resolved and carried on, generic rights mapped, NP ending the line.
    #[test]
    fn a_child_gets_what_kacs_gives_one_it_creates() {
        let parent = sd("O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)(A;OICI;GR;;;AU)(A;OICINP;FR;;;S-1-5-21-1-2-3-1001)");
        let folder = sd(&format!("O:{ME}G:AUD:(A;;FA;;;{ME})"));
        let got = text(&reinherit_with(&parent, &folder, true, Some(FILE), DACL_SECURITY_INFORMATION).unwrap());
        assert_eq!(
            got,
            format!(
                "O:{ME}G:AUD:AI(A;;FA;;;{ME})(A;CIOIID;FA;;;BA)(A;ID;FA;;;{ME})(A;CIOIIOID;GA;;;CO)(A;ID;FR;;;AU)(A;CIOIIOID;GR;;;AU)(A;ID;FR;;;S-1-5-21-1-2-3-1001)"
            )
        );
        let file = sd(&format!("O:{ME}G:AUD:"));
        let got = text(&reinherit_with(&parent, &file, false, Some(FILE), DACL_SECURITY_INFORMATION).unwrap());
        assert_eq!(got, format!("O:{ME}G:AUD:AI(A;ID;FA;;;BA)(A;ID;FA;;;{ME})(A;ID;FR;;;AU)(A;ID;FR;;;S-1-5-21-1-2-3-1001)"));
    }

    #[test]
    fn a_grandchild_resolves_the_rule_its_parent_carried_on() {
        let parent = sd("O:BAG:BAD:(A;OICIIOID;GA;;;CO)");
        let child = sd("O:S-1-5-21-1-2-3-1002G:BAD:");
        let got = text(&reinherit_with(&parent, &child, false, Some(FILE), DACL_SECURITY_INFORMATION).unwrap());
        assert_eq!(got, "O:S-1-5-21-1-2-3-1002G:BAD:AI(A;ID;FA;;;S-1-5-21-1-2-3-1002)");
    }

    #[test]
    fn a_protected_list_is_left_and_the_other_redone() {
        let parent = sd("O:BAG:BAD:(A;OICI;FA;;;BA)S:(AU;OICISA;FA;;;WD)");
        let child = sd("O:BAG:BAD:P(A;;FA;;;SY)S:(AU;IDSA;FA;;;AU)");
        let got = text(&reinherit_with(&parent, &child, true, Some(FILE), DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION).unwrap());
        assert_eq!(got, "O:BAG:BAD:P(A;;FA;;;SY)S:AI(AU;CIOIIDSA;FA;;;WD)");
        let child = sd("O:BAG:BAD:(A;;FA;;;SY)S:P(AU;IDSA;FA;;;AU)");
        let got = text(&reinherit_with(&parent, &child, true, Some(FILE), DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION).unwrap());
        assert_eq!(got, "O:BAG:BAD:AI(A;;FA;;;SY)(A;CIOIID;FA;;;BA)S:P(AU;IDSA;FA;;;AU)");
    }

    #[test]
    fn only_the_lists_asked_for_are_redone() {
        let parent = sd("O:BAG:BAD:(A;OICI;FA;;;BA)S:(AU;OICISA;FA;;;WD)");
        let child = sd("O:BAG:BAD:(A;ID;FR;;;AU)S:(AU;IDSA;FA;;;AU)");
        let got = text(&reinherit_with(&parent, &child, false, None, SACL_SECURITY_INFORMATION).unwrap());
        assert_eq!(got, "O:BAG:BAD:(A;ID;FR;;;AU)S:AI(AU;IDSA;FA;;;WD)");
    }
}
