// SDDL — Security Descriptor Definition Language.
//
// Bidirectional translation between MS-DTYP §2.5.1 text form and
// `libp-sd`'s typed shapes.
//
//   parse(s)           — &str → SdBuilder
//   format(sd)         — &SecurityDescriptor → String
//   parse_acl(s,kind)  — &str → ParsedAcl     (fragment-level, "P(...)..." with
//                                              no leading "D:"/"S:" prefix)
//   format_acl(...)    — &Acl + kind + ctrl → String
//   parse_ace(s)       — &str → AceBuilder    (interior of one "(...)" ACE,
//                                              with no enclosing parens)
//   format_ace(&ace)   — &AceRef → String     (emits the enclosing "(...)")
//
// The high-level shape: parse drives `SdBuilder`/`AclBuilder`/`AceBuilder`
// (the same builders the rest of libp-sd uses) and format drives the
// existing zero-copy parse types (`SecurityDescriptor`/`Acl`/`AceRef`).
// SDDL is purely a text representation — no new binary primitives.
//
// Vocabulary is the canonical MS-DTYP set plus the well-known SID
// aliases. Domain-relative aliases (DA/DU/LA/…) are recognised but
// rejected — Peios has no Samba bridge yet, so resolving them would
// require a guess.

#![allow(clippy::module_inception)]

extern crate alloc;

mod cond;
mod vocab;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::security::sddl::codec::{
    ACE_FLAG_INHERITED, ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT,
    ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
    ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT, ACE_TYPE_ACCESS_ALLOWED_OBJECT,
    ACE_TYPE_ACCESS_DENIED, ACE_TYPE_ACCESS_DENIED_CALLBACK,
    ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT, ACE_TYPE_ACCESS_DENIED_OBJECT, ACE_TYPE_SYSTEM_AUDIT,
    ACE_TYPE_SYSTEM_AUDIT_CALLBACK, ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT,
    ACE_TYPE_SYSTEM_AUDIT_OBJECT, ACE_TYPE_SYSTEM_MANDATORY_LABEL,
    ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE, AceRef, Acl, SE_DACL_AUTO_INHERITED, SE_DACL_PRESENT,
    SE_DACL_PROTECTED, SE_SACL_AUTO_INHERITED, SE_SACL_PRESENT, SE_SACL_PROTECTED,
    SecurityDescriptor,
};
use crate::security::sddl::wire::{Sid, SidRef};

use crate::security::sddl::build::{AceBuilder, AclBuilder, SdBuilder};
use crate::security::sddl::claims::{ClaimAttribute, ClaimValue};
use crate::security::sddl::condition::Condition;

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Which kind of ACL is being parsed/formatted — affects which control
/// bits the `P`/`AR`/`AI` flag-prefixes resolve to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclKind {
    /// Discretionary ACL — flags map to `SE_DACL_PROTECTED` /
    /// `SE_DACL_AUTO_INHERIT_REQ` / `SE_DACL_AUTO_INHERITED`.
    Dacl,
    /// System ACL — flags map to the matching `SE_SACL_*` bits.
    Sacl,
}

/// The result of [`parse_acl`] — an `AclBuilder` plus the SD control-word
/// bits the ACL's flag-prefix (`P`/`AR`/`AI`) implies.
#[derive(Debug, Clone)]
pub struct ParsedAcl {
    /// The built-up ACL.
    pub acl: AclBuilder,
    /// Bits to OR into the SD's control word — `SE_DACL_PROTECTED`,
    /// `SE_DACL_AUTO_INHERITED`, etc., depending on `AclKind`. Always
    /// includes the matching `SE_*_PRESENT` bit if the section was given
    /// at all.
    pub control: u16,
}

// SE_DACL_AUTO_INHERIT_REQ / SE_SACL_AUTO_INHERIT_REQ are not exported
// by peios-uapi (the public re-exports skip them). Define locally —
// MS-DTYP §2.4.6 fixes these bits.
const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;

/// Errors produced by the SDDL parser / formatter.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SddlError {
    /// Input was empty or contained no recognisable section.
    Empty,
    /// Two sections of the same kind were present (e.g. two `D:`).
    DuplicateSection(char),
    /// Unknown / unsupported leading character at the start of a section
    /// (anything outside `OGDS`).
    UnknownSection(usize),
    /// An ACE / ACL flag code wasn't recognised. Carries the offending
    /// two-character code.
    UnknownFlag(String),
    /// An ACE type code wasn't recognised.
    UnknownAceType(String),
    /// An access-right code wasn't recognised.
    UnknownRight(String),
    /// An ACE didn't have 6 or 7 semicolon-delimited fields.
    WrongFieldCount(usize),
    /// A SID alias or `S-1-…` literal didn't resolve.
    BadSid(String),
    /// A two-letter alias refers to a domain-relative SID; resolving it
    /// needs a domain SID prefix Peios does not yet have.
    DomainRelativeAlias(String),
    /// A GUID field couldn't be parsed.
    BadGuid(String),
    /// A hex literal couldn't be parsed.
    BadHex(String),
    /// The 7th (payload) field was given on an ACE type that doesn't
    /// accept one.
    UnexpectedPayload(String),
    /// The 7th (payload) field is required for this ACE type but was
    /// missing.
    MissingPayload(String),
    /// Object-ACE fields (ObjectType / InheritedObjectType GUIDs) were
    /// given on a non-object ACE type.
    ObjectFieldsOnNonObjectAce(String),
    /// A conditional-expression payload could not be parsed.
    BadCondition(String),
    /// A resource-attribute claim payload could not be parsed.
    BadClaim(String),
    /// Input ended where more was expected.
    UnexpectedEof(&'static str),
    /// Generic parse failure with a static hint.
    Malformed(&'static str),
    /// A binary input passed to the formatter could not be walked
    /// (truncated, unknown ACE shape, …).
    Format(&'static str),
}

/// Result alias for SDDL operations.
pub type Result<T> = core::result::Result<T, SddlError>;

impl core::fmt::Display for SddlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SddlError::Empty => write!(f, "empty SDDL input"),
            SddlError::DuplicateSection(c) => write!(f, "duplicate section: {c}:"),
            SddlError::UnknownSection(n) => write!(f, "unknown section prefix at byte {n}"),
            SddlError::UnknownFlag(s) => write!(f, "unknown flag code {s:?}"),
            SddlError::UnknownAceType(s) => write!(f, "unknown ACE type code {s:?}"),
            SddlError::UnknownRight(s) => write!(f, "unknown access-right code {s:?}"),
            SddlError::WrongFieldCount(n) => write!(f, "ACE has {n} fields, expected 6 or 7"),
            SddlError::BadSid(s) => write!(f, "invalid SID {s:?}"),
            SddlError::DomainRelativeAlias(s) => write!(
                f,
                "domain-relative SID alias {s:?} cannot be resolved without a domain SID"
            ),
            SddlError::BadGuid(s) => write!(f, "invalid GUID {s:?}"),
            SddlError::BadHex(s) => write!(f, "invalid hex literal {s:?}"),
            SddlError::UnexpectedPayload(s) => {
                write!(f, "ACE type {s:?} does not accept a trailing payload field")
            }
            SddlError::MissingPayload(s) => {
                write!(f, "ACE type {s:?} requires a trailing payload field")
            }
            SddlError::ObjectFieldsOnNonObjectAce(s) => write!(
                f,
                "ACE type {s:?} is not an object-ACE but has object/inherited-object GUIDs"
            ),
            SddlError::BadCondition(s) => write!(f, "conditional expression: {s}"),
            SddlError::BadClaim(s) => write!(f, "resource-attribute claim: {s}"),
            SddlError::UnexpectedEof(s) => write!(f, "unexpected end of input: {s}"),
            SddlError::Malformed(s) => write!(f, "malformed SDDL: {s}"),
            SddlError::Format(s) => write!(f, "cannot format: {s}"),
        }
    }
}

impl core::error::Error for SddlError {}

// ---------------------------------------------------------------------------
// Top-level parse / format
// ---------------------------------------------------------------------------

/// Parse a full SDDL string into an [`SdBuilder`]. Call `.build()` on the
/// result to get the self-relative wire bytes.
///
/// Recognised sections, in any order: `O:` (owner), `G:` (group),
/// `D:` (DACL), `S:` (SACL). Whitespace is **not** stripped — SDDL is a
/// dense format and unexpected whitespace usually means an authoring
/// bug.
pub fn parse(s: &str) -> Result<SdBuilder> {
    if s.is_empty() {
        return Err(SddlError::Empty);
    }
    let sections = split_sections(s)?;
    if sections.is_empty() {
        return Err(SddlError::Empty);
    }

    let mut builder = SdBuilder::new();
    let mut extra_control: u16 = 0;
    for (kind, body) in &sections {
        match kind {
            'O' => {
                let sid = parse_sid_ref(body)?;
                builder = builder.owner(sid);
            }
            'G' => {
                let sid = parse_sid_ref(body)?;
                builder = builder.group(sid);
            }
            'D' => {
                let parsed = parse_acl(body, AclKind::Dacl)?;
                builder = builder.dacl(parsed.acl);
                // SE_DACL_PRESENT comes free from `.dacl(...)`; only the
                // P/AR/AI bits need to ride through `.control()`.
                extra_control |= parsed.control & !(SE_DACL_PRESENT);
            }
            'S' => {
                let parsed = parse_acl(body, AclKind::Sacl)?;
                builder = builder.sacl(parsed.acl);
                extra_control |= parsed.control & !(SE_SACL_PRESENT);
            }
            _ => unreachable!("split_sections only yields OGDS"),
        }
    }
    if extra_control != 0 {
        builder = builder.control(extra_control);
    }
    Ok(builder)
}

/// Format a parsed self-relative SECURITY_DESCRIPTOR as an SDDL string.
///
/// Sections are emitted in canonical order — `O`, `G`, `D`, `S` — and
/// elided when absent (owner offset 0, etc.). An SD with
/// `SE_DACL_PRESENT` set but no DACL bytes (NULL DACL) emits a bare
/// `D:` exactly as Windows does.
pub fn format(sd: &SecurityDescriptor<'_>) -> Result<String> {
    let mut out = String::new();
    if let Some(owner) = sd.owner_ref() {
        out.push_str("O:");
        out.push_str(&format_sid(&owner.to_owned()));
    }
    if let Some(group) = sd.group_ref() {
        out.push_str("G:");
        out.push_str(&format_sid(&group.to_owned()));
    }
    if sd.control & SE_DACL_PRESENT != 0 {
        out.push_str("D:");
        let acl_opt = sd
            .dacl()
            .transpose()
            .map_err(|_| SddlError::Format("DACL did not parse"))?;
        out.push_str(&format_acl_body(
            acl_opt.as_ref(),
            AclKind::Dacl,
            sd.control,
        )?);
    }
    if sd.control & SE_SACL_PRESENT != 0 {
        out.push_str("S:");
        let acl_opt = sd
            .sacl()
            .transpose()
            .map_err(|_| SddlError::Format("SACL did not parse"))?;
        out.push_str(&format_acl_body(
            acl_opt.as_ref(),
            AclKind::Sacl,
            sd.control,
        )?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Fragment-level: parse_acl / format_acl
// ---------------------------------------------------------------------------

/// Parse an ACL fragment — the contents of a `D:` or `S:` section, with
/// no leading prefix. Input shape: `<flags><(ACE)>*` where flags is any
/// concatenation of `P`, `AR`, `AI`.
pub fn parse_acl(s: &str, kind: AclKind) -> Result<ParsedAcl> {
    let (flag_bits, mut rest) = parse_acl_flag_prefix(s, kind)?;
    let mut acl = AclBuilder::new();
    while !rest.is_empty() {
        let (body, after) = take_paren_group(rest)?;
        let ace = parse_ace(body)?;
        acl = acl.ace(ace);
        rest = after;
    }
    let mut control = flag_bits;
    control |= match kind {
        AclKind::Dacl => SE_DACL_PRESENT,
        AclKind::Sacl => SE_SACL_PRESENT,
    };
    Ok(ParsedAcl { acl, control })
}

/// Format an ACL fragment (the contents of a `D:` or `S:` section).
/// `acl` is `None` for a NULL ACL — emits flag-prefix only (e.g. `P` or
/// the empty string).
pub fn format_acl(acl: Option<&Acl<'_>>, kind: AclKind, control: u16) -> Result<String> {
    format_acl_body(acl, kind, control)
}

// ---------------------------------------------------------------------------
// ACE-level: parse_ace / format_ace
// ---------------------------------------------------------------------------

/// Parse a single ACE — the interior of one `(...)` group, *without* the
/// outer parentheses.
///
/// Accepts both the 6-field shape (`type;flags;rights;objguid;inhguid;sid`)
/// and the 7-field shape (`...;sid;payload`) where `payload` is the
/// parenthesised conditional expression (callback ACEs) or the
/// parenthesised resource-attribute claim (`RA`).
/// Parse an SDDL conditional expression (e.g. `@User.Title == "Director"`).
/// Accepts both bare expressions and expressions wrapped in one outer
/// pair of parentheses. The returned `Condition` is the typed AST used
/// by [`AceBuilder::allow_callback`] / `deny_callback` / `audit_callback`.
pub fn parse_condition(s: &str) -> Result<Condition> {
    cond::parse(s).map_err(|e| SddlError::BadCondition(e.to_string()))
}

/// Format a [`Condition`] as canonical SDDL conditional-expression text
/// (no outer parens).
pub fn format_condition(c: &Condition) -> String {
    cond::format(c)
}

/// Parse an SDDL conditional expression directly to its `"artx"` callback-ACE
/// bytecode (the form embedded in a conditional ACE's application data).
pub fn parse_condition_to_artx(s: &str) -> Result<alloc::vec::Vec<u8>> {
    parse_condition(s).map(|c| c.encode())
}

/// Render `"artx"` callback-ACE bytecode back to canonical SDDL
/// conditional-expression text (no outer parens).
pub fn format_condition_from_artx(artx: &[u8]) -> Result<String> {
    let c = cond::decode_artx(artx).map_err(|e| SddlError::BadCondition(e.to_string()))?;
    Ok(cond::format(&c))
}

pub fn parse_ace(s: &str) -> Result<AceBuilder> {
    let fields = split_ace_fields(s);
    let (type_str, flag_str, rights_str, obj_str, inh_str, sid_str, payload) = match fields.len() {
        6 => (
            fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], None,
        ),
        7 => (
            fields[0],
            fields[1],
            fields[2],
            fields[3],
            fields[4],
            fields[5],
            Some(fields[6]),
        ),
        n => return Err(SddlError::WrongFieldCount(n)),
    };

    let type_upper = ascii_upper(type_str);
    let ace_type = vocab::ace_type_from_code(&type_upper)
        .ok_or_else(|| SddlError::UnknownAceType(type_upper.clone()))?;

    let flags = parse_ace_flags(flag_str)?;
    let mask = parse_rights(rights_str)?;

    let object_type = parse_optional_guid(obj_str)?;
    let inherited_object_type = parse_optional_guid(inh_str)?;
    if (object_type.is_some() || inherited_object_type.is_some()) && !is_object_ace(ace_type) {
        return Err(SddlError::ObjectFieldsOnNonObjectAce(type_upper));
    }

    // Resource-attribute ACE: SID slot is fixed to Everyone and ignored;
    // payload carries the claim.
    if ace_type == ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE {
        let payload = payload.ok_or_else(|| SddlError::MissingPayload(type_upper.clone()))?;
        let claim = parse_claim(payload)?;
        let builder = AceBuilder::resource_attribute(&claim).map_err(map_encode)?;
        return Ok(builder.flags(flags));
    }

    let sid = parse_sid_ref(sid_str)?;

    // Dispatch on the ACE category. Order matters: callback types
    // share the mask+SID prefix with simple types, so they must be
    // matched before the simple-mask-SID arm.
    let builder = match ace_type {
        // Conditional (callback) ACEs — must come before the simple
        // mask+SID branch, since they also pass `ace_type_is_simple_mask_sid`.
        ACE_TYPE_ACCESS_ALLOWED_CALLBACK
        | ACE_TYPE_ACCESS_DENIED_CALLBACK
        | ACE_TYPE_SYSTEM_AUDIT_CALLBACK
        | ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT
        | ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT
        | ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT => {
            let payload = payload.ok_or_else(|| SddlError::MissingPayload(type_upper.clone()))?;
            let condition =
                cond::parse(payload).map_err(|e| SddlError::BadCondition(e.to_string()))?;
            match ace_type {
                ACE_TYPE_ACCESS_ALLOWED_CALLBACK => {
                    AceBuilder::allow_callback(sid, mask, &condition).map_err(map_encode)?
                }
                ACE_TYPE_ACCESS_DENIED_CALLBACK => {
                    AceBuilder::deny_callback(sid, mask, &condition).map_err(map_encode)?
                }
                ACE_TYPE_SYSTEM_AUDIT_CALLBACK => {
                    AceBuilder::audit_callback(sid, mask, &condition).map_err(map_encode)?
                }
                ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT => AceBuilder::allow_callback_object(
                    sid,
                    mask,
                    object_type,
                    inherited_object_type,
                    &condition,
                )
                .map_err(map_encode)?,
                ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT => AceBuilder::deny_callback_object(
                    sid,
                    mask,
                    object_type,
                    inherited_object_type,
                    &condition,
                )
                .map_err(map_encode)?,
                ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT => AceBuilder::audit_callback_object(
                    sid,
                    mask,
                    object_type,
                    inherited_object_type,
                    &condition,
                )
                .map_err(map_encode)?,
                _ => unreachable!(),
            }
        }

        // Plain object ACE (no callback).
        ACE_TYPE_ACCESS_ALLOWED_OBJECT => {
            if payload.is_some() {
                return Err(SddlError::UnexpectedPayload(type_upper));
            }
            AceBuilder::allow_object(sid, mask, object_type, inherited_object_type)
        }
        ACE_TYPE_ACCESS_DENIED_OBJECT => {
            if payload.is_some() {
                return Err(SddlError::UnexpectedPayload(type_upper));
            }
            AceBuilder::deny_object(sid, mask, object_type, inherited_object_type)
        }
        ACE_TYPE_SYSTEM_AUDIT_OBJECT => {
            if payload.is_some() {
                return Err(SddlError::UnexpectedPayload(type_upper));
            }
            AceBuilder::audit_object(sid, mask, object_type, inherited_object_type)
        }

        // Simple mask + SID.
        ACE_TYPE_ACCESS_ALLOWED => AceBuilder::allow(sid, mask),
        ACE_TYPE_ACCESS_DENIED => AceBuilder::deny(sid, mask),
        ACE_TYPE_SYSTEM_AUDIT => AceBuilder::audit(sid, mask),
        ACE_TYPE_SYSTEM_MANDATORY_LABEL => AceBuilder::mandatory_label(sid, mask),

        // Other simple mask+sid ACEs (scoped-policy-id, alarm variants).
        // Synthesise the body verbatim — no typed constructor exists.
        t => {
            let mut body = Vec::with_capacity(4 + sid.encoded_len());
            body.extend_from_slice(&mask.to_le_bytes());
            body.extend_from_slice(&sid.encode());
            AceBuilder::raw(t, body).map_err(map_encode)?
        }
    };

    Ok(builder.flags(flags))
}

/// Format a single ACE as an SDDL `(...)` group, including the outer
/// parentheses.
pub fn format_ace(ace: &AceRef<'_>) -> Result<String> {
    let type_code =
        vocab::ace_code_from_type(ace.ace_type).ok_or(SddlError::Format("unknown ACE type"))?;

    let mut out = String::new();
    out.push('(');
    out.push_str(type_code);
    out.push(';');
    out.push_str(&format_ace_flags(ace.flags));
    out.push(';');

    // Pull mask + remaining-body slice based on shape.
    let (mask, object_type, inherited_object_type, sid_and_tail) = decode_ace_body(ace)?;
    out.push_str(&format_rights_for_type(mask, ace.ace_type));
    out.push(';');
    if let Some(g) = object_type {
        out.push_str(&format_guid(&g));
    }
    out.push(';');
    if let Some(g) = inherited_object_type {
        out.push_str(&format_guid(&g));
    }
    out.push(';');

    // The "sid_and_tail" is the byte tail starting at the SID; for
    // resource-attribute ACEs the SID is Everyone and the tail carries
    // the §3.9 claim entry.
    match ace.ace_type {
        ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE => {
            // Body: u32 reserved mask, Sid (Everyone), §3.9 claim entry.
            let (sid, used) = SidRef::parse(sid_and_tail)
                .map_err(|_| SddlError::Format("resource-attribute ACE: SID did not parse"))?;
            out.push_str(&format_sid(&sid.to_owned()));
            out.push(';');
            let claim_bytes = &sid_and_tail[used..];
            out.push_str(&format_claim_payload(claim_bytes)?);
        }
        t if is_callback_ace(t) => {
            let (sid, used) = SidRef::parse(sid_and_tail)
                .map_err(|_| SddlError::Format("callback ACE: SID did not parse"))?;
            out.push_str(&format_sid(&sid.to_owned()));
            out.push(';');
            let cond_bytes = &sid_and_tail[used..];
            let cond = cond::decode_artx(cond_bytes)
                .map_err(|_| SddlError::Format("callback ACE: condition did not decode"))?;
            out.push('(');
            out.push_str(&cond::format(&cond));
            out.push(')');
        }
        _ => {
            let (sid, _) = SidRef::parse(sid_and_tail)
                .map_err(|_| SddlError::Format("ACE: SID did not parse"))?;
            out.push_str(&format_sid(&sid.to_owned()));
        }
    }
    out.push(')');
    Ok(out)
}

// ---------------------------------------------------------------------------
// Helpers (private)
// ---------------------------------------------------------------------------

fn map_encode(err: crate::security::sddl::Error) -> SddlError {
    match err {
        crate::security::sddl::Error::Encode(msg) => SddlError::Malformed(msg),
        _ => SddlError::Malformed("builder rejected input"),
    }
}

fn ascii_upper(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(c.to_ascii_uppercase());
    }
    out
}

/// Walk `s` once at depth 0 (counting `(`/`)` nesting), collecting each
/// `<X>:` where X ∈ {O,G,D,S}, with its body as a slice up to the next
/// section start. Duplicate sections are rejected.
fn split_sections(s: &str) -> Result<Vec<(char, &str)>> {
    let bytes = s.as_bytes();
    let mut starts: Vec<(char, usize)> = Vec::new();
    let mut depth = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
            }
            _ if depth == 0 && i + 1 < bytes.len() && bytes[i + 1] == b':' => {
                let c = (b as char).to_ascii_uppercase();
                if matches!(c, 'O' | 'G' | 'D' | 'S') {
                    starts.push((c, i + 2));
                    i += 2;
                    continue;
                } else {
                    return Err(SddlError::UnknownSection(i));
                }
            }
            _ => {}
        }
        i += 1;
    }

    let mut out: Vec<(char, &str)> = Vec::with_capacity(starts.len());
    for (idx, &(c, start)) in starts.iter().enumerate() {
        // Reject duplicates.
        if out.iter().any(|(k, _)| *k == c) {
            return Err(SddlError::DuplicateSection(c));
        }
        let end = if idx + 1 < starts.len() {
            starts[idx + 1].1 - 2 // back up past "X:"
        } else {
            s.len()
        };
        out.push((c, &s[start..end]));
    }
    Ok(out)
}

/// Parse the leading flag-prefix of an ACL body (`P`, `AR`, `AI` in any
/// order) and return the implied control bits + the remainder of the
/// input (pointing at the first `(` or empty).
fn parse_acl_flag_prefix(s: &str, kind: AclKind) -> Result<(u16, &str)> {
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut bits: u16 = 0;
    while i < bytes.len() && bytes[i] != b'(' {
        let two = if i + 2 <= bytes.len() {
            ascii_upper(&s[i..i + 2])
        } else {
            String::new()
        };
        if two == "AR" {
            bits |= match kind {
                AclKind::Dacl => SE_DACL_AUTO_INHERIT_REQ,
                AclKind::Sacl => SE_SACL_AUTO_INHERIT_REQ,
            };
            i += 2;
            continue;
        }
        if two == "AI" {
            bits |= match kind {
                AclKind::Dacl => SE_DACL_AUTO_INHERITED,
                AclKind::Sacl => SE_SACL_AUTO_INHERITED,
            };
            i += 2;
            continue;
        }
        let one = (bytes[i] as char).to_ascii_uppercase();
        if one == 'P' {
            bits |= match kind {
                AclKind::Dacl => SE_DACL_PROTECTED,
                AclKind::Sacl => SE_SACL_PROTECTED,
            };
            i += 1;
            continue;
        }
        // Anything else is an unknown flag code.
        let len = if i + 2 <= bytes.len() { 2 } else { 1 };
        return Err(SddlError::UnknownFlag(s[i..i + len].to_string()));
    }
    Ok((bits, &s[i..]))
}

/// Take one balanced `(...)` group at the start of `s`. Returns the
/// inner body (without the parens) and the remainder after the closing
/// paren.
fn take_paren_group(s: &str) -> Result<(&str, &str)> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes[0] != b'(' {
        return Err(SddlError::Malformed("expected '(' at start of ACE"));
    }
    let mut depth: usize = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&s[1..i], &s[i + 1..]));
                }
            }
            _ => {}
        }
    }
    Err(SddlError::UnexpectedEof("unterminated '(' group"))
}

/// Split an ACE interior (with no outer parens) into its 6 or 7 fields.
/// Splits on `;` at paren-depth 0 only; quoted strings inside a payload
/// don't appear before the 7th field, so quote-tracking is unnecessary
/// for fields 1–6.
fn split_ace_fields(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut fields: Vec<&str> = Vec::with_capacity(7);
    let mut start = 0usize;
    let mut depth: usize = 0;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth = depth.saturating_sub(1);
            }
            b';' if depth == 0 => {
                fields.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    fields.push(&s[start..]);
    fields
}

fn parse_ace_flags(s: &str) -> Result<u8> {
    if s.is_empty() {
        return Ok(0);
    }
    let mut flags = 0u8;
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if i + 2 > bytes.len() {
            return Err(SddlError::UnknownFlag(s[i..].to_string()));
        }
        let code = ascii_upper(&s[i..i + 2]);
        let f = vocab::ace_flag_from_code(&code).ok_or(SddlError::UnknownFlag(code))?;
        flags |= f;
        i += 2;
    }
    Ok(flags)
}

fn parse_rights(s: &str) -> Result<u32> {
    if s.is_empty() {
        return Ok(0);
    }
    let bytes = s.as_bytes();
    let mut mask = 0u32;
    let mut i = 0usize;
    while i < bytes.len() {
        // Hex literal — consumes to end of field.
        if i + 2 <= bytes.len()
            && bytes[i] == b'0'
            && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
        {
            let hex = &s[i + 2..];
            mask |= u32::from_str_radix(hex, 16).map_err(|_| SddlError::BadHex(hex.to_string()))?;
            break;
        }
        if i + 2 > bytes.len() {
            return Err(SddlError::UnknownRight(s[i..].to_string()));
        }
        let code = ascii_upper(&s[i..i + 2]);
        let v = vocab::right_from_code(&code).ok_or(SddlError::UnknownRight(code))?;
        mask |= v;
        i += 2;
    }
    Ok(mask)
}

fn parse_optional_guid(s: &str) -> Result<Option<[u8; 16]>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    parse_guid(trimmed).map(Some)
}

/// Parse a GUID in the canonical `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`
/// text form into 16 raw bytes — the byte layout matches MS-DTYP §2.3.4
/// (little-endian Data1/2/3, big-endian Data4).
fn parse_guid(s: &str) -> Result<[u8; 16]> {
    let bytes = s.as_bytes();
    if bytes.len() != 36
        || bytes[8] != b'-'
        || bytes[13] != b'-'
        || bytes[18] != b'-'
        || bytes[23] != b'-'
    {
        return Err(SddlError::BadGuid(s.to_string()));
    }
    let mut out = [0u8; 16];
    // Data1 (4 bytes, LE)
    let d1 = u32::from_str_radix(&s[0..8], 16).map_err(|_| SddlError::BadGuid(s.to_string()))?;
    out[0..4].copy_from_slice(&d1.to_le_bytes());
    // Data2 (2 bytes, LE)
    let d2 = u16::from_str_radix(&s[9..13], 16).map_err(|_| SddlError::BadGuid(s.to_string()))?;
    out[4..6].copy_from_slice(&d2.to_le_bytes());
    // Data3 (2 bytes, LE)
    let d3 = u16::from_str_radix(&s[14..18], 16).map_err(|_| SddlError::BadGuid(s.to_string()))?;
    out[6..8].copy_from_slice(&d3.to_le_bytes());
    // Data4 (8 bytes, BE) — two hex pairs then six pairs.
    parse_hex_byte_pairs(&s[19..23], &mut out[8..10])?;
    parse_hex_byte_pairs(&s[24..36], &mut out[10..16])?;
    Ok(out)
}

fn parse_hex_byte_pairs(hex: &str, dst: &mut [u8]) -> Result<()> {
    if hex.len() != dst.len() * 2 {
        return Err(SddlError::BadGuid(hex.to_string()));
    }
    for (i, dst_byte) in dst.iter_mut().enumerate() {
        *dst_byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| SddlError::BadGuid(hex.to_string()))?;
    }
    Ok(())
}

/// Parse a SID reference into an owned [`Sid`].
///
/// Accepts either a two-letter well-known SDDL alias (`BA`, `SY`, `WD`,
/// `AU`, `BU`, `LW`, `ME`, `MP`, `HI`, `SI`, …) or a raw
/// `S-1-AUTH-SUB…` literal (authority and sub-authorities in decimal or
/// `0x…` hex). Leading/trailing whitespace is trimmed; alias matching
/// is ASCII-case-insensitive.
///
/// Domain-relative aliases (`DA`, `DU`, `LA`, …) are recognised but
/// rejected with [`SddlError::DomainRelativeAlias`] — resolving them
/// needs a domain SID prefix Peios does not yet have.
///
/// # Errors
/// [`SddlError::BadSid`] for empty input or an unrecognised / malformed
/// reference; [`SddlError::DomainRelativeAlias`] for a domain-relative
/// alias.
pub fn parse_sid(s: &str) -> Result<Sid> {
    parse_sid_ref(s)
}

/// Resolve a SID reference — either a two-letter SDDL alias (`BA`,
/// `WD`, …) or a raw `S-1-…` string.
fn parse_sid_ref(s: &str) -> Result<Sid> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(SddlError::BadSid(String::new()));
    }
    let upper = ascii_upper(trimmed);
    if upper.len() == 2 {
        if vocab::is_domain_relative_alias(&upper) {
            return Err(SddlError::DomainRelativeAlias(upper));
        }
        if let Some(sid) = vocab::sid_from_alias(&upper) {
            return Ok(sid);
        }
        // Two-char but not a known alias — fall through to S- check.
    }
    if upper.starts_with("S-") {
        return parse_sid_literal(&upper);
    }
    Err(SddlError::BadSid(trimmed.to_string()))
}

/// Parse an `S-1-AUTH-SUB1-SUB2-…` string into a [`Sid`]. Authority and
/// sub-authorities accept decimal or `0x…` hex.
fn parse_sid_literal(s: &str) -> Result<Sid> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() < 3 || parts[0] != "S" {
        return Err(SddlError::BadSid(s.to_string()));
    }
    let revision = parse_uint::<u8>(parts[1]).ok_or_else(|| SddlError::BadSid(s.to_string()))?;
    let authority = parse_uint::<u64>(parts[2]).ok_or_else(|| SddlError::BadSid(s.to_string()))?;
    let mut subs = Vec::with_capacity(parts.len() - 3);
    for p in &parts[3..] {
        subs.push(parse_uint::<u32>(p).ok_or_else(|| SddlError::BadSid(s.to_string()))?);
    }
    Ok(Sid::new(revision, authority, subs))
}

fn parse_uint<T: FromRadix>(s: &str) -> Option<T> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        T::from_radix(hex, 16)
    } else {
        T::from_radix(s, 10)
    }
}

trait FromRadix: Sized {
    fn from_radix(s: &str, radix: u32) -> Option<Self>;
}
impl FromRadix for u8 {
    fn from_radix(s: &str, r: u32) -> Option<u8> {
        u8::from_str_radix(s, r).ok()
    }
}
impl FromRadix for u32 {
    fn from_radix(s: &str, r: u32) -> Option<u32> {
        u32::from_str_radix(s, r).ok()
    }
}
impl FromRadix for u64 {
    fn from_radix(s: &str, r: u32) -> Option<u64> {
        u64::from_str_radix(s, r).ok()
    }
}

// ---------------------------------------------------------------------------
// Format-side helpers
// ---------------------------------------------------------------------------

fn is_object_ace(t: u8) -> bool {
    matches!(
        t,
        ACE_TYPE_ACCESS_ALLOWED_OBJECT
            | ACE_TYPE_ACCESS_DENIED_OBJECT
            | ACE_TYPE_SYSTEM_AUDIT_OBJECT
            | ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT
            | ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT
            | ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT
    )
}

fn is_callback_ace(t: u8) -> bool {
    matches!(
        t,
        ACE_TYPE_ACCESS_ALLOWED_CALLBACK
            | ACE_TYPE_ACCESS_DENIED_CALLBACK
            | ACE_TYPE_SYSTEM_AUDIT_CALLBACK
            | ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT
            | ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT
            | ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT
    )
}

/// `(mask, ObjectType GUID, InheritedObjectType GUID, bytes from the SID
/// onward)` — the shape decode_ace_body returns.
type DecodedAceBody<'a> = (u32, Option<[u8; 16]>, Option<[u8; 16]>, &'a [u8]);

/// Pull `(mask, object_type, inherited_object_type, sid_and_tail)` out
/// of an ACE body, handling all shape variants (simple, object,
/// callback, callback object, mandatory-label, scoped-policy-id,
/// resource-attribute).
fn decode_ace_body<'a>(ace: &AceRef<'a>) -> Result<DecodedAceBody<'a>> {
    if is_object_ace(ace.ace_type) {
        if ace.body.len() < 8 {
            return Err(SddlError::Format("object ACE body truncated"));
        }
        let mask = u32::from_le_bytes([ace.body[0], ace.body[1], ace.body[2], ace.body[3]]);
        let flags = u32::from_le_bytes([ace.body[4], ace.body[5], ace.body[6], ace.body[7]]);
        let mut off = 8usize;
        let object_type = if flags & ACE_OBJECT_TYPE_PRESENT != 0 {
            let g = ace
                .body
                .get(off..off + 16)
                .ok_or(SddlError::Format("object ACE: ObjectType truncated"))?;
            off += 16;
            Some(g.try_into().unwrap())
        } else {
            None
        };
        let inherited_object_type = if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
            let g = ace.body.get(off..off + 16).ok_or(SddlError::Format(
                "object ACE: InheritedObjectType truncated",
            ))?;
            off += 16;
            Some(g.try_into().unwrap())
        } else {
            None
        };
        return Ok((mask, object_type, inherited_object_type, &ace.body[off..]));
    }

    // All non-object ACE bodies we emit start with a u32 mask + SID,
    // optionally with a trailing payload.
    if ace.body.len() < 4 {
        return Err(SddlError::Format("ACE body too short for mask"));
    }
    let mask = u32::from_le_bytes([ace.body[0], ace.body[1], ace.body[2], ace.body[3]]);
    Ok((mask, None, None, &ace.body[4..]))
}

fn format_acl_body(acl: Option<&Acl<'_>>, kind: AclKind, control: u16) -> Result<String> {
    let mut out = String::new();
    // Flag prefix.
    let (protected, ar, ai) = match kind {
        AclKind::Dacl => (
            control & SE_DACL_PROTECTED != 0,
            control & SE_DACL_AUTO_INHERIT_REQ != 0,
            control & SE_DACL_AUTO_INHERITED != 0,
        ),
        AclKind::Sacl => (
            control & SE_SACL_PROTECTED != 0,
            control & SE_SACL_AUTO_INHERIT_REQ != 0,
            control & SE_SACL_AUTO_INHERITED != 0,
        ),
    };
    if protected {
        out.push('P');
    }
    if ar {
        out.push_str("AR");
    }
    if ai {
        out.push_str("AI");
    }
    let Some(acl) = acl else {
        return Ok(out);
    };
    for ace_res in acl.aces_iter() {
        let ace = ace_res.map_err(|_| SddlError::Format("ACE did not parse"))?;
        // Skip ACEs whose type we can't represent — emitting a partial
        // string would silently corrupt meaning.
        if vocab::ace_code_from_type(ace.ace_type).is_none() {
            continue;
        }
        out.push_str(&format_ace(&ace)?);
    }
    Ok(out)
}

fn format_sid(sid: &Sid) -> String {
    if let Some(alias) = vocab::alias_from_sid(sid) {
        alias.to_string()
    } else {
        sid.to_string()
    }
}

fn format_ace_flags(flags: u8) -> String {
    let mut out = String::new();
    for (code, bit) in vocab::ace_flag_format_order() {
        if flags & bit != 0 {
            out.push_str(code);
        }
    }
    // Stray bits get appended as a hex tail — keep round-trip fidelity
    // for the ACE_FLAG_INHERITED bit even though it can't be authored
    // from text. (Inherited bit *is* in our vocab so this is a no-op for
    // it; this catches unknown future flags.)
    let consumed: u8 = vocab::ace_flag_format_order()
        .iter()
        .filter_map(|(_, b)| if flags & *b != 0 { Some(*b) } else { None })
        .fold(0u8, |acc, b| acc | b);
    let _ = ACE_FLAG_INHERITED; // referenced for clarity
    let residue = flags & !consumed;
    if residue != 0 {
        out.push_str(&format!("0x{residue:x}"));
    }
    out
}

/// Format an access-mask, picking the right vocab for the ACE type.
/// Mandatory-label ACEs (`ML`) use the NW/NR/NX policy-bit vocab;
/// everything else uses the standard composites/generic/standard set.
fn format_rights_for_type(mask: u32, ace_type: u8) -> String {
    if mask == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut remaining = mask;
    if ace_type == ACE_TYPE_SYSTEM_MANDATORY_LABEL {
        // Mandatory-label vocab: NW=1, NR=2, NX=4. These bit positions
        // collide with directory-object codes, hence the type-gated path.
        for (code, value) in &[("NW", 0x1u32), ("NR", 0x2u32), ("NX", 0x4u32)] {
            if remaining & *value == *value {
                out.push_str(code);
                remaining &= !value;
            }
        }
    } else {
        for (code, value) in vocab::rights_format_order() {
            if remaining & *value == *value {
                out.push_str(code);
                remaining &= !value;
            }
        }
    }
    if remaining != 0 {
        out.push_str(&format!("0x{remaining:x}"));
    }
    out
}

/// Format a GUID in canonical `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`
/// form. Inverse of [`parse_guid`].
fn format_guid(g: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        d1, d2, d3, g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

// ---------------------------------------------------------------------------
// Resource-attribute claim payload  ("name", TI, flags, val, val, ...)
// ---------------------------------------------------------------------------

/// Parse a resource-attribute payload — `("name",TI,flags,v1,v2,...)`.
fn parse_claim(s: &str) -> Result<ClaimAttribute> {
    let s = s.trim();
    let inner = s
        .strip_prefix('(')
        .and_then(|x| x.strip_suffix(')'))
        .ok_or_else(|| SddlError::BadClaim("payload must be parenthesised".to_string()))?;
    let mut parts = split_top_level_commas(inner);
    if parts.len() < 4 {
        return Err(SddlError::BadClaim(format!(
            "expected at least 4 comma-separated fields, got {}",
            parts.len()
        )));
    }
    let name = parse_quoted_string(parts.remove(0).trim())?;
    let ti = parts.remove(0).trim().to_string();
    let flags_str = parts.remove(0).trim();
    let flags = if flags_str.is_empty() {
        0u32
    } else if let Some(hex) = flags_str
        .strip_prefix("0x")
        .or_else(|| flags_str.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).map_err(|_| SddlError::BadClaim(flags_str.to_string()))?
    } else {
        flags_str
            .parse::<u32>()
            .map_err(|_| SddlError::BadClaim(flags_str.to_string()))?
    };
    let mut values = Vec::with_capacity(parts.len());
    for raw in parts {
        let raw = raw.trim();
        let value = parse_claim_value(&ti, raw)?;
        values.push(value);
    }
    Ok(ClaimAttribute {
        name,
        flags,
        values,
    })
}

fn parse_claim_value(ti: &str, raw: &str) -> Result<ClaimValue> {
    match ti {
        "TI" => Ok(ClaimValue::Int64(
            parse_signed_i64(raw).map_err(|_| SddlError::BadClaim(raw.to_string()))?,
        )),
        "TU" => Ok(ClaimValue::UInt64(
            parse_uint::<u64>(raw).ok_or_else(|| SddlError::BadClaim(raw.to_string()))?,
        )),
        "TB" => match raw {
            "1" | "true" | "TRUE" => Ok(ClaimValue::Boolean(true)),
            "0" | "false" | "FALSE" => Ok(ClaimValue::Boolean(false)),
            _ => Err(SddlError::BadClaim(raw.to_string())),
        },
        "TS" => Ok(ClaimValue::String(parse_quoted_string(raw)?)),
        "TD" => {
            // SID literal: SID(BA) or SID(S-1-5-...).
            let inner = raw
                .strip_prefix("SID(")
                .and_then(|x| x.strip_suffix(')'))
                .ok_or_else(|| SddlError::BadClaim(format!("TD value must be SID(...): {raw}")))?;
            Ok(ClaimValue::Sid(parse_sid_ref(inner)?))
        }
        "TX" => {
            // Octet: #hexhex...
            let hex = raw
                .strip_prefix('#')
                .ok_or_else(|| SddlError::BadClaim(format!("TX value must be #hex: {raw}")))?;
            if hex.len() % 2 != 0 {
                return Err(SddlError::BadClaim("odd hex digit count".to_string()));
            }
            let mut bytes = Vec::with_capacity(hex.len() / 2);
            let hex_bytes = hex.as_bytes();
            for i in (0..hex.len()).step_by(2) {
                bytes.push(
                    u8::from_str_radix(
                        core::str::from_utf8(&hex_bytes[i..i + 2])
                            .map_err(|_| SddlError::BadClaim(raw.to_string()))?,
                        16,
                    )
                    .map_err(|_| SddlError::BadClaim(raw.to_string()))?,
                );
            }
            Ok(ClaimValue::Octet(bytes))
        }
        other => Err(SddlError::BadClaim(format!(
            "unknown type indicator {other:?}"
        ))),
    }
}

fn parse_signed_i64(s: &str) -> core::result::Result<i64, ()> {
    if let Some(rest) = s.strip_prefix("-") {
        if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            i64::from_str_radix(hex, 16).map(|n| -n).map_err(|_| ())
        } else {
            rest.parse::<i64>().map(|n| -n).map_err(|_| ())
        }
    } else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).map_err(|_| ())
    } else {
        s.parse::<i64>().map_err(|_| ())
    }
}

fn parse_quoted_string(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return Err(SddlError::BadClaim(format!(
            "expected double-quoted string, got {s:?}"
        )));
    }
    let inner = &s[1..s.len() - 1];
    // SDDL strings don't support escape sequences in MS-DTYP — quotes
    // simply can't appear in attribute names or string literals.
    if inner.contains('"') {
        return Err(SddlError::BadClaim(
            "embedded quotes not supported".to_string(),
        ));
    }
    Ok(inner.to_string())
}

/// Split a comma-delimited list at top level — ignoring commas inside
/// `"..."` strings and `(...)`/`{...}` nesting.
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut parts: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut in_quote = false;
    let mut depth: i32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b'(' | b'{' if !in_quote => depth += 1,
            b')' | b'}' if !in_quote => depth -= 1,
            b',' if !in_quote && depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Format the §3.9 claim entry bytes back to SDDL `("name",TI,flags,...)`.
fn format_claim_payload(bytes: &[u8]) -> Result<String> {
    let claim = decode_claim_entry(bytes)?;
    let ti = match claim.values.first() {
        Some(ClaimValue::Int64(_)) => "TI",
        Some(ClaimValue::UInt64(_)) => "TU",
        Some(ClaimValue::Boolean(_)) => "TB",
        Some(ClaimValue::String(_)) => "TS",
        Some(ClaimValue::Sid(_)) => "TD",
        Some(ClaimValue::Octet(_)) => "TX",
        None => return Err(SddlError::Format("resource-attribute claim has no values")),
    };
    let mut out = String::new();
    out.push('(');
    out.push('"');
    out.push_str(&claim.name);
    out.push('"');
    out.push(',');
    out.push_str(ti);
    out.push(',');
    out.push_str(&format!("0x{:x}", claim.flags));
    for v in &claim.values {
        out.push(',');
        match v {
            ClaimValue::Int64(n) => out.push_str(&format!("{n}")),
            ClaimValue::UInt64(n) => out.push_str(&format!("{n}")),
            ClaimValue::Boolean(b) => out.push(if *b { '1' } else { '0' }),
            ClaimValue::String(s) => {
                out.push('"');
                out.push_str(s);
                out.push('"');
            }
            ClaimValue::Sid(s) => {
                out.push_str("SID(");
                out.push_str(&format_sid(s));
                out.push(')');
            }
            ClaimValue::Octet(bs) => {
                out.push('#');
                for b in bs {
                    out.push_str(&format!("{b:02x}"));
                }
            }
        }
    }
    out.push(')');
    Ok(out)
}

/// Decode one §3.9 CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 entry from
/// `bytes`, the body following the (mask + Everyone-SID) prefix of a
/// resource-attribute ACE.
fn decode_claim_entry(bytes: &[u8]) -> Result<ClaimAttribute> {
    use crate::security::sddl::abi::{
        CLAIM_TYPE_BOOLEAN, CLAIM_TYPE_INT64, CLAIM_TYPE_OCTET, CLAIM_TYPE_SID, CLAIM_TYPE_STRING,
        CLAIM_TYPE_UINT64,
    };
    if bytes.len() < 20 {
        return Err(SddlError::Format("claim entry header truncated"));
    }
    let name_off = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let value_type = u16::from_le_bytes([bytes[4], bytes[5]]);
    let flags = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let value_count = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    // Value-offset table starts at byte 16.
    let mut value_offsets: Vec<usize> = Vec::with_capacity(value_count);
    for i in 0..value_count {
        let pos = 16 + i * 4;
        if pos + 4 > bytes.len() {
            return Err(SddlError::Format(
                "claim entry value-offset table truncated",
            ));
        }
        value_offsets.push(u32::from_le_bytes([
            bytes[pos],
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
        ]) as usize);
    }
    // Name is UTF-16LE NUL-terminated at name_off.
    let name = read_utf16_z(bytes, name_off)?;
    let mut values: Vec<ClaimValue> = Vec::with_capacity(value_count);
    for off in value_offsets {
        let v = match value_type {
            t if t == CLAIM_TYPE_INT64 => ClaimValue::Int64(read_le_i64(bytes, off)?),
            t if t == CLAIM_TYPE_UINT64 => ClaimValue::UInt64(read_le_u64(bytes, off)?),
            t if t == CLAIM_TYPE_BOOLEAN => ClaimValue::Boolean(read_le_u64(bytes, off)? != 0),
            t if t == CLAIM_TYPE_STRING => {
                let ptr = read_le_u32(bytes, off)? as usize;
                ClaimValue::String(read_utf16_z(bytes, ptr)?)
            }
            t if t == CLAIM_TYPE_SID => {
                let ptr = read_le_u32(bytes, off)? as usize;
                let sid_bytes = bytes
                    .get(ptr..)
                    .ok_or(SddlError::Format("claim entry: SID offset out of bounds"))?;
                let (sid, _) = SidRef::parse(sid_bytes)
                    .map_err(|_| SddlError::Format("claim entry: SID did not parse"))?;
                ClaimValue::Sid(sid.to_owned())
            }
            t if t == CLAIM_TYPE_OCTET => {
                let ptr = read_le_u32(bytes, off)? as usize;
                let len = read_le_u32(bytes, ptr)? as usize;
                let data = bytes
                    .get(ptr + 4..ptr + 4 + len)
                    .ok_or(SddlError::Format("claim entry: octet body out of bounds"))?
                    .to_vec();
                ClaimValue::Octet(data)
            }
            _ => return Err(SddlError::Format("claim entry: unknown value type")),
        };
        values.push(v);
    }
    Ok(ClaimAttribute {
        name,
        flags,
        values,
    })
}

fn read_le_u32(bytes: &[u8], off: usize) -> Result<u32> {
    let slice = bytes
        .get(off..off + 4)
        .ok_or(SddlError::Format("claim entry: u32 out of bounds"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_le_u64(bytes: &[u8], off: usize) -> Result<u64> {
    let slice = bytes
        .get(off..off + 8)
        .ok_or(SddlError::Format("claim entry: u64 out of bounds"))?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_le_i64(bytes: &[u8], off: usize) -> Result<i64> {
    read_le_u64(bytes, off).map(|n| n as i64)
}

fn read_utf16_z(bytes: &[u8], off: usize) -> Result<String> {
    let mut units: Vec<u16> = Vec::new();
    let mut i = off;
    loop {
        let slice = bytes
            .get(i..i + 2)
            .ok_or(SddlError::Format("UTF-16 string out of bounds"))?;
        let u = u16::from_le_bytes([slice[0], slice[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
        i += 2;
    }
    String::from_utf16(&units).map_err(|_| SddlError::Format("UTF-16 string is not well-formed"))
}

#[cfg(test)]
mod tests;
