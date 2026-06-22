// Fluent builders for SECURITY_DESCRIPTOR / ACL / ACE wire bytes.
//
// All three emit self-relative on-wire layouts matching the parsers in
// `crate::codec`. The builders own the offset/size bookkeeping so
// callers describe intent ("allow Everyone GENERIC_READ") rather than
// hand-assembling byte buffers.

use crate::security::sddl::Result;
use crate::security::sddl::claims::ClaimAttribute;
use crate::security::sddl::condition::Condition;
use crate::security::sddl::Error;
use alloc::vec;
use alloc::vec::Vec;
use crate::security::sddl::codec::{
    ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACE_TYPE_ACCESS_ALLOWED,
    ACE_TYPE_ACCESS_ALLOWED_CALLBACK, ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
    ACE_TYPE_ACCESS_ALLOWED_OBJECT, ACE_TYPE_ACCESS_DENIED, ACE_TYPE_ACCESS_DENIED_CALLBACK,
    ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT, ACE_TYPE_ACCESS_DENIED_OBJECT, ACE_TYPE_SYSTEM_AUDIT,
    ACE_TYPE_SYSTEM_AUDIT_CALLBACK, ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT,
    ACE_TYPE_SYSTEM_AUDIT_OBJECT, ACE_TYPE_SYSTEM_MANDATORY_LABEL,
    ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE, Ace, AceRef, SE_DACL_PRESENT, SE_SACL_PRESENT,
    SE_SELF_RELATIVE,
};
use crate::security::sddl::wire::Sid;

/// Standard ACL revision — basic, label, resource-attribute, scoped-policy
/// and process-trust-label ACE types.
const ACL_REVISION: u8 = 2;
/// Directory-services ACL revision — required when object-type or callback
/// (conditional) ACEs are present (ACE types `0x05..=0x10`).
const ACL_REVISION_DS: u8 = 4;
/// SECURITY_DESCRIPTOR revision — always 1.
const SD_REVISION: u8 = 1;

/// Encode an object-ACE body: access mask, the GUID-presence flags, the
/// GUIDs that are present, then the principal SID.
fn object_body(
    mask: u32,
    object_type: Option<[u8; 16]>,
    inherited_object_type: Option<[u8; 16]>,
    sid: &Sid,
) -> Vec<u8> {
    let mut flags: u32 = 0;
    if object_type.is_some() {
        flags |= ACE_OBJECT_TYPE_PRESENT;
    }
    if inherited_object_type.is_some() {
        flags |= ACE_INHERITED_OBJECT_TYPE_PRESENT;
    }
    let mut body = Vec::new();
    body.extend_from_slice(&mask.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    if let Some(guid) = object_type {
        body.extend_from_slice(&guid);
    }
    if let Some(guid) = inherited_object_type {
        body.extend_from_slice(&guid);
    }
    body.extend_from_slice(&sid.encode());
    body
}

// ---------------------------------------------------------------------------
// AceBuilder
// ---------------------------------------------------------------------------

/// The body of an ACE — everything after the 4-byte ACE header.
#[derive(Clone, Debug)]
enum AceBody {
    /// The common "u32 access mask, then SID" layout: covers
    /// ACCESS_ALLOWED / ACCESS_DENIED, SYSTEM_AUDIT, and
    /// SYSTEM_MANDATORY_LABEL.
    MaskSid { mask: u32, sid: Sid },
    /// Verbatim body bytes. Lets the builder express ACE types it has no
    /// typed constructor for — object, callback, resource-attribute — by
    /// carrying their body opaquely.
    Raw(Vec<u8>),
}

/// Builds a single ACE.
///
/// The typed constructors — [`allow`](AceBuilder::allow),
/// [`deny`](AceBuilder::deny), [`audit`](AceBuilder::audit),
/// [`mandatory_label`](AceBuilder::mandatory_label) — cover the common
/// "mask + SID" ACE types. For any other ACE type,
/// [`raw`](AceBuilder::raw) takes the body bytes directly, and
/// [`from_ace_ref`](AceBuilder::from_ace_ref) /
/// [`from_ace`](AceBuilder::from_ace) round-trip a parsed ACE verbatim —
/// so every ACE type is expressible.
#[derive(Clone, Debug)]
pub struct AceBuilder {
    ace_type: u8,
    flags: u8,
    body: AceBody,
}

impl AceBuilder {
    /// An access-allowed ACE granting `mask` to `sid`.
    pub fn allow(sid: impl Into<Sid>, mask: u32) -> Self {
        Self::mask_sid(ACE_TYPE_ACCESS_ALLOWED, sid.into(), mask)
    }

    /// An access-denied ACE denying `mask` to `sid`.
    pub fn deny(sid: impl Into<Sid>, mask: u32) -> Self {
        Self::mask_sid(ACE_TYPE_ACCESS_DENIED, sid.into(), mask)
    }

    /// A system-audit ACE recording access to `mask` by `sid`.
    pub fn audit(sid: impl Into<Sid>, mask: u32) -> Self {
        Self::mask_sid(ACE_TYPE_SYSTEM_AUDIT, sid.into(), mask)
    }

    /// A mandatory-label ACE. The "mask" field carries the mandatory
    /// policy bits; `sid` is the integrity-level SID.
    pub fn mandatory_label(sid: impl Into<Sid>, policy: u32) -> Self {
        Self::mask_sid(ACE_TYPE_SYSTEM_MANDATORY_LABEL, sid.into(), policy)
    }

    /// An access-allowed object ACE granting `mask` to `sid`, optionally
    /// scoped by an `ObjectType` and/or `InheritedObjectType` GUID. A
    /// GUID of `None` is simply omitted from the body. An ACL containing
    /// an object ACE is emitted at `ACL_REVISION_DS`.
    pub fn allow_object(
        sid: impl Into<Sid>,
        mask: u32,
        object_type: Option<[u8; 16]>,
        inherited_object_type: Option<[u8; 16]>,
    ) -> Self {
        Self::object(
            ACE_TYPE_ACCESS_ALLOWED_OBJECT,
            sid.into(),
            mask,
            object_type,
            inherited_object_type,
        )
    }

    /// An access-denied object ACE. See [`allow_object`](AceBuilder::allow_object).
    pub fn deny_object(
        sid: impl Into<Sid>,
        mask: u32,
        object_type: Option<[u8; 16]>,
        inherited_object_type: Option<[u8; 16]>,
    ) -> Self {
        Self::object(
            ACE_TYPE_ACCESS_DENIED_OBJECT,
            sid.into(),
            mask,
            object_type,
            inherited_object_type,
        )
    }

    /// A system-audit object ACE. See [`allow_object`](AceBuilder::allow_object).
    pub fn audit_object(
        sid: impl Into<Sid>,
        mask: u32,
        object_type: Option<[u8; 16]>,
        inherited_object_type: Option<[u8; 16]>,
    ) -> Self {
        Self::object(
            ACE_TYPE_SYSTEM_AUDIT_OBJECT,
            sid.into(),
            mask,
            object_type,
            inherited_object_type,
        )
    }

    fn object(
        ace_type: u8,
        sid: Sid,
        mask: u32,
        object_type: Option<[u8; 16]>,
        inherited_object_type: Option<[u8; 16]>,
    ) -> Self {
        AceBuilder {
            ace_type,
            flags: 0,
            body: AceBody::Raw(object_body(mask, object_type, inherited_object_type, &sid)),
        }
    }

    /// An ACE of `ace_type` carrying `body` verbatim — the bytes after
    /// the 4-byte ACE header. Flags default to 0; set them with
    /// [`flags`](AceBuilder::flags).
    ///
    /// This is the escape hatch for ACE types without a typed
    /// constructor (object, callback, resource-attribute, …): the caller
    /// supplies an already-encoded body.
    ///
    /// # Errors
    /// [`Error::Encode`] if the body is too large for the ACE to fit its
    /// 16-bit `AceSize` field (body length must be ≤ 65531).
    pub fn raw(ace_type: u8, body: impl Into<Vec<u8>>) -> Result<Self> {
        let body = body.into();
        if body.len() > u16::MAX as usize - 4 {
            return Err(Error::Encode("ACE body exceeds 65531 bytes"));
        }
        Ok(AceBuilder {
            ace_type,
            flags: 0,
            body: AceBody::Raw(body),
        })
    }

    /// Reconstruct a builder from a parsed [`AceRef`], carrying its type,
    /// flags, and body verbatim — `build` reproduces the same bytes.
    pub fn from_ace_ref(ace: &AceRef<'_>) -> Self {
        AceBuilder {
            ace_type: ace.ace_type,
            flags: ace.flags,
            body: AceBody::Raw(ace.body.to_vec()),
        }
    }

    /// Owned-input variant of [`from_ace_ref`](AceBuilder::from_ace_ref).
    pub fn from_ace(ace: &Ace) -> Self {
        AceBuilder {
            ace_type: ace.ace_type,
            flags: ace.flags,
            body: AceBody::Raw(ace.body.clone()),
        }
    }

    /// A resource-attribute ACE (`SYSTEM_RESOURCE_ATTRIBUTE_ACE`) carrying
    /// `claim` — one named, typed, multi-valued attribute the object
    /// exposes for conditional-ACE evaluation. The principal SID is fixed
    /// to Everyone (`S-1-1-0`), as the format requires.
    ///
    /// # Errors
    /// [`Error::Encode`] if `claim` is malformed (no values, or values of
    /// mixed type) or the resulting ACE would exceed its 16-bit size.
    pub fn resource_attribute(claim: &ClaimAttribute) -> Result<Self> {
        let entry = claim.encode()?;
        // The format fixes the principal SID to Everyone (S-1-1-0).
        let sid = Sid::new(1, 1, vec![0u32]).encode();
        let mut body = Vec::with_capacity(4 + sid.len() + entry.len());
        body.extend_from_slice(&0u32.to_le_bytes()); // Mask — reserved, unused
        body.extend_from_slice(&sid);
        body.extend_from_slice(&entry);
        Self::raw(ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE, body)
    }

    /// An access-allowed conditional (callback) ACE: grants `mask` to
    /// `sid` only when `condition` evaluates TRUE during AccessCheck.
    ///
    /// # Errors
    /// [`Error::Encode`] if the encoded ACE would exceed its 16-bit size.
    pub fn allow_callback(sid: impl Into<Sid>, mask: u32, condition: &Condition) -> Result<Self> {
        Self::callback(
            ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
            sid.into(),
            mask,
            condition,
        )
    }

    /// An access-denied conditional ACE. See [`allow_callback`](AceBuilder::allow_callback).
    pub fn deny_callback(sid: impl Into<Sid>, mask: u32, condition: &Condition) -> Result<Self> {
        Self::callback(ACE_TYPE_ACCESS_DENIED_CALLBACK, sid.into(), mask, condition)
    }

    /// A system-audit conditional ACE. See [`allow_callback`](AceBuilder::allow_callback).
    pub fn audit_callback(sid: impl Into<Sid>, mask: u32, condition: &Condition) -> Result<Self> {
        Self::callback(ACE_TYPE_SYSTEM_AUDIT_CALLBACK, sid.into(), mask, condition)
    }

    /// An access-allowed conditional *object* ACE — [`allow_callback`](AceBuilder::allow_callback)
    /// additionally scoped by `ObjectType` / `InheritedObjectType` GUIDs,
    /// exactly as [`allow_object`](AceBuilder::allow_object).
    ///
    /// # Errors
    /// [`Error::Encode`] if the encoded ACE would exceed its 16-bit size.
    pub fn allow_callback_object(
        sid: impl Into<Sid>,
        mask: u32,
        object_type: Option<[u8; 16]>,
        inherited_object_type: Option<[u8; 16]>,
        condition: &Condition,
    ) -> Result<Self> {
        Self::callback_object(
            ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT,
            sid.into(),
            mask,
            object_type,
            inherited_object_type,
            condition,
        )
    }

    /// An access-denied conditional object ACE. See
    /// [`allow_callback_object`](AceBuilder::allow_callback_object).
    pub fn deny_callback_object(
        sid: impl Into<Sid>,
        mask: u32,
        object_type: Option<[u8; 16]>,
        inherited_object_type: Option<[u8; 16]>,
        condition: &Condition,
    ) -> Result<Self> {
        Self::callback_object(
            ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT,
            sid.into(),
            mask,
            object_type,
            inherited_object_type,
            condition,
        )
    }

    /// A system-audit conditional object ACE. See
    /// [`allow_callback_object`](AceBuilder::allow_callback_object).
    pub fn audit_callback_object(
        sid: impl Into<Sid>,
        mask: u32,
        object_type: Option<[u8; 16]>,
        inherited_object_type: Option<[u8; 16]>,
        condition: &Condition,
    ) -> Result<Self> {
        Self::callback_object(
            ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT,
            sid.into(),
            mask,
            object_type,
            inherited_object_type,
            condition,
        )
    }

    fn callback(ace_type: u8, sid: Sid, mask: u32, condition: &Condition) -> Result<Self> {
        // Non-object callback body: mask, SID, then the conditional
        // expression as ApplicationData.
        let mut body = Vec::new();
        body.extend_from_slice(&mask.to_le_bytes());
        body.extend_from_slice(&sid.encode());
        body.extend_from_slice(&condition.encode());
        Self::raw(ace_type, body)
    }

    fn callback_object(
        ace_type: u8,
        sid: Sid,
        mask: u32,
        object_type: Option<[u8; 16]>,
        inherited_object_type: Option<[u8; 16]>,
        condition: &Condition,
    ) -> Result<Self> {
        // Object-callback body: the object-ACE body, then the conditional
        // expression as ApplicationData.
        let mut body = object_body(mask, object_type, inherited_object_type, &sid);
        body.extend_from_slice(&condition.encode());
        Self::raw(ace_type, body)
    }

    fn mask_sid(ace_type: u8, sid: Sid, mask: u32) -> Self {
        AceBuilder {
            ace_type,
            flags: 0,
            body: AceBody::MaskSid { mask, sid },
        }
    }

    /// Replace the ACE flags byte (ACE_FLAG_* — inheritance, audit
    /// success/failure). Overwrites any previously-set flags.
    pub fn flags(mut self, flags: u8) -> Self {
        self.flags = flags;
        self
    }

    /// Total wire size of this ACE: 4-byte header plus the body.
    fn encoded_len(&self) -> usize {
        4 + match &self.body {
            AceBody::MaskSid { sid, .. } => 4 + sid.encoded_len(),
            AceBody::Raw(body) => body.len(),
        }
    }

    /// True if this ACE type requires `ACL_REVISION_DS` — the object-type
    /// and callback (conditional) ACE types, `0x05..=0x10`.
    fn needs_ds_revision(&self) -> bool {
        (0x05..=0x10).contains(&self.ace_type)
    }

    /// Emit ACE wire bytes.
    pub fn build(&self) -> Vec<u8> {
        // `encoded_len` fits a u16: a MaskSid body is at most ~84 bytes,
        // and a Raw body was bounds-checked at construction.
        let size = self.encoded_len();
        let mut out = Vec::with_capacity(size);
        out.push(self.ace_type);
        out.push(self.flags);
        out.extend_from_slice(&(size as u16).to_le_bytes());
        match &self.body {
            AceBody::MaskSid { mask, sid } => {
                out.extend_from_slice(&mask.to_le_bytes());
                out.extend_from_slice(&sid.encode());
            }
            AceBody::Raw(body) => out.extend_from_slice(body),
        }
        out
    }
}

// ---------------------------------------------------------------------------
// AclBuilder
// ---------------------------------------------------------------------------

/// Builds an ACL (access-control list) — an 8-byte header followed by
/// ACEs in declaration order.
#[derive(Clone, Debug, Default)]
pub struct AclBuilder {
    aces: Vec<AceBuilder>,
}

impl AclBuilder {
    /// An empty ACL. An empty *DACL* denies everyone everything; an
    /// empty *SACL* audits nothing — both are valid and meaningful.
    pub fn new() -> Self {
        AclBuilder { aces: Vec::new() }
    }

    /// Append an ACE.
    pub fn ace(mut self, ace: AceBuilder) -> Self {
        self.aces.push(ace);
        self
    }

    /// Convenience: append an access-allowed ACE.
    pub fn allow(self, sid: impl Into<Sid>, mask: u32) -> Self {
        self.ace(AceBuilder::allow(sid, mask))
    }

    /// Convenience: append an access-denied ACE.
    pub fn deny(self, sid: impl Into<Sid>, mask: u32) -> Self {
        self.ace(AceBuilder::deny(sid, mask))
    }

    /// Number of ACEs accumulated so far.
    pub fn len(&self) -> usize {
        self.aces.len()
    }

    /// True if no ACEs have been added.
    pub fn is_empty(&self) -> bool {
        self.aces.is_empty()
    }

    /// Total wire size: 8-byte header + every ACE.
    fn encoded_len(&self) -> usize {
        8 + self.aces.iter().map(|a| a.encoded_len()).sum::<usize>()
    }

    /// Emit ACL wire bytes.
    ///
    /// Errors if there are more ACEs than the 16-bit count field can
    /// hold, or the total size exceeds the 16-bit size field.
    pub fn build(&self) -> Result<Vec<u8>> {
        if self.aces.len() > u16::MAX as usize {
            return Err(Error::Encode("ACL has more than 65535 ACEs"));
        }
        let total = self.encoded_len();
        if total > u16::MAX as usize {
            return Err(Error::Encode("ACL wire size exceeds 65535 bytes"));
        }
        // ACL_REVISION_DS is required once an object-type or callback ACE
        // is present; a plain ACL stays at the standard revision.
        let revision = if self.aces.iter().any(AceBuilder::needs_ds_revision) {
            ACL_REVISION_DS
        } else {
            ACL_REVISION
        };
        let mut out = Vec::with_capacity(total);
        out.push(revision);
        out.push(0); // sbz1
        out.extend_from_slice(&(total as u16).to_le_bytes());
        out.extend_from_slice(&(self.aces.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // sbz2
        for ace in &self.aces {
            out.extend_from_slice(&ace.build());
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// SdBuilder
// ---------------------------------------------------------------------------

/// Builds a self-relative SECURITY_DESCRIPTOR — a 20-byte header
/// followed by the owner SID, group SID, SACL, and DACL it references.
#[derive(Clone, Debug, Default)]
pub struct SdBuilder {
    owner: Option<Sid>,
    group: Option<Sid>,
    dacl: Option<AclBuilder>,
    sacl: Option<AclBuilder>,
    extra_control: u16,
}

impl SdBuilder {
    /// An empty self-relative SD — no owner, no group, no ACLs. The
    /// `SE_SELF_RELATIVE` control bit is always set on the output.
    pub fn new() -> Self {
        SdBuilder::default()
    }

    /// Set the owner SID.
    pub fn owner(mut self, sid: impl Into<Sid>) -> Self {
        self.owner = Some(sid.into());
        self
    }

    /// Set the group SID.
    pub fn group(mut self, sid: impl Into<Sid>) -> Self {
        self.group = Some(sid.into());
        self
    }

    /// Set the DACL. Presence sets `SE_DACL_PRESENT`. An *absent* DACL
    /// (never calling this) is distinct from an *empty* one
    /// (`SdBuilder::dacl(AclBuilder::new())`): absent grants implicit
    /// full access, empty denies everyone.
    pub fn dacl(mut self, acl: AclBuilder) -> Self {
        self.dacl = Some(acl);
        self
    }

    /// Set the SACL. Presence sets `SE_SACL_PRESENT`.
    pub fn sacl(mut self, acl: AclBuilder) -> Self {
        self.sacl = Some(acl);
        self
    }

    /// OR additional bits into the control word (e.g.
    /// `SE_DACL_PROTECTED`). `SE_SELF_RELATIVE` and the
    /// `SE_*_PRESENT` bits are set automatically.
    pub fn control(mut self, bits: u16) -> Self {
        self.extra_control |= bits;
        self
    }

    /// Emit self-relative SECURITY_DESCRIPTOR wire bytes.
    pub fn build(&self) -> Result<Vec<u8>> {
        // 20-byte header placeholder; referenced data appended after.
        let mut buf = vec![0u8; 20];
        let mut control = SE_SELF_RELATIVE | self.extra_control;
        let mut owner_off: u32 = 0;
        let mut group_off: u32 = 0;
        let mut sacl_off: u32 = 0;
        let mut dacl_off: u32 = 0;

        if let Some(owner) = &self.owner {
            owner_off = buf.len() as u32;
            buf.extend_from_slice(&owner.encode());
        }
        if let Some(group) = &self.group {
            group_off = buf.len() as u32;
            buf.extend_from_slice(&group.encode());
        }
        if let Some(sacl) = &self.sacl {
            control |= SE_SACL_PRESENT;
            sacl_off = buf.len() as u32;
            buf.extend_from_slice(&sacl.build()?);
        }
        if let Some(dacl) = &self.dacl {
            control |= SE_DACL_PRESENT;
            dacl_off = buf.len() as u32;
            buf.extend_from_slice(&dacl.build()?);
        }

        buf[0] = SD_REVISION;
        buf[1] = 0; // sbz1
        buf[2..4].copy_from_slice(&control.to_le_bytes());
        buf[4..8].copy_from_slice(&owner_off.to_le_bytes());
        buf[8..12].copy_from_slice(&group_off.to_le_bytes());
        buf[12..16].copy_from_slice(&sacl_off.to_le_bytes());
        buf[16..20].copy_from_slice(&dacl_off.to_le_bytes());
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::sddl::claims::ClaimValue;
    use crate::security::sddl::condition::Operand;
    use crate::security::sddl::wellknown::WellKnownSid;
    use crate::security::sddl::codec::{
        ACCESS_GENERIC_ALL, ACCESS_GENERIC_READ, ACE_FLAG_INHERITED,
        ACE_INHERITED_OBJECT_TYPE_PRESENT, ACE_OBJECT_TYPE_PRESENT, ACE_TYPE_ACCESS_ALLOWED_OBJECT,
        SE_DACL_PROTECTED, SecurityDescriptor,
    };

    #[test]
    fn ace_allow_roundtrips_through_parser() {
        let bytes = AceBuilder::allow(WellKnownSid::Everyone, 0x8000_0000).build();
        // 4 header + 4 mask + (8 + 4) SID = 20.
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes[0], ACE_TYPE_ACCESS_ALLOWED);
    }

    #[test]
    fn empty_acl_has_zero_ace_count() {
        let bytes = AclBuilder::new().build().unwrap();
        assert_eq!(bytes.len(), 8);
        assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 0);
    }

    #[test]
    fn sd_with_owner_and_dacl_parses_back() {
        let sd_bytes = SdBuilder::new()
            .owner(WellKnownSid::LocalSystem)
            .group(WellKnownSid::BuiltinAdministrators)
            .dacl(
                AclBuilder::new()
                    .allow(WellKnownSid::Everyone, 0x8000_0000)
                    .allow(WellKnownSid::LocalSystem, 0x1000_0000),
            )
            .control(SE_DACL_PROTECTED)
            .build()
            .unwrap();

        let sd = SecurityDescriptor::parse(&sd_bytes).unwrap();
        assert_eq!(sd.revision, 1);
        assert!(sd.control & SE_SELF_RELATIVE != 0);
        assert!(sd.control & SE_DACL_PRESENT != 0);
        assert!(sd.control & SE_DACL_PROTECTED != 0);

        let owner = sd.owner().unwrap();
        assert_eq!(owner, WellKnownSid::LocalSystem.to_sid());
        let group = sd.group().unwrap();
        assert_eq!(group, WellKnownSid::BuiltinAdministrators.to_sid());

        let dacl = sd.dacl().unwrap().unwrap();
        assert_eq!(dacl.ace_count, 2);
        let aces: Vec<_> = dacl.aces_iter().collect();
        assert_eq!(aces.len(), 2);
        let (mask0, sid0) = aces[0].as_ref().unwrap().as_mask_sid().unwrap();
        assert_eq!(mask0, 0x8000_0000);
        assert_eq!(sid0.to_owned(), WellKnownSid::Everyone.to_sid());
    }

    #[test]
    fn sd_without_dacl_has_no_dacl_present_bit() {
        let sd_bytes = SdBuilder::new()
            .owner(WellKnownSid::LocalSystem)
            .build()
            .unwrap();
        let sd = SecurityDescriptor::parse(&sd_bytes).unwrap();
        assert_eq!(sd.control & SE_DACL_PRESENT, 0);
        assert!(sd.dacl().is_none());
    }

    #[test]
    fn raw_ace_carries_an_arbitrary_body() {
        // An object ACE (0x05) — no typed constructor models it; the body
        // rides along verbatim.
        let body = alloc::vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        let bytes = AceBuilder::raw(ACE_TYPE_ACCESS_ALLOWED_OBJECT, body.clone())
            .unwrap()
            .flags(ACE_FLAG_INHERITED)
            .build();
        assert_eq!(bytes[0], ACE_TYPE_ACCESS_ALLOWED_OBJECT);
        assert_eq!(bytes[1], ACE_FLAG_INHERITED);
        assert_eq!(
            u16::from_le_bytes([bytes[2], bytes[3]]) as usize,
            bytes.len()
        );
        assert_eq!(&bytes[4..], &body[..]);
    }

    #[test]
    fn from_ace_rebuilds_verbatim() {
        // Build a typed ACE, view it as a parsed ACE, rebuild from it.
        let original = AceBuilder::deny(WellKnownSid::Everyone, 0x4)
            .flags(ACE_FLAG_INHERITED)
            .build();
        let aref = AceRef {
            ace_type: original[0],
            flags: original[1],
            size: u16::from_le_bytes([original[2], original[3]]),
            body: &original[4..],
        };
        assert_eq!(AceBuilder::from_ace_ref(&aref).build(), original);
        // The owned-input path produces the same bytes.
        let owned = aref.to_owned();
        assert_eq!(AceBuilder::from_ace(&owned).build(), original);
    }

    #[test]
    fn raw_rejects_oversized_body() {
        let huge = alloc::vec![0u8; 70_000];
        assert!(matches!(
            AceBuilder::raw(ACE_TYPE_ACCESS_ALLOWED, huge),
            Err(Error::Encode(_))
        ));
    }

    #[test]
    fn object_ace_encodes_present_guids() {
        let ot = [0x11u8; 16];
        let iot = [0x22u8; 16];
        let ace = AceBuilder::allow_object(
            WellKnownSid::Everyone,
            ACCESS_GENERIC_READ,
            Some(ot),
            Some(iot),
        )
        .build();
        assert_eq!(ace[0], ACE_TYPE_ACCESS_ALLOWED_OBJECT);
        // Body @4: mask(4), flags(4), ObjectType(16), InheritedObjectType(16), SID.
        let flags = u32::from_le_bytes([ace[8], ace[9], ace[10], ace[11]]);
        assert_eq!(
            flags,
            ACE_OBJECT_TYPE_PRESENT | ACE_INHERITED_OBJECT_TYPE_PRESENT
        );
        assert_eq!(&ace[12..28], &ot);
        assert_eq!(&ace[28..44], &iot);
        assert_eq!(u16::from_le_bytes([ace[2], ace[3]]) as usize, ace.len());
    }

    #[test]
    fn object_ace_without_guids_omits_them() {
        let ace =
            AceBuilder::deny_object(WellKnownSid::Everyone, ACCESS_GENERIC_ALL, None, None).build();
        let flags = u32::from_le_bytes([ace[8], ace[9], ace[10], ace[11]]);
        assert_eq!(flags, 0);
        // header(4) + mask(4) + flags(4) + Everyone SID(12), no GUIDs.
        assert_eq!(ace.len(), 24);
    }

    #[test]
    fn acl_with_object_ace_uses_ds_revision() {
        let acl = AclBuilder::new()
            .ace(AceBuilder::audit_object(
                WellKnownSid::Everyone,
                ACCESS_GENERIC_READ,
                Some([0u8; 16]),
                None,
            ))
            .build()
            .unwrap();
        assert_eq!(acl[0], ACL_REVISION_DS);
    }

    #[test]
    fn acl_with_only_basic_aces_uses_standard_revision() {
        let acl = AclBuilder::new()
            .allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
            .build()
            .unwrap();
        assert_eq!(acl[0], ACL_REVISION);
    }

    #[test]
    fn resource_attribute_ace_wraps_a_claim_entry() {
        let claim = ClaimAttribute::new("Confidentiality", alloc::vec![ClaimValue::Int64(3)]);
        let entry = claim.encode().unwrap();
        let ace = AceBuilder::resource_attribute(&claim).unwrap().build();
        assert_eq!(ace[0], ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE);
        assert_eq!(u16::from_le_bytes([ace[2], ace[3]]) as usize, ace.len());
        // Body @4: Mask(4)=0, Everyone SID(12), then the §3.9 claim entry.
        assert_eq!(&ace[4..8], &[0u8, 0, 0, 0]);
        let everyone = Sid::new(1, 1, alloc::vec![0u32]).encode();
        assert_eq!(&ace[8..8 + everyone.len()], &everyone[..]);
        assert_eq!(&ace[8 + everyone.len()..], &entry[..]);
    }

    #[test]
    fn resource_attribute_rejects_malformed_claim() {
        let empty = ClaimAttribute::new("Bad", alloc::vec![]);
        assert!(matches!(
            AceBuilder::resource_attribute(&empty),
            Err(Error::Encode(_))
        ));
    }

    #[test]
    fn callback_ace_appends_the_condition() {
        let cond = Condition::Exists(Operand::User("clearance".into()));
        let expr = cond.encode();
        let ace = AceBuilder::allow_callback(WellKnownSid::Everyone, ACCESS_GENERIC_READ, &cond)
            .unwrap()
            .build();
        // Type 0x09; body = mask(4) + Everyone SID(12) + the artx expr.
        assert_eq!(ace[0], 0x09);
        assert_eq!(u16::from_le_bytes([ace[2], ace[3]]) as usize, ace.len());
        assert_eq!(
            u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]),
            ACCESS_GENERIC_READ
        );
        let everyone = Sid::new(1, 1, alloc::vec![0u32]).encode();
        assert_eq!(&ace[8..8 + everyone.len()], &everyone[..]);
        assert_eq!(&ace[8 + everyone.len()..], &expr[..]);
    }

    #[test]
    fn callback_object_ace_uses_ds_revision() {
        let cond = Condition::Exists(Operand::User("x".into()));
        let acl = AclBuilder::new()
            .ace(
                AceBuilder::deny_callback_object(
                    WellKnownSid::Everyone,
                    ACCESS_GENERIC_ALL,
                    Some([0u8; 16]),
                    None,
                    &cond,
                )
                .unwrap(),
            )
            .build()
            .unwrap();
        assert_eq!(acl[0], ACL_REVISION_DS);
    }
}
