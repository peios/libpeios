// WellKnownSid — a typed enum over the well-known SIDs Peios cares
// about, with conversions to/from the raw `Sid`.
//
// peios-uapi has a string-keyed `well_known_label()`; this enum is the
// semantic layer on top — it lets callers pattern-match identity and
// construct well-known SIDs without hand-assembling subauthority arrays.

use crate::security::sddl::wire::Sid;

/// A well-known SID. Variant set covers the identities Peios uses for
/// system principals and the integrity-level ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WellKnownSid {
    /// `S-1-0-0` — the null SID.
    Null,
    /// `S-1-1-0` — World / Everyone.
    Everyone,
    /// `S-1-5-7` — Anonymous logon.
    Anonymous,
    /// `S-1-5-11` — Authenticated Users.
    AuthenticatedUsers,
    /// `S-1-5-18` — LocalSystem.
    LocalSystem,
    /// `S-1-5-19` — LocalService.
    LocalService,
    /// `S-1-5-20` — NetworkService.
    NetworkService,
    /// `S-1-5-32-544` — BUILTIN\Administrators.
    BuiltinAdministrators,
    /// `S-1-5-32-545` — BUILTIN\Users.
    BuiltinUsers,

    // Integrity levels (authority 16).
    /// `S-1-16-0` — Untrusted integrity level.
    UntrustedIl,
    /// `S-1-16-4096` — Low integrity level.
    LowIl,
    /// `S-1-16-8192` — Medium integrity level.
    MediumIl,
    /// `S-1-16-8448` — Medium-Plus integrity level.
    MediumPlusIl,
    /// `S-1-16-12288` — High integrity level.
    HighIl,
    /// `S-1-16-16384` — System integrity level.
    SystemIl,
    /// `S-1-16-20480` — Protected-Process integrity level.
    ProtectedProcessIl,
}

impl WellKnownSid {
    /// All variants, for iteration (`from_sid` uses this internally).
    const ALL: &'static [WellKnownSid] = &[
        WellKnownSid::Null,
        WellKnownSid::Everyone,
        WellKnownSid::Anonymous,
        WellKnownSid::AuthenticatedUsers,
        WellKnownSid::LocalSystem,
        WellKnownSid::LocalService,
        WellKnownSid::NetworkService,
        WellKnownSid::BuiltinAdministrators,
        WellKnownSid::BuiltinUsers,
        WellKnownSid::UntrustedIl,
        WellKnownSid::LowIl,
        WellKnownSid::MediumIl,
        WellKnownSid::MediumPlusIl,
        WellKnownSid::HighIl,
        WellKnownSid::SystemIl,
        WellKnownSid::ProtectedProcessIl,
    ];

    /// The `(authority, &[subauthorities])` for this well-known SID.
    /// Revision is always 1.
    const fn parts(self) -> (u64, &'static [u32]) {
        match self {
            WellKnownSid::Null => (0, &[0]),
            WellKnownSid::Everyone => (1, &[0]),
            WellKnownSid::Anonymous => (5, &[7]),
            WellKnownSid::AuthenticatedUsers => (5, &[11]),
            WellKnownSid::LocalSystem => (5, &[18]),
            WellKnownSid::LocalService => (5, &[19]),
            WellKnownSid::NetworkService => (5, &[20]),
            WellKnownSid::BuiltinAdministrators => (5, &[32, 544]),
            WellKnownSid::BuiltinUsers => (5, &[32, 545]),
            WellKnownSid::UntrustedIl => (16, &[0]),
            WellKnownSid::LowIl => (16, &[4096]),
            WellKnownSid::MediumIl => (16, &[8192]),
            WellKnownSid::MediumPlusIl => (16, &[8448]),
            WellKnownSid::HighIl => (16, &[12288]),
            WellKnownSid::SystemIl => (16, &[16384]),
            WellKnownSid::ProtectedProcessIl => (16, &[20480]),
        }
    }

    /// Construct the owned [`Sid`] for this well-known identity.
    pub fn to_sid(self) -> Sid {
        let (authority, subs) = self.parts();
        Sid::new(1, authority, subs.to_vec())
    }

    /// True if `sid` is exactly this well-known SID.
    pub fn matches(self, sid: &Sid) -> bool {
        let (authority, subs) = self.parts();
        sid.revision == 1 && sid.authority == authority && sid.sub_authorities.as_slice() == subs
    }

    /// Identify a `Sid` as a well-known SID, or `None` if it isn't one.
    pub fn from_sid(sid: &Sid) -> Option<WellKnownSid> {
        Self::ALL.iter().copied().find(|w| w.matches(sid))
    }

    /// Human-readable label (e.g. `"LocalSystem"`).
    pub fn label(self) -> &'static str {
        match self {
            WellKnownSid::Null => "Null",
            WellKnownSid::Everyone => "Everyone",
            WellKnownSid::Anonymous => "Anonymous",
            WellKnownSid::AuthenticatedUsers => "Authenticated Users",
            WellKnownSid::LocalSystem => "LocalSystem",
            WellKnownSid::LocalService => "LocalService",
            WellKnownSid::NetworkService => "NetworkService",
            WellKnownSid::BuiltinAdministrators => "BUILTIN\\Administrators",
            WellKnownSid::BuiltinUsers => "BUILTIN\\Users",
            WellKnownSid::UntrustedIl => "Untrusted IL",
            WellKnownSid::LowIl => "Low IL",
            WellKnownSid::MediumIl => "Medium IL",
            WellKnownSid::MediumPlusIl => "Medium-Plus IL",
            WellKnownSid::HighIl => "High IL",
            WellKnownSid::SystemIl => "System IL",
            WellKnownSid::ProtectedProcessIl => "Protected-Process IL",
        }
    }
}

impl From<WellKnownSid> for Sid {
    fn from(w: WellKnownSid) -> Sid {
        w.to_sid()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn local_system_roundtrips() {
        let sid = WellKnownSid::LocalSystem.to_sid();
        assert_eq!(sid.to_string(), "S-1-5-18");
        assert_eq!(
            WellKnownSid::from_sid(&sid),
            Some(WellKnownSid::LocalSystem)
        );
        assert!(WellKnownSid::LocalSystem.matches(&sid));
    }

    #[test]
    fn builtin_admins_two_subauthorities() {
        let sid = WellKnownSid::BuiltinAdministrators.to_sid();
        assert_eq!(sid.to_string(), "S-1-5-32-544");
        assert_eq!(
            WellKnownSid::from_sid(&sid),
            Some(WellKnownSid::BuiltinAdministrators)
        );
    }

    #[test]
    fn integrity_levels() {
        assert_eq!(WellKnownSid::HighIl.to_sid().to_string(), "S-1-16-12288");
        assert_eq!(WellKnownSid::SystemIl.to_sid().to_string(), "S-1-16-16384");
    }

    #[test]
    fn unknown_sid_is_none() {
        // A domain user SID — definitely not well-known.
        let sid = Sid::new(1, 5, vec![21, 1234, 5678, 1001]);
        assert_eq!(WellKnownSid::from_sid(&sid), None);
    }

    #[test]
    fn no_cross_matching() {
        // LocalSystem's SID must not match LocalService's variant.
        let ls = WellKnownSid::LocalSystem.to_sid();
        assert!(!WellKnownSid::LocalService.matches(&ls));
    }
}
