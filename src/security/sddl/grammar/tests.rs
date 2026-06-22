// SDDL round-trip and unit tests.

use super::*;
use crate::security::sddl::build::{AceBuilder, AclBuilder, SdBuilder};
use crate::security::sddl::condition::{CompareOp, Condition, MemberOp, Operand};
use crate::security::sddl::wellknown::WellKnownSid;
use alloc::string::{String, ToString};
use alloc::vec;
use crate::security::sddl::codec::{
    ACCESS_GENERIC_ALL, ACCESS_GENERIC_READ, ACE_FLAG_CONTAINER_INHERIT, SecurityDescriptor,
};
use crate::security::sddl::wire::Sid;

// Re-roll bytes through both pipelines and confirm the textual form is
// stable.
fn round_trip(sddl: &str) -> String {
    let builder = parse(sddl).expect("parse");
    let bytes = builder.build().expect("build");
    let sd = SecurityDescriptor::parse(&bytes).expect("re-parse");
    format(&sd).expect("format")
}

// ---- Top-level SD parse/format ----

#[test]
fn empty_input_is_an_error() {
    assert!(matches!(parse(""), Err(SddlError::Empty)));
}

#[test]
fn owner_and_group_round_trip() {
    let s = "O:SYG:BA";
    assert_eq!(round_trip(s), s);
}

#[test]
fn raw_sid_literal_round_trips() {
    // A domain-user SID that has no two-letter alias.
    let s = "O:S-1-5-21-1234-5678-9012-1001";
    assert_eq!(round_trip(s), s);
}

#[test]
fn simple_dacl_round_trips() {
    let s = "O:SYG:BAD:(A;;FA;;;BA)(A;;FR;;;BU)";
    assert_eq!(round_trip(s), s);
}

#[test]
fn protected_dacl_emits_p_flag() {
    let s = "D:P(A;;FA;;;SY)";
    assert_eq!(round_trip(s), s);
}

#[test]
fn auto_inherited_dacl_emits_ai_flag() {
    let s = "D:AI(A;;FA;;;SY)";
    assert_eq!(round_trip(s), s);
}

#[test]
fn dacl_and_sacl_together_round_trip() {
    let s = "D:(A;;FA;;;BA)S:(AU;FA;FA;;;WD)";
    assert_eq!(round_trip(s), s);
}

// ---- ACE flags ----

#[test]
fn ace_flags_round_trip() {
    // Container-inherit + object-inherit + no-propagate.
    let s = "D:(A;CIOINP;FA;;;BA)";
    assert_eq!(round_trip(s), s);
}

#[test]
fn audit_flags_round_trip() {
    let s = "S:(AU;SAFA;FA;;;BA)";
    assert_eq!(round_trip(s), s);
}

#[test]
fn inherited_flag_is_emitted_on_round_trip() {
    // The inherited bit can't be authored from text in real SDDL (the
    // kernel sets it), but our parser accepts ID for symmetry; the
    // formatter emits it when the bit is set on the wire ACE.
    let s = "D:(A;ID;FA;;;BA)";
    assert_eq!(round_trip(s), s);
}

// ---- Rights ----

#[test]
fn generic_rights_round_trip() {
    let s = "D:(A;;GA;;;SY)";
    assert_eq!(round_trip(s), s);
}

#[test]
fn standard_rights_round_trip() {
    let s = "D:(A;;SDRCWDWO;;;SY)";
    assert_eq!(round_trip(s), s);
}

#[test]
fn unknown_rights_bits_become_hex_suffix() {
    // GA = 0x1000_0000 plus 0x0010_0000 (SYNCHRONIZE — no SDDL code) —
    // the formatter must emit GA plus the residue as hex.
    let mask = 0x1010_0000u32;
    let ace = AceBuilder::allow(WellKnownSid::LocalSystem, mask).build();
    let aref = crate::security::sddl::codec::AceRef {
        ace_type: ace[0],
        flags: ace[1],
        size: u16::from_le_bytes([ace[2], ace[3]]),
        body: &ace[4..],
    };
    let s = format_ace(&aref).expect("format");
    assert!(s.contains("GA"));
    assert!(s.contains("0x"));
}

#[test]
fn hex_rights_parse_and_format_round_trip() {
    let s = "D:(A;;0x1234;;;SY)";
    // Parse and reformat — the formatter will emit the largest matching
    // composite first; 0x1234 has no composite match, so it round-trips
    // verbatim (lowercase).
    assert_eq!(round_trip(s), "D:(A;;0x1234;;;SY)");
}

// ---- Object ACEs ----

#[test]
fn object_ace_round_trips_with_guids() {
    let s = "D:(OA;;GR;11111111-2222-3333-4444-555555555555;\
             66666666-7777-8888-9999-aaaaaaaaaaaa;BA)";
    assert_eq!(round_trip(s), s);
}

#[test]
fn object_ace_round_trips_with_one_guid() {
    let s = "D:(OA;;GR;11111111-2222-3333-4444-555555555555;;BA)";
    assert_eq!(round_trip(s), s);
}

#[test]
fn object_ace_with_no_guids_still_works() {
    let s = "D:(OA;;GR;;;BA)";
    assert_eq!(round_trip(s), s);
}

#[test]
fn object_guid_on_simple_ace_is_rejected() {
    let s = "D:(A;;FA;11111111-2222-3333-4444-555555555555;;BA)";
    let err = parse(s).unwrap_err();
    assert!(matches!(err, SddlError::ObjectFieldsOnNonObjectAce(_)));
}

// ---- Mandatory label / scoped policy ----

#[test]
fn mandatory_label_round_trips() {
    // High IL, no-write-up policy.
    let s = "S:(ML;;NW;;;HI)";
    assert_eq!(round_trip(s), s);
}

#[test]
fn scoped_policy_id_round_trips() {
    let s = "S:(SP;;;;;SY)";
    assert_eq!(round_trip(s), s);
}

// ---- Conditional / callback ACEs ----

#[test]
fn conditional_ace_simple_compare_round_trips() {
    let sddl = "D:(XA;;FA;;;BU;(@User.title == \"VP\"))";
    let got = round_trip(sddl);
    // Operator spacing is canonical: single space either side.
    assert_eq!(got, sddl);
}

#[test]
fn conditional_ace_membership_round_trips() {
    let sddl = "D:(XA;;FA;;;BU;(Member_of {SID(BA)}))";
    let got = round_trip(sddl);
    assert_eq!(got, sddl);
}

#[test]
fn conditional_ace_logical_combination_round_trips() {
    let sddl = "D:(XA;;FA;;;BU;(Exists @User.dept && @User.clearance >= 3))";
    let got = round_trip(sddl);
    assert_eq!(got, sddl);
}

#[test]
fn conditional_ace_object_round_trips() {
    let sddl = "D:(ZA;;GR;11111111-2222-3333-4444-555555555555;;\
                BU;(@User.level == 10))";
    let got = round_trip(sddl);
    assert_eq!(got, sddl);
}

// ---- Resource attribute ----

#[test]
fn resource_attribute_int64_round_trips() {
    let sddl = "S:(RA;;;;;WD;(\"Confidentiality\",TI,0x0,3))";
    assert_eq!(round_trip(sddl), sddl);
}

#[test]
fn resource_attribute_string_multi_value_round_trips() {
    let sddl = "S:(RA;;;;;WD;(\"Dept\",TS,0x0,\"sales\",\"eng\"))";
    assert_eq!(round_trip(sddl), sddl);
}

#[test]
fn resource_attribute_bool_round_trips() {
    let sddl = "S:(RA;;;;;WD;(\"IsManaged\",TB,0x0,1))";
    assert_eq!(round_trip(sddl), sddl);
}

// ---- Fragment-level helpers ----

#[test]
fn parse_acl_extracts_flag_bits() {
    let parsed = parse_acl("P(A;;FA;;;BA)", AclKind::Dacl).expect("parse");
    assert!(parsed.control & crate::security::sddl::codec::SE_DACL_PROTECTED != 0);
    assert!(parsed.control & crate::security::sddl::codec::SE_DACL_PRESENT != 0);
    let bytes = parsed.acl.build().expect("build");
    assert!(!bytes.is_empty());
}

#[test]
fn parse_ace_basic() {
    let ace = parse_ace("A;;FA;;;BA").expect("parse");
    let bytes = ace.build();
    assert_eq!(bytes[0], crate::security::sddl::codec::ACE_TYPE_ACCESS_ALLOWED);
}

#[test]
fn format_ace_basic() {
    let bytes = AceBuilder::allow(WellKnownSid::BuiltinAdministrators, 0x001F_01FF).build();
    let aref = crate::security::sddl::codec::AceRef {
        ace_type: bytes[0],
        flags: bytes[1],
        size: u16::from_le_bytes([bytes[2], bytes[3]]),
        body: &bytes[4..],
    };
    let s = format_ace(&aref).expect("format");
    assert_eq!(s, "(A;;FA;;;BA)");
}

// ---- Negative cases ----

#[test]
fn unknown_ace_type_is_rejected() {
    let err = parse("D:(QQ;;FA;;;BA)").unwrap_err();
    assert!(matches!(err, SddlError::UnknownAceType(_)));
}

#[test]
fn unknown_flag_is_rejected() {
    let err = parse("D:(A;XX;FA;;;BA)").unwrap_err();
    assert!(matches!(err, SddlError::UnknownFlag(_)));
}

#[test]
fn unknown_right_is_rejected() {
    let err = parse("D:(A;;ZZ;;;BA)").unwrap_err();
    assert!(matches!(err, SddlError::UnknownRight(_)));
}

#[test]
fn domain_relative_alias_is_rejected() {
    let err = parse("O:DA").unwrap_err();
    assert!(matches!(err, SddlError::DomainRelativeAlias(_)));
}

#[test]
fn wrong_field_count_is_rejected() {
    let err = parse("D:(A;;FA;;BA)").unwrap_err();
    assert!(matches!(err, SddlError::WrongFieldCount(5)));
}

#[test]
fn malformed_guid_is_rejected() {
    let err = parse("D:(OA;;FA;not-a-guid;;BA)").unwrap_err();
    assert!(matches!(err, SddlError::BadGuid(_)));
}

#[test]
fn duplicate_section_is_rejected() {
    let err = parse("O:SYO:BA").unwrap_err();
    assert!(matches!(err, SddlError::DuplicateSection('O')));
}

// ---- Conditional expression parser unit tests ----

#[test]
fn cond_parse_int_compare() {
    let c = cond::parse("@User.x == 5").unwrap();
    assert_eq!(
        c,
        Condition::Compare {
            op: CompareOp::Eq,
            lhs: Operand::User("x".to_string()),
            rhs: Operand::Int(5),
        }
    );
}

#[test]
fn cond_parse_string_compare() {
    let c = cond::parse("@User.dept == \"eng\"").unwrap();
    assert_eq!(
        c,
        Condition::Compare {
            op: CompareOp::Eq,
            lhs: Operand::User("dept".to_string()),
            rhs: Operand::Str("eng".to_string()),
        }
    );
}

#[test]
fn cond_parse_member_with_sid_composite() {
    let c = cond::parse("Member_of {SID(BA)}").unwrap();
    assert!(matches!(
        c,
        Condition::Member {
            op: MemberOp::MemberOf,
            ..
        }
    ));
}

#[test]
fn cond_parse_and_or_precedence() {
    // && binds tighter than || — "a && b || c" parses as "(a && b) || c".
    let c = cond::parse("Exists @User.a && Exists @User.b || Exists @User.c").unwrap();
    match c {
        Condition::Or(lhs, rhs) => {
            assert!(matches!(*lhs, Condition::And(_, _)));
            assert!(matches!(*rhs, Condition::Exists(_)));
        }
        _ => panic!("expected Or at root"),
    }
}

#[test]
fn cond_parse_negation() {
    let c = cond::parse("!Exists @User.x").unwrap();
    assert!(matches!(c, Condition::Not(_)));
}

#[test]
fn cond_parse_octet_literal() {
    let c = cond::parse("@User.token == #deadbeef").unwrap();
    if let Condition::Compare {
        rhs: Operand::Octet(bytes),
        ..
    } = c
    {
        assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    } else {
        panic!("expected octet operand");
    }
}

#[test]
fn cond_format_canonical_spacing() {
    let c = Condition::Compare {
        op: CompareOp::Eq,
        lhs: Operand::User("x".into()),
        rhs: Operand::Int(5),
    };
    assert_eq!(cond::format(&c), "@User.x == 5");
}

#[test]
fn cond_artx_round_trip_via_condition_encode() {
    // Build a condition with the in-tree encoder, decode with our decoder,
    // confirm equal.
    let c = Condition::Exists(Operand::User("clearance".into())).and(Condition::Compare {
        op: CompareOp::Gt,
        lhs: Operand::User("level".into()),
        rhs: Operand::Int(-1),
    });
    let bytes = c.encode();
    let decoded = cond::decode_artx(&bytes).unwrap();
    assert_eq!(decoded, c);
}

#[test]
fn cond_artx_round_trip_member_of() {
    let admins = Sid::new(1, 5, vec![32, 544]);
    let c = Condition::Member {
        op: MemberOp::MemberOf,
        operand: Operand::Composite(vec![Operand::Sid(admins)]),
    };
    let bytes = c.encode();
    let decoded = cond::decode_artx(&bytes).unwrap();
    assert_eq!(decoded, c);
}

// ---- Section ordering + bare D: ----

#[test]
fn out_of_order_sections_are_canonicalised() {
    // Input order: G, O, S, D. Output must be O, G, D, S.
    let s = "G:BAO:SYS:(AU;FA;FA;;;WD)D:(A;;FA;;;BA)";
    let out = round_trip(s);
    assert_eq!(out, "O:SYG:BAD:(A;;FA;;;BA)S:(AU;FA;FA;;;WD)");
}

// ---- Builder-level use ----

#[test]
fn programmatic_build_then_format() {
    let sd = SdBuilder::new()
        .owner(WellKnownSid::LocalSystem)
        .group(WellKnownSid::BuiltinAdministrators)
        .dacl(
            AclBuilder::new()
                .ace(
                    AceBuilder::allow(WellKnownSid::BuiltinAdministrators, ACCESS_GENERIC_ALL)
                        .flags(ACE_FLAG_CONTAINER_INHERIT),
                )
                .ace(AceBuilder::allow(
                    WellKnownSid::BuiltinUsers,
                    ACCESS_GENERIC_READ,
                )),
        )
        .build()
        .unwrap();
    let parsed = SecurityDescriptor::parse(&sd).unwrap();
    let s = format(&parsed).unwrap();
    assert_eq!(s, "O:SYG:BAD:(A;CI;GA;;;BA)(A;;GR;;;BU)");
}

// ---- parse_sid (public string → Sid) ----

#[test]
fn parse_sid_accepts_literal() {
    assert_eq!(
        parse_sid("S-1-5-18").unwrap(),
        WellKnownSid::LocalSystem.to_sid()
    );
}

#[test]
fn parse_sid_accepts_alias() {
    assert_eq!(
        parse_sid("BA").unwrap(),
        WellKnownSid::BuiltinAdministrators.to_sid()
    );
}

#[test]
fn parse_sid_alias_is_case_insensitive() {
    assert_eq!(
        parse_sid("ba").unwrap(),
        WellKnownSid::BuiltinAdministrators.to_sid()
    );
}

#[test]
fn parse_sid_trims_whitespace() {
    assert_eq!(
        parse_sid("  SY  ").unwrap(),
        WellKnownSid::LocalSystem.to_sid()
    );
}

#[test]
fn parse_sid_accepts_integrity_level_literal() {
    assert_eq!(
        parse_sid("S-1-16-12288").unwrap(),
        WellKnownSid::HighIl.to_sid()
    );
}

#[test]
fn parse_sid_rejects_domain_relative_alias() {
    let err = parse_sid("DA").unwrap_err();
    assert!(matches!(err, SddlError::DomainRelativeAlias(_)));
}

#[test]
fn parse_sid_rejects_empty() {
    let err = parse_sid("").unwrap_err();
    assert!(matches!(err, SddlError::BadSid(_)));
}

#[test]
fn parse_sid_rejects_garbage() {
    let err = parse_sid("notasid").unwrap_err();
    assert!(matches!(err, SddlError::BadSid(_)));
}
