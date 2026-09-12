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

/// `SU` is the Service identity (`S-1-5-6`) — the group stapled onto every
/// token minted for a service logon, and therefore the grantee any
/// service-reachable socket names. Without the alias a descriptor has to spell
/// the literal SID, which is what made the notify-socket descriptor unreadable.
#[test]
fn parse_sid_accepts_the_service_alias() {
    assert_eq!(parse_sid("SU").unwrap(), WellKnownSid::Service.to_sid());
    assert_eq!(parse_sid("SU").unwrap().to_string(), "S-1-5-6");
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

// ---- Shared conformance corpus (PEI-562) ----
//
// The cases libpeios and libp-go must agree on. The same file, byte for
// byte, lives at `libp-go/sddl/testdata/sddl-conformance.txt` and is read
// by that package's `conformance_test.go`; the corpus header explains why
// it is a copy rather than a genuinely shared file, and what to do when
// changing it.

const CONFORMANCE: &str = include_str!("../testdata/sddl-conformance.txt");

/// Must match the corpus's `# revision:` line. Bumping the corpus without
/// bumping this constant fails here, which is how a corpus updated on one
/// side and not the other gets caught.
const CONFORMANCE_REVISION: u32 = 1;

struct ConformanceCase {
    line: usize,
    kind: &'static str,
    arg: &'static str,
    want: &'static str,
}

fn conformance_cases() -> alloc::vec::Vec<ConformanceCase> {
    let mut cases = alloc::vec::Vec::new();
    let mut revision = None;
    for (index, text) in CONFORMANCE.lines().enumerate() {
        let line = index + 1;
        if let Some(rest) = text.strip_prefix("# revision:") {
            revision = Some(rest.trim().parse::<u32>().expect("malformed revision line"));
            continue;
        }
        if text.starts_with('#') || text.trim().is_empty() {
            continue;
        }
        let mut fields = text.split('\t');
        let kind = fields.next().expect("split yields at least one field");
        let arg = fields
            .next()
            .unwrap_or_else(|| panic!("corpus line {line}: {kind} has no argument"));
        let want = fields.next().unwrap_or("");
        assert!(
            fields.next().is_none(),
            "corpus line {line}: too many tab-separated fields"
        );
        match kind {
            "rights" | "sid" => assert!(
                !want.is_empty(),
                "corpus line {line}: {kind} takes two fields"
            ),
            "badrights" => assert!(
                want.is_empty(),
                "corpus line {line}: badrights takes one field"
            ),
            other => panic!("corpus line {line}: unknown case kind {other:?}"),
        }
        cases.push(ConformanceCase {
            line,
            kind,
            arg,
            want,
        });
    }
    assert_eq!(
        revision,
        Some(CONFORMANCE_REVISION),
        "the corpus and its copy in libp-go must be updated together"
    );
    assert!(!cases.is_empty(), "corpus is empty");
    cases
}

#[test]
fn conformance_rights_fields() {
    let mut checked = 0usize;
    for case in conformance_cases().iter().filter(|c| c.kind == "rights") {
        checked += 1;
        let want = u32::from_str_radix(case.want.trim_start_matches("0x"), 16)
            .unwrap_or_else(|_| panic!("corpus line {}: bad expected mask", case.line));
        let got = parse_rights(case.arg).unwrap_or_else(|e| {
            panic!(
                "corpus line {}: parse_rights({:?}) failed: {e:?}",
                case.line, case.arg
            )
        });
        assert_eq!(
            got, want,
            "corpus line {}: parse_rights({:?})",
            case.line, case.arg
        );
    }
    assert!(checked > 0, "no rights cases in the corpus");
}

#[test]
fn conformance_bad_rights_fields() {
    let mut checked = 0usize;
    for case in conformance_cases().iter().filter(|c| c.kind == "badrights") {
        checked += 1;
        assert!(
            parse_rights(case.arg).is_err(),
            "corpus line {}: parse_rights({:?}) should have failed",
            case.line,
            case.arg
        );
    }
    assert!(checked > 0, "no badrights cases in the corpus");
}

#[test]
fn conformance_sid_aliases() {
    let mut checked = 0usize;
    for case in conformance_cases().iter().filter(|c| c.kind == "sid") {
        checked += 1;
        let sid = vocab::sid_from_alias(case.arg)
            .unwrap_or_else(|| panic!("corpus line {}: unknown alias {:?}", case.line, case.arg));
        assert_eq!(
            sid.to_string(),
            case.want,
            "corpus line {}: {:?} resolves to the wrong SID",
            case.line,
            case.arg
        );
        assert_eq!(
            vocab::alias_from_sid(&sid),
            Some(case.arg),
            "corpus line {}: {} must format back as {:?}",
            case.line,
            case.want,
            case.arg
        );
        // And through the whole pipeline, which is the round trip the
        // ticket asks for: text in, wire bytes, text out.
        let text = alloc::format!("O:{}", case.arg);
        assert_eq!(round_trip(&text), text, "corpus line {}", case.line);
    }
    assert!(checked > 0, "no sid cases in the corpus");
}

#[test]
fn mixed_rights_field_in_whole_descriptor() {
    // The case from the ticket: /tmp's descriptor wants FILE_ADD_FILE and
    // FILE_ADD_SUBDIRECTORY, which have no two-letter mnemonic.
    assert_eq!(parse_rights("FRFX0x6").unwrap(), 0x0012_00AF);
    assert!(parse("D:(A;;FRFX0x6;;;WD)").is_ok());
}

#[test]
fn ru_is_builtin_not_domain_relative() {
    // BUILTIN\Pre-Windows 2000 Compatible Access reads like a domain alias
    // and is not one; libpeios used to reject it as domain-relative.
    assert_eq!(
        parse_sid("RU").unwrap().to_string(),
        "S-1-5-32-554"
    );
}
