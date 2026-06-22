// Conditional ACE expressions — the typed AST and its bytecode encoder.
//
// A conditional (callback) ACE only takes effect when its expression
// evaluates TRUE against the caller's token and the object's resource
// attributes. The expression lives in the ACE's `ApplicationData` as the
// "artx" bytecode of PSD-004 §3.11: an `artx` magic followed by a postfix
// (reverse-Polish) token stream.
//
// This module provides:
//   - `Operand`   — a literal value or an attribute reference.
//   - `Condition` — a tree of comparisons, membership tests, and logical
//                   combinators that evaluates to TRUE / FALSE / UNKNOWN.
//   - `Condition::encode` — flatten the tree to postfix and emit the
//                   `artx`-prefixed, DWORD-padded bytecode.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use crate::security::sddl::wire::Sid;

// ---------------------------------------------------------------------------
// Bytecode alphabet (PSD-004 §3.11). Postfix token stream; all multibyte
// integers little-endian.
// ---------------------------------------------------------------------------

const TOK_INT64: u8 = 0x04;
const TOK_STRING: u8 = 0x10;
const TOK_OCTET: u8 = 0x18;
const TOK_COMPOSITE: u8 = 0x50;
const TOK_SID: u8 = 0x51;
const TOK_EXISTS: u8 = 0x87;
const TOK_NOT_EXISTS: u8 = 0x8d;
const TOK_AND: u8 = 0xa0;
const TOK_OR: u8 = 0xa1;
const TOK_NOT: u8 = 0xa2;
const TOK_ATTR_LOCAL: u8 = 0xf8;
const TOK_ATTR_USER: u8 = 0xf9;
const TOK_ATTR_RESOURCE: u8 = 0xfa;
const TOK_ATTR_DEVICE: u8 = 0xfb;

/// Sign byte: negative literal.
const SIGN_NEGATIVE: u8 = 0x02;
/// Sign byte: no sign (evaluated as the positive magnitude).
const SIGN_NONE: u8 = 0x03;
/// Base byte: decimal (display-only; the value is always 2's complement).
const BASE_DECIMAL: u8 = 0x02;

/// A binary relational operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `Contains` — the left operand includes every value of the right.
    Contains,
    /// `Any_of` — the right operand includes any value of the left.
    AnyOf,
    /// `Not_Contains` — the inverse of `Contains`.
    NotContains,
    /// `Not_Any_of` — the inverse of `Any_of`.
    NotAnyOf,
}

impl CompareOp {
    fn byte_code(self) -> u8 {
        match self {
            CompareOp::Eq => 0x80,
            CompareOp::Ne => 0x81,
            CompareOp::Lt => 0x82,
            CompareOp::Le => 0x83,
            CompareOp::Gt => 0x84,
            CompareOp::Ge => 0x85,
            CompareOp::Contains => 0x86,
            CompareOp::AnyOf => 0x88,
            CompareOp::NotContains => 0x8e,
            CompareOp::NotAnyOf => 0x8f,
        }
    }
}

/// A SID-membership operator. The operand is a SID literal or a composite
/// of SID literals; the implicit subject is the caller's token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberOp {
    /// `Member_of` — the token's groups contain all of the operand.
    MemberOf,
    /// `Device_Member_of` — likewise, against device groups.
    DeviceMemberOf,
    /// `Member_of_Any` — the token's groups contain any of the operand.
    MemberOfAny,
    /// `Device_Member_of_Any` — likewise, against device groups.
    DeviceMemberOfAny,
    /// `Not_Member_of` — the inverse of `Member_of`.
    NotMemberOf,
    /// `Not_Device_Member_of` — the inverse of `Device_Member_of`.
    NotDeviceMemberOf,
    /// `Not_Member_of_Any` — the inverse of `Member_of_Any`.
    NotMemberOfAny,
    /// `Not_Device_Member_of_Any` — the inverse of `Device_Member_of_Any`.
    NotDeviceMemberOfAny,
}

impl MemberOp {
    fn byte_code(self) -> u8 {
        match self {
            MemberOp::MemberOf => 0x89,
            MemberOp::DeviceMemberOf => 0x8a,
            MemberOp::MemberOfAny => 0x8b,
            MemberOp::DeviceMemberOfAny => 0x8c,
            MemberOp::NotMemberOf => 0x90,
            MemberOp::NotDeviceMemberOf => 0x91,
            MemberOp::NotMemberOfAny => 0x92,
            MemberOp::NotDeviceMemberOfAny => 0x93,
        }
    }
}

/// An operand in a conditional expression — a literal value, an attribute
/// reference, or a composite grouping several operands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operand {
    /// A signed integer literal (encoded as an int64 token).
    Int(i64),
    /// A Unicode string literal.
    Str(String),
    /// A SID literal.
    Sid(Sid),
    /// An octet-string literal.
    Octet(Vec<u8>),
    /// A composite — an ordered, possibly heterogeneous group of
    /// operands. Used to supply a set of SIDs to a membership operator.
    Composite(Vec<Operand>),
    /// `@Local.<name>` — a local claim passed to AccessCheck.
    Local(String),
    /// `@User.<name>` — a claim from the caller's token.
    User(String),
    /// `@Resource.<name>` — a resource attribute from the object's SACL.
    Resource(String),
    /// `@Device.<name>` — a device claim from the caller's token.
    Device(String),
}

/// A conditional ACE expression. Evaluates to TRUE, FALSE, or UNKNOWN
/// against the caller's token and the object's resource attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// A binary relational comparison of two operands.
    Compare {
        /// The operator.
        op: CompareOp,
        /// Left-hand operand.
        lhs: Operand,
        /// Right-hand operand.
        rhs: Operand,
    },
    /// A SID-membership test against the caller's token.
    Member {
        /// The operator.
        op: MemberOp,
        /// The SID, or composite of SIDs, to test for.
        operand: Operand,
    },
    /// `Exists` — true if the operand is a present, non-null attribute.
    Exists(Operand),
    /// `Not_Exists` — the inverse of [`Exists`](Condition::Exists).
    NotExists(Operand),
    /// Logical negation.
    Not(Box<Condition>),
    /// Logical conjunction.
    And(Box<Condition>, Box<Condition>),
    /// Logical disjunction.
    Or(Box<Condition>, Box<Condition>),
}

impl Condition {
    /// Combine with `rhs` under logical AND.
    pub fn and(self, rhs: Condition) -> Condition {
        Condition::And(Box::new(self), Box::new(rhs))
    }

    /// Combine with `rhs` under logical OR.
    pub fn or(self, rhs: Condition) -> Condition {
        Condition::Or(Box::new(self), Box::new(rhs))
    }

    /// Logically negate this condition.
    pub fn negate(self) -> Condition {
        Condition::Not(Box::new(self))
    }

    /// Encode to the `artx`-prefixed conditional ACE bytecode (PSD-004
    /// §3.11): the magic, the expression's tokens in postfix order, then
    /// `0x00` padding to a 4-byte boundary. This is exactly the
    /// `ApplicationData` body of a callback (conditional) ACE.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"artx");
        emit_condition(self, &mut out);
        // The ApplicationData must be DWORD-aligned; trailing 0x00s are
        // valid Padding tokens.
        while out.len() % 4 != 0 {
            out.push(0x00);
        }
        out
    }
}

fn emit_condition(c: &Condition, out: &mut Vec<u8>) {
    match c {
        Condition::Compare { op, lhs, rhs } => {
            emit_operand(lhs, out);
            emit_operand(rhs, out);
            out.push(op.byte_code());
        }
        Condition::Member { op, operand } => {
            emit_operand(operand, out);
            out.push(op.byte_code());
        }
        Condition::Exists(o) => {
            emit_operand(o, out);
            out.push(TOK_EXISTS);
        }
        Condition::NotExists(o) => {
            emit_operand(o, out);
            out.push(TOK_NOT_EXISTS);
        }
        Condition::Not(inner) => {
            emit_condition(inner, out);
            out.push(TOK_NOT);
        }
        Condition::And(a, b) => {
            emit_condition(a, out);
            emit_condition(b, out);
            out.push(TOK_AND);
        }
        Condition::Or(a, b) => {
            emit_condition(a, out);
            emit_condition(b, out);
            out.push(TOK_OR);
        }
    }
}

fn emit_operand(o: &Operand, out: &mut Vec<u8>) {
    match o {
        Operand::Int(n) => {
            // int64 literal: tag, 8-byte 2's-complement value, sign, base.
            out.push(TOK_INT64);
            out.extend_from_slice(&n.to_le_bytes());
            out.push(if *n < 0 { SIGN_NEGATIVE } else { SIGN_NONE });
            out.push(BASE_DECIMAL);
        }
        Operand::Str(s) => {
            out.push(TOK_STRING);
            emit_len_prefixed(&utf16le(s), out);
        }
        Operand::Sid(sid) => {
            out.push(TOK_SID);
            emit_len_prefixed(&sid.encode(), out);
        }
        Operand::Octet(data) => {
            out.push(TOK_OCTET);
            emit_len_prefixed(data, out);
        }
        Operand::Composite(items) => {
            out.push(TOK_COMPOSITE);
            let mut inner = Vec::new();
            for it in items {
                emit_operand(it, &mut inner);
            }
            emit_len_prefixed(&inner, out);
        }
        Operand::Local(name) => emit_attr(TOK_ATTR_LOCAL, name, out),
        Operand::User(name) => emit_attr(TOK_ATTR_USER, name, out),
        Operand::Resource(name) => emit_attr(TOK_ATTR_RESOURCE, name, out),
        Operand::Device(name) => emit_attr(TOK_ATTR_DEVICE, name, out),
    }
}

fn emit_attr(tag: u8, name: &str, out: &mut Vec<u8>) {
    out.push(tag);
    emit_len_prefixed(&utf16le(name), out);
}

/// Emit a `u32` little-endian length followed by `data`.
fn emit_len_prefixed(data: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
}

/// `s` as UTF-16LE bytes — no NUL terminator. Conditional-bytecode
/// strings and attribute names are length-prefixed, not terminated.
fn utf16le(s: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(s.len() * 2);
    for unit in s.encode_utf16() {
        buf.extend_from_slice(&unit.to_le_bytes());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn artx_magic_and_dword_padding() {
        let bytes = Condition::Exists(Operand::User("dept".into())).encode();
        assert_eq!(&bytes[..4], b"artx");
        assert_eq!(bytes.len() % 4, 0);
    }

    #[test]
    fn int_literal_matches_spec_example() {
        // PSD-004 §3.11: decimal -1 as int64 →
        //   04, FF×8, 02 (negative), 02 (decimal).
        let mut out = Vec::new();
        emit_operand(&Operand::Int(-1), &mut out);
        assert_eq!(
            out,
            vec![
                0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x02
            ]
        );
    }

    #[test]
    fn positive_int_carries_no_sign() {
        let mut out = Vec::new();
        emit_operand(&Operand::Int(5), &mut out);
        assert_eq!(out[0], TOK_INT64);
        assert_eq!(out[9], SIGN_NONE);
        assert_eq!(out[10], BASE_DECIMAL);
    }

    #[test]
    fn string_literal_is_utf16_and_not_terminated() {
        let mut out = Vec::new();
        emit_operand(&Operand::Str("Hi".into()), &mut out);
        // tag + u32 length + two UTF-16 code units (4 bytes), no NUL.
        assert_eq!(out[0], TOK_STRING);
        assert_eq!(u32::from_le_bytes([out[1], out[2], out[3], out[4]]), 4);
        assert_eq!(out.len(), 1 + 4 + 4);
    }

    #[test]
    fn comparison_emits_operands_then_operator() {
        // @User.clearance >= @Resource.level
        let bytes = Condition::Compare {
            op: CompareOp::Ge,
            lhs: Operand::User("clearance".into()),
            rhs: Operand::Resource("level".into()),
        }
        .encode();
        assert_eq!(&bytes[..4], b"artx");
        // @User token first, @Resource second, >= operator after both.
        let user = bytes.iter().position(|&b| b == TOK_ATTR_USER).unwrap();
        let resource = bytes.iter().position(|&b| b == TOK_ATTR_RESOURCE).unwrap();
        let op = bytes.iter().position(|&b| b == 0x85).unwrap();
        assert!(user < resource && resource < op);
    }

    #[test]
    fn logical_operators_emit_their_tokens() {
        let bytes = Condition::Exists(Operand::User("a".into()))
            .and(Condition::Exists(Operand::User("b".into())))
            .negate()
            .encode();
        assert_eq!(bytes.iter().filter(|&&b| b == TOK_EXISTS).count(), 2);
        assert!(bytes.contains(&TOK_AND));
        assert!(bytes.contains(&TOK_NOT));
    }

    #[test]
    fn member_of_takes_a_sid_composite() {
        let admins = Sid::new(1, 5, vec![32, 544]);
        let bytes = Condition::Member {
            op: MemberOp::MemberOf,
            operand: Operand::Composite(vec![Operand::Sid(admins)]),
        }
        .encode();
        assert!(bytes.contains(&TOK_COMPOSITE));
        assert!(bytes.contains(&TOK_SID));
        assert!(bytes.contains(&0x89)); // Member_of
    }
}
