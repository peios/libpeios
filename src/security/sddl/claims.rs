// `@Local` claim-attribute array encoding.
//
// The AccessCheck ABI accepts a buffer of claim attributes used by
// conditional ACEs. Each attribute is a named, typed, multi-valued
// entry. The wire format is offset-based:
//
//   array  := entry*
//   entry  := [entry_len: u32] [entry_payload: entry_len bytes]
//   payload:
//     [0]  name_offset    u32   (offset into payload to the UTF-16 name)
//     [4]  value_type     u16
//     [6]  _pad           u16
//     [8]  flags          u32
//     [12] value_count    u32
//     [16] value_offset   u32 * value_count
//     ...  name + value data, addressed by the offsets above ...
//
// Values are addressed by a per-value offset (relative to payload
// start) into the "value slot" region. The slot contents depend on the
// value type:
//   INT64/UINT64/BOOLEAN — the slot holds an inline little-endian u64.
//   STRING/SID/OCTET     — the slot holds a u32 that is itself an
//                          offset to the real data:
//                            STRING → UTF-16 NUL-terminated string
//                            SID    → binary SID
//                            OCTET  → [len: u32][data]
//
// So indirect types cost a 4-byte pointer slot plus the data appended
// elsewhere in the payload.

use crate::security::sddl::Result;
use crate::security::sddl::Error;
use alloc::string::String;
use alloc::vec::Vec;
use crate::security::sddl::abi::{
    CLAIM_TYPE_BOOLEAN, CLAIM_TYPE_INT64, CLAIM_TYPE_OCTET, CLAIM_TYPE_SID, CLAIM_TYPE_STRING,
    CLAIM_TYPE_UINT64,
};
use crate::security::sddl::wire::Sid;

/// One value within a claim attribute. All values in a single
/// [`ClaimAttribute`] must be the same variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimValue {
    Int64(i64),
    UInt64(u64),
    Boolean(bool),
    String(String),
    Sid(Sid),
    Octet(Vec<u8>),
}

impl ClaimValue {
    /// The `CLAIM_TYPE_*` discriminant for this value's variant.
    fn type_code(&self) -> u16 {
        match self {
            ClaimValue::Int64(_) => CLAIM_TYPE_INT64,
            ClaimValue::UInt64(_) => CLAIM_TYPE_UINT64,
            ClaimValue::Boolean(_) => CLAIM_TYPE_BOOLEAN,
            ClaimValue::String(_) => CLAIM_TYPE_STRING,
            ClaimValue::Sid(_) => CLAIM_TYPE_SID,
            ClaimValue::Octet(_) => CLAIM_TYPE_OCTET,
        }
    }
}

/// A named, typed, multi-valued claim attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimAttribute {
    /// Attribute name (e.g. `"Department"`).
    pub name: String,
    /// `CLAIM_SECURITY_ATTRIBUTE_*` flags.
    pub flags: u32,
    /// The values. Must be non-empty and all the same `ClaimValue`
    /// variant — `encode` rejects violations.
    pub values: Vec<ClaimValue>,
}

impl ClaimAttribute {
    /// A claim attribute with the given name, no flags, and the
    /// supplied values.
    pub fn new(name: impl Into<String>, values: Vec<ClaimValue>) -> Self {
        ClaimAttribute {
            name: name.into(),
            flags: 0,
            values,
        }
    }

    /// Set the `CLAIM_SECURITY_ATTRIBUTE_*` flags.
    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Encode this attribute as one `CLAIM_SECURITY_ATTRIBUTE` claim
    /// entry (PSD-004 §3.9) — the bare entry, no length prefix.
    ///
    /// This is the single-entry-container form: it is exactly the
    /// `ApplicationData` body of a `SYSTEM_RESOURCE_ATTRIBUTE_ACE`. For
    /// the multi-entry array form (token / `@Local` claims) use
    /// [`encode_claims_array`].
    ///
    /// # Errors
    /// [`Error::Encode`] if the attribute has no values or its values are
    /// not all the same type.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.values.is_empty() {
            return Err(Error::Encode("claim attribute has no values"));
        }
        let value_type = self.values[0].type_code();
        for v in &self.values {
            if v.type_code() != value_type {
                return Err(Error::Encode(
                    "claim attribute values are not all the same type",
                ));
            }
        }
        let count = self.values.len();
        if count > u32::MAX as usize {
            return Err(Error::Encode("claim attribute has too many values"));
        }

        // Fixed prefix: 16-byte header + 4-byte offset per value.
        let prefix_len = 16 + count * 4;
        let mut payload = alloc::vec![0u8; prefix_len];

        // Append the name (UTF-16 NUL-terminated), record its offset.
        let name_offset = payload.len() as u32;
        append_utf16_cstr(&mut payload, &self.name);

        // Lay out the value slots. Inline types (Int64/UInt64/Boolean)
        // put their 8-byte datum directly in the slot. Indirect types
        // (String/Sid/Octet) put a u32 pointer in the slot and have
        // their data appended afterwards.
        let mut value_offsets: Vec<u32> = Vec::with_capacity(count);
        // (slot byte position, real data) for indirect values.
        let mut indirect: Vec<(usize, Vec<u8>)> = Vec::new();
        for v in &self.values {
            let slot = payload.len();
            value_offsets.push(slot as u32);
            match v {
                ClaimValue::Int64(n) => {
                    payload.extend_from_slice(&n.to_le_bytes());
                }
                ClaimValue::UInt64(n) => {
                    payload.extend_from_slice(&n.to_le_bytes());
                }
                ClaimValue::Boolean(b) => {
                    let n: u64 = if *b { 1 } else { 0 };
                    payload.extend_from_slice(&n.to_le_bytes());
                }
                ClaimValue::String(s) => {
                    payload.extend_from_slice(&0u32.to_le_bytes()); // ptr placeholder
                    indirect.push((slot, utf16_cstr_bytes(s)));
                }
                ClaimValue::Sid(sid) => {
                    payload.extend_from_slice(&0u32.to_le_bytes());
                    indirect.push((slot, sid.encode()));
                }
                ClaimValue::Octet(data) => {
                    payload.extend_from_slice(&0u32.to_le_bytes());
                    let mut blob = Vec::with_capacity(4 + data.len());
                    blob.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    blob.extend_from_slice(data);
                    indirect.push((slot, blob));
                }
            }
        }

        // Append the indirect data and backfill each slot's u32 pointer.
        for (slot, data) in indirect {
            let data_offset = payload.len() as u32;
            payload[slot..slot + 4].copy_from_slice(&data_offset.to_le_bytes());
            payload.extend_from_slice(&data);
        }

        // Backfill the header.
        payload[0..4].copy_from_slice(&name_offset.to_le_bytes());
        payload[4..6].copy_from_slice(&value_type.to_le_bytes());
        // bytes 6..8 are padding, already zero.
        payload[8..12].copy_from_slice(&self.flags.to_le_bytes());
        payload[12..16].copy_from_slice(&(count as u32).to_le_bytes());
        for (i, off) in value_offsets.iter().enumerate() {
            let at = 16 + i * 4;
            payload[at..at + 4].copy_from_slice(&off.to_le_bytes());
        }

        Ok(payload)
    }

    /// The length-prefixed entry form used inside a multi-entry claims
    /// array: `[entry_len: u32][entry bytes]`.
    fn encode_entry(&self) -> Result<Vec<u8>> {
        let payload = self.encode()?;
        let mut entry = Vec::with_capacity(4 + payload.len());
        entry.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        entry.extend_from_slice(&payload);
        Ok(entry)
    }
}

/// Encode a slice of claim attributes into the `@Local` claims array
/// wire format. An empty slice produces an empty `Vec`.
pub fn encode_claims_array(claims: &[ClaimAttribute]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for c in claims {
        out.extend_from_slice(&c.encode_entry()?);
    }
    Ok(out)
}

/// Append `s` as a UTF-16LE NUL-terminated string.
fn append_utf16_cstr(buf: &mut Vec<u8>, s: &str) {
    for unit in s.encode_utf16() {
        buf.extend_from_slice(&unit.to_le_bytes());
    }
    buf.extend_from_slice(&0u16.to_le_bytes());
}

/// `s` as standalone UTF-16LE NUL-terminated bytes.
fn utf16_cstr_bytes(s: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity((s.len() + 1) * 2);
    append_utf16_cstr(&mut buf, s);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn empty_claims_array_is_empty() {
        assert!(encode_claims_array(&[]).unwrap().is_empty());
    }

    #[test]
    fn single_int64_claim_layout() {
        let claim = ClaimAttribute::new("Level", vec![ClaimValue::Int64(7)]);
        let bytes = encode_claims_array(&[claim]).unwrap();
        // entry_len prefix + payload.
        let entry_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(entry_len as usize, bytes.len() - 4);
        let payload = &bytes[4..];
        // header: name_offset, value_type, pad, flags, value_count.
        let value_type = u16::from_le_bytes([payload[4], payload[5]]);
        assert_eq!(value_type, CLAIM_TYPE_INT64);
        let value_count = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
        assert_eq!(value_count, 1);
        // name "Level" = 5 UTF-16 units + NUL = 12 bytes; value is u64.
        let name_offset =
            u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        // payload prefix is 16 (header) + 4 (one value offset) = 20.
        assert_eq!(name_offset, 20);
    }

    #[test]
    fn rejects_mixed_value_types() {
        let claim = ClaimAttribute::new(
            "Mixed",
            vec![ClaimValue::Int64(1), ClaimValue::Boolean(true)],
        );
        assert!(matches!(
            encode_claims_array(&[claim]),
            Err(Error::Encode(_))
        ));
    }

    #[test]
    fn rejects_empty_values() {
        let claim = ClaimAttribute::new("Empty", vec![]);
        assert!(matches!(
            encode_claims_array(&[claim]),
            Err(Error::Encode(_))
        ));
    }

    #[test]
    fn encode_is_the_array_entry_without_its_length_prefix() {
        let claim = ClaimAttribute::new("Level", vec![ClaimValue::Int64(7)]);
        let entry = claim.encode().unwrap();
        let arrayed = encode_claims_array(&[claim]).unwrap();
        // The array form is the bare entry with a 4-byte length prefix.
        assert_eq!(arrayed.len(), entry.len() + 4);
        assert_eq!(&arrayed[4..], &entry[..]);
        let prefix = u32::from_le_bytes([arrayed[0], arrayed[1], arrayed[2], arrayed[3]]);
        assert_eq!(prefix as usize, entry.len());
    }

    #[test]
    fn multi_value_string_claim() {
        let claim = ClaimAttribute::new(
            "Tags",
            vec![
                ClaimValue::String("alpha".into()),
                ClaimValue::String("beta".into()),
            ],
        );
        let bytes = encode_claims_array(&[claim]).unwrap();
        let payload = &bytes[4..];
        let value_count = u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
        assert_eq!(value_count, 2);
        // Two distinct value offsets in the table at byte 16.
        let off0 = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let off1 = u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]);
        assert_ne!(off0, off1);
    }
}
