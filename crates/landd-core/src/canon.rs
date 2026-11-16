//! Canonical JSON: one byte string per value.
//!
//! Object keys are sorted by their UTF-8 bytes, there is no insignificant
//! whitespace, strings use the shortest escape, and numbers are integers.
//! Floats are refused: their text form is not unique, so they cannot sit
//! under a digest or a signature.
//!
//! This is landd's own canonical form, not RFC 8785 (JCS): JCS sorts keys by
//! UTF-16 code units and serializes floats. Nothing outside landd is
//! expected to produce these bytes. `-0`, `1.0`, `1e2` and duplicate keys
//! are all refused by [`CanonicalJson::from_untrusted`].

use crate::digest::Digest32;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum CanonError {
    #[error("non-integer number {0} has no canonical form")]
    Float(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("input is valid JSON but not in canonical form")]
    NotCanonical,
}

pub fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CanonError> {
    let value = serde_json::to_value(value)?;
    let mut out = Vec::with_capacity(128);
    write_value(&value, &mut out)?;
    Ok(out)
}

pub fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(i) = n.as_i64() {
                out.extend_from_slice(i.to_string().as_bytes());
            } else {
                return Err(CanonError::Float(n.to_string()));
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(&map[key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes()),
            c => out.extend_from_slice(c.encode_utf8(&mut [0u8; 4]).as_bytes()),
        }
    }
    out.push(b'"');
}

/// Bytes known to be in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CanonicalJson(Vec<u8>);

impl CanonicalJson {
    pub fn of<T: Serialize + ?Sized>(value: &T) -> Result<Self, CanonError> {
        canonical_json(value).map(Self)
    }

    /// Accept bytes from outside only when they already are canonical.
    pub fn from_untrusted(bytes: &[u8]) -> Result<Self, CanonError> {
        let value: Value = serde_json::from_slice(bytes)?;
        let mut again = Vec::with_capacity(bytes.len());
        write_value(&value, &mut again)?;
        if again != bytes {
            return Err(CanonError::NotCanonical);
        }
        Ok(Self(again))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn digest(&self) -> Digest32 {
        Digest32::blake3(&self.0)
    }

    pub fn parse<T: DeserializeOwned>(&self) -> Result<T, CanonError> {
        Ok(serde_json::from_slice(&self.0)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_sort_and_whitespace_vanishes() {
        let a = canonical_json(&json!({"b": 1, "a": [true, null, "x"], "c": {"z": -3, "y": 2}})).unwrap();
        assert_eq!(a, br#"{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":-3}}"#);
        let reordered: Value = serde_json::from_str(r#" { "c": {"y": 2, "z": -3}, "a": [true, null, "x"], "b": 1 } "#).unwrap();
        assert_eq!(canonical_json(&reordered).unwrap(), a);
    }

    #[test]
    fn strings_use_shortest_escapes() {
        let got = canonical_json(&json!("a\"b\\c\n\u{01}é")).unwrap();
        assert_eq!(got, "\"a\\\"b\\\\c\\n\\u0001é\"".as_bytes());
    }

    #[test]
    fn tooth_floats_are_refused() {
        assert!(matches!(canonical_json(&json!({"x": 1.5})), Err(CanonError::Float(_))));
        assert!(canonical_json(&json!({"x": u64::MAX, "y": i64::MIN})).is_ok());
    }

    #[test]
    fn tooth_untrusted_bytes_must_already_be_canonical() {
        assert!(CanonicalJson::from_untrusted(br#"{"a":1,"b":2}"#).is_ok());
        assert!(matches!(CanonicalJson::from_untrusted(br#"{"b":2,"a":1}"#), Err(CanonError::NotCanonical)));
        assert!(matches!(CanonicalJson::from_untrusted(br#"{"a": 1}"#), Err(CanonError::NotCanonical)));
        assert!(CanonicalJson::from_untrusted(b"{").is_err());
    }

    #[test]
    fn digest_is_stable_across_key_order() {
        let one = CanonicalJson::of(&json!({"k": "v", "n": 7})).unwrap();
        let two = CanonicalJson::of(&json!({"n": 7, "k": "v"})).unwrap();
        assert_eq!(one.digest(), two.digest());
        assert_ne!(one.digest(), CanonicalJson::of(&json!({"n": 8, "k": "v"})).unwrap().digest());
    }
}
