//! `Digest32` (BLAKE3) and `Oid` (git object id, SHA-1 or SHA-256).

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha1::{Digest as _, Sha1};
use std::fmt;
use std::str::FromStr;

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

/// Strict lowercase hex. Uppercase is rejected so one value has one spelling.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let raw = s.as_bytes();
    if raw.len() % 2 != 0 {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    raw.chunks_exact(2)
        .map(|pair| Some(nibble(pair[0])? << 4 | nibble(pair[1])?))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {what}: {input:?}")]
pub struct ParseIdError {
    pub what: &'static str,
    pub input: String,
}

/// A 32-byte BLAKE3 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest32([u8; 32]);

impl Digest32 {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Plain `BLAKE3(data)`.
    pub fn blake3(data: &[u8]) -> Self {
        Self(*blake3::hash(data).as_bytes())
    }

    /// Domain-separated digest over length-framed parts, so `["ab","c"]` and
    /// `["a","bc"]` never collide and no two domains share a preimage space.
    pub fn tagged(domain: &str, parts: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(domain);
        for part in parts {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        Self(*hasher.finalize().as_bytes())
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, ParseIdError> {
        hex_decode(s)
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .map(Self)
            .ok_or_else(|| ParseIdError { what: "digest", input: s.to_owned() })
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest32({})", self.to_hex())
    }
}

impl FromStr for Digest32 {
    type Err = ParseIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

/// Hex in text formats (JSON, TOML); the 32 raw bytes in binary ones.
impl Serialize for Digest32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_hex())
        } else {
            self.0.serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for Digest32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let text = String::deserialize(d)?;
            Self::from_hex(&text).map_err(de::Error::custom)
        } else {
            <[u8; 32]>::deserialize(d).map(Self)
        }
    }
}

/// A git object id: 20 bytes (SHA-1) or 32 bytes (SHA-256).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid {
    len: u8,
    bytes: [u8; 32],
}

impl Oid {
    pub fn from_slice(raw: &[u8]) -> Option<Self> {
        if raw.len() != 20 && raw.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 32];
        bytes[..raw.len()].copy_from_slice(raw);
        Some(Self { len: raw.len() as u8, bytes })
    }

    pub fn from_hex(s: &str) -> Result<Self, ParseIdError> {
        hex_decode(s)
            .and_then(|v| Self::from_slice(&v))
            .ok_or_else(|| ParseIdError { what: "git oid", input: s.to_owned() })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    pub fn to_hex(&self) -> String {
        hex_encode(self.as_bytes())
    }

    /// The all-zero id git uses for "no object" (ref creation and deletion).
    pub fn is_zero(&self) -> bool {
        self.as_bytes().iter().all(|b| *b == 0)
    }

    pub fn zero_sha1() -> Self {
        Self { len: 20, bytes: [0u8; 32] }
    }

    /// The SHA-1 blob id git would assign to `content`.
    pub fn git_blob_sha1(content: &[u8]) -> Self {
        let mut hasher = Sha1::new();
        hasher.update(format!("blob {}\0", content.len()).as_bytes());
        hasher.update(content);
        Self::from_slice(&hasher.finalize()).expect("sha1 is 20 bytes")
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Oid({})", self.to_hex())
    }
}

impl FromStr for Oid {
    type Err = ParseIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for Oid {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Oid {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::from_hex(&text).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_uppercase() {
        assert_eq!(hex_decode(&hex_encode(&[0, 1, 0xab, 0xff])).unwrap(), vec![0, 1, 0xab, 0xff]);
        assert!(hex_decode("AB").is_none());
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn git_blob_oid_matches_git() {
        // `printf 'hello\n' | git hash-object --stdin`
        assert_eq!(Oid::git_blob_sha1(b"hello\n").to_hex(), "ce013625030ba8dba906f756967f9e9ca394464a");
        // The empty blob.
        assert_eq!(Oid::git_blob_sha1(b"").to_hex(), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    }

    #[test]
    fn oid_accepts_sha1_and_sha256_widths_only() {
        assert!(Oid::from_hex(&"a".repeat(40)).is_ok());
        assert!(Oid::from_hex(&"a".repeat(64)).is_ok());
        assert!(Oid::from_hex(&"a".repeat(39)).is_err());
        assert!(Oid::from_hex(&"a".repeat(42)).is_err());
        assert!(Oid::zero_sha1().is_zero());
    }

    #[test]
    fn tagged_digest_frames_parts_and_separates_domains() {
        let ab_c = Digest32::tagged("landd test", &[b"ab", b"c"]);
        let a_bc = Digest32::tagged("landd test", &[b"a", b"bc"]);
        assert_ne!(ab_c, a_bc);
        assert_ne!(ab_c, Digest32::tagged("landd other", &[b"ab", b"c"]));
        assert_eq!(ab_c, Digest32::tagged("landd test", &[b"ab", b"c"]));
    }

    #[test]
    fn serde_uses_hex_strings() {
        let d = Digest32::blake3(b"x");
        let text = serde_json::to_string(&d).unwrap();
        assert_eq!(text, format!("\"{}\"", d.to_hex()));
        assert_eq!(serde_json::from_str::<Digest32>(&text).unwrap(), d);
        assert!(serde_json::from_str::<Digest32>("\"00\"").is_err());
    }
}
