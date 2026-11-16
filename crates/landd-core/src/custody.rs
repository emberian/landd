//! `CustodyEnvelopeV2`: a signed, versioned, open-ended receipt.
//!
//! The signature covers
//! `"landd-custody/v2\n" || BLAKE3(canonical_header) || BLAKE3(canonical_claims)`.
//! Verification hashes the claims object exactly as it was sealed, whatever
//! keys it holds, so a verifier needs no list of permitted claim names: a
//! signer may add counters (`rung_cpu_s`, `audit_cones`, `batch_size`, …) that
//! an older verifier has never heard of and the envelope still verifies. Any
//! change to a claim or to the header after sealing fails closed.

use crate::canon::{canonical_json, CanonError};
use crate::digest::{hex_decode, hex_encode, Digest32};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512};
use std::collections::BTreeMap;
use std::path::Path;

pub const DOMAIN: &[u8] = b"landd-custody/v2\n";
pub const VERSION: u32 = 2;
pub const SSHSIG_NAMESPACE: &str = "landd-custody-v2";
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";
const SSH_ED25519: &[u8] = b"ssh-ed25519";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigAlg {
    Ed25519,
    SshsigEd25519,
    HmacSha256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyHeader {
    pub v: u32,
    pub alg: SigAlg,
    pub key_id: String,
    /// Who sealed it (a seat or a runner supervisor).
    pub seat: String,
    /// What it attests, e.g. `land-receipt` or `runner-attestation`.
    pub kind: String,
    /// Digest of the thing attested (for a land: the ref update).
    pub subject: Digest32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyEnvelopeV2 {
    pub header: CustodyHeader,
    /// Open-ended: any JSON object without floats.
    pub claims: serde_json::Value,
    /// Hex of the signature bytes (for `sshsig-ed25519`, of the SSHSIG blob).
    pub signature: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CustodyError {
    #[error("unsupported envelope version {0}")]
    Version(u32),
    #[error("claims must be a JSON object")]
    ClaimsNotObject,
    #[error("canonical form: {0}")]
    Canon(#[from] CanonError),
    #[error("no trusted key named {0:?}")]
    UnknownKey(String),
    #[error("key {key_id:?} is not a {alg:?} key")]
    AlgMismatch { key_id: String, alg: SigAlg },
    #[error("signature encoding is malformed")]
    Malformed,
    #[error("signature does not verify")]
    BadSignature,
    #[error("key material is invalid: {0}")]
    BadKey(String),
    #[error("reading {path}: {detail}")]
    KeyFile { path: String, detail: String },
}

/// The subject of a land receipt: one ref moving from `old` to `new`.
pub fn ref_update_subject(target_ref: &str, old: &crate::digest::Oid, new: &crate::digest::Oid) -> Digest32 {
    Digest32::tagged("landd ref update v1", &[target_ref.as_bytes(), old.as_bytes(), new.as_bytes()])
}

/// The push option that carries a receipt to the forge's `pre-receive` hook.
pub const PUSH_OPTION: &str = "landd-custody";

/// The exact bytes that get signed.
pub fn signing_message(header: &CustodyHeader, claims: &serde_json::Value) -> Result<Vec<u8>, CustodyError> {
    signing_message_with_domain(DOMAIN, header, claims)
}

fn signing_message_with_domain(
    domain: &[u8],
    header: &CustodyHeader,
    claims: &serde_json::Value,
) -> Result<Vec<u8>, CustodyError> {
    if !claims.is_object() {
        return Err(CustodyError::ClaimsNotObject);
    }
    let mut message = Vec::with_capacity(domain.len() + 64);
    message.extend_from_slice(domain);
    message.extend_from_slice(Digest32::blake3(&canonical_json(header)?).as_bytes());
    message.extend_from_slice(Digest32::blake3(&canonical_json(claims)?).as_bytes());
    Ok(message)
}

/// Secret key material. Lives only in the supervisor process.
pub enum SigningKey {
    Ed25519(EdSigningKey),
    SshsigEd25519(EdSigningKey),
    HmacSha256(Vec<u8>),
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey({:?}, <secret>)", self.alg())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum TrustedKey {
    Ed25519(EdVerifyingKey),
    SshsigEd25519(EdVerifyingKey),
    HmacSha256(Vec<u8>),
}

impl TrustedKey {
    pub fn alg(&self) -> SigAlg {
        match self {
            Self::Ed25519(_) => SigAlg::Ed25519,
            Self::SshsigEd25519(_) => SigAlg::SshsigEd25519,
            Self::HmacSha256(_) => SigAlg::HmacSha256,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFileEntry {
    key_id: String,
    alg: SigAlg,
    /// Hex: the 32-byte Ed25519 seed or public key, or the HMAC secret.
    key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedFile {
    keys: Vec<KeyFileEntry>,
}

fn ed_bytes(hex: &str) -> Result<[u8; 32], CustodyError> {
    hex_decode(hex)
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| CustodyError::BadKey("expected 32 bytes of lowercase hex".into()))
}

impl SigningKey {
    pub fn alg(&self) -> SigAlg {
        match self {
            Self::Ed25519(_) => SigAlg::Ed25519,
            Self::SshsigEd25519(_) => SigAlg::SshsigEd25519,
            Self::HmacSha256(_) => SigAlg::HmacSha256,
        }
    }

    pub fn ed25519_from_seed(seed: [u8; 32]) -> Self {
        Self::Ed25519(EdSigningKey::from_bytes(&seed))
    }

    pub fn sshsig_from_seed(seed: [u8; 32]) -> Self {
        Self::SshsigEd25519(EdSigningKey::from_bytes(&seed))
    }

    /// What a verifier needs in order to trust this key.
    pub fn trusted(&self) -> TrustedKey {
        match self {
            Self::Ed25519(k) => TrustedKey::Ed25519(k.verifying_key()),
            Self::SshsigEd25519(k) => TrustedKey::SshsigEd25519(k.verifying_key()),
            Self::HmacSha256(secret) => TrustedKey::HmacSha256(secret.clone()),
        }
    }

    /// Parse a key file: `{"key_id": …, "alg": …, "key": "<hex>"}`.
    pub fn from_json(text: &str) -> Result<(String, Self), CustodyError> {
        let entry: KeyFileEntry = serde_json::from_str(text).map_err(|e| CustodyError::BadKey(e.to_string()))?;
        let key = match entry.alg {
            SigAlg::Ed25519 => Self::ed25519_from_seed(ed_bytes(&entry.key)?),
            SigAlg::SshsigEd25519 => Self::sshsig_from_seed(ed_bytes(&entry.key)?),
            SigAlg::HmacSha256 => Self::HmacSha256(hmac_secret(&entry.key)?),
        };
        Ok((entry.key_id, key))
    }

    pub fn load(path: &Path) -> Result<(String, Self), CustodyError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CustodyError::KeyFile { path: path.display().to_string(), detail: e.to_string() })?;
        Self::from_json(&text)
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.sign(message).to_bytes().to_vec(),
            Self::SshsigEd25519(key) => sshsig_sign(key, message),
            Self::HmacSha256(secret) => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac takes any key length");
                mac.update(message);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }
}

fn hmac_secret(hex: &str) -> Result<Vec<u8>, CustodyError> {
    match hex_decode(hex) {
        Some(secret) if secret.len() >= 16 => Ok(secret),
        _ => Err(CustodyError::BadKey("hmac secret must be at least 16 bytes of lowercase hex".into())),
    }
}

/// The keys a verifier accepts, by `key_id`.
#[derive(Clone, Default)]
pub struct TrustedKeys(BTreeMap<String, TrustedKey>);

impl TrustedKeys {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key_id: impl Into<String>, key: TrustedKey) {
        self.0.insert(key_id.into(), key);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Parse `{"keys": [{"key_id": …, "alg": …, "key": "<hex>"}, …]}`.
    pub fn from_json(text: &str) -> Result<Self, CustodyError> {
        let file: TrustedFile = serde_json::from_str(text).map_err(|e| CustodyError::BadKey(e.to_string()))?;
        let mut keys = Self::new();
        for entry in file.keys {
            let verifying = |hex: &str| {
                EdVerifyingKey::from_bytes(&ed_bytes(hex)?).map_err(|e| CustodyError::BadKey(e.to_string()))
            };
            let key = match entry.alg {
                SigAlg::Ed25519 => TrustedKey::Ed25519(verifying(&entry.key)?),
                SigAlg::SshsigEd25519 => TrustedKey::SshsigEd25519(verifying(&entry.key)?),
                SigAlg::HmacSha256 => TrustedKey::HmacSha256(hmac_secret(&entry.key)?),
            };
            keys.insert(entry.key_id, key);
        }
        Ok(keys)
    }

    pub fn load(path: &Path) -> Result<Self, CustodyError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CustodyError::KeyFile { path: path.display().to_string(), detail: e.to_string() })?;
        Self::from_json(&text)
    }

    /// The trusted-keys file text for these keys.
    pub fn to_json(&self) -> String {
        let keys = self
            .0
            .iter()
            .map(|(key_id, key)| KeyFileEntry {
                key_id: key_id.clone(),
                alg: key.alg(),
                key: match key {
                    TrustedKey::Ed25519(k) | TrustedKey::SshsigEd25519(k) => hex_encode(k.as_bytes()),
                    TrustedKey::HmacSha256(secret) => hex_encode(secret),
                },
            })
            .collect();
        serde_json::to_string_pretty(&TrustedFile { keys }).expect("key file serializes")
    }
}

impl CustodyEnvelopeV2 {
    pub fn seal(
        key: &SigningKey,
        key_id: &str,
        seat: &str,
        kind: &str,
        subject: Digest32,
        claims: serde_json::Value,
    ) -> Result<Self, CustodyError> {
        let header = CustodyHeader {
            v: VERSION,
            alg: key.alg(),
            key_id: key_id.to_owned(),
            seat: seat.to_owned(),
            kind: kind.to_owned(),
            subject,
        };
        let message = signing_message(&header, &claims)?;
        Ok(Self { header, claims, signature: hex_encode(&key.sign(&message)) })
    }

    /// Fails closed: an unknown version, an unknown key, a key of another
    /// algorithm, a malformed signature and a wrong signature are all errors.
    pub fn verify(&self, trusted: &TrustedKeys) -> Result<(), CustodyError> {
        if self.header.v != VERSION {
            return Err(CustodyError::Version(self.header.v));
        }
        let key = trusted.0.get(&self.header.key_id).ok_or_else(|| CustodyError::UnknownKey(self.header.key_id.clone()))?;
        if key.alg() != self.header.alg {
            return Err(CustodyError::AlgMismatch { key_id: self.header.key_id.clone(), alg: self.header.alg });
        }
        let message = signing_message(&self.header, &self.claims)?;
        let signature = hex_decode(&self.signature).ok_or(CustodyError::Malformed)?;
        match key {
            TrustedKey::Ed25519(public) => ed_verify(public, &message, &signature),
            TrustedKey::SshsigEd25519(public) => sshsig_verify(public, &message, &signature),
            TrustedKey::HmacSha256(secret) => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac takes any key length");
                mac.update(&message);
                mac.verify_slice(&signature).map_err(|_| CustodyError::BadSignature)
            }
        }
    }

    /// Read the claims a caller knows about; unknown claims are ignored here
    /// and still covered by the signature.
    pub fn claims_as<T: DeserializeOwned>(&self) -> Result<T, CustodyError> {
        serde_json::from_value(self.claims.clone()).map_err(|e| CustodyError::Canon(CanonError::Json(e)))
    }

    pub fn to_wire(&self) -> Result<Vec<u8>, CustodyError> {
        Ok(canonical_json(self)?)
    }

    pub fn from_wire(bytes: &[u8]) -> Result<Self, CustodyError> {
        serde_json::from_slice(bytes).map_err(|e| CustodyError::Canon(CanonError::Json(e)))
    }

    /// The SSHSIG signature in the armored form `ssh-keygen -Y verify` reads.
    pub fn sshsig_armored(&self) -> Option<String> {
        if self.header.alg != SigAlg::SshsigEd25519 {
            return None;
        }
        let blob = hex_decode(&self.signature)?;
        let body = base64::engine::general_purpose::STANDARD.encode(blob);
        let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
        for line in body.as_bytes().chunks(70) {
            out.push_str(std::str::from_utf8(line).expect("base64 is ascii"));
            out.push('\n');
        }
        out.push_str("-----END SSH SIGNATURE-----\n");
        Some(out)
    }
}

fn ed_verify(public: &EdVerifyingKey, message: &[u8], signature: &[u8]) -> Result<(), CustodyError> {
    let bytes = <[u8; 64]>::try_from(signature).map_err(|_| CustodyError::Malformed)?;
    public
        .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&bytes))
        .map_err(|_| CustodyError::BadSignature)
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn take_string<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], CustodyError> {
    if input.len() < 4 {
        return Err(CustodyError::Malformed);
    }
    let len = u32::from_be_bytes(input[..4].try_into().expect("four bytes")) as usize;
    let rest = &input[4..];
    if rest.len() < len {
        return Err(CustodyError::Malformed);
    }
    *input = &rest[len..];
    Ok(&rest[..len])
}

fn ssh_public_blob(public: &EdVerifyingKey) -> Vec<u8> {
    let mut blob = Vec::with_capacity(51);
    put_string(&mut blob, SSH_ED25519);
    put_string(&mut blob, public.as_bytes());
    blob
}

/// The `authorized_keys`-style line for an Ed25519 public key.
pub fn ssh_public_line(key: &TrustedKey) -> Option<String> {
    match key {
        TrustedKey::Ed25519(public) | TrustedKey::SshsigEd25519(public) => Some(format!(
            "ssh-ed25519 {}",
            base64::engine::general_purpose::STANDARD.encode(ssh_public_blob(public))
        )),
        TrustedKey::HmacSha256(_) => None,
    }
}

/// What SSHSIG actually signs (PROTOCOL.sshsig, hash algorithm sha512).
fn sshsig_signed_data(hash_alg: &[u8], message: &[u8]) -> Result<Vec<u8>, CustodyError> {
    let hashed = match hash_alg {
        b"sha512" => Sha512::digest(message).to_vec(),
        b"sha256" => Sha256::digest(message).to_vec(),
        _ => return Err(CustodyError::Malformed),
    };
    let mut data = Vec::with_capacity(128);
    data.extend_from_slice(SSHSIG_MAGIC);
    put_string(&mut data, SSHSIG_NAMESPACE.as_bytes());
    put_string(&mut data, b"");
    put_string(&mut data, hash_alg);
    put_string(&mut data, &hashed);
    Ok(data)
}

fn sshsig_sign(key: &EdSigningKey, message: &[u8]) -> Vec<u8> {
    let signed = sshsig_signed_data(b"sha512", message).expect("sha512 is supported");
    let mut inner = Vec::with_capacity(83);
    put_string(&mut inner, SSH_ED25519);
    put_string(&mut inner, &key.sign(&signed).to_bytes());
    let mut blob = Vec::with_capacity(256);
    blob.extend_from_slice(SSHSIG_MAGIC);
    blob.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut blob, &ssh_public_blob(&key.verifying_key()));
    put_string(&mut blob, SSHSIG_NAMESPACE.as_bytes());
    put_string(&mut blob, b"");
    put_string(&mut blob, b"sha512");
    put_string(&mut blob, &inner);
    blob
}

fn sshsig_verify(public: &EdVerifyingKey, message: &[u8], blob: &[u8]) -> Result<(), CustodyError> {
    let mut rest = blob.strip_prefix(SSHSIG_MAGIC).ok_or(CustodyError::Malformed)?;
    if rest.len() < 4 || rest[..4] != 1u32.to_be_bytes() {
        return Err(CustodyError::Malformed);
    }
    rest = &rest[4..];
    let embedded_key = take_string(&mut rest)?;
    let namespace = take_string(&mut rest)?;
    let _reserved = take_string(&mut rest)?;
    let hash_alg = take_string(&mut rest)?;
    let mut inner = take_string(&mut rest)?;
    if !rest.is_empty() || namespace != SSHSIG_NAMESPACE.as_bytes() {
        return Err(CustodyError::Malformed);
    }
    // The blob names its own key; only the trusted one counts.
    if embedded_key != ssh_public_blob(public) {
        return Err(CustodyError::BadSignature);
    }
    if take_string(&mut inner)? != SSH_ED25519 {
        return Err(CustodyError::Malformed);
    }
    let signature = take_string(&mut inner)?;
    if !inner.is_empty() {
        return Err(CustodyError::Malformed);
    }
    ed_verify(public, &sshsig_signed_data(hash_alg, message)?, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn keys() -> Vec<SigningKey> {
        vec![
            SigningKey::ed25519_from_seed([7; 32]),
            SigningKey::sshsig_from_seed([8; 32]),
            SigningKey::HmacSha256(vec![9; 32]),
        ]
    }

    fn trust(key: &SigningKey) -> TrustedKeys {
        let mut trusted = TrustedKeys::new();
        trusted.insert("seat-a", key.trusted());
        trusted
    }

    fn seal(key: &SigningKey, claims: serde_json::Value) -> CustodyEnvelopeV2 {
        CustodyEnvelopeV2::seal(key, "seat-a", "seat-a", "land-receipt", Digest32::blake3(b"subject"), claims).unwrap()
    }

    #[test]
    fn every_algorithm_seals_and_verifies() {
        for key in keys() {
            let envelope = seal(&key, json!({"verdict": "green", "units_run": 3}));
            envelope.verify(&trust(&key)).unwrap();
            let wire = envelope.to_wire().unwrap();
            let back = CustodyEnvelopeV2::from_wire(&wire).unwrap();
            assert_eq!(back, envelope);
            back.verify(&trust(&key)).unwrap();
        }
    }

    /// A newer signer seals five telemetry claims this verifier has no name
    /// for. The verifier reads the claims it knows through a closed struct,
    /// re-serializes the envelope with its keys in another order, and the
    /// original signature, byte for byte, still verifies.
    #[test]
    fn tooth_five_unknown_telemetry_claims_verify_with_the_original_signature() {
        #[derive(Deserialize)]
        struct Known {
            verdict: String,
        }
        for key in keys() {
            let envelope = seal(
                &key,
                json!({
                    "verdict": "green",
                    "rung_cpu_s": 412, "audit_cones": 88, "batch_size": 4,
                    "transported_units": 1907, "future_counter_nobody_named_yet": {"nested": [1, 2, 3]},
                }),
            );
            let original_signature = envelope.signature.clone();
            let text = format!(
                "{{ \"signature\": {:?}, \"claims\": {{ \"future_counter_nobody_named_yet\": {{\"nested\": [1,2,3]}}, \
                 \"transported_units\": 1907, \"batch_size\": 4, \"audit_cones\": 88, \"rung_cpu_s\": 412, \
                 \"verdict\": \"green\" }}, \"header\": {} }}",
                envelope.signature,
                serde_json::to_string(&envelope.header).unwrap()
            );
            let received = CustodyEnvelopeV2::from_wire(text.as_bytes()).unwrap();
            assert_eq!(received.signature, original_signature);
            received.verify(&trust(&key)).unwrap();
            assert_eq!(received.claims_as::<Known>().unwrap().verdict, "green");
        }
    }

    #[test]
    fn tooth_any_change_to_claims_fails_closed() {
        for key in keys() {
            let envelope = seal(&key, json!({"verdict": "green", "batch_size": 4}));
            let trusted = trust(&key);

            let mut flipped = envelope.clone();
            flipped.claims["batch_size"] = json!(5); // 0b100 -> 0b101
            assert!(matches!(flipped.verify(&trusted), Err(CustodyError::BadSignature)));

            let mut added = envelope.clone();
            added.claims["smuggled"] = json!(true);
            assert!(matches!(added.verify(&trusted), Err(CustodyError::BadSignature)));

            let mut removed = envelope.clone();
            removed.claims.as_object_mut().unwrap().remove("batch_size");
            assert!(matches!(removed.verify(&trusted), Err(CustodyError::BadSignature)));
        }
    }

    #[test]
    fn tooth_any_change_to_the_header_fails_closed() {
        for key in keys() {
            let envelope = seal(&key, json!({"verdict": "green"}));
            let trusted = trust(&key);

            let mut subject = envelope.clone();
            let mut bytes = *subject.header.subject.as_bytes();
            bytes[0] ^= 1;
            subject.header.subject = Digest32::from_bytes(bytes);
            assert!(matches!(subject.verify(&trusted), Err(CustodyError::BadSignature)));

            let mut seat = envelope.clone();
            seat.header.seat = "seat-b".into();
            assert!(matches!(seat.verify(&trusted), Err(CustodyError::BadSignature)));

            let mut kind = envelope.clone();
            kind.header.kind = "runner-attestation".into();
            assert!(matches!(kind.verify(&trusted), Err(CustodyError::BadSignature)));

            let mut version = envelope.clone();
            version.header.v = 3;
            assert!(matches!(version.verify(&trusted), Err(CustodyError::Version(3))));
        }
    }

    #[test]
    fn tooth_wrong_domain_tag_fails_closed() {
        let seed = [7; 32];
        let key = SigningKey::ed25519_from_seed(seed);
        let good = seal(&key, json!({"verdict": "green"}));
        for domain in [&b"landd-custody/v1\n"[..], b"landd-custody/v2", b""] {
            let message = signing_message_with_domain(domain, &good.header, &good.claims).unwrap();
            let forged = CustodyEnvelopeV2 {
                signature: hex_encode(&EdSigningKey::from_bytes(&seed).sign(&message).to_bytes()),
                ..good.clone()
            };
            assert!(matches!(forged.verify(&trust(&key)), Err(CustodyError::BadSignature)));
        }
    }

    #[test]
    fn tooth_wrong_key_unknown_key_and_algorithm_swap_fail_closed() {
        let key = SigningKey::ed25519_from_seed([7; 32]);
        let envelope = seal(&key, json!({"verdict": "green"}));

        let other = SigningKey::ed25519_from_seed([1; 32]);
        assert!(matches!(envelope.verify(&trust(&other)), Err(CustodyError::BadSignature)));
        assert!(matches!(envelope.verify(&TrustedKeys::new()), Err(CustodyError::UnknownKey(_))));

        // The same Ed25519 key trusted only for SSHSIG does not accept a raw signature.
        let as_sshsig = SigningKey::sshsig_from_seed([7; 32]);
        assert!(matches!(envelope.verify(&trust(&as_sshsig)), Err(CustodyError::AlgMismatch { .. })));
        let mut relabelled = envelope.clone();
        relabelled.header.alg = SigAlg::SshsigEd25519;
        assert!(relabelled.verify(&trust(&as_sshsig)).is_err());

        let mut garbage = envelope.clone();
        garbage.signature = "zz".into();
        assert!(matches!(garbage.verify(&trust(&key)), Err(CustodyError::Malformed)));
        let mut truncated = envelope.clone();
        truncated.signature.truncate(100);
        assert!(matches!(truncated.verify(&trust(&key)), Err(CustodyError::Malformed)));
    }

    #[test]
    fn tooth_claims_must_be_an_object_without_floats() {
        let key = SigningKey::ed25519_from_seed([7; 32]);
        let subject = Digest32::blake3(b"s");
        assert!(matches!(
            CustodyEnvelopeV2::seal(&key, "k", "s", "land-receipt", subject, json!([1, 2])),
            Err(CustodyError::ClaimsNotObject)
        ));
        assert!(matches!(
            CustodyEnvelopeV2::seal(&key, "k", "s", "land-receipt", subject, json!({"cpu": 1.5})),
            Err(CustodyError::Canon(CanonError::Float(_)))
        ));
    }

    #[test]
    fn tooth_sshsig_blob_with_a_foreign_embedded_key_is_rejected() {
        let trusted_key = SigningKey::sshsig_from_seed([8; 32]);
        let attacker = SigningKey::sshsig_from_seed([66; 32]);
        let mut envelope = seal(&trusted_key, json!({"verdict": "green"}));
        let message = signing_message(&envelope.header, &envelope.claims).unwrap();
        envelope.signature = hex_encode(&attacker.sign(&message));
        assert!(matches!(envelope.verify(&trust(&trusted_key)), Err(CustodyError::BadSignature)));
    }

    #[test]
    fn key_files_round_trip() {
        let secret = format!(r#"{{"key_id":"seat-a","alg":"ed25519","key":"{}"}}"#, hex_encode(&[7; 32]));
        let (key_id, key) = SigningKey::from_json(&secret).unwrap();
        assert_eq!(key_id, "seat-a");
        let trusted = TrustedKeys::from_json(&trust(&key).to_json()).unwrap();
        assert_eq!(trusted.len(), 1);
        seal(&key, json!({"a": 1})).verify(&trusted).unwrap();
        assert!(SigningKey::from_json(r#"{"key_id":"x","alg":"hmac-sha256","key":"00"}"#).is_err());
        assert!(format!("{key:?}").contains("<secret>"));
    }

    /// Interoperability with OpenSSH: `ssh-keygen -Y check-novalidate` accepts
    /// the armored signature over the signing message. Skipped where
    /// `ssh-keygen` is not installed.
    #[test]
    fn sshsig_is_accepted_by_ssh_keygen() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        if Command::new("ssh-keygen").arg("-?").stdout(Stdio::null()).stderr(Stdio::null()).status().is_err() {
            eprintln!("ssh-keygen not found; skipping interop check");
            return;
        }
        let key = SigningKey::sshsig_from_seed([8; 32]);
        let envelope = seal(&key, json!({"verdict": "green"}));
        let dir = tempfile::tempdir().unwrap();
        let sig_path = dir.path().join("receipt.sig");
        std::fs::write(&sig_path, envelope.sshsig_armored().unwrap()).unwrap();
        let check = |message: &[u8]| {
            let mut child = Command::new("ssh-keygen")
                .args(["-Y", "check-novalidate", "-n", SSHSIG_NAMESPACE, "-s"])
                .arg(&sig_path)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(message).unwrap();
            child.wait().unwrap().success()
        };
        let message = signing_message(&envelope.header, &envelope.claims).unwrap();
        assert!(check(&message));
        let mut tampered = message.clone();
        tampered[20] ^= 1;
        assert!(!check(&tampered));
        assert!(ssh_public_line(&key.trusted()).unwrap().starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5"));
    }
}
