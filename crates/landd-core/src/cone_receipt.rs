//! Transport of local pass receipts and HMAC-authenticated OBB v2 file-unit receipts.
use crate::git::{GitError, GitRepo};
use crate::reasons::Input;
use crate::{Digest32, Oid};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConeReceipt {
    pub judge_name: String,
    pub gate_sha256: Digest32,
    pub toolchain_sha256: Digest32,
    pub tree_oid: Oid,
    pub all_passed: bool,
    pub clean_working_tree: bool,
    pub cone_blobs: BTreeMap<String, Oid>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict_source")]
pub enum VerdictSource {
    TransportedFrom { original_tree: Oid, cone_size: usize },
}

/// Prepared once against the issuer's immutable tree. Both input maps
/// iterate in path order, so a speculative comparison is a single linear pass.
pub struct BoundReceipt {
    receipt: ConeReceipt,
    inputs: BTreeMap<String, Input>,
}
impl ConeReceipt {
    pub fn bind(self, repo: &GitRepo) -> Result<Option<BoundReceipt>, GitError> {
        if !self.all_passed || !self.clean_working_tree || self.cone_blobs.is_empty() {
            return Ok(None);
        }
        match repo.blob_reader()?.resolve_tree(&self.tree_oid.to_hex()) {
            Ok(tree) if tree == self.tree_oid => {}
            Ok(_) | Err(GitError::Missing(_)) => return Ok(None),
            Err(error) => return Err(error),
        }
        let paths: Vec<_> = self.cone_blobs.keys().map(String::as_str).collect();
        let inputs = repo.tree_inputs(self.tree_oid, &paths)?;
        let matches = inputs.iter().map(|(p, i)| (p, &i.oid)).eq(self.cone_blobs.iter());
        Ok(matches.then_some(BoundReceipt { receipt: self, inputs }))
    }
}
impl BoundReceipt {
    pub fn unit(&self) -> &str {
        &self.receipt.judge_name
    }
    pub fn transport(&self, gate: Digest32, tools: Digest32, inputs: &BTreeMap<String, Input>) -> Option<VerdictSource> {
        (self.receipt.gate_sha256 == gate && self.receipt.toolchain_sha256 == tools && self.inputs == *inputs)
            .then_some(VerdictSource::TransportedFrom { original_tree: self.receipt.tree_oid, cone_size: self.inputs.len() })
    }
}

/// The operator grants equivalence between one OBB gate/runtime pair and one
/// local unit/runner pair. A toolchain or runner profile change requires a new grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObbGrant {
    pub gate_sha256: Digest32,
    pub toolchain_sha256: Digest32,
    pub local_gate_sha256: Digest32,
    pub local_toolchain_sha256: Digest32,
}

type EvidenceError = Box<dyn std::error::Error + Send + Sync>;

/// Consume the recursively sorted, compact signable payload emitted by OBB. Only after
/// authentication do we translate SHA-256 content digests to Git object IDs.
pub fn native_obb(
    repo: &GitRepo,
    bytes: &[u8],
    key: &[u8],
    grants: &BTreeMap<String, ObbGrant>,
) -> Result<ConeReceipt, EvidenceError> {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    #[derive(Deserialize)]
    struct Evidence {
        receipt_version: u32,
        judge_name: String,
        tree_oid: Oid,
        all_passed: bool,
        clean_working_tree: bool,
        gate_sha256: Digest32,
        toolchain_sha256: Digest32,
        cone_blobs: BTreeMap<String, Digest32>,
        cone_modes: BTreeMap<String, String>,
        cone_oids: BTreeMap<String, Oid>,
        cone_merkle_root: Digest32,
        receipt_hash: Digest32,
        receipt_mac: Digest32,
    }
    let e: Evidence = serde_json::from_slice(bytes)?;
    if key.is_empty() || e.receipt_version != 2 || !e.clean_working_tree || !e.all_passed || e.cone_blobs.is_empty() {
        return Err("expected a clean passing OBB v2 cone receipt".into());
    }
    let mut payload: serde_json::Map<String, serde_json::Value> = serde_json::from_slice(bytes)?;
    payload.shift_remove("receipt_mac");
    payload.shift_remove("receipt_hash");
    let mut payload = serde_json::Value::Object(payload);
    payload.sort_all_objects();
    if Sha256::digest(serde_json::to_vec(&payload)?)[..] != e.receipt_hash.as_bytes()[..] {
        return Err("OBB receipt hash mismatch".into());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key)?;
    mac.update(b"obb-judge-receipt-v2\0");
    mac.update(e.receipt_hash.to_hex().as_bytes());
    mac.verify_slice(e.receipt_mac.as_bytes())?;
    let grant = grants
        .get(&e.judge_name)
        .filter(|g| g.gate_sha256 == e.gate_sha256 && g.toolchain_sha256 == e.toolchain_sha256)
        .ok_or("OBB gate or toolchain outside station grant")?;
    if !e.cone_modes.keys().eq(e.cone_blobs.keys()) || !e.cone_oids.keys().eq(e.cone_blobs.keys()) {
        return Err("inconsistent cone modes".into());
    }
    let paths: Vec<_> = e.cone_blobs.keys().map(String::as_str).collect();
    let inputs = repo.tree_inputs(e.tree_oid, &paths)?;
    let mut reader = repo.blob_reader()?;
    let mut blobs = BTreeMap::new();
    let mut nodes = Vec::new();
    for (path, digest) in &e.cone_blobs {
        let input = inputs.get(path).ok_or("missing source blob")?;
        let mode = &e.cone_modes[path];
        if e.cone_oids[path] != input.oid
            || !matches!(input.mode, 0o100644 | 0o100755)
            || format!("{:o}", input.mode) != *mode
            || Sha256::digest(reader.read(&input.oid)?)[..] != digest.as_bytes()[..]
        {
            return Err("OBB source input mismatch".into());
        }
        blobs.insert(path.clone(), input.oid);
        nodes.push(format!("{:x}", Sha256::digest(serde_json::to_vec(&("obb-cone-leaf-v2", path, mode, digest))?)));
    }
    while nodes.len() > 1 {
        nodes = nodes
            .chunks(2)
            .map(|pair| format!("{:x}", Sha256::digest(format!("obb-cone-node-v2\0{}{}", pair[0], pair.last().unwrap()))))
            .collect();
    }
    if nodes[0] != e.cone_merkle_root.to_hex() {
        return Err("invalid OBB cone root".into());
    }
    Ok(ConeReceipt {
        judge_name: e.judge_name,
        tree_oid: e.tree_oid,
        all_passed: true,
        clean_working_tree: true,
        cone_blobs: blobs,
        gate_sha256: grant.local_gate_sha256,
        toolchain_sha256: grant.local_toolchain_sha256,
    })
}
