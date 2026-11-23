//! Transport of operator-authenticated pass receipts. OBB's JudgeReceipt
//! binds a whole tree. A narrower scope requires a separately attested map.
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
