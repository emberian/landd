use crate::station::{load_config, AnyError, Station};
use landd_core::pod_ledger::{Action, PodLedger};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(clap::Args)]
pub struct Setup {
    #[arg(long)]
    repo: PathBuf,
    #[arg(long)]
    config: PathBuf,
}
impl Setup {
    pub fn open(&self) -> Result<Station, AnyError> {
        Station::open(&self.repo, load_config(Some(&self.config), &[])?)
    }
}

pub fn pod(database: &Path, lead: &str, principal: &str, stream: bool) -> Result<ExitCode, AnyError> {
    #[derive(serde::Deserialize)]
    struct Request {
        pod: String,
        #[serde(default)]
        task: String,
        action: Action,
    }
    use std::io::{BufRead, Write};
    let mut ledger = PodLedger::open(database, lead)?;
    let mut apply = |request: Request| -> Result<_, AnyError> {
        Ok(ledger.apply(principal, &request.pod, &request.task, crate::daemon::unix_now().try_into()?, request.action)?)
    };
    if stream {
        for line in std::io::stdin().lock().lines() {
            let result = serde_json::from_str(&line?).map_err(Into::into).and_then(&mut apply);
            let response = match result {
                Ok(task) => serde_json::json!({"ok":true,"task":task}),
                Err(e) => serde_json::json!({"ok":false,"reason":e.to_string()}),
            };
            writeln!(std::io::stdout().lock(), "{response}")?;
        }
    } else {
        crate::print_json(&apply(serde_json::from_reader(std::io::stdin().lock())?)?)?;
    }
    Ok(ExitCode::SUCCESS)
}

/// An authenticated OBB sidecar binds the upstream evidence digest and the
/// landd gate/runner equivalence. changed_paths is never a dependency cone.
pub fn receipt(bytes: &[u8], station: &Station) -> Result<landd_core::cone_receipt::ConeReceipt, AnyError> {
    use landd_core::{cone_receipt::ConeReceipt, Digest32, Oid};
    #[derive(serde::Deserialize)]
    struct Judge {
        receipt_version: u32,
        receipt_hash: Digest32,
        judge_name: String,
        gate_sha256: Digest32,
        tree_oid: Oid,
        all_passed: bool,
        clean_working_tree: bool,
    }
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Evidence {
        Obb { judge_receipt_json: String, judge_file_sha256: Digest32, obb_gate_sha256: Digest32, cone_attestation: ConeReceipt },
        Native(ConeReceipt),
    }
    if serde_json::from_slice::<serde_json::Value>(bytes)?.get("receipt_version").is_some() {
        let key = std::fs::read(station.state.join("obb-receipt.key"))?;
        return landd_core::cone_receipt::native_obb(&station.repo, bytes, &key, &station.config.obb_grants);
    }
    match serde_json::from_slice(bytes)? {
        Evidence::Native(r) => Ok(r),
        Evidence::Obb { judge_receipt_json, judge_file_sha256, obb_gate_sha256, cone_attestation: r } => {
            use sha2::{Digest, Sha256};
            let j: Judge = serde_json::from_str(&judge_receipt_json)?;
            let actual = Digest32::from_bytes(Sha256::digest(judge_receipt_json.as_bytes()).into());
            // OBB hashes compact serde JSON in declaration order. Keep the upstream
            // field order (including nested floor evaluations) when checking its file.
            let mut payload: serde_json::Map<String, serde_json::Value> = serde_json::from_str(&judge_receipt_json)?;
            payload.shift_remove("receipt_hash");
            payload.shift_remove("receipt_mac");
            let signable = Digest32::from_bytes(Sha256::digest(serde_json::to_vec(&payload)?).into());
            if j.receipt_version == 1
                && actual == judge_file_sha256
                && j.receipt_hash == signable
                && j.judge_name == r.judge_name
                && j.gate_sha256 == obb_gate_sha256
                && j.tree_oid == r.tree_oid
                && j.all_passed
                && j.clean_working_tree
            {
                Ok(r)
            } else {
                Err("OBB judge receipt disagrees with its authenticated cone attestation".into())
            }
        }
    }
}
