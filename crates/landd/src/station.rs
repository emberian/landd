//! Everything a train needs, assembled from a `LandConfig`.

use ast_sweep::{BlobFactsCache, RulePack};
use landd_core::custody::{SigAlg, SigningKey};
use landd_core::delivery::DeliveryJournal;
use landd_core::git::GitRepo;
use landd_core::reasons::DiskVerdictStore;
use landd_core::{fsx, ConeSourceKind, CustodyMode, LandConfig};
use landd_train::{ConeSource, ManifestCones, PythonCones, Runner, RunnerConfig, Train};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub type AnyError = Box<dyn std::error::Error + Send + Sync>;

/// `--repo` and `--config`: the station a one-shot command runs against.
#[derive(clap::Args)]
pub struct StationArgs {
    #[arg(long)]
    repo: PathBuf,
    #[arg(long)]
    config: PathBuf,
}

impl StationArgs {
    pub fn open(&self) -> Result<Station, AnyError> {
        Station::open(&self.repo, load_config(Some(&self.config), &[])?)
    }
}

pub struct Station {
    pub repo: GitRepo,
    pub config: LandConfig,
    /// The trusted state directory: facts, verdicts, deliveries, the queue.
    pub state: PathBuf,
    /// Where pushes go and where the target ref is read from.
    pub destination: String,
    pub store: DiskVerdictStore,
    pub journal: DeliveryJournal,
    pub source: Box<dyn ConeSource + Send + Sync>,
    runner: Runner,
    /// Loaded once, at start; held in this process only.
    signer: Option<(String, SigningKey)>,
}

pub fn load_config(path: Option<&Path>, overrides: &[String]) -> Result<LandConfig, AnyError> {
    let config = match path {
        Some(path) => LandConfig::load(path)?,
        None => LandConfig::default(),
    };
    Ok(config.with_overrides(overrides)?)
}

/// The rule pack at an operator path (never one from the tree under test),
/// with a `gateaudits.json` folded in when given.
pub fn load_pack(rules: Option<&Path>, gateaudits: Option<&Path>) -> Result<RulePack, AnyError> {
    let pack = match rules {
        Some(path) => RulePack::load(path)?,
        None => RulePack::builtin(),
    };
    match gateaudits {
        Some(path) => Ok(pack.with_gateaudits(&std::fs::read_to_string(path)?)?),
        None => Ok(pack),
    }
}

/// `$XDG_CACHE_HOME/landd`, else `$HOME/.cache/landd`: for the read-only
/// commands (`sweep`, `cones`), which keep facts and nothing else.
pub fn default_cache_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(base.join("landd"))
}

fn load_signer(config: &LandConfig) -> Result<Option<(String, SigningKey)>, AnyError> {
    let wanted = match config.custody_mode {
        CustodyMode::Off => return Ok(None),
        CustodyMode::Ed25519 => SigAlg::Ed25519,
        CustodyMode::SshsigEd25519 => SigAlg::SshsigEd25519,
        CustodyMode::HmacSha256 => SigAlg::HmacSha256,
    };
    let path = config.custody_key.as_deref().ok_or("custody_mode is set but custody_key is not")?;
    let (key_id, key) = SigningKey::load(path)?;
    if key.alg() != wanted {
        return Err(format!("custody_key {} is a {:?} key; custody_mode wants {wanted:?}", path.display(), key.alg()).into());
    }
    Ok(Some((key_id, key)))
}

impl Station {
    pub fn open(repo: &Path, config: LandConfig) -> Result<Self, AnyError> {
        let repo_dir = std::fs::canonicalize(repo)?;
        let git_repo = GitRepo::open(&repo_dir)?.with_network_timeout(Duration::from_secs(config.network_timeout_s));
        let state = config.state_dir()?;
        // State inside the repository could be committed, checked out by a
        // lane, or shown to the units under test. Refuse before creating
        // directories, and resolve both the worktree root and `.git` so
        // opening from a subdirectory cannot miss a top-level cache path.
        let state_real = fsx::canonical_or_missing(&state)?;
        let mut forbidden = vec![repo_dir.clone()];
        for query in ["--show-toplevel", "--git-dir", "--git-common-dir"] {
            if let Ok(out) = git_repo.run_ok(&["rev-parse", query]) {
                let text = String::from_utf8_lossy(&out);
                let raw = Path::new(text.trim());
                let resolved = if raw.is_absolute() { raw.to_path_buf() } else { repo_dir.join(raw) };
                if let Ok(canon) = std::fs::canonicalize(&resolved) {
                    if !forbidden.contains(&canon) {
                        forbidden.push(canon);
                    }
                }
            }
        }
        if let Some(root) = forbidden.iter().find(|root| state_real.starts_with(root)) {
            return Err(format!("the state directory {} is inside the repository {}", state.display(), root.display()).into());
        }
        fsx::private_dir(&state)?;
        let source: Box<dyn ConeSource + Send + Sync> = match config.cone_source {
            ConeSourceKind::Manifest => Box::new(ManifestCones { manifest: config.unit_manifest.clone() }),
            ConeSourceKind::Python if !config.ast_sweep_enabled => {
                return Err("cone_source = \"python\" needs ast_sweep_enabled = true".into())
            }
            ConeSourceKind::Python => Box::new(PythonCones {
                pack: load_pack(config.rules.as_deref(), config.gateaudits.as_deref())?,
                cache: Some(BlobFactsCache::open(state.join("facts"))?),
            }),
        };
        let repo = git_repo;
        let destination = repo.push_destination(&config.remote)?;
        // A runner that cannot isolate as configured is an error here, at
        // start, and so is a key the sandbox would expose or that cannot be read.
        let runner = Runner::new(RunnerConfig::from_config(&config))?;
        let signer = load_signer(&config)?;
        Ok(Self {
            store: DiskVerdictStore::open(state.join("verdicts")),
            journal: DeliveryJournal::open(state.join("deliveries")),
            repo,
            destination,
            source,
            runner,
            signer,
            state,
            config,
        })
    }

    pub fn train(&self) -> Result<Train<'_>, AnyError> {
        let train = Train::new(&self.repo, &self.config, self.source.as_ref(), &self.store, &self.journal, self.runner.clone())?;
        Ok(match &self.signer {
            Some((key_id, key)) => train.with_signer(key_id.clone(), key.clone())?,
            None => train,
        })
    }

    /// An authenticated OBB sidecar binds the upstream evidence digest and the
    /// landd gate/runner equivalence. changed_paths is never a dependency cone.
    pub fn cone_receipt(&self, bytes: &[u8]) -> Result<landd_core::cone_receipt::ConeReceipt, AnyError> {
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
            Obb {
                judge_receipt_json: String,
                judge_file_sha256: Digest32,
                obb_gate_sha256: Digest32,
                cone_attestation: ConeReceipt,
            },
            Native(ConeReceipt),
        }
        if serde_json::from_slice::<serde_json::Value>(bytes)?.get("receipt_version").is_some() {
            let key = std::fs::read(self.state.join("obb-receipt.key"))?;
            return landd_core::cone_receipt::native_obb(&self.repo, bytes, &key, &self.config.obb_grants);
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
}
