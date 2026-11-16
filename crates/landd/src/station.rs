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
        let state = config.state_dir()?;
        fsx::private_dir(&state)?;
        // State inside the repository could be committed, checked out by a
        // lane, or shown to the units under test.
        if std::fs::canonicalize(&state)?.starts_with(&repo_dir) {
            return Err(format!("the state directory {} is inside the repository {}", state.display(), repo_dir.display()).into());
        }
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
        let repo = GitRepo::open(&repo_dir)?.with_network_timeout(Duration::from_secs(config.network_timeout_s));
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
}
