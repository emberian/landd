//! Everything a train needs, assembled from a `LandConfig`.

use ast_sweep::{BlobFactsCache, RulePack};
use landd_core::custody::{SigAlg, SigningKey};
use landd_core::delivery::DeliveryJournal;
use landd_core::git::GitRepo;
use landd_core::reasons::DiskVerdictStore;
use landd_core::{ConeSourceKind, CustodyMode, LandConfig};
use landd_train::{ConeSource, ManifestCones, PythonCones, Runner, RunnerConfig, Train};
use std::path::{Path, PathBuf};

pub type AnyError = Box<dyn std::error::Error + Send + Sync>;

pub struct Station {
    pub repo: GitRepo,
    pub config: LandConfig,
    pub store: DiskVerdictStore,
    pub journal: DeliveryJournal,
    pub source: Box<dyn ConeSource + Send + Sync>,
}

pub fn load_config(path: Option<&Path>, overrides: &[String]) -> Result<LandConfig, AnyError> {
    let config = match path {
        Some(path) => LandConfig::load(path)?,
        None => LandConfig::default(),
    };
    Ok(config.with_overrides(overrides)?)
}

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

/// `$XDG_CACHE_HOME/landd`, else `$HOME/.cache/landd`.
pub fn default_cache_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?;
    Some(base.join("landd"))
}

impl Station {
    pub fn open(repo: &Path, config: LandConfig) -> Result<Self, AnyError> {
        let source: Box<dyn ConeSource + Send + Sync> = match config.cone_source {
            ConeSourceKind::Manifest => Box::new(ManifestCones { manifest: config.unit_manifest.clone() }),
            ConeSourceKind::Python if !config.ast_sweep_enabled => {
                return Err("cone_source = \"python\" needs ast_sweep_enabled = true".into())
            }
            ConeSourceKind::Python => Box::new(PythonCones {
                pack: load_pack(config.rules.as_deref(), None)?,
                cache: Some(BlobFactsCache::open(config.cache_dir.join("facts"))),
            }),
        };
        Ok(Self {
            repo: GitRepo::open(repo)?,
            store: DiskVerdictStore::open(config.cache_dir.join("verdicts")),
            journal: DeliveryJournal::open(config.cache_dir.join("deliveries")),
            source,
            config,
        })
    }

    fn signer(&self) -> Result<Option<(String, SigningKey)>, AnyError> {
        let wanted = match self.config.custody_mode {
            CustodyMode::Off => return Ok(None),
            CustodyMode::Ed25519 => SigAlg::Ed25519,
            CustodyMode::SshsigEd25519 => SigAlg::SshsigEd25519,
            CustodyMode::HmacSha256 => SigAlg::HmacSha256,
        };
        let path = self.config.custody_key.as_deref().ok_or("custody_mode is set but custody_key is not")?;
        let (key_id, key) = SigningKey::load(path)?;
        if key.alg() != wanted {
            return Err(format!("custody_key {} is a {:?} key; custody_mode wants {wanted:?}", path.display(), key.alg()).into());
        }
        Ok(Some((key_id, key)))
    }

    pub fn train(&self) -> Result<Train<'_>, AnyError> {
        let runner = Runner::new(RunnerConfig::from_config(&self.config));
        let train = Train::new(&self.repo, &self.config, self.source.as_ref(), &self.store, &self.journal, runner);
        Ok(match self.signer()? {
            Some((key_id, key)) => train.with_signer(key_id, key),
            None => train,
        })
    }
}
