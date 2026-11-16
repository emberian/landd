//! `LandConfig`: every limit is a runtime setting (TOML or JSON file, then
//! `key=value` overrides from the command line).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CustodyMode {
    /// No receipts are sealed and none are required.
    Off,
    Ed25519,
    SshsigEd25519,
    HmacSha256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConeSourceKind {
    /// Static Python import cones from `ast-sweep`.
    Python,
    /// Units and their input globs declared in a manifest file in the tree.
    Manifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LandConfig {
    /// Most candidates composed into one speculative batch.
    pub max_batch_size: usize,
    /// How long a batch of two or more waits for company. A queue of one
    /// never waits.
    pub batch_coalesce_ms: u64,
    pub test_timeout_s: u64,
    pub max_reruns_on_flake: u32,
    pub runner_concurrency: usize,
    pub cache_dir: PathBuf,
    pub custody_mode: CustodyMode,
    pub ast_sweep_enabled: bool,

    pub remote: String,
    pub target_ref: String,
    /// Argv of one test unit. `{unit}` and `{path}` are substituted.
    pub test_command: Vec<String>,
    /// Environment variables the isolated runner inherits; all others are cleared.
    pub env_allow: Vec<String>,
    pub cone_source: ConeSourceKind,
    /// Rule pack (TOML or JSON) for `ast-sweep`.
    pub rules: Option<PathBuf>,
    /// Path, inside the tree, of the unit manifest for `cone_source = "manifest"`.
    pub unit_manifest: String,
    pub committer_name: String,
    pub committer_email: String,
    /// Sends allowed for one delivery before it is declined.
    pub max_refusals: u32,
    pub refusal_backoff_s: u64,
    pub seat: String,
    pub custody_key: Option<PathBuf>,
}

impl Default for LandConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 8,
            batch_coalesce_ms: 250,
            test_timeout_s: 600,
            max_reruns_on_flake: 1,
            runner_concurrency: 4,
            cache_dir: PathBuf::from(".landd-cache"),
            custody_mode: CustodyMode::Off,
            ast_sweep_enabled: true,
            remote: "origin".into(),
            target_ref: "refs/heads/main".into(),
            test_command: ["python3", "-m", "pytest", "-q", "{path}"].map(String::from).to_vec(),
            env_allow: ["PATH", "LANG", "LC_ALL", "TZ"].map(String::from).to_vec(),
            cone_source: ConeSourceKind::Python,
            rules: None,
            unit_manifest: "landd-units.json".into(),
            committer_name: "landd".into(),
            committer_email: "landd@localhost".into(),
            max_refusals: 5,
            refusal_backoff_s: 5,
            seat: "landd".into(),
            custody_key: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("override {0:?} is not key=value")]
    BadOverride(String),
    #[error("unknown setting {0:?}")]
    UnknownKey(String),
    #[error("invalid setting: {0}")]
    Invalid(String),
}

impl LandConfig {
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.validated()
    }

    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_json::from_str(text)?;
        config.validated()
    }

    /// `.json` files are JSON; everything else is TOML.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io { path: path.to_owned(), source })?;
        if path.extension().is_some_and(|e| e == "json") {
            Self::from_json(&text)
        } else {
            Self::from_toml(&text)
        }
    }

    /// Apply one `key=value` override. The value is read as JSON when it
    /// parses as JSON (`8`, `true`, `["sh","-c","x"]`) and as a string otherwise.
    pub fn with_override(self, spec: &str) -> Result<Self, ConfigError> {
        let (key, raw) = spec.split_once('=').ok_or_else(|| ConfigError::BadOverride(spec.to_owned()))?;
        let key = key.trim();
        let mut tree = serde_json::to_value(&self)?;
        let fields = tree.as_object_mut().expect("LandConfig serializes to an object");
        if !fields.contains_key(key) {
            return Err(ConfigError::UnknownKey(key.to_owned()));
        }
        let value = serde_json::from_str(raw).unwrap_or_else(|_| serde_json::Value::String(raw.to_owned()));
        fields.insert(key.to_owned(), value);
        let config: Self = serde_json::from_value(tree)?;
        config.validated()
    }

    pub fn with_overrides<S: AsRef<str>>(self, specs: &[S]) -> Result<Self, ConfigError> {
        specs.iter().try_fold(self, |config, spec| config.with_override(spec.as_ref()))
    }

    fn validated(self) -> Result<Self, ConfigError> {
        let need = |ok: bool, what: &str| if ok { Ok(()) } else { Err(ConfigError::Invalid(what.to_owned())) };
        need(self.max_batch_size >= 1, "max_batch_size must be at least 1")?;
        need(self.runner_concurrency >= 1, "runner_concurrency must be at least 1")?;
        need(self.test_timeout_s >= 1, "test_timeout_s must be at least 1")?;
        need(!self.test_command.is_empty(), "test_command must name a program")?;
        need(self.target_ref.starts_with("refs/"), "target_ref must be a full ref name (refs/...)")?;
        need(!self.remote.is_empty(), "remote must not be empty")?;
        need(
            self.custody_mode == CustodyMode::Off || self.custody_key.is_some(),
            "custody_mode other than off needs custody_key",
        )?;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_spec_examples() {
        let c = LandConfig::default();
        assert_eq!((c.max_batch_size, c.batch_coalesce_ms), (8, 250));
        assert_eq!(c.custody_mode, CustodyMode::Off);
        assert!(c.ast_sweep_enabled);
    }

    #[test]
    fn toml_and_json_agree() {
        let toml = LandConfig::from_toml(
            "max_batch_size = 3\nbatch_coalesce_ms = 10\ncache_dir = \"/var/cache/landd\"\ncone_source = \"manifest\"\n",
        )
        .unwrap();
        let json = LandConfig::from_json(
            r#"{"max_batch_size":3,"batch_coalesce_ms":10,"cache_dir":"/var/cache/landd","cone_source":"manifest"}"#,
        )
        .unwrap();
        assert_eq!(toml, json);
        assert_eq!(toml.cone_source, ConeSourceKind::Manifest);
        assert_eq!(toml.test_timeout_s, 600);
    }

    #[test]
    fn overrides_cover_every_limit() {
        let c = LandConfig::default()
            .with_overrides(&[
                "max_batch_size=2",
                "batch_coalesce_ms=0",
                "test_timeout_s=5",
                "max_reruns_on_flake=0",
                "runner_concurrency=16",
                "cache_dir=/x/y",
                "ast_sweep_enabled=false",
                r#"test_command=["sh","{path}"]"#,
            ])
            .unwrap();
        assert_eq!(c.max_batch_size, 2);
        assert_eq!(c.batch_coalesce_ms, 0);
        assert_eq!(c.test_timeout_s, 5);
        assert_eq!(c.max_reruns_on_flake, 0);
        assert_eq!(c.runner_concurrency, 16);
        assert_eq!(c.cache_dir, PathBuf::from("/x/y"));
        assert!(!c.ast_sweep_enabled);
        assert_eq!(c.test_command, vec!["sh", "{path}"]);
    }

    #[test]
    fn tooth_bad_settings_are_refused() {
        assert!(matches!(LandConfig::from_toml("max_batch_sise = 3"), Err(ConfigError::Toml(_))));
        assert!(matches!(LandConfig::from_toml("max_batch_size = 0"), Err(ConfigError::Invalid(_))));
        assert!(matches!(LandConfig::default().with_override("nope=1"), Err(ConfigError::UnknownKey(_))));
        assert!(matches!(LandConfig::default().with_override("max_batch_size"), Err(ConfigError::BadOverride(_))));
        assert!(matches!(LandConfig::default().with_override("max_batch_size=many"), Err(ConfigError::Json(_))));
        assert!(matches!(LandConfig::default().with_override("target_ref=main"), Err(ConfigError::Invalid(_))));
        assert!(matches!(LandConfig::default().with_override("custody_mode=ed25519"), Err(ConfigError::Invalid(_))));
    }
}
