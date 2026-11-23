//! `LandConfig`: every limit is a runtime setting (TOML or JSON file, then
//! `key=value` overrides from the command line).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
    /// Static import and read cones from `ast-sweep`.
    #[serde(alias = "imports")]
    Python,
    /// Units and their input globs declared in a manifest file in the tree.
    Manifest,
}

/// How test units are kept away from the supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Isolation {
    /// Each unit runs in a `bwrap` sandbox: its own user, mount, pid, ipc and
    /// (unless `sandbox_network`) network namespaces, a filesystem made of
    /// read-only system directories and the unit's own view, and nothing
    /// else of the host. Required whenever receipts are signed.
    Bwrap,
    /// Units run as ordinary child processes of the supervisor's user. They
    /// can read whatever that user can, including the verdict store and any
    /// key file. For trusted code on a developer machine only; receipts
    /// cannot be signed in this mode.
    None,
}

/// What a unit sees of the tree it is tested on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnitView {
    /// Only the files of the unit's cone. A read the cone does not account
    /// for finds no file, instead of silently depending on one.
    Cone,
    /// The whole tree.
    Tree,
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
    /// Trusted state: facts, verdicts, deliveries, the daemon queue. Must be
    /// absolute and outside the repository. Unset means
    /// `$XDG_STATE_HOME/landd`, else `$HOME/.local/state/landd`.
    pub cache_dir: Option<PathBuf>,
    pub custody_mode: CustodyMode,
    pub ast_sweep_enabled: bool,

    pub remote: String,
    pub target_ref: String,
    /// Argv of one test unit. `{unit}` and `{path}` are substituted.
    pub test_command: Vec<String>,
    /// Environment variables the runner passes through; all others are cleared.
    pub env_allow: Vec<String>,
    pub cone_source: ConeSourceKind,
    /// Rule pack (TOML or JSON) for `ast-sweep`. Always an operator path:
    /// never read from the tree under test.
    pub rules: Option<PathBuf>,
    /// A `gateaudits.json` (operator path) whose guards, domains and
    /// dynamic-loader declarations join the rule pack.
    pub gateaudits: Option<PathBuf>,
    /// Path, inside the tree, of the unit manifest for `cone_source = "manifest"`.
    pub unit_manifest: String,
    pub committer_name: String,
    pub committer_email: String,
    /// Sends allowed for one delivery before it is declined.
    pub max_refusals: u32,
    pub refusal_backoff_s: u64,
    pub seat: String,
    pub custody_key: Option<PathBuf>,

    pub isolation: Isolation,
    pub unit_view: UnitView,
    /// Host directories the sandbox mounts read-only (those that exist).
    pub sandbox_ro: Vec<String>,
    /// Let sandboxed units reach the network.
    pub sandbox_network: bool,
    /// Commands whose output identifies the toolchain (`["python3", "-VV"]`).
    /// Their output is part of every verdict's identity.
    pub profile_commands: Vec<Vec<String>>,
    /// The operator's name for the runtime image under `sandbox_ro`. landd
    /// hashes the test program itself and the output of `profile_commands`,
    /// not every library under `/usr`: recorded verdicts are valid for one
    /// runtime image, and this id (part of every verdict's identity) is how
    /// the operator says the image changed.
    pub runtime_id: String,
    /// A candidate may delete check units that exist on the base.
    pub allow_unit_removal: bool,
    /// A unit that fails without naming items on both base and candidate
    /// counts as an inherited red. Off by default: two such failures cannot
    /// be compared, so the candidate may be hiding a new one.
    pub inherit_coarse_failures: bool,
    /// Pass `--no-verify` to `git push` (skip client-side pre-push hooks).
    pub push_no_verify: bool,
    /// Extra environment for `git push`.
    pub push_env: BTreeMap<String, String>,
    /// Deadline for each `ls-remote`, `fetch` and `push`.
    pub network_timeout_s: u64,
    /// Blobs larger than this are not parsed; their readers widen.
    pub max_blob_bytes: u64,
    /// Overrides the canonical push destination as the repository's identity
    /// in delivery bindings and receipts.
    pub repo_id: Option<String>,
    /// Daemon: connections served at once.
    pub max_connections: usize,
    /// Daemon: seconds a client has to send its request and take the reply.
    pub request_timeout_s: u64,
    /// Daemon: settled lanes kept for `status`.
    pub settled_history: usize,
}

impl Default for LandConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 8,
            batch_coalesce_ms: 250,
            test_timeout_s: 600,
            max_reruns_on_flake: 1,
            runner_concurrency: 4,
            cache_dir: None,
            custody_mode: CustodyMode::Off,
            ast_sweep_enabled: true,
            remote: "origin".into(),
            target_ref: "refs/heads/main".into(),
            test_command: ["python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "{path}"].map(String::from).to_vec(),
            env_allow: ["PATH", "LANG", "LC_ALL", "TZ"].map(String::from).to_vec(),
            cone_source: ConeSourceKind::Python,
            rules: None,
            gateaudits: None,
            unit_manifest: "landd-units.json".into(),
            committer_name: "landd".into(),
            committer_email: "landd@localhost".into(),
            max_refusals: 5,
            refusal_backoff_s: 5,
            seat: "landd".into(),
            custody_key: None,
            isolation: Isolation::Bwrap,
            unit_view: UnitView::Cone,
            sandbox_ro: ["/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc"].map(String::from).to_vec(),
            sandbox_network: false,
            profile_commands: Vec::new(),
            runtime_id: String::new(),
            allow_unit_removal: false,
            inherit_coarse_failures: false,
            push_no_verify: true,
            push_env: BTreeMap::new(),
            network_timeout_s: 120,
            max_blob_bytes: 64 << 20,
            repo_id: None,
            max_connections: 32,
            request_timeout_s: 10,
            settled_history: 256,
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

/// `git check-ref-format` for a full ref name, plus the characters a refspec
/// or an option parser would read as something else.
pub fn valid_ref_name(name: &str) -> bool {
    let forbidden = |c: char| c.is_ascii_control() || " ~^:?*[\\".contains(c);
    name.starts_with("refs/")
        && !name.ends_with('/')
        && !name.ends_with('.')
        && !name.contains("..")
        && !name.contains("@{")
        && !name.contains("//")
        && !name.chars().any(forbidden)
        && name.split('/').all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

/// A remote name or URL that cannot be read as an option or a refspec.
pub fn valid_remote(remote: &str) -> bool {
    !remote.is_empty() && !remote.starts_with(['-', '+']) && !remote.chars().any(|c| c.is_ascii_control() || c.is_whitespace())
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

    /// The trusted state directory: `cache_dir`, else the user's state
    /// directory. Always absolute, so it never depends on the directory a
    /// command happens to run in (a checkout could carry a planted cache).
    pub fn state_dir(&self) -> Result<PathBuf, ConfigError> {
        if let Some(dir) = &self.cache_dir {
            return Ok(dir.clone());
        }
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("state")))
            .filter(|p| p.is_absolute())
            .ok_or_else(|| {
                ConfigError::Invalid("cache_dir is unset and neither XDG_STATE_HOME nor HOME names a directory".into())
            })?;
        Ok(base.join("landd"))
    }

    fn validated(self) -> Result<Self, ConfigError> {
        let need = |ok: bool, what: &str| if ok { Ok(()) } else { Err(ConfigError::Invalid(what.to_owned())) };
        need(self.max_batch_size >= 1, "max_batch_size must be at least 1")?;
        need(self.runner_concurrency >= 1, "runner_concurrency must be at least 1")?;
        need(self.test_timeout_s >= 1, "test_timeout_s must be at least 1")?;
        need(self.network_timeout_s >= 1, "network_timeout_s must be at least 1")?;
        need(self.max_connections >= 1, "max_connections must be at least 1")?;
        need(self.request_timeout_s >= 1, "request_timeout_s must be at least 1")?;
        need(self.settled_history >= 1, "settled_history must be at least 1")?;
        need(!self.test_command.is_empty() && !self.test_command[0].is_empty(), "test_command must name a program")?;
        need(self.profile_commands.iter().all(|c| !c.is_empty()), "profile_commands entries must name a program")?;
        need(valid_ref_name(&self.target_ref), "target_ref must be a well-formed full ref name (refs/...)")?;
        need(valid_remote(&self.remote), "remote must be a remote name or URL, not an option or refspec")?;
        need(self.cache_dir.as_ref().is_none_or(|dir| dir.is_absolute()), "cache_dir must be an absolute path")?;
        need(
            self.custody_mode == CustodyMode::Off || self.custody_key.is_some(),
            "custody_mode other than off needs custody_key",
        )?;
        need(
            self.custody_mode == CustodyMode::Off || self.isolation == Isolation::Bwrap,
            "receipts can only be signed with isolation = \"bwrap\": without a sandbox the units under test can read the signing key",
        )?;
        need(
            !self.unit_manifest.is_empty()
                && !self.unit_manifest.starts_with('/')
                && !self.unit_manifest.split('/').any(|p| p == ".."),
            "unit_manifest must be a path inside the tree",
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
        assert_eq!((c.isolation, c.unit_view), (Isolation::Bwrap, UnitView::Cone));
        assert!(!c.allow_unit_removal && !c.inherit_coarse_failures && !c.sandbox_network);
    }

    #[test]
    fn toml_and_json_agree() {
        let toml = LandConfig::from_toml(
            "max_batch_size = 3\nbatch_coalesce_ms = 10\ncache_dir = \"/var/cache/landd\"\ncone_source = \"manifest\"\nisolation = \"none\"\n",
        )
        .unwrap();
        let json = LandConfig::from_json(
            r#"{"max_batch_size":3,"batch_coalesce_ms":10,"cache_dir":"/var/cache/landd","cone_source":"manifest","isolation":"none"}"#,
        )
        .unwrap();
        assert_eq!(toml, json);
        assert_eq!(toml.cone_source, ConeSourceKind::Manifest);
        assert_eq!(toml.test_timeout_s, 600);
        assert_eq!(toml.state_dir().unwrap(), PathBuf::from("/var/cache/landd"));
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
                "network_timeout_s=7",
                r#"push_env={"FAB_PUSH_IS_LAND":"1"}"#,
                "push_no_verify=false",
            ])
            .unwrap();
        assert_eq!(c.max_batch_size, 2);
        assert_eq!(c.batch_coalesce_ms, 0);
        assert_eq!(c.test_timeout_s, 5);
        assert_eq!(c.max_reruns_on_flake, 0);
        assert_eq!(c.runner_concurrency, 16);
        assert_eq!(c.cache_dir, Some(PathBuf::from("/x/y")));
        assert!(!c.ast_sweep_enabled && !c.push_no_verify);
        assert_eq!(c.test_command, vec!["sh", "{path}"]);
        assert_eq!(c.push_env["FAB_PUSH_IS_LAND"], "1");
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
        // A relative cache directory would follow the working directory into a checkout.
        assert!(matches!(LandConfig::default().with_override("cache_dir=.landd-cache"), Err(ConfigError::Invalid(_))));
        assert!(matches!(LandConfig::default().with_override("unit_manifest=../outside.json"), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn tooth_signing_requires_the_sandbox() {
        let signed = LandConfig::default().with_overrides(&["custody_key=/keys/seat.json", "custody_mode=ed25519"]).unwrap();
        assert_eq!(signed.isolation, Isolation::Bwrap);
        assert!(matches!(signed.with_override("isolation=none"), Err(ConfigError::Invalid(_))));
        let local = LandConfig::default().with_override("isolation=none").unwrap();
        assert!(matches!(
            local.with_overrides(&["custody_key=/keys/seat.json", "custody_mode=ed25519"]),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn tooth_ref_and_remote_names_cannot_smuggle_options_or_refspecs() {
        for good in ["refs/heads/main", "refs/heads/release/1.2", "refs/tags/v1"] {
            assert!(valid_ref_name(good), "{good}");
        }
        for bad in [
            "main",
            "refs/",
            "refs/heads/",
            "refs/heads/a..b",
            "refs/heads/a:refs/heads/b",
            "refs/heads/a b",
            "refs/heads/.hidden",
            "refs/heads/x.lock",
            "refs/heads/a//b",
            "refs/heads/a@{1}",
            "refs/heads/a~1",
            "refs/heads/a^",
            "refs/heads/a*",
            "refs/heads/a\n",
            "+refs/heads/main",
            "-refs/heads/main",
            "refs/heads/a.",
        ] {
            assert!(!valid_ref_name(bad), "{bad:?}");
            assert!(
                LandConfig::default().with_override(&format!("target_ref={}", serde_json::to_string(bad).unwrap())).is_err(),
                "{bad:?}"
            );
        }
        for good in ["origin", "ssh://git@forge/x.git", "/srv/forge.git", "git@forge:x.git"] {
            assert!(valid_remote(good), "{good}");
        }
        for bad in ["", "--upload-pack=evil", "+origin", "a b", "a\tb", "a\nb"] {
            assert!(!valid_remote(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_default_state_directory_is_absolute() {
        let dir = LandConfig::default().state_dir().unwrap();
        assert!(dir.is_absolute() && dir.ends_with("landd"), "{}", dir.display());
    }
}
