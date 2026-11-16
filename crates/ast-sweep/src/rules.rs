//! Declarative rule packs (TOML or JSON).
//!
//! ```toml
//! [imports]
//! tests = ["tests/**/test_*.py"]
//!
//! [[rule]]
//! id = "atomic-replace"
//! kind = "atomic_replace_owner"
//! owners = ["fleetd/pk.py"]
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// No `*.pyc` / `*.pyo` / `__pycache__` in the tree.
    NoTrackedBytecode,
    /// No bare `python` command in recipes or subprocess argv.
    NoBarePythonRecipe,
    /// No blocking `flock` outside `owners`; no unbounded sleep-poll loop anywhere in scope.
    FlockBounded,
    /// `os.replace` / `os.rename` only in `owners` (or at an `allow`ed `path::function`).
    AtomicReplaceOwner,
    /// Dotted literal settings reads must exist in one of `catalogs`.
    UncataloguedSettingsKeys,
    /// `symbols`, `imports` and `facts` that must not appear in scope.
    ForbiddenSymbolOrCall,
    /// `functions` are defined, and the owner's bodies appear, only in the owner.
    SingleOwnerPattern,
    /// Export import cones; fail on relative imports that resolve to nothing.
    PythonImportGraph,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactSelector {
    DynamicLoad,
    Scan,
    Strftime,
    SysExecutable,
    ExceptionStoredOnSelf,
    ParseError,
}

fn default_readers() -> Vec<String> {
    ["setting", "or_default", "get"].map(String::from).to_vec()
}

fn default_min_statements() -> u32 {
    3
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub kind: RuleKind,
    /// Paths the rule looks at; empty means every path.
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Why the rule exists; echoed in findings.
    #[serde(default)]
    pub why: Option<String>,
    /// Owner paths (`flock_bounded`, `atomic_replace_owner`, `single_owner_pattern`).
    #[serde(default)]
    pub owners: Vec<String>,
    /// Exemptions: path globs, or `path::function` for `atomic_replace_owner`.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Catalog JSON files in the tree (`uncatalogued_settings_keys`).
    #[serde(default)]
    pub catalogs: Vec<String>,
    /// Callee names that read settings.
    #[serde(default = "default_readers")]
    pub readers: Vec<String>,
    #[serde(default)]
    pub ignore_keys: Vec<String>,
    /// Dotted-name patterns (`forbidden_symbol_or_call`).
    #[serde(default)]
    pub symbols: Vec<String>,
    /// Only calls of `symbols` count, not mere references.
    #[serde(default)]
    pub calls_only: bool,
    /// Module patterns that must not be imported.
    #[serde(default)]
    pub imports: Vec<String>,
    #[serde(default)]
    pub facts: Vec<FactSelector>,
    /// Function-name patterns (`single_owner_pattern`).
    #[serde(default)]
    pub functions: Vec<String>,
    /// Bodies shorter than this are not compared for copies.
    #[serde(default = "default_min_statements")]
    pub min_statements: u32,
}

impl Rule {
    pub fn new(id: &str, kind: RuleKind) -> Self {
        Self {
            id: id.to_owned(),
            kind,
            include: Vec::new(),
            exclude: Vec::new(),
            why: None,
            owners: Vec::new(),
            allow: Vec::new(),
            catalogs: Vec::new(),
            readers: default_readers(),
            ignore_keys: Vec::new(),
            symbols: Vec::new(),
            calls_only: false,
            imports: Vec::new(),
            facts: Vec::new(),
            functions: Vec::new(),
            min_statements: default_min_statements(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TaintPolicy {
    /// A cone that reaches a dynamic load depends on the whole tree.
    #[default]
    WholeTree,
    /// A cone that reaches a dynamic load depends on every file under the
    /// loader's own directory (the plugin-package pattern). A heuristic: it
    /// is wrong for a loader that reads paths outside its package.
    Package,
    /// Record the taint bit and keep the static cone.
    FlagOnly,
}

fn default_roots() -> Vec<String> {
    vec![String::new()]
}

fn default_tests() -> Vec<String> {
    vec!["**/test_*.py".to_owned()]
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportConfig {
    /// Directories that are on `sys.path`; `""` is the tree root.
    #[serde(default = "default_roots")]
    pub roots: Vec<String>,
    /// Which files are test units.
    #[serde(default = "default_tests")]
    pub tests: Vec<String>,
    /// A test also depends on every `conftest.py` above it.
    #[serde(default = "default_true")]
    pub implicit_conftest: bool,
    /// Extra inputs a unit reads without importing them: unit -> path patterns.
    #[serde(default)]
    pub guards: BTreeMap<String, Vec<String>>,
    /// Audited dynamic loaders: file -> the path patterns its dynamic loads
    /// can reach. A declared loader does not taint; its reads join the cone
    /// of everything that imports it.
    #[serde(default)]
    pub loaders: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub taint: TaintPolicy,
}

impl Default for ImportConfig {
    fn default() -> Self {
        Self {
            roots: default_roots(),
            tests: default_tests(),
            implicit_conftest: true,
            guards: BTreeMap::new(),
            loaders: BTreeMap::new(),
            taint: TaintPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePack {
    #[serde(default)]
    pub imports: ImportConfig,
    #[serde(default, alias = "rules")]
    pub rule: Vec<Rule>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("reading {path}: {detail}")]
    Io { path: String, detail: String },
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("rule {id:?}: {problem}")]
    Invalid { id: String, problem: String },
}

#[derive(Deserialize)]
struct GateAudits {
    #[serde(default)]
    guards: BTreeMap<String, GateGuard>,
}

#[derive(Deserialize)]
struct GateGuard {
    #[serde(default)]
    reads: Vec<String>,
}

impl RulePack {
    /// Bytecode, bare-python and import-graph rules with default scopes.
    pub fn builtin() -> Self {
        Self {
            imports: ImportConfig::default(),
            rule: vec![
                Rule::new("no-tracked-bytecode", RuleKind::NoTrackedBytecode),
                Rule::new("no-bare-python-recipe", RuleKind::NoBarePythonRecipe),
                Rule::new("python-import-graph", RuleKind::PythonImportGraph),
            ],
        }
    }

    pub fn from_toml(text: &str) -> Result<Self, RuleError> {
        toml::from_str::<Self>(text)?.validated()
    }

    pub fn from_json(text: &str) -> Result<Self, RuleError> {
        serde_json::from_str::<Self>(text)?.validated()
    }

    pub fn load(path: &Path) -> Result<Self, RuleError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| RuleError::Io { path: path.display().to_string(), detail: e.to_string() })?;
        if path.extension().is_some_and(|e| e == "json") {
            Self::from_json(&text)
        } else {
            Self::from_toml(&text)
        }
    }

    /// Adopt the `guards` table of a `gateaudits.json`: each guarded test
    /// module's `reads` become extra cone inputs for that unit.
    pub fn with_gateaudits(mut self, text: &str) -> Result<Self, RuleError> {
        let audits: GateAudits = serde_json::from_str(text)?;
        for (unit, guard) in audits.guards {
            self.imports.guards.entry(unit).or_default().extend(guard.reads);
        }
        Ok(self)
    }

    pub fn exports_cones(&self) -> bool {
        self.rule.iter().any(|r| r.kind == RuleKind::PythonImportGraph)
    }

    fn validated(self) -> Result<Self, RuleError> {
        let mut seen = std::collections::BTreeSet::new();
        for rule in &self.rule {
            let invalid = |problem: &str| RuleError::Invalid { id: rule.id.clone(), problem: problem.to_owned() };
            if rule.id.is_empty() {
                return Err(invalid("id must not be empty"));
            }
            if !seen.insert(rule.id.as_str()) {
                return Err(invalid("id is used twice"));
            }
            match rule.kind {
                RuleKind::AtomicReplaceOwner if rule.owners.is_empty() => return Err(invalid("needs owners")),
                RuleKind::UncataloguedSettingsKeys if rule.catalogs.is_empty() => return Err(invalid("needs catalogs")),
                RuleKind::ForbiddenSymbolOrCall
                    if rule.symbols.is_empty() && rule.imports.is_empty() && rule.facts.is_empty() =>
                {
                    return Err(invalid("needs symbols, imports or facts"))
                }
                RuleKind::SingleOwnerPattern if rule.owners.len() != 1 => {
                    return Err(invalid("needs exactly one owner path"))
                }
                _ => {}
            }
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACK: &str = r#"
[imports]
roots = ["", "src"]
tests = ["tests/**/test_*.py"]

[[rule]]
id = "replace"
kind = "atomic_replace_owner"
owners = ["fleetd/pk.py"]
allow = ["land/x.py::swap"]

[[rule]]
id = "no-stopfacts"
kind = "forbidden_symbol_or_call"
include = ["fleetd/*"]
symbols = ["land.stopfacts.*"]
imports = ["land.stopfacts"]
why = "stopfacts has one reader"
"#;

    #[test]
    fn toml_and_json_packs_agree() {
        let toml = RulePack::from_toml(PACK).unwrap();
        assert_eq!(toml.rule.len(), 2);
        assert_eq!(toml.imports.roots, vec!["", "src"]);
        assert!(toml.imports.implicit_conftest);
        assert_eq!(toml.rule[0].readers, default_readers());
        let json = RulePack::from_json(&serde_json::to_string(&toml).unwrap()).unwrap();
        assert_eq!(json, toml);
        let aliased = RulePack::from_json(r#"{"rules":[{"id":"b","kind":"no_tracked_bytecode"}]}"#).unwrap();
        assert_eq!(aliased.rule[0].kind, RuleKind::NoTrackedBytecode);
    }

    #[test]
    fn tooth_malformed_packs_are_refused() {
        let bad = |text: &str| RulePack::from_toml(text).unwrap_err();
        assert!(matches!(bad("[[rule]]\nid = \"x\"\nkind = \"no_such_kind\"\n"), RuleError::Toml(_)));
        assert!(matches!(bad("[[rule]]\nid = \"x\"\nkind = \"no_tracked_bytecode\"\nownerz = []\n"), RuleError::Toml(_)));
        assert!(matches!(bad("[[rule]]\nid = \"x\"\nkind = \"atomic_replace_owner\"\n"), RuleError::Invalid { .. }));
        assert!(matches!(bad("[[rule]]\nid = \"x\"\nkind = \"forbidden_symbol_or_call\"\n"), RuleError::Invalid { .. }));
        assert!(matches!(bad("[[rule]]\nid = \"x\"\nkind = \"uncatalogued_settings_keys\"\n"), RuleError::Invalid { .. }));
        let twice = "[[rule]]\nid = \"x\"\nkind = \"no_tracked_bytecode\"\n[[rule]]\nid = \"x\"\nkind = \"no_tracked_bytecode\"\n";
        assert!(matches!(bad(twice), RuleError::Invalid { .. }));
    }

    #[test]
    fn gateaudits_guards_become_cone_reads() {
        let audits = r#"{"schema": 2, "carries": ["test_one_owner"], "guards": {
            "tests.door.test_help_artifact": {"reads": ["*"], "why": "copies the whole repo"},
            "tests.door.test_service_state_base": {"reads": ["fabd/*", "land/*", "unchanged.py"], "why": "copies fabd"}}}"#;
        let pack = RulePack::builtin().with_gateaudits(audits).unwrap();
        assert_eq!(pack.imports.guards["tests.door.test_help_artifact"], vec!["*"]);
        assert_eq!(pack.imports.guards["tests.door.test_service_state_base"].len(), 3);
        assert!(pack.exports_cones());
    }
}
