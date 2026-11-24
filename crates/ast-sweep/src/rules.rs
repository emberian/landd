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

/// A TypeScript or JavaScript specifier that is neither relative, a workspace package, nor claimed by `tsconfig` paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BareImports {
    /// An external leaf: `node:*` built-ins add no tree inputs, and bare npm packages bind deterministically to the
    /// nearest lockfile (`pnpm-lock.yaml`, `package-lock.json`, `yarn.lock`, `Cargo.lock`) when present.
    #[default]
    External,
    /// Widen the cone to the whole tree, as an unresolved load does.
    Widen,
}

/// What a cone does about a read it cannot bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConeModel {
    /// Static analysis alone must justify the cone. A read through a path
    /// the analysis cannot follow (a parameter, an attribute, a computed
    /// name), a child process, and an undeclared dynamic load each widen
    /// the cone to the whole tree.
    #[default]
    Strict,
    /// The cone is enforced, not only inferred: the runner shows a unit
    /// nothing but its cone's files, so a read the analysis missed finds no
    /// file instead of silently depending on one. Opaque reads, child
    /// processes and dynamic imports therefore do not widen; a path with a
    /// known directory and an unknown tail reads that directory's subtree.
    /// Scans the analysis cannot bound still widen, because a scan of
    /// missing files passes vacuously. Only sound with `unit_view = "cone"`.
    Hermetic,
}

/// What a loader declaration is worth when the loader's source does not
/// show where its loads go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnverifiedLoaders {
    /// Nothing: the loader widens every cone that reaches it.
    #[default]
    Taint,
    /// The operator's word.
    Trust,
}

fn default_roots() -> Vec<String> {
    vec![String::new()]
}

fn default_tests() -> Vec<String> {
    vec!["**/test_*.py".to_owned()]
}

fn default_always() -> Vec<String> {
    ["pytest.ini", "pyproject.toml", "setup.cfg", "tox.ini"].map(String::from).to_vec()
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
    /// Files every unit depends on (test-runner configuration).
    #[serde(default = "default_always")]
    pub always: Vec<String>,
    /// Extra inputs a unit reads without importing them: unit name pattern
    /// -> path patterns (both fnmatch: `*` crosses `.` and `/`).
    #[serde(default)]
    pub guards: BTreeMap<String, Vec<String>>,
    /// Declared dynamic loaders: file -> the path patterns its dynamic loads
    /// can reach. A declaration counts only while the loader's own source
    /// agrees with it (see `unverified_loaders`); it is checked again on
    /// every tree, so an edit to the loader cannot hide behind it.
    #[serde(default)]
    pub loaders: BTreeMap<String, Vec<String>>,
    /// As `loaders`, keyed and valued by module (`a.b`, `a.b.*`), the form
    /// `gateaudits.json` uses.
    #[serde(default)]
    pub loader_modules: BTreeMap<String, Vec<String>>,
    /// Calls that read the whole tree (dotted-name patterns).
    #[serde(default)]
    pub whole_tree_calls: Vec<String>,
    #[serde(default)]
    pub cone_model: ConeModel,
    #[serde(default)]
    pub unverified_loaders: UnverifiedLoaders,
    /// Explicit TypeScript `compilerOptions.paths` overrides (`@/*` -> `["./src/*"]`), resolved relative to
    /// `ts_base_url` before any auto-discovered `tsconfig.json` in the tree.
    #[serde(default)]
    pub ts_paths: BTreeMap<String, Vec<String>>,
    /// Explicit `compilerOptions.baseUrl` for `ts_paths` (empty is the tree root).
    #[serde(default)]
    pub ts_base_url: String,
    /// What a non-relative specifier that no `tsconfig` alias or workspace package claims does to a cone.
    #[serde(default)]
    pub bare_imports: BareImports,
}

impl Default for ImportConfig {
    fn default() -> Self {
        Self {
            roots: default_roots(),
            tests: default_tests(),
            implicit_conftest: true,
            always: default_always(),
            guards: BTreeMap::new(),
            loaders: BTreeMap::new(),
            loader_modules: BTreeMap::new(),
            whole_tree_calls: Vec::new(),
            cone_model: ConeModel::default(),
            unverified_loaders: UnverifiedLoaders::default(),
            ts_paths: BTreeMap::new(),
            ts_base_url: String::new(),
            bare_imports: BareImports::default(),
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

/// The parts of a `gateaudits.json` that describe what units read. Its
/// other tables (`carries`, `unrun`, `ledgers`, `absent`) are selection and
/// merge hints for another tool and are not consumed: in particular `unrun`
/// ("no test reads this file") is not used to shrink whole-tree cones,
/// because a unit that reads every tracked file does read those files.
#[derive(Deserialize)]
struct GateAudits {
    #[serde(default)]
    guards: BTreeMap<String, GateGuard>,
    #[serde(default)]
    domains: BTreeMap<String, GateDomain>,
    #[serde(default)]
    dynamic: BTreeMap<String, GateLoader>,
}

#[derive(Deserialize)]
struct GateGuard {
    #[serde(default)]
    reads: Vec<String>,
}

#[derive(Deserialize)]
struct GateDomain {
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Deserialize)]
struct GateLoader {
    #[serde(default)]
    loads: Vec<String>,
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

    /// Adopt a `gateaudits.json`: `guards` (unit -> reads) and `domains`
    /// (unit pattern -> paths) become extra cone inputs of the units they
    /// name, and `dynamic` (module -> loads) becomes loader declarations.
    pub fn with_gateaudits(mut self, text: &str) -> Result<Self, RuleError> {
        let audits: GateAudits = serde_json::from_str(text)?;
        for (unit, guard) in audits.guards {
            self.imports.guards.entry(unit).or_default().extend(guard.reads);
        }
        for (units, domain) in audits.domains {
            self.imports.guards.entry(units).or_default().extend(domain.paths);
        }
        for (module, loader) in audits.dynamic {
            self.imports.loader_modules.entry(module).or_default().extend(loader.loads);
        }
        Ok(self)
    }

    /// Identifies this pack. It is part of every cone's context, so a
    /// verdict made under one pack is never read under another.
    pub fn digest(&self) -> landd_core::Digest32 {
        let canonical = landd_core::canonical_json(self).expect("a rule pack has no floats");
        landd_core::Digest32::tagged("ast-sweep rule pack v1", &[&canonical, crate::facts::facts_version().as_bytes()])
    }

    /// Whether some rule needs the import graph (cones, or forbidden
    /// imports, which resolve relative imports through it).
    pub fn needs_graph(&self) -> bool {
        self.exports_cones() || self.rule.iter().any(|r| !r.imports.is_empty() || !r.symbols.is_empty())
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
                RuleKind::SingleOwnerPattern if rule.owners.len() != 1 => return Err(invalid("needs exactly one owner path")),
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
        let twice =
            "[[rule]]\nid = \"x\"\nkind = \"no_tracked_bytecode\"\n[[rule]]\nid = \"x\"\nkind = \"no_tracked_bytecode\"\n";
        assert!(matches!(bad(twice), RuleError::Invalid { .. }));
    }

    #[test]
    fn gateaudits_guards_become_cone_reads() {
        let audits = r#"{"schema": 2, "carries": ["test_one_owner"], "guards": {
            "tests.door.test_help_artifact": {"reads": ["*"], "why": "copies the whole repo"},
            "tests.door.test_service_state_base": {"reads": ["fabd/*", "land/*", "unchanged.py"], "why": "copies fabd"}},
            "domains": {"tests.fleetd.test_task*": {"naming": ["TaskDefaults"], "paths": ["fleetd/taskdefaults.json"], "why": "reads the catalog as data"}},
            "dynamic": {"land.checks": {"loads": ["land.checks.*"], "why": "by name"}, "fleetd.hooks.capability": {"loads": [], "why": "find_spec"}},
            "unrun": {"LICENSE": "no source reads it"}, "ledgers": {}, "absent": {}}"#;
        let pack = RulePack::builtin().with_gateaudits(audits).unwrap();
        assert_eq!(pack.imports.guards["tests.door.test_help_artifact"], vec!["*"]);
        assert_eq!(pack.imports.guards["tests.door.test_service_state_base"].len(), 3);
        assert_eq!(pack.imports.guards["tests.fleetd.test_task*"], vec!["fleetd/taskdefaults.json"]);
        assert_eq!(pack.imports.loader_modules["land.checks"], vec!["land.checks.*"]);
        assert!(pack.imports.loader_modules["fleetd.hooks.capability"].is_empty());
        assert!(pack.exports_cones());
        // The pack's identity moves with every declaration.
        assert_ne!(pack.digest(), RulePack::builtin().digest());
        assert_eq!(pack.digest(), RulePack::builtin().with_gateaudits(audits).unwrap().digest());
    }
}
