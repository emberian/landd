//! The in-memory `Reduce` pass: rule packs over [`AllFacts`].
//!
//! Nothing here reads a blob or parses source; every rule is a scan of facts
//! the map pass already extracted. A rule that cannot be evaluated (a missing
//! catalog, a missing owner) fails with a finding that says so.

use crate::cache::{BlobFactsCache, CatalogKeys};
use crate::facts::{FileFacts, Site};
use crate::glob::{Glob, GlobSet};
use crate::imports::ImportGraph;
use crate::rules::{FactSelector, Rule, RuleKind, RulePack};
use crate::sweep::{light_pool, AllFacts, FileEntry};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Finding {
    pub path: String,
    /// 0 when the finding is about the file as a whole.
    pub line: u32,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleVerdict {
    pub rule_id: String,
    pub kind: RuleKind,
    pub status: VerdictStatus,
    pub why: Option<String>,
    pub findings: Vec<Finding>,
}

/// The settings keys each catalog file declares; `None` for a catalog that
/// is missing or is not JSON.
#[derive(Debug, Clone, Default)]
pub struct Catalogs(BTreeMap<String, Option<CatalogKeys>>);

impl Catalogs {
    /// Read the catalog files the pack names. This is the only place the
    /// reduce side touches blob content, and it happens before reducing. A
    /// catalog's key set is a function of its blob, so it is cached by blob id.
    pub fn load(
        pack: &RulePack,
        all: &AllFacts,
        cache: Option<&BlobFactsCache>,
        read: impl Fn(&FileEntry) -> Option<Vec<u8>>,
    ) -> Self {
        let mut catalogs = BTreeMap::new();
        for path in pack.rule.iter().flat_map(|r| &r.catalogs) {
            catalogs.entry(path.clone()).or_insert_with(|| {
                let entry = all.find(path)?;
                if let Some(keys) = cache.and_then(|c| c.get_catalog(&entry.oid)) {
                    return Some(keys);
                }
                let json: serde_json::Value = serde_json::from_slice(&read(entry)?).ok()?;
                let mut keys = BTreeSet::new();
                collect_keys(&json, "", &mut keys);
                let keys: CatalogKeys = Arc::new(keys.into_iter().collect());
                if let Some(cache) = cache {
                    // A failed write costs the next run a re-read, nothing else.
                    let _ = cache.put_catalog(&entry.oid, &keys);
                }
                Some(keys)
            });
        }
        Self(catalogs)
    }

    pub fn from_json(entries: &[(&str, &str)]) -> Self {
        let all = AllFacts::from_sources(entries);
        let mut pack = RulePack::default();
        let mut rule = Rule::new("catalogs", RuleKind::UncataloguedSettingsKeys);
        rule.catalogs = entries.iter().map(|(path, _)| path.to_string()).collect();
        pack.rule.push(rule);
        let content: HashMap<&str, &str> = entries.iter().copied().collect();
        Self::load(&pack, &all, None, |entry| content.get(entry.path.as_str()).map(|c| c.as_bytes().to_vec()))
    }
}

/// Every dotted path through nested objects is a key: `{"a": {"b": 1}}`
/// declares `a` and `a.b`. Arrays of strings declare their elements.
fn collect_keys(value: &serde_json::Value, prefix: &str, out: &mut BTreeSet<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
                collect_keys(child, &path, out);
                out.insert(path);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                match item {
                    serde_json::Value::String(key) if prefix.is_empty() => {
                        out.insert(key.clone());
                    }
                    serde_json::Value::String(key) => {
                        out.insert(format!("{prefix}.{key}"));
                    }
                    other => collect_keys(other, prefix, out),
                }
            }
        }
        _ => {}
    }
}

struct Scope {
    include: GlobSet,
    exclude: GlobSet,
}

impl Scope {
    fn of(rule: &Rule) -> Self {
        Self { include: GlobSet::new(&rule.include), exclude: GlobSet::new(&rule.exclude) }
    }

    fn holds(&self, path: &str) -> bool {
        (self.include.is_empty() || self.include.matches(path)) && !self.exclude.matches(path)
    }
}

fn finding(path: &str, line: u32, message: impl Into<String>) -> Finding {
    Finding { path: path.to_owned(), line, message: message.into() }
}

fn within(site: &Site) -> String {
    if site.func.is_empty() {
        String::new()
    } else {
        format!(" in {}", site.func)
    }
}

/// Files in scope that carry facts.
fn scoped<'a>(all: &'a AllFacts, scope: &'a Scope) -> impl Iterator<Item = (&'a FileEntry, &'a FileFacts)> + 'a {
    all.files.iter().filter_map(move |file| {
        let facts = file.facts.as_deref()?;
        scope.holds(&file.path).then_some((file, facts))
    })
}

fn python<'a>(all: &'a AllFacts, scope: &'a Scope) -> impl Iterator<Item = (&'a FileEntry, &'a FileFacts)> + 'a {
    scoped(all, scope).filter(|(file, _)| file.is_python())
}

pub fn reduce(all: &AllFacts, pack: &RulePack, catalogs: &Catalogs, graph: Option<&ImportGraph>) -> Vec<RuleVerdict> {
    reduce_timed(all, pack, catalogs, graph).0
}

/// As [`reduce`], with the milliseconds each rule took.
pub fn reduce_timed(
    all: &AllFacts,
    pack: &RulePack,
    catalogs: &Catalogs,
    graph: Option<&ImportGraph>,
) -> (Vec<RuleVerdict>, BTreeMap<String, f64>) {
    let timed: Vec<(RuleVerdict, f64)> = light_pool().install(|| {
        pack.rule
            .par_iter()
            .map(|rule| {
                let started = std::time::Instant::now();
                let mut findings = evaluate(all, rule, catalogs, graph);
                findings.sort();
                findings.dedup();
                let verdict = RuleVerdict {
                    rule_id: rule.id.clone(),
                    kind: rule.kind,
                    status: if findings.is_empty() { VerdictStatus::Pass } else { VerdictStatus::Fail },
                    why: rule.why.clone(),
                    findings,
                };
                (verdict, started.elapsed().as_secs_f64() * 1000.0)
            })
            .collect()
    });
    let rule_ms = timed.iter().map(|(verdict, ms)| (verdict.rule_id.clone(), *ms)).collect();
    (timed.into_iter().map(|(verdict, _)| verdict).collect(), rule_ms)
}

fn evaluate(all: &AllFacts, rule: &Rule, catalogs: &Catalogs, graph: Option<&ImportGraph>) -> Vec<Finding> {
    let scope = Scope::of(rule);
    let mut out = Vec::new();
    match rule.kind {
        RuleKind::NoTrackedBytecode => {
            for file in all.files.iter().filter(|f| scope.holds(&f.path)) {
                let path = file.path.as_str();
                let cached = path.starts_with("__pycache__/") || path.contains("/__pycache__/");
                if cached || path.ends_with(".pyc") || path.ends_with(".pyo") {
                    out.push(finding(path, 0, "compiled bytecode is tracked"));
                }
            }
        }
        RuleKind::NoBarePythonRecipe => {
            for (file, facts) in scoped(all, &scope) {
                for site in &facts.bare_python {
                    out.push(finding(&file.path, site.line, format!("bare `python` command: {}", site.what)));
                }
            }
        }
        RuleKind::FlockBounded => {
            let owners = GlobSet::new(&rule.owners);
            for (file, facts) in python(all, &scope) {
                for site in facts.flocks.iter().filter(|s| !s.unlock) {
                    let place = if site.func.is_empty() { String::new() } else { format!(" in {}", site.func) };
                    if !site.nonblocking && !site.flags_opaque && !owners.matches(&file.path) {
                        out.push(finding(&file.path, site.line, format!("blocking {} without LOCK_NB{place}", site.call)));
                    }
                    if site.flags_opaque && !owners.matches(&file.path) {
                        out.push(finding(
                            &file.path,
                            site.line,
                            format!(
                                "{} flags are not visible here (a variable); cannot tell whether it blocks{place}",
                                site.call
                            ),
                        ));
                    }
                    if site.polled && !site.poll_bounded {
                        out.push(finding(
                            &file.path,
                            site.line,
                            format!("{} polled in a sleep loop with no bound{place}", site.call),
                        ));
                    }
                }
            }
        }
        RuleKind::AtomicReplaceOwner => {
            let owners = GlobSet::new(&rule.owners);
            let (functions, paths): (Vec<&String>, Vec<&String>) = rule.allow.iter().partition(|a| a.contains("::"));
            let allowed_paths = GlobSet::new(&paths);
            for (file, facts) in python(all, &scope) {
                if owners.matches(&file.path) || allowed_paths.matches(&file.path) {
                    continue;
                }
                for site in &facts.replaces {
                    let here = format!("{}::{}", file.path, site.func);
                    if !functions.iter().any(|allowed| **allowed == here) {
                        out.push(finding(&file.path, site.line, format!("{} outside its owner{}", site.what, within(site))));
                    }
                }
            }
        }
        RuleKind::UncataloguedSettingsKeys => {
            let mut known: Vec<&CatalogKeys> = Vec::new();
            for path in &rule.catalogs {
                match catalogs.0.get(path).and_then(Option::as_ref) {
                    Some(keys) => known.push(keys),
                    None => out.push(finding(path, 0, "settings catalog is missing or is not JSON")),
                }
            }
            // Catalog keys are sorted: a lookup is a binary search per catalog.
            let catalogued = |key: &str| known.iter().any(|keys| keys.binary_search_by(|probe| probe.as_str().cmp(key)).is_ok());
            let ignored = GlobSet::new(&rule.ignore_keys);
            for (file, facts) in python(all, &scope) {
                for read in &facts.settings_reads {
                    let is_reader = rule.readers.contains(&read.reader);
                    if is_reader && !catalogued(&read.key) && !ignored.matches(&read.key) {
                        out.push(finding(
                            &file.path,
                            read.line,
                            format!("settings key {:?} read by {}() is in no catalog", read.key, read.reader),
                        ));
                    }
                }
            }
        }
        RuleKind::ForbiddenSymbolOrCall => forbidden(all, rule, &scope, graph, &mut out),
        RuleKind::SingleOwnerPattern => single_owner(all, rule, &scope, &mut out),
        RuleKind::PythonImportGraph => {
            for unresolved in graph.map(|g| g.unresolved_relative.as_slice()).unwrap_or_default() {
                let path = all.files[unresolved.file as usize].path.as_str();
                if scope.holds(path) {
                    let message = format!("relative import {:?} resolves to nothing in the tree", unresolved.import);
                    out.push(finding(path, unresolved.line, message));
                }
            }
        }
    }
    out
}

fn forbidden(all: &AllFacts, rule: &Rule, scope: &Scope, graph: Option<&ImportGraph>, out: &mut Vec<Finding>) {
    let allowed = GlobSet::new(&rule.allow);
    let symbols: Vec<Glob> = rule.symbols.iter().map(|p| Glob::new(p)).collect();
    let imports = GlobSet::new(&rule.imports);
    for (file, facts) in python(all, scope) {
        if allowed.matches(&file.path) {
            continue;
        }
        for pattern in &symbols {
            // Symbols are sorted by name, so a literal pattern is a binary search.
            let candidates = match pattern.exact() {
                Some(exact) => {
                    let start = facts.symbols.partition_point(|s| s.name.as_str() < exact);
                    let len = facts.symbols[start..].iter().take_while(|s| s.name == exact).count();
                    &facts.symbols[start..start + len]
                }
                None => &facts.symbols[..],
            };
            for symbol in candidates {
                if (symbol.call || !rule.calls_only) && pattern.matches(&symbol.name) {
                    let verb = if symbol.call { "call of" } else { "reference to" };
                    out.push(finding(&file.path, symbol.line, format!("forbidden {verb} {}", symbol.name)));
                }
            }
            // Names reached through a relative import are spelled with
            // leading dots; they sort first. Each is the absolute name it
            // resolves to from this file.
            for symbol in facts.symbols.iter().take_while(|s| s.name.starts_with('.')) {
                let level = symbol.name.bytes().take_while(|b| *b == b'.').count();
                let absolute =
                    absolute_module(&file.path, graph, file_index(all, &file.path), level.min(255) as u8, &symbol.name[level..]);
                if let Some(name) = absolute.filter(|name| (symbol.call || !rule.calls_only) && pattern.matches(name)) {
                    let verb = if symbol.call { "call of" } else { "reference to" };
                    out.push(finding(&file.path, symbol.line, format!("forbidden {verb} {name}")));
                }
            }
        }
        if !imports.is_empty() {
            for import in &facts.imports {
                // A relative import is the module it resolves to from here.
                let module = match import.level {
                    0 => Some(import.module.clone()),
                    level => absolute_module(&file.path, graph, file_index(all, &file.path), level, &import.module),
                };
                let Some(module) = module else { continue };
                // `import a.b.c` imports `a`, `a.b` and `a.b.c`; `from a import b` may import `a.b`.
                let mut spelled: Vec<String> = module.match_indices('.').map(|(dot, _)| module[..dot].to_owned()).collect();
                spelled.push(module.clone());
                spelled.extend(import.names.iter().filter(|n| *n != "*").map(|n| format!("{module}.{n}")));
                if let Some(hit) = spelled.into_iter().find(|m| imports.matches(m)) {
                    out.push(finding(&file.path, import.line, format!("forbidden import of {hit}")));
                }
            }
        }
        for selector in &rule.facts {
            let mut sites = |label: &str, line: u32, func: &str, what: &str| {
                let place = if func.is_empty() { String::new() } else { format!(" in {func}") };
                out.push(finding(&file.path, line, format!("forbidden {label}: {what}{place}")));
            };
            match selector {
                FactSelector::DynamicLoad => {
                    facts.dynamic_loads.iter().for_each(|s| sites("dynamic load", s.line, &s.func, &s.what));
                    for site in facts
                        .reads
                        .iter()
                        .filter(|s| s.shape == crate::facts::ReadShape::Module && !s.reach.places.iter().any(|p| !p.open))
                    {
                        sites("dynamic load", site.line, &site.func, &site.what);
                    }
                }
                FactSelector::Scan => facts.scans().for_each(|s| sites("tree scan", s.line, &s.func, &s.what)),
                FactSelector::SysExecutable => {
                    facts.sys_executable.iter().for_each(|s| sites("interpreter reference", s.line, &s.func, &s.what))
                }
                FactSelector::ExceptionStoredOnSelf => {
                    facts.exc_on_self.iter().for_each(|s| sites("exception stored on self", s.line, &s.func, &s.what))
                }
                FactSelector::Strftime => {
                    for site in &facts.strftimes {
                        let format = site.format.as_deref().unwrap_or("<computed>");
                        out.push(finding(&file.path, site.line, format!("forbidden strftime/strptime: {format}")));
                    }
                }
                FactSelector::ParseError => {
                    if facts.parse_error {
                        out.push(finding(&file.path, 0, "file does not parse"));
                    }
                }
            }
        }
    }
}

fn file_index(all: &AllFacts, path: &str) -> u32 {
    all.index_of(path).unwrap_or(0) as u32
}

/// The absolute module a relative import names from `path`, when the file
/// has a module name under some root.
fn absolute_module(path: &str, graph: Option<&ImportGraph>, file: u32, level: u8, module: &str) -> Option<String> {
    let own = graph?.module_of(file)?;
    let mut parts: Vec<&str> = own.split('.').collect();
    if !path.ends_with("/__init__.py") && path != "__init__.py" {
        parts.pop();
    }
    let up = level as usize - 1;
    if up > parts.len() {
        return None;
    }
    parts.truncate(parts.len() - up);
    if !module.is_empty() {
        parts.push(module);
    }
    Some(parts.join("."))
}

fn single_owner(all: &AllFacts, rule: &Rule, scope: &Scope, out: &mut Vec<Finding>) {
    let owner_path = rule.owners[0].as_str();
    let Some(owner) = all.find(owner_path).and_then(|f| f.facts.as_deref()) else {
        out.push(finding(owner_path, 0, "owner module is missing"));
        return;
    };
    let names = GlobSet::new(&rule.functions);
    let leaf = |name: &str| name.rsplit('.').next().unwrap_or(name).to_owned();
    // With `functions`, only those owner bodies are protected; without, all of them.
    let owned: HashMap<_, &str> = owner
        .functions
        .iter()
        .filter(|f| f.statements >= rule.min_statements && (names.is_empty() || names.matches(&leaf(&f.name))))
        .map(|f| (f.body_hash, f.name.as_str()))
        .collect();
    let allowed = GlobSet::new(&rule.allow);
    for (file, facts) in python(all, scope) {
        if file.path == owner_path || allowed.matches(&file.path) {
            continue;
        }
        for function in &facts.functions {
            if names.matches(&leaf(&function.name)) {
                out.push(finding(
                    &file.path,
                    function.line,
                    format!("{} is defined outside its owner {owner_path}", function.name),
                ));
            } else if let Some(original) = owned.get(&function.body_hash) {
                let message = format!("{} is a copy of {owner_path}::{original}", function.name);
                out.push(finding(&file.path, function.line, message));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(files: &[(&str, &str)], rule: Rule) -> RuleVerdict {
        run_with(files, rule, &Catalogs::default())
    }

    fn run_with(files: &[(&str, &str)], rule: Rule, catalogs: &Catalogs) -> RuleVerdict {
        let all = AllFacts::from_sources(files);
        let pack = RulePack { rule: vec![rule], ..RulePack::default() };
        let graph = ImportGraph::build(&all, &pack.imports);
        reduce(&all, &pack, catalogs, Some(&graph)).remove(0)
    }

    fn places(verdict: &RuleVerdict) -> Vec<(&str, u32)> {
        verdict.findings.iter().map(|f| (f.path.as_str(), f.line)).collect()
    }

    fn rule(kind: RuleKind, edit: impl FnOnce(&mut Rule)) -> Rule {
        let mut rule = Rule::new("r", kind);
        edit(&mut rule);
        rule
    }

    #[test]
    fn no_tracked_bytecode() {
        let files = [("a.py", ""), ("pkg/__pycache__/a.cpython-313.pyc", "x"), ("b.pyo", "x"), ("__pycache__/c.txt", "x")];
        let verdict = run(&files, Rule::new("r", RuleKind::NoTrackedBytecode));
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(places(&verdict), [("__pycache__/c.txt", 0), ("b.pyo", 0), ("pkg/__pycache__/a.cpython-313.pyc", 0)]);
        assert_eq!(
            run(&[("a.py", ""), ("pyc.txt", "")], Rule::new("r", RuleKind::NoTrackedBytecode)).status,
            VerdictStatus::Pass
        );
    }

    #[test]
    fn no_bare_python_recipe_with_scope() {
        let files = [
            ("Makefile", "t:\n\tpython -m pytest\n"),
            ("ci.sh", "python3 -m pytest\n"),
            ("tool.py", "import subprocess\nsubprocess.run(['python', 'x.py'])\n"),
            ("vendor/run.sh", "python legacy.py\n"),
        ];
        let verdict = run(&files, rule(RuleKind::NoBarePythonRecipe, |r| r.exclude = vec!["vendor/*".into()]));
        assert_eq!(places(&verdict), [("Makefile", 2), ("tool.py", 2)]);
    }

    const LOCKS: &str = "import fcntl, time\n\
        def blocking(fd):\n    fcntl.flock(fd, fcntl.LOCK_EX)\n\
        def spin(fd):\n    while True:\n        try:\n            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n            return\n\
        \x20       except OSError:\n            time.sleep(1)\n\
        def fine(fd):\n    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n    fcntl.flock(fd, fcntl.LOCK_UN)\n";

    #[test]
    fn flock_bounded() {
        let files = [("fleetd/lock.py", LOCKS), ("land/user.py", LOCKS)];
        let verdict = run(&files, rule(RuleKind::FlockBounded, |r| r.owners = vec!["fleetd/lock.py".into()]));
        // The owner may block; nobody may poll without a bound.
        assert_eq!(places(&verdict), [("fleetd/lock.py", 7), ("land/user.py", 3), ("land/user.py", 7)]);
        assert!(verdict.findings[1].message.contains("blocking fcntl.flock without LOCK_NB in blocking"));
        assert!(verdict.findings[2].message.contains("no bound"));
    }

    #[test]
    fn atomic_replace_owner_survives_refactors_of_the_owner() {
        let owner = "import os\ndef atomic_write(p, d):\n    os.replace(p + '.tmp', p)\n";
        let refactored = "import os\n\n\ndef helper(a, b):\n    os.replace(a, b)\ndef atomic_write(p, d):\n    helper(p + '.tmp', p)\ndef third(a, b):\n    os.rename(a, b)\n";
        let user = "import os\nfrom os import rename\ndef save(p):\n    os.replace(p, p)\ndef swap(a, b):\n    rename(a, b)\n";
        let make = |r: &mut Rule| {
            r.owners = vec!["fleetd/pk.py".into()];
            r.allow = vec!["land/x.py::swap".into()];
        };
        let verdict = run(&[("fleetd/pk.py", owner), ("land/x.py", user)], rule(RuleKind::AtomicReplaceOwner, make));
        assert_eq!(places(&verdict), [("land/x.py", 4)]);
        assert!(verdict.findings[0].message.contains("os.replace outside its owner in save"));
        // Moving, splitting and adding replace sites inside the owner changes nothing.
        let again = run(&[("fleetd/pk.py", refactored), ("land/x.py", user)], rule(RuleKind::AtomicReplaceOwner, make));
        assert_eq!(places(&again), [("land/x.py", 4)]);
    }

    #[test]
    fn uncatalogued_settings_keys() {
        let catalogs =
            Catalogs::from_json(&[("settings.json", r#"{"land": {"run": {"hub_cpu_s": 600}}, "fabd.route": "land"}"#)]);
        let source = "a = setting('land.run.hub_cpu_s')\nb = setting('land.run.typo')\nc = or_default('fabd.route', 1)\n\
                      d = thing.get('not.a.setting')\ne = setting('local.only')\n";
        let make = |r: &mut Rule| {
            r.catalogs = vec!["settings.json".into()];
            r.readers = vec!["setting".into(), "or_default".into()];
            r.ignore_keys = vec!["local.*".into()];
        };
        let verdict = run_with(&[("x.py", source)], rule(RuleKind::UncataloguedSettingsKeys, make), &catalogs);
        assert_eq!(places(&verdict), [("x.py", 2)]);
        assert!(verdict.findings[0].message.contains("land.run.typo"));

        // A missing catalog fails the rule instead of passing everything.
        let missing = run_with(&[("x.py", "a = 1\n")], rule(RuleKind::UncataloguedSettingsKeys, make), &Catalogs::from_json(&[]));
        assert_eq!(places(&missing), [("settings.json", 0)]);
    }

    #[test]
    fn forbidden_symbols_calls_imports_and_facts() {
        let files = [
            (
                "fleetd/a.py",
                "import subprocess as sp\nfrom land import stopfacts\nsp.run(['x'])\nhandler = sp.Popen\nstopfacts.read()\n",
            ),
            ("fleetd/ok.py", "import subprocess\nsubprocess.run(['x'])\n"),
            ("land/b.py", "import subprocess\nsubprocess.run(['x'])\n"),
        ];
        let symbols = rule(RuleKind::ForbiddenSymbolOrCall, |r| {
            r.include = vec!["fleetd/*".into()];
            r.allow = vec!["fleetd/ok.py".into()];
            r.symbols = vec!["subprocess.run".into(), "subprocess.Popen".into()];
            r.why = Some("one process owner".into());
        });
        let verdict = run(&files, symbols.clone());
        assert_eq!(places(&verdict), [("fleetd/a.py", 3), ("fleetd/a.py", 4)]);
        assert_eq!(verdict.why.as_deref(), Some("one process owner"));
        assert!(verdict.findings[0].message.contains("call of subprocess.run"));

        let calls_only = run(&files, Rule { calls_only: true, ..symbols });
        assert_eq!(places(&calls_only), [("fleetd/a.py", 3)]);

        let reader = run(
            &files,
            rule(RuleKind::ForbiddenSymbolOrCall, |r| {
                r.symbols = vec!["land.stopfacts.*".into()];
                r.imports = vec!["land.stopfacts".into()];
            }),
        );
        assert_eq!(places(&reader), [("fleetd/a.py", 2), ("fleetd/a.py", 5)]);

        let facts = run(
            &[(
                "x.py",
                "import os, sys, time\nfor _ in os.walk('.'): pass\nexe = sys.executable\nt = time.strftime('%Y')\nexec(code)\n",
            )],
            rule(RuleKind::ForbiddenSymbolOrCall, |r| {
                r.facts =
                    vec![FactSelector::Scan, FactSelector::SysExecutable, FactSelector::Strftime, FactSelector::DynamicLoad];
            }),
        );
        assert_eq!(places(&facts), [("x.py", 2), ("x.py", 3), ("x.py", 4), ("x.py", 5)]);
    }

    #[test]
    fn single_owner_pattern_finds_redefinitions_and_copies() {
        let owner = "import os\ndef atomic_write(path, data):\n    tmp = path + '.tmp'\n    write(tmp, data)\n    os.replace(tmp, path)\n";
        let copy = "import os\nclass Saver:\n    def persist(self, path, data):\n        # same body, new name\n        tmp = path + '.tmp'\n        write(tmp, data)\n        os.replace(tmp, path)\n";
        let redefinition = "def atomic_write(path, data):\n    return None\n";
        let files = [
            ("fleetd/pk.py", owner),
            ("land/copy.py", copy),
            ("land/redef.py", redefinition),
            ("land/ok.py", "def other():\n    return 1\n"),
        ];
        let make = |r: &mut Rule| {
            r.owners = vec!["fleetd/pk.py".into()];
            r.functions = vec!["atomic_write".into()];
        };
        let verdict = run(&files, rule(RuleKind::SingleOwnerPattern, make));
        assert_eq!(places(&verdict), [("land/copy.py", 3), ("land/redef.py", 1)]);
        assert!(verdict.findings[0].message.contains("Saver.persist is a copy of fleetd/pk.py::atomic_write"));

        let missing = run(&files[1..], rule(RuleKind::SingleOwnerPattern, make));
        assert_eq!(places(&missing), [("fleetd/pk.py", 0)]);
    }

    #[test]
    fn python_import_graph_flags_dangling_relative_imports() {
        let files = [("pkg/__init__.py", ""), ("pkg/a.py", "from . import b\nfrom .gone import x\n"), ("pkg/b.py", "")];
        let verdict = run(&files, Rule::new("r", RuleKind::PythonImportGraph));
        assert_eq!(places(&verdict), [("pkg/a.py", 2)]);
        let clean = run(&files[..1], Rule::new("r", RuleKind::PythonImportGraph));
        assert_eq!(clean.status, VerdictStatus::Pass);
    }

    #[test]
    fn catalog_keys_cover_nested_objects_and_arrays() {
        let mut keys = BTreeSet::new();
        let json = serde_json::json!({"a": {"b": {"c": 1}}, "x.y": 2, "list": ["k1", "k2"], "top": [{"deep": 1}]});
        collect_keys(&json, "", &mut keys);
        let got: Vec<&str> = keys.iter().map(String::as_str).collect();
        assert_eq!(got, ["a", "a.b", "a.b.c", "list", "list.k1", "list.k2", "top", "top.deep", "x.y"]);
    }

    /// Relative spellings, deeper submodules and names reached through a
    /// relative import cannot slip past a forbidden-import rule.
    #[test]
    fn tooth_forbidden_imports_see_relative_and_deeper_spellings() {
        let files = [
            ("land/__init__.py", ""),
            ("land/stopfacts/__init__.py", ""),
            ("land/stopfacts/sub.py", "def read():\n    return 1\n"),
            ("land/a.py", "from . import stopfacts\n"),
            ("land/b.py", "from .stopfacts import sub\nsub.read()\n"),
            ("land/deep/__init__.py", ""),
            ("land/deep/c.py", "from ..stopfacts.sub import read\nread()\n"),
            ("fleetd/d.py", "import land.stopfacts.sub\n"),
            ("fleetd/ok.py", "import land.other\nfrom . import stopfacts_like\n"),
        ];
        let imports = run(
            &files,
            rule(RuleKind::ForbiddenSymbolOrCall, |r| {
                r.imports = vec!["land.stopfacts".into()];
                r.exclude = vec!["land/stopfacts/*".into()];
            }),
        );
        assert_eq!(places(&imports), [("fleetd/d.py", 1), ("land/a.py", 1), ("land/b.py", 1), ("land/deep/c.py", 1)]);

        let calls = run(
            &files,
            rule(RuleKind::ForbiddenSymbolOrCall, |r| {
                r.symbols = vec!["land.stopfacts.sub.read".into()];
                r.calls_only = true;
            }),
        );
        assert_eq!(places(&calls), [("land/b.py", 2), ("land/deep/c.py", 2)]);
        assert!(calls.findings[0].message.contains("call of land.stopfacts.sub.read"));
    }

    #[test]
    fn flock_flags_in_a_variable_are_reported_as_unknown_not_as_blocking() {
        let source = "import fcntl\ndef lock(fd, flags):\n    fcntl.flock(fd, flags)\n";
        let verdict = run(&[("land/x.py", source)], Rule::new("r", RuleKind::FlockBounded));
        assert_eq!(places(&verdict), [("land/x.py", 3)]);
        assert!(verdict.findings[0].message.contains("flags are not visible"), "{}", verdict.findings[0].message);
    }

    #[test]
    fn rules_see_python_without_a_py_suffix() {
        let all = AllFacts::from_entries(&[
            ("bin/tool", 0o100755, "#!/usr/bin/env python3\nimport os\ndef save(a, b):\n    os.replace(a, b)\n"),
            ("bin/notes", 0o100644, "os.replace is mentioned here\n"),
        ]);
        let pack = RulePack {
            rule: vec![rule(RuleKind::AtomicReplaceOwner, |r| r.owners = vec!["fleetd/pk.py".into()])],
            ..RulePack::default()
        };
        let verdict = reduce(&all, &pack, &Catalogs::default(), None).remove(0);
        assert_eq!(places(&verdict), [("bin/tool", 4)]);
    }
}
