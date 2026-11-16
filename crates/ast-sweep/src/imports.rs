//! The static Python import graph and the import cone of every test unit.
//!
//! A unit's cone is everything its verdict can depend on: the files reached
//! by following imports from the test (and from each `conftest.py` above it),
//! plus the files its `guards` say it reads without importing. A cone that
//! reaches a dynamic load cannot be bounded statically, so under the default
//! taint policy it widens to the whole tree.

use crate::facts::FileKind;
use crate::glob::GlobSet;
use crate::rules::{ImportConfig, TaintPolicy};
use crate::sweep::{light_pool, AllFacts};
use landd_core::reasons::{cone_digest, cone_inputs_digest, cone_leaf, Cone};
use landd_core::Digest32;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedImport {
    pub file: u32,
    pub line: u32,
    pub import: String,
}

/// Nodes are indices into [`AllFacts::files`].
#[derive(Debug, Clone, Default)]
pub struct ImportGraph {
    by_name: HashMap<String, u32>,
    /// The module name of each Python file under its deepest root.
    names: HashMap<u32, String>,
    edges: Vec<Vec<u32>>,
    dynamic: Vec<bool>,
    /// Relative imports that name nothing in the tree.
    pub unresolved_relative: Vec<UnresolvedImport>,
    /// Top-level modules imported from outside the tree.
    pub external: BTreeSet<String>,
}

fn module_name(path: &str, root: &str) -> Option<String> {
    let root = root.trim_end_matches('/');
    let relative = if root.is_empty() { path } else { path.strip_prefix(root)?.strip_prefix('/')? };
    let stem = relative.strip_suffix(".py")?;
    let stem = stem.strip_suffix("/__init__").unwrap_or(if stem == "__init__" { "" } else { stem });
    (!stem.is_empty()).then(|| stem.replace('/', "."))
}

struct NodeEdges {
    targets: Vec<u32>,
    dynamic: bool,
    unresolved: Vec<UnresolvedImport>,
    external: Vec<String>,
}

impl ImportGraph {
    pub fn build(all: &AllFacts, config: &ImportConfig) -> Self {
        let count = all.files.len();
        let mut graph = Self { edges: vec![Vec::new(); count], dynamic: vec![false; count], ..Self::default() };
        let mut roots: Vec<&str> = config.roots.iter().map(String::as_str).collect();
        roots.sort_by_key(|root| std::cmp::Reverse(root.len()));
        // A second file claiming a name (`a.py` beside `a/__init__.py`): keep
        // both reachable by linking the first to it.
        let mut shadowed: Vec<(u32, u32)> = Vec::new();
        for (index, file) in all.files.iter().enumerate() {
            if file.kind != Some(FileKind::Python) {
                continue;
            }
            let index = index as u32;
            for root in &roots {
                let Some(name) = module_name(&file.path, root) else { continue };
                graph.names.entry(index).or_insert_with(|| name.clone());
                match graph.by_name.get(&name) {
                    Some(first) if *first != index => shadowed.push((*first, index)),
                    Some(_) => {}
                    None => {
                        graph.by_name.insert(name, index);
                    }
                }
            }
        }

        let paths = all.paths();
        let loader_reads: HashMap<u32, Vec<u32>> = config
            .loaders
            .iter()
            .filter_map(|(path, reads)| Some((all.index_of(path)? as u32, GlobSet::new(reads).select(&paths))))
            .collect();
        let nodes: Vec<Option<NodeEdges>> = light_pool().install(|| {
            (0..count).into_par_iter().map(|index| graph.edges_of(all, config, &paths, &loader_reads, index)).collect()
        });
        for (index, node) in nodes.into_iter().enumerate() {
            let Some(node) = node else { continue };
            graph.edges[index] = node.targets;
            graph.dynamic[index] = node.dynamic;
            graph.unresolved_relative.extend(node.unresolved);
            graph.external.extend(node.external);
        }
        for (first, second) in shadowed {
            graph.edges[first as usize].push(second);
        }
        graph
    }

    /// The outgoing edges of one Python file.
    fn edges_of(
        &self,
        all: &AllFacts,
        config: &ImportConfig,
        paths: &[&str],
        loader_reads: &HashMap<u32, Vec<u32>>,
        index: usize,
    ) -> Option<NodeEdges> {
        let file = &all.files[index];
        let facts = file.facts.as_deref().filter(|_| file.kind == Some(FileKind::Python))?;
        let declared = loader_reads.get(&(index as u32));
        let mut node = NodeEdges {
            targets: Vec::new(),
            dynamic: !facts.dynamic_loads.is_empty() && declared.is_none(),
            unresolved: Vec::new(),
            external: Vec::new(),
        };
        let own = self.names.get(&(index as u32));
        // Importing `a.b.c` runs `a/__init__` and `a/b/__init__` first; the
        // same holds for the module's own packages.
        if let Some((parent, _)) = own.and_then(|own| own.rsplit_once('.')) {
            self.with_prefixes(parent, &mut node.targets);
        }
        for import in &facts.imports {
            let target = if import.level == 0 {
                Some(import.module.clone())
            } else {
                own.and_then(|own| {
                    let mut parts: Vec<&str> = own.split('.').collect();
                    if !file.path.ends_with("__init__.py") {
                        parts.pop();
                    }
                    let up = import.level as usize - 1;
                    if up > parts.len() {
                        return None;
                    }
                    parts.truncate(parts.len() - up);
                    if !import.module.is_empty() {
                        parts.push(&import.module);
                    }
                    Some(parts.join("."))
                })
            };
            // Resolved when the module itself, or a submodule it names, is in the tree.
            let (mut resolved, mut in_tree) = (false, false);
            if let Some(target) = &target {
                let before = node.targets.len();
                self.with_prefixes(target, &mut node.targets);
                in_tree = node.targets.len() > before;
                resolved = self.by_name.contains_key(target.as_str());
                for name in import.names.iter().filter(|n| *n != "*") {
                    let submodule = if target.is_empty() { name.clone() } else { format!("{target}.{name}") };
                    if let Some(found) = self.by_name.get(&submodule) {
                        node.targets.push(*found);
                        resolved = true;
                    }
                }
            }
            if resolved || (import.level == 0 && in_tree) {
                continue;
            }
            if import.level > 0 {
                node.unresolved.push(UnresolvedImport {
                    file: index as u32,
                    line: import.line,
                    import: format!("{}{}", ".".repeat(import.level as usize), import.module),
                });
            } else if let Some(top) = import.module.split('.').next().filter(|t| !t.is_empty()) {
                node.external.push(top.to_owned());
            }
        }
        if let Some(reads) = declared {
            node.targets.extend(reads);
        } else if node.dynamic && config.taint == TaintPolicy::Package {
            let package = match file.path.rsplit_once('/') {
                Some((dir, _)) => format!("{dir}/*"),
                None => "*".to_owned(),
            };
            node.targets.extend(GlobSet::new(&[package]).select(paths));
        }
        node.targets.sort_unstable();
        node.targets.dedup();
        node.targets.retain(|t| *t != index as u32);
        Some(node)
    }

    /// Push the node of `dotted` and of each of its package prefixes.
    fn with_prefixes(&self, dotted: &str, out: &mut Vec<u32>) {
        let mut end = 0;
        while end < dotted.len() {
            end = dotted[end + 1..].find('.').map(|i| end + 1 + i).unwrap_or(dotted.len());
            if let Some(node) = self.by_name.get(&dotted[..end]) {
                out.push(*node);
            }
        }
    }

    pub fn module_of(&self, file: u32) -> Option<&str> {
        self.names.get(&file).map(String::as_str)
    }

    pub fn node_of(&self, module: &str) -> Option<u32> {
        self.by_name.get(module).copied()
    }

    pub fn imports_of(&self, file: u32) -> &[u32] {
        &self.edges[file as usize]
    }

    pub fn edge_count(&self) -> usize {
        self.edges.iter().map(Vec::len).sum()
    }
}

/// One test unit's cone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportCone {
    /// The test's module name (`tests.door.test_x`).
    pub unit: String,
    pub path: String,
    pub digest: Digest32,
    /// The import closure reaches a dynamic load.
    pub dynamic_loads: bool,
    /// Files reached through imports alone.
    pub imported_files: usize,
    /// Every input: imports, guard reads and, when tainted, the whole tree.
    #[serde(skip)]
    pub inputs: Vec<u32>,
    pub input_files: usize,
    /// The undeclared dynamic loaders the import closure reaches.
    #[serde(skip)]
    pub taint_sources: Vec<u32>,
}

impl ImportCone {
    pub fn input_paths<'a>(&'a self, all: &'a AllFacts) -> impl Iterator<Item = &'a str> + 'a {
        self.inputs.iter().map(|i| all.files[*i as usize].path.as_str())
    }

    /// The same cone in the form the admissibility engine judges.
    pub fn to_cone(&self, all: &AllFacts) -> Cone {
        Cone {
            unit: self.unit.clone(),
            inputs: self.inputs.iter().map(|i| &all.files[*i as usize]).map(|f| (f.path.clone(), f.oid)).collect(),
            tainted: self.dynamic_loads,
        }
    }
}

/// Export the cone of every test unit, in path order.
pub fn cones(all: &AllFacts, graph: &ImportGraph, config: &ImportConfig) -> Vec<ImportCone> {
    let paths = all.paths();
    let tests: Vec<u32> = GlobSet::new(&config.tests)
        .select(&paths)
        .into_iter()
        .filter(|i| all.files[*i as usize].kind == Some(FileKind::Python))
        .collect();
    let leaves: Vec<[u8; 32]> = light_pool().install(|| all.files.par_iter().map(|f| cone_leaf(&f.path, &f.oid)).collect());
    let guards: HashMap<&str, Vec<u32>> =
        config.guards.iter().map(|(unit, reads)| (unit.as_str(), GlobSet::new(reads).select(&paths))).collect();
    let everything: Vec<u32> = (0..all.files.len() as u32).collect();
    let whole_tree = cone_inputs_digest(leaves.iter());

    light_pool().install(|| {
        tests
            .par_iter()
            .map_init(
                || (vec![false; all.files.len()], Vec::<u32>::new()),
                |(seen, stack), test| {
                    let path = all.files[*test as usize].path.as_str();
                    let unit = graph.module_of(*test).unwrap_or(path).to_owned();
                    stack.clear();
                    stack.push(*test);
                    if config.implicit_conftest {
                        let mut dir = path;
                        loop {
                            dir = dir.rsplit_once('/').map(|(parent, _)| parent).unwrap_or("");
                            let conftest = if dir.is_empty() { "conftest.py".to_owned() } else { format!("{dir}/conftest.py") };
                            if let Some(index) = all.index_of(&conftest) {
                                stack.push(index as u32);
                            }
                            if dir.is_empty() {
                                break;
                            }
                        }
                    }
                    let mut closure = Vec::new();
                    let mut taint_sources = Vec::new();
                    while let Some(node) = stack.pop() {
                        if std::mem::replace(&mut seen[node as usize], true) {
                            continue;
                        }
                        closure.push(node);
                        if graph.dynamic[node as usize] {
                            taint_sources.push(node);
                        }
                        stack.extend(graph.edges[node as usize].iter().filter(|n| !seen[**n as usize]));
                    }
                    for node in &closure {
                        seen[*node as usize] = false;
                    }
                    let imported_files = closure.len();
                    let tainted = !taint_sources.is_empty();
                    let widened = tainted && config.taint == TaintPolicy::WholeTree;
                    let inputs = if widened {
                        everything.clone()
                    } else {
                        if let Some(reads) = guards.get(unit.as_str()) {
                            closure.extend(reads);
                        }
                        closure.sort_unstable();
                        closure.dedup();
                        closure
                    };
                    let inputs_digest =
                        if widened { whole_tree } else { cone_inputs_digest(inputs.iter().map(|i| &leaves[*i as usize])) };
                    taint_sources.sort_unstable();
                    ImportCone {
                        digest: cone_digest(&unit, &inputs_digest, tainted),
                        taint_sources,
                        unit,
                        path: path.to_owned(),
                        dynamic_loads: tainted,
                        imported_files,
                        input_files: inputs.len(),
                        inputs,
                    }
                },
            )
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREE: &[(&str, &str)] = &[
        ("conftest.py", "import fixtures\n"),
        ("fixtures.py", "X = 1\n"),
        ("lib/__init__.py", "from . import core\n"),
        ("lib/core.py", "from .deep import leaf\nimport json\n"),
        ("lib/deep/__init__.py", ""),
        ("lib/deep/leaf.py", "VALUE = 1\n"),
        ("lib/island.py", "ALONE = 1\n"),
        ("lib/plugins.py", "import importlib\ndef load(n):\n    return importlib.import_module(n)\n"),
        ("docs/readme.md", "docs\n"),
        ("data/table.json", "{}\n"),
        ("tests/__init__.py", ""),
        ("tests/conftest.py", ""),
        ("tests/test_core.py", "from lib import core\n"),
        ("tests/test_island.py", "import lib.island\n"),
        ("tests/test_plugins.py", "from lib.plugins import load\n"),
        ("tests/helper.py", ""),
    ];

    fn with(tree: &[(&str, &str)], edit: &[(&str, &str)]) -> Vec<(String, String)> {
        let mut files: Vec<(String, String)> = tree.iter().map(|(p, c)| (p.to_string(), c.to_string())).collect();
        for (path, content) in edit {
            match files.iter_mut().find(|(p, _)| p == path) {
                Some(file) => file.1 = content.to_string(),
                None => files.push((path.to_string(), content.to_string())),
            }
        }
        files
    }

    fn cones_of(files: &[(String, String)], config: &ImportConfig) -> (AllFacts, Vec<ImportCone>) {
        let borrowed: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
        let all = AllFacts::from_sources(&borrowed);
        let graph = ImportGraph::build(&all, config);
        let cones = cones(&all, &graph, config);
        (all, cones)
    }

    fn config() -> ImportConfig {
        ImportConfig { tests: vec!["tests/**/test_*.py".into()], ..ImportConfig::default() }
    }

    fn cone<'a>(cones: &'a [ImportCone], unit: &str) -> &'a ImportCone {
        cones.iter().find(|c| c.unit == unit).unwrap_or_else(|| panic!("no cone for {unit}"))
    }

    #[test]
    fn cones_follow_imports_packages_and_conftests() {
        let (all, cones) = cones_of(&with(TREE, &[]), &config());
        assert_eq!(cones.iter().map(|c| c.unit.as_str()).collect::<Vec<_>>(), [
            "tests.test_core",
            "tests.test_island",
            "tests.test_plugins"
        ]);
        let core: Vec<&str> = cone(&cones, "tests.test_core").input_paths(&all).collect();
        assert_eq!(core, [
            "conftest.py",
            "fixtures.py",
            "lib/__init__.py",
            "lib/core.py",
            "lib/deep/__init__.py",
            "lib/deep/leaf.py",
            "tests/__init__.py",
            "tests/conftest.py",
            "tests/test_core.py",
        ]);
        let island: Vec<&str> = cone(&cones, "tests.test_island").input_paths(&all).collect();
        assert!(island.contains(&"lib/island.py") && island.contains(&"lib/core.py"));
        assert!(!island.contains(&"tests/helper.py") && !island.contains(&"docs/readme.md"));
        assert!(!cone(&cones, "tests.test_core").dynamic_loads);
    }

    #[test]
    fn graph_resolves_relative_imports_and_names_externals() {
        let borrowed: Vec<(&str, &str)> = TREE.to_vec();
        let all = AllFacts::from_sources(&borrowed);
        let graph = ImportGraph::build(&all, &config());
        let core = graph.node_of("lib.core").unwrap();
        let reached: Vec<&str> = graph.imports_of(core).iter().map(|n| graph.module_of(*n).unwrap()).collect();
        assert_eq!(reached, ["lib", "lib.deep", "lib.deep.leaf"]);
        assert!(graph.external.contains("json") && graph.external.contains("importlib"));
        assert!(graph.unresolved_relative.is_empty());

        let broken = AllFacts::from_sources(&[("pkg/__init__.py", ""), ("pkg/a.py", "from .gone import x\nfrom ... import y\n")]);
        let graph = ImportGraph::build(&broken, &config());
        let unresolved: Vec<(&str, u32)> = graph.unresolved_relative.iter().map(|u| (u.import.as_str(), u.line)).collect();
        assert_eq!(unresolved, [(".gone", 1), ("...", 2)]);
    }

    #[test]
    fn tooth_one_byte_in_a_transitive_dependency_changes_exactly_the_cones_that_reach_it() {
        let (_, before) = cones_of(&with(TREE, &[]), &config());
        let (_, after) = cones_of(&with(TREE, &[("lib/deep/leaf.py", "VALUE = 2\n")]), &config());
        // `lib/__init__` imports `core`, so every test that imports `lib.*` reaches the leaf.
        for unit in ["tests.test_core", "tests.test_island"] {
            assert_ne!(cone(&before, unit).digest, cone(&after, unit).digest, "{unit}");
        }
        let (_, island_edit) = cones_of(&with(TREE, &[("lib/island.py", "ALONE = 2\n")]), &config());
        assert_eq!(cone(&before, "tests.test_core").digest, cone(&island_edit, "tests.test_core").digest);
        assert_ne!(cone(&before, "tests.test_island").digest, cone(&island_edit, "tests.test_island").digest);
    }

    #[test]
    fn tooth_disjoint_changes_preserve_cone_digests_byte_for_byte() {
        let (_, before) = cones_of(&with(TREE, &[]), &config());
        let edits = [("docs/readme.md", "new docs\n"), ("tests/helper.py", "X = 1\n"), ("brand/new.py", "Y = 2\n")];
        let (_, after) = cones_of(&with(TREE, &edits), &config());
        for unit in ["tests.test_core", "tests.test_island"] {
            assert_eq!(cone(&before, unit).digest.as_bytes(), cone(&after, unit).digest.as_bytes(), "{unit}");
        }
    }

    #[test]
    fn tooth_revert_restores_the_exact_cone_digest() {
        let (_, good) = cones_of(&with(TREE, &[]), &config());
        let (_, bad) = cones_of(&with(TREE, &[("lib/core.py", "from .deep import leaf\nBUG = 1\n")]), &config());
        let (_, reverted) = cones_of(&with(TREE, &[("lib/core.py", "from .deep import leaf\nimport json\n")]), &config());
        assert_ne!(cone(&good, "tests.test_core").digest, cone(&bad, "tests.test_core").digest);
        assert_eq!(good, reverted);
    }

    #[test]
    fn tooth_dynamic_loads_widen_the_cone_to_the_whole_tree() {
        let (all, cones) = cones_of(&with(TREE, &[]), &config());
        let plugins = cone(&cones, "tests.test_plugins");
        assert!(plugins.dynamic_loads);
        assert_eq!(plugins.input_files, all.files.len());
        assert!(plugins.imported_files < all.files.len());

        // So a change no import reaches still moves it, and only it.
        let (_, after) = cones_of(&with(TREE, &[("docs/readme.md", "new docs\n")]), &config());
        assert_ne!(plugins.digest, cone(&after, "tests.test_plugins").digest);
        assert_eq!(cone(&cones, "tests.test_core").digest, cone(&after, "tests.test_core").digest);

        let flag_only = ImportConfig { taint: TaintPolicy::FlagOnly, ..config() };
        let (_, flagged) = cones_of(&with(TREE, &[]), &flag_only);
        let plugins = cone(&flagged, "tests.test_plugins");
        assert!(plugins.dynamic_loads && plugins.input_files == plugins.imported_files);
    }

    #[test]
    fn guard_reads_join_the_cone() {
        let mut guarded = config();
        guarded.guards.insert("tests.test_island".into(), vec!["data/*".into(), "docs/readme.md".into()]);
        let (all, cones) = cones_of(&with(TREE, &[]), &guarded);
        let island: Vec<&str> = cone(&cones, "tests.test_island").input_paths(&all).collect();
        assert!(island.contains(&"data/table.json") && island.contains(&"docs/readme.md"));
        let (_, after) = cones_of(&with(TREE, &[("data/table.json", "{\"k\": 1}\n")]), &guarded);
        assert_ne!(cone(&cones, "tests.test_island").digest, cone(&after, "tests.test_island").digest);
        assert_eq!(cone(&cones, "tests.test_core").digest, cone(&after, "tests.test_core").digest);
    }

    #[test]
    fn exported_digest_is_the_admissibility_engines_digest() {
        let (all, cones) = cones_of(&with(TREE, &[]), &config());
        for cone in &cones {
            assert_eq!(cone.digest, cone.to_cone(&all).digest(), "{}", cone.unit);
        }
    }

    #[test]
    fn source_roots_name_modules() {
        assert_eq!(module_name("src/pkg/mod.py", "src").as_deref(), Some("pkg.mod"));
        assert_eq!(module_name("src/pkg/__init__.py", "src/").as_deref(), Some("pkg"));
        assert_eq!(module_name("pkg/mod.py", "").as_deref(), Some("pkg.mod"));
        assert_eq!(module_name("other/mod.py", "src"), None);
        assert_eq!(module_name("__init__.py", ""), None);
        let config = ImportConfig { roots: vec!["".into(), "src".into()], tests: vec!["test_*.py".into()], ..ImportConfig::default() };
        let all = AllFacts::from_sources(&[("src/pkg/mod.py", "A = 1\n"), ("test_x.py", "import pkg.mod\n")]);
        let graph = ImportGraph::build(&all, &config);
        let cones = cones(&all, &graph, &config);
        assert_eq!(cones[0].input_paths(&all).collect::<Vec<_>>(), ["src/pkg/mod.py", "test_x.py"]);
    }

    #[test]
    fn a_declared_loader_contributes_its_reads_instead_of_tainting() {
        let mut declared = config();
        declared.loaders.insert("lib/plugins.py".into(), vec!["lib/island.py".into(), "data/*".into()]);
        let (all, cones) = cones_of(&with(TREE, &[]), &declared);
        let plugins = cone(&cones, "tests.test_plugins");
        assert!(!plugins.dynamic_loads && plugins.taint_sources.is_empty());
        let inputs: Vec<&str> = plugins.input_paths(&all).collect();
        assert!(inputs.contains(&"lib/island.py") && inputs.contains(&"data/table.json"));
        assert!(!inputs.contains(&"docs/readme.md"));
        assert!(plugins.input_files < all.files.len());

        // What the loader can reach moves the cone; what it cannot does not.
        let (_, data_edit) = cones_of(&with(TREE, &[("data/table.json", "{\"k\": 1}\n")]), &declared);
        let (_, docs_edit) = cones_of(&with(TREE, &[("docs/readme.md", "new docs\n")]), &declared);
        assert_ne!(plugins.digest, cone(&data_edit, "tests.test_plugins").digest);
        assert_eq!(plugins.digest, cone(&docs_edit, "tests.test_plugins").digest);
    }

    #[test]
    fn package_taint_widens_to_the_loaders_directory_only() {
        let package = ImportConfig { taint: TaintPolicy::Package, ..config() };
        let (all, cones) = cones_of(&with(TREE, &[]), &package);
        let plugins = cone(&cones, "tests.test_plugins");
        assert!(plugins.dynamic_loads);
        assert_eq!(plugins.taint_sources.iter().map(|i| all.files[*i as usize].path.as_str()).collect::<Vec<_>>(), ["lib/plugins.py"]);
        let inputs: Vec<&str> = plugins.input_paths(&all).collect();
        assert!(inputs.contains(&"lib/island.py") && inputs.contains(&"lib/deep/leaf.py"));
        assert!(!inputs.contains(&"docs/readme.md") && !inputs.contains(&"data/table.json"));
    }
}
