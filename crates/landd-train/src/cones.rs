//! Where a tree's check units and their input cones come from.
//!
//! What defines the units is trusted input. For Python cones it is the
//! operator's rule pack, which is never read from the tree under test. For
//! manifest cones it is a file in the tree, so the candidate's manifest is
//! not allowed to weaken the base's: a unit's inputs are the union of what
//! both manifests declare, and a unit the candidate's manifest drops is a
//! removed unit, which the judge blocks unless the operator allows removals.

use crate::runner::UnitJob;
use ast_sweep::glob::GlobSet;
use ast_sweep::{BlobFactsCache, ImportGraph, RulePack};
use landd_core::git::GitRepo;
use landd_core::reasons::{Cone, Input, UnitId};
use landd_core::{Digest32, Oid};
use serde::Deserialize;
use std::collections::BTreeMap;

/// The units of one tree: each unit's cone and the path the runner is given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitCones {
    pub cones: BTreeMap<UnitId, Cone>,
    pub paths: BTreeMap<UnitId, String>,
}

impl UnitCones {
    /// The job that runs `unit`: its command path and, unless its cone is
    /// the whole tree, the files it may see.
    pub fn job(&self, unit: &str) -> UnitJob {
        let cone = self.cones.get(unit);
        UnitJob {
            unit: unit.to_owned(),
            path: self.paths.get(unit).cloned().unwrap_or_else(|| unit.to_owned()),
            inputs: cone.filter(|cone| !cone.tainted).map(|cone| cone.inputs.keys().cloned().collect()),
        }
    }
}

pub trait ConeSource: Sync {
    /// The cones of `commit`. `trusted` is the base commit, whose own
    /// declarations the candidate cannot weaken. `context` identifies the
    /// runner and becomes part of every cone's digest.
    fn cones(&self, repo: &GitRepo, commit: &Oid, trusted: &Oid, context: &Digest32) -> Result<UnitCones, String>;
}

/// Units declared by a JSON manifest in the tree:
///
/// ```json
/// {"units": {"lint": {"path": "checks/lint.sh", "inputs": ["checks/lint.sh", "src/*"]}}}
/// ```
///
/// The manifest itself is an input of every unit.
#[derive(Debug, Clone)]
pub struct ManifestCones {
    pub manifest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    units: BTreeMap<String, ManifestUnit>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestUnit {
    path: String,
    inputs: Vec<String>,
}

impl ManifestCones {
    /// The manifest of a tree; no manifest is no units.
    fn read(&self, repo: &GitRepo, commit: &Oid) -> Result<Option<Manifest>, String> {
        let entries = repo.ls_tree(&commit.to_hex(), false).map_err(|e| e.to_string())?;
        let Some(entry) = entries.iter().find(|entry| entry.path == self.manifest) else {
            return Ok(None);
        };
        let bytes = repo.read_blob(&entry.oid).map_err(|e| e.to_string())?;
        serde_json::from_slice(&bytes).map(Some).map_err(|e| format!("unit manifest {}: {e}", self.manifest))
    }
}

impl ConeSource for ManifestCones {
    fn cones(&self, repo: &GitRepo, commit: &Oid, trusted: &Oid, context: &Digest32) -> Result<UnitCones, String> {
        let mut entries = repo.ls_tree(&commit.to_hex(), false).map_err(|e| e.to_string())?;
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        let Some(manifest) = self.read(repo, commit)? else {
            return Ok(UnitCones::default());
        };
        let base = if commit == trusted { None } else { self.read(repo, trusted)? };
        let context = Digest32::tagged("landd manifest cones v1", &[context.as_bytes()]);
        let mut units = UnitCones::default();
        for (unit, declared) in manifest.units {
            let mut patterns = declared.inputs.clone();
            // What the base says the unit reads still counts.
            if let Some(before) = base.as_ref().and_then(|m| m.units.get(&unit)) {
                patterns.extend(before.inputs.iter().cloned());
            }
            patterns.extend([self.manifest.clone(), declared.path.clone()]);
            let inputs = GlobSet::new(&patterns)
                .select(&paths)
                .into_iter()
                .map(|i| &entries[i as usize])
                .map(|e| (e.path.clone(), Input { mode: e.mode, oid: e.oid }))
                .collect();
            units.cones.insert(unit.clone(), Cone { unit: unit.clone(), inputs, tainted: false, context });
            units.paths.insert(unit, declared.path);
        }
        Ok(units)
    }
}

/// Units are the Python test modules of the tree; cones are their import
/// and read cones as exported by `ast-sweep` under the operator's rule pack.
#[derive(Debug, Clone)]
pub struct PythonCones {
    pub pack: RulePack,
    pub cache: Option<BlobFactsCache>,
}

impl ConeSource for PythonCones {
    fn cones(&self, repo: &GitRepo, commit: &Oid, _trusted: &Oid, context: &Digest32) -> Result<UnitCones, String> {
        let (all, _) = ast_sweep::sweep_git(repo, &commit.to_hex(), self.cache.as_ref()).map_err(|e| e.to_string())?;
        let graph = ImportGraph::build(&all, &self.pack.imports);
        let context = Digest32::tagged("landd python cones v1", &[self.pack.digest().as_bytes(), context.as_bytes()]);
        let mut units = UnitCones::default();
        for cone in ast_sweep::imports::cones(&all, &graph, &self.pack.imports, &context) {
            units.paths.insert(cone.unit.clone(), cone.path.clone());
            units.cones.insert(cone.unit.clone(), cone.to_cone(&all));
        }
        Ok(units)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landd_core::git::testkit::Sandbox;

    const MANIFEST: &str = r#"{"units": {
        "a": {"path": "checks/a.sh", "inputs": ["src/a/*"]},
        "b": {"path": "checks/b.sh", "inputs": ["src/b.txt"]}}}"#;

    fn context() -> Digest32 {
        Digest32::blake3(b"runner")
    }

    fn files() -> Vec<(&'static str, &'static str)> {
        vec![
            ("landd-units.json", MANIFEST),
            ("checks/a.sh", "true\n"),
            ("checks/b.sh", "true\n"),
            ("src/a/one.txt", "1\n"),
            ("src/a/deep/two.txt", "2\n"),
            ("src/b.txt", "b\n"),
            ("docs.md", "docs\n"),
        ]
    }

    #[test]
    fn manifest_cones_cover_declared_inputs_the_unit_and_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &files());
        let repo = sandbox.repo();
        let source = ManifestCones { manifest: "landd-units.json".into() };
        let base = repo.rev_parse("HEAD").unwrap();
        let before = source.cones(&repo, &base, &base, &context()).unwrap();
        assert_eq!(before.paths["a"], "checks/a.sh");
        let a: Vec<&str> = before.cones["a"].inputs.keys().map(String::as_str).collect();
        assert_eq!(a, ["checks/a.sh", "landd-units.json", "src/a/deep/two.txt", "src/a/one.txt"]);
        assert_eq!(before.job("a").inputs.as_deref().map(<[String]>::len), Some(4));

        let head = sandbox.commit("main", "edit", &[("src/a/deep/two.txt", "changed\n"), ("docs.md", "new\n")], &[]);
        let after = source.cones(&repo, &head, &base, &context()).unwrap();
        assert_ne!(before.cones["a"].digest(), after.cones["a"].digest());
        assert_eq!(before.cones["b"].digest(), after.cones["b"].digest());
        // Another runner is another verdict.
        let other = source.cones(&repo, &base, &base, &Digest32::blake3(b"other runner")).unwrap();
        assert_ne!(before.cones["b"].digest(), other.cones["b"].digest());

        let none = ManifestCones { manifest: "absent.json".into() };
        assert!(none.cones(&repo, &head, &base, &context()).unwrap().cones.is_empty());
    }

    /// The manifest lives in the tree under test, so it cannot be used to
    /// shrink a unit's cone or to make a unit disappear quietly.
    #[test]
    fn tooth_a_candidate_manifest_cannot_weaken_the_bases() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &files());
        let repo = sandbox.repo();
        let source = ManifestCones { manifest: "landd-units.json".into() };
        let base = repo.rev_parse("HEAD").unwrap();
        // The lane narrows `a` to nothing, drops `b`, and adds `c`.
        let weaker =
            r#"{"units": {"a": {"path": "checks/a.sh", "inputs": []}, "c": {"path": "checks/a.sh", "inputs": ["docs.md"]}}}"#;
        let head = sandbox.commit("main", "weaken", &[("landd-units.json", weaker), ("src/a/one.txt", "broken\n")], &[]);
        let cand = source.cones(&repo, &head, &base, &context()).unwrap();
        // `a` still reads what the base said it reads.
        assert!(cand.cones["a"].inputs.contains_key("src/a/one.txt"));
        // `b` is gone from the candidate's units (the judge reports it removed), `c` is new.
        assert!(!cand.cones.contains_key("b") && cand.cones.contains_key("c"));
        // Judged on its own (as a future base), the weaker manifest is all there is.
        let alone = source.cones(&repo, &head, &head, &context()).unwrap();
        assert!(!alone.cones["a"].inputs.contains_key("src/a/one.txt"));
        // A manifest that does not parse is an error, not zero units.
        let broken = sandbox.commit("main", "break", &[("landd-units.json", "{")], &[]);
        assert!(source.cones(&repo, &broken, &base, &context()).is_err());
    }

    #[test]
    fn python_cones_are_ast_sweep_cones_under_the_operators_pack() {
        let dir = tempfile::tempdir().unwrap();
        let files = [
            ("lib/__init__.py", ""),
            ("lib/a.py", "A = 1\n"),
            ("lib/b.py", "B = 1\n"),
            ("tests/test_a.py", "from lib import a\n"),
            ("tests/test_b.py", "from lib import b\n"),
            ("tests/test_all.py", "import subprocess\ndef test():\n    subprocess.run(['true'])\n"),
        ];
        let sandbox = Sandbox::new(dir.path(), &files);
        let repo = sandbox.repo();
        let source =
            PythonCones { pack: RulePack::builtin(), cache: Some(BlobFactsCache::open(dir.path().join("cache")).unwrap()) };
        let base = repo.rev_parse("HEAD").unwrap();
        let before = source.cones(&repo, &base, &base, &context()).unwrap();
        assert_eq!(before.paths["tests.test_a"], "tests/test_a.py");
        let head = sandbox.commit("main", "edit", &[("lib/a.py", "A = 2\n")], &[]);
        let after = source.cones(&repo, &head, &base, &context()).unwrap();
        assert_ne!(before.cones["tests.test_a"].digest(), after.cones["tests.test_a"].digest());
        assert_eq!(before.cones["tests.test_b"].digest(), after.cones["tests.test_b"].digest());
        // A bounded cone runs on its inputs; a widened one on the whole tree.
        assert_eq!(before.job("tests.test_a").inputs.unwrap(), ["lib/__init__.py", "lib/a.py", "tests/test_a.py"]);
        assert!(before.cones["tests.test_all"].tainted && before.job("tests.test_all").inputs.is_none());
        // Another pack is another verdict.
        let mut pack = RulePack::builtin();
        pack.imports.guards.insert("tests.test_b".into(), vec!["lib/a.py".into()]);
        let repacked = PythonCones { pack, cache: None }.cones(&repo, &base, &base, &context()).unwrap();
        assert_ne!(before.cones["tests.test_a"].digest(), repacked.cones["tests.test_a"].digest());
    }
}
