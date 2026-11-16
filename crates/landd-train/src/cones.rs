//! Where a tree's check units and their input cones come from.

use ast_sweep::glob::GlobSet;
use ast_sweep::{BlobFactsCache, ImportGraph, RulePack};
use landd_core::git::GitRepo;
use landd_core::reasons::{Cone, UnitId};
use landd_core::Oid;
use serde::Deserialize;
use std::collections::BTreeMap;

/// The units of one tree: each unit's cone and the path the runner is given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitCones {
    pub cones: BTreeMap<UnitId, Cone>,
    pub paths: BTreeMap<UnitId, String>,
}

pub trait ConeSource: Sync {
    fn cones(&self, repo: &GitRepo, commit: &Oid) -> Result<UnitCones, String>;
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

impl ConeSource for ManifestCones {
    fn cones(&self, repo: &GitRepo, commit: &Oid) -> Result<UnitCones, String> {
        let mut entries = repo.ls_tree(&commit.to_hex(), false).map_err(|e| e.to_string())?;
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        let Ok(at) = paths.binary_search(&self.manifest.as_str()) else {
            // A tree without a manifest has no units.
            return Ok(UnitCones::default());
        };
        let bytes = repo.read_blob(&entries[at].oid).map_err(|e| e.to_string())?;
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|e| format!("unit manifest {}: {e}", self.manifest))?;
        let mut units = UnitCones::default();
        for (unit, declared) in manifest.units {
            let mut picked = GlobSet::new(&declared.inputs).select(&paths);
            picked.push(at as u32);
            let inputs = picked.into_iter().map(|i| &entries[i as usize]).map(|e| (e.path.clone(), e.oid)).collect();
            units.cones.insert(unit.clone(), Cone { unit: unit.clone(), inputs, tainted: false });
            units.paths.insert(unit, declared.path);
        }
        Ok(units)
    }
}

/// Units are the Python test modules of the tree; cones are their static
/// import cones as exported by `ast-sweep`.
#[derive(Debug, Clone)]
pub struct PythonCones {
    pub pack: RulePack,
    pub cache: Option<BlobFactsCache>,
}

impl ConeSource for PythonCones {
    fn cones(&self, repo: &GitRepo, commit: &Oid) -> Result<UnitCones, String> {
        let (all, _) = ast_sweep::sweep_git(repo, &commit.to_hex(), self.cache.as_ref()).map_err(|e| e.to_string())?;
        let graph = ImportGraph::build(&all, &self.pack.imports);
        let mut units = UnitCones::default();
        for cone in ast_sweep::imports::cones(&all, &graph, &self.pack.imports) {
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
        "a": {"path": "checks/a.sh", "inputs": ["checks/a.sh", "src/a/*"]},
        "b": {"path": "checks/b.sh", "inputs": ["checks/b.sh", "src/b.txt"]}}}"#;

    #[test]
    fn manifest_cones_cover_declared_inputs_and_the_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let files = [
            ("landd-units.json", MANIFEST),
            ("checks/a.sh", "true\n"),
            ("checks/b.sh", "true\n"),
            ("src/a/one.txt", "1\n"),
            ("src/a/deep/two.txt", "2\n"),
            ("src/b.txt", "b\n"),
            ("docs.md", "docs\n"),
        ];
        let sandbox = Sandbox::new(dir.path(), &files);
        let repo = sandbox.repo();
        let source = ManifestCones { manifest: "landd-units.json".into() };
        let before = source.cones(&repo, &repo.rev_parse("HEAD").unwrap()).unwrap();
        assert_eq!(before.paths["a"], "checks/a.sh");
        let a: Vec<&str> = before.cones["a"].inputs.keys().map(String::as_str).collect();
        assert_eq!(a, ["checks/a.sh", "landd-units.json", "src/a/deep/two.txt", "src/a/one.txt"]);

        let head = sandbox.commit("main", "edit", &[("src/a/deep/two.txt", "changed\n"), ("docs.md", "new\n")], &[]);
        let after = source.cones(&repo, &head).unwrap();
        assert_ne!(before.cones["a"].digest(), after.cones["a"].digest());
        assert_eq!(before.cones["b"].digest(), after.cones["b"].digest());

        let none = ManifestCones { manifest: "absent.json".into() };
        assert!(none.cones(&repo, &head).unwrap().cones.is_empty());
    }

    #[test]
    fn python_cones_are_ast_sweep_import_cones() {
        let dir = tempfile::tempdir().unwrap();
        let files = [
            ("lib/__init__.py", ""),
            ("lib/a.py", "A = 1\n"),
            ("lib/b.py", "B = 1\n"),
            ("tests/test_a.py", "from lib import a\n"),
            ("tests/test_b.py", "from lib import b\n"),
        ];
        let sandbox = Sandbox::new(dir.path(), &files);
        let repo = sandbox.repo();
        let source = PythonCones { pack: RulePack::builtin(), cache: Some(BlobFactsCache::open(dir.path().join("cache"))) };
        let before = source.cones(&repo, &repo.rev_parse("HEAD").unwrap()).unwrap();
        assert_eq!(before.paths["tests.test_a"], "tests/test_a.py");
        let head = sandbox.commit("main", "edit", &[("lib/a.py", "A = 2\n")], &[]);
        let after = source.cones(&repo, &head).unwrap();
        assert_ne!(before.cones["tests.test_a"].digest(), after.cones["tests.test_a"].digest());
        assert_eq!(before.cones["tests.test_b"].digest(), after.cones["tests.test_b"].digest());
    }
}
