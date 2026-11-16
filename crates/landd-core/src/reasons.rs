//! Timeless, content-addressed admissibility: "no redder than base".
//!
//! A check unit's verdict is an [`Observation`] keyed by the unit and the
//! digest of its input cone, never by when it was made. The cone digest
//! covers every input's path, git mode and blob, whether the cone was
//! widened, and a *context* digest naming what produced the verdict (the
//! trusted rule pack, the runner's argv, environment and toolchain). A
//! candidate tree is admissible relative to a base tree iff every unit of
//! either tree is accounted for:
//!
//! * the same cone digest on both trees: the base verdict transports and
//!   nothing runs;
//! * a pass at the candidate cone;
//! * a failure at the candidate cone that names its failing items, where the
//!   base failure names a superset of them (an inherited red).
//!
//! Anything else blocks: a new failing item, a failure that cannot be
//! compared item by item (a crash or a timeout on either side, unless the
//! policy says such failures inherit), and a unit that exists on the base
//! and is gone from the candidate (unless the policy allows removals).
//! [`Reasons::why_not`] names every blocker together with the input paths
//! that moved under it.

use crate::canon::canonical_json;
use crate::digest::{Digest32, Oid};
use crate::fsx;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Mutex;

pub type UnitId = String;

const CONE_DOMAIN: &str = "landd cone digest v2";
const LEAF_DOMAIN: &str = "landd cone leaf v2";
const OBSERVATION_DOMAIN: &str = "landd observation key v2";

/// The item a crash is reported under in `why_not`.
pub const CRASH_ITEM: &str = "landd:crash";
/// The item a timeout is reported under in `why_not`.
pub const TIMEOUT_ITEM: &str = "landd:timeout";
/// The item a removed unit is reported under in `why_not`.
pub const REMOVED_ITEM: &str = "landd:unit-removed";

/// One cone input as git records it: `chmod +x`, and a symlink in place of
/// a file with the same bytes, are different inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Input {
    pub mode: u32,
    pub oid: Oid,
}

/// Digest of one cone input: a path bound to the mode and object at that path.
pub fn cone_leaf(path: &str, mode: u32, oid: &Oid) -> [u8; 32] {
    *Digest32::tagged(LEAF_DOMAIN, &[path.as_bytes(), &mode.to_be_bytes(), oid.as_bytes()]).as_bytes()
}

/// Digest of a cone's input set: its leaves, already in path order.
pub fn cone_inputs_digest<'a>(leaves: impl Iterator<Item = &'a [u8; 32]>) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(leaves.size_hint().0 * 32);
    for leaf in leaves {
        bytes.extend_from_slice(leaf);
    }
    *blake3::hash(&bytes).as_bytes()
}

/// A unit's cone digest: the unit, whether its cone was widened, its input
/// set, and the context that judges it.
pub fn cone_digest(unit: &str, inputs: &[u8; 32], tainted: bool, context: &Digest32) -> Digest32 {
    Digest32::tagged(CONE_DOMAIN, &[unit.as_bytes(), &[tainted as u8], inputs, context.as_bytes()])
}

/// Everything a unit's verdict can depend on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cone {
    pub unit: UnitId,
    pub inputs: BTreeMap<String, Input>,
    /// The unit reaches something that cannot be bounded statically, so
    /// `inputs` was widened to the whole tree.
    pub tainted: bool,
    /// What produces and interprets the verdict: rule pack, runner profile.
    pub context: Digest32,
}

impl Cone {
    pub fn digest(&self) -> Digest32 {
        let leaves: Vec<[u8; 32]> = self.inputs.iter().map(|(path, input)| cone_leaf(path, input.mode, &input.oid)).collect();
        cone_digest(&self.unit, &cone_inputs_digest(leaves.iter()), self.tainted, &self.context)
    }

    /// Input paths added, removed or changed between `self` and `other`.
    pub fn moved_paths(&self, other: &Cone) -> Vec<String> {
        let mut moved = BTreeSet::new();
        for (path, input) in &self.inputs {
            if other.inputs.get(path) != Some(input) {
                moved.insert(path.clone());
            }
        }
        for path in other.inputs.keys() {
            if !self.inputs.contains_key(path) {
                moved.insert(path.clone());
            }
        }
        moved.into_iter().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Status {
    Pass,
    /// The unit ran to completion and named what failed. Never empty.
    Fail {
        items: BTreeSet<String>,
    },
    /// The unit failed without saying what: a crash, a collection error, a
    /// non-zero exit with no result frame. Two crashes cannot be compared.
    Crash,
    Timeout,
}

impl Status {
    pub fn fail<S: AsRef<str>>(items: &[S]) -> Self {
        Self::Fail { items: items.iter().map(|s| s.as_ref().to_owned()).collect() }
    }

    /// A failure that names nothing is not a verdict.
    pub fn is_well_formed(&self) -> bool {
        !matches!(self, Self::Fail { items } if items.is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub unit_id: UnitId,
    pub cone_digest: Digest32,
    #[serde(flatten)]
    pub status: Status,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("verdict store io at {path}: {detail}")]
    Io { path: PathBuf, detail: String },
    #[error("verdict store record {path} is corrupt: {detail}")]
    Corrupt { path: PathBuf, detail: String },
    #[error("unit {unit} at cone {cone} already holds a different verdict")]
    Conflict { unit: UnitId, cone: Digest32 },
    #[error("a failure of {unit} that names no item cannot be recorded")]
    EmptyFailure { unit: UnitId },
}

/// Verdicts by `(unit, cone digest)`. There is no clock in this interface.
pub trait VerdictStore: Sync {
    fn get(&self, unit: &str, cone: &Digest32) -> Result<Option<Status>, StoreError>;
    /// Idempotent for an equal verdict; a different verdict for the same key
    /// is a [`StoreError::Conflict`] and the first one stands.
    fn put(&self, observation: &Observation) -> Result<(), StoreError>;
}

fn well_formed(observation: &Observation) -> Result<(), StoreError> {
    if observation.status.is_well_formed() {
        Ok(())
    } else {
        Err(StoreError::EmptyFailure { unit: observation.unit_id.clone() })
    }
}

#[derive(Debug, Default)]
pub struct MemoryStore(Mutex<BTreeMap<(UnitId, Digest32), Status>>);

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.0.lock().expect("store lock").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl VerdictStore for MemoryStore {
    fn get(&self, unit: &str, cone: &Digest32) -> Result<Option<Status>, StoreError> {
        Ok(self.0.lock().expect("store lock").get(&(unit.to_owned(), *cone)).cloned())
    }

    fn put(&self, observation: &Observation) -> Result<(), StoreError> {
        well_formed(observation)?;
        let mut map = self.0.lock().expect("store lock");
        let key = (observation.unit_id.clone(), observation.cone_digest);
        match map.get(&key) {
            Some(existing) if *existing != observation.status => Err(StoreError::Conflict { unit: key.0, cone: key.1 }),
            Some(_) => Ok(()),
            None => {
                map.insert(key, observation.status.clone());
                Ok(())
            }
        }
    }
}

/// Write-once files at `<root>/ab/cd/<key>.json`. A lookup is one `open`.
#[derive(Debug, Clone)]
pub struct DiskVerdictStore {
    root: PathBuf,
}

impl DiskVerdictStore {
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn path_for(&self, unit: &str, cone: &Digest32) -> PathBuf {
        let key = Digest32::tagged(OBSERVATION_DOMAIN, &[unit.as_bytes(), cone.as_bytes()]);
        fsx::shard2(&self.root, &key.to_hex(), ".json")
    }
}

impl VerdictStore for DiskVerdictStore {
    fn get(&self, unit: &str, cone: &Digest32) -> Result<Option<Status>, StoreError> {
        let path = self.path_for(unit, cone);
        let Some(bytes) = fsx::read_optional(&path).map_err(|e| StoreError::Io { path: path.clone(), detail: e.to_string() })?
        else {
            return Ok(None);
        };
        let observation: Observation =
            serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt { path: path.clone(), detail: e.to_string() })?;
        if observation.unit_id != unit || observation.cone_digest != *cone {
            return Err(StoreError::Corrupt { path, detail: "record is for another key".into() });
        }
        if !observation.status.is_well_formed() {
            return Err(StoreError::Corrupt { path, detail: "a failure that names no item".into() });
        }
        Ok(Some(observation.status))
    }

    fn put(&self, observation: &Observation) -> Result<(), StoreError> {
        well_formed(observation)?;
        let path = self.path_for(&observation.unit_id, &observation.cone_digest);
        let bytes = canonical_json(observation).map_err(|e| StoreError::Corrupt { path: path.clone(), detail: e.to_string() })?;
        let created =
            fsx::create_exclusive(&path, &bytes).map_err(|e| StoreError::Io { path: path.clone(), detail: e.to_string() })?;
        if created {
            return Ok(());
        }
        match self.get(&observation.unit_id, &observation.cone_digest)? {
            Some(existing) if existing == observation.status => Ok(()),
            _ => Err(StoreError::Conflict { unit: observation.unit_id.clone(), cone: observation.cone_digest }),
        }
    }
}

/// Three-valued admissibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Slot {
    /// Every unit is accounted for: the candidate may land.
    Supported,
    /// Some verdicts are missing: run them, then judge again.
    Undefined,
    /// At least one unit is redder than on base, or is gone.
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum UnitReason {
    /// Same cone digest on base and candidate: zero runs.
    Transported,
    Pass,
    /// Fails, but only with items it already fails with on base.
    Inherited {
        items: BTreeSet<String>,
    },
    NewRed {
        new_items: BTreeSet<String>,
        moved_paths: Vec<String>,
    },
    /// The unit exists on the base and not on the candidate.
    Removed,
    /// No verdict at the candidate cone yet.
    NeedsCandidateRun,
    /// Fails on the candidate and base has no verdict to compare against.
    NeedsBaseRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitJudgement {
    pub unit: UnitId,
    pub base_cone: Option<Digest32>,
    /// `None` for a removed unit.
    pub cand_cone: Option<Digest32>,
    #[serde(flatten)]
    pub reason: UnitReason,
}

/// One blocking unit: what newly fails and which of its inputs moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocker {
    pub unit: UnitId,
    pub new_items: Vec<String>,
    pub moved_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Side {
    Base,
    Candidate,
}

/// A verdict that has to be produced before judgement can finish.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Need {
    pub side: Side,
    pub unit: UnitId,
    pub cone: Digest32,
}

/// What the operator has decided about the two fail-closed defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct JudgePolicy {
    /// A candidate may delete units that exist on the base.
    pub allow_removed: bool,
    /// A crash or timeout on both sides counts as inherited.
    pub inherit_coarse: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Reasons {
    pub units: Vec<UnitJudgement>,
}

impl Reasons {
    pub fn slot(&self) -> Slot {
        let mut slot = Slot::Supported;
        for unit in &self.units {
            match unit.reason {
                UnitReason::NewRed { .. } | UnitReason::Removed => return Slot::Unsupported,
                UnitReason::NeedsCandidateRun | UnitReason::NeedsBaseRun => slot = Slot::Undefined,
                _ => {}
            }
        }
        slot
    }

    /// Every blocker at once, not the first one found.
    pub fn why_not(&self) -> Vec<Blocker> {
        self.units
            .iter()
            .filter_map(|unit| match &unit.reason {
                UnitReason::NewRed { new_items, moved_paths } => Some(Blocker {
                    unit: unit.unit.clone(),
                    new_items: new_items.iter().cloned().collect(),
                    moved_paths: moved_paths.clone(),
                }),
                UnitReason::Removed => {
                    Some(Blocker { unit: unit.unit.clone(), new_items: vec![REMOVED_ITEM.to_owned()], moved_paths: Vec::new() })
                }
                _ => None,
            })
            .collect()
    }

    pub fn needs(&self) -> Vec<Need> {
        self.units
            .iter()
            .filter_map(|unit| match unit.reason {
                UnitReason::NeedsCandidateRun => {
                    unit.cand_cone.map(|cone| Need { side: Side::Candidate, unit: unit.unit.clone(), cone })
                }
                UnitReason::NeedsBaseRun => unit.base_cone.map(|cone| Need { side: Side::Base, unit: unit.unit.clone(), cone }),
                _ => None,
            })
            .collect()
    }

    pub fn count(&self, pick: impl Fn(&UnitReason) -> bool) -> usize {
        self.units.iter().filter(|unit| pick(&unit.reason)).count()
    }

    pub fn transported(&self) -> usize {
        self.count(|r| matches!(r, UnitReason::Transported))
    }

    pub fn removed(&self) -> Vec<&str> {
        self.units.iter().filter(|u| u.reason == UnitReason::Removed).map(|u| u.unit.as_str()).collect()
    }
}

/// The items a failing status is reported under.
fn items_of(status: &Status) -> BTreeSet<String> {
    match status {
        Status::Pass => BTreeSet::new(),
        Status::Fail { items } => items.clone(),
        Status::Crash => BTreeSet::from([CRASH_ITEM.to_owned()]),
        Status::Timeout => BTreeSet::from([TIMEOUT_ITEM.to_owned()]),
    }
}

/// Compare a failing candidate status with the base status. `None` means
/// the candidate is no redder: every item it fails with is one the base
/// already fails with. `Some(items)` are the new ones.
fn redder(cand: &Status, base: &Status, policy: &JudgePolicy) -> Option<BTreeSet<String>> {
    match (cand, base) {
        (Status::Pass, _) => None,
        (Status::Fail { items: cand_items }, Status::Fail { items: base_items }) => {
            let new: BTreeSet<String> = cand_items.difference(base_items).cloned().collect();
            (!new.is_empty()).then_some(new)
        }
        // Coarse against coarse: nothing says the candidate fails for the
        // base's reason. Inherited only when the operator has said so.
        (Status::Crash | Status::Timeout, Status::Crash | Status::Timeout) if policy.inherit_coarse => None,
        _ => Some(items_of(cand)),
    }
}

/// Judge the candidate cones against the base cones using recorded verdicts.
/// Units that exist only on the candidate have nothing to inherit. Units
/// that exist only on the base were removed by the candidate.
pub fn judge(
    base: &BTreeMap<UnitId, Cone>,
    cand: &BTreeMap<UnitId, Cone>,
    store: &dyn VerdictStore,
    policy: &JudgePolicy,
) -> Result<Reasons, StoreError> {
    let mut units = Vec::with_capacity(cand.len());
    for (unit, cand_cone) in cand {
        let cand_digest = cand_cone.digest();
        let base_cone = base.get(unit);
        let base_digest = base_cone.map(Cone::digest);
        let reason = if base_digest == Some(cand_digest) {
            UnitReason::Transported
        } else {
            match store.get(unit, &cand_digest)? {
                None => UnitReason::NeedsCandidateRun,
                Some(Status::Pass) => UnitReason::Pass,
                Some(cand_status) => {
                    let base_status = match &base_digest {
                        Some(digest) => store.get(unit, digest)?,
                        // A unit the candidate introduces: base fails nothing.
                        None => Some(Status::Pass),
                    };
                    match base_status {
                        None => UnitReason::NeedsBaseRun,
                        Some(base_status) => match redder(&cand_status, &base_status, policy) {
                            None => UnitReason::Inherited { items: items_of(&cand_status) },
                            Some(new_items) => UnitReason::NewRed {
                                new_items,
                                moved_paths: match base_cone {
                                    Some(base_cone) => base_cone.moved_paths(cand_cone),
                                    None => cand_cone.inputs.keys().cloned().collect(),
                                },
                            },
                        },
                    }
                }
            }
        };
        units.push(UnitJudgement { unit: unit.clone(), base_cone: base_digest, cand_cone: Some(cand_digest), reason });
    }
    if !policy.allow_removed {
        for (unit, base_cone) in base {
            if !cand.contains_key(unit) {
                units.push(UnitJudgement {
                    unit: unit.clone(),
                    base_cone: Some(base_cone.digest()),
                    cand_cone: None,
                    reason: UnitReason::Removed,
                });
            }
        }
        units.sort_by(|a, b| a.unit.cmp(&b.unit));
    }
    Ok(Reasons { units })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRICT: JudgePolicy = JudgePolicy { allow_removed: false, inherit_coarse: false };

    fn blob(text: &str) -> Oid {
        Oid::git_blob_sha1(text.as_bytes())
    }

    fn context() -> Digest32 {
        Digest32::blake3(b"runner profile")
    }

    fn cone(unit: &str, inputs: &[(&str, &str)]) -> Cone {
        Cone {
            unit: unit.into(),
            inputs: inputs
                .iter()
                .map(|(path, content)| (path.to_string(), Input { mode: 0o100644, oid: blob(content) }))
                .collect(),
            tainted: false,
            context: context(),
        }
    }

    fn tree(cones: &[Cone]) -> BTreeMap<UnitId, Cone> {
        cones.iter().map(|c| (c.unit.clone(), c.clone())).collect()
    }

    fn fail(items: &[&str]) -> Status {
        Status::fail(items)
    }

    fn record(store: &dyn VerdictStore, cone: &Cone, status: Status) {
        store.put(&Observation { unit_id: cone.unit.clone(), cone_digest: cone.digest(), status }).unwrap();
    }

    #[test]
    fn tooth_one_byte_in_a_transitive_dependency_changes_the_cone_digest() {
        let before = cone("tests.test_a", &[("tests/test_a.py", "import lib"), ("lib/deep.py", "X = 1\n")]);
        let after = cone("tests.test_a", &[("tests/test_a.py", "import lib"), ("lib/deep.py", "X = 2\n")]);
        assert_ne!(before.digest(), after.digest());
        assert_eq!(before.moved_paths(&after), vec!["lib/deep.py"]);
    }

    #[test]
    fn cone_digest_binds_unit_path_content_mode_taint_and_context() {
        let base = cone("u", &[("a.py", "1"), ("b.py", "2")]);
        assert_eq!(base.digest(), cone("u", &[("b.py", "2"), ("a.py", "1")]).digest());
        assert_ne!(base.digest(), cone("v", &[("a.py", "1"), ("b.py", "2")]).digest());
        // Same blobs under swapped paths is a different cone.
        assert_ne!(base.digest(), cone("u", &[("a.py", "2"), ("b.py", "1")]).digest());
        assert_ne!(base.digest(), cone("u", &[("a.py", "1")]).digest());
        assert_ne!(base.digest(), Cone { tainted: true, ..base.clone() }.digest());
        // The same tree judged by another toolchain or rule pack is another cone.
        assert_ne!(base.digest(), Cone { context: Digest32::blake3(b"python 3.14"), ..base.clone() }.digest());
        // `chmod +x`, and a symlink whose target text equals the file's bytes.
        for mode in [0o100755, 0o120000] {
            let mut changed = base.clone();
            changed.inputs.get_mut("a.py").unwrap().mode = mode;
            assert_ne!(base.digest(), changed.digest(), "{mode:o}");
            assert_eq!(base.moved_paths(&changed), vec!["a.py"]);
        }
    }

    #[test]
    fn tooth_disjoint_advance_of_main_transports_with_zero_runs() {
        // `main` moved `docs/readme.md`, which is in no cone.
        let unit = cone("tests.test_a", &[("tests/test_a.py", "t"), ("lib/a.py", "a")]);
        let store = MemoryStore::new();
        let reasons = judge(&tree(std::slice::from_ref(&unit)), &tree(std::slice::from_ref(&unit)), &store, &STRICT).unwrap();
        assert_eq!(reasons.slot(), Slot::Supported);
        assert_eq!(reasons.transported(), 1);
        assert!(reasons.needs().is_empty());
        assert!(store.is_empty());
        assert_eq!(reasons.units[0].base_cone, reasons.units[0].cand_cone);
    }

    #[test]
    fn missing_verdicts_are_undefined_then_pass_supports() {
        let base = cone("u", &[("a.py", "1")]);
        let cand = cone("u", &[("a.py", "2")]);
        let store = MemoryStore::new();
        let reasons = judge(&tree(std::slice::from_ref(&base)), &tree(std::slice::from_ref(&cand)), &store, &STRICT).unwrap();
        assert_eq!(reasons.slot(), Slot::Undefined);
        assert_eq!(reasons.needs(), vec![Need { side: Side::Candidate, unit: "u".into(), cone: cand.digest() }]);
        record(&store, &cand, Status::Pass);
        assert_eq!(judge(&tree(&[base]), &tree(&[cand]), &store, &STRICT).unwrap().slot(), Slot::Supported);
    }

    #[test]
    fn inherited_red_never_blocks_and_needs_the_base_verdict_first() {
        let base = cone("u", &[("a.py", "1"), ("unrelated.py", "x")]);
        let cand = cone("u", &[("a.py", "1"), ("unrelated.py", "y")]);
        let store = MemoryStore::new();
        record(&store, &cand, fail(&["test_old_bug"]));
        let (b, c) = (tree(std::slice::from_ref(&base)), tree(std::slice::from_ref(&cand)));

        let waiting = judge(&b, &c, &store, &STRICT).unwrap();
        assert_eq!(waiting.slot(), Slot::Undefined);
        assert_eq!(waiting.needs(), vec![Need { side: Side::Base, unit: "u".into(), cone: base.digest() }]);

        record(&store, &base, fail(&["test_old_bug", "test_other_old_bug"]));
        let reasons = judge(&b, &c, &store, &STRICT).unwrap();
        assert_eq!(reasons.slot(), Slot::Supported);
        assert!(matches!(&reasons.units[0].reason, UnitReason::Inherited { items } if items.len() == 1));
        assert!(reasons.why_not().is_empty());
    }

    #[test]
    fn tooth_why_not_names_every_blocker_and_moved_path_at_once() {
        let base = tree(&[
            cone("green_stays_green", &[("a.py", "1")]),
            cone("was_green", &[("b.py", "1"), ("shared.py", "1")]),
            cone("was_red", &[("c.py", "1"), ("shared.py", "1")]),
            cone("untouched", &[("d.py", "1")]),
        ]);
        let cand_cones = [
            cone("green_stays_green", &[("a.py", "2")]),
            cone("was_green", &[("b.py", "2"), ("shared.py", "2")]),
            cone("was_red", &[("c.py", "1"), ("shared.py", "2")]),
            cone("untouched", &[("d.py", "1")]),
            cone("brand_new", &[("e.py", "1")]),
        ];
        let cand = tree(&cand_cones);
        let store = MemoryStore::new();
        record(&store, &base["was_green"], Status::Pass);
        record(&store, &base["was_red"], fail(&["t1"]));
        record(&store, &cand["green_stays_green"], Status::Pass);
        record(&store, &cand["was_green"], fail(&["t9"]));
        record(&store, &cand["was_red"], fail(&["t1", "t2"]));
        record(&store, &cand["brand_new"], fail(&["t_new"]));

        let reasons = judge(&base, &cand, &store, &STRICT).unwrap();
        assert_eq!(reasons.slot(), Slot::Unsupported);
        assert_eq!(
            reasons.why_not(),
            vec![
                Blocker { unit: "brand_new".into(), new_items: vec!["t_new".into()], moved_paths: vec!["e.py".into()] },
                Blocker {
                    unit: "was_green".into(),
                    new_items: vec!["t9".into()],
                    moved_paths: vec!["b.py".into(), "shared.py".into()],
                },
                Blocker { unit: "was_red".into(), new_items: vec!["t2".into()], moved_paths: vec!["shared.py".into()] },
            ]
        );
        assert_eq!(reasons.transported(), 1);
    }

    /// A lane cannot get past the gate by deleting (or hiding) the unit that
    /// would have failed it.
    #[test]
    fn tooth_removed_units_block_unless_the_policy_allows_removal() {
        let base = tree(&[cone("gone", &[("a.py", "1")]), cone("kept", &[("b.py", "1")])]);
        let cand = tree(&[cone("kept", &[("b.py", "1")])]);
        let reasons = judge(&base, &cand, &MemoryStore::new(), &STRICT).unwrap();
        assert_eq!(reasons.slot(), Slot::Unsupported);
        assert_eq!(reasons.removed(), vec!["gone"]);
        assert_eq!(
            reasons.why_not(),
            vec![Blocker { unit: "gone".into(), new_items: vec![REMOVED_ITEM.into()], moved_paths: vec![] }]
        );
        // Deleting every unit is not "nothing to check".
        let emptied = judge(&base, &BTreeMap::new(), &MemoryStore::new(), &STRICT).unwrap();
        assert_eq!((emptied.slot(), emptied.why_not().len()), (Slot::Unsupported, 2));

        let lenient = JudgePolicy { allow_removed: true, ..STRICT };
        let reasons = judge(&base, &cand, &MemoryStore::new(), &lenient).unwrap();
        assert_eq!(reasons.slot(), Slot::Supported);
        assert_eq!(reasons.units.len(), 1);
    }

    /// Failures that do not name items cannot hide a new red behind an old one.
    #[test]
    fn tooth_coarse_failures_are_not_comparable() {
        let base = cone("u", &[("a.py", "1")]);
        let cand = cone("u", &[("a.py", "2")]);
        let (b, c) = (tree(std::slice::from_ref(&base)), tree(std::slice::from_ref(&cand)));
        let verdict = |base_status: Status, cand_status: Status, policy: &JudgePolicy| {
            let store = MemoryStore::new();
            record(&store, &base, base_status);
            record(&store, &cand, cand_status);
            judge(&b, &c, &store, policy).unwrap()
        };
        // Base crashed; the candidate crashes too. Same crash? Nobody knows.
        let both = verdict(Status::Crash, Status::Crash, &STRICT);
        assert_eq!(both.slot(), Slot::Unsupported);
        assert_eq!(both.why_not()[0].new_items, vec![CRASH_ITEM]);
        assert_eq!(verdict(Status::Timeout, Status::Crash, &STRICT).slot(), Slot::Unsupported);
        // Items against a crash, either way round, are not comparable either.
        assert_eq!(verdict(Status::Crash, fail(&["t1"]), &STRICT).slot(), Slot::Unsupported);
        assert_eq!(verdict(fail(&["t1"]), Status::Crash, &STRICT).slot(), Slot::Unsupported);
        assert_eq!(verdict(Status::Pass, Status::Timeout, &STRICT).why_not()[0].new_items, vec![TIMEOUT_ITEM]);
        // Only an explicit policy makes coarse failures inherit, and only coarse from coarse.
        let lenient = JudgePolicy { inherit_coarse: true, ..STRICT };
        assert_eq!(verdict(Status::Crash, Status::Crash, &lenient).slot(), Slot::Supported);
        assert_eq!(verdict(fail(&["t1"]), Status::Crash, &lenient).slot(), Slot::Unsupported);
        assert_eq!(verdict(Status::Pass, Status::Crash, &lenient).slot(), Slot::Unsupported);
    }

    /// Revert: a bad commit changes a blob, the revert restores the old blob
    /// id, and the old `Pass` answers again from disk with no rerun, however
    /// old the record is. The store's file is aged ten years to show that no
    /// reader consults a clock.
    #[test]
    fn tooth_revert_restores_the_cone_digest_and_hits_the_cache_ten_years_later() {
        let dir = crate::git::testkit::private_tempdir().unwrap();
        let store = DiskVerdictStore::open(dir.path());
        let good = cone("tests.test_a", &[("tests/test_a.py", "t"), ("lib/a.py", "good")]);
        let bad = cone("tests.test_a", &[("tests/test_a.py", "t"), ("lib/a.py", "bad")]);
        let reverted = cone("tests.test_a", &[("tests/test_a.py", "t"), ("lib/a.py", "good")]);
        record(&store, &good, Status::Pass);
        record(&store, &bad, fail(&["test_a"]));

        assert_ne!(good.digest(), bad.digest());
        assert_eq!(good.digest().as_bytes(), reverted.digest().as_bytes());

        let path = store.path_for(&good.unit, &good.digest());
        let ten_years = std::time::Duration::from_secs(10 * 366 * 24 * 3600);
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(std::time::SystemTime::now() - ten_years).unwrap();
        drop(file);
        let age = std::fs::metadata(&path).unwrap().modified().unwrap().elapsed().unwrap();
        assert!(age >= ten_years);

        // Judge the reverted tree against the bad tip of main.
        let reopened = DiskVerdictStore::open(dir.path());
        let reasons = judge(&tree(&[bad]), &tree(&[reverted]), &reopened, &STRICT).unwrap();
        assert_eq!(reasons.slot(), Slot::Supported);
        assert_eq!(reasons.units[0].reason, UnitReason::Pass);
        assert!(reasons.needs().is_empty());
    }

    #[test]
    fn tooth_stores_refuse_a_contradicting_or_empty_verdict() {
        let dir = crate::git::testkit::private_tempdir().unwrap();
        let unit = cone("u", &[("a.py", "1")]);
        let stores: [&dyn VerdictStore; 2] = [&MemoryStore::new(), &DiskVerdictStore::open(dir.path())];
        for store in stores {
            record(store, &unit, Status::Pass);
            record(store, &unit, Status::Pass);
            let contradiction = Observation { unit_id: "u".into(), cone_digest: unit.digest(), status: fail(&["x"]) };
            assert!(matches!(store.put(&contradiction), Err(StoreError::Conflict { .. })));
            assert_eq!(store.get("u", &unit.digest()).unwrap(), Some(Status::Pass));
            assert_eq!(store.get("other", &unit.digest()).unwrap(), None);
            // `Fail(∅)` would be a subset of every failure.
            let empty = Observation { unit_id: "e".into(), cone_digest: unit.digest(), status: fail(&[]) };
            assert!(matches!(store.put(&empty), Err(StoreError::EmptyFailure { .. })));
            assert_eq!(store.get("e", &unit.digest()).unwrap(), None);
        }
    }

    #[test]
    fn observation_wire_form_is_flat() {
        let observation = Observation { unit_id: "u".into(), cone_digest: Digest32::blake3(b"c"), status: fail(&["b", "a"]) };
        let text = String::from_utf8(canonical_json(&observation).unwrap()).unwrap();
        assert!(text.contains(r#""items":["a","b"]"#) && text.contains(r#""status":"fail""#));
        assert_eq!(serde_json::from_str::<Observation>(&text).unwrap(), observation);
        for status in [Status::Pass, Status::Crash, Status::Timeout] {
            let observation = Observation { unit_id: "u".into(), cone_digest: Digest32::blake3(b"c"), status };
            let text = String::from_utf8(canonical_json(&observation).unwrap()).unwrap();
            assert_eq!(serde_json::from_str::<Observation>(&text).unwrap(), observation);
        }
    }
}
