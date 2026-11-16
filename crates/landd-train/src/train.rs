//! Judge a batch, isolate culprits, land the rest.

use crate::compose::{compose, Candidate, Composition, Dropped};
use crate::cones::{ConeSource, UnitCones};
use crate::runner::{Runner, RunnerError};
use landd_core::custody::{self, CustodyEnvelopeV2, CustodyError, SigningKey};
use landd_core::delivery::{AncestryEvidence, Binding, DeclineEvidence, DeliveryError, DeliveryJournal, JournalError};
use landd_core::digest::hex_encode;
use landd_core::git::{GitError, GitRepo, Identity};
use landd_core::reasons::{judge, Blocker, MemoryStore, Observation, Side, Slot, Status, StoreError, VerdictStore};
use landd_core::{Digest32, LandConfig, Oid};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, thiserror::Error)]
pub enum TrainError {
    #[error(transparent)]
    Git(#[from] GitError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Runner(#[from] RunnerError),
    #[error(transparent)]
    Custody(#[from] CustodyError),
    #[error("cones: {0}")]
    Cones(String),
    #[error("{remote} has no {target_ref}")]
    NoTargetRef { remote: String, target_ref: String },
    #[error("refusing to push {tip}: it does not descend from {base}")]
    NotFastForward { base: Oid, tip: Oid },
    #[error("verdicts for {0} units are still missing after running them")]
    Stuck(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CandidateOutcome {
    /// Pushed, and the forge shows the lane tip on the target ref.
    Landed { merge: Oid, evidence: AncestryEvidence },
    /// The lane tip was on the target ref before this batch.
    AlreadyLanded { evidence: AncestryEvidence },
    Declined { evidence: DeclineEvidence },
    /// Admissible, but the forge did not take the push (the ref moved).
    Refused { not_before: u64 },
    /// Admissible; not pushed because this was a dry run.
    WouldLand { merge: Oid },
    /// The push was sent and the forge could not be read afterwards.
    Unknown { merge: Oid },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Tally {
    /// Compositions judged, including those of the bisection.
    pub evaluations: usize,
    pub candidate_units_run: usize,
    pub base_units_run: usize,
    /// Units of the first judgement whose cone did not move (zero runs).
    pub units_transported: usize,
    pub units_total: usize,
    pub flaky_units: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchReport {
    pub base: Oid,
    /// The chain tip that was pushed, when a push was attempted.
    pub pushed: Option<Oid>,
    pub push_exit: Option<i32>,
    pub remote_head: Option<Oid>,
    pub outcomes: Vec<(Candidate, CandidateOutcome)>,
    pub tally: Tally,
    pub compose_ms: f64,
    pub total_ms: f64,
    pub receipt: Option<CustodyEnvelopeV2>,
}

impl BatchReport {
    pub fn outcome_of(&self, lane: &str) -> Option<&CandidateOutcome> {
        self.outcomes.iter().find(|(candidate, _)| candidate.lane == lane).map(|(_, outcome)| outcome)
    }

    pub fn landed(&self) -> usize {
        self.outcomes.iter().filter(|(_, o)| matches!(o, CandidateOutcome::Landed { .. })).count()
    }
}

/// Session verdicts (flaky passes, timeouts) shadow the durable store
/// without ever being written to it.
struct Overlay<'a> {
    durable: &'a dyn VerdictStore,
    session: &'a MemoryStore,
}

impl VerdictStore for Overlay<'_> {
    fn get(&self, unit: &str, cone: &Digest32) -> Result<Option<Status>, StoreError> {
        match self.session.get(unit, cone)? {
            Some(status) => Ok(Some(status)),
            None => self.durable.get(unit, cone),
        }
    }

    fn put(&self, observation: &Observation) -> Result<(), StoreError> {
        self.durable.put(observation)
    }
}

enum Eval {
    Admissible,
    Blocked(DeclineEvidence),
}

pub struct Train<'a> {
    pub repo: &'a GitRepo,
    pub config: &'a LandConfig,
    pub cones: &'a dyn ConeSource,
    pub store: &'a dyn VerdictStore,
    pub journal: &'a DeliveryJournal,
    pub runner: Runner,
    /// Names the destination in delivery bindings.
    pub repo_id: String,
    /// `(key_id, key)` for sealing land receipts.
    pub signer: Option<(String, SigningKey)>,
    session: MemoryStore,
    memo: Mutex<HashMap<Oid, Arc<UnitCones>>>,
}

impl<'a> Train<'a> {
    pub fn new(
        repo: &'a GitRepo,
        config: &'a LandConfig,
        cones: &'a dyn ConeSource,
        store: &'a dyn VerdictStore,
        journal: &'a DeliveryJournal,
        runner: Runner,
    ) -> Self {
        let repo_id = format!("{}#{}", repo.dir().display(), config.remote);
        Self { repo, config, cones, store, journal, runner, repo_id, signer: None, session: MemoryStore::new(), memo: Mutex::new(HashMap::new()) }
    }

    pub fn with_signer(mut self, key_id: impl Into<String>, key: SigningKey) -> Self {
        self.signer = Some((key_id.into(), key));
        self
    }

    fn cones_at(&self, commit: &Oid) -> Result<Arc<UnitCones>, TrainError> {
        if let Some(hit) = self.memo.lock().expect("cone memo").get(commit) {
            return Ok(hit.clone());
        }
        let cones = Arc::new(self.cones.cones(self.repo, commit).map_err(TrainError::Cones)?);
        self.memo.lock().expect("cone memo").insert(*commit, cones.clone());
        Ok(cones)
    }

    fn binding(&self, base: &Oid, lane_tip: &Oid, merged_head: Oid) -> Binding {
        Binding {
            repo: self.repo_id.clone(),
            target_ref: self.config.target_ref.clone(),
            lane_tip: *lane_tip,
            expected_old: *base,
            merged_head,
        }
    }

    /// The forge's current target ref, with its objects present locally.
    pub fn forge_head(&self) -> Result<Oid, TrainError> {
        let (remote, target_ref) = (&self.config.remote, &self.config.target_ref);
        let head = self
            .repo
            .ls_remote(remote, target_ref)?
            .ok_or_else(|| TrainError::NoTargetRef { remote: remote.clone(), target_ref: target_ref.clone() })?;
        if !self.repo.has_object(&head)? {
            self.repo.fetch(remote, target_ref)?;
        }
        Ok(head)
    }

    /// Land `candidates` onto the forge's current target ref. With `apply`
    /// false nothing is pushed and nothing is journaled. `now` is seconds
    /// since the epoch; it dates the merge commits and the delivery journal.
    pub fn land_batch(&self, candidates: &[Candidate], apply: bool, now: u64) -> Result<BatchReport, TrainError> {
        let base = self.forge_head()?;
        self.land_on(&base, candidates, apply, now)
    }

    /// As [`Train::land_batch`], against a base the caller read earlier. If
    /// the forge has moved since, the lease refuses the push.
    pub fn land_on(&self, base: &Oid, candidates: &[Candidate], apply: bool, now: u64) -> Result<BatchReport, TrainError> {
        let started = Instant::now();
        let who = Identity { name: self.config.committer_name.clone(), email: self.config.committer_email.clone(), time: now };
        let mut tally = Tally::default();
        let mut outcomes: BTreeMap<usize, CandidateOutcome> = BTreeMap::new();
        let position = |candidate: &Candidate| candidates.iter().position(|c| c == candidate).expect("a batch member");
        let zero = Oid::zero_sha1();

        // Compose once: conflicts and already-landed tips leave the batch here.
        let first = compose(self.repo, base, candidates, &who)?;
        let compose_ms = started.elapsed().as_secs_f64() * 1000.0;
        for (candidate, dropped) in &first.dropped {
            let outcome = match dropped {
                Dropped::Conflict { conflicting_paths } => {
                    let evidence = DeclineEvidence::Conflict { conflicting_paths: conflicting_paths.clone() };
                    self.decline(apply, base, candidate, &evidence)?;
                    CandidateOutcome::Declined { evidence }
                }
                Dropped::AlreadyLanded => {
                    let evidence = AncestryEvidence {
                        target_ref: self.config.target_ref.clone(),
                        remote_head: *base,
                        lane_tip: candidate.tip,
                    };
                    if apply {
                        let binding = self.binding(base, &candidate.tip, zero);
                        self.journal.transition(&binding, |d| d.complete(evidence.clone()))?;
                    }
                    CandidateOutcome::AlreadyLanded { evidence }
                }
            };
            outcomes.insert(position(candidate), outcome);
        }

        // Judge; on a new red, split to find the culprits.
        let survivors: Vec<Candidate> = first.links.iter().map(|link| link.candidate.clone()).collect();
        let mut good = Vec::new();
        let mut culprits = Vec::new();
        self.isolate(base, &mut good, &survivors, &who, &mut tally, &mut culprits)?;
        for (candidate, evidence) in culprits {
            self.decline(apply, base, &candidate, &evidence)?;
            outcomes.insert(position(&candidate), CandidateOutcome::Declined { evidence });
        }

        let mut report = BatchReport {
            base: *base,
            pushed: None,
            push_exit: None,
            remote_head: None,
            outcomes: Vec::new(),
            tally: Tally::default(),
            compose_ms,
            total_ms: 0.0,
            receipt: None,
        };
        if !good.is_empty() {
            // Same inputs, same identity: this is the chain that was judged.
            let chain = compose(self.repo, base, &good, &who)?;
            let tip = chain.tip();
            if !apply {
                for link in &chain.links {
                    outcomes.insert(position(&link.candidate), CandidateOutcome::WouldLand { merge: link.merge });
                }
            } else {
                if !self.repo.is_ancestor(base, &tip)? {
                    return Err(TrainError::NotFastForward { base: *base, tip });
                }
                for (candidate, outcome) in self.deliver(base, &chain, &tally, now, &mut report)? {
                    outcomes.insert(position(&candidate), outcome);
                }
            }
        }
        report.outcomes = candidates.iter().cloned().enumerate().filter_map(|(i, c)| Some((c, outcomes.remove(&i)?))).collect();
        report.tally = tally;
        report.total_ms = started.elapsed().as_secs_f64() * 1000.0;
        Ok(report)
    }

    fn decline(&self, apply: bool, base: &Oid, candidate: &Candidate, evidence: &DeclineEvidence) -> Result<(), TrainError> {
        if !apply {
            return Ok(());
        }
        let binding = self.binding(base, &candidate.tip, Oid::zero_sha1());
        match self.journal.transition(&binding, |d| d.declined(evidence.clone())) {
            // Declining twice, or declining what the forge already holds, changes nothing.
            Ok(_) | Err(JournalError::Delivery(DeliveryError::Declined(_) | DeliveryError::Completed)) => Ok(()),
            Err(other) => Err(other.into()),
        }
    }

    /// Extend `good` with every member of `list` that keeps the chain
    /// admissible, in order; the rest go to `culprits`. Each split reuses the
    /// verdicts already recorded, so only cones nobody has judged run again.
    fn isolate(
        &self,
        base: &Oid,
        good: &mut Vec<Candidate>,
        list: &[Candidate],
        who: &Identity,
        tally: &mut Tally,
        culprits: &mut Vec<(Candidate, DeclineEvidence)>,
    ) -> Result<(), TrainError> {
        if list.is_empty() {
            return Ok(());
        }
        let trial: Vec<Candidate> = good.iter().chain(list).cloned().collect();
        match self.evaluate(base, &trial, who, tally)? {
            Eval::Admissible => good.extend_from_slice(list),
            Eval::Blocked(evidence) if list.len() == 1 => culprits.push((list[0].clone(), evidence)),
            Eval::Blocked(_) => {
                let (left, right) = list.split_at(list.len() / 2);
                self.isolate(base, good, left, who, tally, culprits)?;
                self.isolate(base, good, right, who, tally, culprits)?;
            }
        }
        Ok(())
    }

    fn evaluate(&self, base: &Oid, list: &[Candidate], who: &Identity, tally: &mut Tally) -> Result<Eval, TrainError> {
        let composition = compose(self.repo, base, list, who)?;
        // Without an earlier member of the batch, a later one may no longer merge.
        for (_, dropped) in &composition.dropped {
            if let Dropped::Conflict { conflicting_paths } = dropped {
                return Ok(Eval::Blocked(DeclineEvidence::Conflict { conflicting_paths: conflicting_paths.clone() }));
            }
        }
        let first_judgement = tally.evaluations == 0;
        tally.evaluations += 1;
        let tip = composition.tip();
        let (base_units, cand_units) = (self.cones_at(base)?, self.cones_at(&tip)?);
        let overlay = Overlay { durable: self.store, session: &self.session };
        let mut reasons = judge(&base_units.cones, &cand_units.cones, &overlay)?;
        if first_judgement {
            tally.units_total = reasons.units.len();
            tally.units_transported = reasons.transported();
        }
        // A candidate run can reveal the need for a base run; two rounds settle it.
        for _ in 0..3 {
            let needs = reasons.needs();
            if needs.is_empty() {
                break;
            }
            for (side, units, commit) in [(Side::Candidate, &cand_units, &tip), (Side::Base, &base_units, base)] {
                let wanted: Vec<_> = needs.iter().filter(|need| need.side == side).collect();
                if wanted.is_empty() {
                    continue;
                }
                let jobs: Vec<(String, String)> = wanted
                    .iter()
                    .map(|need| (need.unit.clone(), units.paths.get(&need.unit).cloned().unwrap_or_else(|| need.unit.clone())))
                    .collect();
                let runs = self.runner.run_units(self.repo, &self.repo.tree_of(&commit.to_hex())?, &jobs)?;
                match side {
                    Side::Candidate => tally.candidate_units_run += runs.len(),
                    Side::Base => tally.base_units_run += runs.len(),
                }
                for (need, run) in wanted.iter().zip(&runs) {
                    let observation = Observation { unit_id: need.unit.clone(), cone_digest: need.cone, status: run.status() };
                    if run.is_durable() {
                        self.store.put(&observation)?;
                    } else {
                        if run.flaky {
                            tally.flaky_units.push(need.unit.clone());
                        }
                        self.session.put(&observation)?;
                    }
                }
            }
            reasons = judge(&base_units.cones, &cand_units.cones, &overlay)?;
        }
        Ok(match reasons.slot() {
            Slot::Supported => Eval::Admissible,
            Slot::Unsupported => Eval::Blocked(DeclineEvidence::NewRed { why_not: reasons.why_not() }),
            Slot::Undefined => return Err(TrainError::Stuck(reasons.needs().len())),
        })
    }

    /// Journal the sends, push the chain once under a lease, then read the
    /// forge and record what it actually holds.
    fn deliver(
        &self,
        base: &Oid,
        chain: &Composition,
        tally: &Tally,
        now: u64,
        report: &mut BatchReport,
    ) -> Result<Vec<(Candidate, CandidateOutcome)>, TrainError> {
        let (remote, target_ref) = (&self.config.remote, &self.config.target_ref);
        let tip = chain.tip();
        let bindings: Vec<Binding> =
            chain.links.iter().map(|link| self.binding(base, &link.candidate.tip, link.merge)).collect();

        // Persist every intent before the network call.
        for binding in &bindings {
            match self.journal.transition(binding, |d| d.start(now)) {
                Ok(_) => {}
                Err(JournalError::Delivery(DeliveryError::OutcomeUnknown)) => {
                    // An earlier send of this exact binding never learned its
                    // outcome. Read the forge for it, then start again.
                    let head = self.forge_head()?;
                    if self.repo.is_ancestor(&binding.lane_tip, &head)? {
                        let evidence = AncestryEvidence { target_ref: target_ref.clone(), remote_head: head, lane_tip: binding.lane_tip };
                        self.journal.transition(binding, |d| d.complete(evidence.clone()))?;
                    } else {
                        self.journal.transition(binding, |d| d.refused(now))?;
                        self.journal.transition(binding, |d| d.start(now))?;
                    }
                }
                Err(JournalError::Delivery(DeliveryError::Completed)) => {}
                Err(other) => return Err(other.into()),
            }
        }

        let mut push_options = Vec::new();
        if let Some((key_id, key)) = &self.signer {
            let claims = serde_json::json!({
                "base": base,
                "merged_head": tip,
                "lane_tips": chain.links.iter().map(|l| l.candidate.tip).collect::<Vec<_>>(),
                "batch_size": chain.links.len(),
                "evaluations": tally.evaluations,
                "candidate_units_run": tally.candidate_units_run,
                "base_units_run": tally.base_units_run,
                "units_transported": tally.units_transported,
                "units_total": tally.units_total,
            });
            let subject = custody::ref_update_subject(target_ref, base, &tip);
            let receipt = CustodyEnvelopeV2::seal(key, key_id, &self.config.seat, "land-receipt", subject, claims)?;
            push_options.push(format!("{}={}", custody::PUSH_OPTION, hex_encode(&receipt.to_wire()?)));
            report.receipt = Some(receipt);
        }

        report.pushed = Some(tip);
        // The push's exit code is kept for the record and decides nothing.
        report.push_exit = self.repo.push_with_lease(remote, &tip, target_ref, base, &push_options).unwrap_or(None);

        let unknown = |chain: &Composition| {
            chain.links.iter().map(|l| (l.candidate.clone(), CandidateOutcome::Unknown { merge: l.merge })).collect()
        };
        let Ok(Some(head)) = self.repo.ls_remote(remote, target_ref) else {
            return Ok(unknown(chain));
        };
        report.remote_head = Some(head);
        if !self.repo.has_object(&head)? && self.repo.fetch(remote, target_ref).is_err() {
            return Ok(unknown(chain));
        }

        let mut outcomes = Vec::with_capacity(chain.links.len());
        for (link, binding) in chain.links.iter().zip(&bindings) {
            let outcome = if self.repo.is_ancestor(&link.candidate.tip, &head)? {
                let evidence = AncestryEvidence { target_ref: target_ref.clone(), remote_head: head, lane_tip: link.candidate.tip };
                self.journal.transition(binding, |d| d.complete(evidence.clone()))?;
                CandidateOutcome::Landed { merge: link.merge, evidence }
            } else {
                let not_before = now + self.config.refusal_backoff_s;
                let stored = self.journal.transition(binding, |d| d.refused(not_before))?;
                if stored.delivery.sends >= self.config.max_refusals {
                    let evidence = DeclineEvidence::RefusalsExhausted { attempts: stored.delivery.sends };
                    self.journal.transition(binding, |d| d.declined(evidence.clone()))?;
                    CandidateOutcome::Declined { evidence }
                } else {
                    CandidateOutcome::Refused { not_before }
                }
            };
            outcomes.push((link.candidate.clone(), outcome));
        }
        Ok(outcomes)
    }
}

/// Every blocker of a declined candidate, for display.
pub fn blockers(evidence: &DeclineEvidence) -> &[Blocker] {
    match evidence {
        DeclineEvidence::NewRed { why_not } => why_not,
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cones::ManifestCones;
    use crate::runner::RunnerConfig;
    use landd_core::custody::TrustedKeys;
    use landd_core::delivery::DeliveryState;
    use landd_core::git::testkit::Sandbox;
    use std::time::Duration;

    const MANIFEST: &str = r#"{"units": {
        "a": {"path": "checks/a.sh", "inputs": ["checks/a.sh", "src/a.txt"]},
        "b": {"path": "checks/b.sh", "inputs": ["checks/b.sh", "src/b.txt"]},
        "d": {"path": "checks/d.sh", "inputs": ["checks/d.sh", "src/d.txt"]}}}"#;
    const MAIN: &str = "refs/heads/main";
    const NOW: u64 = 1_800_000_000;

    fn base_files() -> Vec<(&'static str, &'static str)> {
        vec![
            ("landd-units.json", MANIFEST),
            ("checks/a.sh", "grep -q '^ok' src/a.txt\n"),
            ("checks/b.sh", "grep -q '^ok' src/b.txt\n"),
            ("checks/d.sh", "grep -q '^ok' src/d.txt\n"),
            ("src/a.txt", "ok\n"),
            ("src/b.txt", "ok\n"),
            ("src/d.txt", "ok\n"),
            ("docs/readme.md", "docs\n"),
        ]
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        sandbox: Sandbox,
        repo: GitRepo,
        config: LandConfig,
        store: MemoryStore,
        journal: DeliveryJournal,
        source: ManifestCones,
    }

    impl Fixture {
        fn new(files: &[(&str, &str)]) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let sandbox = Sandbox::new(dir.path(), files);
            let config = LandConfig {
                cache_dir: dir.path().join("cache"),
                test_command: vec!["sh".into(), "{path}".into()],
                env_allow: vec!["PATH".into()],
                test_timeout_s: 20,
                max_reruns_on_flake: 0,
                ..LandConfig::default()
            };
            Self {
                repo: sandbox.repo(),
                journal: DeliveryJournal::open(dir.path().join("journal")),
                store: MemoryStore::new(),
                source: ManifestCones { manifest: "landd-units.json".into() },
                config,
                sandbox,
                _dir: dir,
            }
        }

        fn train(&self) -> Train<'_> {
            let runner = Runner::new(RunnerConfig::from_config(&self.config));
            Train::new(&self.repo, &self.config, &self.source, &self.store, &self.journal, runner)
        }

        fn lane(&self, name: &str, write: &[(&str, &str)]) -> Candidate {
            Candidate { lane: name.into(), tip: self.sandbox.lane(name, "main", write) }
        }

        fn forge(&self) -> Oid {
            self.sandbox.forge_head(MAIN)
        }

        fn state(&self, train: &Train<'_>, base: &Oid, tip: &Oid, merged: Oid) -> DeliveryState {
            self.journal.load(&train.binding(base, tip, merged)).unwrap().delivery.state
        }
    }

    /// The headline tooth: `[good1, bad2, conflict3, good4]`.
    #[test]
    fn tooth_batch_drops_the_conflict_isolates_the_culprit_and_lands_the_rest() {
        let fx = Fixture::new(&base_files());
        let base = fx.forge();
        let good1 = fx.lane("good1", &[("src/a.txt", "ok one\n")]);
        let bad2 = fx.lane("bad2", &[("src/b.txt", "broken\n")]);
        let conflict3 = fx.lane("conflict3", &[("src/a.txt", "ok three\n")]);
        let good4 = fx.lane("good4", &[("src/d.txt", "ok four\n")]);
        let batch = [good1.clone(), bad2.clone(), conflict3.clone(), good4.clone()];
        let train = fx.train();

        let report = train.land_batch(&batch, true, NOW).unwrap();

        // conflict3 never reached a test run.
        assert_eq!(
            report.outcome_of("conflict3"),
            Some(&CandidateOutcome::Declined {
                evidence: DeclineEvidence::Conflict { conflicting_paths: vec!["src/a.txt".into()] }
            })
        );
        // bad2 is named with its blocking unit and the input that moved.
        let Some(CandidateOutcome::Declined { evidence }) = report.outcome_of("bad2") else { panic!("bad2 must be declined") };
        assert_eq!(
            blockers(evidence),
            [Blocker { unit: "b".into(), new_items: vec!["b".into()], moved_paths: vec!["src/b.txt".into()] }]
        );
        // good1 and good4 landed as a chain of two-parent merges.
        let Some(CandidateOutcome::Landed { merge: m1, .. }) = report.outcome_of("good1") else { panic!("good1 must land") };
        let Some(CandidateOutcome::Landed { merge: m2, .. }) = report.outcome_of("good4") else { panic!("good4 must land") };
        assert_eq!(fx.forge(), *m2);
        assert_eq!(fx.repo.parents(m1).unwrap(), vec![base, good1.tip]);
        assert_eq!(fx.repo.parents(m2).unwrap(), vec![*m1, good4.tip]);
        assert_eq!(report.pushed, Some(*m2));
        assert_eq!(report.remote_head, Some(*m2));

        // Fast-forward only: the old tip is an ancestor of the new one, and
        // neither declined lane is on main.
        assert!(fx.repo.is_ancestor(&base, m2).unwrap());
        assert!(!fx.repo.is_ancestor(&bad2.tip, m2).unwrap());
        assert!(!fx.repo.is_ancestor(&conflict3.tip, m2).unwrap());
        let landed_tree = fx.sandbox.forge_git(&["ls-tree", "-r", "--name-only", MAIN]);
        assert!(landed_tree.contains("src/a.txt"));
        assert_eq!(fx.sandbox.forge_git(&["show", &format!("{MAIN}:src/b.txt")]), "ok");
        assert_eq!(fx.sandbox.forge_git(&["show", &format!("{MAIN}:src/a.txt")]), "ok one");

        // Three moved cones ran once on the batch tip, plus one base run to
        // tell a new red from an inherited one. The bisection ran nothing.
        assert_eq!((report.tally.candidate_units_run, report.tally.base_units_run), (3, 1));
        assert!(report.tally.evaluations >= 4);

        // The journal agrees with the forge.
        assert!(matches!(fx.state(&train, &base, &good1.tip, *m1), DeliveryState::Completed { .. }));
        assert!(matches!(fx.state(&train, &base, &good4.tip, *m2), DeliveryState::Completed { .. }));
        assert!(matches!(fx.state(&train, &base, &bad2.tip, Oid::zero_sha1()), DeliveryState::Declined { .. }));
        assert!(matches!(fx.state(&train, &base, &conflict3.tip, Oid::zero_sha1()), DeliveryState::Declined { .. }));
    }

    #[test]
    fn tooth_a_change_outside_every_cone_lands_with_zero_runs() {
        let fx = Fixture::new(&base_files());
        let docs = fx.lane("docs", &[("docs/readme.md", "new docs\n")]);
        let report = fx.train().land_batch(std::slice::from_ref(&docs), true, NOW).unwrap();
        assert!(matches!(report.outcome_of("docs"), Some(CandidateOutcome::Landed { .. })));
        assert_eq!((report.tally.candidate_units_run, report.tally.base_units_run), (0, 0));
        assert_eq!((report.tally.units_transported, report.tally.units_total), (3, 3));
        assert!(fx.store.is_empty());
        assert!(fx.repo.is_ancestor(&docs.tip, &fx.forge()).unwrap());
    }

    #[test]
    fn inherited_red_does_not_block_and_new_red_on_top_of_it_does() {
        let mut files = base_files();
        files.retain(|(path, _)| *path != "src/b.txt" && *path != "checks/b.sh");
        files.push(("src/b.txt", "broken on main\n"));
        files.push(("checks/b.sh", "grep -q '^ok' src/b.txt || { echo '{\"status\":\"fail\",\"items\":[\"old\"]}' > \"$LANDD_RESULT_FILE\"; exit 1; }\n"));
        let fx = Fixture::new(&files);
        // Touches b's cone; b stays exactly as red as it is on main.
        let still_red = fx.lane("still-red", &[("src/b.txt", "broken differently\n")]);
        let report = fx.train().land_batch(&[still_red], true, NOW).unwrap();
        assert!(matches!(report.outcome_of("still-red"), Some(CandidateOutcome::Landed { .. })));
        assert_eq!((report.tally.candidate_units_run, report.tally.base_units_run), (1, 1));

        // Adds a failing item main does not have.
        let script = "echo '{\"status\":\"fail\",\"items\":[\"old\",\"fresh\"]}' > \"$LANDD_RESULT_FILE\"; exit 1\n";
        let redder = fx.lane("redder", &[("checks/b.sh", script)]);
        let report = fx.train().land_batch(&[redder], true, NOW).unwrap();
        let Some(CandidateOutcome::Declined { evidence }) = report.outcome_of("redder") else { panic!("redder must be declined") };
        assert_eq!(blockers(evidence)[0].new_items, vec!["fresh"]);
        assert_eq!(blockers(evidence)[0].moved_paths, vec!["checks/b.sh"]);
    }

    #[test]
    fn dry_run_pushes_nothing_and_journals_nothing() {
        let fx = Fixture::new(&base_files());
        let base = fx.forge();
        let good = fx.lane("good", &[("src/a.txt", "ok one\n")]);
        let bad = fx.lane("bad", &[("src/b.txt", "broken\n")]);
        let train = fx.train();
        let report = train.land_batch(&[good.clone(), bad.clone()], false, NOW).unwrap();
        let Some(CandidateOutcome::WouldLand { merge }) = report.outcome_of("good") else { panic!("good would land") };
        assert!(matches!(report.outcome_of("bad"), Some(CandidateOutcome::Declined { .. })));
        assert_eq!(fx.forge(), base);
        assert_eq!(report.pushed, None);
        assert_eq!(fx.state(&train, &base, &good.tip, *merge), DeliveryState::Fresh);
        assert_eq!(fx.state(&train, &base, &bad.tip, Oid::zero_sha1()), DeliveryState::Fresh);
        assert!(!fx.journal.root().exists());
    }

    #[test]
    fn tooth_a_lost_race_is_refused_never_forced_and_lands_on_retry() {
        let fx = Fixture::new(&base_files());
        let stale_base = fx.forge();
        let rival = fx.lane("rival", &[("docs/readme.md", "rival\n")]);
        let mine = fx.lane("mine", &[("src/a.txt", "ok mine\n")]);
        let train = fx.train();
        train.land_batch(std::slice::from_ref(&rival), true, NOW).unwrap();
        let moved = fx.forge();
        assert_ne!(moved, stale_base);

        // Composed against the base read before the rival landed.
        let report = train.land_on(&stale_base, std::slice::from_ref(&mine), true, NOW).unwrap();
        assert_eq!(report.outcome_of("mine"), Some(&CandidateOutcome::Refused { not_before: NOW + fx.config.refusal_backoff_s }));
        assert_ne!(report.push_exit, Some(0));
        assert_eq!(fx.forge(), moved, "the forge must be untouched by a refused push");
        let merged = report.pushed.unwrap();
        assert_eq!(fx.state(&train, &stale_base, &mine.tip, merged), DeliveryState::Refused { attempts: 1, not_before: NOW + 5 });

        let retry = train.land_batch(std::slice::from_ref(&mine), true, NOW + 10).unwrap();
        assert!(matches!(retry.outcome_of("mine"), Some(CandidateOutcome::Landed { .. })));
        // The cone verdict from the refused attempt is reused: nothing reran.
        assert_eq!(retry.tally.candidate_units_run, 0);
        assert!(fx.repo.is_ancestor(&rival.tip, &fx.forge()).unwrap());
        assert!(fx.repo.is_ancestor(&moved, &fx.forge()).unwrap());
    }

    /// `confirmation_wins` end to end: the lease refuses the push, but the
    /// forge already holds the lane tip (a sibling carried it), so the
    /// delivery completes.
    #[test]
    fn tooth_forge_ancestry_completes_a_delivery_whose_push_was_refused() {
        let fx = Fixture::new(&base_files());
        let stale_base = fx.forge();
        let lane = fx.lane("lane", &[("src/a.txt", "ok lane\n")]);
        let train = fx.train();
        train.land_batch(std::slice::from_ref(&lane), true, NOW).unwrap();
        let carried = fx.forge();

        let report = train.land_on(&stale_base, std::slice::from_ref(&lane), true, NOW + 1).unwrap();
        assert_ne!(report.push_exit, Some(0));
        let Some(CandidateOutcome::Landed { evidence, .. }) = report.outcome_of("lane") else { panic!("ancestry must win") };
        assert_eq!(evidence.remote_head, carried);
        assert_eq!(fx.forge(), carried);

        // And a tip that is already on the base is settled at compose time.
        let again = train.land_batch(std::slice::from_ref(&lane), true, NOW + 2).unwrap();
        assert!(matches!(again.outcome_of("lane"), Some(CandidateOutcome::AlreadyLanded { .. })));
        assert_eq!(again.pushed, None);
    }

    #[test]
    fn timeouts_block_the_batch_but_are_never_recorded_as_verdicts() {
        let mut fx = Fixture::new(&base_files());
        fx.config.test_timeout_s = 1;
        let slow = fx.lane("slow", &[("checks/a.sh", "sleep 30\n")]);
        let report = fx.train().land_batch(&[slow], true, NOW).unwrap();
        let Some(CandidateOutcome::Declined { evidence }) = report.outcome_of("slow") else { panic!("slow must be declined") };
        assert_eq!(blockers(evidence)[0].new_items, vec![crate::runner::TIMEOUT_ITEM]);
        // Only the base's pass for `a` is durable; the timeout is not.
        assert_eq!(fx.store.len(), 1);
    }

    #[test]
    fn land_receipts_are_sealed_by_the_supervisor_and_verify() {
        let fx = Fixture::new(&base_files());
        fx.sandbox.forge_git(&["config", "receive.advertisePushOptions", "true"]);
        let base = fx.forge();
        let key = SigningKey::ed25519_from_seed([42; 32]);
        let mut trusted = TrustedKeys::new();
        trusted.insert("seat-1", key.trusted());
        let train = fx.train().with_signer("seat-1", key);
        let good = fx.lane("good", &[("src/a.txt", "ok one\n")]);
        let report = train.land_batch(&[good], true, NOW).unwrap();
        assert_eq!(report.landed(), 1);
        let receipt = report.receipt.expect("a receipt is sealed");
        receipt.verify(&trusted).unwrap();
        assert_eq!(receipt.header.subject, custody::ref_update_subject(MAIN, &base, &fx.forge()));
        assert_eq!(receipt.claims["batch_size"], 1);
        assert_eq!(receipt.claims["candidate_units_run"], 1);
    }

    #[test]
    fn a_missing_target_ref_is_an_error() {
        let fx = Fixture::new(&base_files());
        let mut config = fx.config.clone();
        config.target_ref = "refs/heads/absent".into();
        let runner = Runner::new(RunnerConfig { timeout: Duration::from_secs(1), ..RunnerConfig::from_config(&config) });
        let train = Train::new(&fx.repo, &config, &fx.source, &fx.store, &fx.journal, runner);
        assert!(matches!(train.land_batch(&[], true, NOW), Err(TrainError::NoTargetRef { .. })));
    }
}
