//! Judge a batch, isolate culprits, land the rest.

use crate::compose::{compose, Candidate, Committer, Composition, Dropped};
use crate::cones::{ConeSource, UnitCones};
use crate::runner::{Runner, RunnerError};
use landd_core::cone_receipt::{BoundReceipt, ConeReceipt, VerdictSource};
use landd_core::custody::{self, CustodyEnvelopeV2, CustodyError, SigningKey};
use landd_core::delivery::{
    AncestryEvidence, Binding, DeclineEvidence, DeliveryError, DeliveryJournal, DeliveryState, JournalError,
};
use landd_core::digest::hex_encode;
use landd_core::git::{canonical_repo_id, GitError, GitRepo, MergeOutcome};
use landd_core::reasons::{
    judge, Blocker, Input, JudgePolicy, MemoryStore, Observation, Side, Slot, Status, StoreError, VerdictStore,
};
use landd_core::{Digest32, Isolation, LandConfig, Oid, UnitView};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
    #[error("cones of the base: {0}")]
    Cones(String),
    #[error("{destination} has no {target_ref}")]
    NoTargetRef { destination: String, target_ref: String },
    #[error("receipts can only be signed when units run in the sandbox (isolation = \"bwrap\")")]
    UnsandboxedSigning,
    #[error("the land receipt is {0} bytes, more than one push option can carry")]
    ReceiptTooLarge(usize),
    #[error("verdicts for {0} units are still missing after running them")]
    Stuck(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CandidateOutcome {
    /// This train's merge of the lane is on the destination.
    Landed {
        merge: Oid,
        evidence: AncestryEvidence,
    },
    /// The lane tip is on the destination, but not through this train's
    /// merge: another push, or another lane of the batch, carried it.
    Carried {
        carrier: Oid,
        evidence: AncestryEvidence,
    },
    /// The lane tip was already reachable from the target ref: the lane
    /// has nothing to land.
    OnBase {
        evidence: AncestryEvidence,
    },
    /// The lane merges cleanly and changes nothing; nothing was pushed.
    NoChange,
    Declined {
        evidence: DeclineEvidence,
    },
    /// Admissible, but the destination did not take the push (the ref moved).
    Refused {
        not_before: u64,
    },
    /// Not judged on its own merits this time; submit it again.
    Deferred {
        reason: String,
    },
    /// Admissible; not pushed because this was a dry run.
    WouldLand {
        merge: Oid,
    },
    /// The push was sent and the destination could not be read afterwards.
    Unknown {
        merge: Oid,
    },
}

impl CandidateOutcome {
    /// When to try again, for the outcomes that say "not this time".
    pub fn retry_at(&self) -> Option<u64> {
        match self {
            Self::Refused { not_before } => Some(*not_before),
            Self::Deferred { .. } => Some(0),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Tally {
    pub external_receipts: std::collections::BTreeMap<String, VerdictSource>,
    /// Compositions judged, including those of the bisection.
    pub evaluations: usize,
    pub candidate_units_run: usize,
    pub base_units_run: usize,
    /// Units of the first judgement whose cone did not move (zero runs).
    pub units_transported: usize,
    pub units_total: usize,
    pub flaky_units: Vec<String>,
    /// A run disagreed with a verdict already recorded for the same cone;
    /// the recorded verdict stood.
    pub verdict_conflicts: Vec<String>,
    /// Units the landed chain removes (only when the policy allows removal).
    pub units_removed: Vec<String>,
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
    Admissible { removed: Vec<String> },
    Blocked(DeclineEvidence),
}

pub struct Train<'a> {
    pub repo: &'a GitRepo,
    pub config: &'a LandConfig,
    pub cones: &'a dyn ConeSource,
    pub store: &'a dyn VerdictStore,
    pub journal: &'a DeliveryJournal,
    pub runner: Runner,
    /// Where pushes go, and where the target ref is read from afterwards.
    pub destination: String,
    /// The destination's identity in delivery bindings and receipts.
    pub repo_id: String,
    /// `(key_id, key)` for sealing land receipts.
    signer: Option<(String, SigningKey)>,
    pub receipts: Vec<BoundReceipt>,
    session: MemoryStore,
    memo: Mutex<HashMap<(Oid, Oid), Arc<UnitCones>>>,
}

impl<'a> Train<'a> {
    pub fn new(
        repo: &'a GitRepo,
        config: &'a LandConfig,
        cones: &'a dyn ConeSource,
        store: &'a dyn VerdictStore,
        journal: &'a DeliveryJournal,
        runner: Runner,
    ) -> Result<Self, TrainError> {
        let destination = repo.push_destination(&config.remote)?;
        let repo_id = config.repo_id.clone().unwrap_or_else(|| canonical_repo_id(&destination));
        Ok(Self {
            repo,
            config,
            cones,
            store,
            journal,
            runner,
            destination,
            repo_id,
            signer: None,
            receipts: Vec::new(),
            session: MemoryStore::new(),
            memo: Mutex::new(HashMap::new()),
        })
    }

    /// Seal land receipts with `key`. Refused unless units run in the
    /// sandbox: a receipt says the checks ran where they could not reach
    /// this key or the verdict store.
    pub fn with_signer(mut self, key_id: impl Into<String>, key: SigningKey) -> Result<Self, TrainError> {
        if self.runner.isolation() != Isolation::Bwrap {
            return Err(TrainError::UnsandboxedSigning);
        }
        self.signer = Some((key_id.into(), key));
        Ok(self)
    }

    fn cones_at(&self, commit: &Oid, base: &Oid) -> Result<Arc<UnitCones>, String> {
        if let Some(hit) = self.memo.lock().expect("cone memo").get(&(*commit, *base)) {
            return Ok(hit.clone());
        }
        let mut cones = self.cones.cones(self.repo, commit, base, &self.runner.profile().digest)?;
        // A whole-tree process may observe every tracked path, even when the
        // declared or inferred cone is narrower. Bind its verdict to the view
        // it actually receives; changing only the profile's view label is not
        // enough to invalidate a verdict when an undeclared file changes.
        if self.runner.unit_view() == UnitView::Tree && !cones.cones.is_empty() {
            let inputs: std::collections::BTreeMap<_, _> = self
                .repo
                .ls_tree(&commit.to_hex(), false)
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|entry| (entry.path, Input { mode: entry.mode, oid: entry.oid }))
                .collect();
            for cone in cones.cones.values_mut() {
                cone.inputs = inputs.clone();
                cone.tainted = true;
            }
        }
        let cones = Arc::new(cones);
        self.memo.lock().expect("cone memo").insert((*commit, *base), cones.clone());
        Ok(cones)
    }

    fn receipt_ids(&self, unit: &str, units: &UnitCones) -> (Digest32, Digest32) {
        let profile = &self.runner.profile().description;
        let gate = serde_json::json!([unit, units.paths.get(unit), profile["argv"], profile["program"]]);
        let hash = |v| Digest32::from_bytes(Sha256::digest(landd_core::canonical_json(v).expect("JSON value")).into());
        (hash(&gate), hash(profile))
    }

    /// Execute the candidate gate on its declared view and export its exact inputs.
    pub fn judge_cone(&self, tip: Oid, base: Oid, unit: &str) -> Result<ConeReceipt, TrainError> {
        let units = self.cones_at(&tip, &base).map_err(TrainError::Cones)?;
        let cone = units.cones.get(unit).ok_or_else(|| TrainError::Cones(format!("unknown unit {unit}")))?;
        let tree_oid = self.repo.tree_of(&tip.to_hex())?;
        let run = self.runner.run_units(self.repo, &tree_oid, &[units.job(unit)])?.remove(0);
        let (gate_sha256, toolchain_sha256) = self.receipt_ids(unit, &units);
        Ok(ConeReceipt {
            judge_name: unit.to_owned(),
            gate_sha256,
            toolchain_sha256,
            tree_oid,
            all_passed: run.is_durable() && run.status() == Status::Pass,
            clean_working_tree: true,
            cone_blobs: cone.inputs.iter().map(|(p, i)| (p.clone(), i.oid)).collect(),
        })
    }

    pub fn verify_cone(&self, r: ConeReceipt, tip: Oid, base: Oid) -> Result<Option<VerdictSource>, TrainError> {
        let Some(bound) = r.bind(self.repo)? else { return Ok(None) };
        let units = self.cones_at(&tip, &base).map_err(TrainError::Cones)?;
        let Some(cone) = units.cones.get(bound.unit()) else { return Ok(None) };
        let (gate, tools) = self.receipt_ids(bound.unit(), &units);
        Ok(bound.transport(gate, tools, &cone.inputs))
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

    fn evidence(&self, head: &Oid, lane_tip: &Oid) -> AncestryEvidence {
        AncestryEvidence {
            repo: self.repo_id.clone(),
            target_ref: self.config.target_ref.clone(),
            remote_head: *head,
            lane_tip: *lane_tip,
        }
    }

    /// The destination's current target ref, with its objects present locally.
    pub fn forge_head(&self) -> Result<Oid, TrainError> {
        let head = self.repo.ls_remote(&self.destination, &self.config.target_ref)?.ok_or_else(|| TrainError::NoTargetRef {
            destination: self.destination.clone(),
            target_ref: self.config.target_ref.clone(),
        })?;
        if !self.repo.has_object(&head)? {
            self.repo.fetch(&self.destination, &self.config.target_ref)?;
        }
        Ok(head)
    }

    /// Land `candidates` onto the destination's current target ref. With
    /// `apply` false nothing is pushed and nothing is journaled. `now` is
    /// seconds since the epoch; it dates journal backoffs only (merge
    /// commits are dated by their parents).
    pub fn land_batch(&self, candidates: &[Candidate], apply: bool, now: u64) -> Result<BatchReport, TrainError> {
        let base = self.forge_head()?;
        self.land_on(&base, candidates, apply, now)
    }

    /// Before composing: if an earlier send of this lane tip never learned
    /// its outcome, read the destination and record what it holds. Returns
    /// an outcome when the lane must sit this batch out.
    fn settle(&self, candidate: &Candidate, base: &Oid, now: u64) -> Result<Option<CandidateOutcome>, TrainError> {
        let Some(stored) = self.journal.latest_for_tip(&self.repo_id, &self.config.target_ref, &candidate.tip)? else {
            return Ok(None);
        };
        let binding = stored.delivery.binding.clone();
        // A caller may hold a stale base. Destination completion dominates
        // every local state, including a refusal limit, and must leave the
        // batch before re-composition can misreport an already delivered lane.
        let head = self.forge_head()?;
        if self.repo.is_ancestor(&candidate.tip, &head)? {
            let evidence = self.evidence(&head, &candidate.tip);
            self.journal.transition(&binding, |d| d.complete(evidence.clone()))?;
            if self.repo.is_ancestor(&candidate.tip, base)? {
                return Ok(Some(CandidateOutcome::OnBase { evidence }));
            }
            // Preserve the landed/carried distinction without running checks
            // or attempting another push. A singleton composition identifies
            // this train's deterministic merge; otherwise the destination is
            // the observed carrier, including if the stale base now conflicts.
            let who = Committer { name: self.config.committer_name.clone(), email: self.config.committer_email.clone() };
            let own_merge = compose(self.repo, base, std::slice::from_ref(candidate), &who)
                .ok()
                .and_then(|chain| chain.links.first().map(|link| link.merge));
            if let Some(merge) = own_merge {
                if self.repo.is_ancestor(&merge, &head)? {
                    return Ok(Some(CandidateOutcome::Landed { merge, evidence }));
                }
            }
            return Ok(Some(CandidateOutcome::Carried { carrier: head, evidence }));
        }
        match stored.delivery.state {
            DeliveryState::Unknown => {
                let settled = self.journal.transition(&binding, |d| d.refused(now))?;
                if settled.delivery.sends >= self.config.max_refusals {
                    let evidence = DeclineEvidence::RefusalsExhausted { attempts: settled.delivery.sends };
                    self.journal.transition(&binding, |d| d.declined(evidence.clone()))?;
                    if binding.expected_old == *base {
                        return Ok(Some(CandidateOutcome::Declined { evidence }));
                    }
                }
                Ok(None)
            }
            // Still backing off from a refusal of this very composition.
            DeliveryState::Refused { not_before, .. } if now < not_before && binding.expected_old == *base => {
                Ok(Some(CandidateOutcome::Refused { not_before }))
            }
            DeliveryState::Declined { evidence: evidence @ DeclineEvidence::RefusalsExhausted { .. } }
                if binding.expected_old == *base =>
            {
                Ok(Some(CandidateOutcome::Declined { evidence }))
            }
            _ => Ok(None),
        }
    }

    /// As [`Train::land_batch`], against a base the caller read earlier. If
    /// the destination has moved since, the lease refuses the push.
    pub fn land_on(&self, base: &Oid, candidates: &[Candidate], apply: bool, now: u64) -> Result<BatchReport, TrainError> {
        let started = Instant::now();
        let who = Committer { name: self.config.committer_name.clone(), email: self.config.committer_email.clone() };
        let mut tally = Tally::default();
        let mut outcomes: Vec<Option<CandidateOutcome>> = vec![None; candidates.len()];

        let mut active: Vec<usize> = Vec::new();
        for (index, candidate) in candidates.iter().enumerate() {
            match if apply { self.settle(candidate, base, now)? } else { None } {
                Some(outcome) => outcomes[index] = Some(outcome),
                None => active.push(index),
            }
        }
        let list: Vec<Candidate> = active.iter().map(|i| candidates[*i].clone()).collect();

        // Compose once. Whatever cannot join the chain leaves the batch here.
        let first = compose(self.repo, base, &list, &who)?;
        let compose_ms = started.elapsed().as_secs_f64() * 1000.0;
        // Candidates to look at again once it is known who lands.
        let mut riders: Vec<(usize, usize)> = Vec::new();
        let mut second_look: Vec<usize> = Vec::new();
        for (at, dropped) in &first.dropped {
            let (index, candidate) = (active[*at], &list[*at]);
            match dropped {
                Dropped::OnBase => {
                    let evidence = self.evidence(base, &candidate.tip);
                    if apply {
                        let binding = self.binding(base, &candidate.tip, Oid::zero_sha1());
                        self.journal.transition(&binding, |d| d.complete(evidence.clone()))?;
                    }
                    outcomes[index] = Some(CandidateOutcome::OnBase { evidence });
                }
                Dropped::NoChange => outcomes[index] = Some(CandidateOutcome::NoChange),
                Dropped::Unmergeable { detail } => {
                    let evidence = DeclineEvidence::Unmergeable { detail: detail.clone() };
                    self.decline(apply, base, candidate, &evidence)?;
                    outcomes[index] = Some(CandidateOutcome::Declined { evidence });
                }
                Dropped::Subsumed { by } => riders.push((*at, *by)),
                Dropped::Conflict { conflicting_paths } => {
                    // A conflict with the base is the lane's own; a conflict
                    // with a peer depends on whether that peer lands.
                    match self.repo.merge_tree(base, &candidate.tip) {
                        Ok(MergeOutcome::Clean { .. }) => second_look.push(*at),
                        _ => {
                            let evidence = DeclineEvidence::Conflict { conflicting_paths: conflicting_paths.clone() };
                            self.decline(apply, base, candidate, &evidence)?;
                            outcomes[index] = Some(CandidateOutcome::Declined { evidence });
                        }
                    }
                }
            }
        }

        // Judge; on a new red, split to find the culprits.
        let survivors: Vec<Candidate> = first.links.iter().map(|link| link.candidate.clone()).collect();
        let mut good: Vec<Candidate> = Vec::new();
        let mut culprits: Vec<(Candidate, DeclineEvidence)> = Vec::new();
        self.isolate(base, &mut good, &survivors, &who, &mut tally, &mut culprits)?;

        // A lane that only conflicted with a culprit, or was contained in
        // one, is judged against the chain that actually stands.
        let mut waiting: Vec<(usize, String)> = Vec::new();
        riders.retain(|(at, by)| {
            let rides = good.contains(&list[*by]) && *by != *at;
            if !rides && !good.contains(&list[*at]) {
                second_look.push(*at);
            }
            rides
        });
        second_look.sort_unstable();
        second_look.dedup();
        for at in second_look {
            let candidate = &list[at];
            let trial: Vec<Candidate> = good.iter().cloned().chain([candidate.clone()]).collect();
            let composed = compose(self.repo, base, &trial, &who)?;
            match composed.dropped.iter().find(|(position, _)| *position == trial.len() - 1).map(|(_, why)| why) {
                None => self.isolate(base, &mut good, std::slice::from_ref(candidate), &who, &mut tally, &mut culprits)?,
                Some(Dropped::Conflict { conflicting_paths }) => {
                    waiting.push((at, format!("conflicts with a lane of this batch in {}", conflicting_paths.join(", "))))
                }
                Some(Dropped::Subsumed { by }) => riders.push((at, list.iter().position(|c| *c == trial[*by]).unwrap_or(at))),
                Some(Dropped::NoChange) => outcomes[active[at]] = Some(CandidateOutcome::NoChange),
                Some(Dropped::OnBase) => {}
                Some(Dropped::Unmergeable { detail }) => {
                    let evidence = DeclineEvidence::Unmergeable { detail: detail.clone() };
                    self.decline(apply, base, candidate, &evidence)?;
                    outcomes[active[at]] = Some(CandidateOutcome::Declined { evidence });
                }
            }
        }
        for (candidate, evidence) in culprits {
            self.decline(apply, base, &candidate, &evidence)?;
            let at = list.iter().position(|c| *c == candidate).expect("a batch member");
            outcomes[active[at]] = Some(CandidateOutcome::Declined { evidence });
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
        // Same inputs, same committer: this is the chain that was judged.
        let chain = compose(self.repo, base, &good, &who)?;
        let merge_of = |candidate: &Candidate| chain.links.iter().find(|l| l.candidate == *candidate).map(|l| l.merge);
        let position = |candidate: &Candidate| active[list.iter().position(|c| c == candidate).expect("a batch member")];
        if !apply {
            for link in &chain.links {
                outcomes[position(&link.candidate)] = Some(CandidateOutcome::WouldLand { merge: link.merge });
            }
            for (at, by) in &riders {
                if let Some(merge) = merge_of(&list[*by]) {
                    outcomes[active[*at]] = Some(CandidateOutcome::WouldLand { merge });
                }
            }
            for (at, reason) in waiting {
                outcomes[active[at]] = Some(CandidateOutcome::Deferred { reason });
            }
        } else {
            let mut landed_tip = false;
            if !chain.links.is_empty() {
                for (candidate, outcome) in self.deliver(base, &chain, &tally, now, &mut report)? {
                    outcomes[position(&candidate)] = Some(outcome);
                }
                let tip = chain.tip();
                landed_tip = report.remote_head.is_some_and(|head| self.repo.is_ancestor(&tip, &head).unwrap_or(false));
            }
            // A contained lane lands exactly when the destination holds it.
            for (at, by) in riders {
                let candidate = &list[at];
                let held = report.remote_head.filter(|head| self.repo.is_ancestor(&candidate.tip, head).unwrap_or(false));
                outcomes[active[at]] = Some(match (held, merge_of(&list[by])) {
                    (Some(head), carrier) => {
                        let evidence = self.evidence(&head, &candidate.tip);
                        let binding = self.binding(base, &candidate.tip, Oid::zero_sha1());
                        self.journal.transition(&binding, |d| d.complete(evidence.clone()))?;
                        CandidateOutcome::Carried { carrier: carrier.unwrap_or(head), evidence }
                    }
                    (None, _) => {
                        CandidateOutcome::Deferred { reason: format!("contained in {}, which did not land", list[by].lane) }
                    }
                });
            }
            for (at, reason) in waiting {
                let candidate = &list[at];
                outcomes[active[at]] = Some(if landed_tip {
                    // What it conflicts with is on the destination now.
                    let conflicting_paths = match self.repo.merge_tree(&chain.tip(), &candidate.tip) {
                        Ok(MergeOutcome::Conflict { conflicting_paths }) => conflicting_paths,
                        _ => Vec::new(),
                    };
                    let evidence = DeclineEvidence::Conflict { conflicting_paths };
                    self.decline(true, base, candidate, &evidence)?;
                    CandidateOutcome::Declined { evidence }
                } else {
                    CandidateOutcome::Deferred { reason }
                });
            }
        }
        report.outcomes = candidates
            .iter()
            .cloned()
            .zip(outcomes)
            .map(|(candidate, outcome)| {
                let outcome = outcome.unwrap_or(CandidateOutcome::Deferred { reason: "not reached in this batch".into() });
                (candidate, outcome)
            })
            .collect();
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
            // Declining twice, or declining what the destination already holds, changes nothing.
            Ok(_) | Err(JournalError::Delivery(DeliveryError::Declined(_) | DeliveryError::Completed)) => Ok(()),
            Err(other) => Err(other.into()),
        }
    }

    /// Extend `good` with every member of `list` that keeps the chain
    /// admissible, in order; the rest go to `culprits`. Each split reuses the
    /// verdicts already recorded, so only cones nobody has judged run again.
    /// When two lanes are only red together, the later one is the culprit.
    fn isolate(
        &self,
        base: &Oid,
        good: &mut Vec<Candidate>,
        list: &[Candidate],
        who: &Committer,
        tally: &mut Tally,
        culprits: &mut Vec<(Candidate, DeclineEvidence)>,
    ) -> Result<(), TrainError> {
        if list.is_empty() {
            return Ok(());
        }
        let trial: Vec<Candidate> = good.iter().chain(list).cloned().collect();
        match self.evaluate(base, &trial, who, tally)? {
            Eval::Admissible { removed } => {
                good.extend_from_slice(list);
                tally.units_removed = removed;
            }
            Eval::Blocked(evidence) if list.len() == 1 => culprits.push((list[0].clone(), evidence)),
            Eval::Blocked(_) => {
                let (left, right) = list.split_at(list.len() / 2);
                self.isolate(base, good, left, who, tally, culprits)?;
                self.isolate(base, good, right, who, tally, culprits)?;
            }
        }
        Ok(())
    }

    fn evaluate(&self, base: &Oid, list: &[Candidate], who: &Committer, tally: &mut Tally) -> Result<Eval, TrainError> {
        let composition = compose(self.repo, base, list, who)?;
        // Without an earlier member of the batch, a later one may no longer merge.
        for (_, dropped) in &composition.dropped {
            match dropped {
                Dropped::Conflict { conflicting_paths } => {
                    return Ok(Eval::Blocked(DeclineEvidence::Conflict { conflicting_paths: conflicting_paths.clone() }))
                }
                Dropped::Unmergeable { detail } => {
                    return Ok(Eval::Blocked(DeclineEvidence::Unmergeable { detail: detail.clone() }))
                }
                _ => {}
            }
        }
        let first_judgement = tally.evaluations == 0;
        tally.evaluations += 1;
        let tip = composition.tip();
        // The base's cones are the operator's to get right; a candidate
        // whose cones cannot be computed is that candidate's problem.
        let base_units = self.cones_at(base, base).map_err(TrainError::Cones)?;
        let cand_units = match self.cones_at(&tip, base) {
            Ok(units) => units,
            Err(detail) => {
                return Ok(Eval::Blocked(DeclineEvidence::Other { detail: format!("cones of the candidate: {detail}") }))
            }
        };
        let overlay = Overlay { durable: self.store, session: &self.session };
        for receipt in &self.receipts {
            let unit = receipt.unit();
            let Some(cone) = cand_units.cones.get(unit) else { continue };
            let digest = cone.digest();
            if overlay.get(unit, &digest)?.is_some() {
                continue;
            }
            let (gate, tools) = self.receipt_ids(unit, &cand_units);
            if let Some(source) = receipt.transport(gate, tools, &cone.inputs) {
                self.session.put(&Observation { unit_id: unit.to_owned(), cone_digest: digest, status: Status::Pass })?;
                tally.external_receipts.insert(unit.to_owned(), source);
            }
        }
        let policy =
            JudgePolicy { allow_removed: self.config.allow_unit_removal, inherit_coarse: self.config.inherit_coarse_failures };
        let mut reasons = judge(&base_units.cones, &cand_units.cones, &overlay, &policy)?;
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
                let jobs: Vec<_> = wanted.iter().map(|need| units.job(&need.unit)).collect();
                let runs = self.runner.run_units(self.repo, &self.repo.tree_of(&commit.to_hex())?, &jobs)?;
                match side {
                    Side::Candidate => tally.candidate_units_run += runs.len(),
                    Side::Base => tally.base_units_run += runs.len(),
                }
                for (need, run) in wanted.iter().zip(&runs) {
                    let observation = Observation { unit_id: need.unit.clone(), cone_digest: need.cone, status: run.status() };
                    if !run.is_durable() {
                        if run.flaky {
                            tally.flaky_units.push(need.unit.clone());
                        }
                        self.session.put(&observation)?;
                        continue;
                    }
                    match self.store.put(&observation) {
                        Ok(()) => {}
                        // Someone recorded another verdict for this exact
                        // cone first. The first verdict stands; say so.
                        Err(StoreError::Conflict { unit, .. }) => tally.verdict_conflicts.push(unit),
                        Err(other) => return Err(other.into()),
                    }
                }
            }
            reasons = judge(&base_units.cones, &cand_units.cones, &overlay, &policy)?;
        }
        Ok(match reasons.slot() {
            Slot::Supported => {
                let removed = base_units.cones.keys().filter(|unit| !cand_units.cones.contains_key(*unit)).cloned().collect();
                Eval::Admissible { removed }
            }
            Slot::Unsupported => Eval::Blocked(DeclineEvidence::NewRed { why_not: reasons.why_not() }),
            Slot::Undefined => return Err(TrainError::Stuck(reasons.needs().len())),
        })
    }

    /// Journal the sends, push the chain once under a lease, then read the
    /// destination and record what it actually holds.
    fn deliver(
        &self,
        base: &Oid,
        chain: &Composition,
        tally: &Tally,
        now: u64,
        report: &mut BatchReport,
    ) -> Result<Vec<(Candidate, CandidateOutcome)>, TrainError> {
        let target_ref = &self.config.target_ref;
        let tip = chain.tip();
        let bindings: Vec<Binding> = chain.links.iter().map(|link| self.binding(base, &link.candidate.tip, link.merge)).collect();

        // Every binding must be able to start before any of them does: a
        // send that is half journaled is worse than one not made.
        let mut held: Vec<Option<CandidateOutcome>> = Vec::with_capacity(bindings.len());
        for binding in &bindings {
            let stored = self.journal.load(binding)?;
            held.push(match stored.delivery.start(now) {
                Ok(_) | Err(DeliveryError::Completed) => None,
                Err(DeliveryError::NotBefore { not_before, .. }) => Some(CandidateOutcome::Refused { not_before }),
                Err(DeliveryError::OutcomeUnknown) => {
                    Some(CandidateOutcome::Deferred { reason: "an earlier send of this merge is still unread".into() })
                }
                Err(_) => match stored.delivery.state {
                    DeliveryState::Declined { evidence } => Some(CandidateOutcome::Declined { evidence }),
                    _ => Some(CandidateOutcome::Deferred { reason: "its delivery record cannot start".into() }),
                },
            });
        }
        if held.iter().any(Option::is_some) {
            return Ok(chain
                .links
                .iter()
                .zip(held)
                .map(|(link, outcome)| {
                    let peer = CandidateOutcome::Deferred { reason: "a lane of this batch could not be sent".into() };
                    (link.candidate.clone(), outcome.unwrap_or(peer))
                })
                .collect());
        }

        let mut push_options = Vec::new();
        if let Some((key_id, key)) = &self.signer {
            let claims = serde_json::json!({
                "repo": self.repo_id,
                "base": base,
                "merged_head": tip,
                "lane_tips": chain.links.iter().map(|l| l.candidate.tip).collect::<Vec<_>>(),
                "batch_size": chain.links.len(),
                "evaluations": tally.evaluations,
                "candidate_units_run": tally.candidate_units_run,
                "base_units_run": tally.base_units_run,
                "units_transported": tally.units_transported,
                "units_total": tally.units_total,
                "units_removed": tally.units_removed,
                "runner_profile": self.runner.profile().digest,
                "isolation": self.runner.profile().description["sandbox"],
                "unit_view": self.runner.profile().description["unit_view"],
            });
            let subject = custody::ref_update_subject(&self.repo_id, target_ref, base, &tip);
            let receipt = CustodyEnvelopeV2::seal(key, key_id, &self.config.seat, "land-receipt", subject, claims)?;
            let option = format!("{}={}", custody::PUSH_OPTION, hex_encode(&receipt.to_wire()?));
            if option.len() > custody::MAX_PUSH_OPTION_BYTES {
                return Err(TrainError::ReceiptTooLarge(option.len()));
            }
            push_options.push(option);
            report.receipt = Some(receipt);
        }

        // Persist every intent, and how to find it again, before the network call.
        for binding in &bindings {
            self.journal.note_tip(binding)?;
            match self.journal.transition(binding, |d| d.start(now)) {
                Ok(_) | Err(JournalError::Delivery(DeliveryError::Completed)) => {}
                Err(other) => return Err(other.into()),
            }
        }

        report.pushed = Some(tip);
        let env: Vec<(&str, &str)> = self.config.push_env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        // The push's exit code is kept for the record and decides nothing; a
        // push that timed out or could not start is simply unread.
        report.push_exit = self
            .repo
            .push_with_lease(&self.destination, &tip, target_ref, base, &push_options, self.config.push_no_verify, &env)
            .unwrap_or(None);

        let unknown = |chain: &Composition| {
            chain.links.iter().map(|l| (l.candidate.clone(), CandidateOutcome::Unknown { merge: l.merge })).collect()
        };
        let Ok(Some(head)) = self.repo.ls_remote(&self.destination, target_ref) else {
            return Ok(unknown(chain));
        };
        report.remote_head = Some(head);
        if !self.repo.has_object(&head).unwrap_or(false) && self.repo.fetch(&self.destination, target_ref).is_err() {
            return Ok(unknown(chain));
        }

        let mut outcomes = Vec::with_capacity(chain.links.len());
        for (link, binding) in chain.links.iter().zip(&bindings) {
            let on_forge = (self.repo.is_ancestor(&link.merge, &head), self.repo.is_ancestor(&link.candidate.tip, &head));
            let outcome = match on_forge {
                (Ok(ours), Ok(true)) => {
                    let evidence = self.evidence(&head, &link.candidate.tip);
                    self.journal.transition(binding, |d| d.complete(evidence.clone()))?;
                    match ours {
                        true => CandidateOutcome::Landed { merge: link.merge, evidence },
                        // On the destination, but not by this push.
                        false => CandidateOutcome::Carried { carrier: head, evidence },
                    }
                }
                (Ok(_), Ok(false)) => {
                    let not_before = now + self.config.refusal_backoff_s;
                    let stored = self.journal.transition(binding, |d| d.refused(not_before))?;
                    if stored.delivery.sends >= self.config.max_refusals {
                        let evidence = DeclineEvidence::RefusalsExhausted { attempts: stored.delivery.sends };
                        self.journal.transition(binding, |d| d.declined(evidence.clone()))?;
                        CandidateOutcome::Declined { evidence }
                    } else {
                        CandidateOutcome::Refused { not_before }
                    }
                }
                // The destination answered but ancestry could not be computed here: still unread.
                _ => CandidateOutcome::Unknown { merge: link.merge },
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
    use crate::cones::{ManifestCones, PythonCones};
    use crate::runner::RunnerConfig;
    use landd_core::custody::{Grant, TrustedKeys};
    use landd_core::git::testkit::Sandbox;
    use landd_core::reasons::{CRASH_ITEM, REMOVED_ITEM, TIMEOUT_ITEM};
    use landd_core::ConeSourceKind;

    const MANIFEST: &str = r#"{"units": {
        "a": {"path": "checks/a.sh", "inputs": ["src/a.txt"]},
        "b": {"path": "checks/b.sh", "inputs": ["src/b.txt"]},
        "d": {"path": "checks/d.sh", "inputs": ["src/d.txt"]}}}"#;
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
        dir: tempfile::TempDir,
        sandbox: Sandbox,
        repo: GitRepo,
        config: LandConfig,
        store: MemoryStore,
        journal: DeliveryJournal,
        source: Box<dyn ConeSource>,
    }

    impl Fixture {
        fn new(files: &[(&str, &str)]) -> Self {
            let dir = landd_core::git::testkit::private_tempdir().unwrap();
            let sandbox = Sandbox::new(dir.path(), files);
            let config = LandConfig {
                cache_dir: Some(dir.path().join("state")),
                test_command: vec!["sh".into(), "{path}".into()],
                env_allow: vec!["PATH".into()],
                test_timeout_s: 20,
                max_reruns_on_flake: 0,
                cone_source: ConeSourceKind::Manifest,
                ..LandConfig::default()
            };
            Self {
                repo: sandbox.repo(),
                journal: DeliveryJournal::open(dir.path().join("journal")),
                store: MemoryStore::new(),
                source: Box::new(ManifestCones { manifest: "landd-units.json".into() }),
                config,
                sandbox,
                dir,
            }
        }

        fn runner(&self) -> Runner {
            let mut config = RunnerConfig::from_config(&self.config);
            config.scratch = self.dir.path().join("runs");
            Runner::new(config).unwrap()
        }

        fn train(&self) -> Train<'_> {
            Train::new(&self.repo, &self.config, self.source.as_ref(), &self.store, &self.journal, self.runner()).unwrap()
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

    fn declined(report: &BatchReport, lane: &str) -> DeclineEvidence {
        match report.outcome_of(lane) {
            Some(CandidateOutcome::Declined { evidence }) => evidence.clone(),
            other => panic!("{lane} must be declined, got {other:?}"),
        }
    }

    fn landed(report: &BatchReport, lane: &str) -> Oid {
        match report.outcome_of(lane) {
            Some(CandidateOutcome::Landed { merge, .. }) => *merge,
            other => panic!("{lane} must land, got {other:?}"),
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

        // conflict3 conflicts with good1, which landed.
        assert_eq!(declined(&report, "conflict3"), DeclineEvidence::Conflict { conflicting_paths: vec!["src/a.txt".into()] });
        // bad2 is named with its blocking unit and the input that moved.
        assert_eq!(
            blockers(&declined(&report, "bad2")),
            [Blocker { unit: "b".into(), new_items: vec![CRASH_ITEM.into()], moved_paths: vec!["src/b.txt".into()] }]
        );
        // good1 and good4 landed as a chain of two-parent merges.
        let (m1, m2) = (landed(&report, "good1"), landed(&report, "good4"));
        assert_eq!(fx.forge(), m2);
        assert_eq!(fx.repo.parents(&m1).unwrap(), vec![base, good1.tip]);
        assert_eq!(fx.repo.parents(&m2).unwrap(), vec![m1, good4.tip]);
        assert_eq!((report.pushed, report.remote_head), (Some(m2), Some(m2)));

        // Fast-forward only: the old tip is an ancestor of the new one, and
        // neither declined lane is on main.
        assert!(fx.repo.is_ancestor(&base, &m2).unwrap());
        assert!(!fx.repo.is_ancestor(&bad2.tip, &m2).unwrap());
        assert!(!fx.repo.is_ancestor(&conflict3.tip, &m2).unwrap());
        assert_eq!(fx.sandbox.forge_git(&["show", &format!("{MAIN}:src/b.txt")]), "ok");
        assert_eq!(fx.sandbox.forge_git(&["show", &format!("{MAIN}:src/a.txt")]), "ok one");

        // Three moved cones ran once on the batch tip, plus one base run to
        // tell a new red from an inherited one. The bisection ran nothing.
        assert_eq!((report.tally.candidate_units_run, report.tally.base_units_run), (3, 1));
        assert!(report.tally.evaluations >= 4);

        // The journal agrees with the destination.
        assert!(matches!(fx.state(&train, &base, &good1.tip, m1), DeliveryState::Completed { .. }));
        assert!(matches!(fx.state(&train, &base, &good4.tip, m2), DeliveryState::Completed { .. }));
        assert!(matches!(fx.state(&train, &base, &bad2.tip, Oid::zero_sha1()), DeliveryState::Declined { .. }));
        assert!(matches!(fx.state(&train, &base, &conflict3.tip, Oid::zero_sha1()), DeliveryState::Declined { .. }));
    }

    #[test]
    fn tooth_a_change_outside_every_cone_lands_with_zero_runs() {
        let fx = Fixture::new(&base_files());
        let docs = fx.lane("docs", &[("docs/readme.md", "new docs\n")]);
        let report = fx.train().land_batch(std::slice::from_ref(&docs), true, NOW).unwrap();
        landed(&report, "docs");
        assert_eq!((report.tally.candidate_units_run, report.tally.base_units_run), (0, 0));
        assert_eq!((report.tally.units_transported, report.tally.units_total), (3, 3));
        assert!(fx.store.is_empty());
        assert!(fx.repo.is_ancestor(&docs.tip, &fx.forge()).unwrap());
    }

    #[test]
    fn inherited_red_needs_named_items_on_both_sides() {
        let mut files = base_files();
        files.retain(|(path, _)| *path != "src/b.txt" && *path != "checks/b.sh");
        files.push(("src/b.txt", "broken on main\n"));
        files.push((
            "checks/b.sh",
            "grep -q '^ok' src/b.txt || { echo '{\"status\":\"fail\",\"items\":[\"old\"]}' > \"$LANDD_RESULT_FILE\"; exit 1; }\n",
        ));
        let fx = Fixture::new(&files);
        // Touches b's cone; b stays exactly as red as it is on main.
        let still_red = fx.lane("still-red", &[("src/b.txt", "broken differently\n")]);
        let report = fx.train().land_batch(&[still_red], true, NOW).unwrap();
        landed(&report, "still-red");
        assert_eq!((report.tally.candidate_units_run, report.tally.base_units_run), (1, 1));

        // Adds a failing item main does not have.
        let script = "echo '{\"status\":\"fail\",\"items\":[\"old\",\"fresh\"]}' > \"$LANDD_RESULT_FILE\"; exit 1\n";
        let redder = fx.lane("redder", &[("checks/b.sh", script)]);
        let report = fx.train().land_batch(&[redder], true, NOW).unwrap();
        let evidence = declined(&report, "redder");
        assert_eq!(blockers(&evidence)[0].new_items, vec!["fresh"]);
        assert_eq!(blockers(&evidence)[0].moved_paths, vec!["checks/b.sh"]);

        // A failure that names nothing cannot be shown to be the old one.
        let coarse = fx.lane("coarse", &[("checks/b.sh", "exit 1\n")]);
        let report = fx.train().land_batch(std::slice::from_ref(&coarse), true, NOW).unwrap();
        assert_eq!(blockers(&declined(&report, "coarse"))[0].new_items, vec![CRASH_ITEM]);
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
        declined(&report, "bad");
        assert_eq!(fx.forge(), base);
        assert_eq!(report.pushed, None);
        assert_eq!(fx.state(&train, &base, &good.tip, *merge), DeliveryState::Fresh);
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
        assert_eq!(fx.forge(), moved, "the destination must be untouched by a refused push");
        let merged = report.pushed.unwrap();
        assert_eq!(fx.state(&train, &stale_base, &mine.tip, merged), DeliveryState::Refused { attempts: 1, not_before: NOW + 5 });

        let retry = train.land_batch(std::slice::from_ref(&mine), true, NOW + 10).unwrap();
        landed(&retry, "mine");
        // The cone verdict from the refused attempt is reused: nothing reran.
        assert_eq!(retry.tally.candidate_units_run, 0);
        assert!(fx.repo.is_ancestor(&rival.tip, &fx.forge()).unwrap());
        assert!(fx.repo.is_ancestor(&moved, &fx.forge()).unwrap());
    }

    /// Merge identities are deterministic, so a retry against the same base
    /// is the same delivery: refusals accumulate, backoff holds, and the
    /// limit is reached.
    #[test]
    fn tooth_retries_of_one_composition_are_one_delivery_with_a_refusal_limit() {
        let mut fx = Fixture::new(&base_files());
        fx.config.max_refusals = 2;
        let stale_base = fx.forge();
        let rival = fx.lane("rival", &[("docs/readme.md", "rival\n")]);
        let mine = fx.lane("mine", &[("src/a.txt", "ok mine\n")]);
        let train = fx.train();
        train.land_batch(&[rival], true, NOW).unwrap();

        let first = train.land_on(&stale_base, std::slice::from_ref(&mine), true, NOW).unwrap();
        assert!(matches!(first.outcome_of("mine"), Some(CandidateOutcome::Refused { .. })));
        // Asked again inside the backoff: no second push.
        let early = train.land_on(&stale_base, std::slice::from_ref(&mine), true, NOW + 1).unwrap();
        assert_eq!(early.outcome_of("mine"), Some(&CandidateOutcome::Refused { not_before: NOW + 5 }));
        assert_eq!(early.pushed, None);
        // After it, by a new train (a restart): the same merge, the same record, the second send.
        let second = fx.train().land_on(&stale_base, std::slice::from_ref(&mine), true, NOW + 6).unwrap();
        assert_eq!(second.pushed, first.pushed);
        assert_eq!(declined(&second, "mine"), DeclineEvidence::RefusalsExhausted { attempts: 2 });
        let again = fx.train().land_on(&stale_base, std::slice::from_ref(&mine), true, NOW + 60).unwrap();
        assert_eq!(declined(&again, "mine"), DeclineEvidence::RefusalsExhausted { attempts: 2 });
        assert_eq!(again.pushed, None);
        // Against the destination's real head it is a new delivery, and lands.
        landed(&fx.train().land_batch(&[mine], true, NOW + 61).unwrap(), "mine");
    }

    /// A send whose reply was lost is found again from the lane tip and
    /// settled by reading the destination before anything is resent.
    #[test]
    fn tooth_an_unread_send_is_settled_from_the_destination_before_resending() {
        let fx = Fixture::new(&base_files());
        let base = fx.forge();
        let lost = fx.lane("lost", &[("src/a.txt", "ok lost\n")]);
        let arrived = fx.lane("arrived", &[("src/d.txt", "ok arrived\n")]);
        let train = fx.train();
        let who = Committer { name: fx.config.committer_name.clone(), email: fx.config.committer_email.clone() };

        // A crash between journaling the send and pushing: the destination never got it.
        let merge = compose(&fx.repo, &base, std::slice::from_ref(&lost), &who).unwrap().tip();
        let binding = train.binding(&base, &lost.tip, merge);
        fx.journal.note_tip(&binding).unwrap();
        fx.journal.transition(&binding, |d| d.start(NOW)).unwrap();
        // A push that arrived, whose reply (and journal update) was lost.
        let merge2 = compose(&fx.repo, &base, std::slice::from_ref(&arrived), &who).unwrap().tip();
        let binding2 = train.binding(&base, &arrived.tip, merge2);
        fx.journal.note_tip(&binding2).unwrap();
        fx.journal.transition(&binding2, |d| d.start(NOW)).unwrap();
        fx.sandbox.git(&["push", "--quiet", "origin", &format!("{merge2}:{MAIN}")]);

        // A new process picks both lanes up again.
        let report = fx.train().land_batch(&[lost.clone(), arrived.clone()], true, NOW + 100).unwrap();
        // The arrived one is recognised as already there; nothing is pushed for it.
        assert!(
            matches!(report.outcome_of("arrived"), Some(CandidateOutcome::OnBase { .. })),
            "{:?}",
            report.outcome_of("arrived")
        );
        assert!(matches!(fx.journal.load(&binding2).unwrap().delivery.state, DeliveryState::Completed { .. }));
        // The lost one was read as not delivered, then sent on the new base.
        assert!(matches!(fx.journal.load(&binding).unwrap().delivery.state, DeliveryState::Refused { .. }));
        landed(&report, "lost");
        assert!(fx.repo.is_ancestor(&lost.tip, &fx.forge()).unwrap());
    }

    /// An already delivered lane cannot become a new red merely because
    /// this caller still has the old base or a local refusal in its journal.
    #[test]
    fn tooth_destination_completion_wins_over_stale_base_and_local_refusals() {
        for prior in ["unknown", "refused", "declined", "completed"] {
            let fx = Fixture::new(&base_files());
            let base = fx.forge();
            let lane = fx.lane("arrived", &[("src/a.txt", "broken\n")]);
            let train = fx.train();
            let who = Committer { name: fx.config.committer_name.clone(), email: fx.config.committer_email.clone() };
            let merge = compose(&fx.repo, &base, std::slice::from_ref(&lane), &who).unwrap().tip();
            let binding = train.binding(&base, &lane.tip, merge);
            fx.journal.note_tip(&binding).unwrap();
            fx.journal.transition(&binding, |d| d.start(NOW)).unwrap();
            match prior {
                "refused" => {
                    fx.journal.transition(&binding, |d| d.refused(NOW + 100)).unwrap();
                }
                "declined" => {
                    fx.journal.transition(&binding, |d| d.refused(NOW)).unwrap();
                    fx.journal.transition(&binding, |d| d.declined(DeclineEvidence::RefusalsExhausted { attempts: 1 })).unwrap();
                }
                "completed" => {
                    fx.journal.transition(&binding, |d| d.complete(train.evidence(&merge, &lane.tip))).unwrap();
                }
                _ => {}
            }
            // Another writer delivered the lane. Its test would be a new red
            // against our stale base, but the destination already contains it.
            fx.sandbox.git(&["push", "--quiet", "origin", &format!("{merge}:{MAIN}")]);
            let report = train.land_on(&base, std::slice::from_ref(&lane), true, NOW + 1).unwrap();
            assert_eq!(
                report.outcome_of("arrived"),
                Some(&CandidateOutcome::Landed { merge, evidence: train.evidence(&merge, &lane.tip) }),
                "prior state: {prior}"
            );
            assert_eq!(report.pushed, None);
            assert_eq!(report.tally.candidate_units_run, 0);
            assert_eq!(fx.forge(), merge);
            let settled = fx.journal.load(&binding).unwrap().delivery;
            assert_eq!(settled.sends, 1);
            assert!(matches!(settled.state, DeliveryState::Completed { .. }));
        }
    }

    #[test]
    fn tooth_settling_an_unread_send_at_max_refusals_declines_without_resending() {
        let mut fx = Fixture::new(&base_files());
        fx.config.max_refusals = 1;
        let base = fx.forge();
        let lane = fx.lane("capped", &[("src/a.txt", "ok capped\n")]);
        let train = fx.train();
        let who = Committer { name: fx.config.committer_name.clone(), email: fx.config.committer_email.clone() };
        let merge = compose(&fx.repo, &base, std::slice::from_ref(&lane), &who).unwrap().tip();
        let binding = train.binding(&base, &lane.tip, merge);
        fx.journal.note_tip(&binding).unwrap();
        fx.journal.transition(&binding, |d| d.start(NOW)).unwrap();

        let report = fx.train().land_batch(std::slice::from_ref(&lane), true, NOW + 10).unwrap();
        assert_eq!(declined(&report, "capped"), DeclineEvidence::RefusalsExhausted { attempts: 1 });
        assert_eq!(report.pushed, None);
        assert_eq!(fx.journal.load(&binding).unwrap().delivery.sends, 1);
    }

    /// The lease refuses the push, but the destination already holds the
    /// lane tip because someone else's push carried it: the delivery
    /// completes (`confirmation_wins`) and is reported as carried, not landed.
    #[test]
    fn tooth_a_lane_someone_else_carried_is_carried_not_landed() {
        let fx = Fixture::new(&base_files());
        let stale_base = fx.forge();
        let lane = fx.lane("lane", &[("src/a.txt", "ok lane\n")]);
        let train = fx.train();
        landed(&train.land_batch(std::slice::from_ref(&lane), true, NOW).unwrap(), "lane");
        let carried_by = fx.forge();

        let report = train.land_on(&stale_base, std::slice::from_ref(&lane), true, NOW + 1).unwrap();
        // Identical inputs identify the already delivered merge without a second push.
        let original_merge = landed(&report, "lane");
        assert_eq!(report.pushed, None);

        // A different train identity composes a different merge of the same lane.
        let mut other = fx.config.clone();
        other.committer_name = "another seat".into();
        let train = Train::new(&fx.repo, &other, fx.source.as_ref(), &fx.store, &fx.journal, fx.runner()).unwrap();
        let report = train.land_on(&stale_base, std::slice::from_ref(&lane), true, NOW + 2).unwrap();
        assert_ne!(report.push_exit, Some(0));
        let Some(CandidateOutcome::Carried { carrier, evidence }) = report.outcome_of("lane") else {
            panic!("the lane is on the destination through another merge: {:?}", report.outcome_of("lane"));
        };
        assert_eq!((*carrier, evidence.remote_head), (carried_by, carried_by));
        assert_eq!(fx.forge(), carried_by);
        assert_eq!(report.pushed, None, "destination completion needs no second send");
        assert!(matches!(fx.state(&train, &stale_base, &lane.tip, original_merge), DeliveryState::Completed { .. }));

        // And a tip that is already on the base has nothing to land.
        let again = train.land_batch(std::slice::from_ref(&lane), true, NOW + 3).unwrap();
        assert!(matches!(again.outcome_of("lane"), Some(CandidateOutcome::OnBase { .. })));
        assert_eq!(again.pushed, None);
    }

    /// A lane contained in another lane lands only if that lane does.
    #[test]
    fn tooth_a_stacked_lane_shares_its_carriers_fate() {
        let fx = Fixture::new(&base_files());
        let lower = fx.lane("lower", &[("src/a.txt", "ok lower\n")]);
        let upper = Candidate { lane: "upper".into(), tip: fx.sandbox.lane("upper", "lower", &[("src/d.txt", "ok upper\n")]) };
        let report = fx.train().land_batch(&[upper.clone(), lower.clone(), upper.clone()], true, NOW).unwrap();
        let merge = landed(&report, "upper");
        let CandidateOutcome::Carried { carrier, .. } = &report.outcomes[1].1 else { panic!("lower rides with upper") };
        assert_eq!(*carrier, merge);
        assert!(matches!(&report.outcomes[2].1, CandidateOutcome::Carried { .. }), "a duplicate rides with the first");
        assert!(fx.repo.is_ancestor(&lower.tip, &fx.forge()).unwrap());

        // The carrier is red: the contained lane is judged on its own, and
        // is not reported as on the destination when it is not.
        let fx = Fixture::new(&base_files());
        let lower = fx.lane("lower", &[("src/a.txt", "ok lower\n")]);
        let upper = Candidate { lane: "upper".into(), tip: fx.sandbox.lane("upper", "lower", &[("src/b.txt", "broken\n")]) };
        let report = fx.train().land_batch(&[upper.clone(), lower.clone()], true, NOW).unwrap();
        declined(&report, "upper");
        landed(&report, "lower");
        assert!(fx.repo.is_ancestor(&lower.tip, &fx.forge()).unwrap());
        assert!(!fx.repo.is_ancestor(&upper.tip, &fx.forge()).unwrap());
    }

    /// A lane that only conflicts with a peer the batch then declines is
    /// not declined with it.
    #[test]
    fn tooth_a_conflict_with_a_culprit_is_reconsidered_once_the_culprit_is_out() {
        let fx = Fixture::new(&base_files());
        let culprit = fx.lane("culprit", &[("src/a.txt", "broken\n")]);
        let victim = fx.lane("victim", &[("src/a.txt", "ok victim\n")]);
        let report = fx.train().land_batch(&[culprit.clone(), victim.clone()], true, NOW).unwrap();
        assert!(matches!(declined(&report, "culprit"), DeclineEvidence::NewRed { .. }));
        landed(&report, "victim");
        assert_eq!(fx.sandbox.forge_git(&["show", &format!("{MAIN}:src/a.txt")]), "ok victim");
    }

    /// Deleting the check that would fail is not a way through.
    #[test]
    fn tooth_removing_a_unit_blocks_unless_the_operator_allows_it() {
        let mut fx = Fixture::new(&base_files());
        let fewer = r#"{"units": {"a": {"path": "checks/a.sh", "inputs": ["src/a.txt"]}, "d": {"path": "checks/d.sh", "inputs": ["src/d.txt"]}}}"#;
        let lane = fx.lane("drops-b", &[("landd-units.json", fewer), ("src/b.txt", "broken\n")]);
        let gone = Candidate {
            lane: "drops-manifest".into(),
            tip: {
                fx.sandbox.git(&["checkout", "--quiet", "main"]);
                let tip = fx.sandbox.commit("drops-manifest", "drop", &[], &["landd-units.json"]);
                fx.sandbox.git(&["checkout", "--quiet", "main"]);
                tip
            },
        };
        let report = fx.train().land_batch(&[lane.clone(), gone.clone()], true, NOW).unwrap();
        let evidence = declined(&report, "drops-b");
        assert_eq!(
            blockers(&evidence),
            [Blocker { unit: "b".into(), new_items: vec![REMOVED_ITEM.into()], moved_paths: vec![] }]
        );
        // No manifest is not "no checks": all three units are reported removed.
        assert_eq!(blockers(&declined(&report, "drops-manifest")).len(), 3);

        fx.config.allow_unit_removal = true;
        let report = fx.train().land_batch(std::slice::from_ref(&lane), true, NOW).unwrap();
        landed(&report, "drops-b");
        assert_eq!(report.tally.units_removed, vec!["b"]);
    }

    #[test]
    fn tooth_one_bad_candidate_does_not_fail_its_peers() {
        let fx = Fixture::new(&base_files());
        let good = fx.lane("good", &[("src/a.txt", "ok one\n")]);
        fx.sandbox.git(&["checkout", "--quiet", "--orphan", "island"]);
        let orphan = Candidate { lane: "orphan".into(), tip: fx.sandbox.commit("island", "island", &[("z.txt", "z\n")], &[]) };
        fx.sandbox.git(&["checkout", "--quiet", "main"]);
        let absent = Candidate { lane: "absent".into(), tip: Oid::from_slice(&[0xab; 20]).unwrap() };
        // Its cones cannot even be computed.
        let unreadable = fx.lane("unreadable", &[("landd-units.json", "{ not json")]);
        let report = fx.train().land_batch(&[absent, orphan, unreadable, good], true, NOW).unwrap();
        assert!(matches!(declined(&report, "absent"), DeclineEvidence::Unmergeable { .. }));
        assert!(matches!(declined(&report, "orphan"), DeclineEvidence::Unmergeable { .. }));
        assert!(matches!(declined(&report, "unreadable"), DeclineEvidence::Other { .. }));
        landed(&report, "good");
    }

    #[test]
    fn a_lane_that_changes_nothing_is_not_pushed() {
        let fx = Fixture::new(&base_files());
        let first = fx.lane("first", &[("docs/readme.md", "same change\n")]);
        let twin = fx.lane("twin", &[("docs/readme.md", "same change\n")]);
        let train = fx.train();
        landed(&train.land_batch(&[first], true, NOW).unwrap(), "first");
        let head = fx.forge();
        let report = train.land_batch(&[twin], true, NOW).unwrap();
        assert_eq!(report.outcome_of("twin"), Some(&CandidateOutcome::NoChange));
        assert_eq!((report.pushed, fx.forge()), (None, head));
    }

    #[test]
    fn timeouts_block_the_batch_but_are_never_recorded_as_verdicts() {
        let mut fx = Fixture::new(&base_files());
        fx.config.test_timeout_s = 1;
        let slow = fx.lane("slow", &[("checks/a.sh", "sleep 30\n")]);
        let report = fx.train().land_batch(&[slow], true, NOW).unwrap();
        assert_eq!(blockers(&declined(&report, "slow"))[0].new_items, vec![TIMEOUT_ITEM]);
        // Only the base's pass for `a` is durable; the timeout is not.
        assert_eq!(fx.store.len(), 1);
    }

    #[test]
    fn land_receipts_are_sealed_by_the_supervisor_bound_to_the_repository_and_verify() {
        let fx = Fixture::new(&base_files());
        fx.sandbox.forge_git(&["config", "receive.advertisePushOptions", "true"]);
        let base = fx.forge();
        let key = SigningKey::ed25519_from_seed([42; 32]);
        let mut trusted = TrustedKeys::new();
        trusted.insert("seat-1", key.trusted(), Grant::new(&["landd"], &["land-receipt"])).unwrap();
        let train = fx.train().with_signer("seat-1", key).unwrap();
        let good = fx.lane("good", &[("src/a.txt", "ok one\n")]);
        let report = train.land_batch(&[good], true, NOW).unwrap();
        assert_eq!(report.landed(), 1);
        let receipt = report.receipt.expect("a receipt is sealed");
        receipt.verify(&trusted).unwrap();
        assert_eq!(train.repo_id, landd_core::git::canonical_repo_id(fx.sandbox.forge.to_str().unwrap()));
        assert_eq!(receipt.header.subject, custody::ref_update_subject(&train.repo_id, MAIN, &base, &fx.forge()));
        assert_ne!(receipt.header.subject, custody::ref_update_subject("a mirror", MAIN, &base, &fx.forge()));
        assert_eq!(receipt.claims["batch_size"], 1);
        assert_eq!(receipt.claims["candidate_units_run"], 1);
        // The receipt says how the checks were isolated.
        assert_eq!(receipt.claims["isolation"]["isolation"], "bwrap");
        assert_eq!(receipt.claims["unit_view"], "cone");
        assert_eq!(receipt.claims["runner_profile"], serde_json::json!(train.runner.profile().digest));
    }

    #[test]
    fn tooth_receipts_cannot_be_signed_without_the_sandbox() {
        let mut fx = Fixture::new(&base_files());
        fx.config.isolation = Isolation::None;
        let refused = fx.train().with_signer("seat-1", SigningKey::ed25519_from_seed([42; 32]));
        assert!(matches!(refused, Err(TrainError::UnsandboxedSigning)));
    }

    /// A whole-tree view cannot reuse a narrow cone while a visible input
    /// changes. Exercise admission, the sandboxed check and the actual forge.
    #[test]
    fn tooth_whole_tree_views_bind_every_visible_input() {
        let mut fx = Fixture::new(&[
            ("landd-units.json", r#"{"units":{"check":{"path":"check.sh","inputs":[]}}}"#),
            ("check.sh", "grep -q '^ok' undeclared.txt\n"),
            ("undeclared.txt", "ok base\n"),
        ]);
        fx.config.unit_view = UnitView::Tree;
        let good = fx.lane("good", &[("undeclared.txt", "ok changed\n")]);
        let bad = fx.lane("bad", &[("undeclared.txt", "broken\n")]);
        let train = fx.train();
        let first = train.land_batch(&[good], false, NOW).unwrap();
        assert!(matches!(first.outcome_of("good"), Some(CandidateOutcome::WouldLand { .. })));
        assert_eq!(first.tally.candidate_units_run, 1);
        let head = fx.forge();
        let report = train.land_batch(&[bad], true, NOW + 1).unwrap();
        assert_eq!(report.tally.candidate_units_run, 1);
        assert_eq!(blockers(&declined(&report, "bad"))[0].moved_paths, ["undeclared.txt"]);
        assert_eq!(fx.forge(), head, "the red must not reach the forge");
    }

    #[test]
    fn a_missing_target_ref_is_an_error() {
        let mut fx = Fixture::new(&base_files());
        fx.config.target_ref = "refs/heads/absent".into();
        assert!(matches!(fx.train().land_batch(&[], true, NOW), Err(TrainError::NoTargetRef { .. })));
    }

    /// Python checks through the whole path: `ast-sweep` cones, the sandbox,
    /// cone-only views, the judge. A data file a test opens is in its cone,
    /// so changing it reruns (and here fails) exactly that test.
    #[test]
    fn tooth_python_checks_run_through_the_train_and_data_changes_reach_their_readers() {
        let files = [
            ("tests/__init__.py", ""),
            ("tests/support.py", "import os\nREPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))\n"),
            (
                "tests/test_table.py",
                "import json, os, sys\nfrom tests.support import REPO\n\
                 table = json.load(open(os.path.join(REPO, 'data', 'table.json')))\n\
                 # A read the analysis cannot see finds nothing: the view holds the cone only.\n\
                 assert not getattr(os.path, 'exists')('docs/readme.md'), 'a file outside the cone is visible'\n\
                 sys.exit(0 if table.get('ok') else 1)\n",
            ),
            ("tests/test_pure.py", "import sys\nimport lib.core\nsys.exit(0 if lib.core.VALUE == 1 else 1)\n"),
            ("lib/__init__.py", ""),
            ("lib/core.py", "VALUE = 1\n"),
            ("data/table.json", "{\"ok\": true}\n"),
            ("docs/readme.md", "docs\n"),
        ];
        let mut fx = Fixture::new(&files);
        fx.config.test_command = vec!["python3".into(), "-m".into(), "{unit}".into()];
        fx.config.cone_source = ConeSourceKind::Python;
        let mut pack = ast_sweep::RulePack::builtin();
        pack.imports.tests = vec!["tests/**/test_*.py".into()];
        fx.source =
            Box::new(PythonCones { pack, cache: Some(ast_sweep::BlobFactsCache::open(fx.dir.path().join("facts")).unwrap()) });

        // Docs are in no cone: nothing runs.
        let docs = fx.lane("docs", &[("docs/readme.md", "new docs\n")]);
        let report = fx.train().land_batch(&[docs], true, NOW).unwrap();
        landed(&report, "docs");
        assert_eq!((report.tally.candidate_units_run, report.tally.units_transported, report.tally.units_total), (0, 2, 2));

        // The data file is in the cone of the test that opens it, and only that one.
        let data = fx.lane("data", &[("data/table.json", "{\"ok\": false}\n")]);
        let report = fx.train().land_batch(&[data], true, NOW).unwrap();
        let evidence = declined(&report, "data");
        assert_eq!(
            blockers(&evidence),
            [Blocker {
                unit: "tests.test_table".into(),
                new_items: vec![CRASH_ITEM.into()],
                moved_paths: vec!["data/table.json".into()]
            }]
        );
        assert_eq!((report.tally.candidate_units_run, report.tally.base_units_run, report.tally.units_transported), (1, 1, 1));

        // A code change reaches its importer; a harmless data change passes after one run.
        let code = fx.lane("code", &[("lib/core.py", "VALUE = 2\n")]);
        let harmless = fx.lane("harmless", &[("data/table.json", "{\"ok\": true, \"more\": 1}\n")]);
        let report = fx.train().land_batch(&[code, harmless], true, NOW).unwrap();
        assert_eq!(blockers(&declined(&report, "code"))[0].unit, "tests.test_pure");
        landed(&report, "harmless");
    }
}
