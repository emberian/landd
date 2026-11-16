//! The `Delivery` outbox: an external compare-and-swap state machine that is
//! persisted before any network send.
//!
//! ```text
//! Fresh ──start──▶ Unknown ──refused──▶ Refused ──start──▶ Unknown …
//!   │                 │                    │
//!   └────declined─────┴─────declined───────┴──▶ Declined
//!
//! any state ──complete(ancestry evidence)──▶ Completed
//! ```
//!
//! `Declined` is terminal against `start`, `refused` and `declined`, and can
//! only be entered from `Fresh` or `Refused`: while a send is outstanding
//! (`Unknown`) the destination has to be read first.
//! `Completed` is terminal against everything. Completion needs proof that
//! the lane tip is an ancestor of the target ref on the destination, and with
//! that proof it wins from every state (`confirmation_wins`): a decline
//! recorded from a flaky check, a lost reply or a sibling carrying the same
//! commits cannot contradict what the destination holds.

use crate::canon::canonical_json;
use crate::digest::{Digest32, Oid};
use crate::fsx;
use crate::reasons::Blocker;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// What a delivery is a delivery of. Its digest is the journal key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    pub repo: String,
    pub target_ref: String,
    pub lane_tip: Oid,
    pub expected_old: Oid,
    pub merged_head: Oid,
}

impl Binding {
    /// Domain-separated BLAKE3 of the canonical binding.
    pub fn key(&self) -> Digest32 {
        Digest32::tagged("landd delivery binding v1", &[&canonical_json(self).expect("a binding has no floats")])
    }

    /// Key of the pointer that names the latest binding made for this lane
    /// tip on this destination, whatever base it was composed against.
    pub fn tip_key(repo: &str, target_ref: &str, lane_tip: &Oid) -> Digest32 {
        Digest32::tagged("landd delivery tip pointer v1", &[repo.as_bytes(), target_ref.as_bytes(), lane_tip.as_bytes()])
    }
}

/// Proof read from the destination: `lane_tip` is an ancestor of
/// `remote_head`, the value of `target_ref` on the forge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AncestryEvidence {
    /// The destination the ref was read from (the binding's `repo`).
    pub repo: String,
    pub target_ref: String,
    pub remote_head: Oid,
    pub lane_tip: Oid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DeclineEvidence {
    Conflict {
        conflicting_paths: Vec<String>,
    },
    NewRed {
        why_not: Vec<Blocker>,
    },
    /// The tip cannot be merged at all (missing object, unrelated history).
    Unmergeable {
        detail: String,
    },
    RefusalsExhausted {
        attempts: u32,
    },
    Other {
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeliveryState {
    Fresh,
    /// A send was started and its outcome has not been read from the destination.
    Unknown,
    /// The destination was read and does not hold the commit; retry at `not_before`.
    Refused {
        attempts: u32,
        not_before: u64,
    },
    Declined {
        evidence: DeclineEvidence,
    },
    Completed {
        evidence: AncestryEvidence,
    },
}

impl DeliveryState {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Unknown => "unknown",
            Self::Refused { .. } => "refused",
            Self::Declined { .. } => "declined",
            Self::Completed { .. } => "completed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryError {
    #[error("a send is outstanding: read the destination before starting another")]
    OutcomeUnknown,
    #[error("refused until {not_before} (now {now})")]
    NotBefore { not_before: u64, now: u64 },
    #[error("declined deliveries are terminal against {0}")]
    Declined(&'static str),
    #[error("already completed")]
    Completed,
    #[error("{op} is not valid from {from}")]
    Invalid { op: &'static str, from: &'static str },
    #[error("the send counter of this delivery is exhausted")]
    SendsExhausted,
    #[error("evidence is for another destination, lane tip or target ref")]
    EvidenceMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delivery {
    pub binding: Binding,
    #[serde(flatten)]
    pub state: DeliveryState,
    /// Sends started so far.
    pub sends: u32,
}

impl Delivery {
    pub fn fresh(binding: Binding) -> Self {
        Self { binding, state: DeliveryState::Fresh, sends: 0 }
    }

    fn next(&self, state: DeliveryState) -> Self {
        Self { binding: self.binding.clone(), state, sends: self.sends }
    }

    /// Record the intent to send. Must be durable before the network call.
    pub fn start(&self, now: u64) -> Result<Self, DeliveryError> {
        match &self.state {
            DeliveryState::Fresh => {}
            DeliveryState::Refused { not_before, .. } if now >= *not_before => {}
            DeliveryState::Refused { not_before, .. } => return Err(DeliveryError::NotBefore { not_before: *not_before, now }),
            DeliveryState::Unknown => return Err(DeliveryError::OutcomeUnknown),
            DeliveryState::Declined { .. } => return Err(DeliveryError::Declined("start")),
            DeliveryState::Completed { .. } => return Err(DeliveryError::Completed),
        }
        // A counter at its limit refuses the send and leaves the record as
        // it is; it never wraps back to "no sends yet".
        let mut next = self.next(DeliveryState::Unknown);
        next.sends = self.sends.checked_add(1).ok_or(DeliveryError::SendsExhausted)?;
        Ok(next)
    }

    /// The destination was read after a send and does not hold the commit.
    pub fn refused(&self, not_before: u64) -> Result<Self, DeliveryError> {
        match &self.state {
            DeliveryState::Unknown => Ok(self.next(DeliveryState::Refused { attempts: self.sends, not_before })),
            DeliveryState::Declined { .. } => Err(DeliveryError::Declined("refused")),
            DeliveryState::Completed { .. } => Err(DeliveryError::Completed),
            other => Err(DeliveryError::Invalid { op: "refused", from: other.name() }),
        }
    }

    pub fn declined(&self, evidence: DeclineEvidence) -> Result<Self, DeliveryError> {
        match &self.state {
            DeliveryState::Fresh | DeliveryState::Refused { .. } => Ok(self.next(DeliveryState::Declined { evidence })),
            // The send may have landed: only the destination can say.
            DeliveryState::Unknown => Err(DeliveryError::OutcomeUnknown),
            DeliveryState::Declined { .. } => Err(DeliveryError::Declined("declined")),
            DeliveryState::Completed { .. } => Err(DeliveryError::Completed),
        }
    }

    /// Destination completion dominates: succeeds from every state, given
    /// evidence for this binding. Completing twice keeps the first evidence.
    pub fn complete(&self, evidence: AncestryEvidence) -> Result<Self, DeliveryError> {
        if evidence.repo != self.binding.repo
            || evidence.lane_tip != self.binding.lane_tip
            || evidence.target_ref != self.binding.target_ref
        {
            return Err(DeliveryError::EvidenceMismatch);
        }
        match &self.state {
            DeliveryState::Completed { .. } => Ok(self.clone()),
            _ => Ok(self.next(DeliveryState::Completed { evidence })),
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, DeliveryState::Declined { .. } | DeliveryState::Completed { .. })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("journal io at {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("journal record {path} is corrupt: {detail}")]
    Corrupt { path: PathBuf, detail: String },
    #[error("key {key} already holds a different binding")]
    BindingMismatch { key: Digest32 },
    #[error("lost the compare-and-swap for {key} {attempts} times")]
    Contended { key: Digest32, attempts: u32 },
    #[error("journal for {key} reached its bound of {bound} revisions")]
    Full { key: Digest32, bound: u64 },
    #[error(transparent)]
    Delivery(#[from] DeliveryError),
}

/// A delivery as stored, with the revision it was read at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub delivery: Delivery,
    pub rev: u64,
}

#[derive(Serialize, Deserialize)]
struct Record {
    rev: u64,
    #[serde(flatten)]
    delivery: Delivery,
}

#[derive(Serialize, Deserialize)]
struct TipRecord {
    rev: u64,
    binding: Binding,
}

/// Append-only, bounded, per-key journal: `<root>/ab/cd/<key>/r<rev>.json`.
///
/// Each revision is created exclusively, so two writers racing from the same
/// revision cannot both win, with no lock and no directory listing. The
/// newest revision is found by galloping over the dense revision numbers.
#[derive(Debug, Clone)]
pub struct DeliveryJournal {
    root: PathBuf,
}

/// Revisions one key may hold. `max_refusals` keeps real journals far below it.
pub const MAX_REVISIONS: u64 = 1 << 16;
const CAS_ATTEMPTS: u32 = 16;

impl DeliveryJournal {
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn log_dir(&self, space: &str, key: &Digest32) -> PathBuf {
        let hex = key.to_hex();
        self.root.join(space).join(&hex[..2]).join(&hex[2..4]).join(&hex)
    }

    fn rev_path(&self, key: &Digest32, rev: u64) -> PathBuf {
        self.log_dir("bindings", key).join(format!("r{rev:08}.json"))
    }

    fn tip_path(&self, key: &Digest32, rev: u64) -> PathBuf {
        self.log_dir("tips", key).join(format!("r{rev:08}.json"))
    }

    /// Highest revision on disk, 0 when there is none. `path_of` names the
    /// file of a revision; revisions are dense, so existence is monotone.
    fn latest(path_of: impl Fn(u64) -> PathBuf) -> Result<u64, JournalError> {
        let exists = |rev: u64| {
            let path = path_of(rev);
            path.try_exists().map_err(|source| JournalError::Io { path, source })
        };
        if !exists(1)? {
            return Ok(0);
        }
        let (mut low, mut high) = (1u64, 2u64);
        while high <= MAX_REVISIONS && exists(high)? {
            low = high;
            high *= 2;
        }
        // Invariant: `low` exists, `high` does not (or is past the bound).
        let mut high = high.min(MAX_REVISIONS + 1);
        while high - low > 1 {
            let mid = low + (high - low) / 2;
            if exists(mid)? {
                low = mid;
            } else {
                high = mid;
            }
        }
        Ok(low)
    }

    fn latest_rev(&self, key: &Digest32) -> Result<u64, JournalError> {
        Self::latest(|rev| self.rev_path(key, rev))
    }

    /// Durably record `binding` as the latest one made for its lane tip.
    /// Call this before `start`: after a crash, or after the base moved and
    /// the next composition has a different key, [`Self::latest_for_tip`]
    /// still finds the send whose outcome was never read.
    pub fn note_tip(&self, binding: &Binding) -> Result<(), JournalError> {
        let key = Binding::tip_key(&binding.repo, &binding.target_ref, &binding.lane_tip);
        for _ in 0..CAS_ATTEMPTS {
            let rev = Self::latest(|rev| self.tip_path(&key, rev))?;
            if rev > 0 && self.read_tip(&key, rev)? == *binding {
                return Ok(());
            }
            if rev >= MAX_REVISIONS {
                return Err(JournalError::Full { key, bound: MAX_REVISIONS });
            }
            let path = self.tip_path(&key, rev + 1);
            let bytes = canonical_json(&TipRecord { rev: rev + 1, binding: binding.clone() })
                .map_err(|e| JournalError::Corrupt { path: path.clone(), detail: e.to_string() })?;
            if fsx::create_exclusive(&path, &bytes).map_err(|source| JournalError::Io { path, source })? {
                return Ok(());
            }
        }
        Err(JournalError::Contended { key, attempts: CAS_ATTEMPTS })
    }

    fn read_tip(&self, key: &Digest32, rev: u64) -> Result<Binding, JournalError> {
        let path = self.tip_path(key, rev);
        let bytes = std::fs::read(&path).map_err(|source| JournalError::Io { path: path.clone(), source })?;
        let record: TipRecord =
            serde_json::from_slice(&bytes).map_err(|e| JournalError::Corrupt { path: path.clone(), detail: e.to_string() })?;
        if record.rev != rev {
            return Err(JournalError::Corrupt { path, detail: format!("holds revision {}", record.rev) });
        }
        Ok(record.binding)
    }

    /// The latest delivery recorded for a lane tip on a destination.
    pub fn latest_for_tip(&self, repo: &str, target_ref: &str, lane_tip: &Oid) -> Result<Option<Stored>, JournalError> {
        let key = Binding::tip_key(repo, target_ref, lane_tip);
        let rev = Self::latest(|rev| self.tip_path(&key, rev))?;
        if rev == 0 {
            return Ok(None);
        }
        let binding = self.read_tip(&key, rev)?;
        self.load(&binding).map(Some)
    }

    fn read_rev(&self, key: &Digest32, rev: u64) -> Result<Delivery, JournalError> {
        let path = self.rev_path(key, rev);
        let bytes = std::fs::read(&path).map_err(|source| JournalError::Io { path: path.clone(), source })?;
        let record: Record =
            serde_json::from_slice(&bytes).map_err(|e| JournalError::Corrupt { path: path.clone(), detail: e.to_string() })?;
        if record.rev != rev {
            return Err(JournalError::Corrupt { path, detail: format!("holds revision {}", record.rev) });
        }
        Ok(record.delivery)
    }

    /// The current delivery for `binding`; `Fresh` at revision 0 when unseen.
    pub fn load(&self, binding: &Binding) -> Result<Stored, JournalError> {
        self.load_keyed(&binding.key(), binding)
    }

    /// As `load`, under an explicit key. A key that already holds another
    /// binding is an error, never a silent overwrite.
    pub fn load_keyed(&self, key: &Digest32, binding: &Binding) -> Result<Stored, JournalError> {
        let rev = self.latest_rev(key)?;
        if rev == 0 {
            return Ok(Stored { delivery: Delivery::fresh(binding.clone()), rev: 0 });
        }
        let delivery = self.read_rev(key, rev)?;
        if delivery.binding != *binding {
            return Err(JournalError::BindingMismatch { key: *key });
        }
        Ok(Stored { delivery, rev })
    }

    /// Apply a transition and persist it with compare-and-swap. When another
    /// writer advances the key first, the transition is re-applied to the
    /// state that writer left. A transition that changes nothing writes
    /// nothing and returns the state as read; that read can be stale only in
    /// the sense that a later writer may already have moved on, which every
    /// caller must tolerate anyway.
    pub fn transition(
        &self,
        binding: &Binding,
        step: impl Fn(&Delivery) -> Result<Delivery, DeliveryError>,
    ) -> Result<Stored, JournalError> {
        self.transition_keyed(&binding.key(), binding, step)
    }

    pub fn transition_keyed(
        &self,
        key: &Digest32,
        binding: &Binding,
        step: impl Fn(&Delivery) -> Result<Delivery, DeliveryError>,
    ) -> Result<Stored, JournalError> {
        for _ in 0..CAS_ATTEMPTS {
            let current = self.load_keyed(key, binding)?;
            let next = step(&current.delivery)?;
            if next == current.delivery {
                return Ok(current);
            }
            let rev = current.rev + 1;
            if rev > MAX_REVISIONS {
                return Err(JournalError::Full { key: *key, bound: MAX_REVISIONS });
            }
            let bytes = canonical_json(&Record { rev, delivery: next.clone() })
                .map_err(|e| JournalError::Corrupt { path: self.rev_path(key, rev), detail: e.to_string() })?;
            let path = self.rev_path(key, rev);
            if fsx::create_exclusive(&path, &bytes).map_err(|source| JournalError::Io { path, source })? {
                return Ok(Stored { delivery: next, rev });
            }
        }
        Err(JournalError::Contended { key: *key, attempts: CAS_ATTEMPTS })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(n: u8) -> Oid {
        Oid::from_slice(&[n; 20]).unwrap()
    }

    fn binding(tip: u8) -> Binding {
        Binding {
            repo: "repo".into(),
            target_ref: "refs/heads/main".into(),
            lane_tip: oid(tip),
            expected_old: oid(1),
            merged_head: oid(tip.wrapping_add(100)),
        }
    }

    fn landed(b: &Binding) -> AncestryEvidence {
        AncestryEvidence { repo: b.repo.clone(), target_ref: b.target_ref.clone(), remote_head: oid(200), lane_tip: b.lane_tip }
    }

    fn conflict() -> DeclineEvidence {
        DeclineEvidence::Conflict { conflicting_paths: vec!["a.py".into()] }
    }

    #[test]
    fn happy_path_and_retry_after_refusal() {
        let b = binding(2);
        let sent = Delivery::fresh(b.clone()).start(10).unwrap();
        assert_eq!(sent.state, DeliveryState::Unknown);
        let refused = sent.refused(50).unwrap();
        assert_eq!(refused.state, DeliveryState::Refused { attempts: 1, not_before: 50 });
        assert_eq!(refused.start(49), Err(DeliveryError::NotBefore { not_before: 50, now: 49 }));
        let again = refused.start(50).unwrap();
        assert_eq!(again.sends, 2);
        let done = again.complete(landed(&b)).unwrap();
        assert!(matches!(done.state, DeliveryState::Completed { .. }));
    }

    #[test]
    fn tooth_lost_reply_refuses_start() {
        let unknown = Delivery::fresh(binding(2)).start(0).unwrap();
        assert_eq!(unknown.start(0), Err(DeliveryError::OutcomeUnknown));
        assert_eq!(unknown.start(u64::MAX), Err(DeliveryError::OutcomeUnknown));
    }

    #[test]
    fn tooth_declined_is_terminal_except_against_completion() {
        let b = binding(2);
        let declined = Delivery::fresh(b.clone()).declined(conflict()).unwrap();
        assert_eq!(declined.start(u64::MAX), Err(DeliveryError::Declined("start")));
        assert_eq!(declined.refused(u64::MAX), Err(DeliveryError::Declined("refused")));
        assert_eq!(declined.declined(conflict()), Err(DeliveryError::Declined("declined")));
        // confirmation_wins: the forge shows the lane tip on the target ref.
        let done = declined.complete(landed(&b)).unwrap();
        assert_eq!(done.state, DeliveryState::Completed { evidence: landed(&b) });
    }

    #[test]
    fn tooth_completion_needs_evidence_for_this_binding() {
        let b = binding(2);
        let other_tip = AncestryEvidence { lane_tip: oid(9), ..landed(&b) };
        let other_ref = AncestryEvidence { target_ref: "refs/heads/release".into(), ..landed(&b) };
        // The same commits on a fork or mirror are not this delivery.
        let other_repo = AncestryEvidence { repo: "mirror".into(), ..landed(&b) };
        for state in [Delivery::fresh(b.clone()), Delivery::fresh(b.clone()).start(0).unwrap()] {
            assert_eq!(state.complete(other_tip.clone()), Err(DeliveryError::EvidenceMismatch));
            assert_eq!(state.complete(other_ref.clone()), Err(DeliveryError::EvidenceMismatch));
            assert_eq!(state.complete(other_repo.clone()), Err(DeliveryError::EvidenceMismatch));
        }
    }

    #[test]
    fn tooth_completed_is_terminal_and_keeps_first_evidence() {
        let b = binding(2);
        let done = Delivery::fresh(b.clone()).start(0).unwrap().complete(landed(&b)).unwrap();
        assert_eq!(done.start(u64::MAX), Err(DeliveryError::Completed));
        assert_eq!(done.refused(0), Err(DeliveryError::Completed));
        assert_eq!(done.declined(conflict()), Err(DeliveryError::Completed));
        let later = AncestryEvidence { remote_head: oid(201), ..landed(&b) };
        assert_eq!(done.complete(later).unwrap(), done);
    }

    #[test]
    fn tooth_refused_needs_an_outstanding_send() {
        let fresh = Delivery::fresh(binding(2));
        assert_eq!(fresh.refused(0), Err(DeliveryError::Invalid { op: "refused", from: "fresh" }));
    }

    /// `confirmation_wins` as a property: over random operation sequences,
    /// completion with matching evidence succeeds from every reachable state,
    /// nothing leaves `Completed`, and `Declined` is left only by completion.
    #[test]
    fn property_confirmation_wins_over_random_histories() {
        let b = binding(2);
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..4000 {
            let mut d = Delivery::fresh(b.clone());
            for _ in 0..(next() % 12) {
                let before = d.clone();
                let now = next() % 100;
                let stepped = match next() % 4 {
                    0 => d.start(now),
                    1 => d.refused(now + next() % 50),
                    2 => d.declined(conflict()),
                    _ => d.complete(landed(&b)),
                };
                if let Ok(after) = stepped {
                    d = after;
                }
                match (&before.state, &d.state) {
                    (DeliveryState::Completed { .. }, after) => assert_eq!(after, &before.state),
                    (DeliveryState::Declined { .. }, after) => {
                        assert!(matches!(after, DeliveryState::Declined { .. } | DeliveryState::Completed { .. }))
                    }
                    _ => {}
                }
                assert!(d.sends >= before.sends);
            }
            let done = d.complete(landed(&b)).expect("completion wins from every state");
            assert!(matches!(done.state, DeliveryState::Completed { .. }));
        }
    }

    #[test]
    fn journal_persists_before_send_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let b = binding(2);
        let journal = DeliveryJournal::open(dir.path());
        assert_eq!(journal.load(&b).unwrap(), Stored { delivery: Delivery::fresh(b.clone()), rev: 0 });
        let sent = journal.transition(&b, |d| d.start(5)).unwrap();
        assert_eq!((sent.rev, sent.delivery.state.clone()), (1, DeliveryState::Unknown));

        // A second process opening the same directory sees the outstanding send.
        let reopened = DeliveryJournal::open(dir.path());
        assert_eq!(reopened.load(&b).unwrap(), sent);
        assert!(matches!(reopened.transition(&b, |d| d.start(6)), Err(JournalError::Delivery(DeliveryError::OutcomeUnknown))));
        let done = reopened.transition(&b, |d| d.complete(landed(&b))).unwrap();
        assert_eq!(done.rev, 2);
        assert_eq!(journal.load(&b).unwrap(), done);
    }

    #[test]
    fn tooth_journal_declined_then_forge_confirms() {
        let dir = tempfile::tempdir().unwrap();
        let b = binding(3);
        let journal = DeliveryJournal::open(dir.path());
        journal.transition(&b, |d| d.declined(conflict())).unwrap();
        assert!(matches!(
            journal.transition(&b, |d| d.start(u64::MAX)),
            Err(JournalError::Delivery(DeliveryError::Declined("start")))
        ));
        let done = journal.transition(&b, |d| d.complete(landed(&b))).unwrap();
        assert!(matches!(done.delivery.state, DeliveryState::Completed { .. }));
    }

    #[test]
    fn tooth_mismatched_binding_under_same_key_errors() {
        let dir = tempfile::tempdir().unwrap();
        let journal = DeliveryJournal::open(dir.path());
        let (a, b) = (binding(2), binding(3));
        let key = a.key();
        assert_ne!(key, b.key());
        journal.transition_keyed(&key, &a, |d| d.start(0)).unwrap();
        assert!(matches!(journal.load_keyed(&key, &b), Err(JournalError::BindingMismatch { .. })));
        assert!(matches!(journal.transition_keyed(&key, &b, |d| d.start(0)), Err(JournalError::BindingMismatch { .. })));
    }

    #[test]
    fn journal_finds_latest_revision_across_many_refusals() {
        let dir = tempfile::tempdir().unwrap();
        let b = binding(4);
        let journal = DeliveryJournal::open(dir.path());
        for round in 0..37u64 {
            journal.transition(&b, |d| d.start(round)).unwrap();
            journal.transition(&b, |d| d.refused(round)).unwrap();
        }
        let stored = journal.load(&b).unwrap();
        assert_eq!(stored.rev, 74);
        assert_eq!(stored.delivery.state, DeliveryState::Refused { attempts: 37, not_before: 36 });
    }

    #[test]
    fn tooth_concurrent_starts_send_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let b = binding(5);
        let journal = DeliveryJournal::open(dir.path());
        let wins: usize = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8).map(|_| scope.spawn(|| journal.transition(&b, |d| d.start(0)).is_ok())).collect();
            handles.into_iter().map(|h| h.join().unwrap() as usize).sum()
        });
        assert_eq!(wins, 1);
        assert_eq!(journal.load(&b).unwrap().delivery.sends, 1);
    }

    #[test]
    fn tooth_an_outstanding_send_cannot_be_declined_unread() {
        let b = binding(2);
        let unknown = Delivery::fresh(b.clone()).start(0).unwrap();
        assert_eq!(unknown.declined(conflict()), Err(DeliveryError::OutcomeUnknown));
        // Read the destination: it either holds the tip or it does not.
        assert!(unknown.refused(1).unwrap().declined(conflict()).is_ok());
        assert!(unknown.complete(landed(&b)).is_ok());
    }

    #[test]
    fn binding_keys_are_domain_separated() {
        let b = binding(2);
        assert_ne!(b.key(), Digest32::blake3(&canonical_json(&b).unwrap()));
        assert_ne!(b.key(), Binding::tip_key(&b.repo, &b.target_ref, &b.lane_tip));
        assert_ne!(Binding::tip_key("repo", "refs/heads/main", &oid(2)), Binding::tip_key("repo2", "refs/heads/main", &oid(2)));
    }

    /// The recovery pointer: a send made against one base is found again
    /// from the lane tip alone, after the base (and so the key) has changed.
    #[test]
    fn tooth_tip_pointer_finds_an_outstanding_send_across_rebinding() {
        let dir = tempfile::tempdir().unwrap();
        let journal = DeliveryJournal::open(dir.path());
        let first = binding(2);
        assert_eq!(journal.latest_for_tip(&first.repo, &first.target_ref, &first.lane_tip).unwrap(), None);
        journal.note_tip(&first).unwrap();
        journal.note_tip(&first).unwrap();
        journal.transition(&first, |d| d.start(1)).unwrap();

        // A new process, composing against a moved base, has another key.
        let reopened = DeliveryJournal::open(dir.path());
        let second = Binding { expected_old: oid(77), merged_head: oid(78), ..first.clone() };
        assert_ne!(first.key(), second.key());
        assert_eq!(reopened.load(&second).unwrap().delivery.state, DeliveryState::Fresh);
        let outstanding = reopened.latest_for_tip(&first.repo, &first.target_ref, &first.lane_tip).unwrap().unwrap();
        assert_eq!(outstanding.delivery.binding, first);
        assert_eq!(outstanding.delivery.state, DeliveryState::Unknown);

        // Once settled and rebound, the pointer names the new binding.
        reopened.transition(&first, |d| d.refused(5)).unwrap();
        reopened.note_tip(&second).unwrap();
        let latest = reopened.latest_for_tip(&first.repo, &first.target_ref, &first.lane_tip).unwrap().unwrap();
        assert_eq!(latest.delivery.binding, second);
        assert_eq!(reopened.latest_for_tip("elsewhere", &first.target_ref, &first.lane_tip).unwrap(), None);
    }

    /// A record read from disk may hold any counter value.
    #[test]
    fn tooth_a_saturated_send_counter_refuses_instead_of_wrapping() {
        let b = binding(2);
        let text = serde_json::to_string(&Delivery {
            binding: b.clone(),
            state: DeliveryState::Refused { attempts: u32::MAX, not_before: 0 },
            sends: u32::MAX,
        })
        .unwrap();
        let saturated: Delivery = serde_json::from_str(&text).unwrap();
        assert_eq!(saturated.start(10), Err(DeliveryError::SendsExhausted));
        // Nothing else about the record is disturbed: it can still be declined or completed.
        assert!(saturated.declined(conflict()).is_ok());
        assert!(saturated.complete(landed(&b)).is_ok());
        let one_left = Delivery { sends: u32::MAX - 1, ..saturated.clone() };
        assert_eq!(one_left.start(10).unwrap().sends, u32::MAX);

        let dir = tempfile::tempdir().unwrap();
        let journal = DeliveryJournal::open(dir.path());
        journal.transition(&b, |_| Ok(saturated.clone())).unwrap();
        assert!(matches!(journal.transition(&b, |d| d.start(10)), Err(JournalError::Delivery(DeliveryError::SendsExhausted))));
        assert_eq!(journal.load(&b).unwrap().delivery, saturated);
    }
}
