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
//! `Declined` is terminal against `start`, `refused` and `declined`.
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
    /// `BLAKE3(canonical_binding)`.
    pub fn key(&self) -> Digest32 {
        Digest32::blake3(&canonical_json(self).expect("a binding has no floats"))
    }
}

/// Proof read from the destination: `lane_tip` is an ancestor of
/// `remote_head`, the value of `target_ref` on the forge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AncestryEvidence {
    pub target_ref: String,
    pub remote_head: Oid,
    pub lane_tip: Oid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DeclineEvidence {
    Conflict { conflicting_paths: Vec<String> },
    NewRed { why_not: Vec<Blocker> },
    RefusalsExhausted { attempts: u32 },
    Other { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeliveryState {
    Fresh,
    /// A send was started and its outcome has not been read from the destination.
    Unknown,
    /// The destination was read and does not hold the commit; retry at `not_before`.
    Refused { attempts: u32, not_before: u64 },
    Declined { evidence: DeclineEvidence },
    Completed { evidence: AncestryEvidence },
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
    #[error("evidence is for another lane tip or target ref")]
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
            DeliveryState::Refused { not_before, .. } => {
                return Err(DeliveryError::NotBefore { not_before: *not_before, now })
            }
            DeliveryState::Unknown => return Err(DeliveryError::OutcomeUnknown),
            DeliveryState::Declined { .. } => return Err(DeliveryError::Declined("start")),
            DeliveryState::Completed { .. } => return Err(DeliveryError::Completed),
        }
        let mut next = self.next(DeliveryState::Unknown);
        next.sends += 1;
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
            DeliveryState::Fresh | DeliveryState::Unknown | DeliveryState::Refused { .. } => {
                Ok(self.next(DeliveryState::Declined { evidence }))
            }
            DeliveryState::Declined { .. } => Err(DeliveryError::Declined("declined")),
            DeliveryState::Completed { .. } => Err(DeliveryError::Completed),
        }
    }

    /// Destination completion dominates: succeeds from every state, given
    /// evidence for this binding. Completing twice keeps the first evidence.
    pub fn complete(&self, evidence: AncestryEvidence) -> Result<Self, DeliveryError> {
        if evidence.lane_tip != self.binding.lane_tip || evidence.target_ref != self.binding.target_ref {
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

    fn rev_path(&self, key: &Digest32, rev: u64) -> PathBuf {
        let hex = key.to_hex();
        self.root.join(&hex[..2]).join(&hex[2..4]).join(&hex).join(format!("r{rev:08}.json"))
    }

    fn exists(&self, key: &Digest32, rev: u64) -> Result<bool, JournalError> {
        let path = self.rev_path(key, rev);
        path.try_exists().map_err(|source| JournalError::Io { path, source })
    }

    /// Highest revision on disk, 0 when there is none.
    fn latest_rev(&self, key: &Digest32) -> Result<u64, JournalError> {
        if !self.exists(key, 1)? {
            return Ok(0);
        }
        let (mut low, mut high) = (1u64, 2u64);
        while high <= MAX_REVISIONS && self.exists(key, high)? {
            low = high;
            high *= 2;
        }
        // Invariant: `low` exists, `high` does not (or is past the bound).
        let mut high = high.min(MAX_REVISIONS + 1);
        while high - low > 1 {
            let mid = low + (high - low) / 2;
            if self.exists(key, mid)? {
                low = mid;
            } else {
                high = mid;
            }
        }
        Ok(low)
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
    /// state that writer left.
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
        AncestryEvidence { target_ref: b.target_ref.clone(), remote_head: oid(200), lane_tip: b.lane_tip }
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
        for state in [Delivery::fresh(b.clone()), Delivery::fresh(b.clone()).start(0).unwrap()] {
            assert_eq!(state.complete(other_tip.clone()), Err(DeliveryError::EvidenceMismatch));
            assert_eq!(state.complete(other_ref.clone()), Err(DeliveryError::EvidenceMismatch));
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
        assert!(matches!(
            reopened.transition(&b, |d| d.start(6)),
            Err(JournalError::Delivery(DeliveryError::OutcomeUnknown))
        ));
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
        assert!(matches!(
            journal.transition_keyed(&key, &b, |d| d.start(0)),
            Err(JournalError::BindingMismatch { .. })
        ));
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
            let handles: Vec<_> =
                (0..8).map(|_| scope.spawn(|| journal.transition(&b, |d| d.start(0)).is_ok())).collect();
            handles.into_iter().map(|h| h.join().unwrap() as usize).sum()
        });
        assert_eq!(wins, 1);
        assert_eq!(journal.load(&b).unwrap().delivery.sends, 1);
    }
}
