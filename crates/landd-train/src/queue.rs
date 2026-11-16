//! When a batch leaves the station, and who is waiting for it.
//!
//! The queue is keyed by lane: a lane that is submitted again replaces its
//! own earlier entry, so a re-pushed lane lands its new tip and not both.
//! An entry may carry a time before which it is not ready (a refused push
//! backing off). The queue can be saved after every change and loaded at
//! start, so lanes survive a restart.

use crate::compose::Candidate;
use landd_core::{fsx, LandConfig, Oid};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::Path;

/// Whether an idle train should take a batch now. A queue of one leaves at
/// once: with nobody to share the run with, waiting buys nothing. Two or more
/// wait until the oldest has waited `batch_coalesce_ms`, or the batch is full.
pub fn batch_ready(depth: usize, oldest_wait_ms: u64, config: &LandConfig) -> bool {
    match depth {
        0 => false,
        1 => true,
        n => n >= config.max_batch_size || oldest_wait_ms >= config.batch_coalesce_ms,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    lane: String,
    tip: Oid,
    /// When it joined the queue, on the queue's own clock.
    since_ms: u64,
    /// Unix seconds before which it must not be sent again.
    not_before: u64,
}

/// What `push` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pushed {
    Added,
    /// The lane was waiting with another tip, which this one replaces.
    Replaced,
    /// The lane was already waiting with this tip.
    Duplicate,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Queue {
    waiting: VecDeque<Entry>,
}

impl Queue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    /// Enqueue at `now_ms`, not to be sent before `not_before` (unix seconds).
    pub fn push(&mut self, candidate: Candidate, now_ms: u64, not_before: u64) -> Pushed {
        if let Some(entry) = self.waiting.iter_mut().find(|entry| entry.lane == candidate.lane) {
            if entry.tip == candidate.tip {
                entry.not_before = entry.not_before.max(not_before);
                return Pushed::Duplicate;
            }
            // The newer tip takes the lane's place in line.
            entry.tip = candidate.tip;
            entry.not_before = not_before;
            return Pushed::Replaced;
        }
        self.waiting.push_back(Entry { lane: candidate.lane, tip: candidate.tip, since_ms: now_ms, not_before });
        Pushed::Added
    }

    pub fn waiting(&self) -> impl Iterator<Item = Candidate> + '_ {
        self.waiting.iter().map(|entry| Candidate { lane: entry.lane.clone(), tip: entry.tip })
    }

    fn ready(&self, now_s: u64) -> impl Iterator<Item = &Entry> {
        self.waiting.iter().filter(move |entry| entry.not_before <= now_s)
    }

    /// Up to `max_batch_size` ready candidates in arrival order, when a batch is due.
    pub fn take_batch(&mut self, now_ms: u64, now_s: u64, config: &LandConfig) -> Option<Vec<Candidate>> {
        let depth = self.ready(now_s).count();
        let oldest = self.ready(now_s).map(|entry| entry.since_ms).min()?;
        if !batch_ready(depth, now_ms.saturating_sub(oldest), config) {
            return None;
        }
        let mut batch = Vec::new();
        self.waiting.retain(|entry| {
            let take = entry.not_before <= now_s && batch.len() < config.max_batch_size;
            if take {
                batch.push(Candidate { lane: entry.lane.clone(), tip: entry.tip });
            }
            !take
        });
        Some(batch)
    }

    /// Milliseconds until the waiting candidates become a batch on their
    /// own; `None` when nothing is waiting.
    pub fn due_in_ms(&self, now_ms: u64, now_s: u64, config: &LandConfig) -> Option<u64> {
        let backing_off = self.waiting.iter().filter(|e| e.not_before > now_s).map(|e| (e.not_before - now_s) * 1000).min();
        let depth = self.ready(now_s).count();
        let Some(oldest) = self.ready(now_s).map(|entry| entry.since_ms).min() else {
            return backing_off;
        };
        if batch_ready(depth, now_ms.saturating_sub(oldest), config) {
            return Some(0);
        }
        let window = (oldest + config.batch_coalesce_ms).saturating_sub(now_ms);
        Some(backing_off.map_or(window, |wait| wait.min(window)))
    }

    /// Durably replace the saved queue at `path`.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let bytes = landd_core::canonical_json(self).map_err(std::io::Error::other)?;
        fsx::replace_atomic(path, &bytes, true)
    }

    /// The queue saved at `path`; empty when there is none. Waiting times
    /// restart from zero: the saved clock belonged to another process.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let Some(bytes) = fsx::read_optional(path)? else {
            return Ok(Self::new());
        };
        let mut queue: Self =
            serde_json::from_slice(&bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        queue.waiting.iter_mut().for_each(|entry| entry.since_ms = 0);
        Ok(queue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(n: u8) -> Candidate {
        Candidate { lane: format!("lane-{n}"), tip: Oid::from_slice(&[n; 20]).unwrap() }
    }

    #[test]
    fn tooth_a_queue_of_one_never_waits() {
        let config = LandConfig { batch_coalesce_ms: 60_000, ..LandConfig::default() };
        assert!(batch_ready(1, 0, &config));
        assert!(!batch_ready(0, u64::MAX, &config));
        let mut queue = Queue::new();
        queue.push(candidate(1), 1000, 0);
        assert_eq!(queue.due_in_ms(1000, 50, &config), Some(0));
        assert_eq!(queue.take_batch(1000, 50, &config).unwrap().len(), 1);
        assert!(queue.take_batch(1000, 50, &config).is_none());
        assert_eq!(queue.due_in_ms(1000, 50, &config), None);
    }

    #[test]
    fn several_coalesce_until_the_window_or_a_full_batch() {
        let config = LandConfig { batch_coalesce_ms: 250, max_batch_size: 3, ..LandConfig::default() };
        let mut queue = Queue::new();
        assert_eq!(queue.push(candidate(1), 1000, 0), Pushed::Added);
        assert_eq!(queue.push(candidate(2), 1100, 0), Pushed::Added);
        assert_eq!(queue.push(candidate(2), 1150, 0), Pushed::Duplicate);
        assert!(queue.take_batch(1200, 9, &config).is_none());
        assert_eq!(queue.due_in_ms(1200, 9, &config), Some(50));
        assert_eq!(queue.take_batch(1250, 9, &config).unwrap().len(), 2);

        for n in 1..=5 {
            queue.push(candidate(n), 2000, 0);
        }
        // Full: leaves at once, three at a time, in arrival order.
        let first = queue.take_batch(2000, 9, &config).unwrap();
        assert_eq!(first.iter().map(|c| c.lane.as_str()).collect::<Vec<_>>(), ["lane-1", "lane-2", "lane-3"]);
        assert!(queue.take_batch(2001, 9, &config).is_none());
        assert_eq!(queue.take_batch(2250, 9, &config).unwrap().len(), 2);
    }

    /// A lane pushed again lands its new tip only.
    #[test]
    fn tooth_a_resubmitted_lane_replaces_its_stale_tip() {
        let config = LandConfig::default();
        let mut queue = Queue::new();
        queue.push(candidate(1), 0, 0);
        let newer = Candidate { lane: "lane-1".into(), tip: Oid::from_slice(&[9; 20]).unwrap() };
        assert_eq!(queue.push(newer.clone(), 10, 0), Pushed::Replaced);
        assert_eq!(queue.len(), 1);
        assert_eq!(queue.take_batch(10, 0, &config).unwrap(), vec![newer]);
    }

    /// A refused lane waits out its backoff instead of spinning.
    #[test]
    fn tooth_entries_are_not_taken_before_their_time() {
        let config = LandConfig::default();
        let mut queue = Queue::new();
        queue.push(candidate(1), 0, 105);
        queue.push(candidate(2), 0, 0);
        assert_eq!(queue.take_batch(0, 100, &config).unwrap(), vec![candidate(2)]);
        assert!(queue.take_batch(10, 100, &config).is_none());
        assert_eq!(queue.due_in_ms(10, 100, &config), Some(5000));
        assert!(queue.take_batch(10, 104, &config).is_none());
        assert_eq!(queue.take_batch(10, 105, &config).unwrap(), vec![candidate(1)]);
    }

    #[test]
    fn the_queue_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queue.json");
        assert!(Queue::load(&path).unwrap().is_empty());
        let mut queue = Queue::new();
        queue.push(candidate(1), 5000, 0);
        queue.push(candidate(2), 6000, 77);
        queue.save(&path).unwrap();
        let loaded = Queue::load(&path).unwrap();
        assert_eq!(loaded.waiting().collect::<Vec<_>>(), vec![candidate(1), candidate(2)]);
        assert_eq!(loaded.clone().take_batch(0, 0, &LandConfig::default()).unwrap(), vec![candidate(1)]);
        std::fs::write(&path, b"not json").unwrap();
        assert!(Queue::load(&path).is_err());
    }
}
