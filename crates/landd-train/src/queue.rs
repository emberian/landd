//! When a batch leaves the station.

use crate::compose::Candidate;
use landd_core::LandConfig;
use std::collections::VecDeque;

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

#[derive(Debug, Default)]
pub struct Queue {
    waiting: VecDeque<(Candidate, u64)>,
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

    /// Enqueue at `now_ms`. A tip that is already waiting is not added twice.
    pub fn push(&mut self, candidate: Candidate, now_ms: u64) -> bool {
        if self.waiting.iter().any(|(waiting, _)| waiting.tip == candidate.tip) {
            return false;
        }
        self.waiting.push_back((candidate, now_ms));
        true
    }

    pub fn waiting(&self) -> impl Iterator<Item = &Candidate> {
        self.waiting.iter().map(|(candidate, _)| candidate)
    }

    /// Up to `max_batch_size` candidates in arrival order, when a batch is due.
    pub fn take_batch(&mut self, now_ms: u64, config: &LandConfig) -> Option<Vec<Candidate>> {
        let oldest = self.waiting.front()?.1;
        if !batch_ready(self.waiting.len(), now_ms.saturating_sub(oldest), config) {
            return None;
        }
        let take = self.waiting.len().min(config.max_batch_size);
        Some(self.waiting.drain(..take).map(|(candidate, _)| candidate).collect())
    }

    /// Milliseconds until the waiting candidates become a batch on their own.
    pub fn due_in_ms(&self, now_ms: u64, config: &LandConfig) -> Option<u64> {
        let oldest = self.waiting.front()?.1;
        if batch_ready(self.waiting.len(), now_ms.saturating_sub(oldest), config) {
            return Some(0);
        }
        Some((oldest + config.batch_coalesce_ms).saturating_sub(now_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use landd_core::Oid;

    fn candidate(n: u8) -> Candidate {
        Candidate { lane: format!("lane-{n}"), tip: Oid::from_slice(&[n; 20]).unwrap() }
    }

    #[test]
    fn tooth_a_queue_of_one_never_waits() {
        let config = LandConfig { batch_coalesce_ms: 60_000, ..LandConfig::default() };
        assert!(batch_ready(1, 0, &config));
        assert!(!batch_ready(0, u64::MAX, &config));
        let mut queue = Queue::new();
        queue.push(candidate(1), 1000);
        assert_eq!(queue.due_in_ms(1000, &config), Some(0));
        assert_eq!(queue.take_batch(1000, &config).unwrap().len(), 1);
        assert!(queue.take_batch(1000, &config).is_none());
    }

    #[test]
    fn several_coalesce_until_the_window_or_a_full_batch() {
        let config = LandConfig { batch_coalesce_ms: 250, max_batch_size: 3, ..LandConfig::default() };
        let mut queue = Queue::new();
        assert!(queue.push(candidate(1), 1000));
        assert!(queue.push(candidate(2), 1100));
        assert!(!queue.push(candidate(2), 1150));
        assert!(queue.take_batch(1200, &config).is_none());
        assert_eq!(queue.due_in_ms(1200, &config), Some(50));
        assert_eq!(queue.take_batch(1250, &config).unwrap().len(), 2);

        for n in 1..=5 {
            queue.push(candidate(n), 2000);
        }
        // Full: leaves at once, three at a time, in arrival order.
        let first = queue.take_batch(2000, &config).unwrap();
        assert_eq!(first.iter().map(|c| c.lane.as_str()).collect::<Vec<_>>(), ["lane-1", "lane-2", "lane-3"]);
        assert!(queue.take_batch(2001, &config).is_none());
        assert_eq!(queue.take_batch(2250, &config).unwrap().len(), 2);
    }
}
