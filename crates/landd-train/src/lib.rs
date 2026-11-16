//! The speculative batch merge train.
//!
//! 1. [`compose`]: merge each candidate onto the previous one with
//!    `git merge-tree --write-tree`; a candidate that cannot join the chain
//!    is dropped on the spot and its peers carry on.
//! 2. [`train`]: judge the tip of the chain against the base ("no redder than
//!    base"), running only the units whose cones moved, in isolated child
//!    processes ([`runner`]).
//! 3. On a new red, split the batch to isolate the culprits, decline them
//!    with their blockers, and land everyone else.
//! 4. Push the chain of two-parent merges once, as a fast-forward under a
//!    lease, then read the push destination and record what it holds.

pub mod compose;
pub mod cones;
pub mod queue;
pub mod runner;
pub mod train;

pub use compose::{compose, valid_lane, Candidate, Committer, Composition, Dropped, Link};
pub use cones::{ConeSource, ManifestCones, PythonCones, UnitCones};
pub use queue::{batch_ready, Pushed, Queue};
pub use runner::{RunOutcome, Runner, RunnerConfig, RunnerError, UnitJob, UnitRun};
pub use train::{BatchReport, CandidateOutcome, Train, TrainError};
