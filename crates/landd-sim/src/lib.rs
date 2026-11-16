//! Offline replay of a `fleet` land ledger.
//!
//! [`ledger`] reads `land_runs.jsonl` as it was written. [`sim`] reports
//! what the ledger shows about what happened, and, only when the ledger
//! records which test modules each run selected and what they cost, replays
//! its arrivals through a discrete-event model of the batch train. When
//! those inputs are missing the replay says so; it does not fill them in.

pub mod ledger;
pub mod sim;

pub use ledger::{parse_ledger, Class, LandRun, Ledger, ModuleCosts, Timings};
pub use sim::{simulate, Observed, Replay, Report, Side, SimConfig};
