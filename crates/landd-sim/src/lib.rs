//! Offline replay of a `fleet` land ledger.
//!
//! [`ledger`] reads `land_runs.jsonl` as it was written; [`sim`] replays its
//! arrivals through a discrete-event model of the batch train and reports
//! both sides next to each other.

pub mod ledger;
pub mod sim;

pub use ledger::{parse_ledger, LandRun, Ledger, ModuleCosts};
pub use sim::{simulate, Report, Side, SimConfig};
