//! Shared foundation for `landd`: content-addressed identifiers, canonical
//! JSON, runtime configuration, the `Delivery` outbox, the v2 custody
//! envelope, cone admissibility and the git plumbing every other crate uses.

pub mod canon;
pub mod config;
pub mod custody;
pub mod delivery;
pub mod digest;
pub mod fsx;
pub mod git;
pub mod reasons;

pub use canon::{canonical_json, CanonError, CanonicalJson};
pub use config::{ConeSourceKind, ConfigError, CustodyMode, Isolation, LandConfig, UnitView};
pub use digest::{Digest32, Oid};
