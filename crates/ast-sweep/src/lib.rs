//! `ast-sweep`: one pass over a tree instead of sixty.
//!
//! * **Map** ([`extract`]): each blob is summarized once into [`FileFacts`],
//!   keyed by its git object id and cached forever ([`cache`]).
//! * **Reduce** ([`reduce`]): declarative rule packs ([`rules`]) are evaluated
//!   over the in-memory facts of the whole tree, and static Python import
//!   cones ([`imports`]) are exported for cone digests.

pub mod cache;
pub mod extract;
pub mod facts;
pub mod glob;
pub mod imports;
mod modules;
pub mod reduce;
pub mod rules;
pub mod sweep;

pub use cache::BlobFactsCache;
pub use facts::{FileFacts, FileKind};
pub use imports::{ImportCone, ImportGraph};
pub use reduce::{Finding, RuleVerdict, VerdictStatus};
pub use rules::{ImportConfig, Rule, RuleKind, RulePack};
pub use sweep::{run_sweep, sweep_dir, sweep_git, AllFacts, FileEntry, Source, SweepError, SweepReport, SweepStats};
