//! `FileFacts`: everything the reduce pass may ask about one blob.
//!
//! Facts depend only on the blob's bytes and its [`FileKind`], never on the
//! path or the rule pack, so one cached summary serves every rule and every
//! commit that contains the blob. Anything that depends on where the file
//! sits (`__file__`, relative imports) is recorded symbolically and resolved
//! when the tree is known.

use landd_core::Digest32;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Identifies the code that produces facts: the crate version, the Python
/// grammar, and the source of the extractor, the fact types and the reducer.
/// It is part of every cache path, so a summary never outlives the code
/// that made it and nobody has to remember to bump a number.
pub fn facts_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let language: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
        let digest = Digest32::tagged(
            "ast-sweep facts version",
            &[
                env!("CARGO_PKG_VERSION").as_bytes(),
                &(language.abi_version() as u64).to_le_bytes(),
                &(language.node_kind_count() as u64).to_le_bytes(),
                include_bytes!("extract.rs"),
                include_bytes!("facts.rs"),
                include_bytes!("reduce.rs"),
            ],
        );
        format!("f{}", &digest.to_hex()[..16])
    })
}

/// How a blob is read, decided from its path and git mode alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileKind {
    Python,
    /// Makefiles, justfiles, shell scripts and CI YAML: scanned by line.
    Recipe,
    /// An executable or extensionless file: Python or a recipe when its
    /// first line says so (`#!…python`, `#!…sh`), nothing otherwise.
    Sniff,
    /// A symbolic link; the blob is its target.
    Link,
}

pub const MODE_SYMLINK: u32 = 0o120000;
pub const MODE_GITLINK: u32 = 0o160000;
pub const MODE_EXECUTABLE: u32 = 0o100755;

impl FileKind {
    pub fn of_entry(path: &str, mode: u32) -> Option<Self> {
        if mode == MODE_SYMLINK {
            return Some(Self::Link);
        }
        if mode == MODE_GITLINK {
            return None;
        }
        let name = path.rsplit('/').next().unwrap_or(path);
        if name.ends_with(".py") {
            return Some(Self::Python);
        }
        let recipe_name = matches!(name, "Makefile" | "makefile" | "GNUmakefile" | "justfile" | "Justfile" | "Procfile")
            || name.starts_with("Dockerfile");
        let recipe_ext = [".mk", ".sh", ".bash", ".yml", ".yaml", ".just"].iter().any(|ext| name.ends_with(ext));
        if recipe_name || recipe_ext {
            return Some(Self::Recipe);
        }
        (mode == MODE_EXECUTABLE || !name.contains('.')).then_some(Self::Sniff)
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Python => "py",
            Self::Recipe => "recipe",
            Self::Sniff => "sniff",
            Self::Link => "link",
        }
    }
}

/// What the bytes turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Language {
    Python,
    Recipe,
    #[default]
    Other,
}

/// A place in a file. `func` is the enclosing `Class.method` path, or empty
/// at module level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Site {
    pub line: u32,
    pub func: String,
    pub what: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Import {
    /// Dotted module; empty for `from . import x`.
    pub module: String,
    /// Leading dots of a relative import.
    pub level: u8,
    /// Names after `import` in a `from` import (`*` for a wildcard).
    pub names: Vec<String>,
    /// Top-level symbol owning this import (`""` when executed at module import time).
    pub owner: String,
    /// `(imported_name, local_name)` bindings (`("", bound)` for `import a.b [as c]`).
    pub bindings: Vec<(String, String)>,
    pub line: u32,
}

/// A reference to an imported binding from a specific top-level symbol scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScopedRef {
    /// `""` when evaluated at module import time, else the top-level symbol name.
    pub owner: String,
    /// Local binding head (`"support"`, `"a"`).
    pub head: String,
    /// Outermost dotted chain (`"support.hold_bindings"`, or `"support"` when bare).
    pub dotted: String,
    pub call: bool,
}

/// Where a path expression starts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Anchor {
    /// The path of the file itself (`__file__`).
    File,
    /// The root of the tree: the working directory tests run in.
    Root,
    /// A name defined in another module, as a dotted path with import
    /// aliases resolved; leading dots mean a relative import.
    Name(String),
}

/// A path built from an anchor by going `up` directories and then down
/// `tail`. With `open`, something unknown follows the tail.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Place {
    pub anchor: Anchor,
    pub up: u16,
    pub tail: String,
    pub open: bool,
}

/// What a path expression may name, as far as its literals say.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Reach {
    pub places: Vec<Place>,
    /// Built from a place in a way that loses where it points.
    pub unknown: bool,
    /// Nothing ties it to a known place: a parameter, an attribute, a call.
    pub opaque: bool,
}

impl Reach {
    /// Provably nothing in the tree (a temporary path, an absolute path).
    pub fn is_nothing(&self) -> bool {
        self.places.is_empty() && !self.unknown && !self.opaque
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadShape {
    /// The file's content.
    File,
    /// Whether it exists, and what kind of thing it is.
    Probe,
    /// The names directly inside a directory.
    Level,
    /// Everything below a directory.
    Subtree,
    /// The paths matching these patterns below the place (`.glob`).
    Glob(Vec<String>),
    /// The paths matching these patterns at any depth (`.rglob`).
    RGlob(Vec<String>),
    /// The place is itself a glob pattern (`glob.glob`).
    Pattern,
    /// A Python file loaded and run by path.
    Module,
    /// A child process: it can read whatever it is shown.
    Process,
}

/// One place where a file reads the tree as data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadSite {
    pub line: u32,
    pub func: String,
    /// Top-level symbol owning this site (`""` when executed at module import time).
    pub owner: String,
    pub what: String,
    pub shape: ReadShape,
    pub reach: Reach,
    /// True when `reach.opaque` comes solely from `owner`'s own parameters and
    /// every intra-module call to `owner` supplies non-opaque arguments.
    #[serde(default)]
    pub internal_clean: bool,
}

/// A module load whose target is not a literal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicLoad {
    pub line: u32,
    pub func: String,
    /// Top-level symbol owning this load (`""` when executed at module import time).
    pub owner: String,
    pub what: String,
    /// The literal start of the module name, when the source shows one:
    /// `import_module(f"pkg.plugins.{name}")` has `pkg.plugins.`. A leading
    /// `@module.` or `@package.` stands for the file's own module or package.
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlockSite {
    pub line: u32,
    pub func: String,
    pub call: String,
    pub nonblocking: bool,
    pub unlock: bool,
    /// The flags argument names no `LOCK_*` constant (it is a variable).
    pub flags_opaque: bool,
    /// Inside a loop that sleeps (a poll loop).
    pub polled: bool,
    /// Every enclosing sleeping loop shows a bound (see `extract`).
    pub poll_bounded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrftimeSite {
    pub line: u32,
    pub func: String,
    /// The format string when it is a literal.
    pub format: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsRead {
    pub line: u32,
    /// Final name of the callee: `setting`, `or_default`, `get`, …
    pub reader: String,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionFact {
    /// `Class.method` path.
    pub name: String,
    pub line: u32,
    /// Digest of the body's syntax tree, blind to comments, docstrings and layout.
    pub body_hash: Digest32,
    /// Statements in the body, docstring excluded.
    pub statements: u32,
}

/// A name the file calls, or an imported name it refers to, with import
/// aliases resolved (`from os import replace as r; r()` is `os.replace`).
/// References to locals and their attributes are not recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolRef {
    pub name: String,
    pub call: bool,
    /// First line it appears on.
    pub line: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFacts {
    pub language: Language,
    /// The parser reported a syntax error, or the bytes are not UTF-8;
    /// facts cover what did parse.
    pub parse_error: bool,
    /// Nesting was too deep to walk in full.
    pub truncated: bool,
    /// The blob was over the size limit and was not read.
    pub too_large: bool,
    /// For a symbolic link: its target text.
    pub link_target: Option<String>,
    pub imports: Vec<Import>,
    /// Module loads whose target is not a literal (`importlib.import_module(x)`,
    /// `exec`, a wildcard import that can hide one, …).
    pub dynamic_loads: Vec<DynamicLoad>,
    /// Reads of the tree as data: opens, existence probes, listings, walks,
    /// globs, modules loaded by path, child processes.
    pub reads: Vec<ReadSite>,
    /// Module-level names bound to paths, for the modules that import them.
    pub exports: Vec<(String, Reach)>,
    pub flocks: Vec<FlockSite>,
    /// `os.replace` / `os.rename` call sites.
    pub replaces: Vec<Site>,
    pub strftimes: Vec<StrftimeSite>,
    pub sys_executable: Vec<Site>,
    pub settings_reads: Vec<SettingsRead>,
    /// `except E as e: self.x = e`.
    pub exc_on_self: Vec<Site>,
    /// A bare `python` command (not `python3`, not `sys.executable`).
    pub bare_python: Vec<Site>,
    pub functions: Vec<FunctionFact>,
    /// Sorted by `(name, call)`.
    pub symbols: Vec<SymbolRef>,
    /// Names statically bound at module top-level.
    pub defined_symbols: Vec<String>,
    /// Intra-module `(from_owner, to_symbol_or_star)` dependencies.
    pub symbol_deps: Vec<(String, String)>,
    /// Direct intra-module calls `(from_owner, to_top_fn, forwards_own_param)`.
    #[serde(default)]
    pub internal_calls: Vec<(String, String, bool)>,
    /// Scoped references to imported bindings.
    pub external_refs: Vec<ScopedRef>,
    /// `(owner, resolved_callee)` for calls, used to scope `whole_tree_calls`.
    pub scoped_calls: Vec<(String, String)>,
}

impl FileFacts {
    /// Tree scans: listings, walks and globs.
    pub fn scans(&self) -> impl Iterator<Item = &ReadSite> {
        self.reads.iter().filter(|site| {
            matches!(
                site.shape,
                ReadShape::Level | ReadShape::Subtree | ReadShape::Glob(_) | ReadShape::RGlob(_) | ReadShape::Pattern
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_come_from_the_name_and_mode() {
        assert_eq!(FileKind::of_entry("a/b/c.py", 0o100644), Some(FileKind::Python));
        for recipe in ["Makefile", "ci/build.sh", ".github/workflows/ci.yml", "Dockerfile.dev", "justfile", "x.mk"] {
            assert_eq!(FileKind::of_entry(recipe, 0o100644), Some(FileKind::Recipe), "{recipe}");
        }
        for other in ["a.pyc", "README.md", "data.json", "x.python"] {
            assert_eq!(FileKind::of_entry(other, 0o100644), None, "{other}");
        }
        // Extensionless and executable files are sniffed; links are links whatever their name.
        assert_eq!(FileKind::of_entry("bin/tool", 0o100755), Some(FileKind::Sniff));
        assert_eq!(FileKind::of_entry("bin/tool", 0o100644), Some(FileKind::Sniff));
        assert_eq!(FileKind::of_entry("scripts/run.rb", 0o100755), Some(FileKind::Sniff));
        assert_eq!(FileKind::of_entry("a/link.py", MODE_SYMLINK), Some(FileKind::Link));
        assert_eq!(FileKind::of_entry("vendor/sub", MODE_GITLINK), None);
    }

    #[test]
    fn the_facts_version_names_the_extractor() {
        let version = facts_version();
        assert!(version.starts_with('f') && version.len() == 17, "{version}");
        assert_eq!(version, facts_version());
    }
}
