//! `FileFacts`: everything the reduce pass may ask about one blob.
//!
//! Facts depend only on the blob's bytes and its [`FileKind`], never on the
//! rule pack, so one cached summary serves every rule and every commit that
//! contains the blob.

use landd_core::Digest32;
use serde::{Deserialize, Serialize};

/// Bumped whenever the extractor's output for some input changes. It is part
/// of every cache path, so old summaries are never read as new ones.
pub const FACTS_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileKind {
    Python,
    /// Makefiles, justfiles, shell scripts and CI YAML: scanned by line.
    Recipe,
}

impl FileKind {
    pub fn of_path(path: &str) -> Option<Self> {
        let name = path.rsplit('/').next().unwrap_or(path);
        if name.ends_with(".py") {
            return Some(Self::Python);
        }
        let recipe_name = matches!(name, "Makefile" | "makefile" | "GNUmakefile" | "justfile" | "Justfile" | "Procfile")
            || name.starts_with("Dockerfile");
        let recipe_ext = [".mk", ".sh", ".bash", ".yml", ".yaml", ".just"].iter().any(|ext| name.ends_with(ext));
        (recipe_name || recipe_ext).then_some(Self::Recipe)
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Python => "py",
            Self::Recipe => "recipe",
        }
    }
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
    pub line: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlockSite {
    pub line: u32,
    pub func: String,
    pub call: String,
    pub nonblocking: bool,
    pub unlock: bool,
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
    /// The parser reported a syntax error; facts cover what did parse.
    pub parse_error: bool,
    /// Nesting was too deep to walk in full.
    pub truncated: bool,
    pub imports: Vec<Import>,
    /// Module loads whose target is not a literal (`importlib.import_module(x)`, `exec`, …).
    pub dynamic_loads: Vec<Site>,
    /// Whole-tree scans: `os.walk`, `glob`, `rglob`, `git ls-files`, …
    pub scans: Vec<Site>,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_come_from_the_file_name() {
        assert_eq!(FileKind::of_path("a/b/c.py"), Some(FileKind::Python));
        for recipe in ["Makefile", "ci/build.sh", ".github/workflows/ci.yml", "Dockerfile.dev", "justfile", "x.mk"] {
            assert_eq!(FileKind::of_path(recipe), Some(FileKind::Recipe), "{recipe}");
        }
        for other in ["a.pyc", "README.md", "data.json", "py", "x.python"] {
            assert_eq!(FileKind::of_path(other), None, "{other}");
        }
    }
}
