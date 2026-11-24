//! The static dependency graph of a Python tree and the cone of every test
//! unit.
//!
//! A unit's cone is everything its verdict can depend on:
//!
//! * the files reached by following imports from the test and from each
//!   `conftest.py` above it, including modules loaded by a literal path and
//!   Python child processes with a literal script or `-m` module;
//! * the files those modules read as data: opens, existence probes,
//!   listings, walks and globs whose path is built from `__file__`, the
//!   working directory or literals (see [`crate::extract`]);
//! * the files its `guards` and the pack's `always` list name;
//! * what a declared loader can load, while the loader's source agrees
//!   with the declaration.
//!
//! Whatever cannot be bounded widens the cone to the whole tree, and the
//! cone records why ([`Cause`]). Under [`ConeModel::Strict`] that includes
//! every read through a path the analysis cannot follow. Symbolic links are
//! followed inside the tree and widen when they leave it; an input is its
//! path, git mode and blob, so `chmod` and a gitlink bump move cones too.

use crate::facts::{Anchor, FileFacts, FileKind, Language, Place, Reach, ReadShape, MODE_SYMLINK};
use crate::glob::{select_one, Glob, GlobSet};
use crate::rules::{ConeModel, ImportConfig, UnverifiedLoaders};
use crate::sweep::{light_pool, AllFacts};
use landd_core::reasons::{cone_digest, cone_inputs_digest, cone_leaf, Cone, Input};
use landd_core::Digest32;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// How far a name is followed from module to module.
const MAX_NAME_HOPS: usize = 4;

/// Python 3 standard-library top-level module names (sorted). When no configured
/// source root explains `import select` or `import inspect`, Python resolves it
/// from the standard library unless a sibling file in the importer's own
/// directory shadows it; an unrelated subdirectory file (`land/checks/select.py`)
/// does not.
const PYTHON_STDLIB: &[&str] = &[
    "abc",
    "antigravity",
    "argparse",
    "array",
    "ast",
    "asyncio",
    "atexit",
    "base64",
    "bdb",
    "binascii",
    "bisect",
    "builtins",
    "bz2",
    "cProfile",
    "calendar",
    "cmath",
    "cmd",
    "code",
    "codecs",
    "codeop",
    "collections",
    "colorsys",
    "compileall",
    "concurrent",
    "configparser",
    "contextlib",
    "contextvars",
    "copy",
    "copyreg",
    "csv",
    "ctypes",
    "curses",
    "dataclasses",
    "datetime",
    "dbm",
    "decimal",
    "difflib",
    "dis",
    "doctest",
    "email",
    "encodings",
    "ensurepip",
    "enum",
    "errno",
    "faulthandler",
    "fcntl",
    "filecmp",
    "fileinput",
    "fnmatch",
    "fractions",
    "ftplib",
    "functools",
    "gc",
    "genericpath",
    "getopt",
    "getpass",
    "gettext",
    "glob",
    "graphlib",
    "grp",
    "gzip",
    "hashlib",
    "heapq",
    "hmac",
    "html",
    "http",
    "idlelib",
    "imaplib",
    "importlib",
    "inspect",
    "io",
    "ipaddress",
    "itertools",
    "json",
    "keyword",
    "linecache",
    "locale",
    "logging",
    "lzma",
    "mailbox",
    "marshal",
    "math",
    "mimetypes",
    "mmap",
    "modulefinder",
    "msvcrt",
    "multiprocessing",
    "netrc",
    "nt",
    "ntpath",
    "nturl2path",
    "numbers",
    "opcode",
    "operator",
    "optparse",
    "os",
    "pathlib",
    "pdb",
    "pickle",
    "pickletools",
    "pkgutil",
    "platform",
    "plistlib",
    "poplib",
    "posix",
    "posixpath",
    "pprint",
    "profile",
    "pstats",
    "pty",
    "pwd",
    "py_compile",
    "pyclbr",
    "pydoc",
    "pydoc_data",
    "pyexpat",
    "queue",
    "quopri",
    "random",
    "re",
    "readline",
    "reprlib",
    "resource",
    "rlcompleter",
    "runpy",
    "sched",
    "secrets",
    "select",
    "selectors",
    "shelve",
    "shlex",
    "shutil",
    "signal",
    "site",
    "smtplib",
    "socket",
    "socketserver",
    "sqlite3",
    "sre_compile",
    "sre_constants",
    "sre_parse",
    "ssl",
    "stat",
    "statistics",
    "string",
    "stringprep",
    "struct",
    "subprocess",
    "symtable",
    "sys",
    "sysconfig",
    "syslog",
    "tabnanny",
    "tarfile",
    "tempfile",
    "termios",
    "textwrap",
    "this",
    "threading",
    "time",
    "timeit",
    "tkinter",
    "token",
    "tokenize",
    "tomllib",
    "trace",
    "traceback",
    "tracemalloc",
    "tty",
    "turtle",
    "turtledemo",
    "types",
    "typing",
    "unicodedata",
    "unittest",
    "urllib",
    "uuid",
    "venv",
    "warnings",
    "wave",
    "weakref",
    "webbrowser",
    "winreg",
    "winsound",
    "wsgiref",
    "xml",
    "xmlrpc",
    "zipapp",
    "zipfile",
    "zipimport",
    "zlib",
    "zoneinfo",
];

/// Why a cone was widened to the whole tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Cause {
    /// A module load whose target is computed, in a file with no declaration.
    DynamicLoad,
    /// A declared loader whose source does not show where its loads go.
    UnverifiedLoader,
    /// A declared loader whose source loads something the declaration omits.
    ContradictedLoader,
    /// A module loaded from a path the analysis cannot resolve.
    UnresolvedLoad,
    /// A read below a known place through something that is not a literal.
    UnresolvedRead,
    /// A read through a path with no known origin.
    OpaqueRead,
    /// A child process, which can read whatever it is shown.
    Process,
    /// The file really does read or scan the whole tree.
    WholeTreeRead,
    /// A guard declares that the unit reads everything.
    GuardEverything,
    /// A call the pack lists as reading the whole tree.
    WholeTreeCall,
    /// The file did not parse, was too deeply nested, or is not UTF-8.
    ParseError,
    TooLarge,
    /// A relative import that names nothing in the tree.
    UnresolvedRelativeImport,
    /// A symbolic link that leaves the tree or points at nothing.
    LinkEscape,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedImport {
    pub file: u32,
    pub line: u32,
    pub import: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoaderStatus {
    /// Every dynamic load in the file shows a prefix the declaration covers.
    Verified,
    /// Some load shows nothing to check the declaration against.
    Unverifiable,
    /// Some load shows a target the declaration does not cover.
    Contradicted,
    /// The declaration names no file in the tree.
    Missing,
    /// The file has no dynamic load at all.
    NoDynamicLoad,
}

/// What became of one loader declaration on this tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoaderReport {
    pub declared: String,
    pub path: Option<String>,
    pub status: LoaderStatus,
    /// Whether the declaration is in force (it bounds the loader's cones).
    pub in_force: bool,
    pub detail: String,
}

#[derive(Debug, Clone)]
enum LinkTarget {
    File(u32),
    Dir(String),
    Escapes,
}

#[derive(Debug, Clone)]
struct Link {
    index: u32,
    target: LinkTarget,
}

/// Per-symbol execution states across all files, flattened to `u32` IDs so
/// cone reachability is a plain integer graph walk.
#[derive(Debug, Clone, Default)]
struct ScopeGraph {
    /// `(top_state, unit_state, all_state)` per file index in `AllFacts::files`.
    file_states: Vec<(u32, u32, u32)>,
    /// Owning file index for each state `0..state_edges.len()`.
    state_file: Vec<u32>,
    state_edges: Vec<Vec<u32>>,
    state_reads: Vec<Vec<u32>>,
    state_causes: Vec<Vec<Cause>>,
}

/// Nodes are indices into [`AllFacts::files`].
#[derive(Debug, Clone, Default)]
pub struct ImportGraph {
    /// Module name -> the files importing it depends on.
    by_name: HashMap<String, Vec<u32>>,
    /// The module name of each Python file under its deepest root.
    names: HashMap<u32, String>,
    edges: Vec<Vec<u32>>,
    /// Files a node reads as data.
    reads: Vec<Vec<u32>>,
    causes: Vec<Vec<Cause>>,
    scopes: ScopeGraph,
    /// Relative imports that name nothing in the tree.
    pub unresolved_relative: Vec<UnresolvedImport>,
    /// Top-level modules imported from outside the tree.
    pub external: BTreeSet<String>,
    pub loaders: Vec<LoaderReport>,
}

fn module_name(path: &str, root: &str) -> Option<String> {
    let root = root.trim_end_matches('/');
    let relative = if root.is_empty() { path } else { path.strip_prefix(root)?.strip_prefix('/')? };
    let stem = relative.strip_suffix(".py")?;
    let stem = stem.strip_suffix("/__init__").unwrap_or(if stem == "__init__" { "" } else { stem });
    (!stem.is_empty()).then(|| stem.replace('/', "."))
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("")
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn join(base: &str, tail: &str) -> String {
    match (base.is_empty(), tail.is_empty()) {
        (true, _) => tail.to_owned(),
        (_, true) => base.to_owned(),
        _ => format!("{base}/{tail}"),
    }
}

/// `target` as written in a link that sits in `dir`; `None` when it is
/// absolute or climbs out of the tree.
pub(crate) fn link_destination(dir: &str, target: &str) -> Option<String> {
    if target.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty()).collect();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    Some(parts.join("/"))
}

/// What a path expression names on this tree.
#[derive(Debug, Default)]
struct Resolved {
    /// `(path, an unknown suffix follows)`.
    bases: Vec<(String, bool)>,
    unknown: bool,
    opaque: bool,
}

#[derive(Default)]
struct NodeOut {
    targets: Vec<u32>,
    reads: Vec<u32>,
    causes: Vec<Cause>,
    unresolved: Vec<UnresolvedImport>,
    external: Vec<String>,
    loader: Option<LoaderReport>,
}

struct Context<'a> {
    all: &'a AllFacts,
    paths: Vec<&'a str>,
    config: &'a ImportConfig,
    links: Vec<Link>,
    link_at: HashMap<u32, usize>,
    /// Loader file -> (how it was declared, the path patterns it may load).
    declared: HashMap<u32, (String, Vec<String>)>,
    whole_calls: GlobSet,
    /// File stem (or package directory name) -> Python files.
    stems: HashMap<&'a str, Vec<u32>>,
    /// Directory name -> directories of that name that hold Python.
    dirs: HashMap<&'a str, Vec<&'a str>>,
    /// Precomputed `tsconfig` aliases, monorepo `package.json` workspaces, and lockfiles for TS/JS resolution.
    ts_index: crate::modules::TsProjectIndex,
}

impl Context<'_> {
    fn is_python(&self, index: u32) -> bool {
        self.all.files[index as usize].is_python()
    }

    /// The files a path names: itself, or the file a linked directory leads to.
    fn lookup(&self, path: &str, out: &mut Vec<u32>) -> bool {
        if let Some(index) = self.all.index_of(path) {
            out.push(index as u32);
            return true;
        }
        for link in &self.links {
            let LinkTarget::Dir(target) = &link.target else { continue };
            let here = self.all.files[link.index as usize].path.as_str();
            if let Some(rest) = path.strip_prefix(here).filter(|rest| rest.starts_with('/')) {
                if let Some(index) = self.all.index_of(&format!("{target}{rest}")) {
                    out.extend([link.index, index as u32]);
                    return true;
                }
            }
        }
        false
    }

    /// Select the files matching `patterns` into `out`, following links.
    /// Returns whether some pattern matches the whole tree.
    fn select(&self, patterns: &[String], segments: bool, out: &mut Vec<u32>, causes: &mut Vec<Cause>) -> bool {
        let mut whole = false;
        let start = out.len();
        for pattern in patterns {
            let glob = if segments { Glob::segments(pattern) } else { Glob::new(pattern) };
            if glob.is_everything() {
                whole = true;
                continue;
            }
            select_one(&glob, &self.paths, out);
            // A pattern that goes through a linked directory.
            for link in &self.links {
                let LinkTarget::Dir(target) = &link.target else { continue };
                let here = self.all.files[link.index as usize].path.as_str();
                if let Some(rest) = pattern.strip_prefix(here).filter(|rest| rest.starts_with('/')) {
                    let moved = format!("{target}{rest}");
                    let glob = if segments { Glob::segments(&moved) } else { Glob::new(&moved) };
                    select_one(&glob, &self.paths, out);
                    out.push(link.index);
                }
            }
        }
        // A selected link stands for what it points at.
        let mut beyond = Vec::new();
        for index in &out[start..] {
            match self.link_at.get(index).map(|at| &self.links[*at].target) {
                Some(LinkTarget::File(file)) => beyond.push(*file),
                Some(LinkTarget::Dir(dir)) => select_one(&Glob::new(&format!("{dir}/*")), &self.paths, &mut beyond),
                Some(LinkTarget::Escapes) => causes.push(Cause::LinkEscape),
                None => {}
            }
        }
        out.extend(beyond);
        whole
    }
}

/// The patterns one read of `base` covers; `None` when it cannot be bounded.
fn site_patterns(shape: &ReadShape, base: &str, open: bool, model: ConeModel) -> Option<Vec<String>> {
    let below = |tail: &str| join(base, tail);
    if open {
        // Something unknown follows the known directory. An enforced view
        // bounds it to that directory; analysis alone cannot rule out `..`.
        return (model == ConeModel::Hermetic).then(|| vec![base.to_owned(), below("**")]);
    }
    Some(match shape {
        ReadShape::File | ReadShape::Module | ReadShape::Pattern => vec![base.to_owned()],
        // Whether a directory exists, and which subdirectories a listing
        // shows, both depend on the existence of everything below it.
        ReadShape::Probe | ReadShape::Subtree | ReadShape::Level => vec![base.to_owned(), below("**")],
        ReadShape::Glob(tails) => tails.iter().map(|tail| below(tail)).collect(),
        ReadShape::RGlob(tails) => tails.iter().map(|tail| below(&format!("**/{tail}"))).collect(),
        ReadShape::Process => return None,
    })
}

impl ImportGraph {
    pub fn build(all: &AllFacts, config: &ImportConfig) -> Self {
        let count = all.files.len();
        let mut graph = Self {
            edges: vec![Vec::new(); count],
            reads: vec![Vec::new(); count],
            causes: vec![Vec::new(); count],
            ..Self::default()
        };
        let paths = all.paths();
        let mut roots: Vec<&str> = config.roots.iter().map(String::as_str).collect();
        roots.sort_by_key(|root| std::cmp::Reverse(root.len()));

        // Symbolic links, and where they lead.
        let mut links = Vec::new();
        for (index, file) in all.files.iter().enumerate() {
            if file.mode != MODE_SYMLINK {
                continue;
            }
            let written = file.facts.as_deref().and_then(|f| f.link_target.as_deref());
            let target = match written.and_then(|target| link_destination(parent(&file.path), target)) {
                Some(destination) => match all.index_of(&destination) {
                    Some(file) => LinkTarget::File(file as u32),
                    None => {
                        let below = format!("{destination}/");
                        let at = paths.partition_point(|probe| *probe < below.as_str());
                        match paths.get(at).is_some_and(|p| p.starts_with(below.as_str())) && !destination.is_empty() {
                            true => LinkTarget::Dir(destination),
                            false => LinkTarget::Escapes,
                        }
                    }
                },
                None => LinkTarget::Escapes,
            };
            links.push(Link { index: index as u32, target });
        }
        let link_at: HashMap<u32, usize> = links.iter().enumerate().map(|(at, link)| (link.index, at)).collect();

        // Module names. Two files claiming one name are both depended on.
        let claim = |by_name: &mut HashMap<String, Vec<u32>>, name: String, nodes: &[u32]| {
            let slot = by_name.entry(name).or_default();
            for node in nodes {
                if !slot.contains(node) {
                    slot.push(*node);
                }
            }
        };
        for (index, file) in all.files.iter().enumerate() {
            let index = index as u32;
            if file.is_python() {
                for root in &roots {
                    if let Some(name) = module_name(&file.path, root) {
                        graph.names.entry(index).or_insert_with(|| name.clone());
                        claim(&mut graph.by_name, name, &[index]);
                    }
                }
            }
        }
        for link in &links {
            let here = all.files[link.index as usize].path.as_str();
            for root in &roots {
                // The link as a module, and as a package.
                for spelled in [here.to_owned(), format!("{here}/__init__.py")] {
                    if let Some(name) = module_name(&spelled, root) {
                        claim(&mut graph.by_name, name, &[link.index]);
                    }
                }
                if let LinkTarget::Dir(target) = &link.target {
                    let below = format!("{target}/");
                    let start = paths.partition_point(|probe| *probe < below.as_str());
                    for (offset, path) in paths[start..].iter().enumerate() {
                        let Some(rest) = path.strip_prefix(below.as_str()) else { break };
                        let real = (start + offset) as u32;
                        if all.files[real as usize].is_python() {
                            if let Some(name) = module_name(&format!("{here}/{rest}"), root) {
                                claim(&mut graph.by_name, name, &[link.index, real]);
                            }
                        }
                    }
                }
            }
        }

        let mut stems: HashMap<&str, Vec<u32>> = HashMap::new();
        let mut dir_set: BTreeSet<&str> = BTreeSet::new();
        for (index, file) in all.files.iter().enumerate() {
            if !file.is_python() {
                continue;
            }
            let name = file_name(&file.path);
            let stem = match name.strip_suffix(".py") {
                Some("__init__") => file_name(parent(&file.path)),
                Some(stem) => stem,
                None => name,
            };
            stems.entry(stem).or_default().push(index as u32);
            let mut dir = parent(&file.path);
            while !dir.is_empty() && dir_set.insert(dir) {
                dir = parent(dir);
            }
        }
        let mut dirs: HashMap<&str, Vec<&str>> = HashMap::new();
        for dir in dir_set {
            dirs.entry(file_name(dir)).or_default().push(dir);
        }

        // Loader declarations, by file.
        let mut declared: HashMap<u32, (String, Vec<String>)> = HashMap::new();
        let missing = |declared: &str| LoaderReport {
            declared: declared.to_owned(),
            path: None,
            status: LoaderStatus::Missing,
            in_force: false,
            detail: "names no Python file in the tree".into(),
        };
        for (path, loads) in &config.loaders {
            match all.index_of(path).filter(|i| all.files[*i].is_python()) {
                Some(index) => {
                    declared.entry(index as u32).or_insert_with(|| (path.clone(), Vec::new())).1.extend(loads.iter().cloned())
                }
                None => graph.loaders.push(missing(path)),
            }
        }
        for (module, loads) in &config.loader_modules {
            let file =
                graph.by_name.get(module).and_then(|nodes| nodes.iter().copied().find(|n| all.files[*n as usize].is_python()));
            let Some(index) = file else {
                graph.loaders.push(missing(module));
                continue;
            };
            let slot = &mut declared.entry(index).or_insert_with(|| (module.clone(), Vec::new())).1;
            for load in loads {
                // `a.b.*` is everything under `a/b/`; `a.b` is that module.
                let as_path = load.replace('.', "/");
                for root in &roots {
                    match as_path.strip_suffix("/*") {
                        Some(package) => slot.push(join(root, &format!("{package}/*"))),
                        None => {
                            slot.extend([join(root, &format!("{as_path}.py")), join(root, &format!("{as_path}/__init__.py"))])
                        }
                    }
                }
            }
        }

        let ts_index = crate::modules::TsProjectIndex::build(all, config);
        let context = Context {
            all,
            paths,
            config,
            links,
            link_at,
            declared,
            whole_calls: GlobSet::new(&config.whole_tree_calls),
            stems,
            dirs,
            ts_index,
        };
        let nodes: Vec<Option<NodeOut>> =
            light_pool().install(|| (0..count).into_par_iter().map(|index| graph.node(&context, index as u32)).collect());
        for (index, node) in nodes.into_iter().enumerate() {
            let Some(mut node) = node else { continue };
            node.targets.sort_unstable();
            node.targets.dedup();
            node.targets.retain(|t| *t != index as u32);
            node.reads.sort_unstable();
            node.reads.dedup();
            node.causes.sort_unstable();
            node.causes.dedup();
            graph.edges[index] = node.targets;
            graph.reads[index] = node.reads;
            graph.causes[index] = node.causes;
            graph.unresolved_relative.extend(node.unresolved);
            graph.external.extend(node.external);
            graph.loaders.extend(node.loader);
        }
        graph.loaders.sort_by(|a, b| a.declared.cmp(&b.declared));
        graph.build_scopes(&context);
        graph
    }

    /// Push the files of `dotted` and of each of its package prefixes.
    fn with_prefixes(&self, dotted: &str, out: &mut Vec<u32>) {
        for (dot, _) in dotted.match_indices('.') {
            if let Some(nodes) = self.by_name.get(&dotted[..dot]) {
                out.extend(nodes);
            }
        }
        if let Some(nodes) = self.by_name.get(dotted) {
            out.extend(nodes);
        }
    }

    /// The module (and the names imported from it) found by walking
    /// directories from `dir`, the way a relative import does.
    fn by_path(&self, context: &Context, dir: &str, module: &str, names: &[String], out: &mut Vec<u32>) -> bool {
        let mut resolved = false;
        let mut here = dir.to_owned();
        let segments: Vec<&str> = module.split('.').filter(|s| !s.is_empty()).collect();
        for (at, segment) in segments.iter().enumerate() {
            let next = join(&here, segment);
            let package = context.lookup(&format!("{next}/__init__.py"), out);
            if at + 1 == segments.len() {
                resolved |= package | context.lookup(&format!("{next}.py"), out);
            }
            here = next;
        }
        if segments.is_empty() {
            resolved |= context.lookup(&join(&here, "__init__.py"), out);
        }
        for name in names.iter().filter(|n| *n != "*") {
            let base = join(&here, name);
            resolved |= context.lookup(&format!("{base}.py"), out) | context.lookup(&format!("{base}/__init__.py"), out);
        }
        resolved
    }

    /// A top-level name that no root explains: any file or package of that
    /// name anywhere in the tree may be what `sys.path` makes it mean.
    /// Standard-library module names only match a sibling in the importer's
    /// own directory, never an unrelated subdirectory file across the repo.
    fn loose(&self, context: &Context, importer: u32, module: &str, names: &[String], out: &mut Vec<u32>) -> bool {
        let (top, rest) = module.split_once('.').unwrap_or((module, ""));
        let stdlib = PYTHON_STDLIB.binary_search(&top).is_ok();
        let importer_dir = parent(&context.all.files[importer as usize].path);
        let mut found = false;
        for file in context.stems.get(top).into_iter().flatten().filter(|f| **f != importer) {
            let path = context.all.files[*file as usize].path.as_str();
            let package = path.ends_with("/__init__.py").then(|| parent(path));
            let holder = match package {
                Some(pkg) => parent(pkg),
                None => parent(path),
            };
            if stdlib && holder != importer_dir {
                continue;
            }
            match (rest.is_empty() && names.is_empty(), package) {
                (true, _) => {
                    out.push(*file);
                    found = true;
                }
                (false, Some(package)) => {
                    out.push(*file);
                    self.by_path(context, package, rest, names, out);
                    found = true;
                }
                (false, None) if rest.is_empty() => {
                    // `from name import x` where `name.py` is a module.
                    out.push(*file);
                    found = true;
                }
                (false, None) => {}
            }
        }
        for dir in context.dirs.get(top).into_iter().flatten() {
            if stdlib && parent(dir) != importer_dir {
                continue;
            }
            found |= self.by_path(context, dir, rest, names, out);
        }
        found
    }

    /// What a name imported from another module holds as a path.
    fn name_reach(&self, context: &Context, file: u32, dotted: &str, hops: usize) -> Option<Resolved> {
        if hops >= MAX_NAME_HOPS {
            return None;
        }
        let level = dotted.bytes().take_while(|b| *b == b'.').count();
        let (module, name) = dotted[level..].rsplit_once('.').unwrap_or(("", &dotted[level..]));
        let mut owners = Vec::new();
        if level > 0 {
            let mut dir = parent(&context.all.files[file as usize].path);
            for _ in 1..level {
                if dir.is_empty() {
                    return None;
                }
                dir = parent(dir);
            }
            self.by_path(context, dir, module, &[], &mut owners);
        } else if let Some(nodes) = self.by_name.get(module) {
            owners.extend(nodes);
        }
        let owner = owners.into_iter().rev().find(|n| context.is_python(*n))?;
        let facts = context.all.files[owner as usize].facts.as_deref()?;
        let reach = &facts.exports.iter().find(|(exported, _)| exported == name)?.1;
        Some(self.resolve(context, owner, reach, hops + 1))
    }

    fn resolve(&self, context: &Context, file: u32, reach: &Reach, hops: usize) -> Resolved {
        let mut out = Resolved { bases: Vec::new(), unknown: reach.unknown, opaque: reach.opaque };
        for Place { anchor, up, tail, open } in &reach.places {
            let starts = match anchor {
                Anchor::Root => vec![(String::new(), false)],
                Anchor::File => vec![(context.all.files[file as usize].path.clone(), false)],
                Anchor::Name(dotted) => match self.name_reach(context, file, dotted, hops) {
                    Some(found) => {
                        out.unknown |= found.unknown;
                        out.opaque |= found.opaque;
                        found.bases
                    }
                    // Not a path this tree defines: nothing is known about it.
                    None => {
                        out.opaque = true;
                        Vec::new()
                    }
                },
            };
            for (start, start_open) in starts {
                if start_open {
                    // Below an unknown suffix nothing more can be said.
                    match *up {
                        0 => out.bases.push((start, true)),
                        _ => out.unknown = true,
                    }
                    continue;
                }
                let mut parts: Vec<&str> = start.split('/').filter(|p| !p.is_empty()).collect();
                if *up as usize > parts.len() {
                    // Above the root: not the tree.
                    continue;
                }
                parts.truncate(parts.len() - *up as usize);
                out.bases.push((join(&parts.join("/"), tail), *open));
            }
        }
        out
    }

    /// How a declared loader's source compares with its declaration.
    ///
    /// Each dynamic load shows, at best, a literal prefix of what it loads.
    /// A prefix some declared pattern covers whole is *verified*. A prefix
    /// that merely contains declared targets (the source loads "something
    /// under `pkg/`", the declaration names two files there) is consistent
    /// with the declaration but does not prove it: *unverifiable*. A prefix
    /// or a complete name that no declared pattern lies under or matches is
    /// a *contradiction*.
    fn verify_loader(&self, context: &Context, index: u32, facts: &FileFacts, patterns: &[String]) -> (LoaderStatus, String) {
        let literal = |pattern: &str| pattern.find(['*', '?']).unwrap_or(pattern.len());
        let covers = |prefix: &str| patterns.iter().any(|p| p.ends_with('*') && prefix.starts_with(&p[..literal(p)]));
        let consistent = |prefix: &str| patterns.iter().any(|p| p[..literal(p)].starts_with(prefix));
        let own = self.names.get(&index).map(String::as_str).unwrap_or("");
        let package = if context.all.files[index as usize].path.ends_with("/__init__.py") {
            own
        } else {
            own.rsplit_once('.').map(|(p, _)| p).unwrap_or("")
        };
        let (mut sites, mut unverifiable, mut contradicted) = (0usize, Vec::new(), Vec::new());
        // `Some(true)`: covered. `Some(false)`: consistent only. `None`: contradicted.
        let judge = |prefixes: &[String]| {
            if prefixes.iter().any(|prefix| covers(prefix)) {
                Some(true)
            } else if prefixes.iter().any(|prefix| consistent(prefix)) {
                Some(false)
            } else {
                None
            }
        };
        for load in &facts.dynamic_loads {
            sites += 1;
            let Some(prefix) = &load.prefix else {
                unverifiable.push(load.line);
                continue;
            };
            let spelled = prefix.replacen("@module", own, 1).replacen("@package", package, 1);
            if spelled.starts_with('.') || spelled.contains('@') {
                unverifiable.push(load.line);
                continue;
            }
            let as_path = spelled.replace('.', "/");
            let candidates: Vec<String> =
                context.config.roots.iter().map(|root| join(root.trim_end_matches('/'), &as_path)).collect();
            if spelled.ends_with('.') {
                match judge(&candidates) {
                    Some(true) => {}
                    Some(false) => unverifiable.push(load.line),
                    None => contradicted.push(load.line),
                }
            } else {
                // A complete module name: the declaration must name it.
                let set = GlobSet::new(patterns);
                let named =
                    candidates.iter().any(|c| set.matches(&format!("{c}.py")) || set.matches(&format!("{c}/__init__.py")));
                if !named {
                    contradicted.push(load.line);
                }
            }
        }
        for site in facts.reads.iter().filter(|site| site.shape == ReadShape::Module) {
            let resolved = self.resolve(context, index, &site.reach, 0);
            if resolved.unknown || resolved.opaque {
                sites += 1;
                unverifiable.push(site.line);
            }
            for (base, _) in resolved.bases.iter().filter(|(_, open)| *open) {
                sites += 1;
                match judge(&[if base.is_empty() { String::new() } else { format!("{base}/") }]) {
                    Some(true) => {}
                    Some(false) => unverifiable.push(site.line),
                    None => contradicted.push(site.line),
                }
            }
        }
        let lines = |lines: &[u32]| {
            let mut lines: Vec<u32> = lines.to_vec();
            lines.sort_unstable();
            lines.dedup();
            lines.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
        };
        match (sites, contradicted.is_empty(), unverifiable.is_empty()) {
            (0, ..) => (LoaderStatus::NoDynamicLoad, "the file has no dynamic load".into()),
            (_, false, _) => {
                (LoaderStatus::Contradicted, format!("line {} loads where the declaration names nothing", lines(&contradicted)))
            }
            (_, true, false) => (
                LoaderStatus::Unverifiable,
                format!("line {} shows no literal target, or only a prefix wider than the declaration", lines(&unverifiable)),
            ),
            (_, true, true) => (LoaderStatus::Verified, format!("{sites} dynamic loads, each within the declared patterns")),
        }
    }

    /// Everything one file contributes: import edges, data reads and causes.
    fn node(&self, context: &Context, index: u32) -> Option<NodeOut> {
        let file = &context.all.files[index as usize];
        let mut out = NodeOut::default();
        if let Some(at) = context.link_at.get(&index) {
            match &context.links[*at].target {
                LinkTarget::File(target) => out.targets.push(*target),
                LinkTarget::Dir(dir) => {
                    let mut below = Vec::new();
                    select_one(&Glob::new(&format!("{dir}/*")), &context.paths, &mut below);
                    out.targets.extend(below.iter().copied().filter(|f| context.is_python(*f)));
                    out.reads.extend(below);
                }
                LinkTarget::Escapes => out.causes.push(Cause::LinkEscape),
            }
            return Some(out);
        }
        if let Some(kind) = file.kind.filter(|kind| crate::modules::supported(*kind)) {
            let facts = file.facts.as_deref()?;
            if facts.parse_error || facts.truncated {
                out.causes.push(Cause::ParseError);
            }
            if facts.too_large {
                out.causes.push(Cause::TooLarge);
            }
            if !facts.dynamic_loads.is_empty() && context.config.cone_model == ConeModel::Strict {
                out.causes.push(Cause::DynamicLoad);
            }
            if matches!(kind, FileKind::TypeScript | FileKind::Tsx | FileKind::Dts) {
                for name in &facts.module_paths {
                    let res = context.ts_index.resolve_ts(kind, &file.path, name, context.config, |p, targets| {
                        context.lookup(p, targets);
                    });
                    out.targets.extend(res.targets);
                    out.reads.extend(res.reads);
                    if res.unresolved {
                        out.causes.push(Cause::UnresolvedLoad);
                    }
                }
            } else {
                for name in &facts.module_paths {
                    let paths = crate::modules::resolve(kind, &file.path, name, context.config);
                    let before = out.targets.len();
                    for p in &paths {
                        context.lookup(p, &mut out.targets);
                    }
                    if out.targets.len() == before {
                        out.causes.push(Cause::UnresolvedLoad);
                    }
                }
            }
            return Some(out);
        }
        let facts =
            file.facts.as_deref().filter(|facts| file.kind == Some(FileKind::Python) || facts.language == Language::Python)?;
        let model = context.config.cone_model;
        let strict = model == ConeModel::Strict;
        if facts.parse_error || facts.truncated {
            out.causes.push(Cause::ParseError);
        }
        if facts.too_large {
            out.causes.push(Cause::TooLarge);
        }

        // Importing `a.b.c` runs `a/__init__` and `a/b/__init__` first; the
        // same holds for the module's own packages.
        let own = self.names.get(&index);
        if let Some((package, _)) = own.and_then(|own| own.rsplit_once('.')) {
            self.with_prefixes(package, &mut out.targets);
        }
        for import in &facts.imports {
            if import.level == 0 {
                let before = out.targets.len();
                self.with_prefixes(&import.module, &mut out.targets);
                let mut resolved = out.targets.len() > before;
                for name in import.names.iter().filter(|n| *n != "*") {
                    if let Some(nodes) = self.by_name.get(&format!("{}.{name}", import.module)) {
                        out.targets.extend(nodes);
                        resolved = true;
                    }
                }
                if !resolved && !self.loose(context, index, &import.module, &import.names, &mut out.targets) {
                    if let Some(top) = import.module.split('.').next().filter(|t| !t.is_empty()) {
                        out.external.push(top.to_owned());
                    }
                }
                continue;
            }
            // Relative: resolved by directory, whatever the roots are.
            let mut dir = Some(parent(&file.path));
            for _ in 1..import.level {
                dir = dir.filter(|d| !d.is_empty()).map(parent);
            }
            let resolved = dir.is_some_and(|dir| self.by_path(context, dir, &import.module, &import.names, &mut out.targets));
            if !resolved {
                out.causes.push(Cause::UnresolvedRelativeImport);
                out.unresolved.push(UnresolvedImport {
                    file: index,
                    line: import.line,
                    import: format!("{}{}", ".".repeat(import.level as usize), import.module),
                });
            }
        }

        // A declaration is in force only while this file's source agrees with it.
        let declaration = context.declared.get(&index);
        let mut bounded_loader = false;
        if let Some((how, patterns)) = declaration {
            let (status, detail) = self.verify_loader(context, index, facts, patterns);
            bounded_loader = status == LoaderStatus::Verified
                || (status == LoaderStatus::Unverifiable && context.config.unverified_loaders == UnverifiedLoaders::Trust);
            match status {
                LoaderStatus::Contradicted => out.causes.push(Cause::ContradictedLoader),
                LoaderStatus::Unverifiable if !bounded_loader => out.causes.push(Cause::UnverifiedLoader),
                _ => {}
            }
            if bounded_loader {
                let mut loaded = Vec::new();
                if context.select(patterns, false, &mut loaded, &mut out.causes) {
                    out.causes.push(Cause::WholeTreeRead);
                }
                out.targets.extend(loaded.iter().copied().filter(|f| context.is_python(*f)));
                out.reads.extend(loaded);
            }
            out.loader = Some(LoaderReport {
                declared: how.clone(),
                path: Some(file.path.clone()),
                status,
                in_force: bounded_loader,
                detail,
            });
        }

        for load in &facts.dynamic_loads {
            // A package listing and a wildcard import can hide a scan, and a
            // scan of files that are not shown passes vacuously: these widen
            // under either model.
            let hides_scan = load.what.starts_with("pkgutil.") || load.what.starts_with("wildcard import");
            if !bounded_loader && declaration.is_none() && (strict || hides_scan) {
                out.causes.push(Cause::DynamicLoad);
            }
        }

        for site in &facts.reads {
            let loads_code = site.shape == ReadShape::Module;
            if loads_code && bounded_loader {
                // Covered by the declaration, which was checked above.
                let resolved = self.resolve(context, index, &site.reach, 0);
                for (base, open) in resolved.bases.into_iter().filter(|(_, open)| !open) {
                    let _ = open;
                    context.lookup(&base, &mut out.targets);
                }
                continue;
            }
            if site.shape == ReadShape::Process {
                if strict {
                    out.causes.push(Cause::Process);
                }
                continue;
            }
            let unbounded = if loads_code { Cause::UnresolvedLoad } else { Cause::UnresolvedRead };
            let resolved = self.resolve(context, index, &site.reach, 0);
            if resolved.unknown {
                out.causes.push(unbounded);
            }
            if resolved.opaque && strict {
                out.causes.push(if loads_code { Cause::UnresolvedLoad } else { Cause::OpaqueRead });
            }
            for (base, open) in &resolved.bases {
                let Some(patterns) = site_patterns(&site.shape, base, *open, model) else {
                    out.causes.push(unbounded);
                    continue;
                };
                let mut selected = Vec::new();
                if context.select(&patterns, true, &mut selected, &mut out.causes) {
                    out.causes.push(Cause::WholeTreeRead);
                }
                if loads_code {
                    out.targets.extend(selected.iter().copied().filter(|f| context.is_python(*f)));
                }
                out.reads.extend(selected);
            }
        }

        if !context.whole_calls.is_empty() && facts.symbols.iter().any(|s| s.call && context.whole_calls.matches(&s.name)) {
            out.causes.push(Cause::WholeTreeCall);
        }
        Some(out)
    }

    pub fn module_of(&self, file: u32) -> Option<&str> {
        self.names.get(&file).map(String::as_str)
    }

    pub fn node_of(&self, module: &str) -> Option<u32> {
        self.by_name.get(module).and_then(|nodes| nodes.last().copied())
    }

    pub fn imports_of(&self, file: u32) -> &[u32] {
        &self.edges[file as usize]
    }

    pub fn reads_of(&self, file: u32) -> &[u32] {
        &self.reads[file as usize]
    }

    pub fn causes_of(&self, file: u32) -> &[Cause] {
        &self.causes[file as usize]
    }

    pub fn edge_count(&self) -> usize {
        self.edges.iter().map(Vec::len).sum()
    }

    fn build_scopes(&mut self, context: &Context) {
        let count = context.all.files.len();
        let mut scopes = ScopeGraph { file_states: vec![(0, 0, 0); count], ..ScopeGraph::default() };
        let alloc = |scopes: &mut ScopeGraph, file: u32| -> u32 {
            let id = scopes.state_file.len() as u32;
            scopes.state_file.push(file);
            scopes.state_edges.push(Vec::new());
            scopes.state_reads.push(Vec::new());
            scopes.state_causes.push(Vec::new());
            id
        };

        let mut sym_maps: Vec<HashMap<String, u32>> = vec![HashMap::new(); count];
        let mut int_maps: Vec<HashMap<String, u32>> = vec![HashMap::new(); count];
        let mut defined_sets: Vec<std::collections::HashSet<&str>> = vec![std::collections::HashSet::new(); count];
        let mut py_facts: Vec<Option<&FileFacts>> = vec![None; count];

        for (index, file) in context.all.files.iter().enumerate() {
            let idx = index as u32;
            if context.link_at.contains_key(&idx) {
                let top_s = alloc(&mut scopes, idx);
                let all_s = alloc(&mut scopes, idx);
                scopes.state_edges[all_s as usize].push(top_s);
                scopes.file_states[index] = (top_s, all_s, all_s);
                continue;
            }
            let Some(facts) =
                file.facts.as_deref().filter(|facts| file.kind == Some(FileKind::Python) || facts.language == Language::Python)
            else {
                let s = alloc(&mut scopes, idx);
                scopes.file_states[index] = (s, s, s);
                continue;
            };
            py_facts[index] = Some(facts);
            defined_sets[index] = facts.defined_symbols.iter().map(String::as_str).collect();

            let mut syms: BTreeSet<&str> = facts.defined_symbols.iter().map(String::as_str).collect();
            for imp in &facts.imports {
                if !imp.owner.is_empty() {
                    syms.insert(&imp.owner);
                }
                for (_, local) in &imp.bindings {
                    if !local.is_empty() && local != "*" {
                        syms.insert(local);
                    }
                }
            }
            for site in &facts.reads {
                if !site.owner.is_empty() {
                    syms.insert(&site.owner);
                }
            }
            for load in &facts.dynamic_loads {
                if !load.owner.is_empty() {
                    syms.insert(&load.owner);
                }
            }
            for (from, to) in &facts.symbol_deps {
                if !from.is_empty() {
                    syms.insert(from);
                }
                if !to.is_empty() && to != "*" {
                    syms.insert(to);
                }
            }
            for (from, to, _) in &facts.internal_calls {
                if !from.is_empty() {
                    syms.insert(from);
                }
                if !to.is_empty() {
                    syms.insert(to);
                }
            }
            for sref in &facts.external_refs {
                if !sref.owner.is_empty() {
                    syms.insert(&sref.owner);
                }
            }
            for (owner, _) in &facts.scoped_calls {
                if !owner.is_empty() {
                    syms.insert(owner);
                }
            }

            let top_s = alloc(&mut scopes, idx);
            let mut ext_map = HashMap::with_capacity(syms.len());
            let mut int_map = HashMap::with_capacity(syms.len());
            for sym in syms {
                let int_id = alloc(&mut scopes, idx);
                let ext_id = alloc(&mut scopes, idx);
                scopes.state_edges[int_id as usize].push(top_s);
                scopes.state_edges[ext_id as usize].push(int_id);
                int_map.insert(sym.to_owned(), int_id);
                ext_map.insert(sym.to_owned(), ext_id);
            }
            let unit_s = alloc(&mut scopes, idx);
            let all_s = alloc(&mut scopes, idx);
            scopes.state_edges[unit_s as usize].push(top_s);
            scopes.state_edges[all_s as usize].push(unit_s);
            for &ext_id in ext_map.values() {
                scopes.state_edges[all_s as usize].push(ext_id);
            }
            sym_maps[index] = ext_map;
            int_maps[index] = int_map;
            scopes.file_states[index] = (top_s, unit_s, all_s);
        }

        #[allow(clippy::too_many_arguments)] // immutable graph context plus recursive traversal state
        fn push_sym_states(
            context: &Context,
            file_states: &[(u32, u32, u32)],
            sym_maps: &[HashMap<String, u32>],
            defined_sets: &[std::collections::HashSet<&str>],
            target: u32,
            sym: &str,
            hops: usize,
            out: &mut Vec<u32>,
        ) {
            if hops > 16 {
                out.push(file_states[target as usize].2);
                return;
            }
            if let Some(&at) = context.link_at.get(&target) {
                let (top_s, _, all_s) = file_states[target as usize];
                out.push(top_s);
                match &context.links[at].target {
                    LinkTarget::File(real) => {
                        push_sym_states(context, file_states, sym_maps, defined_sets, *real, sym, hops + 1, out)
                    }
                    LinkTarget::Dir(_) | LinkTarget::Escapes => out.push(all_s),
                }
                return;
            }
            let (top_s, _, all_s) = file_states[target as usize];
            if !context.is_python(target) {
                out.push(top_s);
                return;
            }
            if sym == "*" {
                out.push(all_s);
            } else if defined_sets[target as usize].contains(sym) {
                if let Some(&s_id) = sym_maps[target as usize].get(sym) {
                    out.push(s_id);
                } else {
                    out.push(all_s);
                }
            } else {
                out.push(all_s);
            }
        }

        let scope_of = |scopes: &ScopeGraph, sym_maps: &[HashMap<String, u32>], file: usize, owner: &str| -> u32 {
            if owner.is_empty() {
                scopes.file_states[file].0
            } else {
                sym_maps[file].get(owner).copied().unwrap_or(scopes.file_states[file].0)
            }
        };

        let model = context.config.cone_model;
        let strict = model == ConeModel::Strict;

        for index in 0..count {
            let idx = index as u32;
            let (top_s, unit_s, all_s) = scopes.file_states[index];
            if let Some(&at) = context.link_at.get(&idx) {
                match &context.links[at].target {
                    LinkTarget::File(target) => {
                        scopes.state_edges[top_s as usize].push(scopes.file_states[*target as usize].0);
                        scopes.state_edges[all_s as usize].push(scopes.file_states[*target as usize].2);
                    }
                    LinkTarget::Dir(dir) => {
                        let mut below = Vec::new();
                        select_one(&Glob::new(&format!("{dir}/*")), &context.paths, &mut below);
                        for f in below.iter().copied().filter(|f| context.is_python(*f)) {
                            scopes.state_edges[top_s as usize].push(scopes.file_states[f as usize].2);
                        }
                        scopes.state_reads[top_s as usize].extend(below);
                    }
                    LinkTarget::Escapes => scopes.state_causes[top_s as usize].push(Cause::LinkEscape),
                }
                continue;
            }
            let Some(facts) = py_facts[index] else {
                scopes.state_edges[top_s as usize].extend(self.edges[index].iter().map(|i| scopes.file_states[*i as usize].2));
                scopes.state_reads[top_s as usize].extend(&self.reads[index]);
                scopes.state_causes[top_s as usize].extend(&self.causes[index]);
                continue;
            };
            if facts.parse_error || facts.truncated {
                scopes.state_causes[top_s as usize].push(Cause::ParseError);
            }
            if facts.too_large {
                scopes.state_causes[top_s as usize].push(Cause::TooLarge);
            }

            // Package `__init__.py`s execute their module top-level when any submodule is imported.
            if let Some((package, _)) = self.names.get(&idx).and_then(|own| own.rsplit_once('.')) {
                let mut pkg_nodes = Vec::new();
                self.with_prefixes(package, &mut pkg_nodes);
                for pkg in pkg_nodes {
                    if pkg != idx {
                        scopes.state_edges[top_s as usize].push(scopes.file_states[pkg as usize].0);
                    }
                }
            }

            // Intra-module symbol dependencies.
            for (from, to) in &facts.symbol_deps {
                let src = scope_of(&scopes, &int_maps, index, from);
                if to == "*" {
                    scopes.state_edges[src as usize].push(all_s);
                } else if let Some(&dst) = sym_maps[index].get(to.as_str()) {
                    scopes.state_edges[src as usize].push(dst);
                }
            }
            for (from, to, forwards) in &facts.internal_calls {
                let src_int = scope_of(&scopes, &int_maps, index, from);
                if let Some(&dst_int) = int_maps[index].get(to.as_str()) {
                    scopes.state_edges[src_int as usize].push(dst_int);
                }
                if *forwards {
                    let src_ext = scope_of(&scopes, &sym_maps, index, from);
                    if let Some(&dst_ext) = sym_maps[index].get(to.as_str()) {
                        scopes.state_edges[src_ext as usize].push(dst_ext);
                    }
                }
            }

            let mut module_bound: std::collections::HashSet<&str> = std::collections::HashSet::new();
            let mut symbol_bound: std::collections::HashSet<&str> = std::collections::HashSet::new();
            let import_locals: std::collections::HashSet<&str> =
                facts.imports.iter().flat_map(|imp| imp.bindings.iter().map(|(_, l)| l.as_str())).collect();
            let has_own_defs =
                !facts.functions.is_empty() || facts.defined_symbols.iter().any(|s| !import_locals.contains(s.as_str()));

            for import in &facts.imports {
                let imp_src = scope_of(&scopes, &int_maps, index, &import.owner);
                let refs_for = |head: &str| facts.external_refs.iter().filter(move |r| r.head == head).collect::<Vec<_>>();

                if import.level == 0 && import.names.is_empty() {
                    let mut prefix_nodes = Vec::new();
                    for (dot, _) in import.module.match_indices('.') {
                        if let Some(nodes) = self.by_name.get(&import.module[..dot]) {
                            prefix_nodes.extend(nodes.iter().copied());
                        }
                    }
                    let mod_nodes: Vec<u32> = self.by_name.get(&import.module).cloned().unwrap_or_default();
                    let mut any_resolved = !prefix_nodes.is_empty() || !mod_nodes.is_empty();
                    for p in &prefix_nodes {
                        scopes.state_edges[imp_src as usize].push(scopes.file_states[*p as usize].0);
                    }
                    for m in &mod_nodes {
                        scopes.state_edges[imp_src as usize].push(scopes.file_states[*m as usize].0);
                    }
                    if !any_resolved {
                        let mut loose_nodes = Vec::new();
                        if self.loose(context, idx, &import.module, &import.names, &mut loose_nodes) {
                            any_resolved = true;
                            for ln in loose_nodes {
                                scopes.state_edges[imp_src as usize].push(scopes.file_states[ln as usize].2);
                            }
                        }
                    }
                    let _ = any_resolved;

                    if import.bindings.is_empty() {
                        // `import_module("m")`, `run_module("m")`, `python -m m`.
                        for m in &mod_nodes {
                            scopes.state_edges[imp_src as usize].push(scopes.file_states[*m as usize].2);
                        }
                    } else {
                        for (_, bound) in &import.bindings {
                            if bound.is_empty() {
                                continue;
                            }
                            if import.owner.is_empty() {
                                module_bound.insert(bound.as_str());
                            }
                            let head_of_mod = import.module.split('.').next().unwrap_or("");
                            let aliased = bound != head_of_mod;
                            if import.owner.is_empty() {
                                if let Some(&sym_s) = sym_maps[index].get(bound.as_str()) {
                                    for m in &mod_nodes {
                                        scopes.state_edges[sym_s as usize].push(scopes.file_states[*m as usize].2);
                                    }
                                    if !aliased {
                                        for p in &prefix_nodes {
                                            scopes.state_edges[sym_s as usize].push(scopes.file_states[*p as usize].2);
                                        }
                                    }
                                }
                            }
                            let head_refs = refs_for(bound);
                            if !has_own_defs && head_refs.is_empty() {
                                let bare_src = if import.owner.is_empty() { unit_s } else { imp_src };
                                for m in &mod_nodes {
                                    scopes.state_edges[bare_src as usize].push(scopes.file_states[*m as usize].2);
                                }
                            }
                            for sref in head_refs {
                                let r_src = scope_of(&scopes, &int_maps, index, &sref.owner);
                                if aliased {
                                    if sref.dotted == *bound {
                                        for m in &mod_nodes {
                                            scopes.state_edges[r_src as usize].push(scopes.file_states[*m as usize].2);
                                        }
                                    } else if let Some(rest) = sref.dotted.strip_prefix(&format!("{bound}.")) {
                                        let attr = rest.split('.').next().unwrap_or("");
                                        for m in &mod_nodes {
                                            push_sym_states(
                                                context,
                                                &scopes.file_states,
                                                &sym_maps,
                                                &defined_sets,
                                                *m,
                                                attr,
                                                0,
                                                &mut scopes.state_edges[r_src as usize],
                                            );
                                        }
                                    }
                                } else if sref.dotted == import.module {
                                    for m in &mod_nodes {
                                        scopes.state_edges[r_src as usize].push(scopes.file_states[*m as usize].2);
                                    }
                                } else if import.module.starts_with(&format!("{}.", sref.dotted)) {
                                    for m in &mod_nodes {
                                        scopes.state_edges[r_src as usize].push(scopes.file_states[*m as usize].2);
                                    }
                                    if let Some(p_nodes) = self.by_name.get(&sref.dotted) {
                                        for p in p_nodes {
                                            scopes.state_edges[r_src as usize].push(scopes.file_states[*p as usize].2);
                                        }
                                    }
                                } else if let Some(rest) = sref.dotted.strip_prefix(&format!("{}.", import.module)) {
                                    let attr = rest.split('.').next().unwrap_or("");
                                    if !self.by_name.contains_key(&format!("{}.{attr}", import.module)) {
                                        for m in &mod_nodes {
                                            push_sym_states(
                                                context,
                                                &scopes.file_states,
                                                &sym_maps,
                                                &defined_sets,
                                                *m,
                                                attr,
                                                0,
                                                &mut scopes.state_edges[r_src as usize],
                                            );
                                        }
                                    }
                                } else {
                                    // Access on a package prefix, e.g. `import a.b.c; a.helper()`.
                                    for (dot, _) in import.module.match_indices('.') {
                                        let pkg_prefix = &import.module[..dot];
                                        if let Some(rest) = sref.dotted.strip_prefix(&format!("{pkg_prefix}.")) {
                                            let attr = rest.split('.').next().unwrap_or("");
                                            if !self.by_name.contains_key(&format!("{pkg_prefix}.{attr}")) {
                                                if let Some(p_nodes) = self.by_name.get(pkg_prefix) {
                                                    for p in p_nodes {
                                                        push_sym_states(
                                                            context,
                                                            &scopes.file_states,
                                                            &sym_maps,
                                                            &defined_sets,
                                                            *p,
                                                            attr,
                                                            0,
                                                            &mut scopes.state_edges[r_src as usize],
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    continue;
                }

                // `from ... import ...` (absolute or relative), or bare relative.
                let mut prefix_nodes = Vec::new();
                let mut mod_nodes = Vec::new();
                let mut rel_base_dir: Option<String> = None;
                let mut resolved_any = false;

                if import.level == 0 {
                    for (dot, _) in import.module.match_indices('.') {
                        if let Some(nodes) = self.by_name.get(&import.module[..dot]) {
                            prefix_nodes.extend(nodes.iter().copied());
                            resolved_any = true;
                        }
                    }
                    if let Some(nodes) = self.by_name.get(&import.module) {
                        mod_nodes.extend(nodes.iter().copied());
                        resolved_any = true;
                    }
                } else {
                    let mut dir = Some(parent(&context.all.files[index].path));
                    for _ in 1..import.level {
                        dir = dir.filter(|d| !d.is_empty()).map(parent);
                    }
                    if let Some(dir) = dir {
                        let mut here = dir.to_owned();
                        let segments: Vec<&str> = import.module.split('.').filter(|s| !s.is_empty()).collect();
                        for (at, segment) in segments.iter().enumerate() {
                            let next = join(&here, segment);
                            if at + 1 < segments.len() {
                                resolved_any |= context.lookup(&format!("{next}/__init__.py"), &mut prefix_nodes);
                            } else {
                                resolved_any |= context.lookup(&format!("{next}/__init__.py"), &mut mod_nodes);
                                resolved_any |= context.lookup(&format!("{next}.py"), &mut mod_nodes);
                            }
                            here = next;
                        }
                        if segments.is_empty() {
                            resolved_any |= context.lookup(&join(&here, "__init__.py"), &mut mod_nodes);
                        }
                        rel_base_dir = Some(here);
                    }
                }

                for p in &prefix_nodes {
                    scopes.state_edges[imp_src as usize].push(scopes.file_states[*p as usize].0);
                }
                for m in &mod_nodes {
                    scopes.state_edges[imp_src as usize].push(scopes.file_states[*m as usize].0);
                }

                if import.names.iter().any(|n| n == "*") {
                    for m in &mod_nodes {
                        scopes.state_edges[imp_src as usize].push(scopes.file_states[*m as usize].2);
                    }
                }

                if import.bindings.is_empty() {
                    // `__import__('x', fromlist=['y'])`
                    for name in import.names.iter().filter(|n| *n != "*") {
                        let mut sub_nodes = Vec::new();
                        if import.level == 0 {
                            if let Some(nodes) = self.by_name.get(&format!("{}.{name}", import.module)) {
                                sub_nodes.extend(nodes.iter().copied());
                                resolved_any = true;
                            }
                        } else if let Some(here) = &rel_base_dir {
                            let base = join(here, name);
                            resolved_any |= context.lookup(&format!("{base}.py"), &mut sub_nodes);
                            resolved_any |= context.lookup(&format!("{base}/__init__.py"), &mut sub_nodes);
                        }
                        for sub in &sub_nodes {
                            scopes.state_edges[imp_src as usize].push(scopes.file_states[*sub as usize].2);
                        }
                        if sub_nodes.is_empty() {
                            for m in &mod_nodes {
                                push_sym_states(
                                    context,
                                    &scopes.file_states,
                                    &sym_maps,
                                    &defined_sets,
                                    *m,
                                    name,
                                    0,
                                    &mut scopes.state_edges[imp_src as usize],
                                );
                            }
                        }
                    }
                } else {
                    for (orig, local) in &import.bindings {
                        if orig == "*" || local.is_empty() {
                            continue;
                        }
                        let mut sub_nodes = Vec::new();
                        if import.level == 0 {
                            if let Some(nodes) = self.by_name.get(&format!("{}.{orig}", import.module)) {
                                sub_nodes.extend(nodes.iter().copied());
                                resolved_any = true;
                            }
                        } else if let Some(here) = &rel_base_dir {
                            let base = join(here, orig);
                            resolved_any |= context.lookup(&format!("{base}.py"), &mut sub_nodes);
                            resolved_any |= context.lookup(&format!("{base}/__init__.py"), &mut sub_nodes);
                        }

                        if !sub_nodes.is_empty() {
                            if import.owner.is_empty() {
                                module_bound.insert(local.as_str());
                                if let Some(&sym_s) = sym_maps[index].get(local.as_str()) {
                                    for sub in &sub_nodes {
                                        scopes.state_edges[sym_s as usize].push(scopes.file_states[*sub as usize].2);
                                    }
                                }
                            }
                            for sub in &sub_nodes {
                                scopes.state_edges[imp_src as usize].push(scopes.file_states[*sub as usize].0);
                            }
                            // If the package `__init__.py` also explicitly defines `orig`, link it.
                            for m in &mod_nodes {
                                if defined_sets[*m as usize].contains(orig.as_str()) {
                                    if import.owner.is_empty() {
                                        if let Some(&sym_s) = sym_maps[index].get(local.as_str()) {
                                            push_sym_states(
                                                context,
                                                &scopes.file_states,
                                                &sym_maps,
                                                &defined_sets,
                                                *m,
                                                orig,
                                                0,
                                                &mut scopes.state_edges[sym_s as usize],
                                            );
                                        }
                                    } else {
                                        push_sym_states(
                                            context,
                                            &scopes.file_states,
                                            &sym_maps,
                                            &defined_sets,
                                            *m,
                                            orig,
                                            0,
                                            &mut scopes.state_edges[imp_src as usize],
                                        );
                                    }
                                }
                            }
                            let head_refs = refs_for(local);
                            if !has_own_defs && head_refs.is_empty() {
                                let bare_src = if import.owner.is_empty() { unit_s } else { imp_src };
                                for sub in &sub_nodes {
                                    scopes.state_edges[bare_src as usize].push(scopes.file_states[*sub as usize].2);
                                }
                            }
                            for sref in head_refs {
                                let r_src = scope_of(&scopes, &int_maps, index, &sref.owner);
                                if sref.dotted == *local {
                                    for sub in &sub_nodes {
                                        scopes.state_edges[r_src as usize].push(scopes.file_states[*sub as usize].2);
                                    }
                                } else if let Some(rest) = sref.dotted.strip_prefix(&format!("{local}.")) {
                                    let attr = rest.split('.').next().unwrap_or("");
                                    for sub in &sub_nodes {
                                        push_sym_states(
                                            context,
                                            &scopes.file_states,
                                            &sym_maps,
                                            &defined_sets,
                                            *sub,
                                            attr,
                                            0,
                                            &mut scopes.state_edges[r_src as usize],
                                        );
                                    }
                                }
                            }
                        } else {
                            if import.owner.is_empty() {
                                symbol_bound.insert(local.as_str());
                                if let Some(&sym_s) = sym_maps[index].get(local.as_str()) {
                                    for m in &mod_nodes {
                                        push_sym_states(
                                            context,
                                            &scopes.file_states,
                                            &sym_maps,
                                            &defined_sets,
                                            *m,
                                            orig,
                                            0,
                                            &mut scopes.state_edges[sym_s as usize],
                                        );
                                    }
                                }
                            } else {
                                for m in &mod_nodes {
                                    push_sym_states(
                                        context,
                                        &scopes.file_states,
                                        &sym_maps,
                                        &defined_sets,
                                        *m,
                                        orig,
                                        0,
                                        &mut scopes.state_edges[imp_src as usize],
                                    );
                                }
                            }
                            for sref in refs_for(local) {
                                let r_src = scope_of(&scopes, &int_maps, index, &sref.owner);
                                for m in &mod_nodes {
                                    push_sym_states(
                                        context,
                                        &scopes.file_states,
                                        &sym_maps,
                                        &defined_sets,
                                        *m,
                                        orig,
                                        0,
                                        &mut scopes.state_edges[r_src as usize],
                                    );
                                }
                            }
                        }
                    }
                }

                if !resolved_any {
                    if import.level == 0 {
                        let mut loose_nodes = Vec::new();
                        if self.loose(context, idx, &import.module, &import.names, &mut loose_nodes) {
                            for ln in loose_nodes {
                                scopes.state_edges[imp_src as usize].push(scopes.file_states[ln as usize].2);
                            }
                        }
                    } else {
                        scopes.state_causes[imp_src as usize].push(Cause::UnresolvedRelativeImport);
                    }
                }
            }

            // Connect `unit_s` to all non-module-only symbol states in this file.
            let fn_heads: std::collections::HashSet<&str> =
                facts.functions.iter().filter_map(|f| f.name.split('.').next()).collect();
            for (sym_name, &sym_s) in &sym_maps[index] {
                let pure_module = module_bound.contains(sym_name.as_str())
                    && !symbol_bound.contains(sym_name.as_str())
                    && !fn_heads.contains(sym_name.as_str());
                if !pure_module {
                    scopes.state_edges[unit_s as usize].push(sym_s);
                }
            }

            // Declared and undeclared dynamic loaders, scoped to the owning symbol.
            let declaration = context.declared.get(&idx);
            let mut bounded_loader = false;
            if let Some((_, patterns)) = declaration {
                let (status, _) = self.verify_loader(context, idx, facts, patterns);
                bounded_loader = status == LoaderStatus::Verified
                    || (status == LoaderStatus::Unverifiable && context.config.unverified_loaders == UnverifiedLoaders::Trust);
                let mut decl_causes = Vec::new();
                match status {
                    LoaderStatus::Contradicted => decl_causes.push(Cause::ContradictedLoader),
                    LoaderStatus::Unverifiable if !bounded_loader => decl_causes.push(Cause::UnverifiedLoader),
                    _ => {}
                }
                let mut loaded = Vec::new();
                if bounded_loader && context.select(patterns, false, &mut loaded, &mut decl_causes) {
                    decl_causes.push(Cause::WholeTreeRead);
                }
                let loader_owners = facts
                    .dynamic_loads
                    .iter()
                    .map(|l| l.owner.as_str())
                    .chain(facts.reads.iter().filter(|s| s.shape == ReadShape::Module).map(|s| s.owner.as_str()));
                for owner in loader_owners {
                    let l_src = scope_of(&scopes, &int_maps, index, owner);
                    scopes.state_causes[l_src as usize].extend(decl_causes.iter().copied());
                    if bounded_loader {
                        for f in loaded.iter().copied().filter(|f| context.is_python(*f)) {
                            scopes.state_edges[l_src as usize].push(scopes.file_states[f as usize].2);
                        }
                        scopes.state_reads[l_src as usize].extend(loaded.iter().copied());
                    }
                }
            }

            for load in &facts.dynamic_loads {
                let hides_scan = load.what.starts_with("pkgutil.") || load.what.starts_with("wildcard import");
                if !bounded_loader && declaration.is_none() && (strict || hides_scan) {
                    let l_src = scope_of(&scopes, &int_maps, index, &load.owner);
                    scopes.state_causes[l_src as usize].push(Cause::DynamicLoad);
                }
            }

            for site in &facts.reads {
                let s_src = scope_of(&scopes, &int_maps, index, &site.owner);
                let s_ext = scope_of(&scopes, &sym_maps, index, &site.owner);
                let loads_code = site.shape == ReadShape::Module;
                if loads_code && bounded_loader {
                    let resolved = self.resolve(context, idx, &site.reach, 0);
                    for (base, _) in resolved.bases.into_iter().filter(|(_, open)| !open) {
                        let mut targets = Vec::new();
                        context.lookup(&base, &mut targets);
                        for t in targets {
                            scopes.state_edges[s_src as usize].push(scopes.file_states[t as usize].2);
                        }
                    }
                    continue;
                }
                if site.shape == ReadShape::Process {
                    if strict {
                        scopes.state_causes[s_src as usize].push(Cause::Process);
                    }
                    continue;
                }
                let unbounded = if loads_code { Cause::UnresolvedLoad } else { Cause::UnresolvedRead };
                let resolved = self.resolve(context, idx, &site.reach, 0);
                if resolved.unknown {
                    scopes.state_causes[s_src as usize].push(unbounded);
                }
                if resolved.opaque && strict {
                    let cause = if loads_code { Cause::UnresolvedLoad } else { Cause::OpaqueRead };
                    if site.internal_clean {
                        let clean_reach = Reach { places: site.reach.places.clone(), unknown: site.reach.unknown, opaque: false };
                        let res_int = self.resolve(context, idx, &clean_reach, 0);
                        if res_int.opaque {
                            scopes.state_causes[s_src as usize].push(cause);
                        } else {
                            scopes.state_causes[s_ext as usize].push(cause);
                        }
                    } else {
                        scopes.state_causes[s_src as usize].push(cause);
                    }
                }
                for (base, open) in &resolved.bases {
                    let Some(patterns) = site_patterns(&site.shape, base, *open, model) else {
                        scopes.state_causes[s_src as usize].push(unbounded);
                        continue;
                    };
                    let mut selected = Vec::new();
                    if context.select(&patterns, true, &mut selected, &mut scopes.state_causes[s_src as usize]) {
                        scopes.state_causes[s_src as usize].push(Cause::WholeTreeRead);
                    }
                    if loads_code {
                        for f in selected.iter().copied().filter(|f| context.is_python(*f)) {
                            scopes.state_edges[s_src as usize].push(scopes.file_states[f as usize].2);
                        }
                    }
                    scopes.state_reads[s_src as usize].extend(selected);
                }
            }

            if !context.whole_calls.is_empty() {
                for (owner, callee) in &facts.scoped_calls {
                    if context.whole_calls.matches(callee) {
                        let c_src = scope_of(&scopes, &int_maps, index, owner);
                        scopes.state_causes[c_src as usize].push(Cause::WholeTreeCall);
                    }
                }
            }
        }

        for edges in &mut scopes.state_edges {
            edges.sort_unstable();
            edges.dedup();
        }
        for reads in &mut scopes.state_reads {
            reads.sort_unstable();
            reads.dedup();
        }
        for causes in &mut scopes.state_causes {
            causes.sort_unstable();
            causes.dedup();
        }
        self.scopes = scopes;
    }
}

/// One test unit's cone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportCone {
    /// The test's module name (`tests.door.test_x`).
    pub unit: String,
    pub path: String,
    pub digest: Digest32,
    /// The cone was widened to the whole tree.
    pub widened: bool,
    /// Files reached through imports alone.
    pub imported_files: usize,
    /// Every input: imports, data reads, guards and, when widened, the whole tree.
    #[serde(skip)]
    pub inputs: Vec<u32>,
    pub input_files: usize,
    /// Why it was widened: `(file, cause)`; the file is the unit's own for a guard.
    #[serde(skip)]
    pub causes: Vec<(u32, Cause)>,
    #[serde(skip)]
    pub context: Digest32,
}

impl ImportCone {
    pub fn input_paths<'a>(&'a self, all: &'a AllFacts) -> impl Iterator<Item = &'a str> + 'a {
        self.inputs.iter().map(|i| all.files[*i as usize].path.as_str())
    }

    /// The same cone in the form the admissibility engine judges.
    pub fn to_cone(&self, all: &AllFacts) -> Cone {
        Cone {
            unit: self.unit.clone(),
            inputs: self
                .inputs
                .iter()
                .map(|i| &all.files[*i as usize])
                .map(|f| (f.path.clone(), Input { mode: f.mode, oid: f.oid }))
                .collect(),
            tainted: self.widened,
            context: self.context,
        }
    }
}

/// Export the cone of every test unit, in path order. `context` names what
/// judges the cones (rule pack, runner profile) and is part of every digest.
pub fn cones(all: &AllFacts, graph: &ImportGraph, config: &ImportConfig, context: &Digest32) -> Vec<ImportCone> {
    let paths = all.paths();
    let tests: Vec<u32> = GlobSet::new(&config.tests)
        .select(&paths)
        .into_iter()
        .filter(|i| {
            let file = &all.files[*i as usize];
            file.is_python() || file.kind.is_some_and(crate::modules::supported)
        })
        .collect();
    let leaves: Vec<[u8; 32]> =
        light_pool().install(|| all.files.par_iter().map(|f| cone_leaf(&f.path, f.mode, &f.oid)).collect());
    let everything: Vec<u32> = (0..all.files.len() as u32).collect();
    let whole_tree = cone_inputs_digest(leaves.iter());
    let always = GlobSet::new(&config.always).select(&paths);
    // Guards are keyed by unit-name pattern; a pattern may name many units.
    let guards: Vec<(Glob, bool, Vec<u32>)> = config
        .guards
        .iter()
        .map(|(units, reads)| {
            let set = GlobSet::new(reads);
            (Glob::new(units), set.is_everything(), set.select(&paths))
        })
        .collect();

    let state_count = graph.scopes.state_file.len();
    light_pool().install(|| {
        tests
            .par_iter()
            .map_init(
                || (vec![false; state_count], vec![false; all.files.len()], Vec::<u32>::new()),
                |(seen_state, seen_file, stack), test| {
                    let path = all.files[*test as usize].path.as_str();
                    let unit = graph.module_of(*test).unwrap_or(path).to_owned();
                    stack.clear();
                    stack.push(graph.scopes.file_states[*test as usize].1);
                    if config.implicit_conftest && all.files[*test as usize].is_python() {
                        let mut dir = path;
                        loop {
                            dir = parent(dir);
                            if let Some(index) = all.index_of(&join(dir, "conftest.py")) {
                                stack.push(graph.scopes.file_states[index].1);
                            }
                            if dir.is_empty() {
                                break;
                            }
                        }
                    }
                    let mut visited_states = Vec::new();
                    let mut closure = Vec::new();
                    let mut causes = Vec::new();
                    while let Some(state) = stack.pop() {
                        if std::mem::replace(&mut seen_state[state as usize], true) {
                            continue;
                        }
                        visited_states.push(state);
                        let node = graph.scopes.state_file[state as usize];
                        if !std::mem::replace(&mut seen_file[node as usize], true) {
                            closure.push(node);
                        }
                        causes.extend(graph.scopes.state_causes[state as usize].iter().map(|cause| (node, *cause)));
                        stack.extend(graph.scopes.state_edges[state as usize].iter().filter(|s| !seen_state[**s as usize]));
                    }
                    for &s in &visited_states {
                        seen_state[s as usize] = false;
                    }
                    for &node in &closure {
                        seen_file[node as usize] = false;
                    }
                    let imported_files = closure.len();
                    let mut inputs = closure.clone();
                    for (units, everything, reads) in &guards {
                        if units.matches(&unit) {
                            if *everything {
                                causes.push((*test, Cause::GuardEverything));
                            }
                            inputs.extend(reads);
                        }
                    }
                    let widened = !causes.is_empty();
                    let inputs = if widened {
                        everything.clone()
                    } else {
                        for &s in &visited_states {
                            inputs.extend(&graph.scopes.state_reads[s as usize]);
                        }
                        inputs.extend(&always);
                        inputs.sort_unstable();
                        inputs.dedup();
                        inputs
                    };
                    let inputs_digest =
                        if widened { whole_tree } else { cone_inputs_digest(inputs.iter().map(|i| &leaves[*i as usize])) };
                    causes.sort_unstable();
                    causes.dedup();
                    ImportCone {
                        digest: cone_digest(&unit, &inputs_digest, widened, context),
                        causes,
                        unit,
                        path: path.to_owned(),
                        widened,
                        imported_files,
                        input_files: inputs.len(),
                        inputs,
                        context: *context,
                    }
                },
            )
            .collect()
    })
}

/// A count of something the graph could not bound, for reports.
pub fn cause_counts(cones: &[ImportCone], all: &AllFacts) -> BTreeMap<(String, Cause), usize> {
    let mut counts = BTreeMap::new();
    for cone in cones {
        for (file, cause) in &cone.causes {
            *counts.entry((all.files[*file as usize].path.clone(), *cause)).or_insert(0) += 1;
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::{MODE_EXECUTABLE, MODE_GITLINK};

    const FILE: u32 = 0o100644;

    const TREE: &[(&str, &str)] = &[
        ("conftest.py", "import fixtures\n"),
        ("fixtures.py", "X = 1\n"),
        ("lib/__init__.py", "from . import core\n"),
        ("lib/core.py", "from .deep import leaf\nimport json\n"),
        ("lib/deep/__init__.py", ""),
        ("lib/deep/leaf.py", "VALUE = 1\n"),
        ("lib/island.py", "ALONE = 1\n"),
        ("lib/plugins.py", "import importlib\ndef load(n):\n    return importlib.import_module(n)\n"),
        ("docs/readme.md", "docs\n"),
        ("data/table.json", "{}\n"),
        ("tests/__init__.py", ""),
        ("tests/conftest.py", ""),
        ("tests/test_core.py", "from lib import core\n"),
        ("tests/test_island.py", "import lib.island\n"),
        ("tests/test_plugins.py", "from lib.plugins import load\n"),
        ("tests/helper.py", ""),
    ];

    type Entries = Vec<(String, u32, String)>;

    fn with(tree: &[(&str, &str)], edit: &[(&str, &str)]) -> Entries {
        let mut files: Entries = tree.iter().map(|(p, c)| (p.to_string(), FILE, c.to_string())).collect();
        for (path, content) in edit {
            match files.iter_mut().find(|(p, _, _)| p == path) {
                Some(file) => file.2 = content.to_string(),
                None => files.push((path.to_string(), FILE, content.to_string())),
            }
        }
        files
    }

    fn context() -> Digest32 {
        Digest32::blake3(b"pack and runner")
    }

    fn cones_of(files: &Entries, config: &ImportConfig) -> (AllFacts, Vec<ImportCone>) {
        let borrowed: Vec<(&str, u32, &str)> = files.iter().map(|(p, m, c)| (p.as_str(), *m, c.as_str())).collect();
        let all = AllFacts::from_entries(&borrowed);
        let graph = ImportGraph::build(&all, config);
        let cones = cones(&all, &graph, config, &context());
        (all, cones)
    }

    fn config() -> ImportConfig {
        ImportConfig { tests: vec!["tests/**/test_*.py".into()], ..ImportConfig::default() }
    }

    fn hermetic() -> ImportConfig {
        ImportConfig { cone_model: ConeModel::Hermetic, ..config() }
    }

    fn cone<'a>(cones: &'a [ImportCone], unit: &str) -> &'a ImportCone {
        cones.iter().find(|c| c.unit == unit).unwrap_or_else(|| panic!("no cone for {unit}"))
    }

    fn inputs<'a>(all: &'a AllFacts, cone: &'a ImportCone) -> Vec<&'a str> {
        cone.input_paths(all).collect()
    }

    fn causes(all: &AllFacts, cone: &ImportCone) -> Vec<(String, Cause)> {
        cone.causes.iter().map(|(file, cause)| (all.files[*file as usize].path.clone(), *cause)).collect()
    }

    #[test]
    fn cones_follow_imports_packages_and_conftests() {
        let (all, cones) = cones_of(&with(TREE, &[]), &config());
        assert_eq!(
            cones.iter().map(|c| c.unit.as_str()).collect::<Vec<_>>(),
            ["tests.test_core", "tests.test_island", "tests.test_plugins"]
        );
        assert_eq!(
            inputs(&all, cone(&cones, "tests.test_core")),
            [
                "conftest.py",
                "fixtures.py",
                "lib/__init__.py",
                "lib/core.py",
                "lib/deep/__init__.py",
                "lib/deep/leaf.py",
                "tests/__init__.py",
                "tests/conftest.py",
                "tests/test_core.py",
            ]
        );
        let island = inputs(&all, cone(&cones, "tests.test_island"));
        assert!(island.contains(&"lib/island.py") && island.contains(&"lib/core.py"));
        assert!(!island.contains(&"tests/helper.py") && !island.contains(&"docs/readme.md"));
        assert!(!cone(&cones, "tests.test_core").widened);
    }

    #[test]
    fn graph_resolves_relative_imports_and_names_externals() {
        let all = AllFacts::from_sources(TREE);
        let graph = ImportGraph::build(&all, &config());
        let core = graph.node_of("lib.core").unwrap();
        let reached: Vec<&str> = graph.imports_of(core).iter().map(|n| graph.module_of(*n).unwrap()).collect();
        assert_eq!(reached, ["lib", "lib.deep", "lib.deep.leaf"]);
        assert!(graph.external.contains("json") && graph.external.contains("importlib"));
        assert!(graph.unresolved_relative.is_empty());
    }

    /// An import that names nothing is not ignored: every cone that reaches
    /// the importer is widened.
    #[test]
    fn tooth_a_dangling_relative_import_widens() {
        let files = with(
            &[
                ("pkg/__init__.py", ""),
                ("pkg/a.py", "from .gone import x\nfrom ... import y\n"),
                ("tests/test_a.py", "import pkg.a\n"),
            ],
            &[],
        );
        let (all, cones) = cones_of(&files, &config());
        let borrowed: Vec<(&str, u32, &str)> = files.iter().map(|(p, m, c)| (p.as_str(), *m, c.as_str())).collect();
        let graph = ImportGraph::build(&AllFacts::from_entries(&borrowed), &config());
        let unresolved: Vec<(&str, u32)> = graph.unresolved_relative.iter().map(|u| (u.import.as_str(), u.line)).collect();
        assert_eq!(unresolved, [(".gone", 1), ("...", 2)]);
        assert_eq!(causes(&all, cone(&cones, "tests.test_a")), [("pkg/a.py".to_owned(), Cause::UnresolvedRelativeImport)]);
    }

    #[test]
    fn tooth_one_byte_in_a_transitive_dependency_changes_exactly_the_cones_that_reach_it() {
        let (_, before) = cones_of(&with(TREE, &[]), &config());
        let (_, after) = cones_of(&with(TREE, &[("lib/deep/leaf.py", "VALUE = 2\n")]), &config());
        for unit in ["tests.test_core", "tests.test_island"] {
            assert_ne!(cone(&before, unit).digest, cone(&after, unit).digest, "{unit}");
        }
        let (_, island_edit) = cones_of(&with(TREE, &[("lib/island.py", "ALONE = 2\n")]), &config());
        assert_eq!(cone(&before, "tests.test_core").digest, cone(&island_edit, "tests.test_core").digest);
        assert_ne!(cone(&before, "tests.test_island").digest, cone(&island_edit, "tests.test_island").digest);
    }

    #[test]
    fn tooth_disjoint_changes_preserve_cone_digests_byte_for_byte() {
        let (_, before) = cones_of(&with(TREE, &[]), &config());
        let edits = [("docs/readme.md", "new docs\n"), ("tests/helper.py", "X = 1\n"), ("brand/new.py", "Y = 2\n")];
        let (_, after) = cones_of(&with(TREE, &edits), &config());
        for unit in ["tests.test_core", "tests.test_island"] {
            assert_eq!(cone(&before, unit).digest.as_bytes(), cone(&after, unit).digest.as_bytes(), "{unit}");
        }
    }

    #[test]
    fn tooth_revert_restores_the_exact_cone_digest() {
        let (_, good) = cones_of(&with(TREE, &[]), &config());
        let (_, bad) = cones_of(&with(TREE, &[("lib/core.py", "from .deep import leaf\nBUG = 1\n")]), &config());
        let (_, reverted) = cones_of(&with(TREE, &[("lib/core.py", "from .deep import leaf\nimport json\n")]), &config());
        assert_ne!(cone(&good, "tests.test_core").digest, cone(&bad, "tests.test_core").digest);
        assert_eq!(good, reverted);
    }

    #[test]
    fn tooth_an_undeclared_dynamic_load_widens_to_the_whole_tree() {
        let (all, cones) = cones_of(&with(TREE, &[]), &config());
        let plugins = cone(&cones, "tests.test_plugins");
        assert!(plugins.widened);
        assert_eq!(plugins.input_files, all.files.len());
        assert_eq!(causes(&all, plugins), [("lib/plugins.py".to_owned(), Cause::DynamicLoad)]);

        // So a change no import reaches still moves it, and only it.
        let (_, after) = cones_of(&with(TREE, &[("docs/readme.md", "new docs\n")]), &config());
        assert_ne!(plugins.digest, cone(&after, "tests.test_plugins").digest);
        assert_eq!(cone(&cones, "tests.test_core").digest, cone(&after, "tests.test_core").digest);
    }

    #[test]
    fn exported_digest_is_the_admissibility_engines_digest_and_binds_the_context() {
        let files = with(TREE, &[]);
        let (all, cones) = cones_of(&files, &config());
        for cone in &cones {
            assert_eq!(cone.digest, cone.to_cone(&all).digest(), "{}", cone.unit);
        }
        let borrowed: Vec<(&str, u32, &str)> = files.iter().map(|(p, m, c)| (p.as_str(), *m, c.as_str())).collect();
        let all = AllFacts::from_entries(&borrowed);
        let graph = ImportGraph::build(&all, &config());
        let other = super::cones(&all, &graph, &config(), &Digest32::blake3(b"another toolchain"));
        for (a, b) in cones.iter().zip(&other) {
            assert_ne!(a.digest, b.digest, "{}", a.unit);
        }
    }

    #[test]
    fn source_roots_name_modules() {
        assert_eq!(module_name("src/pkg/mod.py", "src").as_deref(), Some("pkg.mod"));
        assert_eq!(module_name("src/pkg/__init__.py", "src/").as_deref(), Some("pkg"));
        assert_eq!(module_name("pkg/mod.py", "").as_deref(), Some("pkg.mod"));
        assert_eq!(module_name("other/mod.py", "src"), None);
        assert_eq!(module_name("__init__.py", ""), None);
        let config =
            ImportConfig { roots: vec!["".into(), "src".into()], tests: vec!["test_*.py".into()], ..ImportConfig::default() };
        let (all, cones) = cones_of(&with(&[("src/pkg/mod.py", "A = 1\n"), ("test_x.py", "import pkg.mod\n")], &[]), &config);
        assert_eq!(inputs(&all, &cones[0]), ["src/pkg/mod.py", "test_x.py"]);
    }

    const READERS: &[(&str, &str)] = &[
        ("tests/__init__.py", ""),
        ("tests/support.py", "from pathlib import Path\nREPO = Path(__file__).resolve().parent.parent\nDATA = REPO / 'data'\n"),
        (
            "tests/test_table.py",
            "import json\nfrom tests.support import REPO\ndef test():\n    json.load(open(REPO / 'data' / 'table.json'))\n",
        ),
        ("tests/test_listing.py", "import os\nfrom tests import support\ndef test():\n    assert os.listdir(support.DATA)\n"),
        (
            "tests/test_walk.py",
            "import os\nfrom tests.support import REPO\ndef test():\n    for _ in os.walk(REPO / 'lib'): pass\n",
        ),
        ("tests/test_pure.py", "def test():\n    assert 1\n"),
        ("data/table.json", "{}\n"),
        ("data/other.json", "{}\n"),
        ("data/deep/more.json", "{}\n"),
        ("lib/a.py", "A = 1\n"),
        ("lib/sub/b.txt", "b\n"),
        ("docs/readme.md", "docs\n"),
    ];

    /// The incident class the audit names: a test reads a file it does not
    /// import. The file is in its cone, so changing it invalidates the test.
    #[test]
    fn tooth_a_data_file_a_test_opens_is_in_its_cone() {
        let (all, before) = cones_of(&with(READERS, &[]), &config());
        let table = cone(&before, "tests.test_table");
        assert!(!table.widened, "{:?}", causes(&all, table));
        assert_eq!(inputs(&all, table), ["data/table.json", "tests/__init__.py", "tests/support.py", "tests/test_table.py"]);

        let (_, after) = cones_of(&with(READERS, &[("data/table.json", "{\"k\": 1}\n")]), &config());
        assert_ne!(table.digest, cone(&after, "tests.test_table").digest);
        // A file it does not read does not move it.
        let (_, other) = cones_of(&with(READERS, &[("data/other.json", "{\"k\": 1}\n"), ("docs/readme.md", "x\n")]), &config());
        assert_eq!(table.digest, cone(&other, "tests.test_table").digest);
        assert_eq!(cone(&before, "tests.test_pure").digest, cone(&after, "tests.test_pure").digest);
    }

    #[test]
    fn tooth_listings_and_walks_see_files_that_appear() {
        let (all, before) = cones_of(&with(READERS, &[]), &config());
        let listing = cone(&before, "tests.test_listing");
        assert_eq!(
            inputs(&all, listing),
            [
                "data/deep/more.json",
                "data/other.json",
                "data/table.json",
                "tests/__init__.py",
                "tests/support.py",
                "tests/test_listing.py"
            ]
        );
        let walk = cone(&before, "tests.test_walk");
        assert_eq!(
            inputs(&all, walk),
            ["lib/a.py", "lib/sub/b.txt", "tests/__init__.py", "tests/support.py", "tests/test_walk.py"]
        );

        // A new file in the listed directory, and one deep under the walked one.
        let (_, after) = cones_of(&with(READERS, &[("data/new.json", "{}\n"), ("lib/sub/deeper/c.txt", "c\n")]), &config());
        assert_ne!(listing.digest, cone(&after, "tests.test_listing").digest);
        assert_ne!(walk.digest, cone(&after, "tests.test_walk").digest);
        // A listing shows subdirectory names, which exist because of what is
        // below them: a new directory deep inside moves the cone too.
        let (_, deep) = cones_of(&with(READERS, &[("data/brand/new/x.json", "{}\n")]), &config());
        assert_ne!(listing.digest, cone(&deep, "tests.test_listing").digest);
    }

    /// Reads the analysis cannot bound widen under the strict model. Under
    /// the hermetic model they do not, and a known directory with an unknown
    /// tail reads that directory.
    #[test]
    fn tooth_unbounded_reads_widen_strictly_and_are_bounded_only_by_an_enforced_view() {
        let tree = [
            ("tests/__init__.py", ""),
            ("tests/test_param.py", "def read(path):\n    return open(path).read()\ndef test():\n    read('x')\n"),
            (
                "tests/test_tail.py",
                "import os\nHERE = os.path.dirname(__file__)\ndef test(name):\n    open(os.path.join(HERE, 'fixtures', name))\n",
            ),
            ("tests/test_child.py", "import subprocess\ndef test():\n    subprocess.run(['make'])\n"),
            ("tests/test_scan.py", "import os\ndef test(root):\n    os.listdir(root)\n"),
            ("tests/fixtures/a.json", "{}\n"),
            ("other/b.json", "{}\n"),
        ];
        let (all, strict) = cones_of(&with(&tree, &[]), &config());
        assert_eq!(causes(&all, cone(&strict, "tests.test_param")), [("tests/test_param.py".to_owned(), Cause::OpaqueRead)]);
        assert_eq!(causes(&all, cone(&strict, "tests.test_tail")), [("tests/test_tail.py".to_owned(), Cause::UnresolvedRead)]);
        assert_eq!(causes(&all, cone(&strict, "tests.test_child")), [("tests/test_child.py".to_owned(), Cause::Process)]);
        assert!(strict.iter().all(|c| c.widened && c.input_files == all.files.len()));

        let (all, enforced) = cones_of(&with(&tree, &[]), &hermetic());
        assert!(!cone(&enforced, "tests.test_param").widened && !cone(&enforced, "tests.test_child").widened);
        let tail = cone(&enforced, "tests.test_tail");
        assert_eq!(inputs(&all, tail), ["tests/__init__.py", "tests/fixtures/a.json", "tests/test_tail.py"]);
        assert!(!cone(&enforced, "tests.test_scan").widened);
    }

    #[test]
    fn guards_match_units_by_pattern_and_star_reads_everything() {
        let mut guarded = config();
        guarded.guards.insert("tests.test_island".into(), vec!["data/*".into(), "docs/readme.md".into()]);
        guarded.guards.insert("tests.test_co*".into(), vec!["docs/*".into()]);
        guarded.guards.insert("tests.absent".into(), vec!["*".into()]);
        let (all, cones) = cones_of(&with(TREE, &[]), &guarded);
        let island = inputs(&all, cone(&cones, "tests.test_island"));
        assert!(island.contains(&"data/table.json") && island.contains(&"docs/readme.md"));
        assert!(inputs(&all, cone(&cones, "tests.test_core")).contains(&"docs/readme.md"));
        let (_, after) = cones_of(&with(TREE, &[("data/table.json", "{\"k\": 1}\n")]), &guarded);
        assert_ne!(cone(&cones, "tests.test_island").digest, cone(&after, "tests.test_island").digest);
        assert_eq!(cone(&cones, "tests.test_core").digest, cone(&after, "tests.test_core").digest);

        guarded.guards.insert("tests.test_core".into(), vec!["*".into()]);
        let (all, cones) = cones_of(&with(TREE, &[]), &guarded);
        let core = cone(&cones, "tests.test_core");
        assert!(core.widened && core.input_files == all.files.len());
        assert_eq!(causes(&all, core), [("tests/test_core.py".to_owned(), Cause::GuardEverything)]);
    }

    #[test]
    fn runner_configuration_is_an_input_of_every_unit() {
        let (all, before) = cones_of(&with(TREE, &[("pytest.ini", "[pytest]\n")]), &config());
        assert!(inputs(&all, cone(&before, "tests.test_core")).contains(&"pytest.ini"));
        let (_, after) = cones_of(&with(TREE, &[("pytest.ini", "[pytest]\naddopts = -x\n")]), &config());
        for unit in ["tests.test_core", "tests.test_island", "tests.test_plugins"] {
            assert_ne!(cone(&before, unit).digest, cone(&after, unit).digest, "{unit}");
        }
    }

    const PLUGINS: &[(&str, &str)] = &[
        ("lib/__init__.py", ""),
        ("lib/loader.py", "import importlib\ndef load(name):\n    return importlib.import_module(f'lib.plugins.{name}')\n"),
        ("lib/plugins/__init__.py", ""),
        ("lib/plugins/one.py", "import lib.shared\n"),
        ("lib/shared.py", "S = 1\n"),
        ("lib/unrelated.py", "U = 1\n"),
        ("tests/test_loader.py", "from lib import loader\n"),
    ];

    /// A declaration is believed only while the loader's source agrees with
    /// it, and the check runs on the tree under test: an edit that makes the
    /// loader load something else takes the declaration out of force.
    #[test]
    fn tooth_loader_declarations_are_verified_against_the_loaders_source() {
        let mut declared = config();
        declared.loader_modules.insert("lib.loader".into(), vec!["lib.plugins.*".into()]);
        let report = |files: &Entries, config: &ImportConfig| {
            let borrowed: Vec<(&str, u32, &str)> = files.iter().map(|(p, m, c)| (p.as_str(), *m, c.as_str())).collect();
            ImportGraph::build(&AllFacts::from_entries(&borrowed), config).loaders
        };

        let (all, cones) = cones_of(&with(PLUGINS, &[]), &declared);
        let unit = cone(&cones, "tests.test_loader");
        assert!(!unit.widened, "{:?}", causes(&all, unit));
        // What the loader can load, and what that imports, is in the cone.
        assert_eq!(
            inputs(&all, unit),
            [
                "lib/__init__.py",
                "lib/loader.py",
                "lib/plugins/__init__.py",
                "lib/plugins/one.py",
                "lib/shared.py",
                "tests/test_loader.py"
            ]
        );
        let verified = report(&with(PLUGINS, &[]), &declared);
        assert_eq!((verified[0].status, verified[0].in_force), (LoaderStatus::Verified, true));
        let (_, plugin_edit) = cones_of(&with(PLUGINS, &[("lib/plugins/two.py", "T = 1\n")]), &declared);
        assert_ne!(unit.digest, cone(&plugin_edit, "tests.test_loader").digest);
        let (_, unrelated) = cones_of(&with(PLUGINS, &[("lib/unrelated.py", "U = 2\n")]), &declared);
        assert_eq!(unit.digest, cone(&unrelated, "tests.test_loader").digest);

        // The lane edits the loader to reach wider than what was declared:
        // the declaration no longer bounds it, so it is out of force.
        let wider = with(
            PLUGINS,
            &[("lib/loader.py", "import importlib\ndef load(name):\n    return importlib.import_module(f'lib.{name}')\n")],
        );
        let (all, cones) = cones_of(&wider, &declared);
        assert_eq!(causes(&all, cone(&cones, "tests.test_loader")), [("lib/loader.py".to_owned(), Cause::UnverifiedLoader)]);
        assert_eq!(report(&wider, &declared)[0].status, LoaderStatus::Unverifiable);
        // Or somewhere the declaration names nothing at all.
        let moved = with(
            PLUGINS,
            &[(
                "lib/loader.py",
                "import importlib\ndef load(name):\n    return importlib.import_module(f'other.place.{name}')\n",
            )],
        );
        let (all, cones) = cones_of(&moved, &declared);
        assert_eq!(causes(&all, cone(&cones, "tests.test_loader")), [("lib/loader.py".to_owned(), Cause::ContradictedLoader)]);
        assert_eq!(report(&moved, &declared)[0].status, LoaderStatus::Contradicted);

        // Or to compute the name entirely: nothing left to check against.
        let blind =
            with(PLUGINS, &[("lib/loader.py", "import importlib\ndef load(name):\n    return importlib.import_module(name)\n")]);
        let (all, cones) = cones_of(&blind, &declared);
        assert_eq!(causes(&all, cone(&cones, "tests.test_loader")), [("lib/loader.py".to_owned(), Cause::UnverifiedLoader)]);
        let trusting = ImportConfig { unverified_loaders: UnverifiedLoaders::Trust, ..declared.clone() };
        let (_, cones) = cones_of(&blind, &trusting);
        assert!(!cone(&cones, "tests.test_loader").widened);
        assert!(report(&blind, &trusting)[0].in_force);

        // The source loads "something under lib/plugins/" and the declaration
        // names one file there: consistent, but not shown. Not in force.
        let narrow =
            ImportConfig { loader_modules: [("lib.loader".to_owned(), vec!["lib.plugins.one".to_owned()])].into(), ..config() };
        let (all, cones) = cones_of(&with(PLUGINS, &[]), &narrow);
        assert_eq!(causes(&all, cone(&cones, "tests.test_loader")), [("lib/loader.py".to_owned(), Cause::UnverifiedLoader)]);
        assert_eq!(report(&with(PLUGINS, &[]), &narrow)[0].status, LoaderStatus::Unverifiable);

        // Declarations that name nothing are reported, not silently dropped.
        declared.loader_modules.insert("lib.gone".into(), vec![]);
        declared.loaders.insert("lib/shared.py".into(), vec!["lib/*".into()]);
        let statuses: Vec<(String, LoaderStatus)> =
            report(&with(PLUGINS, &[]), &declared).into_iter().map(|r| (r.declared, r.status)).collect();
        assert_eq!(
            statuses,
            [
                ("lib.gone".to_owned(), LoaderStatus::Missing),
                ("lib.loader".to_owned(), LoaderStatus::Verified),
                ("lib/shared.py".to_owned(), LoaderStatus::NoDynamicLoad),
            ]
        );
    }

    #[test]
    fn modules_loaded_by_literal_path_are_edges_even_without_a_py_suffix() {
        let tree = [
            ("bin/tool", "#!/usr/bin/env python3\nimport helpers.util\n"),
            ("helpers/util.py", "U = 1\n"),
            ("tests/test_tool.py", "import runpy, os\nREPO = os.path.dirname(os.path.dirname(__file__))\ndef test():\n    runpy.run_path(os.path.join(REPO, 'bin', 'tool'))\n"),
            ("tests/test_child.py", "import subprocess, sys\ndef test():\n    subprocess.run([sys.executable, 'bin/tool'])\n"),
        ];
        let (all, cones) = cones_of(&with(&tree, &[]), &config());
        for unit in ["tests.test_tool", "tests.test_child"] {
            let cone = cone(&cones, unit);
            assert!(!cone.widened, "{unit}: {:?}", causes(&all, cone));
            let paths = inputs(&all, cone);
            assert!(paths.contains(&"bin/tool") && paths.contains(&"helpers/util.py"), "{unit}: {paths:?}");
        }
    }

    /// An import no root explains may still be an in-tree file that
    /// `sys.path` makes importable: every file of that name is depended on.
    #[test]
    fn tooth_imports_outside_every_root_reach_in_tree_files_of_that_name() {
        let tree = [
            ("scripts/gate.py", "G = 1\n"),
            ("scripts/pkgish/__init__.py", ""),
            ("scripts/pkgish/part.py", "P = 1\n"),
            ("scripts/ns/mod.py", "N = 1\n"),
            ("tests/test_gate.py", "import gate\nfrom pkgish import part\nimport ns.mod\nimport json\n"),
        ];
        let (all, cones) = cones_of(&with(&tree, &[]), &config());
        assert_eq!(
            inputs(&all, &cones[0]),
            [
                "scripts/gate.py",
                "scripts/ns/mod.py",
                "scripts/pkgish/__init__.py",
                "scripts/pkgish/part.py",
                "tests/test_gate.py"
            ]
        );
        // Names outside ASCII are ordinary names (this used to panic).
        let unicode = [("\u{f1}/mod.py", "X = 1\n"), ("tests/test_u.py", "import \u{f1}.mod\nimport \u{e9}t\u{e9}\n")];
        let (all, cones) = cones_of(&with(&unicode, &[]), &config());
        assert_eq!(inputs(&all, &cones[0]), ["tests/test_u.py", "\u{f1}/mod.py"]);
    }

    #[test]
    fn tooth_files_that_did_not_parse_widen() {
        let (all, cones) = cones_of(&with(TREE, &[("lib/island.py", "def broken(:\n")]), &config());
        assert_eq!(causes(&all, cone(&cones, "tests.test_island")), [("lib/island.py".to_owned(), Cause::ParseError)]);
        assert!(!cone(&cones, "tests.test_core").widened);
    }

    fn linked(extra: &[(&str, u32, &str)]) -> Entries {
        let mut files: Entries = vec![
            ("real/__init__.py".into(), FILE, "".into()),
            ("real/impl.py".into(), FILE, "I = 1\n".into()),
            ("real/data.json".into(), FILE, "{}\n".into()),
            ("pkg/__init__.py".into(), FILE, "".into()),
            ("pkg/linked.py".into(), MODE_SYMLINK, "../real/impl.py".into()),
            ("alias".into(), MODE_SYMLINK, "real".into()),
            ("tests/test_file_link.py".into(), FILE, "import pkg.linked\n".into()),
            ("tests/test_dir_link.py".into(), FILE, "import alias.impl\n".into()),
            ("tests/test_plain.py".into(), FILE, "import real.impl\n".into()),
        ];
        files.extend(extra.iter().map(|(p, m, c)| (p.to_string(), *m, c.to_string())));
        files
    }

    #[test]
    fn tooth_symbolic_links_are_followed_inside_the_tree() {
        let (all, cones) = cones_of(&linked(&[]), &config());
        let file_link = cone(&cones, "tests.test_file_link");
        assert!(!file_link.widened, "{:?}", causes(&all, file_link));
        assert_eq!(
            inputs(&all, file_link),
            ["pkg/__init__.py", "pkg/linked.py", "real/__init__.py", "real/impl.py", "tests/test_file_link.py"]
        );
        let dir_link = inputs(&all, cone(&cones, "tests.test_dir_link"));
        assert!(dir_link.contains(&"alias") && dir_link.contains(&"real/impl.py"), "{dir_link:?}");

        // Changing the target, or repointing the link, moves the cone.
        let mut edited = linked(&[]);
        edited.iter_mut().find(|f| f.0 == "real/impl.py").unwrap().2 = "I = 2\n".into();
        let (_, after) = cones_of(&edited, &config());
        assert_ne!(file_link.digest, cone(&after, "tests.test_file_link").digest);
        let mut repointed = linked(&[]);
        repointed.iter_mut().find(|f| f.0 == "pkg/linked.py").unwrap().2 = "../real/__init__.py".into();
        let (_, after) = cones_of(&repointed, &config());
        assert_ne!(file_link.digest, cone(&after, "tests.test_file_link").digest);
    }

    #[test]
    fn tooth_links_that_leave_the_tree_widen_whoever_reaches_them() {
        let mut files = linked(&[]);
        files.iter_mut().find(|f| f.0 == "pkg/linked.py").unwrap().2 = "/etc/passwd".into();
        files.iter_mut().find(|f| f.0 == "alias").unwrap().2 = "../../outside".into();
        let (all, cones) = cones_of(&files, &config());
        assert_eq!(causes(&all, cone(&cones, "tests.test_file_link")), [("pkg/linked.py".to_owned(), Cause::LinkEscape)]);
        assert_eq!(causes(&all, cone(&cones, "tests.test_dir_link")), [("alias".to_owned(), Cause::LinkEscape)]);
        assert!(!cone(&cones, "tests.test_plain").widened);
    }

    /// A cone input is a path, a git mode and a blob.
    #[test]
    fn tooth_mode_changes_and_gitlink_bumps_move_cones() {
        let (_, before) = cones_of(&linked(&[("vendor/sub", MODE_GITLINK, "commit-1")]), &config());
        let mut chmod = linked(&[("vendor/sub", MODE_GITLINK, "commit-1")]);
        chmod.iter_mut().find(|f| f.0 == "real/impl.py").unwrap().1 = MODE_EXECUTABLE;
        let (_, after) = cones_of(&chmod, &config());
        assert_ne!(cone(&before, "tests.test_plain").digest, cone(&after, "tests.test_plain").digest);

        // A whole-tree cone depends on the submodule commit; a bounded one does not.
        let tree = |commit: &str| {
            let mut files = linked(&[("vendor/sub", MODE_GITLINK, commit)]);
            files.push((
                "tests/test_all.py".into(),
                FILE,
                "import subprocess\ndef test():\n    subprocess.run(['make'])\n".into(),
            ));
            files
        };
        let (all, one) = cones_of(&tree("commit-1"), &config());
        let (_, two) = cones_of(&tree("commit-2"), &config());
        assert!(inputs(&all, cone(&one, "tests.test_all")).contains(&"vendor/sub"));
        assert_ne!(cone(&one, "tests.test_all").digest, cone(&two, "tests.test_all").digest);
        assert_eq!(cone(&one, "tests.test_plain").digest, cone(&two, "tests.test_plain").digest);
    }

    #[test]
    fn calls_the_pack_lists_as_whole_tree_readers_widen() {
        let tree = [
            ("census.py", "def census():\n    return 1\n"),
            ("tests/test_census.py", "import census\ndef test():\n    census.census()\n"),
        ];
        let (_, plain) = cones_of(&with(&tree, &[]), &config());
        assert!(!plain[0].widened);
        let listed = ImportConfig { whole_tree_calls: vec!["census.census".into()], ..config() };
        let (all, cones) = cones_of(&with(&tree, &[]), &listed);
        assert_eq!(causes(&all, &cones[0]), [("tests/test_census.py".to_owned(), Cause::WholeTreeCall)]);
    }

    #[test]
    fn tooth_symbol_imports_ignore_unrelated_whole_tree_helpers_and_lazy_package_hooks() {
        let tree = [
            (
                "tests/__init__.py",
                "import os\ndef load_tests(loader, standard, pattern):\n    from tests import support\n    return support.guard(standard)\n",
            ),
            (
                "tests/support.py",
                "import json, os, subprocess\n\
                 REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))\n\
                 def pure_slug(s):\n    return s.strip().lower()\n\
                 def catalog():\n    with open(os.path.join(REPO, 'data', 'defaults.json')) as f:\n        return json.load(f)\n\
                 def probe_bus():\n    return subprocess.run(['systemctl', '--user', 'status'])\n\
                 def walk_all():\n    return list(os.walk(REPO))\n\
                 NEED_PROBES = {'bus': probe_bus}\n\
                 def guard(suite):\n    NEED_PROBES['bus']()\n    return suite\n",
            ),
            ("data/defaults.json", "{\"ok\": true}\n"),
            ("docs/unrelated.md", "notes\n"),
            ("tests/test_pure.py", "from tests.support import pure_slug\ndef test():\n    assert pure_slug(' A ') == 'a'\n"),
            ("tests/test_catalog.py", "from tests import support\ndef test():\n    assert support.catalog()['ok']\n"),
            ("tests/test_guard.py", "from tests.support import guard\ndef test():\n    guard(None)\n"),
        ];
        let (all, cones) = cones_of(&with(&tree, &[]), &config());
        let pure = cone(&cones, "tests.test_pure");
        assert!(!pure.widened, "{:?}", causes(&all, pure));
        assert_eq!(inputs(&all, pure), ["tests/__init__.py", "tests/support.py", "tests/test_pure.py"]);

        let cat = cone(&cones, "tests.test_catalog");
        assert!(!cat.widened, "{:?}", causes(&all, cat));
        assert_eq!(inputs(&all, cat), ["data/defaults.json", "tests/__init__.py", "tests/support.py", "tests/test_catalog.py"]);

        let guarded = cone(&cones, "tests.test_guard");
        assert!(guarded.widened);
        assert_eq!(causes(&all, guarded), [("tests/support.py".to_owned(), Cause::Process)]);
    }

    #[test]
    fn tooth_top_level_class_body_and_default_arg_io_still_taint_every_import() {
        let tree = [
            ("mod_top.py", "import os\nPURE = 1\nlist(os.walk('.'))\n"),
            ("mod_def.py", "import os\nPURE = 1\ndef unused(x=open(os.environ['SECRET'])):\n    return x\n"),
            ("mod_cls.py", "import subprocess\nPURE = 1\nclass Unused:\n    RAN = subprocess.run(['git', 'status'])\n"),
            ("tests/test_top.py", "from mod_top import PURE\nassert PURE == 1\n"),
            ("tests/test_def.py", "from mod_def import PURE\nassert PURE == 1\n"),
            ("tests/test_cls.py", "from mod_cls import PURE\nassert PURE == 1\n"),
        ];
        let (all, cones) = cones_of(&with(&tree, &[]), &config());
        assert_eq!(causes(&all, cone(&cones, "tests.test_top")), [("mod_top.py".to_owned(), Cause::WholeTreeRead)]);
        assert_eq!(causes(&all, cone(&cones, "tests.test_def")), [("mod_def.py".to_owned(), Cause::UnresolvedRead)]);
        assert_eq!(causes(&all, cone(&cones, "tests.test_cls")), [("mod_cls.py".to_owned(), Cause::Process)]);
    }

    #[test]
    fn tooth_transitive_internal_helpers_and_parameter_forwarding_stay_sound() {
        let tree = [
            (
                "lib/catalog.py",
                "import json, os\n\
                 HERE = os.path.dirname(os.path.abspath(__file__))\n\
                 def _load_keys(path):\n    with open(path) as f:\n        return json.load(f)\n\
                 def shipped_default(key, product='fleet'):\n\
                     name = 'a.json' if product == 'fleet' else 'b.json'\n\
                     return _load_keys(os.path.join(HERE, name)).get(key)\n\
                 def forward_user_path(custom):\n    return _load_keys(custom)\n",
            ),
            ("lib/__init__.py", ""),
            ("lib/a.json", "{}\n"),
            ("lib/b.json", "{}\n"),
            ("lib/unrelated.json", "{}\n"),
            ("tests/test_shipped.py", "from lib.catalog import shipped_default\ndef test():\n    shipped_default('k')\n"),
            ("tests/test_private.py", "from lib.catalog import _load_keys\ndef test(p):\n    _load_keys('lib/a.json')\n"),
            (
                "tests/test_forward.py",
                "from lib.catalog import forward_user_path\ndef test():\n    forward_user_path('lib/a.json')\n",
            ),
        ];
        let (all, cones) = cones_of(&with(&tree, &[]), &config());
        let shipped = cone(&cones, "tests.test_shipped");
        assert!(!shipped.widened, "{:?}", causes(&all, shipped));
        assert_eq!(
            inputs(&all, shipped),
            ["lib/__init__.py", "lib/a.json", "lib/b.json", "lib/catalog.py", "tests/test_shipped.py"]
        );

        assert_eq!(causes(&all, cone(&cones, "tests.test_private")), [("lib/catalog.py".to_owned(), Cause::OpaqueRead)]);
        assert_eq!(causes(&all, cone(&cones, "tests.test_forward")), [("lib/catalog.py".to_owned(), Cause::OpaqueRead)]);
    }

    #[test]
    fn tooth_dynamic_introspection_wildcards_bare_modules_and_decorators_fall_back_soundly() {
        let tree = [
            ("lib/__init__.py", ""),
            (
                "lib/helpers.py",
                "import subprocess\n\
                 class LazyRe:\n    def __getattr__(self, name):\n        return name\n\
                 def clean():\n    return LazyRe()\n\
                 def dirty():\n    subprocess.run(['id'])\n\
                 def via_globals(k):\n    return globals()[k]()\n\
                 def via_vars(k):\n    return vars()[k]()\n",
            ),
            (
                "lib/decorated.py",
                "import subprocess\n\
                 PURE = 1\n\
                 def register(fn):\n    fn()\n    return fn\n\
                 @register\n\
                 def eager():\n    subprocess.run(['id'])\n",
            ),
            (
                "lib/pep562.py",
                "import subprocess\n\
                 PURE = 1\n\
                 def __getattr__(name):\n    subprocess.run(['id'])\n    return 1\n",
            ),
            ("tests/test_clean.py", "from lib.helpers import clean\ndef test():\n    clean()\n"),
            ("tests/test_bare.py", "from lib import helpers\ndef patch(m):\n    return m\ndef test():\n    patch(helpers)\n"),
            ("tests/test_star.py", "from lib.helpers import *\ndef test():\n    clean()\n"),
            ("tests/test_globals.py", "from lib.helpers import via_globals\ndef test():\n    via_globals('clean')\n"),
            ("tests/test_vars.py", "from lib.helpers import via_vars\ndef test():\n    via_vars('clean')\n"),
            ("tests/test_decorated.py", "from lib.decorated import PURE\nassert PURE == 1\n"),
            ("tests/test_pep562.py", "from lib.pep562 import PURE\nassert PURE == 1\n"),
        ];
        let (_, cones) = cones_of(&with(&tree, &[]), &config());
        assert!(!cone(&cones, "tests.test_clean").widened);
        for widened_unit in [
            "tests.test_bare",
            "tests.test_star",
            "tests.test_globals",
            "tests.test_vars",
            "tests.test_decorated",
            "tests.test_pep562",
        ] {
            assert!(cone(&cones, widened_unit).widened, "{widened_unit} must fall back to widened");
        }
    }

    #[test]
    fn tooth_reexports_and_plain_singleton_construction_stay_narrow_unless_init_touches_state() {
        let tree = [
            ("pkg/__init__.py", "from .clean import Clean\nfrom .dirty import Dirty\n"),
            ("pkg/clean.py", "class Clean:\n    pass\n"),
            ("pkg/dirty.py", "import subprocess\nclass Dirty:\n    def run(self):\n        subprocess.run(['id'])\n"),
            (
                "pkg/watched.py",
                "import os, weakref\n\
                 _WATCHERS = weakref.WeakSet()\n\
                 class Watched:\n\
                     def __init__(self):\n\
                         self.fd = -1\n\
                         _WATCHERS.add(self)\n\
                     def sweep(self, p):\n\
                         return os.stat(p)\n\
                 WATCHED = Watched()\n\
                 def pure():\n    return 42\n",
            ),
            (
                "pkg/eager_cls.py",
                "import os\n\
                 class Eager:\n\
                     def __init__(self):\n\
                         self.sweep('x')\n\
                     def sweep(self, p):\n\
                         return os.stat(p)\n\
                 EAGER = Eager()\n\
                 def pure():\n    return 1\n",
            ),
            ("tests/test_reexport.py", "from pkg import Clean\ndef test():\n    Clean()\n"),
            ("pkg/plain.py", "class Plain:\n    def __init__(self):\n        self.fd = -1\n    def read(self, p):\n        return open(p).read()\nINSTANCE = Plain()\ndef pure():\n    return 1\n"),
            ("pkg/hooks.py", "class Hooked:\n    def __init__(self):\n        self.fd = -1\n    def __setattr__(self, name, value):\n        open('hidden.txt').read()\nINSTANCE = Hooked()\ndef pure():\n    return 1\n"),
            ("hidden.txt", "hello\n"),
            ("tests/test_plain.py", "from pkg.plain import pure\npure()\n"),
            ("tests/test_hooks.py", "from pkg.hooks import pure\npure()\n"),
            ("tests/test_watched_pure.py", "from pkg.watched import pure\ndef test():\n    assert pure() == 42\n"),
            ("tests/test_watched_use.py", "from pkg.watched import WATCHED\ndef test(p):\n    WATCHED.sweep(p)\n"),
            ("tests/test_eager_cls.py", "from pkg.eager_cls import pure\ndef test():\n    pure()\n"),
        ];
        let (all, cones) = cones_of(&with(&tree, &[]), &config());
        let reexp = cone(&cones, "tests.test_reexport");
        assert!(!reexp.widened, "{:?}", causes(&all, reexp));
        assert_eq!(inputs(&all, reexp), ["pkg/__init__.py", "pkg/clean.py", "pkg/dirty.py", "tests/test_reexport.py"]);

        assert!(!cone(&cones, "tests.test_plain").widened);
        assert!(inputs(&all, cone(&cones, "tests.test_hooks")).contains(&"hidden.txt"));
        let wpure = cone(&cones, "tests.test_watched_pure");
        assert!(wpure.widened, "escaping self must conservatively include instance methods");
        assert!(cone(&cones, "tests.test_watched_use").widened);
        assert!(cone(&cones, "tests.test_eager_cls").widened);
    }

    #[test]
    fn tooth_attribute_reads_and_subclass_hooks_execute_at_import_time() {
        let tree = [
            ("data/descriptor.txt", "a"),
            ("data/subclass.txt", "b"),
            ("descriptors.py", "class Holder:\n    @property\n    def data(self):\n        return open('data/descriptor.txt').read()\nobj = Holder()\nVALUE = obj.data\nPURE = 1\n"),
            ("subclasses.py", "class Base:\n    def __init_subclass__(cls):\n        open('data/subclass.txt').read()\nclass Child(Base):\n    pass\nPURE = 1\n"),
            ("tests/test_descriptor.py", "from descriptors import PURE\nassert PURE == 1\n"),
            ("tests/test_subclass.py", "from subclasses import PURE\nassert PURE == 1\n"),
        ];
        let (all, cones) = cones_of(&with(&tree, &[]), &config());
        assert!(inputs(&all, cone(&cones, "tests.test_descriptor")).contains(&"data/descriptor.txt"));
        assert!(inputs(&all, cone(&cones, "tests.test_subclass")).contains(&"data/subclass.txt"));
    }

    #[test]
    fn tooth_shadowed_and_rebound_decorators_are_eager() {
        let tree = [
            ("builtin.py", "property = lambda f: f()\n@property\ndef eager():\n    open('builtin.txt').read()\nPURE = 1\n"),
            ("imported.py", "import functools\nfunctools.cache = lambda f: f()\n@functools.cache\ndef eager():\n    open('imported.txt').read()\nPURE = 1\n"),
            ("builtin.txt", "a"),
            ("imported.txt", "b"),
            ("tests/test_builtin.py", "from builtin import PURE\n"),
            ("tests/test_imported.py", "from imported import PURE\n"),
        ];
        let (all, cones) = cones_of(&with(&tree, &[]), &config());
        assert!(inputs(&all, cone(&cones, "tests.test_builtin")).contains(&"builtin.txt"));
        assert!(inputs(&all, cone(&cones, "tests.test_imported")).contains(&"imported.txt"));
    }

    #[test]
    fn tooth_stdlib_imports_do_not_false_match_unrelated_subdirectories_but_match_siblings() {
        let tree = [
            ("land/checks/select.py", "import subprocess\ndef run():\n    subprocess.run(['git', 'status'])\nrun()\n"),
            ("land/checks/sibling.py", "import select\n"),
            ("fabd/__init__.py", ""),
            ("fabd/poller.py", "import select\ndef poll():\n    return select\n"),
            ("tests/test_poller.py", "from fabd.poller import poll\ndef test():\n    poll()\n"),
            ("tests/test_sibling.py", "import runpy\ndef test():\n    runpy.run_path('land/checks/sibling.py')\n"),
        ];
        let (all, cones) = cones_of(&with(&tree, &[]), &config());
        let poller = cone(&cones, "tests.test_poller");
        assert!(!poller.widened, "{:?}", causes(&all, poller));
        assert_eq!(inputs(&all, poller), ["fabd/__init__.py", "fabd/poller.py", "tests/test_poller.py"]);

        let sib = cone(&cones, "tests.test_sibling");
        assert!(sib.widened);
        assert_eq!(causes(&all, sib), [("land/checks/select.py".to_owned(), Cause::Process)]);
    }
}
