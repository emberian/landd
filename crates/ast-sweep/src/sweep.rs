//! Drive the `Map` pass over a git tree or a directory, then `Reduce`.

use crate::cache::{BlobFactsCache, Pack};
use crate::extract::extract;
use crate::facts::{FileFacts, FileKind, Language, MODE_EXECUTABLE, MODE_SYMLINK};
use crate::imports::{self, Cause, ImportCone, ImportGraph, LoaderReport};
use crate::reduce::{self, Catalogs, RuleVerdict, VerdictStatus};
use crate::rules::RulePack;
use landd_core::git::{EntryKind, GitError, GitRepo};
use landd_core::Oid;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

/// A link target longer than this is not a path.
const MAX_LINK_BYTES: u64 = 4096;
/// Parse sets up to this size run on the light pool.
const SMALL_PARSE: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum SweepError {
    #[error(transparent)]
    Git(#[from] GitError),
    #[error("could not start a blob reader: {0}")]
    Reader(String),
    #[error("reading {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("path {0:?} is not UTF-8; refusing to guess which file it names")]
    NonUtf8Path(String),
}

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub oid: Oid,
    pub mode: u32,
    pub kind: Option<FileKind>,
    pub facts: Option<Arc<FileFacts>>,
}

impl FileEntry {
    /// Python by name, or by its `#!` line.
    pub fn is_python(&self) -> bool {
        match self.kind {
            Some(FileKind::Python) => true,
            Some(FileKind::Sniff) => self.facts.as_deref().is_some_and(|f| f.language == Language::Python),
            _ => false,
        }
    }

    pub fn is_recipe(&self) -> bool {
        self.kind == Some(FileKind::Recipe) || self.facts.as_deref().is_some_and(|f| f.language == Language::Recipe)
    }
}

/// Every file of one tree, in byte order of path, with the facts of the
/// fact-bearing ones.
#[derive(Debug, Clone, Default)]
pub struct AllFacts {
    pub tree: Option<Oid>,
    pub files: Vec<FileEntry>,
}

impl AllFacts {
    pub fn index_of(&self, path: &str) -> Option<usize> {
        self.files.binary_search_by(|probe| probe.path.as_str().cmp(path)).ok()
    }

    pub fn find(&self, path: &str) -> Option<&FileEntry> {
        self.index_of(path).map(|i| &self.files[i])
    }

    pub fn paths(&self) -> Vec<&str> {
        self.files.iter().map(|f| f.path.as_str()).collect()
    }

    /// Facts for an in-memory tree of `(path, content)` regular files.
    pub fn from_sources(sources: &[(&str, &str)]) -> Self {
        let entries: Vec<(&str, u32, &str)> = sources.iter().map(|(path, content)| (*path, 0o100644, *content)).collect();
        Self::from_entries(&entries)
    }

    /// Facts for an in-memory tree of `(path, git mode, content)`; a
    /// symbolic link's content is its target.
    pub fn from_entries(entries: &[(&str, u32, &str)]) -> Self {
        let mut files: Vec<FileEntry> = entries
            .iter()
            .map(|(path, mode, content)| {
                let kind = FileKind::of_entry(path, *mode);
                FileEntry {
                    path: (*path).to_owned(),
                    oid: Oid::git_blob_sha1(content.as_bytes()),
                    mode: *mode,
                    kind,
                    facts: kind.map(|k| Arc::new(extract(k, content.as_bytes()))),
                }
            })
            .collect();
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Self { tree: None, files }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SweepStats {
    pub files: usize,
    /// Python and recipe files: the ones that carry facts.
    pub fact_files: usize,
    /// Runs of sibling files that share a pack.
    pub packs: usize,
    /// Packs answered whole, from memory or by one file read.
    pub packs_hit: usize,
    pub packs_from_memory: usize,
    /// Blobs of a missed pack read one by one from the blob cache.
    pub blobs_from_cache: usize,
    /// Blobs of a missed pack found in memory (no read at all).
    pub blobs_from_memory: usize,
    pub blobs_parsed: usize,
    pub cache_write_errors: usize,
    pub list_ms: f64,
    /// The whole map pass: `load_ms` + `parse_ms` + bookkeeping.
    pub map_ms: f64,
    pub load_ms: f64,
    pub parse_ms: f64,
}

fn ms_since(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

/// A few workers for everything that is not parsing: loading packs,
/// reducing, building the graph, exporting cones. These jobs are short and
/// allocation-heavy; on a many-core box more threads spend their time
/// contending for the address space instead of working.
pub(crate) fn light_pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).min(8);
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .stack_size(16 << 20)
            .thread_name(|i| format!("ast-sweep-light-{i}"))
            .build()
            .expect("the light pool starts")
    })
}

/// One worker per core with deep stacks, for parsing: the extractor recurses
/// over syntax trees. Created on first use, so a warm sweep never pays for it.
pub(crate) fn pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .stack_size(16 << 20)
            .thread_name(|i| format!("ast-sweep-{i}"))
            .build()
            .expect("the worker pool starts")
    })
}

/// A run of fact-bearing sibling files that share one pack.
struct Group {
    /// Indices into the file list.
    members: Vec<usize>,
    /// `(blob id, kind)` of each member: what the pack is keyed by.
    keys: Vec<(Oid, FileKind)>,
}

/// Whether a pack ends before the file called `name`. The cut depends on the
/// name alone, so adding or removing a file moves no other boundary and a
/// change invalidates one small pack, not its whole directory.
fn starts_pack(name: &str) -> bool {
    let hash = name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3));
    (hash >> 32) % 6 == 0
}

/// Sweep the tree of `rev` straight from the object store.
pub fn sweep_git(repo: &GitRepo, rev: &str, cache: Option<&BlobFactsCache>) -> Result<(AllFacts, SweepStats), SweepError> {
    let started = Instant::now();
    // The revision is resolved to a tree exactly once; a ref that moves
    // while the sweep runs cannot make the listing and the id disagree.
    let root = repo.blob_reader()?.resolve_tree(rev)?;
    let listing = repo.ls_tree(&root.to_hex(), false)?;
    let mut stats = SweepStats { list_ms: ms_since(started), ..SweepStats::default() };
    let mapping = Instant::now();

    let mut files: Vec<FileEntry> = listing
        .into_iter()
        // Gitlinks stay: bumping a submodule changes the tree units run on.
        .filter(|entry| entry.kind != EntryKind::Tree)
        .map(|entry| FileEntry {
            kind: FileKind::of_entry(&entry.path, entry.mode),
            path: entry.path,
            oid: entry.oid,
            mode: entry.mode,
            facts: None,
        })
        .collect();
    files.sort_by(|a, b| a.path.cmp(&b.path));

    let mut groups: Vec<Group> = Vec::new();
    let mut open_dir: Option<&str> = None;
    for (index, file) in files.iter().enumerate() {
        if file.kind.is_none() {
            continue;
        }
        let (dir, name) = file.path.rsplit_once('/').unwrap_or(("", &file.path));
        if open_dir != Some(dir) || starts_pack(name) {
            groups.push(Group { members: Vec::new(), keys: Vec::new() });
            open_dir = Some(dir);
        }
        let group = groups.last_mut().expect("a group is open");
        group.members.push(index);
        group.keys.push((file.oid, file.kind.expect("checked above")));
    }
    stats.files = files.len();
    stats.fact_files = groups.iter().map(|g| g.members.len()).sum();
    stats.packs = groups.len();

    // Warm path: one lookup per unchanged pack, else one per known blob.
    enum Loaded {
        Pack(Pack, bool),
        /// Per member: its facts and whether they came from memory.
        Blobs(Vec<Option<(Arc<FileFacts>, bool)>>),
    }
    let mut loaded: Vec<Loaded> = light_pool().install(|| {
        groups
            .par_iter()
            .map(|group| {
                let Some(cache) = cache else {
                    return Loaded::Blobs(vec![None; group.members.len()]);
                };
                match cache.get_pack(&group.keys) {
                    Some((pack, from_memory)) => Loaded::Pack(pack, from_memory),
                    None => Loaded::Blobs(group.keys.iter().map(|(oid, kind)| cache.get_blob(*kind, oid)).collect()),
                }
            })
            .collect()
    });

    // Cold path: read and parse the blobs nobody has seen, in parallel, each
    // worker on its own persistent `cat-file --batch` stream.
    let mut cold: Vec<(usize, usize)> = Vec::new();
    for (g, group) in loaded.iter().enumerate() {
        match group {
            Loaded::Pack(_, from_memory) => {
                stats.packs_hit += 1;
                stats.packs_from_memory += usize::from(*from_memory);
            }
            Loaded::Blobs(slots) => {
                for (s, slot) in slots.iter().enumerate() {
                    match slot {
                        Some((_, true)) => stats.blobs_from_memory += 1,
                        Some((_, false)) => stats.blobs_from_cache += 1,
                        None => cold.push((g, s)),
                    }
                }
            }
        }
    }
    stats.load_ms = ms_since(mapping);
    let parsing = Instant::now();
    let write_errors = AtomicUsize::new(0);
    let parse = || {
        cold.par_iter()
            .map_init(
                || repo.blob_reader(),
                |reader, (g, s)| {
                    let reader = reader.as_mut().map_err(|e| SweepError::Reader(e.to_string()))?;
                    let (oid, kind) = groups[*g].keys[*s];
                    let limit = if kind == FileKind::Link { MAX_LINK_BYTES } else { landd_core::git::DEFAULT_MAX_BLOB_BYTES };
                    let facts = match reader.read_limited(&oid, Some(limit)) {
                        Ok(bytes) => extract(kind, &bytes),
                        // Not read: whoever reaches this file cannot be bounded.
                        Err(GitError::TooLarge { .. }) => FileFacts {
                            too_large: true,
                            language: if kind == FileKind::Python { Language::Python } else { Language::Other },
                            ..FileFacts::default()
                        },
                        Err(other) => return Err(other.into()),
                    };
                    if let Some(cache) = cache {
                        if cache.put_blob(kind, &oid, &facts).is_err() {
                            write_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Ok(facts)
                },
            )
            .collect()
    };
    // A handful of blobs is not worth waking a worker per core for.
    let parsed: Vec<Result<FileFacts, SweepError>> = match cold.len() {
        0 => Vec::new(),
        1..=SMALL_PARSE => light_pool().install(parse),
        _ => pool().install(parse),
    };
    stats.blobs_parsed = cold.len();
    for ((g, s), facts) in cold.iter().zip(parsed) {
        if let Loaded::Blobs(slots) = &mut loaded[*g] {
            slots[*s] = Some((Arc::new(facts?), false));
        }
    }
    stats.parse_ms = ms_since(parsing);

    // Every group is complete now; the ones assembled from blobs become packs.
    let packs: Vec<Pack> = loaded
        .into_iter()
        .map(|group| match group {
            Loaded::Pack(pack, _) => (pack, false),
            Loaded::Blobs(slots) => (Arc::new(slots.into_iter().map(|f| f.expect("every slot is filled").0).collect()), true),
        })
        .zip(&groups)
        .map(|((pack, fresh), group)| {
            if let Some(cache) = cache.filter(|_| fresh) {
                if cache.put_pack(&group.keys, &pack).is_err() {
                    write_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            pack
        })
        .collect();
    stats.cache_write_errors = write_errors.into_inner();

    let placements: Vec<(usize, Arc<FileFacts>)> =
        groups.iter().zip(&packs).flat_map(|(group, pack)| group.members.iter().copied().zip(pack.iter().cloned())).collect();
    for (index, facts) in placements {
        files[index].facts = Some(facts);
    }
    stats.map_ms = ms_since(mapping);
    Ok((AllFacts { tree: Some(root), files }, stats))
}

fn walk(dir: &Path, relative: &str, out: &mut Vec<(String, PathBuf)>) -> Result<(), SweepError> {
    let io = |source| SweepError::Io { path: dir.to_owned(), source };
    for entry in std::fs::read_dir(dir).map_err(io)? {
        let entry = entry.map_err(io)?;
        let Ok(name) = entry.file_name().into_string() else {
            return Err(SweepError::NonUtf8Path(entry.path().to_string_lossy().into_owned()));
        };
        if name == ".git" {
            continue;
        }
        let child = if relative.is_empty() { name } else { format!("{relative}/{name}") };
        let kind = entry.file_type().map_err(io)?;
        if kind.is_dir() {
            walk(&entry.path(), &child, out)?;
        } else if kind.is_file() || kind.is_symlink() {
            // Sockets, FIFOs and devices are not content; reading one could block forever.
            out.push((child, entry.path()));
        }
    }
    Ok(())
}

/// Fallback for a directory that is not a commit (a dirty working tree, an
/// unpacked archive). Blob ids are computed from content, so the blob cache
/// is shared with [`sweep_git`]. This mode walks the directory by nature.
pub fn sweep_dir(dir: &Path, cache: Option<&BlobFactsCache>) -> Result<(AllFacts, SweepStats), SweepError> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let started = Instant::now();
    let mut found = Vec::new();
    walk(dir, "", &mut found)?;
    found.sort();
    let mut stats = SweepStats { files: found.len(), list_ms: ms_since(started), ..SweepStats::default() };
    let mapping = Instant::now();
    let (parsed, cached) = (AtomicUsize::new(0), AtomicUsize::new(0));
    let write_errors = AtomicUsize::new(0);
    let files: Vec<Result<FileEntry, SweepError>> = pool().install(|| {
        found
            .par_iter()
            .map(|(path, full)| {
                let io = |source| SweepError::Io { path: full.clone(), source };
                let meta = std::fs::symlink_metadata(full).map_err(io)?;
                let (content, mode) = if meta.file_type().is_symlink() {
                    (std::fs::read_link(full).map_err(io)?.as_os_str().as_bytes().to_vec(), MODE_SYMLINK)
                } else {
                    let executable = meta.permissions().mode() & 0o111 != 0;
                    (std::fs::read(full).map_err(io)?, if executable { MODE_EXECUTABLE } else { 0o100644 })
                };
                let oid = Oid::git_blob_sha1(&content);
                let kind = FileKind::of_entry(path, mode);
                let facts = kind.map(|kind| {
                    if let Some((hit, _)) = cache.and_then(|c| c.get_blob(kind, &oid)) {
                        cached.fetch_add(1, Ordering::Relaxed);
                        return hit;
                    }
                    parsed.fetch_add(1, Ordering::Relaxed);
                    let facts = extract(kind, &content);
                    if cache.is_some_and(|c| c.put_blob(kind, &oid, &facts).is_err()) {
                        write_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    Arc::new(facts)
                });
                Ok(FileEntry { path: path.clone(), oid, mode, kind, facts })
            })
            .collect()
    });
    let files = files.into_iter().collect::<Result<Vec<_>, _>>()?;
    stats.fact_files = files.iter().filter(|f| f.kind.is_some()).count();
    stats.blobs_parsed = parsed.into_inner();
    stats.blobs_from_cache = cached.into_inner();
    stats.cache_write_errors = write_errors.into_inner();
    stats.map_ms = ms_since(mapping);
    Ok((AllFacts { tree: None, files }, stats))
}

pub enum Source<'a> {
    Git { repo: &'a GitRepo, rev: &'a str },
    Dir(&'a Path),
}

/// One reason cones were widened, and how many cones it widened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Widening {
    pub path: String,
    pub cause: Cause,
    pub cones: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SweepReport {
    pub tree: Option<Oid>,
    pub stats: SweepStats,
    /// How many facts of each kind the tree holds.
    pub census: BTreeMap<&'static str, usize>,
    /// Reading the settings catalogs the pack names.
    pub catalogs_ms: f64,
    /// Building the dependency graph (only when the pack exports cones).
    pub graph_ms: f64,
    pub reduce_ms: f64,
    /// Milliseconds per rule; rules run in parallel, so these overlap.
    pub rule_ms: BTreeMap<String, f64>,
    pub cones_ms: f64,
    pub total_ms: f64,
    pub rules_failed: usize,
    pub findings: usize,
    pub verdicts: Vec<RuleVerdict>,
    /// Cones that depend on the whole tree.
    pub widened_cones: usize,
    /// How many widened cones each cause accounts for (a cone may have several).
    pub widened_by_cause: BTreeMap<Cause, usize>,
    /// The files that widen the most cones, with why.
    pub widening: Vec<Widening>,
    /// What became of each loader declaration on this tree.
    pub loaders: Vec<LoaderReport>,
    pub cones: Vec<ImportCone>,
}

fn census(all: &AllFacts) -> BTreeMap<&'static str, usize> {
    let mut counts = BTreeMap::new();
    for facts in all.files.iter().filter_map(|f| f.facts.as_deref()) {
        for (name, count) in [
            ("imports", facts.imports.len()),
            ("dynamic_loads", facts.dynamic_loads.len()),
            ("reads", facts.reads.len()),
            ("scans", facts.scans().count()),
            ("flocks", facts.flocks.len()),
            ("replaces", facts.replaces.len()),
            ("strftimes", facts.strftimes.len()),
            ("sys_executable", facts.sys_executable.len()),
            ("settings_reads", facts.settings_reads.len()),
            ("exc_on_self", facts.exc_on_self.len()),
            ("bare_python", facts.bare_python.len()),
            ("functions", facts.functions.len()),
            ("symbols", facts.symbols.len()),
            ("parse_errors", usize::from(facts.parse_error)),
            ("truncated", usize::from(facts.truncated)),
        ] {
            *counts.entry(name).or_insert(0) += count;
        }
    }
    counts
}

/// Map, then reduce `pack`, then export cones when the pack asks for them.
pub fn run_sweep(
    source: Source<'_>,
    pack: &RulePack,
    cache: Option<&BlobFactsCache>,
) -> Result<(SweepReport, AllFacts), SweepError> {
    let started = Instant::now();
    let (all, stats) = match source {
        Source::Git { repo, rev } => sweep_git(repo, rev, cache)?,
        Source::Dir(dir) => sweep_dir(dir, cache)?,
    };
    let cataloguing = Instant::now();
    let catalogs = Catalogs::load(pack, &all, cache, |entry| match source {
        Source::Git { repo, .. } => repo.read_blob(&entry.oid).ok(),
        Source::Dir(dir) => std::fs::read(dir.join(&entry.path)).ok(),
    });
    let catalogs_ms = ms_since(cataloguing);

    let graphing = Instant::now();
    let graph = pack.needs_graph().then(|| ImportGraph::build(&all, &pack.imports));
    let cone_graph = graph.as_ref().filter(|_| pack.exports_cones());
    let graph_ms = ms_since(graphing);

    let reducing = Instant::now();
    let (verdicts, rule_ms) = reduce::reduce_timed(&all, pack, &catalogs, graph.as_ref());
    let reduce_ms = ms_since(reducing);

    let coning = Instant::now();
    let context = pack.digest();
    let cones = cone_graph.map(|g| imports::cones(&all, g, &pack.imports, &context)).unwrap_or_default();
    let cones_ms = ms_since(coning);

    let mut widened_by_cause: BTreeMap<Cause, usize> = BTreeMap::new();
    for cone in &cones {
        let kinds: std::collections::BTreeSet<Cause> = cone.causes.iter().map(|(_, cause)| *cause).collect();
        for cause in kinds {
            *widened_by_cause.entry(cause).or_insert(0) += 1;
        }
    }
    let mut widening: Vec<Widening> =
        imports::cause_counts(&cones, &all).into_iter().map(|((path, cause), cones)| Widening { path, cause, cones }).collect();
    widening.sort_by(|a, b| b.cones.cmp(&a.cones).then_with(|| a.path.cmp(&b.path)).then_with(|| a.cause.cmp(&b.cause)));
    widening.truncate(60);

    let report = SweepReport {
        tree: all.tree,
        stats,
        census: census(&all),
        catalogs_ms,
        widened_cones: cones.iter().filter(|cone| cone.widened).count(),
        widened_by_cause,
        widening,
        loaders: cone_graph.map(|g| g.loaders.clone()).unwrap_or_default(),
        graph_ms,
        reduce_ms,
        rule_ms,
        cones_ms,
        total_ms: ms_since(started),
        rules_failed: verdicts.iter().filter(|v| v.status == VerdictStatus::Fail).count(),
        findings: verdicts.iter().map(|v| v.findings.len()).sum(),
        verdicts,
        cones,
    };
    Ok((report, all))
}

#[cfg(test)]
mod tests {
    use super::*;
    use landd_core::git::testkit::Sandbox;

    const FILES: &[(&str, &str)] = &[
        ("pkg/__init__.py", ""),
        ("pkg/a.py", "import os\ndef f():\n    os.replace('a', 'b')\n"),
        ("pkg/sub/b.py", "from pkg import a\n"),
        ("tests/test_a.py", "from pkg.sub import b\n"),
        ("Makefile", "test:\n\tpython -m pytest\n"),
        ("README.md", "# readme\n"),
        ("data/blob.bin", "\x00\x01"),
    ];

    #[test]
    fn cold_then_warm_then_incremental() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), FILES);
        let repo = sandbox.repo();
        let cache = BlobFactsCache::open(dir.path().join("cache")).unwrap();

        let (cold, cold_stats) = sweep_git(&repo, "HEAD", Some(&cache)).unwrap();
        assert_eq!((cold_stats.files, cold_stats.fact_files), (7, 5));
        assert_eq!((cold_stats.blobs_parsed, cold_stats.blobs_from_cache, cold_stats.packs_hit), (5, 0, 0));
        let packs = cold_stats.packs;
        assert!((4..=5).contains(&packs), "one pack per directory, more only where a name cuts one: {packs}");
        assert!(cold_stats.load_ms + cold_stats.parse_ms <= cold_stats.map_ms);
        assert_eq!(cold.find("pkg/a.py").unwrap().facts.as_ref().unwrap().replaces.len(), 1);
        assert_eq!(cold.find("Makefile").unwrap().facts.as_ref().unwrap().bare_python.len(), 1);
        assert!(cold.find("README.md").unwrap().facts.is_none());
        assert_eq!(cold.tree, Some(repo.tree_of("HEAD").unwrap()));

        // The same handle sweeps again from memory; a fresh handle (a new
        // process) reads the pack files.
        let (warm, warm_stats) = sweep_git(&repo, "HEAD", Some(&cache)).unwrap();
        assert_eq!((warm_stats.blobs_parsed, warm_stats.blobs_from_cache), (0, 0));
        assert_eq!((warm_stats.packs_hit, warm_stats.packs_from_memory), (packs, packs));
        let cache = BlobFactsCache::open(dir.path().join("cache")).unwrap();
        let (_, disk_stats) = sweep_git(&repo, "HEAD", Some(&cache)).unwrap();
        assert_eq!((disk_stats.blobs_parsed, disk_stats.packs_hit, disk_stats.packs_from_memory), (0, packs, 0));
        for (a, b) in cold.files.iter().zip(&warm.files) {
            assert_eq!((&a.path, a.oid, a.facts.as_deref()), (&b.path, b.oid, b.facts.as_deref()));
        }

        // One file changes: one blob is parsed; every other pack is a hit.
        sandbox.commit("main", "edit", &[("pkg/sub/b.py", "from pkg import a\nimport json\n")], &[]);
        let (next, next_stats) = sweep_git(&repo, "HEAD", Some(&cache)).unwrap();
        assert_eq!(next_stats.blobs_parsed, 1);
        assert_eq!(next_stats.packs_hit, packs - 1);
        assert_eq!(next_stats.blobs_from_cache, 0);
        assert_eq!(next.find("pkg/sub/b.py").unwrap().facts.as_ref().unwrap().imports.len(), 2);

        // Reverting restores the old blob ids: everything is a pack hit again.
        sandbox.commit("main", "revert", &[("pkg/sub/b.py", "from pkg import a\n")], &[]);
        let (_, reverted_stats) = sweep_git(&repo, "HEAD", Some(&cache)).unwrap();
        assert_eq!((reverted_stats.blobs_parsed, reverted_stats.packs_hit), (0, packs));
    }

    #[test]
    fn sweeping_without_a_cache_parses_everything_every_time() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), FILES);
        let repo = sandbox.repo();
        for _ in 0..2 {
            let (_, stats) = sweep_git(&repo, "HEAD", None).unwrap();
            assert_eq!((stats.blobs_parsed, stats.packs_hit), (5, 0));
        }
        assert!(sweep_git(&repo, "no-such-rev", None).is_err());
    }

    #[test]
    fn directory_mode_matches_git_mode_and_shares_the_blob_cache() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), FILES);
        let cache = BlobFactsCache::open(dir.path().join("cache")).unwrap();
        let (from_git, _) = sweep_git(&sandbox.repo(), "HEAD", Some(&cache)).unwrap();
        let (from_dir, stats) = sweep_dir(&sandbox.work, Some(&cache)).unwrap();
        assert_eq!((stats.blobs_parsed, stats.blobs_from_cache), (0, 5));
        assert_eq!(from_dir.tree, None);
        assert_eq!(from_git.files.len(), from_dir.files.len());
        for (a, b) in from_git.files.iter().zip(&from_dir.files) {
            assert_eq!((&a.path, a.oid, a.mode, a.facts.as_deref()), (&b.path, b.oid, b.mode, b.facts.as_deref()));
        }

        // An uncommitted edit is seen by directory mode only.
        std::fs::write(sandbox.work.join("pkg/new.py"), "import sys\n").unwrap();
        let (dirty, dirty_stats) = sweep_dir(&sandbox.work, Some(&cache)).unwrap();
        assert_eq!(dirty_stats.blobs_parsed, 1);
        assert!(dirty.find("pkg/new.py").is_some());
    }

    #[test]
    fn run_sweep_reports_verdicts_and_cones() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), FILES);
        let repo = sandbox.repo();
        let (report, _) = run_sweep(Source::Git { repo: &repo, rev: "HEAD" }, &RulePack::builtin(), None).unwrap();
        assert_eq!(report.verdicts.len(), 3);
        assert_eq!(report.rules_failed, 1);
        assert_eq!(report.findings, 1);
        assert_eq!(report.cones.len(), 1);
        assert_eq!(report.cones[0].unit, "tests.test_a");
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["verdicts"][1]["findings"][0]["path"], "Makefile");
    }

    #[test]
    fn tooth_a_change_in_a_large_directory_invalidates_one_small_pack() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let sources: Vec<(String, String)> = (0..400).map(|i| (format!("big/mod_{i:03}.py"), format!("X = {i}\n"))).collect();
        let borrowed: Vec<(&str, &str)> = sources.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
        let sandbox = Sandbox::new(dir.path(), &borrowed);
        let repo = sandbox.repo();
        let cache = BlobFactsCache::open(dir.path().join("cache")).unwrap();
        let (_, cold) = sweep_git(&repo, "HEAD", Some(&cache)).unwrap();
        assert!(cold.packs >= 30, "400 siblings must be cut into many packs, got {}", cold.packs);

        // Edit one file, add one and delete one: boundaries elsewhere hold.
        sandbox.commit("main", "edit", &[("big/mod_200.py", "X = -1\n"), ("big/mod_200a.py", "NEW = 1\n")], &["big/mod_017.py"]);
        let cache = BlobFactsCache::open(dir.path().join("cache")).unwrap();
        let (_, next) = sweep_git(&repo, "HEAD", Some(&cache)).unwrap();
        assert_eq!(next.blobs_parsed, 2);
        assert!(next.packs - next.packs_hit <= 3, "{} of {} packs missed", next.packs - next.packs_hit, next.packs);
        assert!(next.blobs_from_cache < 60, "{} blobs were re-read one by one", next.blobs_from_cache);

        // A daemon keeps its handle: after the next change it parses the
        // changed blob and reads nothing else, from memory or from disk.
        sandbox.commit("main", "edit again", &[("big/mod_300.py", "X = -2\n")], &[]);
        let (_, held) = sweep_git(&repo, "HEAD", Some(&cache)).unwrap();
        assert_eq!((held.blobs_parsed, held.blobs_from_cache), (1, 0));
        assert_eq!(held.packs_hit, held.packs_from_memory);
        assert_eq!(held.packs - held.packs_hit, 1);
    }

    /// Real git modes: a symbolic link, an executable Python script without
    /// a suffix, and a tree listed from a subdirectory.
    #[test]
    fn git_modes_links_and_sniffed_scripts_are_read_as_what_they_are() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let sandbox =
            Sandbox::new(dir.path(), &[("lib/impl.py", "I = 1\n"), ("bin/tool", "#!/usr/bin/env python3\nimport lib.impl\n")]);
        std::os::unix::fs::symlink("../lib/impl.py", sandbox.work.join("bin/linked.py")).unwrap();
        std::fs::set_permissions(sandbox.work.join("bin/tool"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        sandbox.git(&["add", "-A"]);
        sandbox.git(&["commit", "--quiet", "-m", "modes"]);
        let repo = landd_core::git::GitRepo::open(sandbox.work.join("lib")).unwrap();
        let (all, stats) = sweep_git(&repo, "HEAD", None).unwrap();
        assert_eq!(stats.files, 3);
        let tool = all.find("bin/tool").unwrap();
        assert_eq!((tool.mode, tool.kind, tool.is_python()), (MODE_EXECUTABLE, Some(FileKind::Sniff), true));
        let link = all.find("bin/linked.py").unwrap();
        assert_eq!((link.mode, link.kind, link.is_python()), (MODE_SYMLINK, Some(FileKind::Link), false));
        assert_eq!(link.facts.as_ref().unwrap().link_target.as_deref(), Some("../lib/impl.py"));
        // The working-tree mode reads the same tree the same way.
        let (from_dir, _) = sweep_dir(&sandbox.work, None).unwrap();
        for (a, b) in all.files.iter().zip(&from_dir.files) {
            assert_eq!(
                (&a.path, a.oid, a.mode, a.kind, a.facts.as_deref()),
                (&b.path, b.oid, b.mode, b.kind, b.facts.as_deref())
            );
        }
    }

    #[test]
    fn tooth_directory_mode_skips_what_is_not_content() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        std::fs::write(dir.path().join("a.py"), "A = 1\n").unwrap();
        let fifo = std::ffi::CString::new(dir.path().join("pipe.py").to_str().unwrap()).unwrap();
        // SAFETY: `mkfifo` is given a valid NUL-terminated path owned by this scope.
        assert_eq!(unsafe { libc_mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let started = std::time::Instant::now();
        let (all, _) = sweep_dir(dir.path(), None).unwrap();
        assert_eq!(all.paths(), ["a.py"]);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    extern "C" {
        #[link_name = "mkfifo"]
        fn libc_mkfifo(path: *const std::os::raw::c_char, mode: u32) -> i32;
    }
}
