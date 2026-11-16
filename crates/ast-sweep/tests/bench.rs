//! In-process sweep timings against a real repository, as a long-lived
//! daemon would see them. Set `LANDD_BENCH_REPO` (and optionally
//! `LANDD_BENCH_REV`, `LANDD_BENCH_PREV`, `LANDD_BENCH_RULES`) to run it. It
//! only reads the repository and writes its cache to a temporary directory.

use ast_sweep::{run_sweep, BlobFactsCache, RulePack, Source, SweepReport};
use landd_core::git::GitRepo;
use std::path::Path;

fn show(label: &str, report: &SweepReport) {
    let stats = &report.stats;
    eprintln!(
        "bench in-process {label}: list {:.1} map {:.1} (load {:.1} parse {:.1}) catalogs {:.1} graph {:.1} reduce {:.1} cones {:.1} total {:.1} ms | {} parsed, {} re-read singly, {} blobs from memory, {}/{} packs hit ({} from memory) | {} findings, {} cones ({} widened)",
        stats.list_ms, stats.map_ms, stats.load_ms, stats.parse_ms, report.catalogs_ms, report.graph_ms, report.reduce_ms, report.cones_ms, report.total_ms,
        stats.blobs_parsed, stats.blobs_from_cache, stats.blobs_from_memory, stats.packs_hit, stats.packs, stats.packs_from_memory,
        report.findings, report.cones.len(), report.widened_cones,
    );
}

#[test]
fn bench_in_process_sweeps() {
    let Some(path) = std::env::var_os("LANDD_BENCH_REPO") else {
        eprintln!("LANDD_BENCH_REPO is not set; skipping the in-process sweep benchmark");
        return;
    };
    let rev = std::env::var("LANDD_BENCH_REV").unwrap_or_else(|_| "HEAD".into());
    let pack = match std::env::var_os("LANDD_BENCH_RULES") {
        Some(rules) => RulePack::load(Path::new(&rules)).unwrap(),
        None => RulePack::builtin(),
    };
    let repo = GitRepo::open(Path::new(&path)).unwrap();
    let dir = landd_core::git::testkit::private_tempdir().unwrap();
    let cache = BlobFactsCache::open(dir.path().join("cache")).unwrap();
    let sweep = |rev: &str, cache: &BlobFactsCache| run_sweep(Source::Git { repo: &repo, rev }, &pack, Some(cache)).unwrap().0;

    if let Ok(previous) = std::env::var("LANDD_BENCH_PREV") {
        show("cold (previous revision)", &sweep(&previous, &cache));
        let next = sweep(&rev, &cache);
        show("incremental, memory tier", &next);
        assert!(next.stats.blobs_parsed < next.stats.fact_files);
    } else {
        show("cold", &sweep(&rev, &cache));
    }
    let again = sweep(&rev, &cache);
    show("same tree again, memory tier", &again);
    assert_eq!((again.stats.blobs_parsed, again.stats.packs_from_memory), (0, again.stats.packs));
    let from_disk = sweep(&rev, &BlobFactsCache::open(dir.path().join("cache")).unwrap());
    show("same tree, fresh handle (disk)", &from_disk);
    assert_eq!((from_disk.stats.blobs_parsed, from_disk.stats.packs_from_memory), (0, 0));
    assert_eq!(serde_json::to_value(&again.verdicts).unwrap(), serde_json::to_value(&from_disk.verdicts).unwrap());
    assert_eq!(again.cones, from_disk.cones);
}
