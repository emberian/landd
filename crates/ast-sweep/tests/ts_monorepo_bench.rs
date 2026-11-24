//! Empirical TypeScript/TSX monorepo sweep and cone-selectivity benchmark against a real repository.
//! Set `LANDD_TS_BENCH_REPO` (e.g. `/path/to/monorepo`) to run; reads the Git object store read-only.

use ast_sweep::{
    imports::{cones, Cause, ImportGraph},
    run_sweep, AllFacts, FileKind, Rule, RuleKind, RulePack, Source,
};
use landd_core::{git::GitRepo, Digest32, Oid};
use std::collections::BTreeMap;
use std::path::Path;

#[test]
fn ts_monorepo_empirical_cones() {
    let Some(repo_path) = std::env::var_os("LANDD_TS_BENCH_REPO") else {
        eprintln!("LANDD_TS_BENCH_REPO is not set; skipping empirical TS monorepo benchmark");
        return;
    };
    let repo = GitRepo::open(Path::new(&repo_path)).unwrap();
    let mut pack = RulePack::default();
    pack.imports.tests = vec!["src/**/*.test.ts".into(), "src/**/*.test.tsx".into()];
    pack.imports.always = vec![];
    pack.rule.push(Rule::new("graph", RuleKind::PythonImportGraph));

    let (report, all) = run_sweep(Source::Git { repo: &repo, rev: "HEAD" }, &pack, None).unwrap();
    let graph = ImportGraph::build(&all, &pack.imports);

    let mut total_ts_js = 0usize;
    let mut src_ts_tsx = 0usize;
    let mut parse_errors_all_ts = 0usize;
    let mut parse_errors_src = 0usize;
    let mut parse_error_paths = Vec::new();
    let mut unresolved_src_files = Vec::new();
    let mut dyn_load_src_files = Vec::new();

    for (idx, f) in all.files.iter().enumerate() {
        if !matches!(f.kind, Some(FileKind::TypeScript | FileKind::Tsx | FileKind::Dts)) {
            continue;
        }
        total_ts_js += 1;
        let in_src = f.path.starts_with("src/");
        if in_src {
            src_ts_tsx += 1;
        }
        let facts = f.facts.as_deref().unwrap();
        if facts.parse_error {
            parse_errors_all_ts += 1;
            if in_src {
                parse_errors_src += 1;
            }
            parse_error_paths.push(f.path.clone());
        }
        let causes = graph.causes_of(idx as u32);
        if in_src && causes.contains(&Cause::UnresolvedLoad) {
            unresolved_src_files.push(f.path.clone());
        }
        if in_src && causes.contains(&Cause::DynamicLoad) {
            dyn_load_src_files.push(f.path.clone());
        }
    }

    let total_cones = report.cones.len();
    let narrowed_cones = report.cones.iter().filter(|c| !c.widened).count();
    let mut input_sizes: Vec<usize> = report.cones.iter().filter(|c| !c.widened).map(|c| c.input_files).collect();
    input_sizes.sort_unstable();
    let median_inputs = if input_sizes.is_empty() { 0 } else { input_sizes[input_sizes.len() / 2] };
    let mean_inputs =
        if input_sizes.is_empty() { 0.0 } else { input_sizes.iter().sum::<usize>() as f64 / input_sizes.len() as f64 };

    eprintln!("=== AFTER FIX: EMPIRICAL MONOREPO REPORT ===");
    eprintln!("Total tracked files: {}", all.files.len());
    eprintln!("Total TS/TSX/JS/DTS files scanned: {total_ts_js} (under src/: {src_ts_tsx})");
    eprintln!("TS/TSX parse_error count: src/ = {parse_errors_src}, whole-repo = {parse_errors_all_ts}");
    if !parse_error_paths.is_empty() {
        eprintln!("  parse_error paths: {:?}", &parse_error_paths[..parse_error_paths.len().min(20)]);
    }
    eprintln!("src/ files with Cause::UnresolvedLoad: {} -> {:?}", unresolved_src_files.len(), unresolved_src_files);
    eprintln!("src/ files with Cause::DynamicLoad: {} -> {:?}", dyn_load_src_files.len(), dyn_load_src_files);
    eprintln!(
        "Test cones (src/**/*.test.{{ts,tsx}}): {total_cones} total | {narrowed_cones} narrowed ({:.1}%), {} widened",
        100.0 * narrowed_cones as f64 / total_cones.max(1) as f64,
        report.widened_cones
    );
    eprintln!("Widened cones by cause: {:?}", report.widened_by_cause);
    eprintln!(
        "Sweep timing: list {:.1} ms, map {:.1} ms (parse {:.1} ms), graph {:.1} ms, cones {:.1} ms, total {:.1} ms",
        report.stats.list_ms, report.stats.map_ms, report.stats.parse_ms, report.graph_ms, report.cones_ms, report.total_ms
    );
    eprintln!("Narrowed cone size: median = {median_inputs} files, mean = {mean_inputs:.1} files");

    // Simulate 1-byte blob edits in memory (pure Oid perturbation, zero disk writes!) and count invalidated cones!
    let context = pack.digest();
    let base_cones: BTreeMap<&str, Digest32> = report.cones.iter().map(|c| (c.unit.as_str(), c.digest)).collect();
    let invalidated_if_edited = |target_path: &str| -> Option<(usize, usize)> {
        let pos = all.index_of(target_path)?;
        let mut perturbed: AllFacts = all.clone();
        perturbed.files[pos].oid = Oid::git_blob_sha1(format!("perturbed:{target_path}").as_bytes());
        let next_cones = cones(&perturbed, &graph, &pack.imports, &context);
        let moved = next_cones.iter().filter(|c| base_cones[c.unit.as_str()] != c.digest).count();
        let bounded_moved = next_cones.iter().filter(|c| !c.widened && base_cones[c.unit.as_str()] != c.digest).count();
        Some((moved, bounded_moved))
    };

    let mut leaf_candidates: Vec<(&str, usize)> = all
        .files
        .iter()
        .filter(|f| f.path.starts_with("src/components/") && f.path.ends_with(".tsx") && !f.path.ends_with(".test.tsx"))
        .filter_map(|f| {
            let (_, bounded) = invalidated_if_edited(&f.path)?;
            let test_path = f.path.replace(".tsx", ".test.tsx");
            (bounded > 0 && all.index_of(&test_path).is_some()).then_some((f.path.as_str(), bounded))
        })
        .collect();
    leaf_candidates.sort_by_key(|&(p, b)| (b, p));

    let mut hook_candidates: Vec<(&str, usize)> = all
        .files
        .iter()
        .filter(|f| {
            f.path.starts_with("src/hooks/")
                && (f.path.ends_with(".ts") || f.path.ends_with(".tsx"))
                && !f.path.contains(".test.")
        })
        .filter_map(|f| {
            let (_, bounded) = invalidated_if_edited(&f.path)?;
            (bounded > 0).then_some((f.path.as_str(), bounded))
        })
        .collect();
    hook_candidates.sort_by_key(|&(p, b)| (std::cmp::Reverse(b), p));

    if let Some(&(leaf_path, _)) = leaf_candidates.first() {
        let (total_moved, bounded_moved) = invalidated_if_edited(leaf_path).unwrap();
        let test_path = leaf_path.replace(".tsx", ".test.tsx");
        let own_cone_inputs = report.cones.iter().find(|c| c.path == test_path).map(|c| c.input_files);
        eprintln!(
            "Leaf component edit `{leaf_path}`: invalidates {total_moved}/{total_cones} cones ({bounded_moved} bounded + {} widened); `{test_path}` cone size = {:?} files",
            report.widened_cones,
            own_cone_inputs
        );
    }
    if let Some(&(hook_path, _)) = hook_candidates.first() {
        let (total_moved, bounded_moved) = invalidated_if_edited(hook_path).unwrap();
        eprintln!(
            "Shared hook edit `{hook_path}`: invalidates {total_moved}/{total_cones} cones ({bounded_moved} bounded + {} widened)",
            report.widened_cones
        );
    }
    if let Some((lock_moved, lock_bounded)) = invalidated_if_edited("pnpm-lock.yaml") {
        eprintln!(
            "Lockfile edit `pnpm-lock.yaml`: invalidates {lock_moved}/{total_cones} cones ({lock_bounded} bounded + {} widened)",
            report.widened_cones
        );
    }
}
