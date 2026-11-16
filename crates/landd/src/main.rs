//! `landd`: sweep a tree, show cones, land a lane, run the daemon, replay a
//! ledger, or guard a forge.

mod daemon;
mod hook;
mod station;
mod wire;

use ast_sweep::{BlobFactsCache, ImportCone, Source, VerdictStatus};
use clap::{Parser, Subcommand};
use landd_core::custody::TrustedKeys;
use landd_core::git::GitRepo;
use landd_sim::{ModuleCosts, SimConfig};
use landd_train::{Candidate, CandidateOutcome};
use serde_json::json;
use station::{default_cache_dir, load_config, load_pack, AnyError, Station};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

// Loading cached facts is hundreds of thousands of small allocations on a
// few threads. glibc grows each thread's arena a page run at a time under
// the address-space lock, and the threads end up queueing on it (measured:
// 58 ms to load what takes 11 ms without the contention).
#[global_allocator]
static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// `println!` for results: when stdout is a closed pipe (`landd … | head`)
/// the process ends quietly instead of panicking.
macro_rules! say {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if writeln!(std::io::stdout(), $($arg)*).is_err() {
            std::process::exit(0);
        }
    }};
}

#[derive(Parser)]
#[command(name = "landd", version, about = "Speculative batch merge train with content-addressed admissibility")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check a tree against a rule pack (exit 1 when a rule fails).
    Sweep {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long, default_value = "HEAD")]
        rev: String,
        /// Sweep the files on disk instead of a commit.
        #[arg(long)]
        worktree: bool,
        #[arg(long)]
        rules: Option<PathBuf>,
        /// A gateaudits.json whose guards become cone reads.
        #[arg(long)]
        gateaudits: Option<PathBuf>,
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        #[arg(long)]
        no_cache: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show which test cones a change moves and which transport untouched.
    Cones {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        base: String,
        #[arg(long)]
        head: String,
        #[arg(long)]
        rules: Option<PathBuf>,
        #[arg(long)]
        gateaudits: Option<PathBuf>,
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        #[arg(long)]
        no_cache: bool,
        #[arg(long)]
        json: bool,
    },
    /// Judge one lane against the target ref; push it with --apply.
    Land {
        #[arg(long)]
        repo: PathBuf,
        #[arg(long)]
        lane: String,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override a setting: --set max_batch_size=4
        #[arg(long = "set", value_name = "KEY=VALUE")]
        overrides: Vec<String>,
    },
    /// Serve enqueue/status requests on a Unix socket and land batches.
    Daemon {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = ".")]
        repo: PathBuf,
        #[arg(long = "set", value_name = "KEY=VALUE")]
        overrides: Vec<String>,
    },
    /// Talk to a running daemon.
    Ctl {
        #[arg(long)]
        socket: PathBuf,
        #[command(subcommand)]
        request: CtlRequest,
    },
    /// Replay a fleet land ledger through the batch-train model.
    Replay {
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        module_costs: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long = "set", value_name = "KEY=VALUE")]
        overrides: Vec<String>,
        /// Seconds assumed for a module the ledger never measured.
        #[arg(long, default_value_t = 30.0)]
        default_module_s: f64,
        #[arg(long)]
        json: bool,
    },
    /// Forge hook: protected refs move only with a verified land receipt.
    PreReceive {
        #[arg(long)]
        trusted_keys: PathBuf,
        #[arg(long, default_value = "refs/heads/main")]
        protect: Vec<String>,
    },
}

#[derive(Subcommand)]
enum CtlRequest {
    Enqueue { lane: String },
    Status,
    Shutdown,
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("landd: {err}");
            ExitCode::from(2)
        }
    }
}

fn print_json(value: &impl serde::Serialize) -> Result<(), AnyError> {
    say!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn facts_cache(cache_dir: Option<PathBuf>, no_cache: bool) -> Option<BlobFactsCache> {
    if no_cache {
        return None;
    }
    cache_dir.or_else(default_cache_dir).map(|dir| BlobFactsCache::open(dir.join("facts")))
}

fn run(command: Command) -> Result<ExitCode, AnyError> {
    match command {
        Command::Sweep { repo, rev, worktree, rules, gateaudits, cache_dir, no_cache, json } => {
            let pack = load_pack(rules.as_deref(), gateaudits.as_deref())?;
            let cache = facts_cache(cache_dir, no_cache);
            let opened;
            let source = if worktree {
                Source::Dir(&repo)
            } else {
                opened = GitRepo::open(&repo)?;
                Source::Git { repo: &opened, rev: &rev }
            };
            let (report, _) = ast_sweep::run_sweep(source, &pack, cache.as_ref())?;
            if json {
                print_json(&report)?;
            } else {
                for verdict in &report.verdicts {
                    let word = if verdict.status == VerdictStatus::Pass { "PASS" } else { "FAIL" };
                    say!("{word} {} ({} findings)", verdict.rule_id, verdict.findings.len());
                    for finding in &verdict.findings {
                        say!("  {}:{}: {}", finding.path, finding.line, finding.message);
                    }
                }
                let stats = &report.stats;
                say!(
                    "{} files, {} with facts: {} parsed, {} from blob cache, {}/{} packs hit; {} cones",
                    stats.files, stats.fact_files, stats.blobs_parsed, stats.blobs_from_cache, stats.packs_hit, stats.packs,
                    report.cones.len()
                );
                if report.tainted_cones > 0 {
                    say!("{} cones reach an undeclared dynamic loader; the widest:", report.tainted_cones);
                    for source in report.taint_sources.iter().take(8) {
                        say!("  {} taints {} cones", source.path, source.cones);
                    }
                }
                say!(
                    "list {:.1} ms, map {:.1} ms, graph {:.1} ms, reduce {:.1} ms, cones {:.1} ms, total {:.1} ms",
                    stats.list_ms, stats.map_ms, report.graph_ms, report.reduce_ms, report.cones_ms, report.total_ms
                );
            }
            Ok(ExitCode::from(u8::from(report.rules_failed > 0)))
        }
        Command::Cones { repo, base, head, rules, gateaudits, cache_dir, no_cache, json } => {
            let started = Instant::now();
            let mut pack = load_pack(rules.as_deref(), gateaudits.as_deref())?;
            pack.rule.retain(|rule| rule.kind == ast_sweep::RuleKind::PythonImportGraph);
            if pack.rule.is_empty() {
                pack.rule = ast_sweep::RulePack::builtin().rule.into_iter().filter(|r| r.kind == ast_sweep::RuleKind::PythonImportGraph).collect();
            }
            let cache = facts_cache(cache_dir, no_cache);
            let repo = GitRepo::open(&repo)?;
            let (base_report, base_all) = ast_sweep::run_sweep(Source::Git { repo: &repo, rev: &base }, &pack, cache.as_ref())?;
            let (head_report, head_all) = ast_sweep::run_sweep(Source::Git { repo: &repo, rev: &head }, &pack, cache.as_ref())?;
            let before: BTreeMap<&str, &ImportCone> = base_report.cones.iter().map(|c| (c.unit.as_str(), c)).collect();
            let (mut transported, mut changed, mut added) = (0usize, Vec::new(), Vec::new());
            for cone in &head_report.cones {
                match before.get(cone.unit.as_str()) {
                    Some(old) if old.digest == cone.digest => transported += 1,
                    Some(old) => {
                        let moved = old.to_cone(&base_all).moved_paths(&cone.to_cone(&head_all));
                        changed.push(json!({"unit": cone.unit, "path": cone.path, "dynamic_loads": cone.dynamic_loads, "moved_paths": moved}));
                    }
                    None => added.push(cone.unit.clone()),
                }
            }
            let after: std::collections::BTreeSet<&str> = head_report.cones.iter().map(|c| c.unit.as_str()).collect();
            let removed: Vec<&str> = before.keys().copied().filter(|unit| !after.contains(unit)).collect();
            let report = json!({
                "base": base_report.tree, "head": head_report.tree,
                "units": head_report.cones.len(), "transported": transported,
                "changed": changed, "added": added, "removed": removed,
                "ms": started.elapsed().as_secs_f64() * 1000.0,
            });
            if json {
                print_json(&report)?;
            } else {
                say!("{} units: {} transported (0 runs), {} changed, {} added, {} removed", head_report.cones.len(), transported, changed.len(), added.len(), removed.len());
                for unit in &changed {
                    let moved: Vec<&str> = unit["moved_paths"].as_array().into_iter().flatten().filter_map(|p| p.as_str()).collect();
                    say!("  changed {} <- {}", unit["unit"].as_str().unwrap_or(""), moved.join(", "));
                }
                for unit in &added {
                    say!("  added   {unit}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Land { repo, lane, target, apply, config, overrides } => {
            let mut config = load_config(config.as_deref(), &overrides)?;
            if let Some(target) = target {
                config = config.with_override(&format!("target_ref={target}"))?;
            }
            let station = Station::open(&repo, config)?;
            let candidate = Candidate { tip: station.repo.commit_of(&lane)?, lane };
            let report = station.train()?.land_batch(&[candidate], apply, daemon::unix_now())?;
            print_json(&report)?;
            let settled = report.outcomes.iter().all(|(_, outcome)| {
                matches!(outcome, CandidateOutcome::Landed { .. } | CandidateOutcome::AlreadyLanded { .. } | CandidateOutcome::WouldLand { .. })
            });
            Ok(ExitCode::from(u8::from(!settled)))
        }
        Command::Daemon { socket, config, repo, overrides } => {
            let station = Station::open(&repo, load_config(Some(&config), &overrides)?)?;
            // Fail now, not on the first batch, if the signer cannot be built.
            station.train()?;
            daemon::serve(&socket, &station)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Ctl { socket, request } => {
            let request = match request {
                CtlRequest::Enqueue { lane } => wire::Request::Enqueue { lane },
                CtlRequest::Status => wire::Request::Status {},
                CtlRequest::Shutdown => wire::Request::Shutdown {},
            };
            let response = daemon::call(&socket, &request)?;
            print_json(&response)?;
            Ok(ExitCode::from(u8::from(matches!(response, wire::Response::Error { .. }))))
        }
        Command::Replay { ledger, module_costs, config, overrides, default_module_s, json } => {
            let config = load_config(config.as_deref(), &overrides)?;
            let ledger = landd_sim::parse_ledger(&std::fs::read_to_string(&ledger)?);
            let mut costs = ModuleCosts::observe(&ledger, default_module_s);
            if let Some(path) = module_costs {
                costs = costs.with_table(&std::fs::read_to_string(path)?)?;
            }
            let report = landd_sim::simulate(&ledger, &costs, &SimConfig::from_config(&config));
            if json {
                print_json(&report)?;
            } else {
                say!("{}", report.to_markdown().trim_end());
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::PreReceive { trusted_keys, protect } => pre_receive(&trusted_keys, &protect),
    }
}

fn pre_receive(trusted_keys: &Path, protect: &[String]) -> Result<ExitCode, AnyError> {
    let trusted = TrustedKeys::load(trusted_keys)?;
    let mut stdin = String::new();
    std::io::stdin().read_to_string(&mut stdin)?;
    let updates = hook::parse_updates(&stdin)?;
    let count: usize = std::env::var("GIT_PUSH_OPTION_COUNT").ok().and_then(|c| c.parse().ok()).unwrap_or(0);
    let options: Vec<String> = (0..count).filter_map(|i| std::env::var(format!("GIT_PUSH_OPTION_{i}")).ok()).collect();
    // The hook runs inside the receiving repository, with the pushed objects in quarantine.
    let repo = GitRepo::open(".")?;
    match hook::check(&updates, &options, &trusted, protect, |old, new| repo.is_ancestor(old, new).unwrap_or(false)) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(why) => {
            eprintln!("landd pre-receive: {why}");
            Ok(ExitCode::from(1))
        }
    }
}
