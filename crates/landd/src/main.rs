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
use landd_train::{valid_lane, Candidate, CandidateOutcome};
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
        /// A trusted gateaudits.json: its guards, domains and loader declarations join the pack.
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
    ///
    /// Exit 0: landed, would land (dry run), or nothing to change. Exit 1:
    /// declined, refused, deferred, carried by another push, or a lane with
    /// nothing to land.
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
    /// Report what a fleet land ledger shows, and replay it when it holds enough.
    Replay {
        #[arg(long)]
        ledger: PathBuf,
        /// Module -> seconds, for ledgers that record module sets without costs.
        #[arg(long)]
        module_costs: Option<PathBuf>,
        /// Fleet's timing tables (keeper walls, push counter), reported as observed.
        #[arg(long)]
        timings: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long = "set", value_name = "KEY=VALUE")]
        overrides: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Forge hook: protected refs move only with a verified land receipt.
    PreReceive {
        #[arg(long)]
        trusted_keys: PathBuf,
        /// This repository's identity, as the landing side names it: the
        /// canonical push destination (or its `repo_id` setting).
        #[arg(long)]
        repo_id: String,
        /// Refs to protect besides refs/heads/main.
        #[arg(long)]
        protect: Vec<String>,
    },
}

#[derive(Subcommand)]
enum CtlRequest {
    /// Queue a lane: its branch on the push destination, or --tip.
    Enqueue {
        lane: String,
        #[arg(long)]
        tip: Option<String>,
    },
    Status {
        /// Cursor from an earlier reply's `next`.
        #[arg(long, default_value_t = 0)]
        since: u64,
    },
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

fn facts_cache(cache_dir: Option<PathBuf>, no_cache: bool) -> Result<Option<BlobFactsCache>, AnyError> {
    if no_cache {
        return Ok(None);
    }
    match cache_dir.or_else(default_cache_dir) {
        Some(dir) => Ok(Some(BlobFactsCache::open(dir.join("facts"))?)),
        None => Ok(None),
    }
}

fn run(command: Command) -> Result<ExitCode, AnyError> {
    match command {
        Command::Sweep { repo, rev, worktree, rules, gateaudits, cache_dir, no_cache, json } => {
            let pack = load_pack(rules.as_deref(), gateaudits.as_deref())?;
            let cache = facts_cache(cache_dir, no_cache)?;
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
                    stats.files,
                    stats.fact_files,
                    stats.blobs_parsed,
                    stats.blobs_from_cache,
                    stats.packs_hit,
                    stats.packs,
                    report.cones.len()
                );
                if report.widened_cones > 0 {
                    say!(
                        "{} of {} cones depend on the whole tree. Cones widened, by cause:",
                        report.widened_cones,
                        report.cones.len()
                    );
                    for (cause, cones) in &report.widened_by_cause {
                        say!("  {:>6}  {}", cones, serde_json::to_value(cause)?.as_str().unwrap_or(""));
                    }
                    say!("The files that widen the most cones:");
                    for source in report.widening.iter().take(12) {
                        say!(
                            "  {:>6}  {}  ({})",
                            source.cones,
                            source.path,
                            serde_json::to_value(source.cause)?.as_str().unwrap_or("")
                        );
                    }
                }
                for loader in &report.loaders {
                    let force = if loader.in_force { "in force" } else { "not in force" };
                    say!(
                        "loader {}: {} ({force}): {}",
                        loader.declared,
                        serde_json::to_value(loader.status)?.as_str().unwrap_or(""),
                        loader.detail
                    );
                }
                say!(
                    "list {:.1} ms, map {:.1} ms, graph {:.1} ms, reduce {:.1} ms, cones {:.1} ms, total {:.1} ms",
                    stats.list_ms,
                    stats.map_ms,
                    report.graph_ms,
                    report.reduce_ms,
                    report.cones_ms,
                    report.total_ms
                );
            }
            Ok(ExitCode::from(u8::from(report.rules_failed > 0)))
        }
        Command::Cones { repo, base, head, rules, gateaudits, cache_dir, no_cache, json } => {
            let started = Instant::now();
            let mut pack = load_pack(rules.as_deref(), gateaudits.as_deref())?;
            pack.rule.retain(|rule| rule.kind == ast_sweep::RuleKind::PythonImportGraph);
            if pack.rule.is_empty() {
                pack.rule.push(ast_sweep::Rule::new("python-import-graph", ast_sweep::RuleKind::PythonImportGraph));
            }
            let cache = facts_cache(cache_dir, no_cache)?;
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
                        changed
                            .push(json!({"unit": cone.unit, "path": cone.path, "widened": cone.widened, "moved_paths": moved}));
                    }
                    None => added.push(cone.unit.clone()),
                }
            }
            let after: std::collections::BTreeSet<&str> = head_report.cones.iter().map(|c| c.unit.as_str()).collect();
            let removed: Vec<&str> = before.keys().copied().filter(|unit| !after.contains(unit)).collect();
            let report = json!({
                "base": base_report.tree, "head": head_report.tree,
                "units": head_report.cones.len(), "transported": transported,
                "widened": head_report.widened_cones, "widened_by_cause": head_report.widened_by_cause,
                "changed": changed, "added": added, "removed": removed,
                "ms": started.elapsed().as_secs_f64() * 1000.0,
            });
            if json {
                print_json(&report)?;
            } else {
                say!(
                    "{} units: {} transported (0 runs), {} changed, {} added, {} removed; {} depend on the whole tree",
                    head_report.cones.len(),
                    transported,
                    changed.len(),
                    added.len(),
                    removed.len(),
                    head_report.widened_cones
                );
                for unit in &changed {
                    let moved: Vec<&str> =
                        unit["moved_paths"].as_array().into_iter().flatten().filter_map(|p| p.as_str()).collect();
                    say!("  changed {} <- {}", unit["unit"].as_str().unwrap_or(""), moved.join(", "));
                }
                for unit in &added {
                    say!("  added   {unit}");
                }
                for unit in &removed {
                    say!("  removed {unit}");
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Land { repo, lane, target, apply, config, overrides } => {
            if !valid_lane(&lane) {
                return Err(format!("{lane:?} is not a lane name (a branch name or a commit id)").into());
            }
            let mut config = load_config(config.as_deref(), &overrides)?;
            if let Some(target) = target {
                config = config.with_override(&format!("target_ref={target}"))?;
            }
            let station = Station::open(&repo, config)?;
            let candidate = Candidate { tip: station.repo.commit_of(&lane)?, lane };
            let report = station.train()?.land_batch(&[candidate], apply, daemon::unix_now())?;
            print_json(&report)?;
            let done = report.outcomes.iter().all(|(_, outcome)| {
                matches!(
                    outcome,
                    CandidateOutcome::Landed { .. } | CandidateOutcome::WouldLand { .. } | CandidateOutcome::NoChange
                )
            });
            Ok(ExitCode::from(u8::from(!done)))
        }
        Command::Daemon { socket, config, repo, overrides } => {
            // Everything that can be wrong with the configuration (sandbox,
            // key, state directory) is an error here, before the socket exists.
            let station = Station::open(&repo, load_config(Some(&config), &overrides)?)?;
            station.train()?;
            daemon::serve(&socket, &station)?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Ctl { socket, request } => {
            let request = match request {
                CtlRequest::Enqueue { lane, tip } => wire::Request::Enqueue { lane, tip },
                CtlRequest::Status { since } => wire::Request::Status { since },
                CtlRequest::Shutdown => wire::Request::Shutdown {},
            };
            let response = daemon::call(&socket, &request)?;
            print_json(&response)?;
            Ok(ExitCode::from(u8::from(matches!(response, wire::Response::Error { .. }))))
        }
        Command::Replay { ledger, module_costs, timings, config, overrides, json } => {
            let config = load_config(config.as_deref(), &overrides)?;
            // Bytes, not text: one bad byte in a long ledger is one bad line.
            let ledger = landd_sim::parse_ledger(&std::fs::read(&ledger)?);
            let mut costs = ModuleCosts::observe(&ledger);
            if let Some(path) = module_costs {
                costs = costs.with_table(&std::fs::read_to_string(path)?)?;
            }
            let timings = match timings {
                Some(path) => Some(landd_sim::Timings::parse(&std::fs::read(path)?)?),
                None => None,
            };
            let report = landd_sim::simulate(&ledger, &costs, timings, &SimConfig::from_config(&config));
            if json {
                print_json(&report)?;
            } else {
                say!("{}", report.to_markdown().trim_end());
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::PreReceive { trusted_keys, repo_id, protect } => pre_receive(&trusted_keys, &repo_id, protect),
    }
}

fn pre_receive(trusted_keys: &Path, repo_id: &str, mut protect: Vec<String>) -> Result<ExitCode, AnyError> {
    // Naming more refs to protect never unprotects main.
    if !protect.iter().any(|name| name == "refs/heads/main") {
        protect.push("refs/heads/main".to_owned());
    }
    let trusted = TrustedKeys::load(trusted_keys)?;
    let mut stdin = String::new();
    std::io::stdin().take(hook::MAX_HOOK_STDIN_BYTES + 1).read_to_string(&mut stdin)?;
    if stdin.len() as u64 > hook::MAX_HOOK_STDIN_BYTES {
        eprintln!("landd pre-receive: ref update input exceeds {} bytes", hook::MAX_HOOK_STDIN_BYTES);
        return Ok(ExitCode::from(1));
    }
    let updates = hook::parse_updates(&stdin)?;
    let count: usize = match std::env::var("GIT_PUSH_OPTION_COUNT") {
        Ok(raw) => match raw.parse::<usize>() {
            Ok(n) if n <= hook::MAX_PUSH_OPTIONS => n,
            Ok(n) => {
                eprintln!("landd pre-receive: too many push options ({n} > {})", hook::MAX_PUSH_OPTIONS);
                return Ok(ExitCode::from(1));
            }
            Err(_) => {
                eprintln!("landd pre-receive: malformed GIT_PUSH_OPTION_COUNT {raw:?}");
                return Ok(ExitCode::from(1));
            }
        },
        Err(_) => 0,
    };
    let options: Vec<String> = (0..count).filter_map(|i| std::env::var(format!("GIT_PUSH_OPTION_{i}")).ok()).collect();
    // The hook runs inside the receiving repository, with the pushed objects
    // in quarantine; only the variables that say so are kept.
    let repo = GitRepo::open_in_hook()?;
    match hook::check(repo_id, &updates, &options, &trusted, &protect, |old, new| repo.is_ancestor(old, new).unwrap_or(false)) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(why) => {
            eprintln!("landd pre-receive: {why}");
            Ok(ExitCode::from(1))
        }
    }
}
