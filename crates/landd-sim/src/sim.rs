//! A discrete-event model of the batch train, driven by a real ledger.
//!
//! What is replayed exactly: arrival times, which lanes arrived, the modules
//! each selected, and what each actually cost `fleet`. What is modelled, and
//! reported as an assumption in every report:
//!
//! * the train is the only writer of the target ref, so it loses no races;
//!   a ledger row that retries a head the train already settled is not an
//!   arrival;
//! * a module runs at most once per batch (on the batch tip) and never again
//!   for a head it has already judged;
//! * a red candidate costs its modules once on the batch tip, one base run of
//!   its costliest module (new red or inherited?), and one rerun of every
//!   module it shares with a healthy peer once it is removed;
//! * a conflicting candidate costs composition only.

use crate::ledger::{LandRun, Ledger, ModuleCosts};
use landd_core::LandConfig;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, PartialEq)]
pub struct SimConfig {
    pub max_batch_size: usize,
    pub batch_coalesce_ms: u64,
    pub runner_concurrency: usize,
    /// `merge-tree` + `commit-tree` per candidate.
    pub compose_s: f64,
    /// Incremental `ast-sweep` + cone export per batch.
    pub sweep_s: f64,
    /// Push and forge ancestry proof per batch.
    pub push_s: f64,
    /// Outcomes that mean "another push won".
    pub lost_race_outcomes: Vec<String>,
    /// Outcomes that mean "did not merge".
    pub conflict_outcomes: Vec<String>,
}

impl SimConfig {
    pub fn from_config(config: &LandConfig) -> Self {
        Self {
            max_batch_size: config.max_batch_size,
            batch_coalesce_ms: config.batch_coalesce_ms,
            runner_concurrency: config.runner_concurrency,
            compose_s: 0.010,
            sweep_s: 0.005,
            push_s: 1.0,
            lost_race_outcomes: ["carried", "refused:push", "unknown:push"].map(String::from).to_vec(),
            conflict_outcomes: ["refused:compose", "refused:conflict"].map(String::from).to_vec(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Side {
    /// Land attempts (ledger rows, or train candidates).
    pub attempts: usize,
    pub landed: usize,
    pub declined: usize,
    pub lost_races: usize,
    pub total_cpu_s: f64,
    pub rung_cpu_p50_s: f64,
    pub rung_cpu_p95_s: f64,
    pub lead_p50_s: f64,
    pub lead_p95_s: f64,
    pub module_runs: usize,
    pub batches: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub ledger_rows: usize,
    pub ledger_malformed: usize,
    pub actual_fleet: Side,
    pub landd: Side,
    pub cpu_saved_s: f64,
    pub module_runs_saved: i64,
    pub assumptions: Vec<String>,
}

/// Nearest-rank percentile; 0 for an empty sample.
fn percentile(values: &[f64], p: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    Good,
    Red,
    Conflict,
}

fn applied_lands(ledger: &Ledger) -> impl Iterator<Item = &LandRun> {
    ledger.runs.iter().filter(|run| run.kind == "land" && run.apply)
}

fn actual(ledger: &Ledger, config: &SimConfig) -> Side {
    let mut side = Side::default();
    let (mut cpu, mut lead) = (Vec::new(), Vec::new());
    for run in applied_lands(ledger) {
        side.attempts += 1;
        side.module_runs += run.modules.len();
        if let Some(spent) = run.cpu_s {
            side.total_cpu_s += spent;
            cpu.push(spent);
        }
        if config.lost_race_outcomes.contains(&run.outcome) {
            side.lost_races += 1;
        } else if run.outcome == "landed" {
            side.landed += 1;
            match (run.pushed_ts, run.wall_s) {
                (Some(pushed), _) if pushed >= run.ts => lead.push(pushed - run.ts),
                (_, Some(wall)) => lead.push(wall),
                _ => {}
            }
        } else if run.outcome.starts_with("refused") {
            side.declined += 1;
        }
    }
    side.batches = side.attempts;
    finish(side, &cpu, &lead)
}

fn finish(mut side: Side, cpu: &[f64], lead: &[f64]) -> Side {
    side.total_cpu_s = round3(side.total_cpu_s);
    side.rung_cpu_p50_s = round3(percentile(cpu, 50.0));
    side.rung_cpu_p95_s = round3(percentile(cpu, 95.0));
    side.lead_p50_s = round3(percentile(lead, 50.0));
    side.lead_p95_s = round3(percentile(lead, 95.0));
    side
}

fn replay(ledger: &Ledger, costs: &ModuleCosts, config: &SimConfig) -> Side {
    let fate = |run: &LandRun| {
        if config.conflict_outcomes.contains(&run.outcome) {
            Fate::Conflict
        } else if run.outcome.starts_with("refused") && !config.lost_race_outcomes.contains(&run.outcome) {
            Fate::Red
        } else {
            Fate::Good
        }
    };
    // A head with no id cannot be recognized as a retry; key it by its row.
    let identity = |run: &LandRun| if run.head.is_empty() { format!("row:{}", run.row) } else { run.head.clone() };
    let arrivals: Vec<&LandRun> = applied_lands(ledger).filter(|r| r.outcome != "dry-run").collect();

    let mut side = Side::default();
    let (mut cpu, mut lead) = (Vec::new(), Vec::new());
    let mut settled: BTreeSet<String> = BTreeSet::new();
    let mut judged: BTreeSet<(String, String)> = BTreeSet::new();
    let mut queue: VecDeque<&LandRun> = VecDeque::new();
    let coalesce = config.batch_coalesce_ms as f64 / 1000.0;
    let (mut next, mut now) = (0usize, f64::NEG_INFINITY);

    loop {
        if queue.is_empty() {
            let Some(run) = arrivals.get(next) else { break };
            now = now.max(run.ts);
        }
        while let Some(run) = arrivals.get(next).filter(|run| run.ts <= now) {
            next += 1;
            let id = identity(run);
            if !settled.contains(&id) && !queue.iter().any(|queued| identity(queued) == id) {
                queue.push_back(run);
            }
        }
        let Some(oldest) = queue.front().map(|run| run.ts) else { continue };
        // The departure rule of `landd_train::batch_ready`.
        let ready = queue.len() == 1 || queue.len() >= config.max_batch_size || now - oldest >= coalesce;
        if !ready {
            let window_closes = oldest + coalesce;
            now = arrivals.get(next).map(|run| run.ts.min(window_closes)).unwrap_or(window_closes);
            continue;
        }

        let take = queue.len().min(config.max_batch_size);
        let batch: Vec<&LandRun> = queue.drain(..take).collect();
        side.batches += 1;
        let mut running: BTreeMap<&str, f64> = BTreeMap::new();
        let mut extra: Vec<f64> = Vec::new();
        for run in &batch {
            if fate(run) == Fate::Conflict {
                continue;
            }
            let id = identity(run);
            for module in run.modules.keys() {
                if judged.insert((module.clone(), id.clone())) {
                    let cost = costs.cost(run, module);
                    let slot = running.entry(module.as_str()).or_insert(cost);
                    *slot = slot.max(cost);
                }
            }
        }
        let healthy: BTreeSet<&str> =
            batch.iter().filter(|r| fate(r) == Fate::Good).flat_map(|r| r.modules.keys().map(String::as_str)).collect();
        for run in batch.iter().filter(|r| fate(r) == Fate::Red) {
            let own: Vec<f64> = run.modules.keys().map(|m| costs.cost(run, m)).collect();
            extra.extend(own.iter().copied().max_by(f64::total_cmp));
            extra.extend(run.modules.keys().filter(|m| healthy.contains(m.as_str())).map(|m| costs.cost(run, m)));
        }
        let runs: Vec<f64> = running.values().copied().chain(extra).collect();
        let batch_cpu: f64 = runs.iter().sum();
        let longest = runs.iter().copied().fold(0.0, f64::max);
        let test_wall = (batch_cpu / config.runner_concurrency.max(1) as f64).max(longest);
        let landing = batch.iter().any(|r| fate(r) == Fate::Good);
        let wall = config.compose_s * batch.len() as f64 + config.sweep_s + test_wall + if landing { config.push_s } else { 0.0 };
        let done = now + wall;

        side.module_runs += runs.len();
        side.total_cpu_s += batch_cpu;
        for run in &batch {
            side.attempts += 1;
            settled.insert(identity(run));
            cpu.push(batch_cpu / batch.len() as f64);
            match fate(run) {
                Fate::Good => {
                    side.landed += 1;
                    lead.push(done - run.ts);
                }
                Fate::Red | Fate::Conflict => side.declined += 1,
            }
        }
        now = done;
    }
    finish(side, &cpu, &lead)
}

pub fn simulate(ledger: &Ledger, costs: &ModuleCosts, config: &SimConfig) -> Report {
    let actual_fleet = actual(ledger, config);
    let landd = replay(ledger, costs, config);
    Report {
        ledger_rows: ledger.lines,
        ledger_malformed: ledger.malformed,
        cpu_saved_s: round3(actual_fleet.total_cpu_s - landd.total_cpu_s),
        module_runs_saved: actual_fleet.module_runs as i64 - landd.module_runs as i64,
        actual_fleet,
        landd,
        assumptions: vec![
            "landd is the only writer of the target ref: it loses no races, and a ledger row that retries an already settled head is not an arrival".into(),
            "a module runs at most once per batch and never again for a head already judged".into(),
            "a red candidate costs its modules on the batch tip, one base run of its costliest module, and one rerun of each module it shares with a healthy peer".into(),
            "a conflicting candidate costs composition only".into(),
            format!(
                "batches of up to {} leave after {} ms (a queue of one leaves at once); {} runners; {} s compose per candidate, {} s sweep and {} s push per batch",
                config.max_batch_size, config.batch_coalesce_ms, config.runner_concurrency, config.compose_s, config.sweep_s, config.push_s
            ),
            "landd CPU counts test modules only; fleet cpu_s is the ledger's own figure for the whole run".into(),
        ],
    }
}

impl Report {
    pub fn to_markdown(&self) -> String {
        let (a, l) = (&self.actual_fleet, &self.landd);
        let mut out = String::from("# land_runs replay: actual fleet vs landd\n\n");
        out.push_str(&format!("Ledger rows: {} ({} unreadable).\n\n", self.ledger_rows, self.ledger_malformed));
        out.push_str("| metric | actual_fleet | landd |\n|---|---:|---:|\n");
        let mut row = |name: &str, x: String, y: String| out.push_str(&format!("| {name} | {x} | {y} |\n"));
        row("land attempts", a.attempts.to_string(), l.attempts.to_string());
        row("landed", a.landed.to_string(), l.landed.to_string());
        row("declined", a.declined.to_string(), l.declined.to_string());
        row("lost races", a.lost_races.to_string(), l.lost_races.to_string());
        row("batches", a.batches.to_string(), l.batches.to_string());
        row("total CPU-s", format!("{:.1}", a.total_cpu_s), format!("{:.1}", l.total_cpu_s));
        row("rung CPU p50 (s)", format!("{:.1}", a.rung_cpu_p50_s), format!("{:.1}", l.rung_cpu_p50_s));
        row("rung CPU p95 (s)", format!("{:.1}", a.rung_cpu_p95_s), format!("{:.1}", l.rung_cpu_p95_s));
        row("commit-to-main lead p50 (s)", format!("{:.1}", a.lead_p50_s), format!("{:.1}", l.lead_p50_s));
        row("commit-to-main lead p95 (s)", format!("{:.1}", a.lead_p95_s), format!("{:.1}", l.lead_p95_s));
        row("test module runs", a.module_runs.to_string(), l.module_runs.to_string());
        out.push_str(&format!("\nCPU saved: {:.1} s. Test module runs saved: {}.\n\n## Model\n\n", self.cpu_saved_s, self.module_runs_saved));
        for assumption in &self.assumptions {
            out.push_str(&format!("- {assumption}\n"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::parse_ledger;

    fn row(ts: f64, head: &str, outcome: &str, modules: &[(&str, f64)]) -> String {
        let measured: Vec<String> = modules.iter().map(|(m, s)| format!("\"{m}\":{s}")).collect();
        let cpu: f64 = modules.iter().map(|(_, s)| s).sum();
        format!(
            "{{\"kind\":\"land\",\"ts\":{ts},\"apply\":true,\"head\":\"{head}\",\"outcome\":\"{outcome}\",\"modules\":{{{}}},\"cpu_s\":{cpu},\"wall_s\":{cpu}}}",
            measured.join(",")
        )
    }

    fn config() -> SimConfig {
        SimConfig { compose_s: 0.0, sweep_s: 0.0, push_s: 0.0, runner_concurrency: 1, ..SimConfig::from_config(&LandConfig::default()) }
    }

    fn run(rows: &[String], config: &SimConfig) -> Report {
        let ledger = parse_ledger(&rows.join("\n"));
        simulate(&ledger, &ModuleCosts::observe(&ledger, 1.0), config)
    }

    #[test]
    fn a_burst_shares_one_run_of_each_module() {
        // h1 arrives alone and leaves at once; h2 and h3 arrive while it runs
        // and share one batch.
        let rows = [
            row(0.0, "h1", "landed", &[("t.a", 10.0), ("t.b", 5.0)]),
            row(1.0, "h2", "landed", &[("t.a", 10.0), ("t.c", 2.0)]),
            row(2.0, "h3", "landed", &[("t.a", 10.0), ("t.c", 2.0)]),
        ];
        let report = run(&rows, &config());
        assert_eq!((report.actual_fleet.total_cpu_s, report.actual_fleet.module_runs), (39.0, 6));
        assert_eq!((report.landd.batches, report.landd.landed, report.landd.module_runs), (2, 3, 4));
        assert_eq!(report.landd.total_cpu_s, 27.0);
        assert_eq!((report.cpu_saved_s, report.module_runs_saved), (12.0, 2));
        // h1: 15 s. h2 and h3 start at t=15 and finish at t=27.
        assert_eq!((report.landd.lead_p50_s, report.landd.lead_p95_s), (25.0, 26.0));
        assert_eq!(report.landd.lost_races, 0);
    }

    #[test]
    fn tooth_no_sharing_means_no_savings() {
        let rows = [
            row(0.0, "h1", "landed", &[("t.a", 10.0)]),
            row(100.0, "h2", "landed", &[("t.b", 7.0)]),
            row(200.0, "h3", "landed", &[("t.c", 3.0)]),
        ];
        let report = run(&rows, &config());
        assert_eq!(report.landd.total_cpu_s, report.actual_fleet.total_cpu_s);
        assert_eq!((report.cpu_saved_s, report.module_runs_saved), (0.0, 0));
        assert_eq!(report.landd.batches, 3);
        // A queue of one never waits: lead time is the test time alone.
        assert_eq!((report.landd.lead_p50_s, report.landd.lead_p95_s), (7.0, 10.0));
    }

    #[test]
    fn retries_after_a_lost_race_are_not_rerun() {
        let rows = [
            row(0.0, "h1", "refused:push", &[("t.a", 10.0)]),
            row(60.0, "h1", "carried", &[("t.a", 10.0)]),
            row(120.0, "h1", "landed", &[("t.a", 10.0)]),
        ];
        let report = run(&rows, &config());
        assert_eq!((report.actual_fleet.attempts, report.actual_fleet.lost_races, report.actual_fleet.landed), (3, 2, 1));
        assert_eq!(report.actual_fleet.total_cpu_s, 30.0);
        assert_eq!((report.landd.attempts, report.landd.landed, report.landd.lost_races), (1, 1, 0));
        assert_eq!((report.landd.total_cpu_s, report.landd.module_runs), (10.0, 1));
    }

    #[test]
    fn red_and_conflicting_candidates_cost_what_the_model_says() {
        let burst = |outcome: &str| {
            [
                row(0.0, "h0", "landed", &[("t.z", 4.0)]),
                row(1.0, "good", "landed", &[("t.a", 10.0), ("t.shared", 3.0)]),
                row(2.0, "other", outcome, &[("t.shared", 3.0), ("t.own", 6.0)]),
            ]
        };
        let red = run(&burst("refused:rung"), &config());
        // Second batch: t.a + t.shared + t.own once (19), a base run of the
        // culprit's costliest module (6), and t.shared again without it (3).
        assert_eq!(red.landd.total_cpu_s, 4.0 + 19.0 + 6.0 + 3.0);
        assert_eq!((red.landd.landed, red.landd.declined), (2, 1));

        let conflict = run(&burst("refused:compose"), &config());
        assert_eq!(conflict.landd.total_cpu_s, 4.0 + 13.0);
        assert_eq!((conflict.landd.landed, conflict.landd.declined), (2, 1));
    }

    #[test]
    fn coalescing_window_and_batch_size_are_honoured() {
        let rows: Vec<String> = (0..5).map(|i| row(10.0 + i as f64 * 0.01, &format!("h{i}"), "landed", &[("t.a", 1.0)])).collect();
        let mut settings = config();
        settings.max_batch_size = 2;
        let report = run(&rows, &settings);
        // h0 alone, then pairs: three batches for five lanes.
        assert_eq!((report.landd.batches, report.landd.landed, report.landd.module_runs), (3, 5, 3));

        // Dry runs and non-land rows are not arrivals.
        let quiet = [
            "{\"kind\":\"land\",\"ts\":1,\"apply\":false,\"outcome\":\"dry-run\",\"head\":\"x\"}".to_owned(),
            "{\"kind\":\"revert\",\"ts\":2,\"apply\":true,\"outcome\":\"landed\"}".to_owned(),
        ];
        let empty = run(&quiet, &config());
        assert_eq!((empty.landd.attempts, empty.actual_fleet.attempts, empty.landd.lead_p95_s), (0, 0, 0.0));
    }

    #[test]
    fn reports_render_as_markdown_and_json() {
        let report = run(&[row(0.0, "h1", "landed", &[("t.a", 10.0)])], &config());
        let markdown = report.to_markdown();
        assert!(markdown.contains("| metric | actual_fleet | landd |"));
        assert!(markdown.contains("| total CPU-s | 10.0 | 10.0 |"));
        assert!(markdown.contains("## Model"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["landd"]["landed"], 1);
        assert_eq!(json["actual_fleet"]["rung_cpu_p95_s"], 10.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 50.0), 2.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 95.0), 4.0);
    }
}
