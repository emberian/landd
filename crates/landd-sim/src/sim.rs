//! What a ledger shows, and (when it holds enough) a model of the batch
//! train on the same arrivals.
//!
//! **Observed** figures are read off the ledger and nothing else: counts by
//! outcome class, run and push-phase wall times, and the lead time of each
//! landed lane from its *first* attempt to main. Hub CPU is reported as hub
//! CPU; it is never divided among test modules.
//!
//! The **replay** needs, for every run that reached the checks, the set of
//! test modules it selected and a measured cost for each. A ledger without
//! them (real `fleet` ledgers record `selected: []` and `modules: {}`) gets
//! `Unavailable` with the reasons, not a number. When they are present the
//! replay models:
//!
//! * the train as the only writer of the target ref, so it loses no races;
//!   a lane is one candidate however many times the ledger retried it;
//! * a module run at most once per batch and never again for a lane already
//!   judged;
//! * a red lane costing its modules once on the batch tip, one base run of
//!   its costliest module, and one rerun of every module it shares with a
//!   healthy peer once it is removed;
//! * a conflicting lane costing composition only.
//!
//! Both sides of the replay are counted in the same unit, module cost
//! seconds, so their difference means something. That presumes landd's
//! cones would select the same modules `fleet` selected, which has to be
//! shown separately for the tree in question.

use crate::ledger::{Class, LandRun, Ledger, ModuleCosts, Timings};
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
    /// Incremental sweep and cone export per batch.
    pub sweep_s: f64,
    /// Push and destination read per batch.
    pub push_s: f64,
}

impl SimConfig {
    pub fn from_config(config: &LandConfig) -> Self {
        Self {
            max_batch_size: config.max_batch_size,
            batch_coalesce_ms: config.batch_coalesce_ms,
            runner_concurrency: config.runner_concurrency,
            compose_s: 0.030,
            sweep_s: 0.150,
            push_s: 1.0,
        }
    }
}

/// What the ledger records about the applied `land` runs.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Observed {
    pub applied_runs: usize,
    /// Distinct lane tips among them.
    pub lanes: usize,
    pub lanes_landed: usize,
    pub runs_by_class: BTreeMap<Class, usize>,
    /// Outcome words the table does not know, with how often each appears.
    pub unclassified_outcomes: BTreeMap<String, usize>,
    /// Refused attempts inside single runs (each re-ran checks).
    pub inner_refused_attempts: usize,
    pub runs_per_landed_lane_p50: f64,
    pub runs_per_landed_lane_p95: f64,
    /// Wall time of the runs that landed.
    pub landed_run_wall_p50_s: f64,
    pub landed_run_wall_p95_s: f64,
    /// Wall time of the `push` phase (checks and push) of the runs that landed.
    pub landed_push_phase_p50_s: f64,
    pub landed_push_phase_p95_s: f64,
    /// From a lane's first applied attempt to its landing on main.
    pub lead_first_attempt_p50_s: f64,
    pub lead_first_attempt_p95_s: f64,
    /// Sum of `cpu_s`: the hub's CPU, not the cost of the test modules.
    pub hub_cpu_total_s: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Side {
    /// Runs (fleet) or candidates (landd) that reached the checks.
    pub attempts: usize,
    pub landed: usize,
    pub declined: usize,
    pub batches: usize,
    pub module_runs: usize,
    /// Sum of the measured cost of every module run.
    pub module_cost_s: f64,
    pub lead_p50_s: f64,
    pub lead_p95_s: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "replay", rename_all = "snake_case")]
pub enum Replay {
    Available {
        fleet: Side,
        landd: Side,
        module_cost_saved_s: f64,
        module_runs_saved: i64,
    },
    /// The ledger does not hold what the replay needs.
    Unavailable {
        reasons: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    pub ledger_rows: usize,
    pub ledger_malformed: usize,
    pub observed: Observed,
    pub timings: Option<Timings>,
    pub replay: Replay,
    pub notes: Vec<String>,
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

fn applied_lands(ledger: &Ledger) -> impl Iterator<Item = &LandRun> {
    ledger.runs.iter().filter(|run| run.kind == "land" && run.apply && run.class() != Class::DryRun)
}

/// Did the run get as far as running checks?
fn reached_checks(class: Class) -> bool {
    matches!(class, Class::Landed | Class::Carried | Class::LostPush | Class::Red)
}

/// When a landing run put its lane on main.
fn landed_at(run: &LandRun) -> f64 {
    match (run.pushed_ts, run.wall_s) {
        (Some(pushed), _) if pushed >= run.ts => pushed,
        (_, Some(wall)) => run.ts + wall,
        _ => run.ts,
    }
}

fn observe(ledger: &Ledger) -> Observed {
    let mut observed = Observed::default();
    let mut by_lane: BTreeMap<String, Vec<&LandRun>> = BTreeMap::new();
    let (mut walls, mut pushes) = (Vec::new(), Vec::new());
    for run in applied_lands(ledger) {
        observed.applied_runs += 1;
        let class = run.class();
        *observed.runs_by_class.entry(class).or_insert(0) += 1;
        if class == Class::Unclassified {
            *observed.unclassified_outcomes.entry(run.outcome.clone()).or_insert(0) += 1;
        }
        observed.inner_refused_attempts += run.refused_attempts;
        observed.hub_cpu_total_s += run.cpu_s.unwrap_or(0.0);
        if class == Class::Landed {
            walls.extend(run.wall_s);
            pushes.extend(run.phases.get("push").copied());
        }
        by_lane.entry(run.lane_key()).or_default().push(run);
    }
    observed.lanes = by_lane.len();
    let (mut leads, mut tries) = (Vec::new(), Vec::new());
    for runs in by_lane.values() {
        // Rows are in time order; the lane's lead runs from its first attempt.
        if let Some(position) = runs.iter().position(|run| run.class() == Class::Landed) {
            observed.lanes_landed += 1;
            leads.push(landed_at(runs[position]) - runs[0].ts);
            tries.push((position + 1) as f64);
        }
    }
    observed.runs_per_landed_lane_p50 = percentile(&tries, 50.0);
    observed.runs_per_landed_lane_p95 = percentile(&tries, 95.0);
    observed.landed_run_wall_p50_s = round3(percentile(&walls, 50.0));
    observed.landed_run_wall_p95_s = round3(percentile(&walls, 95.0));
    observed.landed_push_phase_p50_s = round3(percentile(&pushes, 50.0));
    observed.landed_push_phase_p95_s = round3(percentile(&pushes, 95.0));
    observed.lead_first_attempt_p50_s = round3(percentile(&leads, 50.0));
    observed.lead_first_attempt_p95_s = round3(percentile(&leads, 95.0));
    observed.hub_cpu_total_s = round3(observed.hub_cpu_total_s);
    observed
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fate {
    Good,
    Red,
    Conflict,
}

/// One lane as the train would meet it: when it first arrived, what the
/// ledger says became of it, and the modules its runs selected.
struct Arrival {
    ts: f64,
    fate: Fate,
    /// Module -> measured cost.
    modules: BTreeMap<String, f64>,
}

/// Why the ledger cannot be replayed, or the lanes to replay.
fn arrivals(ledger: &Ledger, costs: &ModuleCosts) -> Result<Vec<Arrival>, Vec<String>> {
    let mut by_lane: BTreeMap<String, Vec<&LandRun>> = BTreeMap::new();
    for run in applied_lands(ledger) {
        by_lane.entry(run.lane_key()).or_default().push(run);
    }
    let (mut checked, mut without_modules) = (0usize, 0usize);
    let mut uncosted: BTreeSet<&str> = BTreeSet::new();
    let mut out = Vec::new();
    for runs in by_lane.values() {
        let classes: BTreeSet<Class> = runs.iter().map(|run| run.class()).collect();
        let fate = if classes.contains(&Class::Landed) || classes.contains(&Class::Carried) {
            Fate::Good
        } else if classes.contains(&Class::Red) {
            Fate::Red
        } else if classes.contains(&Class::Conflict) {
            Fate::Conflict
        } else if classes.contains(&Class::LostPush) {
            // Its checks passed; only the push lost.
            Fate::Good
        } else {
            // Held, refused as a lane, duplicate, infrastructure, unknown:
            // not something a train would have judged.
            continue;
        };
        let mut modules = BTreeMap::new();
        for run in runs.iter().filter(|run| reached_checks(run.class())) {
            checked += 1;
            if run.modules.is_empty() {
                without_modules += 1;
            }
            for module in run.modules.keys() {
                match costs.cost(run, module) {
                    Some(cost) => {
                        modules.insert(module.clone(), cost);
                    }
                    None => {
                        uncosted.insert(module);
                    }
                }
            }
        }
        out.push(Arrival { ts: runs[0].ts, fate, modules });
    }
    let mut reasons = Vec::new();
    if checked == 0 {
        reasons.push("no applied run in the ledger reached the checks".to_owned());
    }
    if without_modules > 0 {
        reasons.push(format!(
            "{without_modules} of the {checked} runs that reached the checks record no module set (`selected` and `modules` are empty), so what each lane would have run is unknown"
        ));
    }
    if !uncosted.is_empty() {
        reasons.push(format!(
            "{} selected modules have no measured cost (first: {})",
            uncosted.len(),
            uncosted.iter().next().unwrap_or(&"")
        ));
    }
    if !reasons.is_empty() {
        reasons.push(
            "hub `cpu_s` is not a substitute: it is the hub's CPU for the whole run, not the cost of the modules".to_owned(),
        );
        return Err(reasons);
    }
    out.sort_by(|a, b| a.ts.total_cmp(&b.ts));
    Ok(out)
}

/// What fleet spent on modules, counted as the replay counts landd's.
fn fleet_side(ledger: &Ledger, costs: &ModuleCosts, observed: &Observed) -> Side {
    let mut side = Side::default();
    for run in applied_lands(ledger).filter(|run| reached_checks(run.class())) {
        side.attempts += 1;
        side.batches += 1;
        side.module_runs += run.modules.len();
        side.module_cost_s += run.modules.keys().filter_map(|m| costs.cost(run, m)).sum::<f64>();
        match run.class() {
            Class::Landed => side.landed += 1,
            Class::Red => side.declined += 1,
            _ => {}
        }
    }
    side.module_cost_s = round3(side.module_cost_s);
    side.lead_p50_s = observed.lead_first_attempt_p50_s;
    side.lead_p95_s = observed.lead_first_attempt_p95_s;
    side
}

fn replay(lanes: &[Arrival], config: &SimConfig) -> Side {
    let mut side = Side::default();
    let mut lead = Vec::new();
    let mut queue: VecDeque<&Arrival> = VecDeque::new();
    let coalesce = config.batch_coalesce_ms as f64 / 1000.0;
    let (mut next, mut now) = (0usize, f64::NEG_INFINITY);

    loop {
        if queue.is_empty() {
            let Some(lane) = lanes.get(next) else { break };
            now = now.max(lane.ts);
        }
        while let Some(lane) = lanes.get(next).filter(|lane| lane.ts <= now) {
            next += 1;
            queue.push_back(lane);
        }
        let Some(oldest) = queue.front().map(|lane| lane.ts) else { continue };
        // The departure rule of `landd_train::batch_ready`.
        let ready = queue.len() == 1 || queue.len() >= config.max_batch_size || now - oldest >= coalesce;
        if !ready {
            let window_closes = oldest + coalesce;
            now = lanes.get(next).map(|lane| lane.ts.min(window_closes)).unwrap_or(window_closes);
            continue;
        }

        let take = queue.len().min(config.max_batch_size);
        let batch: Vec<&Arrival> = queue.drain(..take).collect();
        side.batches += 1;
        // Each module once on the batch tip, at the dearest cost any member measured for it.
        let mut running: BTreeMap<&str, f64> = BTreeMap::new();
        for lane in batch.iter().filter(|lane| lane.fate != Fate::Conflict) {
            for (module, cost) in &lane.modules {
                let slot = running.entry(module.as_str()).or_insert(*cost);
                *slot = slot.max(*cost);
            }
        }
        let healthy: BTreeSet<&str> = batch
            .iter()
            .filter(|lane| lane.fate == Fate::Good)
            .flat_map(|lane| lane.modules.keys().map(String::as_str))
            .collect();
        let mut extra: Vec<f64> = Vec::new();
        for lane in batch.iter().filter(|lane| lane.fate == Fate::Red) {
            extra.extend(lane.modules.values().copied().max_by(f64::total_cmp));
            extra.extend(lane.modules.iter().filter(|(module, _)| healthy.contains(module.as_str())).map(|(_, cost)| *cost));
        }
        let runs: Vec<f64> = running.values().copied().chain(extra).collect();
        let batch_cost: f64 = runs.iter().sum();
        let longest = runs.iter().copied().fold(0.0, f64::max);
        let test_wall = (batch_cost / config.runner_concurrency.max(1) as f64).max(longest);
        let landing = batch.iter().any(|lane| lane.fate == Fate::Good);
        let wall = config.compose_s * batch.len() as f64 + config.sweep_s + test_wall + if landing { config.push_s } else { 0.0 };
        let done = now + wall;

        side.module_runs += runs.len();
        side.module_cost_s += batch_cost;
        for lane in &batch {
            side.attempts += 1;
            match lane.fate {
                Fate::Good => {
                    side.landed += 1;
                    lead.push(done - lane.ts);
                }
                Fate::Red | Fate::Conflict => side.declined += 1,
            }
        }
        now = done;
    }
    side.module_cost_s = round3(side.module_cost_s);
    side.lead_p50_s = round3(percentile(&lead, 50.0));
    side.lead_p95_s = round3(percentile(&lead, 95.0));
    side
}

pub fn simulate(ledger: &Ledger, costs: &ModuleCosts, timings: Option<Timings>, config: &SimConfig) -> Report {
    let observed = observe(ledger);
    let replay = match arrivals(ledger, costs) {
        Ok(lanes) => {
            let fleet = fleet_side(ledger, costs, &observed);
            let landd = replay(&lanes, config);
            Replay::Available {
                module_cost_saved_s: round3(fleet.module_cost_s - landd.module_cost_s),
                module_runs_saved: fleet.module_runs as i64 - landd.module_runs as i64,
                fleet,
                landd,
            }
        }
        Err(reasons) => Replay::Unavailable { reasons },
    };
    let mut notes = vec![
        "observed figures are read off the ledger; nothing in them is modelled".to_owned(),
        "lead time is from a lane's first applied attempt to its landing, not the wall time of one run".to_owned(),
        "`hub_cpu_total_s` is the hub's CPU; it is not test-module CPU and is not compared with anything".to_owned(),
    ];
    if observed.inner_refused_attempts > 0 {
        notes.push(format!(
            "{} refused attempts inside single runs re-ran checks; the ledger does not say which, so fleet's module runs are a lower bound",
            observed.inner_refused_attempts
        ));
    }
    if matches!(replay, Replay::Available { .. }) {
        notes.push(format!(
            "replay model: single writer, each module once per batch and never again per lane, batches of up to {} after {} ms (a queue of one leaves at once), {} runners, {} s compose per candidate, {} s sweep and {} s push per batch",
            config.max_batch_size, config.batch_coalesce_ms, config.runner_concurrency, config.compose_s, config.sweep_s, config.push_s
        ));
        notes.push("the replay assumes landd's cones select the modules fleet selected; that is a property of the tree and the rule pack and is not shown by this report".to_owned());
    }
    Report { ledger_rows: ledger.lines, ledger_malformed: ledger.malformed, observed, timings, replay, notes }
}

impl Report {
    pub fn to_markdown(&self) -> String {
        let o = &self.observed;
        let mut out = String::from("# land_runs replay\n\n");
        out.push_str(&format!(
            "Ledger rows: {} ({} unreadable).\n\n## Observed (fleet)\n\n",
            self.ledger_rows, self.ledger_malformed
        ));
        out.push_str("| metric | value |\n|---|---:|\n");
        let mut row = |name: &str, value: String| out.push_str(&format!("| {name} | {value} |\n"));
        row("applied land runs", o.applied_runs.to_string());
        row("distinct lanes (tips)", o.lanes.to_string());
        row("lanes landed", o.lanes_landed.to_string());
        for (class, count) in &o.runs_by_class {
            let name = serde_json::to_value(class).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
            row(&format!("runs: {name}"), count.to_string());
        }
        row("refused attempts inside runs", o.inner_refused_attempts.to_string());
        row("runs per landed lane p50 / p95", format!("{:.0} / {:.0}", o.runs_per_landed_lane_p50, o.runs_per_landed_lane_p95));
        row("landed run wall p50 / p95 (s)", format!("{:.1} / {:.1}", o.landed_run_wall_p50_s, o.landed_run_wall_p95_s));
        row("landed push phase p50 / p95 (s)", format!("{:.1} / {:.1}", o.landed_push_phase_p50_s, o.landed_push_phase_p95_s));
        row(
            "first attempt to main p50 / p95 (s)",
            format!("{:.1} / {:.1}", o.lead_first_attempt_p50_s, o.lead_first_attempt_p95_s),
        );
        row("hub CPU total (s)", format!("{:.1}", o.hub_cpu_total_s));
        for (word, count) in &o.unclassified_outcomes {
            out.push_str(&format!("\nUnclassified outcome {word:?}: {count} runs.\n"));
        }
        if let Some(t) = &self.timings {
            out.push_str("\n## Timing tables\n\n| metric | value |\n|---|---:|\n");
            out.push_str(&format!("| modules with a keeper wall time | {} |\n", t.keeper_modules));
            out.push_str(&format!("| one run of every such module, wall (s) | {:.1} |\n", t.keeper_suite_wall_s));
            out.push_str(&format!("| push records | {} |\n", t.push_records));
            out.push_str(&format!("| push records with a module count | {} |\n", t.push_records_with_module_count));
            out.push_str(&format!("| module runs those records count | {} |\n", t.push_module_runs));
            out.push_str(&format!("| push rung wall, total (s) | {:.1} |\n", t.push_rung_wall_s));
        }
        out.push_str("\n## Replay (landd model)\n\n");
        match &self.replay {
            Replay::Unavailable { reasons } => {
                out.push_str("Not available from this ledger:\n\n");
                for reason in reasons {
                    out.push_str(&format!("- {reason}\n"));
                }
            }
            Replay::Available { fleet, landd, module_cost_saved_s, module_runs_saved } => {
                out.push_str("| metric | fleet | landd |\n|---|---:|---:|\n");
                let mut row = |name: &str, a: String, b: String| out.push_str(&format!("| {name} | {a} | {b} |\n"));
                row("attempts that reached checks", fleet.attempts.to_string(), landd.attempts.to_string());
                row("landed", fleet.landed.to_string(), landd.landed.to_string());
                row("declined", fleet.declined.to_string(), landd.declined.to_string());
                row("batches", fleet.batches.to_string(), landd.batches.to_string());
                row("test module runs", fleet.module_runs.to_string(), landd.module_runs.to_string());
                row("module cost (s)", format!("{:.1}", fleet.module_cost_s), format!("{:.1}", landd.module_cost_s));
                row("lead p50 (s)", format!("{:.1}", fleet.lead_p50_s), format!("{:.1}", landd.lead_p50_s));
                row("lead p95 (s)", format!("{:.1}", fleet.lead_p95_s), format!("{:.1}", landd.lead_p95_s));
                out.push_str(&format!(
                    "\nModule cost saved: {module_cost_saved_s:.1} s. Module runs saved: {module_runs_saved}.\n"
                ));
            }
        }
        out.push_str("\n## Notes\n\n");
        for note in &self.notes {
            out.push_str(&format!("- {note}\n"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::parse_ledger;

    /// A row whose merged head differs on every attempt, as in real ledgers.
    fn row(ts: f64, tip: &str, outcome: &str, modules: &[(&str, f64)]) -> String {
        let measured: Vec<String> = modules.iter().map(|(m, s)| format!("\"{m}\":{s}")).collect();
        let cost: f64 = modules.iter().map(|(_, s)| s).sum();
        format!(
            "{{\"kind\":\"land\",\"ts\":{ts},\"apply\":true,\"tip\":\"{tip}\",\"head\":\"merged-{tip}-{ts}\",\"outcome\":\"{outcome}\",\"modules\":{{{}}},\"phases\":{{\"push\":{cost}}},\"cpu_s\":1.5,\"wall_s\":{cost},\"pushed_ts\":{}}}",
            measured.join(","),
            ts + cost
        )
    }

    fn config() -> SimConfig {
        SimConfig {
            compose_s: 0.0,
            sweep_s: 0.0,
            push_s: 0.0,
            runner_concurrency: 1,
            ..SimConfig::from_config(&LandConfig::default())
        }
    }

    fn run(rows: &[String], config: &SimConfig) -> Report {
        let ledger = parse_ledger(rows.join("\n").as_bytes());
        simulate(&ledger, &ModuleCosts::observe(&ledger), None, config)
    }

    fn sides(report: &Report) -> (&Side, &Side, f64, i64) {
        match &report.replay {
            Replay::Available { fleet, landd, module_cost_saved_s, module_runs_saved } => {
                (fleet, landd, *module_cost_saved_s, *module_runs_saved)
            }
            Replay::Unavailable { reasons } => panic!("replay unavailable: {reasons:?}"),
        }
    }

    #[test]
    fn a_burst_shares_one_run_of_each_module() {
        // h1 arrives alone and leaves at once; h2 and h3 arrive while it runs
        // and share one batch.
        let rows = [
            row(0.0, "t1", "landed", &[("t.a", 10.0), ("t.b", 5.0)]),
            row(1.0, "t2", "landed", &[("t.a", 10.0), ("t.c", 2.0)]),
            row(2.0, "t3", "landed", &[("t.a", 10.0), ("t.c", 2.0)]),
        ];
        let report = run(&rows, &config());
        let (fleet, landd, saved, runs_saved) = sides(&report);
        assert_eq!((fleet.module_cost_s, fleet.module_runs), (39.0, 6));
        assert_eq!((landd.batches, landd.landed, landd.module_runs), (2, 3, 4));
        assert_eq!(landd.module_cost_s, 27.0);
        assert_eq!((saved, runs_saved), (12.0, 2));
        // t1: 15 s. t2 and t3 start at t=15 and finish at t=27.
        assert_eq!((landd.lead_p50_s, landd.lead_p95_s), (25.0, 26.0));
    }

    #[test]
    fn tooth_no_sharing_means_no_savings() {
        let rows = [
            row(0.0, "t1", "landed", &[("t.a", 10.0)]),
            row(100.0, "t2", "landed", &[("t.b", 7.0)]),
            row(200.0, "t3", "landed", &[("t.c", 3.0)]),
        ];
        let report = run(&rows, &config());
        let (fleet, landd, saved, runs_saved) = sides(&report);
        assert_eq!(landd.module_cost_s, fleet.module_cost_s);
        assert_eq!((saved, runs_saved), (0.0, 0));
        assert_eq!(landd.batches, 3);
        // A queue of one never waits: lead time is the test time alone.
        assert_eq!((landd.lead_p50_s, landd.lead_p95_s), (7.0, 10.0));
    }

    /// A lane is its tip. The merged head changes on every retry and must
    /// not make one lane look like three.
    #[test]
    fn tooth_retries_are_one_lane_and_lead_time_runs_from_the_first_attempt() {
        let rows = [
            row(0.0, "t1", "refused:push", &[("t.a", 10.0)]),
            row(60.0, "t1", "carried", &[("t.a", 10.0)]),
            row(120.0, "t1", "landed", &[("t.a", 10.0)]),
        ];
        let report = run(&rows, &config());
        let o = &report.observed;
        assert_eq!((o.applied_runs, o.lanes, o.lanes_landed), (3, 1, 1));
        assert_eq!(
            (o.runs_by_class[&Class::LostPush], o.runs_by_class[&Class::Carried], o.runs_by_class[&Class::Landed]),
            (1, 1, 1)
        );
        // 120 s of retries plus the 10 s landing run: not the 10 s of one run.
        assert_eq!((o.lead_first_attempt_p50_s, o.landed_run_wall_p50_s, o.runs_per_landed_lane_p50), (130.0, 10.0, 3.0));
        let (fleet, landd, ..) = sides(&report);
        assert_eq!((fleet.attempts, fleet.module_cost_s), (3, 30.0));
        assert_eq!((landd.attempts, landd.landed, landd.module_cost_s, landd.module_runs), (1, 1, 10.0, 1));
    }

    #[test]
    fn red_and_conflicting_lanes_cost_what_the_model_says() {
        let burst = |outcome: &str| {
            [
                row(0.0, "t0", "landed", &[("t.z", 4.0)]),
                row(1.0, "good", "landed", &[("t.a", 10.0), ("t.shared", 3.0)]),
                row(2.0, "other", outcome, &[("t.shared", 3.0), ("t.own", 6.0)]),
            ]
        };
        let red = run(&burst("refused:tests"), &config());
        // Second batch: t.a + t.shared + t.own once (19), a base run of the
        // culprit's costliest module (6), and t.shared again without it (3).
        let (_, landd, ..) = sides(&red);
        assert_eq!(landd.module_cost_s, 4.0 + 19.0 + 6.0 + 3.0);
        assert_eq!((landd.landed, landd.declined), (2, 1));

        let conflict = run(&burst("refused:compose"), &config());
        let (_, landd, ..) = sides(&conflict);
        assert_eq!(landd.module_cost_s, 4.0 + 13.0);
        assert_eq!((landd.landed, landd.declined), (2, 1));
    }

    /// Refusals that are not about the checks are not reds, and words the
    /// table does not know are reported, not guessed.
    #[test]
    fn tooth_only_check_failures_are_reds() {
        let rows = [
            row(0.0, "t1", "landed", &[("t.a", 1.0)]),
            row(10.0, "t2", "refused:held", &[]),
            row(20.0, "t3", "refused:lane", &[]),
            row(30.0, "t4", "refused:duplicate", &[]),
            row(40.0, "t5", "refused:infra", &[]),
            row(50.0, "t6", "refused:brand-new-word", &[]),
            row(60.0, "t7", "refused:tests", &[("t.a", 1.0)]),
        ];
        let report = run(&rows, &config());
        let o = &report.observed;
        assert_eq!(o.runs_by_class[&Class::Red], 1);
        assert_eq!(
            (o.runs_by_class[&Class::Held], o.runs_by_class[&Class::LaneRefused], o.runs_by_class[&Class::Infra]),
            (1, 1, 1)
        );
        assert_eq!(o.unclassified_outcomes["refused:brand-new-word"], 1);
        let (_, landd, ..) = sides(&report);
        // Two lanes reach the train: the one that landed and the red one.
        assert_eq!((landd.attempts, landd.landed, landd.declined), (2, 1, 1));
    }

    /// The real ledger shape: no module sets. The replay does not run, and
    /// says why; hub CPU is not turned into module cost.
    #[test]
    fn tooth_a_ledger_without_module_sets_gets_no_replay_and_no_invented_costs() {
        let real = |ts: f64, tip: &str, outcome: &str| {
            format!(
                "{{\"kind\":\"land\",\"ts\":{ts},\"apply\":true,\"tip\":\"{tip}\",\"head\":\"m{ts}\",\"outcome\":\"{outcome}\",\"count\":0,\"selected\":[],\"modules\":{{}},\"phases\":{{\"merge\":2.3,\"push\":389.7}},\"cpu_s\":14.23,\"wall_s\":395.2,\"pushed_ts\":{},\"refused_attempts\":[{{\"attempt\":1}}]}}",
                ts + 395.0
            )
        };
        let rows = [real(0.0, "t1", "landed"), real(500.0, "t2", "refused:tests"), real(900.0, "t2", "landed")];
        let ledger = parse_ledger(rows.join("\n").as_bytes());
        let timings = Timings::parse(
            br#"{"keeper_walls": {"tests.a": 2.0}, "push_counter": [{"modules": 192, "outcome": "fresh", "rung_s": 240.0}]}"#,
        )
        .unwrap();
        let report = simulate(&ledger, &ModuleCosts::observe(&ledger), Some(timings), &config());
        let Replay::Unavailable { reasons } = &report.replay else { panic!("a replay was invented: {:?}", report.replay) };
        assert!(reasons[0].contains("3 of the 3 runs"), "{reasons:?}");
        assert!(reasons.iter().any(|r| r.contains("hub `cpu_s` is not a substitute")));
        let o = &report.observed;
        assert_eq!((o.applied_runs, o.lanes, o.lanes_landed, o.inner_refused_attempts), (3, 2, 2, 3));
        assert_eq!((o.landed_push_phase_p50_s, o.landed_run_wall_p95_s, o.hub_cpu_total_s), (389.7, 395.2, 42.69));
        assert_eq!(o.lead_first_attempt_p95_s, 795.0);
        let markdown = report.to_markdown();
        assert!(
            markdown.contains("Not available from this ledger") && markdown.contains("| module runs those records count | 192 |"),
            "{markdown}"
        );
        assert!(!markdown.contains("Module cost saved"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["replay"]["replay"], "unavailable");
    }

    #[test]
    fn coalescing_window_and_batch_size_are_honoured() {
        let rows: Vec<String> =
            (0..5).map(|i| row(10.0 + i as f64 * 0.01, &format!("t{i}"), "landed", &[("t.a", 1.0)])).collect();
        let mut settings = config();
        settings.max_batch_size = 2;
        let report = run(&rows, &settings);
        let (_, landd, ..) = sides(&report);
        // t0 alone, then pairs: three batches for five lanes.
        assert_eq!((landd.batches, landd.landed, landd.module_runs), (3, 5, 3));

        // Dry runs and non-land rows are not arrivals.
        let quiet = [
            "{\"kind\":\"land\",\"ts\":1,\"apply\":false,\"outcome\":\"dry-run\",\"tip\":\"x\"}".to_owned(),
            "{\"kind\":\"revert\",\"ts\":2,\"apply\":true,\"outcome\":\"landed\"}".to_owned(),
        ];
        let empty = run(&quiet, &config());
        assert_eq!(empty.observed.applied_runs, 0);
        assert!(matches!(empty.replay, Replay::Unavailable { .. }));
    }

    #[test]
    fn reports_render_as_markdown_and_json() {
        let report = run(&[row(0.0, "t1", "landed", &[("t.a", 10.0)])], &config());
        let markdown = report.to_markdown();
        assert!(markdown.contains("| metric | fleet | landd |"));
        assert!(markdown.contains("| module cost (s) | 10.0 | 10.0 |"));
        assert!(markdown.contains("| hub CPU total (s) | 1.5 |"));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["replay"]["landd"]["landed"], 1);
        assert_eq!(json["observed"]["runs_by_class"]["landed"], 1);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 50.0), 2.0);
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0], 95.0), 4.0);
    }
}
