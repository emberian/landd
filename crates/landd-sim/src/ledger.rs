//! `land_runs.jsonl`: one JSON object per `fleet land` run.
//!
//! The reader takes the keys it models (`kind`, `ts`, `apply`, `outcome`,
//! `lane`, `base`, `tip`, `head`, `changed`, `selected`, `modules`,
//! `phases`, `refused_attempts`, `wall_s`, `cpu_s`, `pushed_ts`) and ignores
//! the rest. Input is read as bytes, line by line: a line that is not UTF-8
//! or not a JSON object is counted, not guessed at, and does not stop the
//! read.
//!
//! Two things about real ledgers shape everything downstream:
//!
//! * `head` is the *merged* head and changes on every retry; a lane is
//!   identified by `tip`.
//! * `cpu_s` is the hub's CPU for the whole run, not the cost of the test
//!   modules; and a ledger may carry no per-run module set at all
//!   (`selected: []`, `modules: {}`).

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// What an `outcome` word means. The table is explicit: a word that is not
/// in it is [`Class::Unclassified`], never assumed to be a failure or a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Landed,
    /// The work reached main through another push.
    Carried,
    /// The push lost a race or its outcome was never read.
    LostPush,
    /// The checks found a new red.
    Red,
    /// The lane did not merge.
    Conflict,
    /// The lane was already being landed.
    Duplicate,
    /// The lane itself was refused (empty, malformed).
    LaneRefused,
    /// An operator hold.
    Held,
    /// The machinery failed: infrastructure, interruption, lease, daemon.
    Infra,
    DryRun,
    /// Nothing to do: already on main, or answered from a record.
    NoOp,
    Unclassified,
}

impl Class {
    pub fn of(outcome: &str) -> Self {
        match outcome {
            "landed" => Self::Landed,
            "carried" => Self::Carried,
            "refused:push" | "unknown:push" | "refused:requalify" => Self::LostPush,
            "refused:tests" | "refused:rung" => Self::Red,
            "refused:compose" | "refused:conflict" | "refused:merge" => Self::Conflict,
            "refused:duplicate" => Self::Duplicate,
            "refused:lane" => Self::LaneRefused,
            "refused:held" => Self::Held,
            "refused:infra" | "refused:interrupted" | "refused:lease" | "refused:fabd" | "refused:preflight" => Self::Infra,
            "dry-run" => Self::DryRun,
            "already-on-main" | "already" | "receipt" => Self::NoOp,
            _ => Self::Unclassified,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct LandRun {
    /// Position in the ledger (0-based line of the row).
    pub row: usize,
    pub ts: f64,
    pub kind: String,
    pub apply: bool,
    pub outcome: String,
    pub lane: String,
    pub base: String,
    /// The lane's own commit: what identifies it across retries.
    pub tip: String,
    /// The merged head of this attempt.
    pub head: String,
    pub changed: Vec<String>,
    /// Test modules the run selected, with the seconds each took when the
    /// ledger says. Empty when the ledger does not record selections.
    pub modules: BTreeMap<String, Option<f64>>,
    /// Seconds per phase of the run (`push` is the test-and-push phase).
    pub phases: BTreeMap<String, f64>,
    /// Refused inner attempts within this one run.
    pub refused_attempts: usize,
    pub wall_s: Option<f64>,
    /// Hub CPU of the whole run.
    pub cpu_s: Option<f64>,
    pub pushed_ts: Option<f64>,
}

impl LandRun {
    pub fn class(&self) -> Class {
        Class::of(&self.outcome)
    }

    /// What identifies the lane: its tip, else (older ledgers) nothing
    /// better than the row itself.
    pub fn lane_key(&self) -> String {
        if self.tip.is_empty() {
            format!("row:{}", self.row)
        } else {
            self.tip.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Ledger {
    pub runs: Vec<LandRun>,
    pub lines: usize,
    pub malformed: usize,
}

fn seconds(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64(),
        Value::Object(map) => ["cpu_s", "wall_s", "s", "seconds"].iter().find_map(|k| map.get(*k)?.as_f64()),
        _ => None,
    }
    .filter(|s| s.is_finite() && *s >= 0.0)
}

fn text(row: &Value, key: &str) -> String {
    row.get(key).and_then(Value::as_str).unwrap_or_default().to_owned()
}

fn strings(row: &Value, key: &str) -> Vec<String> {
    row.get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|i| i.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

pub fn parse_ledger(input: &[u8]) -> Ledger {
    let mut ledger = Ledger::default();
    for (index, line) in input.split(|b| *b == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        ledger.lines += 1;
        let Ok(row @ Value::Object(_)) = serde_json::from_slice::<Value>(line) else {
            ledger.malformed += 1;
            continue;
        };
        let Some(ts) = row.get("ts").and_then(Value::as_f64) else {
            ledger.malformed += 1;
            continue;
        };
        let mut modules: BTreeMap<String, Option<f64>> = strings(&row, "selected").into_iter().map(|m| (m, None)).collect();
        if let Some(Value::Object(measured)) = row.get("modules") {
            for (module, value) in measured {
                modules.insert(module.clone(), seconds(value));
            }
        }
        let phases = match row.get("phases") {
            Some(Value::Object(map)) => map.iter().filter_map(|(k, v)| Some((k.clone(), seconds(v)?))).collect(),
            _ => BTreeMap::new(),
        };
        ledger.runs.push(LandRun {
            row: index,
            ts,
            kind: row.get("kind").and_then(Value::as_str).unwrap_or("land").to_owned(),
            apply: row.get("apply").and_then(Value::as_bool).unwrap_or(false),
            outcome: text(&row, "outcome"),
            lane: text(&row, "lane"),
            base: text(&row, "base"),
            tip: text(&row, "tip"),
            head: text(&row, "head"),
            changed: strings(&row, "changed"),
            modules,
            phases,
            refused_attempts: row.get("refused_attempts").and_then(Value::as_array).map_or(0, Vec::len),
            wall_s: row.get("wall_s").and_then(seconds),
            cpu_s: row.get("cpu_s").and_then(seconds),
            pushed_ts: row.get("pushed_ts").and_then(Value::as_f64),
        });
    }
    ledger.runs.sort_by(|a, b| a.ts.total_cmp(&b.ts).then(a.row.cmp(&b.row)));
    ledger
}

/// Seconds per test module, from an optional table and from the ledger itself.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ModuleCosts {
    table: BTreeMap<String, f64>,
    observed: BTreeMap<String, f64>,
}

#[derive(Debug, thiserror::Error)]
pub enum CostError {
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("module costs must be a JSON object of module -> seconds")]
    Shape,
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    values[values.len() / 2]
}

impl ModuleCosts {
    /// Median of each module's measured seconds across the ledger.
    pub fn observe(ledger: &Ledger) -> Self {
        let mut seen: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        for run in &ledger.runs {
            for (module, cost) in &run.modules {
                if let Some(cost) = cost {
                    seen.entry(module.clone()).or_default().push(*cost);
                }
            }
        }
        let observed = seen.into_iter().map(|(module, mut costs)| (module, median(&mut costs))).collect();
        Self { table: BTreeMap::new(), observed }
    }

    /// Add a table: `{"mod": 1.5}`, `{"mod": {"cpu_s": 1.5}}`, or either
    /// under a top-level `"modules"` key. Table entries win over the ledger.
    pub fn with_table(mut self, json: &str) -> Result<Self, CostError> {
        let value: Value = serde_json::from_str(json)?;
        let table = match value.get("modules") {
            Some(inner) => inner,
            None => &value,
        };
        let Value::Object(entries) = table else { return Err(CostError::Shape) };
        for (module, cost) in entries {
            if let Some(cost) = seconds(cost) {
                self.table.insert(module.clone(), cost);
            }
        }
        Ok(self)
    }

    /// Cost of `module` in `run`: the table, else what this run measured,
    /// else the ledger median. `None` when nothing measured it: a cost is
    /// never made up, and hub CPU is never shared out among modules.
    pub fn cost(&self, run: &LandRun, module: &str) -> Option<f64> {
        self.table
            .get(module)
            .copied()
            .or_else(|| run.modules.get(module).copied().flatten())
            .or_else(|| self.observed.get(module).copied())
    }
}

/// Fleet's own timing tables, when a file of them is given: what the trunk
/// keeper measured per module, and what each push ran.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
pub struct Timings {
    /// Modules with a keeper wall time, and the sum of those times: the
    /// wall-seconds of one run of every module.
    pub keeper_modules: usize,
    pub keeper_suite_wall_s: f64,
    pub push_records: usize,
    /// Push records that say how many modules they ran.
    pub push_records_with_module_count: usize,
    /// The sum of those counts. A count, not a set: which modules is unknown.
    pub push_module_runs: u64,
    pub push_rung_wall_s: f64,
    pub push_outcomes: BTreeMap<String, usize>,
}

impl Timings {
    /// Parse `{"keeper_walls": {module: seconds}, "push_counter": [{modules: int|null, rung_s, outcome}]}`.
    pub fn parse(json: &[u8]) -> Result<Self, CostError> {
        let value: Value = serde_json::from_slice(json)?;
        let mut timings = Self::default();
        if let Some(Value::Object(walls)) = value.get("keeper_walls") {
            for wall in walls.values().filter_map(seconds) {
                timings.keeper_modules += 1;
                timings.keeper_suite_wall_s += wall;
            }
        }
        if let Some(Value::Array(pushes)) = value.get("push_counter") {
            for push in pushes {
                timings.push_records += 1;
                // `modules` is a count here. A map or a list would be a
                // different schema and is not reinterpreted.
                if let Some(count) = push.get("modules").and_then(Value::as_u64) {
                    timings.push_records_with_module_count += 1;
                    timings.push_module_runs += count;
                }
                timings.push_rung_wall_s += push.get("rung_s").and_then(seconds).unwrap_or(0.0);
                let outcome = push.get("outcome").and_then(Value::as_str).unwrap_or("").to_owned();
                *timings.push_outcomes.entry(outcome).or_insert(0) += 1;
            }
        }
        if timings.keeper_modules == 0 && timings.push_records == 0 {
            return Err(CostError::Shape);
        }
        Ok(timings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEDGER: &str = r#"
{"v":1,"gen":3,"kind":"land","ts":100.5,"repo":"/r","apply":true,"lane":"lane/a","base":"b0","tip":"t1","head":"h1","changed":["x.py"],"selected":["tests.t1","tests.t2"],"modules":{"tests.t1":2.0,"tests.t2":{"cpu_s":4.0,"count":7}},"phases":{"merge":0.5,"push":7.25},"refused_attempts":[{"attempt":1},{"attempt":2}],"outcome":"landed","wall_s":9.5,"cpu_s":6.2,"pushed_ts":109.0,"future_key":[1,2]}
not json at all
{"kind":"land","no_ts":true}
[1,2,3]
{"kind":"revert","ts":50,"outcome":"landed"}
{"kind":"land","ts":90,"apply":false,"outcome":"dry-run","selected":["tests.t1"]}
"#;

    #[test]
    fn rows_are_read_tolerantly_and_sorted_by_time() {
        let mut bytes = LEDGER.as_bytes().to_vec();
        // One line that is not even UTF-8 does not stop the read.
        bytes.extend_from_slice(b"{\"kind\":\"land\",\"ts\":1,\"lane\":\"caf\xe9\"}\n");
        let ledger = parse_ledger(&bytes);
        assert_eq!((ledger.lines, ledger.malformed, ledger.runs.len()), (7, 4, 3));
        assert_eq!(ledger.runs.iter().map(|r| r.ts).collect::<Vec<_>>(), [50.0, 90.0, 100.5]);
        let run = &ledger.runs[2];
        assert_eq!((run.kind.as_str(), run.apply, run.outcome.as_str()), ("land", true, "landed"));
        assert_eq!((run.lane.as_str(), run.base.as_str(), run.tip.as_str(), run.head.as_str()), ("lane/a", "b0", "t1", "h1"));
        assert_eq!(run.lane_key(), "t1");
        assert_eq!(run.changed, ["x.py"]);
        assert_eq!(run.modules["tests.t1"], Some(2.0));
        assert_eq!(run.modules["tests.t2"], Some(4.0));
        assert_eq!((run.phases["push"], run.refused_attempts), (7.25, 2));
        assert_eq!((run.wall_s, run.cpu_s, run.pushed_ts), (Some(9.5), Some(6.2), Some(109.0)));
        assert_eq!(ledger.runs[1].modules["tests.t1"], None);
        assert_eq!(ledger.runs[0].kind, "revert");
    }

    #[test]
    fn tooth_outcome_words_are_classified_by_an_explicit_table() {
        for (word, class) in [
            ("landed", Class::Landed),
            ("carried", Class::Carried),
            ("refused:push", Class::LostPush),
            ("unknown:push", Class::LostPush),
            ("refused:tests", Class::Red),
            ("refused:compose", Class::Conflict),
            ("refused:duplicate", Class::Duplicate),
            ("refused:lane", Class::LaneRefused),
            ("refused:held", Class::Held),
            ("refused:infra", Class::Infra),
            ("refused:interrupted", Class::Infra),
            ("dry-run", Class::DryRun),
            ("receipt", Class::NoOp),
            // Not every refusal is a red, and an unknown word is not guessed.
            ("refused:something-new", Class::Unclassified),
            ("", Class::Unclassified),
        ] {
            assert_eq!(Class::of(word), class, "{word}");
        }
    }

    #[test]
    fn tooth_module_costs_are_measured_or_absent_never_invented() {
        let ledger = parse_ledger(LEDGER.as_bytes());
        let landed = &ledger.runs[2];
        let dry = &ledger.runs[1];
        let costs = ModuleCosts::observe(&ledger);
        assert_eq!(costs.cost(landed, "tests.t1"), Some(2.0));
        // The dry run did not measure t1; the ledger median answers.
        assert_eq!(costs.cost(dry, "tests.t1"), Some(2.0));
        // Never measured anywhere: no cost. Hub CPU is not divided among modules.
        assert_eq!(costs.cost(landed, "tests.unknown"), None);

        let tabled = costs.with_table(r#"{"modules": {"tests.t1": 11, "tests.t2": {"cpu_s": 13}}}"#).unwrap();
        assert_eq!((tabled.cost(landed, "tests.t1"), tabled.cost(landed, "tests.t2")), (Some(11.0), Some(13.0)));
        assert!(ModuleCosts::default().with_table("[1]").is_err());
        assert!(ModuleCosts::default().with_table("{").is_err());
    }

    #[test]
    fn timings_read_module_counts_as_counts() {
        let json = br#"{"keeper_walls": {"tests.a": 1.5, "tests.b": 2.5}, "push_seconds": {"tests.a": {"s": 1}},
            "push_counter": [{"modules": 192, "outcome": "fresh", "rung_s": 240.5}, {"modules": null, "outcome": "reused", "rung_s": 0.5},
                             {"modules": {"tests.a": 1}, "outcome": "odd"}]}"#;
        let timings = Timings::parse(json).unwrap();
        assert_eq!((timings.keeper_modules, timings.keeper_suite_wall_s), (2, 4.0));
        assert_eq!((timings.push_records, timings.push_records_with_module_count, timings.push_module_runs), (3, 1, 192));
        assert_eq!(timings.push_rung_wall_s, 241.0);
        assert_eq!(timings.push_outcomes["reused"], 1);
        assert!(Timings::parse(b"{}").is_err());
    }
}
