//! `land_runs.jsonl`: one JSON object per `fleet land` run.
//!
//! The reader takes the keys it models (`kind`, `ts`, `apply`, `outcome`,
//! `lane`, `base`, `head`, `changed`, `selected`, `modules`, `wall_s`,
//! `cpu_s`, `pushed_ts`) and ignores the rest. Lines that are not JSON
//! objects are counted, not guessed at.

use serde_json::Value;
use std::collections::BTreeMap;

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
    pub head: String,
    pub changed: Vec<String>,
    /// Test modules the run selected, with the seconds each took when the
    /// ledger says.
    pub modules: BTreeMap<String, Option<f64>>,
    pub wall_s: Option<f64>,
    pub cpu_s: Option<f64>,
    pub pushed_ts: Option<f64>,
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

pub fn parse_ledger(input: &str) -> Ledger {
    let mut ledger = Ledger::default();
    for (index, line) in input.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        ledger.lines += 1;
        let Ok(row @ Value::Object(_)) = serde_json::from_str::<Value>(line) else {
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
        ledger.runs.push(LandRun {
            row: index,
            ts,
            kind: row.get("kind").and_then(Value::as_str).unwrap_or("land").to_owned(),
            apply: row.get("apply").and_then(Value::as_bool).unwrap_or(false),
            outcome: text(&row, "outcome"),
            lane: text(&row, "lane"),
            base: text(&row, "base"),
            head: text(&row, "head"),
            changed: strings(&row, "changed"),
            modules,
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
    pub default_s: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum CostError {
    #[error("module costs: {0}")]
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
    pub fn observe(ledger: &Ledger, default_s: f64) -> Self {
        let mut seen: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        for run in &ledger.runs {
            for (module, cost) in &run.modules {
                if let Some(cost) = cost {
                    seen.entry(module.clone()).or_default().push(*cost);
                }
            }
        }
        let observed = seen.into_iter().map(|(module, mut costs)| (module, median(&mut costs))).collect();
        Self { table: BTreeMap::new(), observed, default_s }
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
    /// else the ledger median, else an even share of the run's CPU, else the
    /// default.
    pub fn cost(&self, run: &LandRun, module: &str) -> f64 {
        if let Some(cost) = self.table.get(module) {
            return *cost;
        }
        if let Some(Some(cost)) = run.modules.get(module) {
            return *cost;
        }
        if let Some(cost) = self.observed.get(module) {
            return *cost;
        }
        match run.cpu_s {
            Some(cpu) if !run.modules.is_empty() => cpu / run.modules.len() as f64,
            _ => self.default_s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEDGER: &str = r#"
{"v":1,"gen":3,"kind":"land","ts":100.5,"repo":"/r","apply":true,"lane":"lane/a","base":"b0","head":"h1","changed":["x.py"],"selected":["tests.t1","tests.t2"],"modules":{"tests.t1":2.0,"tests.t2":{"cpu_s":4.0,"count":7}},"phases":{},"outcome":"landed","wall_s":9.5,"cpu_s":6.2,"pushed_ts":109.0,"future_key":[1,2]}
not json at all
{"kind":"land","no_ts":true}
[1,2,3]
{"kind":"revert","ts":50,"outcome":"landed"}
{"kind":"land","ts":90,"apply":false,"outcome":"dry-run","selected":["tests.t1"]}
"#;

    #[test]
    fn rows_are_read_tolerantly_and_sorted_by_time() {
        let ledger = parse_ledger(LEDGER);
        assert_eq!((ledger.lines, ledger.malformed, ledger.runs.len()), (6, 3, 3));
        assert_eq!(ledger.runs.iter().map(|r| r.ts).collect::<Vec<_>>(), [50.0, 90.0, 100.5]);
        let run = &ledger.runs[2];
        assert_eq!((run.kind.as_str(), run.apply, run.outcome.as_str()), ("land", true, "landed"));
        assert_eq!((run.lane.as_str(), run.base.as_str(), run.head.as_str()), ("lane/a", "b0", "h1"));
        assert_eq!(run.changed, ["x.py"]);
        assert_eq!(run.modules["tests.t1"], Some(2.0));
        assert_eq!(run.modules["tests.t2"], Some(4.0));
        assert_eq!((run.wall_s, run.cpu_s, run.pushed_ts), (Some(9.5), Some(6.2), Some(109.0)));
        assert_eq!(ledger.runs[1].modules["tests.t1"], None);
        assert_eq!(ledger.runs[0].kind, "revert");
    }

    #[test]
    fn module_costs_prefer_table_then_row_then_ledger_then_share() {
        let ledger = parse_ledger(LEDGER);
        let landed = &ledger.runs[2];
        let dry = &ledger.runs[1];
        let costs = ModuleCosts::observe(&ledger, 30.0);
        assert_eq!(costs.cost(landed, "tests.t1"), 2.0);
        // The dry run did not measure t1; the ledger median answers.
        assert_eq!(costs.cost(dry, "tests.t1"), 2.0);
        // Never measured anywhere: an even share of the run's CPU, else the default.
        assert_eq!(costs.cost(landed, "tests.unknown"), 3.1);
        assert_eq!(costs.cost(dry, "tests.unknown"), 30.0);

        let tabled = costs.with_table(r#"{"modules": {"tests.t1": 11, "tests.t2": {"cpu_s": 13}}}"#).unwrap();
        assert_eq!((tabled.cost(landed, "tests.t1"), tabled.cost(landed, "tests.t2")), (11.0, 13.0));
        assert!(ModuleCosts::default().with_table("[1]").is_err());
        assert!(ModuleCosts::default().with_table("{").is_err());
    }
}
