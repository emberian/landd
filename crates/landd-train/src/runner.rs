//! The out-of-process test runner.
//!
//! Each unit runs as a child process in a scratch export of the tree: no
//! `.git`, a cleared environment plus an explicit allowlist, its own process
//! group, and a hard timeout. The child reports through its exit code and,
//! optionally, a JSON result frame written to `$LANDD_RESULT_FILE`:
//!
//! ```json
//! {"status": "fail", "items": ["test_a", "test_b"]}
//! ```
//!
//! Nothing the child prints is interpreted. Signing keys never enter this
//! module: receipts are sealed by the supervisor that calls it.

use landd_core::git::GitRepo;
use landd_core::reasons::{Status, UnitId};
use landd_core::{LandConfig, Oid};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const TIMEOUT_ITEM: &str = "landd:timeout";
pub const SPAWN_ITEM: &str = "landd:spawn-failed";
const LOG_TAIL_BYTES: usize = 2048;

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Argv; `{unit}` and `{path}` are substituted.
    pub command: Vec<String>,
    pub env_allow: Vec<String>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub max_reruns_on_flake: u32,
    pub scratch: PathBuf,
}

impl RunnerConfig {
    pub fn from_config(config: &LandConfig) -> Self {
        Self {
            command: config.test_command.clone(),
            env_allow: config.env_allow.clone(),
            timeout: Duration::from_secs(config.test_timeout_s),
            concurrency: config.runner_concurrency,
            max_reruns_on_flake: config.max_reruns_on_flake,
            scratch: config.cache_dir.join("runs"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Pass,
    Fail { items: BTreeSet<String> },
    Timeout,
    SpawnFailed { detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitRun {
    pub unit: UnitId,
    pub outcome: RunOutcome,
    pub attempts: u32,
    /// Failed, then passed on a rerun.
    pub flaky: bool,
    pub wall_ms: u64,
    /// The end of the child's stderr, for a failing unit.
    pub log_tail: String,
}

impl UnitRun {
    pub fn status(&self) -> Status {
        match &self.outcome {
            RunOutcome::Pass => Status::Pass,
            RunOutcome::Fail { items } => Status::Fail(items.clone()),
            RunOutcome::Timeout => Status::Fail(BTreeSet::from([TIMEOUT_ITEM.to_owned()])),
            RunOutcome::SpawnFailed { .. } => Status::Fail(BTreeSet::from([SPAWN_ITEM.to_owned()])),
        }
    }

    /// Whether the outcome is a function of the tree alone, and so may be
    /// recorded forever. Flaky passes, timeouts and spawn failures are not.
    pub fn is_durable(&self) -> bool {
        !self.flaky && matches!(self.outcome, RunOutcome::Pass | RunOutcome::Fail { .. })
    }
}

#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum Frame {
    // Braces, not a unit variant: serde only rejects unknown keys on variants with fields.
    Pass {},
    Fail { items: Vec<String> },
}

#[derive(Debug, thiserror::Error)]
pub enum RunnerError {
    #[error("runner scratch {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("exporting the tree: {0}")]
    Export(#[from] landd_core::git::GitError),
}

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Clone)]
pub struct Runner {
    config: RunnerConfig,
}

impl Runner {
    pub fn new(config: RunnerConfig) -> Self {
        Self { config }
    }

    /// Run `units` (`(unit, path)`) against `tree`, at most `concurrency` at a
    /// time. Results come back in the order of `units`.
    pub fn run_units(&self, repo: &GitRepo, tree: &Oid, units: &[(UnitId, String)]) -> Result<Vec<UnitRun>, RunnerError> {
        if units.is_empty() {
            return Ok(Vec::new());
        }
        let name = format!("run-{}-{}", std::process::id(), RUN_COUNTER.fetch_add(1, Ordering::Relaxed));
        let scratch = Scratch(self.config.scratch.join(name));
        let (tree_dir, frames, home) = (scratch.0.join("tree"), scratch.0.join("frames"), scratch.0.join("home"));
        for dir in [&frames, &home] {
            std::fs::create_dir_all(dir).map_err(|source| RunnerError::Io { path: dir.clone(), source })?;
        }
        repo.export_tree(tree, &tree_dir)?;

        let next = AtomicUsize::new(0);
        let results: Mutex<Vec<Option<UnitRun>>> = Mutex::new(vec![None; units.len()]);
        std::thread::scope(|scope| {
            for _ in 0..self.config.concurrency.clamp(1, units.len()) {
                scope.spawn(|| loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some((unit, path)) = units.get(index) else { break };
                    let run = self.run_one(index, unit, path, &tree_dir, &frames, &home);
                    results.lock().expect("results lock")[index] = Some(run);
                });
            }
        });
        let results = results.into_inner().expect("results lock");
        Ok(results.into_iter().map(|run| run.expect("every unit ran")).collect())
    }

    fn run_one(&self, index: usize, unit: &str, path: &str, tree: &Path, frames: &Path, home: &Path) -> UnitRun {
        let started = Instant::now();
        let mut attempts = 0;
        loop {
            let frame = frames.join(format!("{index}-{attempts}.json"));
            let log = frames.join(format!("{index}-{attempts}.log"));
            let outcome = self.attempt(unit, path, tree, &frame, &log, home);
            attempts += 1;
            let passed = outcome == RunOutcome::Pass;
            if passed || attempts > self.config.max_reruns_on_flake {
                let log_tail = if passed { String::new() } else { tail(&log) };
                let wall_ms = started.elapsed().as_millis() as u64;
                return UnitRun { unit: unit.to_owned(), outcome, attempts, flaky: passed && attempts > 1, wall_ms, log_tail };
            }
        }
    }

    fn attempt(&self, unit: &str, path: &str, tree: &Path, frame: &Path, log: &Path, home: &Path) -> RunOutcome {
        let argv: Vec<String> =
            self.config.command.iter().map(|arg| arg.replace("{unit}", unit).replace("{path}", path)).collect();
        let stderr = match std::fs::File::create(log) {
            Ok(file) => Stdio::from(file),
            Err(_) => Stdio::null(),
        };
        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]).current_dir(tree).env_clear();
        for name in &self.config.env_allow {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
            .env("HOME", home)
            .env("LANDD_UNIT", unit)
            .env("LANDD_RESULT_FILE", frame)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr)
            .process_group(0);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) => return RunOutcome::SpawnFailed { detail: format!("{}: {err}", argv[0]) },
        };
        let group = -(child.id() as libc::pid_t);
        // SAFETY: `kill` with a negative pid signals the process group this
        // child was just made the leader of; it touches no memory.
        let kill_group = || unsafe {
            libc::kill(group, libc::SIGKILL);
        };
        let deadline = Instant::now() + self.config.timeout;
        let mut nap = Duration::from_millis(1);
        let exit = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    kill_group();
                    let _ = child.wait();
                    return RunOutcome::Timeout;
                }
                Ok(None) => {
                    std::thread::sleep(nap);
                    nap = (nap * 2).min(Duration::from_millis(20));
                }
                Err(err) => {
                    kill_group();
                    return RunOutcome::SpawnFailed { detail: err.to_string() };
                }
            }
        };
        // Anything the unit left running in its group dies with it.
        kill_group();
        classify(unit, exit.success(), std::fs::read(frame).ok().as_deref())
    }
}

/// Exit code and frame must agree on a pass; any disagreement is a failure.
fn classify(unit: &str, exited_zero: bool, frame: Option<&[u8]>) -> RunOutcome {
    let whole_unit = || RunOutcome::Fail { items: BTreeSet::from([unit.to_owned()]) };
    match frame.map(serde_json::from_slice::<Frame>) {
        None if exited_zero => RunOutcome::Pass,
        None => whole_unit(),
        Some(Ok(Frame::Pass {})) if exited_zero => RunOutcome::Pass,
        Some(Ok(Frame::Fail { items })) if !items.is_empty() => RunOutcome::Fail { items: items.into_iter().collect() },
        Some(Ok(_)) => whole_unit(),
        Some(Err(_)) => RunOutcome::Fail { items: BTreeSet::from([format!("{unit}: malformed result frame")]) },
    }
}

fn tail(log: &Path) -> String {
    let bytes = std::fs::read(log).unwrap_or_default();
    let start = bytes.len().saturating_sub(LOG_TAIL_BYTES);
    String::from_utf8_lossy(&bytes[start..]).trim().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use landd_core::git::testkit::Sandbox;

    fn runner(scratch: &Path, edit: impl FnOnce(&mut RunnerConfig)) -> Runner {
        let mut config = RunnerConfig {
            command: vec!["sh".into(), "{path}".into()],
            env_allow: vec!["PATH".into()],
            timeout: Duration::from_secs(20),
            concurrency: 4,
            max_reruns_on_flake: 0,
            scratch: scratch.join("runs"),
        };
        edit(&mut config);
        Runner::new(config)
    }

    fn units(names: &[&str]) -> Vec<(UnitId, String)> {
        names.iter().map(|n| (n.to_string(), format!("checks/{n}.sh"))).collect()
    }

    fn items(list: &[&str]) -> RunOutcome {
        RunOutcome::Fail { items: list.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn outcomes_come_from_exit_codes_and_result_frames() {
        let dir = tempfile::tempdir().unwrap();
        let files = [
            ("checks/pass.sh", "exit 0\n"),
            ("checks/fail.sh", "echo boom >&2\nexit 3\n"),
            ("checks/framed.sh", "echo '{\"status\":\"fail\",\"items\":[\"t2\",\"t1\"]}' > \"$LANDD_RESULT_FILE\"\nexit 1\n"),
            ("checks/liar.sh", "echo '{\"status\":\"fail\",\"items\":[\"t1\"]}' > \"$LANDD_RESULT_FILE\"\nexit 0\n"),
            ("checks/optimist.sh", "echo '{\"status\":\"pass\"}' > \"$LANDD_RESULT_FILE\"\nexit 1\n"),
            ("checks/garbled.sh", "echo 'PASSED 3 tests' > \"$LANDD_RESULT_FILE\"\nexit 0\n"),
            ("checks/named.sh", "[ \"$LANDD_UNIT\" = named ]\n"),
        ];
        let sandbox = Sandbox::new(dir.path(), &files);
        let repo = sandbox.repo();
        let tree = repo.tree_of("HEAD").unwrap();
        let names = ["pass", "fail", "framed", "liar", "optimist", "garbled", "named"];
        let runs = runner(dir.path(), |_| {}).run_units(&repo, &tree, &units(&names)).unwrap();
        let outcomes: Vec<RunOutcome> = runs.iter().map(|r| r.outcome.clone()).collect();
        assert_eq!(outcomes, vec![
            RunOutcome::Pass,
            items(&["fail"]),
            items(&["t1", "t2"]),
            items(&["t1"]),
            items(&["optimist"]),
            items(&["garbled: malformed result frame"]),
            RunOutcome::Pass,
        ]);
        assert_eq!(runs[1].log_tail, "boom");
        assert!(runs.iter().all(|r| r.attempts == 1 && r.is_durable()));
        // The scratch export is gone.
        assert_eq!(std::fs::read_dir(dir.path().join("runs")).unwrap().count(), 0);
    }

    #[test]
    fn tooth_children_see_no_git_dir_and_no_inherited_environment() {
        let dir = tempfile::tempdir().unwrap();
        let script = "[ ! -e .git ] || exit 10\n[ -z \"$LANDD_TEST_SIGNING_SECRET\" ] || exit 11\n\
                      [ -z \"$GIT_DIR\" ] || exit 12\n[ \"$LANDD_TEST_ALLOWED\" = yes ] || exit 13\n[ -f checks/iso.sh ] || exit 14\n";
        let sandbox = Sandbox::new(dir.path(), &[("checks/iso.sh", script), ("checks/leak.sh", "[ -z \"$LANDD_TEST_SIGNING_SECRET\" ]\n")]);
        let repo = sandbox.repo();
        let tree = repo.tree_of("HEAD").unwrap();
        std::env::set_var("LANDD_TEST_SIGNING_SECRET", "do-not-leak");
        std::env::set_var("LANDD_TEST_ALLOWED", "yes");

        let isolated = runner(dir.path(), |c| c.env_allow.push("LANDD_TEST_ALLOWED".into()));
        let runs = isolated.run_units(&repo, &tree, &units(&["iso"])).unwrap();
        assert_eq!(runs[0].outcome, RunOutcome::Pass);

        // The check has teeth: allowlisting the secret makes the same script fail.
        let leaky = runner(dir.path(), |c| c.env_allow.push("LANDD_TEST_SIGNING_SECRET".into()));
        let runs = leaky.run_units(&repo, &tree, &units(&["leak"])).unwrap();
        assert_eq!(runs[0].outcome, items(&["leak"]));
    }

    #[test]
    fn tooth_timeouts_kill_the_process_group_and_are_not_durable() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("survivor");
        let script = format!("(sleep 2; touch {}) &\nsleep 30\n", marker.display());
        let sandbox = Sandbox::new(dir.path(), &[("checks/slow.sh", script.as_str())]);
        let repo = sandbox.repo();
        let started = Instant::now();
        let runs = runner(dir.path(), |c| c.timeout = Duration::from_millis(300))
            .run_units(&repo, &repo.tree_of("HEAD").unwrap(), &units(&["slow"]))
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(runs[0].outcome, RunOutcome::Timeout);
        assert!(!runs[0].is_durable());
        assert_eq!(runs[0].status(), Status::Fail(BTreeSet::from([TIMEOUT_ITEM.to_owned()])));
        std::thread::sleep(Duration::from_millis(2500));
        assert!(!marker.exists(), "a grandchild outlived the timeout");
    }

    #[test]
    fn flakes_are_rerun_and_never_recorded_as_durable() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("second-time");
        let flaky = format!("[ -e {0} ] && exit 0\ntouch {0}\nexit 1\n", marker.display());
        let sandbox = Sandbox::new(dir.path(), &[("checks/flaky.sh", flaky.as_str()), ("checks/red.sh", "exit 1\n")]);
        let repo = sandbox.repo();
        let tree = repo.tree_of("HEAD").unwrap();
        let runs = runner(dir.path(), |c| c.max_reruns_on_flake = 2).run_units(&repo, &tree, &units(&["flaky", "red"])).unwrap();
        assert_eq!((runs[0].outcome.clone(), runs[0].attempts, runs[0].flaky), (RunOutcome::Pass, 2, true));
        assert!(!runs[0].is_durable());
        assert_eq!((runs[1].outcome.clone(), runs[1].attempts, runs[1].flaky), (items(&["red"]), 3, false));
        assert!(runs[1].is_durable());
    }

    #[test]
    fn tooth_frames_are_a_closed_schema() {
        let frame = |text: &str| classify("u", true, Some(text.as_bytes()));
        assert_eq!(frame(r#"{"status":"pass"}"#), RunOutcome::Pass);
        assert_eq!(frame(r#"{"status":"fail","items":["t"]}"#), items(&["t"]));
        // A pass that also lists failures, an unknown status, an unknown key.
        for bad in [r#"{"status":"pass","items":["t"]}"#, r#"{"status":"skipped"}"#, r#"{"status":"fail","items":["t"],"x":1}"#] {
            assert_eq!(frame(bad), items(&["u: malformed result frame"]), "{bad}");
        }
        // A failure frame with no items blames the whole unit.
        assert_eq!(frame(r#"{"status":"fail","items":[]}"#), items(&["u"]));
        assert_eq!(classify("u", false, None), items(&["u"]));
    }

    #[test]
    fn a_missing_program_is_a_spawn_failure() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("checks/x.sh", "exit 0\n")]);
        let repo = sandbox.repo();
        let runs = runner(dir.path(), |c| c.command = vec!["landd-no-such-program".into()])
            .run_units(&repo, &repo.tree_of("HEAD").unwrap(), &units(&["x"]))
            .unwrap();
        assert!(matches!(runs[0].outcome, RunOutcome::SpawnFailed { .. }));
        assert!(!runs[0].is_durable());
    }
}
