//! The out-of-process test runner.
//!
//! Each unit runs as a child process against a private materialization of
//! the tree under test: exact blobs and git modes written from the object
//! store (no `git archive`, so no `.gitattributes` rewriting), no `.git`,
//! and, with [`UnitView::Cone`], only the files of the unit's cone.
//!
//! With [`Isolation::Bwrap`] the child lives in a sandbox: its own user,
//! mount, pid, ipc and uts namespaces (and network namespace unless
//! configured otherwise), a root made of read-only system directories, the
//! unit's view under a throw-away overlay, a private `/tmp` and home, and
//! one writable directory for its result frame. The supervisor's state
//! directory, key file, other units' files and the host's process table do
//! not exist in there. With [`Isolation::None`] the child is an ordinary
//! process of the supervisor's user: it gets a private copy of its view, a
//! cleared environment and a git ceiling, and nothing stops it from reading
//! anything that user can read. That mode is for trusted code only, and the
//! configuration refuses to sign receipts in it.
//!
//! The child reports through its exit code and, optionally, a JSON result
//! frame written to `$LANDD_RESULT_FILE`:
//!
//! ```json
//! {"status": "fail", "items": ["test_a", "test_b"]}
//! ```
//!
//! Nothing the child prints is interpreted. The frame is read through a
//! descriptor opened without following links and without blocking, must be a
//! regular file, and is bounded in size.

use landd_core::git::{EntryKind, GitError, GitRepo, TreeEntry};
use landd_core::reasons::{Status, UnitId};
use landd_core::{Digest32, Isolation, LandConfig, Oid, UnitView};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const LOG_TAIL_BYTES: usize = 2048;
/// A result frame larger than this is not a result frame.
const MAX_FRAME_BYTES: u64 = 1 << 20;
const MODE_SYMLINK: u32 = 0o120000;
const MODE_EXECUTABLE: u32 = 0o100755;

#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Argv; `{unit}` and `{path}` are substituted.
    pub command: Vec<String>,
    pub env_allow: Vec<String>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub max_reruns_on_flake: u32,
    /// Where per-run trees are materialized. Never inside the state
    /// directory or a repository.
    pub scratch: PathBuf,
    pub isolation: Isolation,
    pub unit_view: UnitView,
    pub sandbox_ro: Vec<String>,
    pub sandbox_network: bool,
    pub profile_commands: Vec<Vec<String>>,
    /// The sandbox program: a name on `PATH`, or a path.
    pub bwrap_program: String,
    pub runtime_id: String,
    /// Paths no unit may be able to read: the signing key, the state
    /// directory. A sandbox whose read-only mounts would show one of them
    /// does not start.
    pub secrets: Vec<PathBuf>,
}

impl RunnerConfig {
    pub fn from_config(config: &LandConfig) -> Self {
        // SAFETY: `geteuid` reads the process's effective uid and cannot fail.
        let uid = unsafe { libc::geteuid() };
        Self {
            command: config.test_command.clone(),
            env_allow: config.env_allow.clone(),
            timeout: Duration::from_secs(config.test_timeout_s),
            concurrency: config.runner_concurrency,
            max_reruns_on_flake: config.max_reruns_on_flake,
            scratch: std::env::temp_dir().join(format!("landd-runs-{uid}")),
            isolation: config.isolation,
            unit_view: config.unit_view,
            sandbox_ro: config.sandbox_ro.clone(),
            sandbox_network: config.sandbox_network,
            profile_commands: config.profile_commands.clone(),
            bwrap_program: "bwrap".into(),
            runtime_id: config.runtime_id.clone(),
            secrets: config.custody_key.iter().cloned().chain(config.state_dir().ok()).collect(),
        }
    }
}

/// One unit to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitJob {
    pub unit: UnitId,
    /// The path handed to the test command.
    pub path: String,
    /// The files the unit may see; `None` for the whole tree.
    pub inputs: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Pass,
    /// The unit named what failed.
    Fail {
        items: BTreeSet<String>,
    },
    /// The unit failed without a usable result frame.
    Crash,
    Timeout,
    SpawnFailed {
        detail: String,
    },
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
            RunOutcome::Fail { items } => Status::Fail { items: items.clone() },
            RunOutcome::Crash | RunOutcome::SpawnFailed { .. } => Status::Crash,
            RunOutcome::Timeout => Status::Timeout,
        }
    }

    /// Whether the outcome is a function of the unit's view and the runner
    /// profile alone, and so may be recorded forever. Flaky passes, timeouts
    /// and spawn failures are not.
    pub fn is_durable(&self) -> bool {
        !self.flaky && matches!(self.outcome, RunOutcome::Pass | RunOutcome::Fail { .. } | RunOutcome::Crash)
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
    #[error("materializing the tree: {0}")]
    Git(#[from] GitError),
    #[error("tree path {0:?} cannot be materialized safely")]
    BadPath(String),
    #[error("runner profile: {0}")]
    Profile(String),
    #[error("{secret} would be visible to units through the sandbox mount {mount}; move it, or take {mount} out of sandbox_ro")]
    Exposed { secret: PathBuf, mount: PathBuf },
    #[error(
        "isolation = \"bwrap\" but bwrap cannot be run ({0}); install bubblewrap, or set isolation = \"none\" for trusted code"
    )]
    NoSandbox(String),
}

fn io_at(path: &Path) -> impl Fn(std::io::Error) -> RunnerError + '_ {
    move |source| RunnerError::Io { path: path.to_owned(), source }
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        // Overlay work may have left unreadable directories behind.
        let _ = Command::new("chmod").arg("-R").arg("u+rwx").arg(&self.0).stdout(Stdio::null()).stderr(Stdio::null()).status();
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What produces a verdict besides the tree: part of every verdict's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerProfile {
    pub digest: Digest32,
    /// The profile in full, for receipts and reports.
    pub description: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct Runner {
    config: RunnerConfig,
    /// Absolute path of `bwrap`, when sandboxing.
    bwrap: Option<PathBuf>,
    profile: RunnerProfile,
    /// The exact allowlisted environment hashed into `profile`.
    env: BTreeMap<String, String>,
}

/// The executable a bare program name resolves to on `path`.
fn which(program: &str, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    if program.contains('/') {
        return Path::new(program).is_file().then(|| PathBuf::from(program));
    }
    std::env::split_paths(path?)
        .map(|dir| dir.join(program))
        .find(|candidate| std::fs::metadata(candidate).is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0))
}

/// Kills a process-group leader's group and reaps the leader on drop unless
/// `wait_deadline` already did so.
struct GroupGuard(Option<Child>);

impl GroupGuard {
    fn wait_deadline(mut self, deadline: Instant) -> Option<ExitStatus> {
        let mut child = self.0.take()?;
        wait_deadline(&mut child, deadline)
    }
}

impl Drop for GroupGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let pid = child.id() as libc::pid_t;
            // SAFETY: signals the process group the un-reaped child leads.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            let _ = child.wait();
        }
    }
}

/// Run a short command and return its output, or `None` past the deadline.
fn probe(argv: &[String], env: &BTreeMap<String, String>) -> Option<(Option<i32>, Vec<u8>)> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .ok()?;
    let (out, err) = (child.stdout.take(), child.stderr.take());
    let guard = GroupGuard(Some(child));
    let (mut out, mut err) = (out?, err?);
    let merged = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = (&mut out).take(1 << 16).read_to_end(&mut bytes);
        let _ = (&mut err).take(1 << 16).read_to_end(&mut bytes);
        bytes
    });
    let status = guard.wait_deadline(Instant::now() + Duration::from_secs(30))?;
    Some((status.code(), merged.join().unwrap_or_default()))
}

use landd_core::fsx::canonical_or_missing;

impl Runner {
    /// Build a runner, checking up front that it can do what its
    /// configuration promises: the test program exists, and when the
    /// configuration asks for a sandbox, a sandbox actually starts.
    pub fn new(config: RunnerConfig) -> Result<Self, RunnerError> {
        let env: BTreeMap<String, String> =
            config.env_allow.iter().filter_map(|name| Some((name.clone(), std::env::var(name).ok()?))).collect();
        let search = env.get("PATH").map(std::ffi::OsString::from).or_else(|| std::env::var_os("PATH"));
        let program = which(&config.command[0], search.as_deref())
            .ok_or_else(|| RunnerError::Profile(format!("test program {:?} was not found", config.command[0])))?;
        let program_bytes = std::fs::read(&program).map_err(io_at(&program))?;

        let mut bwrap = None;
        let mut sandbox = serde_json::json!({"isolation": "none"});
        if config.isolation == Isolation::Bwrap {
            let path = which(&config.bwrap_program, std::env::var_os("PATH").as_deref())
                .ok_or_else(|| RunnerError::NoSandbox(format!("{:?} is not on PATH", config.bwrap_program)))?;
            let version = probe(&[path.display().to_string(), "--version".into()], &BTreeMap::new())
                .filter(|(code, _)| *code == Some(0))
                .map(|(_, out)| String::from_utf8_lossy(&out).trim().to_owned())
                .ok_or_else(|| RunnerError::NoSandbox("bwrap --version failed".into()))?;
            // Whatever is mounted into the sandbox is readable there. A key
            // or state directory below a mounted directory would be too.
            for mount in config.sandbox_ro.iter().filter_map(|dir| std::fs::canonicalize(dir).ok()) {
                for secret in &config.secrets {
                    let real = canonical_or_missing(secret).map_err(io_at(secret))?;
                    if real.starts_with(&mount) {
                        return Err(RunnerError::Exposed { secret: secret.clone(), mount });
                    }
                }
            }
            sandbox = serde_json::json!({
                "isolation": "bwrap", "bwrap": version, "ro": config.sandbox_ro, "network": config.sandbox_network,
            });
            bwrap = Some(path);
        }
        let mut probes = Vec::new();
        for argv in &config.profile_commands {
            let (code, output) =
                probe(argv, &env).ok_or_else(|| RunnerError::Profile(format!("profile command {argv:?} did not run")))?;
            probes.push(serde_json::json!({"argv": argv, "exit": code, "output": Digest32::blake3(&output)}));
        }
        let view = match config.unit_view {
            UnitView::Cone => "cone",
            UnitView::Tree => "tree",
        };
        let description = serde_json::json!({
            "argv": config.command,
            "env": env,
            "program": {"path": program.display().to_string(), "blake3": Digest32::blake3(&program_bytes)},
            "sandbox": sandbox,
            "unit_view": view,
            "runtime_id": config.runtime_id,
            "probes": probes,
            "landd": env!("CARGO_PKG_VERSION"),
            "runner": Digest32::blake3(include_bytes!("runner.rs")),
        });
        let canonical = landd_core::canonical_json(&description).map_err(|e| RunnerError::Profile(e.to_string()))?;
        let profile = RunnerProfile { digest: Digest32::tagged("landd runner profile v1", &[&canonical]), description };
        let runner = Self { config, bwrap, profile, env };
        if runner.bwrap.is_some() {
            runner.check_sandbox()?;
        }
        Ok(runner)
    }

    pub fn profile(&self) -> &RunnerProfile {
        &self.profile
    }

    pub fn isolation(&self) -> Isolation {
        self.config.isolation
    }

    pub fn unit_view(&self) -> UnitView {
        self.config.unit_view
    }

    fn scratch(&self) -> Result<Scratch, RunnerError> {
        landd_core::fsx::private_dir(&self.config.scratch).map_err(io_at(&self.config.scratch))?;
        for _ in 0..8 {
            let unique = Digest32::blake3(format!("{:?}{:?}", Instant::now(), std::thread::current().id()).as_bytes());
            let dir = self.config.scratch.join(format!("run-{}-{}", std::process::id(), &unique.to_hex()[..12]));
            // `create`, not `create_all`: a directory that exists is someone else's.
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => return Ok(Scratch(dir)),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(io_at(&dir)(err)),
            }
        }
        Err(RunnerError::Io { path: self.config.scratch.clone(), source: std::io::ErrorKind::AlreadyExists.into() })
    }

    /// Start the sandbox once on an empty view: a configuration that asks
    /// for isolation must fail here, not degrade later.
    fn check_sandbox(&self) -> Result<(), RunnerError> {
        let scratch = self.scratch()?;
        let (view, out) = (scratch.0.join("view"), scratch.0.join("out"));
        for dir in [&view, &out] {
            std::fs::create_dir(dir).map_err(io_at(dir))?;
        }
        let mut command =
            self.sandboxed(&view, &out, &["/bin/sh".into(), "-c".into(), "test ! -e /landd-out/x".into()], "probe", "probe");
        let status = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| RunnerError::NoSandbox(e.to_string()))?;
        if !status.status.success() {
            return Err(RunnerError::NoSandbox(String::from_utf8_lossy(&status.stderr).trim().to_owned()));
        }
        Ok(())
    }

    /// The environment a unit sees, besides what the allowlist passes on.
    fn unit_env(&self, unit: &str, home: &str, tmp: &str, frame: &str) -> Vec<(String, String)> {
        let mut env: Vec<(String, String)> = self.env.iter().map(|(name, value)| (name.clone(), value.clone())).collect();
        for (name, value) in [
            ("HOME", home),
            ("TMPDIR", tmp),
            ("LANDD_UNIT", unit),
            ("LANDD_RESULT_FILE", frame),
            // No ambient git configuration, and no repository above the view.
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("PYTHONDONTWRITEBYTECODE", "1"),
        ] {
            env.push((name.to_owned(), value.to_owned()));
        }
        env
    }

    fn sandboxed(&self, view: &Path, out: &Path, argv: &[String], unit: &str, _path: &str) -> Command {
        let mut command = Command::new(self.bwrap.as_ref().expect("sandboxed runs have bwrap"));
        command.env_clear();
        command.args(["--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup-try"]);
        if !self.config.sandbox_network {
            command.arg("--unshare-net");
        }
        command.args(["--die-with-parent", "--new-session", "--clearenv"]);
        for dir in &self.config.sandbox_ro {
            let path = Path::new(dir);
            match std::fs::read_link(path) {
                // `/bin -> usr/bin` on merged-usr systems: keep it a link.
                Ok(target) => {
                    command.arg("--symlink").arg(target).arg(path);
                }
                Err(_) if path.exists() => {
                    command.arg("--ro-bind").arg(path).arg(path);
                }
                Err(_) => {}
            }
        }
        command.args(["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home", "--dir", "/home/unit"]);
        // The view is the lower layer of a throw-away overlay: the unit may
        // write anywhere in its tree and nothing outlives the process.
        command.arg("--overlay-src").arg(view).args(["--tmp-overlay", "/work"]);
        command.arg("--bind").arg(out).arg("/landd-out").args(["--chdir", "/work"]);
        for (name, value) in self.unit_env(unit, "/home/unit", "/tmp", "/landd-out/result.json") {
            command.arg("--setenv").arg(name).arg(value);
        }
        command.arg("--").args(argv);
        command
    }

    /// Run `jobs` against `tree`, at most `concurrency` at a time. Results
    /// come back in the order of `jobs`.
    pub fn run_units(&self, repo: &GitRepo, tree: &Oid, jobs: &[UnitJob]) -> Result<Vec<UnitRun>, RunnerError> {
        if jobs.is_empty() {
            return Ok(Vec::new());
        }
        let scratch = self.scratch()?;
        let store = scratch.0.join("store");
        // With cone views only the files some unit may see are written at all.
        let wanted: Option<BTreeSet<&str>> = match self.config.unit_view {
            UnitView::Cone => jobs
                .iter()
                .map(|job| job.inputs.as_ref())
                .collect::<Option<Vec<_>>>()
                .map(|lists| lists.into_iter().flatten().map(String::as_str).collect()),
            UnitView::Tree => None,
        };
        let entries = materialize(repo, tree, &store, wanted.as_ref(), self.config.concurrency)?;
        let by_path: BTreeMap<&str, &TreeEntry> = entries.iter().map(|entry| (entry.path.as_str(), entry)).collect();

        let next = AtomicUsize::new(0);
        let results: Mutex<Vec<Option<Result<UnitRun, RunnerError>>>> = Mutex::new((0..jobs.len()).map(|_| None).collect());
        std::thread::scope(|scope| {
            for _ in 0..self.config.concurrency.clamp(1, jobs.len()) {
                scope.spawn(|| loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(job) = jobs.get(index) else { break };
                    let run = self.run_one(index, job, &scratch.0, &store, &by_path);
                    results.lock().expect("results lock")[index] = Some(run);
                });
            }
        });
        let results = results.into_inner().expect("results lock");
        results.into_iter().map(|run| run.expect("every unit ran")).collect()
    }

    fn run_one(
        &self,
        index: usize,
        job: &UnitJob,
        scratch: &Path,
        store: &Path,
        entries: &BTreeMap<&str, &TreeEntry>,
    ) -> Result<UnitRun, RunnerError> {
        let started = Instant::now();
        let mut attempts = 0;
        loop {
            // Every attempt starts from a pristine view and an empty result directory.
            let unit_dir = scratch.join(format!("u{index}-{attempts}"));
            let (view, out) = (unit_dir.join("view"), unit_dir.join("out"));
            for dir in [&unit_dir, &out] {
                std::fs::DirBuilder::new().mode(0o700).create(dir).map_err(io_at(dir))?;
            }
            let sandboxed = self.bwrap.is_some();
            let cone = job.inputs.as_ref().filter(|_| self.config.unit_view == UnitView::Cone);
            // A sandboxed whole-tree unit reads the shared store through its
            // own overlay; everything else gets a view of its own.
            let lower = match (cone, sandboxed) {
                (None, true) => store.to_owned(),
                (inputs, _) => {
                    build_view(store, &view, entries, inputs.map(Vec::as_slice), !sandboxed)?;
                    view
                }
            };
            let (outcome, log_tail) = self.attempt(job, &lower, &unit_dir, &out);
            attempts += 1;
            let passed = outcome == RunOutcome::Pass;
            if passed || attempts > self.config.max_reruns_on_flake {
                return Ok(UnitRun {
                    unit: job.unit.clone(),
                    outcome,
                    attempts,
                    flaky: passed && attempts > 1,
                    wall_ms: started.elapsed().as_millis() as u64,
                    log_tail: if passed { String::new() } else { log_tail },
                });
            }
        }
    }

    fn attempt(&self, job: &UnitJob, view: &Path, unit_dir: &Path, out: &Path) -> (RunOutcome, String) {
        let argv: Vec<String> =
            self.config.command.iter().map(|arg| arg.replace("{unit}", &job.unit).replace("{path}", &job.path)).collect();
        let frame = out.join("result.json");
        let mut command = match self.bwrap {
            Some(_) => self.sandboxed(view, out, &argv, &job.unit, &job.path),
            None => {
                let (home, tmp) = (unit_dir.join("home"), unit_dir.join("tmp"));
                for dir in [&home, &tmp] {
                    if let Err(err) = std::fs::DirBuilder::new().mode(0o700).create(dir) {
                        return (RunOutcome::SpawnFailed { detail: format!("{}: {err}", dir.display()) }, String::new());
                    }
                }
                let mut command = Command::new(&argv[0]);
                command.args(&argv[1..]).current_dir(view).env_clear();
                command.envs(self.unit_env(&job.unit, &home.to_string_lossy(), &tmp.to_string_lossy(), &frame.to_string_lossy()));
                // Git must not find a repository above the view.
                command.env("GIT_CEILING_DIRECTORIES", &self.config.scratch);
                command
            }
        };
        command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).process_group(0);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) => return (RunOutcome::SpawnFailed { detail: format!("{}: {err}", argv[0]) }, String::new()),
        };
        // Only the end of stderr is kept; the rest is read and dropped, so a
        // unit cannot fill a disk or stall on a full pipe.
        let mut stderr = child.stderr.take().expect("piped stderr");
        let guard = GroupGuard(Some(child));
        let tail = std::thread::spawn(move || {
            let mut kept: Vec<u8> = Vec::new();
            let mut buffer = [0u8; 8192];
            while let Ok(read @ 1..) = stderr.read(&mut buffer) {
                kept.extend_from_slice(&buffer[..read]);
                if kept.len() > 4 * LOG_TAIL_BYTES {
                    kept.drain(..kept.len() - LOG_TAIL_BYTES);
                }
            }
            let start = kept.len().saturating_sub(LOG_TAIL_BYTES);
            String::from_utf8_lossy(&kept[start..]).trim().to_owned()
        });
        let exit = guard.wait_deadline(Instant::now() + self.config.timeout);
        // The group is dead, so every write end of the pipe is closed.
        let log_tail = tail.join().unwrap_or_default();
        let outcome = match exit {
            None => RunOutcome::Timeout,
            Some(status) => classify(status.success(), read_frame(&frame)),
        };
        (outcome, log_tail)
    }
}

/// Wait for `child` until `deadline`, then kill its whole process group and
/// reap it. On a normal exit the group is killed before the child is
/// reaped, while its pid still cannot be reused.
fn wait_deadline(child: &mut Child, deadline: Instant) -> Option<ExitStatus> {
    let pid = child.id() as libc::pid_t;
    let mut nap = Duration::from_millis(1);
    let exited = loop {
        // SAFETY: `waitid` fills a zeroed `siginfo_t` for a child of this
        // process; `WNOWAIT` leaves the child reapable by `Child::wait`.
        let done = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let rc = libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT);
            rc != 0 || info.si_pid() != 0
        };
        if done {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(nap);
        nap = (nap * 2).min(Duration::from_millis(20));
    };
    // SAFETY: signals the process group the child leads; no memory is touched.
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    let status = child.wait().ok();
    if exited {
        status
    } else {
        None
    }
}

/// The result frame, if the unit left a regular file of sane size. The
/// path is the unit's to control: it may be a link, a FIFO or a device.
fn read_frame(path: &Path) -> Option<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_FRAME_BYTES {
        // Present but not a frame: a malformed frame, not an absent one.
        return Some(Vec::new());
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_FRAME_BYTES + 1).read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// Exit code and frame must agree on a pass; any disagreement is a failure.
fn classify(exited_zero: bool, frame: Option<Vec<u8>>) -> RunOutcome {
    match frame.as_deref().map(serde_json::from_slice::<Frame>) {
        None if exited_zero => RunOutcome::Pass,
        Some(Ok(Frame::Pass {})) if exited_zero => RunOutcome::Pass,
        Some(Ok(Frame::Fail { items })) if !items.is_empty() => RunOutcome::Fail { items: items.into_iter().collect() },
        // A non-zero exit with no frame, a frame that contradicts the exit
        // code, a failure that names nothing, a frame that does not parse.
        _ => RunOutcome::Crash,
    }
}

/// A tree path that stays inside the directory it is joined to.
fn safe_relative(path: &str) -> bool {
    !path.is_empty() && !path.starts_with('/') && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

/// Write the entries of `tree` (all of them, or only `wanted`) under `dest`,
/// which must not exist: exact blob bytes, executable bit, symbolic links as
/// links, gitlinks as empty directories. Returns the tree's entries.
fn materialize(
    repo: &GitRepo,
    tree: &Oid,
    dest: &Path,
    wanted: Option<&BTreeSet<&str>>,
    threads: usize,
) -> Result<Vec<TreeEntry>, RunnerError> {
    std::fs::DirBuilder::new().mode(0o700).create(dest).map_err(io_at(dest))?;
    let entries = repo.ls_tree(&tree.to_hex(), false)?;
    if let Some(bad) = entries.iter().find(|entry| !safe_relative(&entry.path)) {
        return Err(RunnerError::BadPath(bad.path.clone()));
    }
    let chosen: Vec<&TreeEntry> =
        entries.iter().filter(|entry| wanted.is_none_or(|set| set.contains(entry.path.as_str()))).collect();
    let mut dirs: BTreeSet<&Path> = BTreeSet::new();
    for entry in &chosen {
        if let Some(parent) = Path::new(&entry.path).parent().filter(|p| !p.as_os_str().is_empty()) {
            dirs.insert(parent);
        }
    }
    for dir in dirs {
        std::fs::create_dir_all(dest.join(dir)).map_err(io_at(dest))?;
    }
    let chunk = chosen.len().div_ceil(threads.clamp(1, 8)).max(1);
    let written: Vec<Result<(), RunnerError>> = std::thread::scope(|scope| {
        let workers: Vec<_> = chosen
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || -> Result<(), RunnerError> {
                    let mut reader = repo.blob_reader()?;
                    for entry in part {
                        let target = dest.join(&entry.path);
                        match (entry.kind, entry.mode) {
                            (EntryKind::Commit, _) => std::fs::create_dir_all(&target).map_err(io_at(&target))?,
                            (_, MODE_SYMLINK) => {
                                use std::os::unix::ffi::OsStrExt;
                                let link = reader.read_limited(&entry.oid, None)?;
                                std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(&link), &target)
                                    .map_err(io_at(&target))?;
                            }
                            (_, mode) => {
                                let bytes = reader.read_limited(&entry.oid, None)?;
                                let mut options = std::fs::OpenOptions::new();
                                options.write(true).create_new(true).mode(if mode == MODE_EXECUTABLE { 0o755 } else { 0o644 });
                                std::io::Write::write_all(&mut options.open(&target).map_err(io_at(&target))?, &bytes)
                                    .map_err(io_at(&target))?;
                            }
                        }
                    }
                    Ok(())
                })
            })
            .collect();
        workers.into_iter().map(|worker| worker.join().expect("materialize worker")).collect()
    });
    written.into_iter().collect::<Result<Vec<()>, _>>()?;
    Ok(entries)
}

/// Build one unit's view of the store: every input (or every entry) at its
/// path. Links to the store's files when the view will be mounted
/// read-only under an overlay; copies when the unit can write to it.
fn build_view(
    store: &Path,
    view: &Path,
    entries: &BTreeMap<&str, &TreeEntry>,
    inputs: Option<&[String]>,
    copy: bool,
) -> Result<(), RunnerError> {
    std::fs::DirBuilder::new().mode(0o700).create(view).map_err(io_at(view))?;
    let all: Vec<&str>;
    let paths: Vec<&str> = match inputs {
        Some(inputs) => inputs.iter().map(String::as_str).collect(),
        None => {
            all = entries.keys().copied().collect();
            all
        }
    };
    for path in paths {
        // An input the tree does not hold (a cone built for another tree) is skipped.
        let Some(entry) = entries.get(path) else { continue };
        let (from, to) = (store.join(path), view.join(path));
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).map_err(io_at(parent))?;
        }
        match (entry.kind, entry.mode, copy) {
            (EntryKind::Commit, ..) => std::fs::create_dir_all(&to).map_err(io_at(&to))?,
            (_, MODE_SYMLINK, _) => {
                let target = std::fs::read_link(&from).map_err(io_at(&from))?;
                std::os::unix::fs::symlink(target, &to).map_err(io_at(&to))?;
            }
            (_, _, true) => {
                std::fs::copy(&from, &to).map_err(io_at(&to))?;
            }
            (_, _, false) => std::fs::hard_link(&from, &to).map_err(io_at(&to))?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use landd_core::git::testkit::Sandbox;

    fn config(scratch: &Path, isolation: Isolation, edit: impl FnOnce(&mut RunnerConfig)) -> RunnerConfig {
        let mut config = RunnerConfig {
            command: vec!["sh".into(), "{path}".into()],
            env_allow: vec!["PATH".into()],
            timeout: Duration::from_secs(20),
            concurrency: 4,
            max_reruns_on_flake: 0,
            scratch: scratch.join("runs"),
            isolation,
            unit_view: UnitView::Tree,
            sandbox_ro: LandConfig::default().sandbox_ro,
            sandbox_network: false,
            profile_commands: Vec::new(),
            bwrap_program: "bwrap".into(),
            runtime_id: String::new(),
            secrets: Vec::new(),
        };
        edit(&mut config);
        config
    }

    fn runner(scratch: &Path, isolation: Isolation, edit: impl FnOnce(&mut RunnerConfig)) -> Runner {
        Runner::new(config(scratch, isolation, edit)).unwrap()
    }

    fn jobs(names: &[&str]) -> Vec<UnitJob> {
        names.iter().map(|n| UnitJob { unit: n.to_string(), path: format!("checks/{n}.sh"), inputs: None }).collect()
    }

    fn items(list: &[&str]) -> RunOutcome {
        RunOutcome::Fail { items: list.iter().map(|s| s.to_string()).collect() }
    }

    const BOTH: [Isolation; 2] = [Isolation::Bwrap, Isolation::None];

    #[test]
    fn outcomes_come_from_exit_codes_and_result_frames() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
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
        for isolation in BOTH {
            let runs = runner(dir.path(), isolation, |_| {}).run_units(&repo, &tree, &jobs(&names)).unwrap();
            let outcomes: Vec<RunOutcome> = runs.iter().map(|r| r.outcome.clone()).collect();
            assert_eq!(
                outcomes,
                vec![
                    RunOutcome::Pass,
                    RunOutcome::Crash,
                    items(&["t1", "t2"]),
                    items(&["t1"]),
                    RunOutcome::Crash,
                    RunOutcome::Crash,
                    RunOutcome::Pass
                ],
                "{isolation:?}"
            );
            assert_eq!(runs[1].log_tail, "boom");
            assert!(runs.iter().all(|r| r.attempts == 1 && r.is_durable()));
            // The scratch tree is gone.
            assert_eq!(std::fs::read_dir(dir.path().join("runs")).unwrap().count(), 0, "{isolation:?}");
        }
    }

    #[test]
    fn tooth_frames_are_a_closed_schema() {
        let frame = |text: &str| classify(true, Some(text.as_bytes().to_vec()));
        assert_eq!(frame(r#"{"status":"pass"}"#), RunOutcome::Pass);
        assert_eq!(frame(r#"{"status":"fail","items":["t"]}"#), items(&["t"]));
        // A pass that also lists failures, an unknown status, an unknown key,
        // a failure that names nothing, and an empty or oversized file.
        for bad in [
            r#"{"status":"pass","items":["t"]}"#,
            r#"{"status":"skipped"}"#,
            r#"{"status":"fail","items":["t"],"x":1}"#,
            r#"{"status":"fail","items":[]}"#,
            "",
        ] {
            assert_eq!(frame(bad), RunOutcome::Crash, "{bad}");
        }
        assert_eq!(classify(false, None), RunOutcome::Crash);
        assert_eq!(classify(true, None), RunOutcome::Pass);
    }

    /// The tree a unit runs on is the tree git stores: bytes, executable
    /// bits and links, whatever `.gitattributes` says about exports.
    #[test]
    fn tooth_materialization_is_exact_and_ignores_export_attributes() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let check = "set -e\n[ -f hidden.txt ]\n[ \"$(cat crlf.txt | od -An -c | tr -d ' \\n')\" = 'a\\nb\\n' ]\n\
                     [ -x tool ]\n[ ! -x plain.txt ]\n[ -L link ]\n[ \"$(readlink link)\" = plain.txt ]\n[ \"$(cat ident.txt)\" = '$Id$' ]\n[ ! -e .git ]\n";
        let sandbox = Sandbox::new(
            dir.path(),
            &[
                (".gitattributes", "hidden.txt export-ignore\ncrlf.txt text eol=crlf\nident.txt ident export-subst\n"),
                ("hidden.txt", "kept\n"),
                ("crlf.txt", "a\nb\n"),
                ("ident.txt", "$Id$\n"),
                ("plain.txt", "p\n"),
                ("tool", "#!/bin/sh\n"),
                ("checks/exact.sh", check),
            ],
        );
        std::os::unix::fs::symlink("plain.txt", sandbox.work.join("link")).unwrap();
        std::fs::set_permissions(sandbox.work.join("tool"), std::fs::Permissions::from_mode(0o755)).unwrap();
        sandbox.git(&["-c", "core.autocrlf=false", "add", "-A"]);
        sandbox.git(&["commit", "--quiet", "-m", "modes and attributes"]);
        let repo = sandbox.repo();
        let tree = repo.tree_of("HEAD").unwrap();
        for isolation in BOTH {
            let runs = runner(dir.path(), isolation, |_| {}).run_units(&repo, &tree, &jobs(&["exact"])).unwrap();
            assert_eq!(runs[0].outcome, RunOutcome::Pass, "{isolation:?}: {}", runs[0].log_tail);
        }
    }

    /// The sandbox: none of the supervisor's files, processes or
    /// environment exist for the unit, and what it writes is gone afterwards.
    #[test]
    fn tooth_sandboxed_units_cannot_reach_the_supervisor() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir_all(state.join("verdicts")).unwrap();
        let key = state.join("seat.key.json");
        std::fs::write(&key, "{\"secret\": true}").unwrap();
        // The unit tries everything a co-uid process could do.
        let script = format!(
            "fail() {{ echo \"$1\" >&2; exit 1; }}\n\
             [ ! -e '{key}' ] || fail 'the signing key is readable'\n\
             [ ! -e '{state}' ] || fail 'the state directory is visible'\n\
             [ ! -e '{work}' ] || fail 'the repository is visible'\n\
             [ ! -e .git ] || fail 'a git directory'\n\
             [ -z \"$LANDD_TEST_SIGNING_SECRET\" ] || fail 'inherited environment'\n\
             [ \"$(ls /proc | grep -c '^[0-9][0-9]*$')\" -lt 8 ] || fail 'the host process table is visible'\n\
             (echo forged > '{state}/verdicts/forged' ) 2>/dev/null && fail 'wrote the verdict store'\n\
             ls /landd-out/.. >/dev/null\n[ \"$(ls /landd-out | wc -l)\" = 0 ] || fail 'sibling results are visible'\n\
             echo mine > scribble.txt && echo x >> src.txt || fail 'the tree is not writable'\n\
             [ \"$HOME\" = /home/unit ] && touch \"$HOME/x\" /tmp/y || fail 'no private home or tmp'\n\
             [ -z \"$(git config --list 2>/dev/null)\" ] || fail 'ambient git config'\n\
             exit 0\n",
            key = key.display(),
            state = state.display(),
            work = dir.path().join("work").display(),
        );
        let sandbox = Sandbox::new(
            dir.path(),
            &[
                ("checks/iso.sh", script.as_str()),
                ("checks/again.sh", "[ ! -e scribble.txt ] && ! grep -q '^x$' src.txt\n"),
                ("src.txt", "s\n"),
            ],
        );
        let repo = sandbox.repo();
        let tree = repo.tree_of("HEAD").unwrap();
        std::env::set_var("LANDD_TEST_SIGNING_SECRET", "do-not-leak");
        let sandboxed = runner(dir.path(), Isolation::Bwrap, |c| c.concurrency = 1);
        let runs = sandboxed.run_units(&repo, &tree, &jobs(&["iso", "again"])).unwrap();
        assert_eq!(runs[0].outcome, RunOutcome::Pass, "{}", runs[0].log_tail);
        // A sibling does not see what the first unit wrote into its tree.
        assert_eq!(runs[1].outcome, RunOutcome::Pass, "{}", runs[1].log_tail);
        assert!(!state.join("verdicts/forged").exists());
        assert_eq!(std::fs::read_to_string(&key).unwrap(), "{\"secret\": true}");

        // The same script outside the sandbox does reach the key: the check has teeth.
        let unsandboxed = runner(dir.path(), Isolation::None, |_| {});
        let runs = unsandboxed.run_units(&repo, &tree, &jobs(&["iso"])).unwrap();
        assert_eq!(runs[0].outcome, RunOutcome::Crash);
        assert!(runs[0].log_tail.contains("the signing key is readable"), "{}", runs[0].log_tail);
        assert_eq!(sandboxed.profile().description["sandbox"]["isolation"], "bwrap");
        assert_eq!(unsandboxed.profile().description["sandbox"]["isolation"], "none");
    }

    #[test]
    fn unsandboxed_units_get_a_cleared_environment_and_a_private_copy() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let script = "[ ! -e .git ] || exit 10\n[ -z \"$LANDD_TEST_OTHER_SECRET\" ] || exit 11\n[ \"$LANDD_TEST_ALLOWED\" = yes ] || exit 13\n\
                      [ -z \"$(git rev-parse --show-toplevel 2>/dev/null)\" ] || exit 14\n! grep -q scribble src.txt || exit 15\necho scribble >> src.txt\n";
        let sandbox = Sandbox::new(dir.path(), &[("checks/iso.sh", script), ("src.txt", "s\n")]);
        let repo = sandbox.repo();
        let tree = repo.tree_of("HEAD").unwrap();
        std::env::set_var("LANDD_TEST_OTHER_SECRET", "do-not-leak");
        std::env::set_var("LANDD_TEST_ALLOWED", "yes");
        let local = runner(dir.path(), Isolation::None, |c| {
            c.env_allow.push("LANDD_TEST_ALLOWED".into());
            c.max_reruns_on_flake = 1;
        });
        // Run twice: the second run sees the pristine script, not the first run's edit.
        for _ in 0..2 {
            let runs = local.run_units(&repo, &tree, &jobs(&["iso"])).unwrap();
            assert_eq!((runs[0].outcome.clone(), runs[0].attempts), (RunOutcome::Pass, 1), "{}", runs[0].log_tail);
        }
        assert_eq!(sandbox.git(&["status", "--porcelain"]), "");
    }

    /// With cone views a unit sees its inputs and nothing else of the tree.
    #[test]
    fn tooth_cone_views_hold_only_the_units_inputs() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(
            dir.path(),
            &[
                ("checks/a.sh", "[ -f src/a.txt ] && [ ! -e src/b.txt ] && [ ! -e checks/b.sh ] && [ ! -e docs ]\n"),
                ("checks/b.sh", "[ -f src/b.txt ] && [ ! -e src/a.txt ]\n"),
                ("checks/all.sh", "[ -f src/a.txt ] && [ -f src/b.txt ] && [ -f docs/readme.md ]\n"),
                ("src/a.txt", "a\n"),
                ("src/b.txt", "b\n"),
                ("docs/readme.md", "d\n"),
            ],
        );
        let repo = sandbox.repo();
        let tree = repo.tree_of("HEAD").unwrap();
        let job = |unit: &str, inputs: Option<&[&str]>| UnitJob {
            unit: unit.into(),
            path: format!("checks/{unit}.sh"),
            inputs: inputs.map(|list| list.iter().map(|s| s.to_string()).collect()),
        };
        let jobs =
            [job("a", Some(&["checks/a.sh", "src/a.txt"])), job("b", Some(&["checks/b.sh", "src/b.txt"])), job("all", None)];
        for isolation in BOTH {
            let cone = runner(dir.path(), isolation, |c| c.unit_view = UnitView::Cone);
            let runs = cone.run_units(&repo, &tree, &jobs).unwrap();
            for run in &runs {
                assert_eq!(run.outcome, RunOutcome::Pass, "{isolation:?} {}: {}", run.unit, run.log_tail);
            }
            // With whole-tree views the same checks see their neighbours and fail.
            let whole = runner(dir.path(), isolation, |_| {});
            let runs = whole.run_units(&repo, &tree, &jobs[..2]).unwrap();
            assert!(runs.iter().all(|r| r.outcome == RunOutcome::Crash), "{isolation:?}");
        }
    }

    #[test]
    fn tooth_timeouts_kill_the_process_group_and_are_not_durable() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let marker = dir.path().join("survivor");
        let script = format!("(sleep 2; touch {}) &\nsleep 30\n", marker.display());
        let sandbox = Sandbox::new(dir.path(), &[("checks/slow.sh", script.as_str())]);
        let repo = sandbox.repo();
        for isolation in BOTH {
            let started = Instant::now();
            let runs = runner(dir.path(), isolation, |c| c.timeout = Duration::from_millis(300))
                .run_units(&repo, &repo.tree_of("HEAD").unwrap(), &jobs(&["slow"]))
                .unwrap();
            assert!(started.elapsed() < Duration::from_secs(10));
            assert_eq!(runs[0].outcome, RunOutcome::Timeout);
            assert!(!runs[0].is_durable());
            assert_eq!(runs[0].status(), Status::Timeout);
        }
        std::thread::sleep(Duration::from_millis(2500));
        assert!(!marker.exists(), "a grandchild outlived the timeout");
    }

    /// The result path is the unit's to control: a link to a device, a FIFO
    /// and an enormous file must not hang or exhaust the supervisor.
    #[test]
    fn tooth_hostile_result_files_do_not_hang_or_exhaust_the_supervisor() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let files = [
            ("checks/zero.sh", "ln -s /dev/zero \"$LANDD_RESULT_FILE\"\nexit 0\n"),
            ("checks/fifo.sh", "mkfifo \"$LANDD_RESULT_FILE\"\nexit 0\n"),
            ("checks/huge.sh", "head -c 3000000 /dev/zero > \"$LANDD_RESULT_FILE\"\nexit 0\n"),
            ("checks/dir.sh", "mkdir \"$LANDD_RESULT_FILE\"\nexit 0\n"),
            ("checks/noise.sh", "head -c 5000000 /dev/zero | tr '\\0' 'x' >&2\necho the-end >&2\nexit 1\n"),
        ];
        let sandbox = Sandbox::new(dir.path(), &files);
        let repo = sandbox.repo();
        let tree = repo.tree_of("HEAD").unwrap();
        for isolation in BOTH {
            let started = Instant::now();
            let runs = runner(dir.path(), isolation, |_| {})
                .run_units(&repo, &tree, &jobs(&["zero", "fifo", "huge", "dir", "noise"]))
                .unwrap();
            assert!(started.elapsed() < Duration::from_secs(15), "{isolation:?}");
            // A link is not followed (so: no frame, exit 0); the others are present but not frames.
            let outcomes: Vec<RunOutcome> = runs.iter().map(|r| r.outcome.clone()).collect();
            assert_eq!(
                outcomes[1..],
                [RunOutcome::Crash, RunOutcome::Crash, RunOutcome::Crash, RunOutcome::Crash],
                "{isolation:?}"
            );
            assert!(matches!(outcomes[0], RunOutcome::Pass | RunOutcome::Crash));
            assert!(runs[4].log_tail.ends_with("the-end") && runs[4].log_tail.len() <= LOG_TAIL_BYTES);
        }
    }

    #[test]
    fn flakes_are_rerun_from_a_pristine_view_and_never_recorded_as_durable() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let marker = dir.path().join("second-time");
        // Unsandboxed, so the script can leave a marker outside its view.
        let flaky = format!("[ -e {0} ] && exit 0\ntouch {0}\nexit 1\n", marker.display());
        let sandbox = Sandbox::new(dir.path(), &[("checks/flaky.sh", flaky.as_str()), ("checks/red.sh", "exit 1\n")]);
        let repo = sandbox.repo();
        let tree = repo.tree_of("HEAD").unwrap();
        let runs = runner(dir.path(), Isolation::None, |c| c.max_reruns_on_flake = 2)
            .run_units(&repo, &tree, &jobs(&["flaky", "red"]))
            .unwrap();
        assert_eq!((runs[0].outcome.clone(), runs[0].attempts, runs[0].flaky), (RunOutcome::Pass, 2, true));
        assert!(!runs[0].is_durable());
        assert_eq!((runs[1].outcome.clone(), runs[1].attempts, runs[1].flaky), (RunOutcome::Crash, 3, false));
        assert!(runs[1].is_durable());
    }

    #[test]
    fn tooth_a_runner_that_cannot_keep_its_promises_does_not_start() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let missing = Runner::new(config(dir.path(), Isolation::None, |c| c.command = vec!["landd-no-such-program".into()]));
        assert!(matches!(missing, Err(RunnerError::Profile(_))));
        // A sandbox was asked for and cannot be had: an error, not a quiet fallback.
        let unavailable = Runner::new(config(dir.path(), Isolation::Bwrap, |c| c.bwrap_program = "landd-no-such-bwrap".into()));
        assert!(matches!(unavailable, Err(RunnerError::NoSandbox(_))), "{unavailable:?}");
        // Something that is there but does not sandbox.
        let fake = Runner::new(config(dir.path(), Isolation::Bwrap, |c| c.bwrap_program = "false".into()));
        assert!(matches!(fake, Err(RunnerError::NoSandbox(_))), "{fake:?}");
    }

    /// The profile is part of every verdict's identity: another argv,
    /// environment value, view or sandbox is another profile.
    #[test]
    fn tooth_the_runner_profile_moves_with_what_produces_verdicts() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        std::env::set_var("LANDD_TEST_PROFILE_VAR", "one");
        let base = runner(dir.path(), Isolation::None, |c| c.env_allow.push("LANDD_TEST_PROFILE_VAR".into())).profile().digest;
        let same = runner(dir.path(), Isolation::None, |c| c.env_allow.push("LANDD_TEST_PROFILE_VAR".into())).profile().digest;
        assert_eq!(base, same);
        type Edit = Box<dyn FnOnce(&mut RunnerConfig)>;
        let variants: Vec<Edit> = vec![
            Box::new(|c| c.command = vec!["sh".into(), "-e".into(), "{path}".into()]),
            Box::new(|c| c.unit_view = UnitView::Cone),
            Box::new(|c| c.profile_commands = vec![vec!["sh".into(), "-c".into(), "echo toolchain 2".into()]]),
            Box::new(|c| c.isolation = Isolation::Bwrap),
            Box::new(|c| c.runtime_id = "image-2026-11".into()),
        ];
        for edit in variants {
            let other = runner(dir.path(), Isolation::None, |c| {
                c.env_allow.push("LANDD_TEST_PROFILE_VAR".into());
                edit(c);
            });
            assert_ne!(base, other.profile().digest);
        }
        std::env::set_var("LANDD_TEST_PROFILE_VAR", "two");
        let moved = runner(dir.path(), Isolation::None, |c| c.env_allow.push("LANDD_TEST_PROFILE_VAR".into())).profile().digest;
        assert_ne!(base, moved);
    }

    #[test]
    fn tooth_units_receive_the_environment_that_was_profiled() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("checks/env.sh", "[ \"$LANDD_TEST_FROZEN_ENV\" = before ]\n")]);
        let repo = sandbox.repo();
        for isolation in BOTH {
            std::env::set_var("LANDD_TEST_FROZEN_ENV", "before");
            let runner = runner(dir.path(), isolation, |c| c.env_allow.push("LANDD_TEST_FROZEN_ENV".into()));
            std::env::set_var("LANDD_TEST_FROZEN_ENV", "after");
            let run = runner.run_units(&repo, &repo.tree_of("HEAD").unwrap(), &jobs(&["env"])).unwrap();
            assert_eq!(run[0].outcome, RunOutcome::Pass, "{isolation:?}: {}", run[0].log_tail);
        }
        std::env::remove_var("LANDD_TEST_FROZEN_ENV");
    }

    /// Moving scratch out of the state directory is not enough if the key
    /// itself sits under a directory the sandbox mounts (the default mounts
    /// include `/etc`): such a configuration does not start.
    #[test]
    fn tooth_a_secret_under_a_sandbox_mount_is_refused() {
        let dir = landd_core::git::testkit::private_tempdir().unwrap();
        let mounted = dir.path().join("etc-like");
        std::fs::create_dir_all(mounted.join("landd")).unwrap();
        let key = mounted.join("landd/seat.key.json");
        std::fs::write(&key, "{}").unwrap();
        let exposed = |secret: PathBuf| {
            Runner::new(config(dir.path(), Isolation::Bwrap, |c| {
                c.sandbox_ro.push(mounted.display().to_string());
                c.secrets = vec![secret];
            }))
        };
        assert!(matches!(exposed(key.clone()), Err(RunnerError::Exposed { .. })));
        // A state directory that does not exist yet, and a path spelled through `..`.
        assert!(matches!(exposed(mounted.join("landd/state/not-yet")), Err(RunnerError::Exposed { .. })));
        assert!(matches!(exposed(dir.path().join("x/../etc-like/landd/seat.key.json")), Err(RunnerError::Exposed { .. })));
        assert!(matches!(exposed(PathBuf::from("/etc/landd/seat.key.json")), Err(RunnerError::Exposed { .. })));
        // `/outside/link/../seat.key.json` resolves through the symlink
        // before `..`; lexical normalization would miss the mounted key.
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::create_dir(mounted.join("landd/nested")).unwrap();
        std::os::unix::fs::symlink(mounted.join("landd/nested"), outside.join("link")).unwrap();
        let aliased_key = outside.join("link/../seat.key.json");
        assert_eq!(std::fs::read(&aliased_key).unwrap(), b"{}");
        assert!(matches!(exposed(aliased_key), Err(RunnerError::Exposed { .. })));
        assert!(matches!(exposed(outside.join("link/../future/state")), Err(RunnerError::Exposed { .. })));
        // A dangling symlink into a mounted directory is also refused.
        std::os::unix::fs::symlink(mounted.join("landd/not-yet"), outside.join("dangling")).unwrap();
        assert!(matches!(exposed(outside.join("dangling/seat.key.json")), Err(RunnerError::Exposed { .. })));
        // Outside every mount it starts, and the unit cannot see the key.
        std::fs::write(dir.path().join("outside.key"), "{}").unwrap();
        assert!(exposed(dir.path().join("outside.key")).is_ok());
        // Without a sandbox there is nothing to check (and nothing is promised).
        assert!(Runner::new(config(dir.path(), Isolation::None, |c| c.secrets = vec![key])).is_ok());
    }
}
