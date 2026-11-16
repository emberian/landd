//! Git plumbing. Trees and blobs are read straight from the object store
//! (`ls-tree -r -z`, a persistent `cat-file --batch`), merges are computed
//! with `merge-tree --write-tree`, and nothing here touches a working tree
//! or the index. Outcomes come from exit codes and NUL-framed plumbing
//! output, never from human-readable messages. Every command runs with the
//! inherited `GIT_*` location variables removed, and every network command
//! runs under a deadline.

use crate::digest::Oid;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Blobs larger than this are refused by [`BlobReader::read`].
pub const DEFAULT_MAX_BLOB_BYTES: u64 = 64 << 20;
/// `merge-tree --write-tree` needs 2.38; `--attr-source` needs 2.40.
const MIN_GIT: (u32, u32) = (2, 40);

/// Variables that would redirect a git command away from `-C <dir>`.
const LOCATION_ENV: [&str; 9] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_QUARANTINE_PATH",
    "GIT_NAMESPACE",
    "GIT_CONFIG_PARAMETERS",
    "GIT_COMMON_DIR",
];
/// What a receive hook must keep to see the objects being pushed.
const HOOK_ENV: [&str; 4] = ["GIT_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_QUARANTINE_PATH"];

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("git io: {0}")]
    Io(#[from] std::io::Error),
    #[error("git {args} exited with {code:?}: {stderr}")]
    Failed { args: String, code: Option<i32>, stderr: String },
    #[error("unexpected git output: {0}")]
    Parse(String),
    #[error("object {0} is missing")]
    Missing(String),
    #[error("path {0:?} is not UTF-8; refusing to guess which file it names")]
    NonUtf8Path(String),
    #[error("object {oid} is {size} bytes, over the limit of {limit}")]
    TooLarge { oid: String, size: u64, limit: u64 },
    #[error("git {args} did not finish within {seconds} s")]
    Timeout { args: String, seconds: u64 },
    #[error("unsupported git: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Blob,
    Tree,
    /// A submodule link.
    Commit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: u32,
    pub kind: EntryKind,
    pub oid: Oid,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutcome {
    Clean { tree: Oid },
    Conflict { conflicting_paths: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub email: String,
    /// Seconds since the epoch, for both author and committer dates.
    pub time: u64,
}

pub struct RawOutput {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// One object as `cat-file --batch` returned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    pub oid: Oid,
    pub kind: String,
    pub bytes: Vec<u8>,
}

/// One long-lived `git cat-file --batch` process.
struct CatFile {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl CatFile {
    fn spawn(repo: &GitRepo) -> Result<Self, GitError> {
        let mut child = repo
            .command()
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::with_capacity(1 << 16, child.stdout.take().expect("piped stdout"));
        Ok(Self { child, stdin, stdout })
    }

    /// Ask for `name` and read the reply. `limit` bounds the object size;
    /// an oversized object is consumed and reported, leaving the stream in
    /// sync. A stream that ends or breaks framing is an I/O or parse error,
    /// never "missing".
    fn object(&mut self, name: &str, limit: Option<u64>) -> Result<Object, GitError> {
        if name.contains(['\n', '\0']) {
            return Err(GitError::Parse(format!("object name {name:?} holds a line break")));
        }
        self.stdin.write_all(format!("{name}\n").as_bytes())?;
        self.stdin.flush()?;
        let mut header = String::new();
        if self.stdout.read_line(&mut header)? == 0 {
            return Err(GitError::Io(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "cat-file closed its stream")));
        }
        let header = header.trim_end_matches('\n');
        if header.strip_suffix(" missing").is_some_and(|rest| rest == name) || header.ends_with(" ambiguous") {
            return Err(GitError::Missing(name.to_owned()));
        }
        let bad = || GitError::Parse(format!("cat-file header {header:?}"));
        let mut fields = header.split(' ');
        let (oid, kind, size) = match (fields.next(), fields.next(), fields.next(), fields.next()) {
            (Some(oid), Some(kind), Some(size), None) => {
                (Oid::from_hex(oid).map_err(|_| bad())?, kind.to_owned(), size.parse::<u64>().map_err(|_| bad())?)
            }
            _ => return Err(bad()),
        };
        if limit.is_some_and(|limit| size > limit) {
            let skipped = std::io::copy(&mut (&mut self.stdout).take(size + 1), &mut std::io::sink())?;
            if skipped != size + 1 {
                return Err(GitError::Io(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "cat-file closed mid-object")));
            }
            return Err(GitError::TooLarge { oid: oid.to_hex(), size, limit: limit.unwrap_or(0) });
        }
        let mut bytes = vec![0u8; size as usize + 1];
        self.stdout.read_exact(&mut bytes)?;
        if bytes.pop() != Some(b'\n') {
            return Err(GitError::Parse("cat-file object is not followed by a newline".into()));
        }
        Ok(Object { oid, kind, bytes })
    }
}

impl Drop for CatFile {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A leased `cat-file --batch` stream; returns itself to the pool on drop.
pub struct BlobReader<'a> {
    repo: &'a GitRepo,
    inner: Option<CatFile>,
}

impl BlobReader<'_> {
    fn object(&mut self, name: &str, limit: Option<u64>) -> Result<Object, GitError> {
        let Some(stream) = self.inner.as_mut() else {
            return Err(GitError::Io(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "the cat-file stream was discarded")));
        };
        let result = stream.object(name, limit);
        if matches!(result, Err(GitError::Io(_)) | Err(GitError::Parse(_))) {
            // The stream is dead or out of sync; do not hand it to the next caller.
            self.inner = None;
        }
        result
    }

    /// The blob `oid`, refused when larger than `limit` bytes. The reply
    /// must be a blob and must be the object that was asked for.
    pub fn read_limited(&mut self, oid: &Oid, limit: Option<u64>) -> Result<Vec<u8>, GitError> {
        let object = self.object(&oid.to_hex(), limit)?;
        if object.oid != *oid || object.kind != "blob" {
            self.inner = None;
            return Err(GitError::Parse(format!("asked for blob {oid}, got {} {}", object.kind, object.oid)));
        }
        Ok(object.bytes)
    }

    /// The blob `oid`, up to [`DEFAULT_MAX_BLOB_BYTES`].
    pub fn read(&mut self, oid: &Oid) -> Result<Vec<u8>, GitError> {
        self.read_limited(oid, Some(DEFAULT_MAX_BLOB_BYTES))
    }

    /// The tree a revision names, resolved exactly once.
    pub fn resolve_tree(&mut self, rev: &str) -> Result<Oid, GitError> {
        let object = self.object(&format!("{rev}^{{tree}}"), None)?;
        if object.kind != "tree" {
            return Err(GitError::Parse(format!("{rev}^{{tree}} is a {}", object.kind)));
        }
        Ok(object.oid)
    }
}

impl Drop for BlobReader<'_> {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            if let Ok(mut pool) = self.repo.readers.lock() {
                pool.push(inner);
            }
        }
    }
}

pub struct GitRepo {
    dir: PathBuf,
    readers: Mutex<Vec<CatFile>>,
    hook: bool,
    network_timeout: Duration,
}

impl std::fmt::Debug for GitRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GitRepo({})", self.dir.display())
    }
}

/// The identity of a push destination: a local path in canonical form, or a
/// URL without a trailing slash or `.git`. Two spellings of one destination
/// that differ only in those ways get one identity.
pub fn canonical_repo_id(destination: &str) -> String {
    if let Ok(path) = std::fs::canonicalize(destination) {
        return path.to_string_lossy().into_owned();
    }
    let trimmed = destination.trim_end_matches('/');
    trimmed.strip_suffix(".git").unwrap_or(trimmed).to_owned()
}

impl GitRepo {
    /// `dir` may be a working tree or a bare repository.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, GitError> {
        Self::open_with(dir.into(), false)
    }

    /// Open the repository a receive hook runs in. Git points the hook at
    /// the repository and at the quarantined objects of the push through
    /// the environment; those variables, and only those, are kept.
    pub fn open_in_hook() -> Result<Self, GitError> {
        Self::open_with(PathBuf::from("."), true)
    }

    fn open_with(dir: PathBuf, hook: bool) -> Result<Self, GitError> {
        let repo = Self { dir, readers: Mutex::new(Vec::new()), hook, network_timeout: Duration::from_secs(120) };
        repo.run_ok(&["rev-parse", "--git-dir"])?;
        // `git version` prints `git version X.Y…`; only the two numbers are read.
        let version = String::from_utf8_lossy(&repo.run_ok(&["version"])?).into_owned();
        let mut numbers = version.split(|c: char| !c.is_ascii_digit()).filter(|part| !part.is_empty()).map(|n| n.parse::<u32>());
        match (numbers.next(), numbers.next()) {
            (Some(Ok(major)), Some(Ok(minor))) if (major, minor) >= MIN_GIT => Ok(repo),
            _ => Err(GitError::Unsupported(format!("need git {}.{} or newer, found {:?}", MIN_GIT.0, MIN_GIT.1, version.trim()))),
        }
    }

    /// Deadline for `ls-remote`, `fetch` and `push`.
    pub fn with_network_timeout(mut self, timeout: Duration) -> Self {
        self.network_timeout = timeout;
        self
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn command(&self) -> Command {
        let mut command = Command::new("git");
        for name in LOCATION_ENV {
            if !(self.hook && HOOK_ENV.contains(&name)) {
                command.env_remove(name);
            }
        }
        command.arg("-C").arg(&self.dir).env("LC_ALL", "C").env("GIT_TERMINAL_PROMPT", "0").env("GIT_OPTIONAL_LOCKS", "0");
        command
    }

    pub fn run(&self, args: &[&str]) -> Result<RawOutput, GitError> {
        self.run_with(args, |_| {})
    }

    fn run_with(&self, args: &[&str], prepare: impl FnOnce(&mut Command)) -> Result<RawOutput, GitError> {
        let mut command = self.command();
        command.args(args).stdin(Stdio::null());
        prepare(&mut command);
        let output = command.output()?;
        Ok(RawOutput { code: output.status.code(), stdout: output.stdout, stderr: output.stderr })
    }

    /// Run a command that talks to another machine. It gets its own process
    /// group and is killed, with everything it started, at the deadline.
    fn run_network(&self, args: &[&str], env: &[(&str, &str)]) -> Result<RawOutput, GitError> {
        let seconds = self.network_timeout.as_secs().max(1);
        let slow = format!("http.lowSpeedTime={seconds}");
        let mut command = self.command();
        command
            .args(["-c", "http.lowSpeedLimit=1000", "-c", &slow])
            .args(args)
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn()?;
        let (mut out, mut err) = (child.stdout.take().expect("piped stdout"), child.stderr.take().expect("piped stderr"));
        struct GroupReap(Option<Child>);
        impl Drop for GroupReap {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    // SAFETY: signals the process group this un-reaped child leads.
                    unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
                    let _ = child.wait();
                }
            }
        }
        let mut child = GroupReap(Some(child));
        let deadline = Instant::now() + self.network_timeout;
        let finished = std::thread::scope(|scope| {
            let stdout = scope.spawn(move || {
                let mut bytes = Vec::new();
                let _ = out.read_to_end(&mut bytes);
                bytes
            });
            let stderr = scope.spawn(move || {
                let mut bytes = Vec::new();
                let _ = (&mut err).take(1 << 16).read_to_end(&mut bytes);
                let _ = std::io::copy(&mut err, &mut std::io::sink());
                bytes
            });
            let mut nap = Duration::from_millis(1);
            let pid = child.0.as_ref().expect("live child").id() as libc::pid_t;
            let exited = loop {
                // Observe without reaping: the leader pins the process-group
                // id until its descendants (including pipe holders) are dead.
                // SAFETY: this is our own child, and waitid initializes info.
                let (rc, done) = unsafe {
                    let mut info: libc::siginfo_t = std::mem::zeroed();
                    let rc =
                        libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOHANG | libc::WNOWAIT);
                    (rc, info.si_pid() != 0)
                };
                if rc != 0 {
                    break false;
                }
                if done {
                    break true;
                }
                if Instant::now() >= deadline {
                    break false;
                }
                std::thread::sleep(nap);
                nap = (nap * 2).min(Duration::from_millis(50));
            };
            // A normally exited Git can leave a transport child holding its
            // stderr pipe. Kill the group before joining either pipe reader,
            // even on success, while the unreaped leader prevents pid reuse.
            // SAFETY: signals the process group our unreaped child leads.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            let status = child.0.take().expect("live child").wait().ok().filter(|_| exited);
            drop(child);
            (status, stdout.join().unwrap_or_default(), stderr.join().unwrap_or_default())
        });
        match finished {
            (Some(status), stdout, stderr) => Ok(RawOutput { code: status.code(), stdout, stderr }),
            (None, ..) => Err(GitError::Timeout { args: args.join(" "), seconds }),
        }
    }

    fn failed(args: &[&str], out: &RawOutput) -> GitError {
        GitError::Failed { args: args.join(" "), code: out.code, stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned() }
    }

    pub fn run_ok(&self, args: &[&str]) -> Result<Vec<u8>, GitError> {
        let out = self.run(args)?;
        if out.code != Some(0) {
            return Err(Self::failed(args, &out));
        }
        Ok(out.stdout)
    }

    fn oid_line(bytes: &[u8]) -> Result<Oid, GitError> {
        let text = String::from_utf8_lossy(bytes);
        Oid::from_hex(text.trim()).map_err(|_| GitError::Parse(format!("expected an object id, got {text:?}")))
    }

    pub fn rev_parse(&self, rev: &str) -> Result<Oid, GitError> {
        Self::oid_line(&self.run_ok(&["rev-parse", "--verify", "--end-of-options", rev])?)
    }

    pub fn commit_of(&self, rev: &str) -> Result<Oid, GitError> {
        self.rev_parse(&format!("{rev}^{{commit}}"))
    }

    pub fn tree_of(&self, rev: &str) -> Result<Oid, GitError> {
        self.rev_parse(&format!("{rev}^{{tree}}"))
    }

    /// Every entry of a tree, recursively, from the root of the tree
    /// whatever directory the repository was opened at. With `with_trees`,
    /// directories are listed too (before their contents). A path that is
    /// not UTF-8 is an error: two such paths could otherwise collapse into
    /// one name and one of them would silently leave every cone.
    pub fn ls_tree(&self, tree: &str, with_trees: bool) -> Result<Vec<TreeEntry>, GitError> {
        let mut command = self.command();
        command.args(["ls-tree", "-r", "-z", "--full-tree"]);
        if with_trees {
            command.arg("-t");
        }
        command.args(["--end-of-options", tree]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let mut reader = BufReader::with_capacity(1 << 16, child.stdout.take().expect("piped stdout"));
        let mut pipe = child.stderr.take().expect("piped stderr");
        struct ChildReap(Option<Child>);
        impl Drop for ChildReap {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }
        let mut child = ChildReap(Some(child));
        let (entries, stderr) = std::thread::scope(|scope| {
            // Drained concurrently: a long error message cannot stall the listing.
            let stderr = scope.spawn(move || {
                let mut text = Vec::new();
                let _ = (&mut pipe).take(1 << 16).read_to_end(&mut text);
                let _ = std::io::copy(&mut pipe, &mut std::io::sink());
                String::from_utf8_lossy(&text).trim().to_owned()
            });
            let mut entries = Vec::new();
            let mut record = Vec::with_capacity(256);
            let listed = loop {
                record.clear();
                match reader.read_until(0, &mut record) {
                    Ok(0) => break Ok(entries),
                    Ok(_) => {}
                    Err(err) => break Err(GitError::Io(err)),
                }
                if record.last() == Some(&0) {
                    record.pop();
                }
                match parse_tree_record(&record) {
                    Ok(entry) => entries.push(entry),
                    Err(err) => break Err(err),
                }
            };
            if listed.is_err() {
                if let Some(live) = child.0.as_mut() {
                    let _ = live.kill();
                }
                drop(reader);
            }
            (listed, stderr.join().unwrap_or_default())
        });
        let status = child.0.take().expect("live child").wait()?;
        let entries = entries?;
        if !status.success() {
            return Err(GitError::Failed { args: format!("ls-tree -r -z --full-tree {tree}"), code: status.code(), stderr });
        }
        Ok(entries)
    }

    /// Lease a persistent `cat-file --batch` stream.
    pub fn blob_reader(&self) -> Result<BlobReader<'_>, GitError> {
        let pooled = self.readers.lock().expect("reader pool").pop();
        let inner = match pooled {
            Some(reader) => reader,
            None => CatFile::spawn(self)?,
        };
        Ok(BlobReader { repo: self, inner: Some(inner) })
    }

    pub fn read_blob(&self, oid: &Oid) -> Result<Vec<u8>, GitError> {
        self.blob_reader()?.read(oid)
    }

    /// The best common ancestor of two commits; `None` for unrelated histories.
    pub fn merge_base(&self, a: &Oid, b: &Oid) -> Result<Option<Oid>, GitError> {
        let (a, b) = (a.to_hex(), b.to_hex());
        let args = ["merge-base", &a, &b];
        let out = self.run(&args)?;
        match out.code {
            Some(0) => Self::oid_line(out.stdout.split(|b| *b == b'\n').next().unwrap_or_default()).map(Some),
            Some(1) => Ok(None),
            _ => Err(Self::failed(&args, &out)),
        }
    }

    /// Merge `theirs` into `ours` (both commits) without a working tree.
    /// Attributes are read from `ours`, never from a checkout, and the
    /// settings that change what a merge produces are pinned, so the result
    /// is a function of the two commits.
    pub fn merge_tree(&self, ours: &Oid, theirs: &Oid) -> Result<MergeOutcome, GitError> {
        let (ours, theirs) = (ours.to_hex(), theirs.to_hex());
        let attr_source = format!("--attr-source={ours}");
        let args = [
            attr_source.as_str(),
            "-c",
            "merge.renames=true",
            "-c",
            "merge.directoryRenames=conflict",
            "-c",
            "merge.renameLimit=7000",
            "-c",
            "merge.conflictStyle=merge",
            "merge-tree",
            "--write-tree",
            "-z",
            "--name-only",
            "--no-messages",
            &ours,
            &theirs,
        ];
        let out = self.run(&args)?;
        let mut fields = out.stdout.split(|b| *b == 0).filter(|f| !f.is_empty());
        match out.code {
            Some(0) => {
                let tree = fields.next().ok_or_else(|| GitError::Parse("merge-tree printed no tree".into()))?;
                Ok(MergeOutcome::Clean { tree: Self::oid_line(tree)? })
            }
            Some(1) => {
                let _tree_with_markers = fields.next();
                let mut conflicting_paths: Vec<String> = fields.map(|f| String::from_utf8_lossy(f).into_owned()).collect();
                conflicting_paths.sort();
                conflicting_paths.dedup();
                Ok(MergeOutcome::Conflict { conflicting_paths })
            }
            _ => Err(Self::failed(&args, &out)),
        }
    }

    pub fn commit_tree(&self, tree: &Oid, parents: &[Oid], message: &str, who: &Identity) -> Result<Oid, GitError> {
        let tree = tree.to_hex();
        let parents: Vec<String> = parents.iter().map(Oid::to_hex).collect();
        let mut args = vec!["commit-tree", tree.as_str()];
        for parent in &parents {
            args.extend(["-p", parent.as_str()]);
        }
        args.extend(["-m", message]);
        let date = format!("{} +0000", who.time);
        let out = self.run_with(&args, |command| {
            command
                .env("GIT_AUTHOR_NAME", &who.name)
                .env("GIT_AUTHOR_EMAIL", &who.email)
                .env("GIT_AUTHOR_DATE", &date)
                .env("GIT_COMMITTER_NAME", &who.name)
                .env("GIT_COMMITTER_EMAIL", &who.email)
                .env("GIT_COMMITTER_DATE", &date);
        })?;
        if out.code != Some(0) {
            return Err(Self::failed(&args, &out));
        }
        Self::oid_line(&out.stdout)
    }

    /// A commit's committer time, seconds since the epoch.
    pub fn commit_time(&self, commit: &Oid) -> Result<u64, GitError> {
        let spec = commit.to_hex();
        let out = self.run_ok(&["show", "-s", "--format=%ct", &spec])?;
        let text = String::from_utf8_lossy(&out);
        text.trim().parse().map_err(|_| GitError::Parse(format!("commit time {text:?}")))
    }

    /// Whether `ancestor` is reachable from `descendant`.
    pub fn is_ancestor(&self, ancestor: &Oid, descendant: &Oid) -> Result<bool, GitError> {
        let (a, d) = (ancestor.to_hex(), descendant.to_hex());
        let args = ["merge-base", "--is-ancestor", &a, &d];
        let out = self.run(&args)?;
        match out.code {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(Self::failed(&args, &out)),
        }
    }

    /// Whether `oid` names a commit that is present here.
    pub fn has_object(&self, oid: &Oid) -> Result<bool, GitError> {
        let spec = format!("{oid}^{{commit}}");
        Ok(self.run(&["cat-file", "-e", &spec])?.code == Some(0))
    }

    /// The parents of a commit, in order.
    pub fn parents(&self, commit: &Oid) -> Result<Vec<Oid>, GitError> {
        let spec = commit.to_hex();
        let out = self.run_ok(&["rev-list", "--parents", "-n", "1", &spec])?;
        let text = String::from_utf8_lossy(&out);
        text.split_whitespace().skip(1).map(|p| Oid::from_hex(p).map_err(|e| GitError::Parse(e.to_string()))).collect()
    }

    /// Where a push to `remote` goes: its push URL when `remote` is a
    /// configured remote, else `remote` itself (a URL or a path). Reads of
    /// the destination must use this, not the fetch URL, which may be a
    /// mirror.
    pub fn push_destination(&self, remote: &str) -> Result<String, GitError> {
        let out = self.run(&["remote", "get-url", "--push", "--end-of-options", remote])?;
        let url = String::from_utf8_lossy(&out.stdout);
        match (out.code, url.lines().next().map(str::trim).filter(|line| !line.is_empty())) {
            (Some(0), Some(url)) => Ok(url.to_owned()),
            _ => Ok(remote.to_owned()),
        }
    }

    /// The destination's value of `target_ref`; `None` when it has no such ref.
    pub fn ls_remote(&self, destination: &str, target_ref: &str) -> Result<Option<Oid>, GitError> {
        let args = ["ls-remote", "--refs", "--end-of-options", destination, target_ref];
        let out = self.run_network(&args, &[])?;
        if out.code != Some(0) {
            return Err(Self::failed(&args, &out));
        }
        for line in out.stdout.split(|b| *b == b'\n') {
            let mut fields = line.splitn(2, |b| *b == b'\t');
            if let (Some(oid), Some(name)) = (fields.next(), fields.next()) {
                if name == target_ref.as_bytes() {
                    return Self::oid_line(oid).map(Some);
                }
            }
        }
        Ok(None)
    }

    /// Bring the destination's `target_ref` objects into this repository
    /// without moving any local ref.
    pub fn fetch(&self, destination: &str, target_ref: &str) -> Result<(), GitError> {
        let args = ["fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--end-of-options", destination, target_ref];
        let out = self.run_network(&args, &[])?;
        if out.code != Some(0) {
            return Err(Self::failed(&args, &out));
        }
        Ok(())
    }

    /// Push `src` to `target_ref` iff the destination still holds
    /// `expected_old` there. The exit code is returned as-is: the caller
    /// decides what happened by reading the destination, not this code.
    #[allow(clippy::too_many_arguments)]
    pub fn push_with_lease(
        &self,
        destination: &str,
        src: &Oid,
        target_ref: &str,
        expected_old: &Oid,
        push_options: &[String],
        no_verify: bool,
        env: &[(&str, &str)],
    ) -> Result<Option<i32>, GitError> {
        let lease = format!("--force-with-lease={target_ref}:{expected_old}");
        let refspec = format!("{src}:{target_ref}");
        let mut args = vec!["push", "--quiet", "--atomic", lease.as_str()];
        if no_verify {
            args.push("--no-verify");
        }
        for option in push_options {
            args.extend(["-o", option.as_str()]);
        }
        args.extend(["--end-of-options", destination, refspec.as_str()]);
        Ok(self.run_network(&args, env)?.code)
    }
}

fn parse_tree_record(record: &[u8]) -> Result<TreeEntry, GitError> {
    let bad = || GitError::Parse(format!("ls-tree record {:?}", String::from_utf8_lossy(record)));
    let tab = record.iter().position(|b| *b == b'\t').ok_or_else(bad)?;
    let meta = std::str::from_utf8(&record[..tab]).map_err(|_| bad())?;
    let mut fields = meta.split(' ');
    let mode = fields.next().and_then(|m| u32::from_str_radix(m, 8).ok()).ok_or_else(bad)?;
    let kind = match fields.next() {
        Some("blob") => EntryKind::Blob,
        Some("tree") => EntryKind::Tree,
        Some("commit") => EntryKind::Commit,
        _ => return Err(bad()),
    };
    let oid = fields.next().and_then(|o| Oid::from_hex(o).ok()).ok_or_else(bad)?;
    let path = std::str::from_utf8(&record[tab + 1..])
        .map_err(|_| GitError::NonUtf8Path(String::from_utf8_lossy(&record[tab + 1..]).into_owned()))?;
    Ok(TreeEntry { mode, kind, oid, path: path.to_owned() })
}

/// Helpers for building throwaway repositories in tests (all crates).
#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
    /// A trusted fixture root, independent of the invoking shell's umask.
    /// Default temporary-directory permissions may be group-writable.
    pub fn private_tempdir() -> std::io::Result<tempfile::TempDir> {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir()
    }

    /// Owns a test child process (`landd daemon`, helper subprocesses) and
    /// guarantees it is killed and reaped even if an assertion unwinds.
    pub struct ChildGuard(Option<std::process::Child>);

    impl ChildGuard {
        pub fn new(child: std::process::Child) -> Self {
            Self(Some(child))
        }

        pub fn id(&self) -> u32 {
            self.0.as_ref().expect("live child").id()
        }

        pub fn inner_mut(&mut self) -> &mut std::process::Child {
            self.0.as_mut().expect("live child")
        }

        pub fn wait(mut self) -> std::io::Result<std::process::ExitStatus> {
            self.0.take().expect("live child").wait()
        }

        pub fn wait_with_output(mut self) -> std::io::Result<std::process::Output> {
            self.0.take().expect("live child").wait_with_output()
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    use super::*;

    pub fn who() -> Identity {
        Identity { name: "Test".into(), email: "test@example.invalid".into(), time: 1_700_000_000 }
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Test")
            .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
            .env("GIT_AUTHOR_DATE", "1700000000 +0000")
            .env("GIT_COMMITTER_NAME", "Test")
            .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
            .env("GIT_COMMITTER_DATE", "1700000000 +0000")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// A bare "forge" and a clone of it whose `origin` is that forge.
    pub struct Sandbox {
        pub forge: PathBuf,
        pub work: PathBuf,
    }

    impl Sandbox {
        /// Create both under `root`, with one commit of `files` on `main`.
        pub fn new(root: &Path, files: &[(&str, &str)]) -> Self {
            let (forge, work) = (root.join("forge.git"), root.join("work"));
            std::fs::create_dir_all(&forge).unwrap();
            std::fs::create_dir_all(&work).unwrap();
            git(&forge, &["init", "--quiet", "--bare", "--initial-branch=main"]);
            git(&work, &["init", "--quiet", "--initial-branch=main"]);
            git(&work, &["remote", "add", "origin", forge.to_str().unwrap()]);
            let sandbox = Self { forge, work };
            sandbox.commit("main", "initial", files, &[]);
            sandbox.git(&["push", "--quiet", "origin", "main"]);
            sandbox
        }

        pub fn git(&self, args: &[&str]) -> String {
            git(&self.work, args)
        }

        pub fn forge_git(&self, args: &[&str]) -> String {
            git(&self.forge, args)
        }

        /// Check out `branch` (creating it from the current HEAD if new),
        /// write and delete files, commit, and return the commit id.
        pub fn commit(&self, branch: &str, message: &str, write: &[(&str, &str)], delete: &[&str]) -> Oid {
            let exists = Command::new("git")
                .arg("-C")
                .arg(&self.work)
                .args(["rev-parse", "--verify", "--quiet", &format!("refs/heads/{branch}")])
                .output()
                .unwrap()
                .status
                .success();
            let unborn = Command::new("git")
                .arg("-C")
                .arg(&self.work)
                .args(["rev-parse", "--verify", "--quiet", "HEAD"])
                .output()
                .unwrap()
                .status
                .code()
                != Some(0);
            if exists {
                self.git(&["checkout", "--quiet", branch]);
            } else if !unborn {
                self.git(&["checkout", "--quiet", "-b", branch]);
            }
            for (path, content) in write {
                let full = self.work.join(path);
                std::fs::create_dir_all(full.parent().unwrap()).unwrap();
                std::fs::write(full, content).unwrap();
            }
            for path in delete {
                std::fs::remove_file(self.work.join(path)).unwrap();
            }
            self.git(&["add", "-A"]);
            self.git(&["commit", "--quiet", "--allow-empty", "-m", message]);
            Oid::from_hex(&self.git(&["rev-parse", "HEAD"])).unwrap()
        }

        /// A branch from `from` with one commit; leaves `main` checked out.
        pub fn lane(&self, name: &str, from: &str, write: &[(&str, &str)]) -> Oid {
            self.git(&["checkout", "--quiet", from]);
            let oid = self.commit(name, name, write, &[]);
            self.git(&["checkout", "--quiet", "main"]);
            oid
        }

        pub fn repo(&self) -> GitRepo {
            GitRepo::open(&self.work).unwrap()
        }

        pub fn forge_head(&self, target_ref: &str) -> Oid {
            Oid::from_hex(&self.forge_git(&["rev-parse", target_ref])).unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    #[test]
    fn ls_tree_and_blob_reader_read_objects_directly() {
        let dir = crate::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "alpha\n"), ("dir/b with space.txt", "beta\n")]);
        let repo = sandbox.repo();

        let blobs = repo.ls_tree("HEAD", false).unwrap();
        assert_eq!(blobs.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(), ["a.txt", "dir/b with space.txt"]);
        assert_eq!(blobs[0].oid, Oid::git_blob_sha1(b"alpha\n"));
        assert_eq!((blobs[0].mode, blobs[0].kind), (0o100644, EntryKind::Blob));

        let with_trees = repo.ls_tree("HEAD", true).unwrap();
        assert_eq!(with_trees.len(), 3);
        assert_eq!((with_trees[1].path.as_str(), with_trees[1].kind), ("dir", EntryKind::Tree));

        let mut reader = repo.blob_reader().unwrap();
        assert_eq!(reader.read(&blobs[1].oid).unwrap(), b"beta\n");
        assert_eq!(reader.read(&blobs[0].oid).unwrap(), b"alpha\n");
        assert!(matches!(reader.read(&Oid::git_blob_sha1(b"absent")), Err(GitError::Missing(_))));
        // An oversized blob is refused without losing the stream's framing.
        assert!(matches!(reader.read_limited(&blobs[0].oid, Some(3)), Err(GitError::TooLarge { size: 6, limit: 3, .. })));
        // Asking the blob reader for a tree is an error, not bytes.
        let tree = repo.tree_of("HEAD").unwrap();
        assert_eq!(reader.resolve_tree("HEAD").unwrap(), tree);
        // The stream stays usable after a miss and is reused from the pool.
        assert_eq!(reader.read(&blobs[0].oid).unwrap(), b"alpha\n");
        drop(reader);
        assert_eq!(repo.readers.lock().unwrap().len(), 1);
        assert_eq!(repo.read_blob(&blobs[1].oid).unwrap(), b"beta\n");
        assert_eq!(repo.readers.lock().unwrap().len(), 1);
        assert!(repo.ls_tree("no-such-rev", false).is_err());
    }

    #[test]
    fn merge_tree_reports_clean_trees_and_conflicting_paths() {
        let dir = crate::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "one\n"), ("b.txt", "one\n")]);
        let left = sandbox.lane("left", "main", &[("a.txt", "left\n")]);
        let right = sandbox.lane("right", "main", &[("b.txt", "right\n")]);
        let clash = sandbox.lane("clash", "main", &[("a.txt", "clash\n")]);
        let repo = sandbox.repo();
        let status_before = sandbox.git(&["status", "--porcelain"]);

        let MergeOutcome::Clean { tree } = repo.merge_tree(&left, &right).unwrap() else { panic!("expected clean") };
        let merged = repo.commit_tree(&tree, &[left, right], "merge", &who()).unwrap();
        assert_eq!(repo.parents(&merged).unwrap(), vec![left, right]);
        assert!(repo.is_ancestor(&left, &merged).unwrap());
        assert!(!repo.is_ancestor(&merged, &left).unwrap());
        // Same inputs, same identity, same commit id.
        assert_eq!(repo.commit_tree(&tree, &[left, right], "merge", &who()).unwrap(), merged);

        assert_eq!(repo.merge_tree(&left, &clash).unwrap(), MergeOutcome::Conflict { conflicting_paths: vec!["a.txt".into()] });
        assert_eq!(repo.merge_base(&left, &right).unwrap(), Some(repo.rev_parse("main").unwrap()));
        assert_eq!(repo.commit_time(&merged).unwrap(), who().time);
        assert_eq!(sandbox.git(&["status", "--porcelain"]), status_before);
        assert_eq!(sandbox.git(&["rev-parse", "--abbrev-ref", "HEAD"]), "main");
    }

    #[test]
    fn tooth_lease_push_is_a_strict_compare_and_swap() {
        let dir = crate::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "one\n")]);
        let repo = sandbox.repo();
        let base = repo.rev_parse("main").unwrap();
        let first = sandbox.lane("first", "main", &[("a.txt", "first\n")]);
        let second = sandbox.lane("second", "main", &[("b.txt", "second\n")]);
        let main = "refs/heads/main";

        let forge = repo.push_destination("origin").unwrap();
        assert_eq!(forge, sandbox.forge.to_str().unwrap());
        assert_eq!(repo.ls_remote(&forge, main).unwrap(), Some(base));
        assert_eq!(repo.ls_remote(&forge, "refs/heads/absent").unwrap(), None);
        assert_eq!(repo.push_with_lease(&forge, &first, main, &base, &[], true, &[]).unwrap(), Some(0));
        assert_eq!(sandbox.forge_head(main), first);

        // The lease names the old base, which the forge no longer holds.
        assert_ne!(repo.push_with_lease(&forge, &second, main, &base, &[], true, &[]).unwrap(), Some(0));
        assert_eq!(sandbox.forge_head(main), first);
    }

    /// The read of the destination follows the push URL, not the fetch URL.
    #[test]
    fn tooth_destination_reads_use_the_push_url() {
        let dir = crate::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "one\n")]);
        let mirror = dir.path().join("stale-mirror.git");
        sandbox.git(&["clone", "--quiet", "--bare", sandbox.forge.to_str().unwrap(), mirror.to_str().unwrap()]);
        // Fetches come from the mirror; pushes go to the forge.
        sandbox.git(&["remote", "set-url", "origin", mirror.to_str().unwrap()]);
        sandbox.git(&["remote", "set-url", "--push", "origin", sandbox.forge.to_str().unwrap()]);
        let repo = sandbox.repo();
        let base = repo.rev_parse("main").unwrap();
        let next = sandbox.lane("next", "main", &[("a.txt", "two\n")]);
        let destination = repo.push_destination("origin").unwrap();
        assert_eq!(destination, sandbox.forge.to_str().unwrap());
        assert_eq!(repo.push_with_lease(&destination, &next, "refs/heads/main", &base, &[], true, &[]).unwrap(), Some(0));
        assert_eq!(repo.ls_remote(&destination, "refs/heads/main").unwrap(), Some(next));
        // The fetch URL still shows the old tip.
        assert_eq!(repo.ls_remote(mirror.to_str().unwrap(), "refs/heads/main").unwrap(), Some(base));
        // A URL or path that is not a configured remote is its own destination.
        assert_eq!(repo.push_destination("/some/where.git").unwrap(), "/some/where.git");
        assert_eq!(canonical_repo_id("ssh://forge/x.git/"), "ssh://forge/x");
        assert_eq!(canonical_repo_id("ssh://forge/x"), "ssh://forge/x");
        let spelled = format!("{}/work/../forge.git/", dir.path().display());
        assert_eq!(canonical_repo_id(&spelled), canonical_repo_id(sandbox.forge.to_str().unwrap()));
    }

    #[test]
    fn tooth_network_commands_die_at_their_deadline() {
        let dir = crate::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "one\n")]);
        let repo = sandbox.repo().with_network_timeout(Duration::from_millis(300));
        // A transport that never answers.
        let marker = dir.path().join("grandchild-survived");
        let script = dir.path().join("hang.sh");
        std::fs::write(&script, format!("#!/bin/sh\n(sleep 3; touch {}) &\nsleep 60\n", marker.display())).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let hang = format!("ext::{}", script.display());
        std::env::set_var("GIT_ALLOW_PROTOCOL", "ext:file");
        let started = Instant::now();
        let result = repo.ls_remote(&hang, "refs/heads/main");
        assert!(matches!(result, Err(GitError::Timeout { .. })), "{result:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
        let oid = repo.rev_parse("main").unwrap();
        assert!(matches!(
            repo.push_with_lease(&hang, &oid, "refs/heads/main", &oid, &[], true, &[]),
            Err(GitError::Timeout { .. })
        ));
        std::thread::sleep(Duration::from_millis(3500));
        assert!(!marker.exists(), "the transport's children outlived the deadline");
    }

    #[test]
    fn tooth_exited_network_leaders_do_not_leave_pipe_holders_alive() {
        let dir = crate::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "one\n")]);
        let repo = sandbox.repo().with_network_timeout(Duration::from_millis(300));
        let marker = dir.path().join("pipe-holder-survived");
        let script = dir.path().join("exit-with-child.sh");
        // Close the protocol stdout in the descendant, but keep Git's stderr
        // open. Git exits on the protocol EOF while the pipe reader still waits.
        std::fs::write(&script, format!("#!/bin/sh\n(sleep 3; touch {}) >/dev/null &\nexit 0\n", marker.display())).unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        std::env::set_var("GIT_ALLOW_PROTOCOL", "ext:file");
        let started = Instant::now();
        let result = repo.ls_remote(&format!("ext::{}", script.display()), "refs/heads/main");
        // Preserve the Git exit failure, rather than turning early EOF into a
        // timeout or letting the reader wait for the descendant's three seconds.
        assert!(matches!(result, Err(GitError::Failed { .. })), "{result:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(3500));
        assert!(!marker.exists(), "an exited transport left its descendants running");
    }

    #[test]
    fn tooth_inherited_git_location_variables_are_ignored() {
        let dir = crate::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "mine\n")]);
        let other = crate::git::testkit::private_tempdir().unwrap();
        let elsewhere = Sandbox::new(other.path(), &[("b.txt", "theirs\n")]);
        // What a hook or a wrapper script would leave in the environment.
        let mut command = sandbox.repo().command();
        command.args(["rev-parse", "HEAD"]);
        let clean: Vec<_> = command.get_envs().filter(|(_, v)| v.is_none()).map(|(k, _)| k.to_owned()).collect();
        for name in LOCATION_ENV {
            assert!(clean.iter().any(|k| k == name), "{name} is not removed");
        }
        let hooked = GitRepo {
            dir: elsewhere.work.clone(),
            readers: Mutex::new(Vec::new()),
            hook: true,
            network_timeout: Duration::from_secs(1),
        };
        let kept: Vec<_> = hooked.command().get_envs().filter(|(_, v)| v.is_none()).map(|(k, _)| k.to_owned()).collect();
        assert!(!kept.iter().any(|k| k == "GIT_DIR") && kept.iter().any(|k| k == "GIT_WORK_TREE"));
    }

    #[test]
    fn tooth_paths_that_are_not_utf8_are_refused() {
        use std::os::unix::ffi::OsStrExt;
        let dir = crate::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "one\n")]);
        std::fs::write(sandbox.work.join(std::ffi::OsStr::from_bytes(b"caf\xe9.py")), "x = 1\n").unwrap();
        sandbox.git(&["add", "-A"]);
        sandbox.git(&["commit", "--quiet", "-m", "latin-1 name"]);
        assert!(matches!(sandbox.repo().ls_tree("HEAD", false), Err(GitError::NonUtf8Path(_))));
    }

    #[test]
    fn ls_tree_lists_from_the_root_whatever_directory_is_opened() {
        let dir = crate::git::testkit::private_tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "one\n"), ("sub/b.txt", "two\n")]);
        let inside = GitRepo::open(sandbox.work.join("sub")).unwrap();
        let paths: Vec<String> = inside.ls_tree("HEAD", false).unwrap().into_iter().map(|e| e.path).collect();
        assert_eq!(paths, ["a.txt", "sub/b.txt"]);
    }
}
