//! Git plumbing. Trees and blobs are read straight from the object store
//! (`ls-tree -r -z`, a persistent `cat-file --batch`), merges are computed
//! with `merge-tree --write-tree`, and nothing here touches a working tree
//! or the index. Outcomes come from exit codes and NUL-framed plumbing
//! output, never from human-readable messages.

use crate::digest::Oid;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

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

    fn read(&mut self, oid: &Oid) -> Result<Vec<u8>, GitError> {
        self.stdin.write_all(format!("{oid}\n").as_bytes())?;
        self.stdin.flush()?;
        let mut header = String::new();
        self.stdout.read_line(&mut header)?;
        let mut fields = header.trim_end().split(' ');
        let (_name, kind, size) = (fields.next(), fields.next(), fields.next());
        if kind == Some("missing") || kind.is_none() {
            return Err(GitError::Missing(oid.to_hex()));
        }
        let size: usize =
            size.and_then(|s| s.parse().ok()).ok_or_else(|| GitError::Parse(format!("cat-file header {header:?}")))?;
        let mut content = vec![0u8; size + 1];
        self.stdout.read_exact(&mut content)?;
        content.pop(); // the newline after the object
        Ok(content)
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
    pub fn read(&mut self, oid: &Oid) -> Result<Vec<u8>, GitError> {
        let result = self.inner.as_mut().expect("reader is live").read(oid);
        if matches!(result, Err(GitError::Io(_)) | Err(GitError::Parse(_))) {
            // The stream is out of sync; do not hand it to the next caller.
            self.inner = None;
        }
        result
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
}

impl std::fmt::Debug for GitRepo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GitRepo({})", self.dir.display())
    }
}

impl GitRepo {
    /// `dir` may be a working tree or a bare repository.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, GitError> {
        let repo = Self { dir: dir.into(), readers: Mutex::new(Vec::new()) };
        repo.run_ok(&["rev-parse", "--git-dir"])?;
        Ok(repo)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn command(&self) -> Command {
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(&self.dir)
            .env("LC_ALL", "C")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0");
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

    fn failed(args: &[&str], out: &RawOutput) -> GitError {
        GitError::Failed {
            args: args.join(" "),
            code: out.code,
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        }
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

    /// Every entry under `rev`, recursively. With `with_trees`, directories
    /// are listed too (before their contents).
    pub fn ls_tree(&self, rev: &str, with_trees: bool) -> Result<Vec<TreeEntry>, GitError> {
        let mut command = self.command();
        command.args(["ls-tree", "-r", "-z"]);
        if with_trees {
            command.arg("-t");
        }
        command.args(["--end-of-options", rev]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let mut reader = BufReader::with_capacity(1 << 16, child.stdout.take().expect("piped stdout"));
        let mut entries = Vec::new();
        let mut record = Vec::with_capacity(256);
        loop {
            record.clear();
            if reader.read_until(0, &mut record)? == 0 {
                break;
            }
            if record.last() == Some(&0) {
                record.pop();
            }
            entries.push(parse_tree_record(&record)?);
        }
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        let status = child.wait()?;
        if !status.success() {
            return Err(GitError::Failed { args: format!("ls-tree -r -z {rev}"), code: status.code(), stderr });
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

    /// Merge `theirs` into `ours` (both commits) without a working tree.
    pub fn merge_tree(&self, ours: &Oid, theirs: &Oid) -> Result<MergeOutcome, GitError> {
        let (ours, theirs) = (ours.to_hex(), theirs.to_hex());
        let args = ["merge-tree", "--write-tree", "-z", "--name-only", "--no-messages", &ours, &theirs];
        let out = self.run(&args)?;
        let mut fields = out.stdout.split(|b| *b == 0).filter(|f| !f.is_empty());
        match out.code {
            Some(0) => {
                let tree = fields.next().ok_or_else(|| GitError::Parse("merge-tree printed no tree".into()))?;
                Ok(MergeOutcome::Clean { tree: Self::oid_line(tree)? })
            }
            Some(1) => {
                let _tree_with_markers = fields.next();
                let mut conflicting_paths: Vec<String> =
                    fields.map(|f| String::from_utf8_lossy(f).into_owned()).collect();
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

    /// The destination's value of `target_ref`; `None` when it has no such ref.
    pub fn ls_remote(&self, remote: &str, target_ref: &str) -> Result<Option<Oid>, GitError> {
        let out = self.run_ok(&["ls-remote", "--refs", "--end-of-options", remote, target_ref])?;
        for line in out.split(|b| *b == b'\n') {
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
    pub fn fetch(&self, remote: &str, target_ref: &str) -> Result<(), GitError> {
        self.run_ok(&["fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--end-of-options", remote, target_ref])
            .map(drop)
    }

    /// Push `src` to `target_ref` iff the destination still holds
    /// `expected_old` there. The exit code is returned as-is: the caller
    /// decides what happened by reading the destination, not this code.
    pub fn push_with_lease(
        &self,
        remote: &str,
        src: &Oid,
        target_ref: &str,
        expected_old: &Oid,
        push_options: &[String],
    ) -> Result<Option<i32>, GitError> {
        let lease = format!("--force-with-lease={target_ref}:{expected_old}");
        let refspec = format!("{src}:{target_ref}");
        let mut args = vec!["push", "--quiet", "--no-verify", "--atomic", lease.as_str()];
        for option in push_options {
            args.extend(["-o", option.as_str()]);
        }
        args.extend(["--end-of-options", remote, refspec.as_str()]);
        Ok(self.run(&args)?.code)
    }

    /// Materialize `tree` into `dest` (no `.git`, no index, no checkout).
    pub fn export_tree(&self, tree: &Oid, dest: &Path) -> Result<(), GitError> {
        std::fs::create_dir_all(dest)?;
        let spec = tree.to_hex();
        let mut archive = self
            .command()
            .args(["archive", "--format=tar", &spec])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let tar = Command::new("tar")
            .arg("-xf")
            .arg("-")
            .arg("-C")
            .arg(dest)
            .stdin(archive.stdout.take().expect("piped stdout"))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()?;
        let archived = archive.wait()?;
        if !archived.success() || !tar.status.success() {
            return Err(GitError::Failed {
                args: format!("archive {spec} | tar -x"),
                code: archived.code().or(tar.status.code()),
                stderr: String::from_utf8_lossy(&tar.stderr).trim().to_owned(),
            });
        }
        Ok(())
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
    Ok(TreeEntry { mode, kind, oid, path: String::from_utf8_lossy(&record[tab + 1..]).into_owned() })
}

/// Helpers for building throwaway repositories in tests (all crates).
#[cfg(any(test, feature = "testkit"))]
pub mod testkit {
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
        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
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

        assert_eq!(
            repo.merge_tree(&left, &clash).unwrap(),
            MergeOutcome::Conflict { conflicting_paths: vec!["a.txt".into()] }
        );
        assert_eq!(sandbox.git(&["status", "--porcelain"]), status_before);
        assert_eq!(sandbox.git(&["rev-parse", "--abbrev-ref", "HEAD"]), "main");
    }

    #[test]
    fn tooth_lease_push_is_a_strict_compare_and_swap() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "one\n")]);
        let repo = sandbox.repo();
        let base = repo.rev_parse("main").unwrap();
        let first = sandbox.lane("first", "main", &[("a.txt", "first\n")]);
        let second = sandbox.lane("second", "main", &[("b.txt", "second\n")]);
        let main = "refs/heads/main";

        assert_eq!(repo.ls_remote("origin", main).unwrap(), Some(base));
        assert_eq!(repo.ls_remote("origin", "refs/heads/absent").unwrap(), None);
        assert_eq!(repo.push_with_lease("origin", &first, main, &base, &[]).unwrap(), Some(0));
        assert_eq!(sandbox.forge_head(main), first);

        // The lease names the old base, which the forge no longer holds.
        assert_ne!(repo.push_with_lease("origin", &second, main, &base, &[]).unwrap(), Some(0));
        assert_eq!(sandbox.forge_head(main), first);
    }

    #[test]
    fn export_tree_writes_files_and_no_git_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sandbox = Sandbox::new(dir.path(), &[("a.txt", "alpha\n"), ("sub/run.sh", "echo hi\n")]);
        let repo = sandbox.repo();
        let dest = dir.path().join("export");
        repo.export_tree(&repo.tree_of("HEAD").unwrap(), &dest).unwrap();
        assert_eq!(std::fs::read(dest.join("sub/run.sh")).unwrap(), b"echo hi\n");
        assert!(!dest.join(".git").exists());
    }
}
