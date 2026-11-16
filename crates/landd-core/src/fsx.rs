//! Atomic, durable file primitives for content-addressed stores.
//!
//! Stores address files by a two-level shard of their key (`ab/cd/<key>`), so
//! a lookup is one `open` and nothing ever lists a directory.

use std::collections::hash_map::RandomState;
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);
const TEMP_ATTEMPTS: u32 = 16;

/// An unpredictable 64-bit value: `RandomState` is seeded by the OS per
/// instance, so a name built from it cannot collide with a file a crashed
/// process (or a recycled pid) left behind except by chance.
fn random_u64() -> u64 {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.write_u32(std::process::id());
    hasher.finish()
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// How many levels above a leaf a store ever creates: two shard levels,
/// a key directory, a space directory and the store root itself.
const SYNC_DEPTH: usize = 6;

/// `create_dir_all`. With `sync`, the directory chain is made durable: the
/// parent of every directory this call created is synced, and so is the
/// parent of each of the nearest [`SYNC_DEPTH`] ancestors that already
/// existed. The second part matters under concurrency: another writer may
/// have created an ancestor a moment ago and not yet synced its entry, and
/// a file made durable below a directory whose own entry is lost is lost
/// with it. Syncing a directory that is already durable is a no-op for the
/// file system, and the bound keeps the cost constant.
pub fn create_dirs(dir: &Path, sync: bool) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut probe = dir;
    while !probe.as_os_str().is_empty() && !probe.is_dir() {
        missing.push(probe);
        match probe.parent() {
            Some(parent) => probe = parent,
            None => break,
        }
    }
    let existing = probe;
    for created in missing.into_iter().rev() {
        match fs::create_dir(created) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists && created.is_dir() => {}
            Err(err) => return Err(err),
        }
    }
    if sync {
        let mut level = Some(dir);
        let mut above_existing = 0;
        while let Some(current) = level.filter(|p| !p.as_os_str().is_empty()) {
            let Some(parent) = current.parent().filter(|p| !p.as_os_str().is_empty()) else { break };
            fsync_dir(parent)?;
            // `current` already existed when this call began.
            if existing.starts_with(current) {
                above_existing += 1;
                if above_existing >= SYNC_DEPTH {
                    break;
                }
            }
            level = Some(parent);
        }
    }
    Ok(())
}

fn write_temp(path: &Path, bytes: &[u8], sync: bool) -> io::Result<PathBuf> {
    if let Some(parent) = path.parent() {
        create_dirs(parent, sync)?;
    }
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    for _ in 0..TEMP_ATTEMPTS {
        let temp = path.with_file_name(format!(".tmp-{:016x}-{name}", random_u64()));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&temp) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        };
        let written = file.write_all(bytes).and_then(|()| if sync { file.sync_all() } else { Ok(()) });
        if let Err(err) = written {
            let _ = fs::remove_file(&temp);
            return Err(err);
        }
        return Ok(temp);
    }
    Err(io::Error::new(io::ErrorKind::AlreadyExists, "no free temporary name"))
}

/// Durably create `path` with `bytes` iff it does not exist (`O_EXCL`
/// semantics with complete content: readers never see a partial file).
/// `Ok(false)` means another writer got there first. Every sync error is an
/// error: a record that may not survive power loss was not written.
pub fn create_exclusive(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let temp = write_temp(path, bytes, true)?;
    let linked = fs::hard_link(&temp, path);
    let _ = fs::remove_file(&temp);
    match linked {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                fsync_dir(parent)?;
            }
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err),
    }
}

/// Replace `path` atomically (temp-and-rename). With `sync` the content and
/// the directory entry are flushed; caches that verify a checksum on read
/// may skip it.
pub fn replace_atomic(path: &Path, bytes: &[u8], sync: bool) -> io::Result<()> {
    let temp = write_temp(path, bytes, sync)?;
    if let Err(err) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    if sync {
        if let Some(parent) = path.parent() {
            fsync_dir(parent)?;
        }
    }
    Ok(())
}

/// `Ok(None)` when the file does not exist.
pub fn read_optional(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// `<root>/ab/cd/<hex><suffix>` for a hex key of at least four characters.
pub fn shard2(root: &Path, hex: &str, suffix: &str) -> PathBuf {
    root.join(&hex[..2]).join(&hex[2..4]).join(format!("{hex}{suffix}"))
}

/// `<root>/ab/<hex><suffix>`.
pub fn shard1(root: &Path, hex: &str, suffix: &str) -> PathBuf {
    root.join(&hex[..2]).join(format!("{hex}{suffix}"))
}

/// Create `dir` (and parents) private to this user and refuse a directory
/// that someone else owns or that group or others can write: whoever can
/// write a trusted store can forge what it holds.
#[cfg(unix)]
pub fn private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    if !dir.is_dir() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    let meta = fs::metadata(dir)?;
    // SAFETY: `geteuid` reads the process's effective uid; it has no failure mode.
    let me = unsafe { libc::geteuid() };
    if meta.uid() != me {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is owned by another user", dir.display())));
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{} is writable by group or others", dir.display())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_exclusive_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let path = shard2(dir.path(), "abcdef", ".json");
        assert!(create_exclusive(&path, b"first").unwrap());
        assert!(!create_exclusive(&path, b"second").unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        assert_eq!(path, dir.path().join("ab").join("cd").join("abcdef.json"));
    }

    #[test]
    fn replace_and_read_optional() {
        let dir = tempfile::tempdir().unwrap();
        let path = shard1(dir.path(), "abcdef", ".bin");
        assert_eq!(read_optional(&path).unwrap(), None);
        replace_atomic(&path, b"one", false).unwrap();
        replace_atomic(&path, b"two", true).unwrap();
        assert_eq!(read_optional(&path).unwrap().unwrap(), b"two");
    }

    #[test]
    fn tooth_stale_temporaries_do_not_block_writers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("record.json");
        // What a crashed writer with any pid and counter could have left.
        for n in 0..64u64 {
            fs::write(dir.path().join(format!(".tmp-{n:016x}-record.json")), b"stale").unwrap();
            fs::write(dir.path().join(format!(".tmp-{}-{n}-record.json", std::process::id())), b"stale").unwrap();
        }
        assert!(create_exclusive(&path, b"fresh").unwrap());
        replace_atomic(&path, b"again", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"again");
        let names: std::collections::BTreeSet<u64> = (0..2000).map(|_| random_u64()).collect();
        assert_eq!(names.len(), 2000);
    }

    #[test]
    fn create_dirs_is_idempotent_and_nested() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("a/b/c/d");
        create_dirs(&deep, true).unwrap();
        create_dirs(&deep, true).unwrap();
        assert!(deep.is_dir());
        fs::write(dir.path().join("file"), b"x").unwrap();
        assert!(create_dirs(&dir.path().join("file/sub"), true).is_err());
    }

    /// Two writers race to create the same shard directories. Whoever
    /// loses the race to create a directory must still make its entry
    /// durable before trusting a file below it: every level of the chain
    /// is synced by every writer, not only by the one that created it.
    #[test]
    fn tooth_every_writer_syncs_the_directory_chain_it_relies_on() {
        let dir = tempfile::tempdir().unwrap();
        let leaf = dir.path().join("store/bindings/ab/cd/key");
        // Writer A created the chain and died before syncing anything.
        fs::create_dir_all(&leaf).unwrap();
        // Writer B finds every directory present. It must still be able to
        // sync the chain (and does: a missing or unreadable level is an error).
        create_dirs(&leaf, true).unwrap();
        let blocked = dir.path().join("store/bindings/ab");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).unwrap();
        let result = create_dirs(&leaf, true);
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o755)).unwrap();
        // SAFETY: `geteuid` cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            assert!(result.is_err(), "a level of the chain that cannot be synced must fail the write");
        }
        // Concurrent creators of one new chain all succeed and all sync.
        let shared = dir.path().join("race/ab/cd/key");
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|i| {
                    let shared = &shared;
                    scope.spawn(move || create_exclusive(&shared.join(format!("r{i}.json")), b"x").unwrap())
                })
                .collect();
            assert!(handles.into_iter().all(|h| h.join().unwrap()));
        });
    }

    #[test]
    fn tooth_private_dir_refuses_group_or_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        private_dir(&store).unwrap();
        assert_eq!(fs::metadata(&store).unwrap().permissions().mode() & 0o777, 0o700);
        private_dir(&store).unwrap();
        fs::set_permissions(&store, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(private_dir(&store).is_err());
        fs::set_permissions(&store, fs::Permissions::from_mode(0o750)).unwrap();
        private_dir(&store).unwrap();
    }
}
