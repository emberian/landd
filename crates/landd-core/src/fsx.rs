//! Atomic file primitives for content-addressed stores.
//!
//! Stores address files by a two-level shard of their key (`ab/cd/<key>`), so
//! a lookup is one `open` and nothing ever lists a directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_sibling(path: &Path) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    path.with_file_name(format!(".tmp-{}-{}-{}", std::process::id(), n, name))
}

fn write_temp(path: &Path, bytes: &[u8], sync: bool) -> io::Result<PathBuf> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = temp_sibling(path);
    let mut file = OpenOptions::new().write(true).create_new(true).open(&temp)?;
    let written = file.write_all(bytes).and_then(|()| if sync { file.sync_all() } else { Ok(()) });
    if let Err(err) = written {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    Ok(temp)
}

/// Durably create `path` with `bytes` iff it does not exist (`O_EXCL`
/// semantics with complete content: readers never see a partial file).
/// `Ok(false)` means another writer got there first.
pub fn create_exclusive(path: &Path, bytes: &[u8]) -> io::Result<bool> {
    let temp = write_temp(path, bytes, true)?;
    let linked = fs::hard_link(&temp, path);
    let _ = fs::remove_file(&temp);
    match linked {
        Ok(()) => {
            sync_parent(path);
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(err),
    }
}

/// Replace `path` atomically (temp-and-rename). With `sync` the content is
/// flushed first; caches that verify a checksum on read may skip it.
pub fn replace_atomic(path: &Path, bytes: &[u8], sync: bool) -> io::Result<()> {
    let temp = write_temp(path, bytes, sync)?;
    if let Err(err) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    if sync {
        sync_parent(path);
    }
    Ok(())
}

fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
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
}
