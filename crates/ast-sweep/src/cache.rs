//! `BlobFactsCache`: summaries keyed by content, kept forever.
//!
//! ```text
//! <root>/blobs/v<N>/<kind>/ab/<blob oid>.bin   one blob's facts
//! <root>/packs/v<N>/ab/<pack key>.bin          facts of one run of sibling files
//! <root>/catalogs/v<N>/ab/<blob oid>.bin       the keys of one settings catalog
//! ```
//!
//! A git object id names its bytes, so an entry is never stale and nothing
//! here reads a clock or lists a directory. A pack holds the facts of a run
//! of fact-bearing files in one directory and is keyed by the digest of
//! their `(blob id, kind)` list, so a warm sweep costs one read per run whose
//! files are unchanged. Everything read or written by a handle is also kept
//! in memory (bounded), by pack and by blob, which is what a long-lived
//! daemon sweeps from: after a change it parses the changed blobs and reads
//! nothing else.
//! Entries carry a checksum; a torn or foreign file is a miss and gets
//! rewritten.

use crate::facts::{FileFacts, FileKind, FACTS_VERSION};
use landd_core::{fsx, Digest32, Oid};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Entries kept in memory per cache handle; past these the tier starts over.
const MEMORY_PACKS: usize = 1 << 15;
const MEMORY_BLOBS: usize = 1 << 18;

const MAGIC: &[u8; 8] = b"LDFACTS\x01";

/// The facts of one pack's files, in the order of the pack key's members.
pub type Pack = Arc<Vec<Arc<FileFacts>>>;

type BlobMemory = HashMap<(Oid, FileKind), Arc<FileFacts>>;

/// The settings keys one catalog blob declares, sorted and unique.
pub type CatalogKeys = Arc<Vec<String>>;

#[derive(Debug, Clone)]
pub struct BlobFactsCache {
    root: PathBuf,
    memory: Arc<Mutex<HashMap<Digest32, Pack>>>,
    blobs: Arc<Mutex<BlobMemory>>,
    catalogs: Arc<Mutex<HashMap<Oid, CatalogKeys>>>,
}

impl BlobFactsCache {
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into(), memory: Arc::default(), blobs: Arc::default(), catalogs: Arc::default() }
    }

    fn remember(&self, key: &Digest32, members: &[(Oid, FileKind)], pack: &Pack) {
        {
            let mut memory = self.memory.lock().expect("pack memory");
            if memory.len() >= MEMORY_PACKS {
                memory.clear();
            }
            memory.insert(*key, pack.clone());
        }
        let mut blobs = self.blobs.lock().expect("blob memory");
        if blobs.len() + members.len() > MEMORY_BLOBS {
            blobs.clear();
        }
        for (member, facts) in members.iter().zip(pack.iter()) {
            blobs.insert(*member, facts.clone());
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn blob_path(&self, kind: FileKind, oid: &Oid) -> PathBuf {
        let dir = self.root.join("blobs").join(format!("v{FACTS_VERSION}")).join(kind.slug());
        fsx::shard1(&dir, &oid.to_hex(), ".bin")
    }

    /// The pack key for a directory's fact-bearing files, in path order.
    pub fn pack_key(members: impl Iterator<Item = (Oid, FileKind)>) -> Digest32 {
        let mut hasher = blake3::Hasher::new_derive_key("ast-sweep directory pack v1");
        for (oid, kind) in members {
            hasher.update(&[oid.as_bytes().len() as u8]);
            hasher.update(oid.as_bytes());
            hasher.update(kind.slug().as_bytes());
            hasher.update(&[0]);
        }
        Digest32::from_bytes(*hasher.finalize().as_bytes())
    }

    pub fn pack_path(&self, key: &Digest32) -> PathBuf {
        let dir = self.root.join("packs").join(format!("v{FACTS_VERSION}"));
        fsx::shard1(&dir, &key.to_hex(), ".bin")
    }

    /// One blob's facts and whether they came from memory.
    pub fn get_blob(&self, kind: FileKind, oid: &Oid) -> Option<(Arc<FileFacts>, bool)> {
        if let Some(facts) = self.blobs.lock().expect("blob memory").get(&(*oid, kind)) {
            return Some((facts.clone(), true));
        }
        let facts: FileFacts = read_entry(&self.blob_path(kind, oid))?;
        Some((Arc::new(facts), false))
    }

    pub fn put_blob(&self, kind: FileKind, oid: &Oid, facts: &FileFacts) -> std::io::Result<()> {
        write_entry(&self.blob_path(kind, oid), facts)
    }

    fn catalog_path(&self, oid: &Oid) -> PathBuf {
        let dir = self.root.join("catalogs").join(format!("v{FACTS_VERSION}"));
        fsx::shard1(&dir, &oid.to_hex(), ".bin")
    }

    /// The settings keys a catalog blob declares.
    pub fn get_catalog(&self, oid: &Oid) -> Option<CatalogKeys> {
        if let Some(keys) = self.catalogs.lock().expect("catalog memory").get(oid) {
            return Some(keys.clone());
        }
        let keys: CatalogKeys = Arc::new(read_entry(&self.catalog_path(oid))?);
        self.catalogs.lock().expect("catalog memory").insert(*oid, keys.clone());
        Some(keys)
    }

    pub fn put_catalog(&self, oid: &Oid, keys: &CatalogKeys) -> std::io::Result<()> {
        self.catalogs.lock().expect("catalog memory").insert(*oid, keys.clone());
        write_entry(&self.catalog_path(oid), keys.as_ref())
    }

    /// The pack of `members` and whether it came from memory. A pack with
    /// the wrong number of files is a miss.
    pub fn get_pack(&self, members: &[(Oid, FileKind)]) -> Option<(Pack, bool)> {
        let key = Self::pack_key(members.iter().copied());
        if let Some(pack) = self.memory.lock().expect("pack memory").get(&key) {
            return Some((pack.clone(), true));
        }
        let facts: Vec<FileFacts> = read_entry(&self.pack_path(&key))?;
        if facts.len() != members.len() {
            return None;
        }
        let pack: Pack = Arc::new(facts.into_iter().map(Arc::new).collect());
        self.remember(&key, members, &pack);
        Some((pack, false))
    }

    pub fn put_pack(&self, members: &[(Oid, FileKind)], pack: &Pack) -> std::io::Result<()> {
        let key = &Self::pack_key(members.iter().copied());
        self.remember(key, members, pack);
        let facts: Vec<&FileFacts> = pack.iter().map(Arc::as_ref).collect();
        write_entry(&self.pack_path(key), &facts)
    }
}

fn read_entry<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let bytes = fsx::read_optional(path).ok()??;
    let payload = bytes.strip_prefix(MAGIC)?;
    if payload.len() < 32 {
        return None;
    }
    let (checksum, body) = payload.split_at(32);
    if blake3::hash(body).as_bytes() != checksum {
        return None;
    }
    bincode::deserialize(body).ok()
}

fn write_entry<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let body = bincode::serialize(value).map_err(std::io::Error::other)?;
    let mut bytes = Vec::with_capacity(body.len() + 40);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(blake3::hash(&body).as_bytes());
    bytes.extend_from_slice(&body);
    fsx::replace_atomic(path, &bytes, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::extract;

    fn sample() -> (Oid, FileFacts) {
        let source = b"import os\ndef f():\n    os.replace('a', 'b')\n";
        (Oid::git_blob_sha1(source), extract(FileKind::Python, source))
    }

    #[test]
    fn blob_entries_round_trip_at_sharded_paths() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobFactsCache::open(dir.path());
        let (oid, facts) = sample();
        assert_eq!(cache.get_blob(FileKind::Python, &oid), None);
        cache.put_blob(FileKind::Python, &oid, &facts).unwrap();
        assert_eq!(cache.get_blob(FileKind::Python, &oid), Some((Arc::new(facts.clone()), false)));
        // The same bytes read as another kind are another entry.
        assert_eq!(cache.get_blob(FileKind::Recipe, &oid), None);
        let hex = oid.to_hex();
        let expected = dir.path().join("blobs/v1/py").join(&hex[..2]).join(format!("{hex}.bin"));
        assert_eq!(cache.blob_path(FileKind::Python, &oid), expected);
        assert!(expected.is_file());

        let pack: Pack = Arc::new(vec![Arc::new(facts.clone())]);
        let members = [(oid, FileKind::Python)];
        assert_ne!(
            BlobFactsCache::pack_key(members.into_iter()),
            BlobFactsCache::pack_key([(oid, FileKind::Recipe)].into_iter())
        );
        let packed = BlobFactsCache::open(dir.path().join("packs-only"));
        assert!(packed.get_pack(&members).is_none());
        packed.put_pack(&members, &pack).unwrap();
        // This handle answers from memory, by pack and by blob; a fresh
        // handle reads the pack file once and then does the same.
        assert_eq!(packed.get_pack(&members), Some((pack.clone(), true)));
        assert_eq!(packed.get_blob(FileKind::Python, &oid), Some((Arc::new(facts), true)));
        let reopened = BlobFactsCache::open(dir.path().join("packs-only"));
        assert_eq!(reopened.get_blob(FileKind::Python, &oid), None);
        assert_eq!(reopened.get_pack(&members), Some((pack.clone(), false)));
        assert_eq!(reopened.get_pack(&members), Some((pack, true)));
        assert!(reopened.get_blob(FileKind::Python, &oid).is_some_and(|(_, from_memory)| from_memory));

        let keys: CatalogKeys = Arc::new(vec!["a.b".to_owned(), "c".to_owned()]);
        assert_eq!(cache.get_catalog(&oid), None);
        cache.put_catalog(&oid, &keys).unwrap();
        assert_eq!(cache.get_catalog(&oid), Some(keys.clone()));
        assert_eq!(BlobFactsCache::open(dir.path()).get_catalog(&oid), Some(keys));
    }

    #[test]
    fn tooth_entries_have_no_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobFactsCache::open(dir.path());
        let (oid, facts) = sample();
        cache.put_blob(FileKind::Python, &oid, &facts).unwrap();
        let path = cache.blob_path(FileKind::Python, &oid);
        let decade = std::time::Duration::from_secs(10 * 366 * 24 * 3600);
        let file = std::fs::File::options().write(true).open(&path).unwrap();
        file.set_modified(std::time::SystemTime::now() - decade).unwrap();
        drop(file);
        assert_eq!(cache.get_blob(FileKind::Python, &oid), Some((Arc::new(facts), false)));
    }

    #[test]
    fn tooth_torn_or_tampered_entries_are_misses() {
        let dir = tempfile::tempdir().unwrap();
        let cache = BlobFactsCache::open(dir.path());
        let (oid, facts) = sample();
        cache.put_blob(FileKind::Python, &oid, &facts).unwrap();
        let path = cache.blob_path(FileKind::Python, &oid);
        let good = std::fs::read(&path).unwrap();

        let mut flipped = good.clone();
        *flipped.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &flipped).unwrap();
        assert_eq!(cache.get_blob(FileKind::Python, &oid), None);

        std::fs::write(&path, &good[..good.len() / 2]).unwrap();
        assert_eq!(cache.get_blob(FileKind::Python, &oid), None);
        std::fs::write(&path, b"").unwrap();
        assert_eq!(cache.get_blob(FileKind::Python, &oid), None);

        cache.put_blob(FileKind::Python, &oid, &facts).unwrap();
        assert_eq!(cache.get_blob(FileKind::Python, &oid), Some((Arc::new(facts), false)));
    }
}
