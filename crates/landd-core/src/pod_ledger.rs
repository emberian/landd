//! One transaction per pod operation. Caller identity and time come from
//! the host, outside the task payload.
//!
//! The ledger keeps one WAL connection with cached statements for its whole
//! life. Claims and completions commit with `synchronous=NORMAL`: durable
//! when the process dies, but a power loss or kernel crash may roll back
//! the last few. Fencing tokens stay strictly increasing across such a
//! rollback because every open durably advances an epoch (with
//! `synchronous=FULL`) before serving, and a claim's token is at least
//! `epoch << 32`. A token handed out before the crash, even one whose
//! commit was lost, is therefore never handed out again. A lost completion
//! leaves its task claimed until the lease runs out, after which it is
//! claimed and run again under a higher token. Lead operations (create,
//! verify, reopen, cancel) are rare and commit with `synchronous=FULL`.
use rusqlite::{params, Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    CreatePod {
        tasks: Vec<String>,
    },
    Claim {
        lease_seconds: u32,
    },
    Done {
        #[serde(with = "wire_token")]
        fencing_token: i64,
    },
    Verify,
    Reopen,
    Cancel,
    Inspect,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Task {
    pub state: String,
    #[serde(with = "wire_token")]
    pub fencing_token: i64,
    pub owner: Option<String>,
    pub lease_until: Option<i64>,
}
// The stream bridge carries tokens through JavaScript. Preserve the numeric
// representation for existing clients until a token exceeds exact JSON/JS integers.
mod wire_token {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(token: &i64, out: S) -> Result<S::Ok, S::Error> {
        if token.unsigned_abs() < 1 << 53 {
            out.serialize_i64(*token)
        } else {
            out.collect_str(token)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(input: D) -> Result<i64, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Token {
            Number(i64),
            Decimal(String),
        }
        match Token::deserialize(input)? {
            Token::Number(n) => Ok(n),
            Token::Decimal(text) => text.parse().map_err(serde::de::Error::custom),
        }
    }
}

pub struct PodLedger {
    db: Connection,
    lead: String,
    /// Whether the connection is at `synchronous=FULL`.
    full: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error("SQLite WAL mode is required for the pod ledger")]
    WalUnavailable,
    #[error("pod action refused for this principal, token, lease or state")]
    Refused,
}

const EPOCH_BITS: u32 = 32;

impl PodLedger {
    pub fn open(path: &Path, lead: &str) -> Result<Self, Error> {
        if lead.is_empty() {
            return Err(Error::Refused);
        }
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        let journal_mode: String = db.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(Error::WalUnavailable);
        }
        db.execute_batch(
            "PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS authority(id INTEGER PRIMARY KEY CHECK(id=1), lead TEXT NOT NULL,
        epoch INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS pods(id TEXT PRIMARY KEY, lead TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS tasks(pod TEXT REFERENCES pods(id), id TEXT, state TEXT NOT NULL DEFAULT 'ready',
        token INTEGER NOT NULL DEFAULT 0, owner TEXT, until INTEGER, PRIMARY KEY(pod,id));",
        )?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let has_epoch: bool =
            tx.query_row("SELECT count(*) FROM pragma_table_info('authority') WHERE name='epoch'", [], |r| r.get(0))?;
        if !has_epoch {
            tx.execute_batch(
                "ALTER TABLE authority ADD COLUMN epoch INTEGER NOT NULL DEFAULT 0;
                 UPDATE authority SET epoch=(SELECT coalesce(max(token),0) >> 32 FROM tasks)",
            )?;
        }
        tx.execute("INSERT OR IGNORE INTO authority(id,lead) VALUES (1,?1)", [lead])?;
        let authority: String = tx.query_row(
            "UPDATE authority SET epoch=epoch+1 WHERE id=1 AND epoch>=0 AND epoch<?1 RETURNING lead",
            [i64::MAX >> EPOCH_BITS],
            |r| r.get(0),
        )?;
        if authority != lead {
            return Err(Error::Refused);
        }
        // The epoch is on disk before any token of it can be.
        tx.commit()?;
        Ok(Self { db, lead: authority, full: true })
    }

    pub fn apply(&mut self, principal: &str, pod: &str, task: &str, now: i64, action: Action) -> Result<Option<Task>, Error> {
        if principal.is_empty() || pod.is_empty() {
            return Err(Error::Refused);
        }
        let full = matches!(action, Action::CreatePod { .. } | Action::Verify | Action::Reopen | Action::Cancel);
        if self.full != full {
            self.db.pragma_update(None, "synchronous", if full { "FULL" } else { "NORMAL" })?;
            self.full = full;
        }
        self.transact(principal, pod, task, now, action)
    }

    fn transact(&mut self, principal: &str, pod: &str, task: &str, now: i64, action: Action) -> Result<Option<Task>, Error> {
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Action::CreatePod { tasks } = action {
            if principal != self.lead || tasks.is_empty() {
                return Err(Error::Refused);
            }
            tx.prepare_cached("INSERT INTO pods VALUES (?1,?2)")?.execute((pod, principal))?;
            let mut insert = tx.prepare_cached("INSERT INTO tasks(pod,id) VALUES (?1,?2)")?;
            for id in tasks {
                if id.is_empty() {
                    return Err(Error::Refused);
                }
                insert.execute((pod, id))?;
            }
            drop(insert);
            tx.commit()?;
            return Ok(None);
        }
        let lead: String = tx.prepare_cached("SELECT lead FROM pods WHERE id=?1")?.query_row([pod], |r| r.get(0))?;
        let changed = match action {
            Action::Claim { lease_seconds } if lease_seconds > 0 => {
                // All writers share the most recently reserved epoch, including connections
                // that were already open when another writer advanced it.
                let epoch: i64 = tx.prepare_cached("SELECT epoch FROM authority WHERE id=1")?.query_row([], |r| r.get(0))?;
                let floor = epoch << EPOCH_BITS;
                let ceiling = floor | ((1 << EPOCH_BITS) - 1);
                let until = now.checked_add(i64::from(lease_seconds)).ok_or(Error::Refused)?;
                tx.prepare_cached(
                    "UPDATE tasks SET state='in_progress',owner=?3,until=?4,token=max(token,?6)+1 WHERE pod=?1 AND id=?2 AND
                     max(token,?6)<?7 AND (state='ready' OR (state='in_progress' AND until<=?5))",
                )?
                .execute(params![pod, task, principal, until, now, floor, ceiling])?
            }
            Action::Done { fencing_token } => tx
                .prepare_cached(
                    "UPDATE tasks SET state='done',until=NULL WHERE pod=?1 AND id=?2 AND owner=?3 AND token=?4 AND state='in_progress' AND until>?5",
                )?
                .execute(params![pod, task, principal, fencing_token, now])?,
            Action::Verify | Action::Reopen | Action::Cancel if lead == principal => {
                let sql = match action {
                    Action::Verify => "UPDATE tasks SET state='verified' WHERE pod=?1 AND id=?2 AND state='done'",
                    Action::Cancel => "UPDATE tasks SET state='canceled',until=NULL WHERE pod=?1 AND id=?2 AND state IN ('in_progress','ready','done')",
                    _ => "UPDATE tasks SET state='ready',owner=NULL,until=NULL WHERE pod=?1 AND id=?2 AND state IN ('done','verified','canceled')",
                };
                tx.prepare_cached(sql)?.execute((pod, task))?
            }
            Action::Inspect => 1,
            _ => return Err(Error::Refused),
        };
        if changed != 1 {
            return Err(Error::Refused);
        }
        let row = tx
            .prepare_cached("SELECT state,token,owner,until FROM tasks WHERE pod=?1 AND id=?2")?
            .query_row((pod, task), |r| {
                Ok(Task { state: r.get(0)?, fencing_token: r.get(1)?, owner: r.get(2)?, lease_until: r.get(3)? })
            })?;
        tx.commit()?;
        Ok(Some(row))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger(dir: &tempfile::TempDir) -> PodLedger {
        PodLedger::open(&dir.path().join("pod.db"), "lead").unwrap()
    }

    fn claim(l: &mut PodLedger, who: &str, task: &str, now: i64) -> Result<Option<Task>, Error> {
        l.apply(who, "p", task, now, Action::Claim { lease_seconds: 10 })
    }

    #[test]
    fn claim_done_refusals_and_lease_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = ledger(&dir);
        assert!(l.apply("worker", "p", "", 0, Action::CreatePod { tasks: vec!["a".into()] }).is_err());
        l.apply("lead", "p", "", 0, Action::CreatePod { tasks: vec!["a".into(), "b".into()] }).unwrap();
        let first = claim(&mut l, "w1", "a", 100).unwrap().unwrap();
        assert_eq!((first.state.as_str(), first.owner.as_deref(), first.lease_until), ("in_progress", Some("w1"), Some(110)));
        assert!(claim(&mut l, "w2", "a", 105).is_err(), "a live lease is not stolen");
        let done = |l: &mut PodLedger, who: &str, token, now| l.apply(who, "p", "a", now, Action::Done { fencing_token: token });
        assert!(done(&mut l, "w2", first.fencing_token, 106).is_err(), "only the owner completes");
        assert!(done(&mut l, "w1", first.fencing_token + 1, 106).is_err(), "only with its own token");
        let second = claim(&mut l, "w2", "a", 110).unwrap().unwrap();
        assert!(second.fencing_token > first.fencing_token);
        assert!(done(&mut l, "w1", first.fencing_token, 111).is_err(), "an expired claim is fenced off");
        assert_eq!(done(&mut l, "w2", second.fencing_token, 111).unwrap().unwrap().state, "done");
        assert!(l.apply("w2", "p", "a", 112, Action::Verify).is_err(), "only the lead verifies");
        assert_eq!(l.apply("lead", "p", "a", 112, Action::Verify).unwrap().unwrap().state, "verified");
        let full: i64 = l.db.pragma_query_value(None, "synchronous", |r| r.get(0)).unwrap();
        assert_eq!(full, 2, "lead operations commit at synchronous=FULL");
        claim(&mut l, "w1", "b", 112).unwrap();
        let sync: i64 = l.db.pragma_query_value(None, "synchronous", |r| r.get(0)).unwrap();
        assert_eq!(sync, 1, "claims run at synchronous=NORMAL");
    }

    #[test]
    fn requires_wal_and_preserves_large_wire_tokens() {
        assert!(matches!(PodLedger::open(Path::new(":memory:"), "lead"), Err(Error::WalUnavailable)));
        let dir = tempfile::tempdir().unwrap();
        let mut l = ledger(&dir);
        l.apply("lead", "p", "", 0, Action::CreatePod { tasks: vec!["a".into()] }).unwrap();
        l.db.execute("UPDATE authority SET epoch=2097152", []).unwrap();
        let task = claim(&mut l, "worker", "a", 0).unwrap().unwrap();
        let token = serde_json::to_value(task).unwrap()["fencing_token"].clone();
        assert_eq!(token, "9007199254740993");
        let done = serde_json::from_value(serde_json::json!({"op":"done","fencing_token":token})).unwrap();
        assert_eq!(l.apply("worker", "p", "a", 1, done).unwrap().unwrap().state, "done");
    }

    #[test]
    fn older_connection_reclaims_after_newer_connection() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = ledger(&dir);
        first.apply("lead", "p", "", 0, Action::CreatePod { tasks: vec!["a".into()] }).unwrap();
        let mut second = ledger(&dir);
        let lost = claim(&mut second, "w2", "a", 100).unwrap().unwrap();
        let next = claim(&mut first, "w1", "a", 110).unwrap().unwrap();
        assert!(next.fencing_token > lost.fencing_token);
        assert!(second.apply("w2", "p", "a", 111, Action::Done { fencing_token: lost.fencing_token }).is_err());
    }

    /// #tooth: with `synchronous=NORMAL` a power loss can roll back a claim
    /// whose token was already handed out. Reopening must still issue a
    /// strictly greater token. Remove the epoch bump in `open` (or the
    /// `max(token, floor)` in the claim) and the reissued token equals the
    /// lost one.
    #[test]
    fn tooth_tokens_lost_to_a_rollback_are_never_reissued() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = ledger(&dir);
        l.apply("lead", "p", "", 0, Action::CreatePod { tasks: vec!["a".into()] }).unwrap();
        let lost = claim(&mut l, "w1", "a", 100).unwrap().unwrap();
        // What a rolled-back commit leaves behind: the task as it was before the claim.
        l.db.execute("UPDATE tasks SET state='ready',owner=NULL,until=NULL,token=0", []).unwrap();
        drop(l);
        let mut l = ledger(&dir);
        let reissued = claim(&mut l, "w2", "a", 100).unwrap().unwrap();
        assert!(reissued.fencing_token > lost.fencing_token, "{} must exceed {}", reissued.fencing_token, lost.fencing_token);
        assert!(l.apply("w1", "p", "a", 101, Action::Done { fencing_token: lost.fencing_token }).is_err());
    }

    /// A ledger written before the epoch column existed opens, keeps its
    /// lead, and fences above its old tokens.
    #[test]
    fn ledger_without_an_epoch_column_is_migrated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pod.db");
        let old = Connection::open(&path).unwrap();
        old.execute_batch(
            "CREATE TABLE authority(id INTEGER PRIMARY KEY CHECK(id=1), lead TEXT NOT NULL);
             INSERT INTO authority VALUES (1,'lead');
             CREATE TABLE pods(id TEXT PRIMARY KEY, lead TEXT NOT NULL);
             CREATE TABLE tasks(pod TEXT REFERENCES pods(id), id TEXT, state TEXT NOT NULL DEFAULT 'ready',
             token INTEGER NOT NULL DEFAULT 0, owner TEXT, until INTEGER, PRIMARY KEY(pod,id));
             INSERT INTO pods VALUES ('p','lead'); INSERT INTO tasks(pod,id,token) VALUES ('p','a',7);",
        )
        .unwrap();
        drop(old);
        assert!(matches!(PodLedger::open(&path, "other"), Err(Error::Refused)));
        let mut l = PodLedger::open(&path, "lead").unwrap();
        assert!(claim(&mut l, "w", "a", 0).unwrap().unwrap().fencing_token > 7);
    }
}
