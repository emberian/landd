//! One transaction per pod operation. Caller identity and time come from
//! the host, outside the task payload.
use rusqlite::{params, Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    CreatePod { tasks: Vec<String> },
    Claim { lease_seconds: u32 },
    Done { fencing_token: i64 },
    Verify,
    Reopen,
    Cancel,
    Inspect,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Task {
    pub state: String,
    pub fencing_token: i64,
    pub owner: Option<String>,
    pub lease_until: Option<i64>,
}
pub struct PodLedger {
    db: Connection,
    lead: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Sql(#[from] rusqlite::Error),
    #[error("pod action refused for this principal, token, lease or state")]
    Refused,
}

impl PodLedger {
    pub fn open(path: &Path, lead: &str) -> Result<Self, Error> {
        if lead.is_empty() {
            return Err(Error::Refused);
        }
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS authority(id INTEGER PRIMARY KEY CHECK(id=1), lead TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS pods(id TEXT PRIMARY KEY, lead TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS tasks(pod TEXT REFERENCES pods(id), id TEXT, state TEXT NOT NULL DEFAULT 'ready',
        token INTEGER NOT NULL DEFAULT 0, owner TEXT, until INTEGER, PRIMARY KEY(pod,id));",
        )?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT OR IGNORE INTO authority VALUES (1,?1)", [lead])?;
        let authority: String = tx.query_row("SELECT lead FROM authority WHERE id=1", [], |r| r.get(0))?;
        if authority != lead {
            return Err(Error::Refused);
        }
        tx.commit()?;
        Ok(Self { db, lead: authority })
    }
    pub fn apply(&mut self, principal: &str, pod: &str, task: &str, now: i64, action: Action) -> Result<Option<Task>, Error> {
        if principal.is_empty() || pod.is_empty() {
            return Err(Error::Refused);
        }
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Action::CreatePod { tasks } = action {
            if principal != self.lead || tasks.is_empty() {
                return Err(Error::Refused);
            }
            tx.execute("INSERT INTO pods VALUES (?1,?2)", (pod, principal))?;
            for id in tasks {
                if id.is_empty() {
                    return Err(Error::Refused);
                }
                tx.execute("INSERT INTO tasks(pod,id) VALUES (?1,?2)", (pod, id))?;
            }
            tx.commit()?;
            return Ok(None);
        }
        let lead: String = tx.query_row("SELECT lead FROM pods WHERE id=?1", [pod], |r| r.get(0))?;
        let changed = match action {
            Action::Claim { lease_seconds } if lease_seconds > 0 => tx.execute(
                "UPDATE tasks SET state='in_progress',owner=?3,until=?4,token=token+1 WHERE pod=?1 AND id=?2 AND
                 token<9223372036854775807 AND (state='ready' OR (state='in_progress' AND until<=?5))",
                params![pod,task,principal,now.checked_add(i64::from(lease_seconds)).ok_or(Error::Refused)?,now])?,
            Action::Done { fencing_token } => tx.execute(
                "UPDATE tasks SET state='done',until=NULL WHERE pod=?1 AND id=?2 AND owner=?3 AND token=?4 AND state='in_progress' AND until>?5",
                params![pod,task,principal,fencing_token,now])?,
            Action::Verify | Action::Reopen | Action::Cancel if lead == principal => {
                let sql = match action {
                    Action::Verify => "UPDATE tasks SET state='verified' WHERE pod=?1 AND id=?2 AND state='done'",
                    Action::Cancel => "UPDATE tasks SET state='canceled',until=NULL WHERE pod=?1 AND id=?2 AND state IN ('in_progress','ready','done')",
                    _ => "UPDATE tasks SET state='ready',owner=NULL,until=NULL WHERE pod=?1 AND id=?2 AND state IN ('done','verified','canceled')",
                };
                tx.execute(sql, (pod,task))?
            }
            Action::Inspect => 1,
            _ => return Err(Error::Refused),
        };
        if changed != 1 {
            return Err(Error::Refused);
        }
        let row = tx.query_row("SELECT state,token,owner,until FROM tasks WHERE pod=?1 AND id=?2", (pod, task), |r| {
            Ok(Task { state: r.get(0)?, fencing_token: r.get(1)?, owner: r.get(2)?, lease_until: r.get(3)? })
        })?;
        tx.commit()?;
        Ok(Some(row))
    }
}
