//! The daemon: a Unix socket that accepts `enqueue` / `status` / `shutdown`
//! from this user's processes, and one train that lands batches.
//!
//! * One daemon per socket: an advisory lock on `<socket>.lock` is held for
//!   the daemon's lifetime, and only a stale *socket* is ever unlinked.
//! * The socket is created mode 0600 and every peer's uid is checked.
//! * Connections are bounded in number, in request size and in total time.
//! * The queue is saved on every change (including the batch in flight), so
//!   a restart resumes what was waiting; the history kept for `status` is a
//!   bounded ring read through a cursor.
//! * If the train thread dies, the daemon stops listening instead of
//!   looking alive.

use crate::station::Station;
use crate::wire::{read_frame, write_frame, Request, Response, Settled, Waiting, MAX_FRAME, MAX_REQUEST};
use landd_core::Oid;
use landd_train::{valid_lane, Candidate, Pushed, Queue};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Room left in a status reply for everything but the settled entries.
const STATUS_BUDGET: usize = (MAX_FRAME as usize) * 3 / 4;

#[derive(Default)]
struct State {
    queue: Queue,
    running: Vec<Candidate>,
    settled: VecDeque<Settled>,
    next_seq: u64,
    /// Times a tip has been re-queued after a refusal or deferral.
    retries: HashMap<Oid, u32>,
    batches: u64,
    shutdown: bool,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    started: Instant,
    connections: AtomicUsize,
    queue_path: PathBuf,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Save what is waiting and what is in flight. A lane in flight when
    /// the daemon dies is tried again after a restart; the delivery journal
    /// makes that safe.
    fn persist(&self, state: &State) {
        let mut saved = state.queue.clone();
        for candidate in &state.running {
            saved.push(candidate.clone(), 0, 0);
        }
        if let Err(err) = saved.save(&self.queue_path) {
            eprintln!("landd daemon: could not save the queue to {}: {err}", self.queue_path.display());
        }
    }
}

fn waiting(candidate: &Candidate) -> Waiting {
    Waiting { lane: candidate.lane.clone(), tip: candidate.tip.to_hex() }
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// The commit a lane names: the given tip, or the lane's branch on the push
/// destination as it is right now. Local branches are not consulted: they
/// may be stale.
fn resolve(station: &Station, lane: &str, tip: Option<&str>) -> Result<Oid, String> {
    if !valid_lane(lane) {
        return Err(format!("{lane:?} is not a lane name"));
    }
    let branch = format!("refs/heads/{lane}");
    let tip = match tip {
        Some(hex) => Oid::from_hex(hex).map_err(|_| format!("{hex:?} is not a commit id"))?,
        None => station
            .repo
            .ls_remote(&station.destination, &branch)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("the push destination has no branch {lane}"))?,
    };
    if !station.repo.has_object(&tip).map_err(|e| e.to_string())? {
        station.repo.fetch(&station.destination, &branch).map_err(|e| e.to_string())?;
        if !station.repo.has_object(&tip).map_err(|e| e.to_string())? {
            return Err(format!("commit {tip} is not on branch {lane} of the push destination"));
        }
    }
    Ok(tip)
}

fn respond(station: &Station, shared: &Shared, request: Request) -> Response {
    match request {
        Request::Enqueue { lane, tip } => {
            let tip = match resolve(station, &lane, tip.as_deref()) {
                Ok(tip) => tip,
                Err(message) => return Response::Error { message },
            };
            let mut state = shared.state.lock().expect("daemon state");
            let in_flight = state.running.iter().any(|c| c.tip == tip);
            let pushed =
                if in_flight { Pushed::Duplicate } else { state.queue.push(Candidate { lane, tip }, shared.now_ms(), 0) };
            let depth = state.queue.len();
            shared.persist(&state);
            drop(state);
            shared.wake.notify_all();
            Response::Enqueued {
                tip: tip.to_hex(),
                depth,
                duplicate: pushed == Pushed::Duplicate,
                replaced: pushed == Pushed::Replaced,
            }
        }
        Request::Status { since } => {
            let state = shared.state.lock().expect("daemon state");
            let mut settled = Vec::new();
            let mut bytes = 0;
            for entry in state.settled.iter().filter(|entry| entry.seq >= since) {
                // The reply must fit one frame: hand over what fits and a cursor for the rest.
                bytes += serde_json::to_vec(entry).map(|v| v.len()).unwrap_or(STATUS_BUDGET);
                if bytes > STATUS_BUDGET {
                    break;
                }
                settled.push(entry.clone());
            }
            let next = settled
                .last()
                .map(|entry| entry.seq + 1)
                .unwrap_or(since.max(state.settled.front().map_or(state.next_seq, |e| e.seq)));
            Response::Status {
                queued: state.queue.waiting().take(1000).map(|c| waiting(&c)).collect(),
                running: state.running.iter().map(waiting).collect(),
                settled,
                next,
                batches: state.batches,
            }
        }
        Request::Shutdown {} => {
            shared.state.lock().expect("daemon state").shutdown = true;
            shared.wake.notify_all();
            Response::ShuttingDown {}
        }
    }
}

/// A stream that gives up at a fixed instant, however slowly bytes arrive.
struct Deadline<'a> {
    stream: &'a UnixStream,
    at: Instant,
}

impl Deadline<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        self.at.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or_else(|| io::ErrorKind::TimedOut.into())
    }
}

impl Read for Deadline<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        (&mut &*self.stream).read(buffer)
    }
}

impl Write for Deadline<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        (&mut &*self.stream).write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The uid of the process at the other end of the socket.
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: u32::MAX, gid: u32::MAX };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `getsockopt` writes at most `len` bytes into `cred`, which is
    // a properly sized and aligned `ucred` owned by this frame.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

fn converse(station: &Station, shared: &Shared, stream: UnixStream) {
    let mut channel = Deadline { stream: &stream, at: Instant::now() + Duration::from_secs(station.config.request_timeout_s) };
    // SAFETY: `geteuid` cannot fail.
    let me = unsafe { libc::geteuid() };
    let response = match peer_uid(&stream) {
        Ok(uid) if uid == me => match read_frame::<Request>(&mut channel, MAX_REQUEST) {
            Ok(request) => respond(station, shared, request),
            Err(err) => Response::Error { message: format!("bad request frame: {err}") },
        },
        _ => Response::Error { message: "this daemon serves its own user only".into() },
    };
    // The reply gets a moment of its own, so a client that used up its
    // time still learns why it was cut off.
    channel.at = channel.at.max(Instant::now() + Duration::from_millis(500));
    let _ = write_frame(&mut channel, &response);
}

fn settle(state: &mut State, history: usize, candidate: &Candidate, outcome: String, detail: serde_json::Value) {
    let seq = state.next_seq;
    state.next_seq += 1;
    state.settled.push_back(Settled { seq, lane: candidate.lane.clone(), tip: candidate.tip.to_hex(), outcome, detail });
    while state.settled.len() > history {
        state.settled.pop_front();
    }
}

/// Sets the shutdown flag and wakes the listener when the train thread
/// leaves `run_train`, however it leaves.
struct StopListening<'a> {
    shared: &'a Shared,
    socket: &'a Path,
}

impl Drop for StopListening<'_> {
    fn drop(&mut self) {
        // A poisoned lock means the train panicked: the flag is still set.
        self.shared.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).shutdown = true;
        // Unblock `accept` so the listener thread sees the flag.
        let _ = UnixStream::connect(self.socket);
    }
}

/// Take batches as the queue's departure rule releases them, until shutdown.
fn run_train(station: &Station, shared: &Shared) {
    let history = station.config.settled_history;
    loop {
        let batch = {
            let mut state = shared.state.lock().expect("daemon state");
            loop {
                if state.shutdown {
                    return;
                }
                let (now_ms, now_s) = (shared.now_ms(), unix_now());
                if let Some(batch) = state.queue.take_batch(now_ms, now_s, &station.config) {
                    state.running = batch.clone();
                    shared.persist(&state);
                    break batch;
                }
                let nap = state.queue.due_in_ms(now_ms, now_s, &station.config).unwrap_or(60_000).clamp(1, 60_000);
                state = shared.wake.wait_timeout(state, Duration::from_millis(nap)).expect("daemon state").0;
            }
        };
        // A train per batch: flaky and timed-out verdicts do not outlive it.
        let result = station.train().and_then(|train| Ok(train.land_batch(&batch, true, unix_now())?));
        let mut state = shared.state.lock().expect("daemon state");
        state.running.clear();
        state.batches += 1;
        match result {
            Ok(report) => {
                for (candidate, outcome) in &report.outcomes {
                    let detail = serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null);
                    let name = detail.get("outcome").and_then(|o| o.as_str()).unwrap_or("unknown").to_owned();
                    let tries = *state.retries.get(&candidate.tip).unwrap_or(&0);
                    let superseded = state.queue.waiting().any(|waiting| waiting.lane == candidate.lane);
                    match outcome.retry_at() {
                        // Not this time: go again when the outcome says so,
                        // unless the lane has been submitted anew meanwhile.
                        Some(not_before) if tries < station.config.max_refusals && !superseded => {
                            state.retries.insert(candidate.tip, tries + 1);
                            state.queue.push(candidate.clone(), shared.now_ms(), not_before);
                        }
                        _ => {
                            state.retries.remove(&candidate.tip);
                            settle(&mut state, history, candidate, name, detail);
                        }
                    }
                }
            }
            Err(err) => {
                let detail = serde_json::json!({"outcome": "error", "message": err.to_string()});
                for candidate in &batch {
                    settle(&mut state, history, candidate, "error".into(), detail.clone());
                }
            }
        }
        shared.persist(&state);
    }
}

pub fn serve(socket: &Path, station: &Station) -> io::Result<()> {
    // One daemon per socket, for as long as this file is held locked.
    let lock_path = PathBuf::from(format!("{}.lock", socket.display()));
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(&lock_path)?;
    // SAFETY: `flock` on a descriptor this function owns; no memory is involved.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("another daemon holds {}", lock_path.display())));
    }
    // Under the lock, a socket file left behind belongs to nobody. Anything
    // else at that path is not ours to delete.
    match std::fs::symlink_metadata(socket) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(socket)?,
        Ok(_) => {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} exists and is not a socket", socket.display())))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    // SAFETY: `umask` only swaps the process's file mode mask; it is
    // restored right after the socket exists, before any thread is started.
    let listener = unsafe {
        let old = libc::umask(0o177);
        let bound = UnixListener::bind(socket);
        libc::umask(old);
        bound?
    };
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;

    let queue_path = station.state.join("queue.json");
    let queue = Queue::load(&queue_path)?;
    let shared = Shared {
        state: Mutex::new(State { queue, ..State::default() }),
        wake: Condvar::new(),
        started: Instant::now(),
        connections: AtomicUsize::new(0),
        queue_path,
    };
    let limit = station.config.max_connections;
    std::thread::scope(|scope| {
        let (shared, listener) = (&shared, &listener);
        scope.spawn(move || {
            for stream in listener.incoming() {
                if shared.state.lock().map(|s| s.shutdown).unwrap_or(true) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                if shared.connections.fetch_add(1, Ordering::SeqCst) >= limit {
                    shared.connections.fetch_sub(1, Ordering::SeqCst);
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
                    let _ = write_frame(&mut &stream, &Response::Error { message: "busy: too many connections".into() });
                    continue;
                }
                scope.spawn(move || {
                    converse(station, shared, stream);
                    shared.connections.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        let _stop = StopListening { shared, socket };
        run_train(station, shared);
    });
    drop(lock);
    std::fs::remove_file(socket)
}

pub fn call(socket: &Path, request: &Request) -> io::Result<Response> {
    let stream = UnixStream::connect(socket)?;
    let mut channel = Deadline { stream: &stream, at: Instant::now() + Duration::from_secs(60) };
    write_frame(&mut channel, request)?;
    read_frame(&mut channel, MAX_FRAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The history kept for `status` is a ring: it never grows past its
    /// bound, and sequence numbers keep counting across evictions.
    #[test]
    fn tooth_settled_history_is_bounded() {
        let mut state = State::default();
        for n in 0..10_000u32 {
            let candidate = Candidate { lane: format!("lane-{n}"), tip: Oid::from_slice(&[(n % 251) as u8; 20]).unwrap() };
            settle(&mut state, 3, &candidate, "landed".into(), serde_json::json!({"outcome": "landed"}));
            assert!(state.settled.len() <= 3);
        }
        let kept: Vec<(u64, &str)> = state.settled.iter().map(|s| (s.seq, s.lane.as_str())).collect();
        assert_eq!(kept, [(9997, "lane-9997"), (9998, "lane-9998"), (9999, "lane-9999")]);
        assert_eq!(state.next_seq, 10_000);
    }
}
