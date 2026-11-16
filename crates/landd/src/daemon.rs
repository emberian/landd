//! The daemon: a Unix socket that accepts `enqueue` / `status` / `shutdown`
//! from any number of clients at once, and one train that lands batches.

use crate::station::Station;
use crate::wire::{read_frame, write_frame, Request, Response, Settled, Waiting};
use landd_core::Oid;
use landd_train::{Candidate, CandidateOutcome, Queue};
use std::collections::HashMap;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Default)]
struct State {
    queue: Queue,
    running: Vec<Candidate>,
    settled: Vec<Settled>,
    /// Times a tip has been re-queued after the forge refused its push.
    retries: HashMap<Oid, u32>,
    batches: u64,
    shutdown: bool,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    started: Instant,
}

impl Shared {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }
}

fn waiting(candidate: &Candidate) -> Waiting {
    Waiting { lane: candidate.lane.clone(), tip: candidate.tip.to_hex() }
}

pub fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn respond(station: &Station, shared: &Shared, request: Request) -> Response {
    match request {
        Request::Enqueue { lane } => {
            let tip = match station.repo.commit_of(&lane) {
                Ok(tip) => tip,
                Err(err) => return Response::Error { message: format!("cannot resolve {lane:?}: {err}") },
            };
            let mut state = shared.state.lock().expect("daemon state");
            let already = state.running.iter().any(|c| c.tip == tip);
            let added = !already && state.queue.push(Candidate { lane, tip }, shared.now_ms());
            let depth = state.queue.len();
            drop(state);
            shared.wake.notify_all();
            Response::Enqueued { tip: tip.to_hex(), depth, duplicate: !added }
        }
        Request::Status {} => {
            let state = shared.state.lock().expect("daemon state");
            Response::Status {
                queued: state.queue.waiting().map(waiting).collect(),
                running: state.running.iter().map(waiting).collect(),
                settled: state.settled.clone(),
                batches: state.batches,
            }
        }
        Request::Shutdown {} => {
            shared.state.lock().expect("daemon state").shutdown = true;
            shared.wake.notify_all();
            Response::ShuttingDown
        }
    }
}

fn converse(station: &Station, shared: &Shared, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let response = match read_frame::<Request>(&mut stream) {
        Ok(request) => respond(station, shared, request),
        Err(err) => Response::Error { message: format!("bad request frame: {err}") },
    };
    let _ = write_frame(&mut stream, &response);
}

fn settle(candidate: &Candidate, outcome: &CandidateOutcome) -> Settled {
    let detail = serde_json::to_value(outcome).unwrap_or(serde_json::Value::Null);
    let name = detail.get("outcome").and_then(|o| o.as_str()).unwrap_or("unknown").to_owned();
    Settled { lane: candidate.lane.clone(), tip: candidate.tip.to_hex(), outcome: name, detail }
}

/// Take batches as the queue's departure rule releases them, until shutdown.
fn run_train(station: &Station, shared: &Shared) {
    loop {
        let batch = {
            let mut state = shared.state.lock().expect("daemon state");
            loop {
                if state.shutdown {
                    return;
                }
                let now = shared.now_ms();
                if let Some(batch) = state.queue.take_batch(now, &station.config) {
                    state.running = batch.clone();
                    break batch;
                }
                let nap = state.queue.due_in_ms(now, &station.config).unwrap_or(60_000).max(1);
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
                    let tries = state.retries.entry(candidate.tip).or_insert(0);
                    if matches!(outcome, CandidateOutcome::Refused { .. }) && *tries < station.config.max_refusals {
                        // The ref moved under the batch: go again on the new base.
                        *tries += 1;
                        state.queue.push(candidate.clone(), shared.now_ms());
                    } else {
                        state.settled.push(settle(candidate, outcome));
                    }
                }
            }
            Err(err) => {
                let detail = serde_json::json!({"outcome": "error", "message": err.to_string()});
                state.settled.extend(batch.iter().map(|c| Settled {
                    lane: c.lane.clone(),
                    tip: c.tip.to_hex(),
                    outcome: "error".into(),
                    detail: detail.clone(),
                }));
            }
        }
    }
}

pub fn serve(socket: &Path, station: &Station) -> std::io::Result<()> {
    // A socket file nobody answers on is left over from a dead daemon.
    if socket.exists() && UnixStream::connect(socket).is_err() {
        std::fs::remove_file(socket)?;
    }
    let listener = UnixListener::bind(socket)?;
    let shared = Shared { state: Mutex::new(State::default()), wake: Condvar::new(), started: Instant::now() };
    std::thread::scope(|scope| {
        let (shared, listener) = (&shared, &listener);
        scope.spawn(move || {
            for stream in listener.incoming() {
                if shared.state.lock().expect("daemon state").shutdown {
                    break;
                }
                if let Ok(stream) = stream {
                    scope.spawn(move || converse(station, shared, stream));
                }
            }
        });
        run_train(station, shared);
        // Unblock `accept` so the listener thread sees the flag.
        let _ = UnixStream::connect(socket);
    });
    std::fs::remove_file(socket)
}

pub fn call(socket: &Path, request: &Request) -> std::io::Result<Response> {
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    write_frame(&mut stream, request)?;
    read_frame(&mut stream)
}
