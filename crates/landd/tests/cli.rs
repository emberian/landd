//! End-to-end tests of the `landd` binary against throwaway repositories.

use landd_core::custody::{Grant, SigningKey, TrustedKeys};
use landd_core::digest::hex_encode;
use landd_core::git::canonical_repo_id;
use landd_core::git::testkit::Sandbox;
use serde_json::Value;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_landd");
const MAIN: &str = "refs/heads/main";

fn landd(args: &[&str]) -> Output {
    Command::new(BIN).args(args).stdin(Stdio::null()).output().expect("landd runs")
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!("not JSON ({e}): {}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr))
    })
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

const MANIFEST: &str = r#"{"units": {
    "a": {"path": "checks/a.sh", "inputs": ["src/a.txt"]},
    "b": {"path": "checks/b.sh", "inputs": ["src/b.txt"]}}}"#;

fn manifest_repo(root: &Path) -> Sandbox {
    Sandbox::new(
        root,
        &[
            ("landd-units.json", MANIFEST),
            ("checks/a.sh", "grep -q '^ok' src/a.txt\n"),
            ("checks/b.sh", "grep -q '^ok' src/b.txt\n"),
            ("src/a.txt", "ok\n"),
            ("src/b.txt", "ok\n"),
            ("docs/readme.md", "docs\n"),
        ],
    )
}

fn write_config(root: &Path, extra: &str) -> PathBuf {
    let path = root.join("landd.toml");
    let body = format!(
        "cache_dir = \"{}\"\ncone_source = \"manifest\"\ntest_command = [\"sh\", \"{{path}}\"]\nenv_allow = [\"PATH\"]\n\
         test_timeout_s = 30\nbatch_coalesce_ms = 100\n{extra}",
        root.join("state").display()
    );
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn sweep_reports_findings_exit_codes_and_a_warm_cache() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = Sandbox::new(
        dir.path(),
        &[
            ("Makefile", "test:\n\tpython -m pytest\n"),
            ("pkg/__init__.py", ""),
            ("pkg/mod.py", "import os\ndef save(a, b):\n    os.replace(a, b)\n"),
            ("tests/test_mod.py", "from pkg import mod\n"),
        ],
    );
    let cache = dir.path().join("cache");
    let rules = dir.path().join("rules.toml");
    std::fs::write(
        &rules,
        "[[rule]]\nid = \"bare-python\"\nkind = \"no_bare_python_recipe\"\n\n\
         [[rule]]\nid = \"replace-owner\"\nkind = \"atomic_replace_owner\"\nowners = [\"pkg/pk.py\"]\n\n\
         [[rule]]\nid = \"graph\"\nkind = \"python_import_graph\"\n",
    )
    .unwrap();
    let args = ["sweep", "--repo", text(&sandbox.work), "--rules", text(&rules), "--cache-dir", text(&cache), "--json"];

    let cold = landd(&args);
    assert_eq!(cold.status.code(), Some(1), "a failing rule exits 1: {}", String::from_utf8_lossy(&cold.stderr));
    let report = json(&cold);
    assert_eq!(report["rules_failed"], 2);
    assert_eq!(report["verdicts"][0]["findings"][0]["path"], "Makefile");
    assert_eq!(report["verdicts"][1]["findings"][0]["line"], 3);
    assert_eq!(report["verdicts"][2]["status"], "pass");
    assert_eq!(report["cones"][0]["unit"], "tests.test_mod");
    assert_eq!((report["cones"][0]["widened"].as_bool(), report["widened_cones"].as_u64()), (Some(false), Some(0)));
    assert_eq!(report["stats"]["blobs_parsed"], 4);

    let warm = json(&landd(&args));
    assert_eq!(warm["stats"]["blobs_parsed"], 0);
    assert_eq!(warm["stats"]["packs_hit"], warm["stats"]["packs"]);
    assert_eq!(warm["verdicts"], report["verdicts"]);
    assert_eq!(warm["cones"], report["cones"]);
    // The cache is private to the user.
    assert_eq!(std::fs::metadata(cache.join("facts")).unwrap().permissions().mode() & 0o077, 0);

    // Human output, the working-tree mode, and a clean pack.
    let human = landd(&["sweep", "--repo", text(&sandbox.work), "--rules", text(&rules), "--no-cache", "--worktree"]);
    let printed = String::from_utf8_lossy(&human.stdout).into_owned();
    assert!(printed.contains("FAIL bare-python (1 findings)") && printed.contains("Makefile:2:"), "{printed}");
    std::fs::write(&rules, "[[rule]]\nid = \"graph\"\nkind = \"python_import_graph\"\n").unwrap();
    assert_eq!(landd(&args).status.code(), Some(0));
    assert_eq!(landd(&["sweep", "--repo", text(dir.path()), "--rev", "nope"]).status.code(), Some(2));
    // A cache directory other accounts can write is refused.
    let loose = dir.path().join("loose");
    std::fs::create_dir_all(loose.join("facts")).unwrap();
    std::fs::set_permissions(loose.join("facts"), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert_eq!(landd(&["sweep", "--repo", text(&sandbox.work), "--cache-dir", text(&loose)]).status.code(), Some(2));
}

#[test]
fn cones_show_changed_transported_and_widened_units() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = Sandbox::new(
        dir.path(),
        &[
            ("lib/__init__.py", ""),
            ("lib/a.py", "A = 1\n"),
            ("lib/b.py", "B = 1\n"),
            ("data/t.json", "{}\n"),
            ("tests/test_a.py", "from lib import a\n"),
            ("tests/test_b.py", "from lib import b\n"),
            ("tests/test_data.py", "import os\nopen(os.path.join(os.path.dirname(__file__), '..', 'data', 't.json'))\n"),
            ("tests/test_any.py", "def read(p):\n    return open(p).read()\n"),
        ],
    );
    let base = sandbox.git(&["rev-parse", "HEAD"]);
    sandbox.commit(
        "main",
        "edit",
        &[("lib/a.py", "A = 2\n"), ("data/t.json", "{\"k\": 1}\n"), ("tests/test_c.py", "import lib\n")],
        &[],
    );
    let out = landd(&["cones", "--repo", text(&sandbox.work), "--base", &base, "--head", "HEAD", "--no-cache", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let report = json(&out);
    assert_eq!(
        (report["units"].as_u64(), report["transported"].as_u64(), report["widened"].as_u64()),
        (Some(5), Some(1), Some(1))
    );
    let changed: Vec<(&str, Vec<&str>)> = report["changed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (c["unit"].as_str().unwrap(), c["moved_paths"].as_array().unwrap().iter().map(|p| p.as_str().unwrap()).collect())
        })
        .collect();
    assert_eq!(
        changed,
        vec![
            ("tests.test_a", vec!["lib/a.py"]),
            // A test that opens through a parameter depends on everything.
            ("tests.test_any", vec!["data/t.json", "lib/a.py", "tests/test_c.py"]),
            // The data file a test opens is in its cone.
            ("tests.test_data", vec!["data/t.json"]),
        ]
    );
    assert_eq!(report["added"], serde_json::json!(["tests.test_c"]));
    assert_eq!(report["widened_by_cause"]["opaque_read"], 1);

    let human = landd(&["cones", "--repo", text(&sandbox.work), "--base", &base, "--head", "HEAD", "--no-cache"]);
    let printed = String::from_utf8_lossy(&human.stdout).into_owned();
    assert!(
        printed.contains("5 units: 1 transported (0 runs), 3 changed, 1 added, 0 removed; 1 depend on the whole tree"),
        "{printed}"
    );
    assert!(printed.contains("changed tests.test_data <- data/t.json"), "{printed}");
}

#[test]
fn land_dry_run_apply_decline_and_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = manifest_repo(dir.path());
    let config = write_config(dir.path(), "");
    let base = sandbox.forge_head(MAIN);
    let good = sandbox.lane("good", "main", &[("src/a.txt", "ok good\n")]);
    sandbox.lane("bad", "main", &[("src/b.txt", "broken\n")]);
    let land = |lane: &str, apply: bool| {
        let mut args = vec!["land", "--repo", text(&sandbox.work), "--lane", lane, "--config", text(&config)];
        if apply {
            args.push("--apply");
        }
        landd(&args)
    };

    let dry = land("good", false);
    assert_eq!(dry.status.code(), Some(0), "{}", String::from_utf8_lossy(&dry.stderr));
    assert_eq!(json(&dry)["outcomes"][0][1]["outcome"], "would_land");
    assert_eq!(sandbox.forge_head(MAIN), base);

    let applied = land("good", true);
    assert_eq!(applied.status.code(), Some(0), "{}", String::from_utf8_lossy(&applied.stderr));
    let report = json(&applied);
    assert_eq!(report["outcomes"][0][1]["outcome"], "landed");
    // The dry run's verdict was recorded by content: the applied run ran nothing.
    assert_eq!(report["tally"]["candidate_units_run"], 0);
    let head = sandbox.forge_head(MAIN);
    assert_eq!(report["outcomes"][0][1]["merge"], head.to_hex());
    assert_eq!(sandbox.forge_git(&["rev-list", "--parents", "-n", "1", MAIN]), format!("{head} {base} {good}"));
    // The merge commit is dated by its parents, not by the clock.
    assert_eq!(sandbox.forge_git(&["show", "-s", "--format=%ct", MAIN]), "1700000000");

    let declined = land("bad", true);
    assert_eq!(declined.status.code(), Some(1));
    let report = json(&declined);
    assert_eq!(report["outcomes"][0][1]["outcome"], "declined");
    assert_eq!(report["outcomes"][0][1]["evidence"]["why_not"][0]["moved_paths"], serde_json::json!(["src/b.txt"]));
    assert_eq!(sandbox.forge_head(MAIN), head);

    // A lane with nothing left to land is a refusal, not a success.
    let again = land("good", true);
    assert_eq!(again.status.code(), Some(1));
    assert_eq!(json(&again)["outcomes"][0][1]["outcome"], "on_base");

    assert_eq!(land("no-such-lane", true).status.code(), Some(2));
    // Revision syntax is not a lane name.
    for sneaky in [":/good", "good^", "--upload-pack=x", "good..bad"] {
        let out = landd(&["land", "--repo", text(&sandbox.work), "--config", text(&config), "--lane", sneaky]);
        assert_eq!(out.status.code(), Some(2), "{sneaky}");
    }
    let bad_setting =
        landd(&["land", "--repo", text(&sandbox.work), "--lane", "good", "--config", text(&config), "--set", "max_batch_size=0"]);
    assert_eq!(bad_setting.status.code(), Some(2));
}

/// The trusted state may not live where a checkout could carry it.
#[test]
fn tooth_state_inside_the_repository_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = manifest_repo(dir.path());
    sandbox.lane("good", "main", &[("src/a.txt", "ok good\n")]);
    let inside = format!("cache_dir={}", sandbox.work.join(".landd-cache").display());
    let out =
        landd(&["land", "--repo", text(&sandbox.work), "--lane", "good", "--set", &inside, "--set", "cone_source=manifest"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("inside the repository"), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!sandbox.work.join(".landd-cache/verdicts").exists());
    let relative = landd(&["land", "--repo", text(&sandbox.work), "--lane", "good", "--set", "cache_dir=.landd-cache"]);
    assert_eq!(relative.status.code(), Some(2));
}

fn ctl(socket: &Path, request: &[&str]) -> Value {
    let mut args = vec!["ctl", "--socket", text(socket)];
    args.extend_from_slice(request);
    json(&landd(&args))
}

fn wait_for(what: &str, limit: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + limit;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn daemon_lands_concurrent_enqueues_keeps_bounded_history_and_guards_its_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = manifest_repo(dir.path());
    let config = write_config(dir.path(), "max_batch_size = 8\nsettled_history = 4\n");
    let base = sandbox.forge_head(MAIN);
    let lanes = [
        ("one", sandbox.lane("one", "main", &[("src/a.txt", "ok one\n")])),
        ("two", sandbox.lane("two", "main", &[("docs/two.md", "two\n")])),
        ("three", sandbox.lane("three", "main", &[("docs/three.md", "three\n")])),
        ("bad", sandbox.lane("bad", "main", &[("src/b.txt", "broken\n")])),
    ];
    // One lane is published on the destination and is queued by name alone.
    sandbox.git(&["push", "--quiet", "origin", "three:refs/heads/three"]);
    let socket = dir.path().join("landd.sock");
    let spawn = |socket: &Path| {
        Command::new(BIN)
            .args(["daemon", "--socket", text(socket), "--config", text(&config), "--repo", text(&sandbox.work)])
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    };

    // Something that is not a socket at the socket path is not deleted.
    let occupied = dir.path().join("precious.txt");
    std::fs::write(&occupied, "keep me").unwrap();
    let refused = spawn(&occupied).wait_with_output().unwrap();
    assert_eq!(refused.status.code(), Some(2));
    assert_eq!(std::fs::read_to_string(&occupied).unwrap(), "keep me");

    let mut daemon = spawn(&socket);
    wait_for("the daemon's socket", Duration::from_secs(20), || socket.exists());
    assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);
    // A second daemon on the same socket does not take it over.
    let second = spawn(&socket).wait_with_output().unwrap();
    assert_eq!(second.status.code(), Some(2), "{}", String::from_utf8_lossy(&second.stderr));
    assert!(socket.exists());

    // Four clients at once.
    std::thread::scope(|scope| {
        for (lane, tip) in &lanes {
            let socket = &socket;
            scope.spawn(move || {
                let hex = tip.to_hex();
                let reply = if *lane == "three" {
                    ctl(socket, &["enqueue", lane])
                } else {
                    ctl(socket, &["enqueue", lane, "--tip", &hex])
                };
                assert_eq!(reply["reply"], "enqueued", "{reply}");
                assert_eq!(reply["tip"], tip.to_hex());
            });
        }
    });
    // A branch the destination does not have, and a name that is not a lane.
    assert_eq!(ctl(&socket, &["enqueue", "one"])["reply"], "error", "a local-only branch needs --tip");
    assert_eq!(ctl(&socket, &["enqueue", ":/x"])["reply"], "error");

    // Read the history through the cursor; the daemon keeps at most four entries.
    let mut seen: Vec<Value> = Vec::new();
    let mut cursor = 0u64;
    wait_for("four settled lanes", Duration::from_secs(60), || {
        let since = cursor.to_string();
        let status = ctl(&socket, &["status", "--since", &since]);
        let settled = status["settled"].as_array().unwrap();
        assert!(settled.len() <= 4, "{status}");
        seen.extend(settled.iter().cloned());
        cursor = status["next"].as_u64().unwrap();
        seen.len() >= lanes.len()
    });
    let outcome =
        |lane: &str| seen.iter().find(|s| s["lane"] == lane).map(|s| s["outcome"].as_str().unwrap().to_owned()).unwrap();
    assert_eq!(
        (outcome("one"), outcome("two"), outcome("three"), outcome("bad")),
        ("landed".into(), "landed".into(), "landed".into(), "declined".into())
    );
    let status = ctl(&socket, &["status"]);
    assert!(status["batches"].as_u64().unwrap() >= 1 && status["settled"].as_array().unwrap().len() <= 4, "{status}");
    // Past the cursor there is nothing new.
    let since = cursor.to_string();
    assert_eq!(ctl(&socket, &["status", "--since", &since])["settled"], serde_json::json!([]));

    let repo = sandbox.repo();
    repo.fetch(text(&sandbox.forge), MAIN).unwrap();
    let head = sandbox.forge_head(MAIN);
    assert!(repo.is_ancestor(&base, &head).unwrap());
    for (lane, tip) in &lanes {
        assert_eq!(repo.is_ancestor(tip, &head).unwrap(), *lane != "bad", "{lane}");
    }
    // The saved queue is empty again, and lives in the state directory.
    let saved: Value = serde_json::from_slice(&std::fs::read(dir.path().join("state/queue.json")).unwrap()).unwrap();
    assert_eq!(saved["waiting"], serde_json::json!([]));

    assert_eq!(ctl(&socket, &["shutdown"])["reply"], "shutting_down");
    let exit = daemon.wait().unwrap();
    assert!(exit.success());
    assert!(!socket.exists());
}

/// A client that sends its request a byte at a time does not hold a
/// connection past the daemon's total deadline, and requests are small.
#[test]
fn tooth_slow_and_oversized_clients_are_cut_off() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let dir = tempfile::tempdir().unwrap();
    let sandbox = manifest_repo(dir.path());
    let config = write_config(dir.path(), "request_timeout_s = 1\nmax_connections = 2\n");
    let socket = dir.path().join("landd.sock");
    let mut daemon = Command::new(BIN)
        .args(["daemon", "--socket", text(&socket), "--config", text(&config), "--repo", text(&sandbox.work)])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    wait_for("the daemon's socket", Duration::from_secs(20), || socket.exists());

    let started = Instant::now();
    let mut slow = UnixStream::connect(&socket).unwrap();
    slow.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    for byte in [0u8, 0, 0] {
        slow.write_all(&[byte]).unwrap();
        std::thread::sleep(Duration::from_millis(450));
    }
    let mut reply = Vec::new();
    let _ = slow.read_to_end(&mut reply);
    assert!(started.elapsed() < Duration::from_secs(5), "the slow client held its connection for {:?}", started.elapsed());
    assert!(String::from_utf8_lossy(&reply).contains("bad request frame"), "{}", String::from_utf8_lossy(&reply));

    // A request frame that claims a megabyte is refused outright.
    let mut big = UnixStream::connect(&socket).unwrap();
    big.write_all(&(1u32 << 20).to_be_bytes()).unwrap();
    let mut reply = Vec::new();
    let _ = big.read_to_end(&mut reply);
    assert!(String::from_utf8_lossy(&reply).contains("frame too large"));

    // The daemon still answers.
    assert_eq!(ctl(&socket, &["status"])["reply"], "status");
    assert_eq!(ctl(&socket, &["shutdown"])["reply"], "shutting_down");
    assert!(daemon.wait().unwrap().success());
}

#[test]
fn replay_reports_observed_figures_and_refuses_to_invent_a_replay() {
    let dir = tempfile::tempdir().unwrap();
    // A ledger that records module sets and costs can be replayed.
    let ledger = dir.path().join("land_runs.jsonl");
    let row = |ts: u32, tip: &str, outcome: &str| {
        format!("{{\"kind\":\"land\",\"ts\":{ts},\"apply\":true,\"tip\":\"{tip}\",\"head\":\"m{ts}\",\"outcome\":\"{outcome}\",\"modules\":{{\"tests.t\":20}},\"phases\":{{\"push\":21}},\"cpu_s\":3,\"wall_s\":25,\"pushed_ts\":{}}}\n", ts + 25)
    };
    let mut bytes = [row(0, "t1", "refused:push"), row(60, "t1", "landed"), row(61, "t2", "landed")].concat().into_bytes();
    bytes.extend_from_slice(b"garbage \xff\xfe not utf-8\n");
    std::fs::write(&ledger, bytes).unwrap();
    let costs = dir.path().join("costs.json");
    std::fs::write(&costs, r#"{"tests.t": 10}"#).unwrap();

    let out =
        landd(&["replay", "--ledger", text(&ledger), "--module-costs", text(&costs), "--json", "--set", "runner_concurrency=1"]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let report = json(&out);
    assert_eq!((report["ledger_rows"].as_u64(), report["ledger_malformed"].as_u64()), (Some(4), Some(1)));
    assert_eq!(
        (report["observed"]["lanes"].as_u64(), report["observed"]["runs_by_class"]["lost_push"].as_u64()),
        (Some(2), Some(1))
    );
    // t1: first attempt at 0, on main at 85.
    assert_eq!(report["observed"]["lead_first_attempt_p95_s"].as_f64(), Some(85.0));
    assert_eq!(report["replay"]["replay"], "available");
    assert_eq!(
        (report["replay"]["fleet"]["module_cost_s"].as_f64(), report["replay"]["landd"]["module_cost_s"].as_f64()),
        (Some(30.0), Some(20.0))
    );

    // A ledger shaped like the real one records no module sets: no replay.
    let real = dir.path().join("real.jsonl");
    std::fs::write(
        &real,
        "{\"kind\":\"land\",\"ts\":0,\"apply\":true,\"tip\":\"t1\",\"head\":\"m\",\"outcome\":\"landed\",\"count\":0,\"selected\":[],\"modules\":{},\"phases\":{\"push\":389.7},\"cpu_s\":14.2,\"wall_s\":395.2,\"pushed_ts\":395}\n",
    )
    .unwrap();
    let timings = dir.path().join("timings.json");
    std::fs::write(
        &timings,
        r#"{"keeper_walls": {"tests.a": 2.5}, "push_counter": [{"modules": 192, "outcome": "fresh", "rung_s": 240.3}]}"#,
    )
    .unwrap();
    let report = json(&landd(&["replay", "--ledger", text(&real), "--timings", text(&timings), "--json"]));
    assert_eq!(report["replay"]["replay"], "unavailable");
    assert_eq!(report["timings"]["push_module_runs"], 192);
    assert_eq!(report["observed"]["hub_cpu_total_s"].as_f64(), Some(14.2));
    let markdown = String::from_utf8(landd(&["replay", "--ledger", text(&real)]).stdout).unwrap();
    assert!(
        markdown.contains("Not available from this ledger")
            && markdown.contains("| landed push phase p50 / p95 (s) | 389.7 / 389.7 |"),
        "{markdown}"
    );
}

/// A forge guarded by `landd pre-receive`: a plain push to main is refused,
/// a push through landd carries a receipt for this repository and is accepted.
#[test]
fn pre_receive_hook_admits_only_receipted_fast_forwards_for_this_repository() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = manifest_repo(dir.path());
    let key = SigningKey::ed25519_from_seed([21; 32]);
    let write_key = |name: &str, seed: u8| {
        let path = dir.path().join(name);
        std::fs::write(&path, format!(r#"{{"key_id":"seat-1","alg":"ed25519","key":"{}"}}"#, hex_encode(&[seed; 32]))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    };
    let key_file = write_key("seat.key.json", 21);
    let mut trusted = TrustedKeys::new();
    trusted.insert("seat-1", key.trusted(), Grant::new(&["landd"], &["land-receipt"])).unwrap();
    let trusted_file = dir.path().join("trusted.json");
    std::fs::write(&trusted_file, trusted.public_json().unwrap()).unwrap();

    let install_hook = |repo_id: &str| {
        let hook = sandbox.forge.join("hooks/pre-receive");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        let script = format!(
            "#!/bin/sh\nexec '{BIN}' pre-receive --trusted-keys '{}' --repo-id '{repo_id}' --protect refs/heads/release\n",
            trusted_file.display()
        );
        std::fs::write(&hook, script).unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    let repo_id = canonical_repo_id(text(&sandbox.forge));
    install_hook(&repo_id);
    sandbox.forge_git(&["config", "receive.advertisePushOptions", "true"]);

    let base = sandbox.forge_head(MAIN);
    let lane = sandbox.lane("lane", "main", &[("src/a.txt", "ok lane\n")]);
    let plain = |refspec: &str| {
        Command::new("git").arg("-C").arg(&sandbox.work).args(["push", "--quiet", "origin", refspec]).output().unwrap()
    };
    let refused = plain(&format!("{lane}:{MAIN}"));
    assert!(!refused.status.success(), "a push without a receipt must be refused");
    assert!(String::from_utf8_lossy(&refused.stderr).contains("no verified land receipt"));
    assert_eq!(sandbox.forge_head(MAIN), base);
    // Naming another protected ref did not unprotect main; other refs are free.
    assert!(!plain(&format!("{lane}:refs/heads/release")).status.success());
    assert!(plain("lane:refs/heads/lane").status.success());

    let custody = |key: &Path| format!("custody_mode = \"ed25519\"\ncustody_key = \"{}\"\n", key.display());
    let config = write_config(dir.path(), &custody(&key_file));
    let land = |lane: &str| landd(&["land", "--repo", text(&sandbox.work), "--lane", lane, "--config", text(&config), "--apply"]);
    let landed = land("lane");
    assert_eq!(
        landed.status.code(),
        Some(0),
        "{}{}",
        String::from_utf8_lossy(&landed.stdout),
        String::from_utf8_lossy(&landed.stderr)
    );
    let report = json(&landed);
    assert_eq!(report["outcomes"][0][1]["outcome"], "landed");
    assert_eq!(report["receipt"]["header"]["kind"], "land-receipt");
    assert_eq!(report["receipt"]["claims"]["isolation"]["isolation"], "bwrap");
    assert_eq!(report["receipt"]["claims"]["repo"], repo_id);
    assert_ne!(sandbox.forge_head(MAIN), base);

    // The same seat's receipt is worth nothing to a forge that is another repository.
    install_hook("ssh://elsewhere/project");
    sandbox.lane("second", "main", &[("docs/second.md", "second\n")]);
    let before = sandbox.forge_head(MAIN);
    let elsewhere = land("second");
    assert_eq!(elsewhere.status.code(), Some(1));
    assert_eq!(json(&elsewhere)["outcomes"][0][1]["outcome"], "refused");
    assert_eq!(sandbox.forge_head(MAIN), before);
    install_hook(&repo_id);

    // A signer the forge does not trust is refused by the hook; landd reads
    // the destination afterwards and reports the refusal instead of a landing.
    let stranger = write_key("stranger.key.json", 22);
    sandbox.lane("third", "main", &[("docs/third.md", "third\n")]);
    write_config(dir.path(), &custody(&stranger));
    let refused = land("third");
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(json(&refused)["outcomes"][0][1]["outcome"], "refused");
    assert_eq!(sandbox.forge_head(MAIN), before);

    // Signing without the sandbox, and with a key other accounts can read, does not start.
    write_config(dir.path(), &format!("{}isolation = \"none\"\n", custody(&key_file)));
    let unsandboxed = land("third");
    assert_eq!(unsandboxed.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unsandboxed.stderr).contains("isolation"));
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    write_config(dir.path(), &custody(&key_file));
    let readable = land("third");
    assert_eq!(readable.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&readable.stderr).contains("0600"), "{}", String::from_utf8_lossy(&readable.stderr));
    assert_eq!(sandbox.forge_head(MAIN), before);
}

/// The `ast-sweep` benchmark against a real repository. Set
/// `LANDD_BENCH_REPO` and `LANDD_BENCH_REV` (a commit id, so the numbers
/// name what they measured) to run it; `LANDD_BENCH_PREV`,
/// `LANDD_BENCH_RULES` and `LANDD_BENCH_GATEAUDITS` are optional. It only
/// reads the repository and writes its cache to a temporary directory.
#[test]
fn bench_sweep_cold_vs_warm() {
    let Some(repo) = std::env::var_os("LANDD_BENCH_REPO") else {
        eprintln!("LANDD_BENCH_REPO is not set; skipping the sweep benchmark");
        return;
    };
    let rev = std::env::var("LANDD_BENCH_REV").unwrap_or_else(|_| "HEAD".into());
    let extra: Vec<String> = [("LANDD_BENCH_RULES", "--rules"), ("LANDD_BENCH_GATEAUDITS", "--gateaudits")]
        .iter()
        .filter_map(|(var, flag)| Some([flag.to_string(), std::env::var(var).ok()?]))
        .flatten()
        .collect();
    let sweep = |rev: &str, cache: &Path| {
        let mut args = vec!["sweep", "--repo", repo.to_str().unwrap(), "--rev", rev, "--cache-dir", text(cache), "--json"];
        args.extend(extra.iter().map(String::as_str));
        let started = Instant::now();
        let out = landd(&args);
        let wall = started.elapsed().as_secs_f64() * 1000.0;
        assert!(matches!(out.status.code(), Some(0 | 1)), "{}", String::from_utf8_lossy(&out.stderr));
        (json(&out), wall)
    };
    let show = |label: &str, report: &Value, wall: f64| {
        eprintln!(
            "bench {label} @ {rev}: process {wall:.1} ms | list {:.1} map {:.1} (load {:.1} parse {:.1}) graph {:.1} reduce {:.1} cones {:.1} total {:.1} ms | {} files, {} parsed, {} re-read singly, {}/{} packs hit | {} findings, {} cones, {} widened",
            report["stats"]["list_ms"].as_f64().unwrap(), report["stats"]["map_ms"].as_f64().unwrap(),
            report["stats"]["load_ms"].as_f64().unwrap(), report["stats"]["parse_ms"].as_f64().unwrap(),
            report["graph_ms"].as_f64().unwrap(), report["reduce_ms"].as_f64().unwrap(),
            report["cones_ms"].as_f64().unwrap(), report["total_ms"].as_f64().unwrap(),
            report["stats"]["files"], report["stats"]["blobs_parsed"], report["stats"]["blobs_from_cache"],
            report["stats"]["packs_hit"], report["stats"]["packs"],
            report["findings"], report["cones"].as_array().map(Vec::len).unwrap_or(0), report["widened_cones"],
        );
    };
    // With LANDD_BENCH_PREV: warm the cache on an earlier revision, then
    // sweep the benchmark revision. Only blobs that changed are parsed.
    if let Ok(previous) = std::env::var("LANDD_BENCH_PREV") {
        let scratch = tempfile::tempdir().unwrap();
        sweep(&previous, &scratch.path().join("cache"));
        let (next, wall) = sweep(&rev, &scratch.path().join("cache"));
        show(&format!("incremental from {previous}"), &next, wall);
        assert!(next["stats"]["blobs_parsed"].as_u64().unwrap() < next["stats"]["fact_files"].as_u64().unwrap());
    }
    let dir = tempfile::tempdir().unwrap();
    let (cold, cold_wall) = sweep(&rev, &dir.path().join("cache"));
    show("cold", &cold, cold_wall);
    let (warm, warm_wall) = sweep(&rev, &dir.path().join("cache"));
    show("warm", &warm, warm_wall);
    assert!(cold["stats"]["blobs_parsed"].as_u64().unwrap() > 0);
    assert_eq!(warm["stats"]["blobs_parsed"], 0);
    assert_eq!(warm["verdicts"], cold["verdicts"]);
    assert_eq!(warm["cones"], cold["cones"]);
    assert!(warm["stats"]["map_ms"].as_f64().unwrap() < cold["stats"]["map_ms"].as_f64().unwrap());
}

#[test]
fn a_closed_stdout_pipe_ends_the_process_quietly() {
    let dir = tempfile::tempdir().unwrap();
    let files: Vec<(String, String)> = (0..300).map(|i| (format!("m{i}.sh"), "python run.py\n".to_owned())).collect();
    let borrowed: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
    let sandbox = Sandbox::new(dir.path(), &borrowed);
    let mut child = Command::new(BIN)
        .args(["sweep", "--repo", text(&sandbox.work), "--no-cache"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Close the read end before the 300 findings are printed.
    drop(child.stdout.take());
    let out = child.wait_with_output().unwrap();
    assert!(out.status.code().is_some(), "killed by a signal");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"), "{}", String::from_utf8_lossy(&out.stderr));
}
