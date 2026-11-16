//! End-to-end tests of the `landd` binary against throwaway repositories.

use landd_core::custody::{SigningKey, TrustedKeys};
use landd_core::digest::hex_encode;
use landd_core::git::testkit::Sandbox;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_landd");
const MAIN: &str = "refs/heads/main";

fn landd(args: &[&str]) -> Output {
    Command::new(BIN).args(args).stdin(Stdio::null()).output().expect("landd runs")
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("not JSON ({e}): {}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
}

fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

const MANIFEST: &str = r#"{"units": {
    "a": {"path": "checks/a.sh", "inputs": ["checks/a.sh", "src/a.txt"]},
    "b": {"path": "checks/b.sh", "inputs": ["checks/b.sh", "src/b.txt"]}}}"#;

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
        root.join("cache").display()
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
    assert_eq!(cold.status.code(), Some(1), "a failing rule exits 1");
    let report = json(&cold);
    assert_eq!(report["rules_failed"], 2);
    assert_eq!(report["verdicts"][0]["findings"][0]["path"], "Makefile");
    assert_eq!(report["verdicts"][1]["findings"][0]["line"], 3);
    assert_eq!(report["verdicts"][2]["status"], "pass");
    assert_eq!(report["cones"][0]["unit"], "tests.test_mod");
    assert_eq!(report["stats"]["blobs_parsed"], 4);

    let warm = json(&landd(&args));
    assert_eq!(warm["stats"]["blobs_parsed"], 0);
    assert_eq!(warm["stats"]["packs_hit"], warm["stats"]["packs"]);
    assert_eq!(warm["verdicts"], report["verdicts"]);
    assert_eq!(warm["cones"], report["cones"]);

    // Human output, the working-tree mode, and a clean pack.
    let human = landd(&["sweep", "--repo", text(&sandbox.work), "--rules", text(&rules), "--no-cache", "--worktree"]);
    let printed = String::from_utf8_lossy(&human.stdout).into_owned();
    assert!(printed.contains("FAIL bare-python (1 findings)") && printed.contains("Makefile:2:"), "{printed}");
    std::fs::write(&rules, "[[rule]]\nid = \"graph\"\nkind = \"python_import_graph\"\n").unwrap();
    assert_eq!(landd(&args).status.code(), Some(0));
    assert_eq!(landd(&["sweep", "--repo", text(dir.path()), "--rev", "nope"]).status.code(), Some(2));
}

#[test]
fn cones_show_changed_and_transported_units() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = Sandbox::new(
        dir.path(),
        &[
            ("lib/__init__.py", ""),
            ("lib/a.py", "A = 1\n"),
            ("lib/b.py", "B = 1\n"),
            ("tests/test_a.py", "from lib import a\n"),
            ("tests/test_b.py", "from lib import b\n"),
        ],
    );
    let base = sandbox.git(&["rev-parse", "HEAD"]);
    sandbox.commit("main", "edit a", &[("lib/a.py", "A = 2\n"), ("tests/test_c.py", "import lib\n")], &[]);
    let out = landd(&["cones", "--repo", text(&sandbox.work), "--base", &base, "--head", "HEAD", "--no-cache", "--json"]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let report = json(&out);
    assert_eq!((report["units"].as_u64(), report["transported"].as_u64()), (Some(3), Some(1)));
    assert_eq!(report["changed"][0]["unit"], "tests.test_a");
    assert_eq!(report["changed"][0]["moved_paths"], serde_json::json!(["lib/a.py"]));
    assert_eq!(report["added"], serde_json::json!(["tests.test_c"]));

    let human = landd(&["cones", "--repo", text(&sandbox.work), "--base", &base, "--head", "HEAD", "--no-cache"]);
    let printed = String::from_utf8_lossy(&human.stdout).into_owned();
    assert!(printed.contains("3 units: 1 transported (0 runs), 1 changed, 1 added, 0 removed"), "{printed}");
    assert!(printed.contains("changed tests.test_a <- lib/a.py"), "{printed}");
}

#[test]
fn land_dry_run_then_apply_then_decline() {
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

    let declined = land("bad", true);
    assert_eq!(declined.status.code(), Some(1));
    let report = json(&declined);
    assert_eq!(report["outcomes"][0][1]["outcome"], "declined");
    assert_eq!(report["outcomes"][0][1]["evidence"]["why_not"][0]["moved_paths"], serde_json::json!(["src/b.txt"]));
    assert_eq!(sandbox.forge_head(MAIN), head);

    assert_eq!(land("no-such-lane", true).status.code(), Some(2));
    let bad_setting = landd(&["land", "--repo", text(&sandbox.work), "--lane", "good", "--set", "max_batch_size=0"]);
    assert_eq!(bad_setting.status.code(), Some(2));
}

fn ctl(socket: &Path, request: &[&str]) -> Value {
    let mut args = vec!["ctl", "--socket", text(socket)];
    args.extend_from_slice(request);
    json(&landd(&args))
}

#[test]
fn daemon_lands_concurrent_enqueues_in_batches() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = manifest_repo(dir.path());
    let config = write_config(dir.path(), "max_batch_size = 8\n");
    let base = sandbox.forge_head(MAIN);
    let lanes = [
        ("one", sandbox.lane("one", "main", &[("src/a.txt", "ok one\n")])),
        ("two", sandbox.lane("two", "main", &[("docs/two.md", "two\n")])),
        ("three", sandbox.lane("three", "main", &[("docs/three.md", "three\n")])),
        ("bad", sandbox.lane("bad", "main", &[("src/b.txt", "broken\n")])),
    ];
    let socket = dir.path().join("landd.sock");
    let mut daemon = Command::new(BIN)
        .args(["daemon", "--socket", text(&socket), "--config", text(&config), "--repo", text(&sandbox.work)])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "the daemon never bound its socket");
        std::thread::sleep(Duration::from_millis(20));
    }

    // Four clients at once.
    std::thread::scope(|scope| {
        for (lane, tip) in &lanes {
            let socket = &socket;
            scope.spawn(move || {
                let reply = ctl(socket, &["enqueue", lane]);
                assert_eq!(reply["reply"], "enqueued", "{reply}");
                assert_eq!(reply["tip"], tip.to_hex());
            });
        }
    });
    assert_eq!(ctl(&socket, &["enqueue", "no-such-lane"])["reply"], "error");

    let status = loop {
        let status = ctl(&socket, &["status"]);
        if status["settled"].as_array().is_some_and(|s| s.len() == lanes.len()) {
            break status;
        }
        assert!(Instant::now() < deadline + Duration::from_secs(40), "the daemon never settled: {status}");
        std::thread::sleep(Duration::from_millis(50));
    };
    let outcome = |lane: &str| {
        let settled = status["settled"].as_array().unwrap();
        settled.iter().find(|s| s["lane"] == lane).map(|s| s["outcome"].as_str().unwrap().to_owned()).unwrap()
    };
    assert_eq!((outcome("one"), outcome("two"), outcome("three"), outcome("bad")), ("landed".into(), "landed".into(), "landed".into(), "declined".into()));
    // Fewer batches than lanes: the burst shared at least one train.
    assert!(status["batches"].as_u64().unwrap() < lanes.len() as u64, "{status}");

    let repo = sandbox.repo();
    repo.fetch("origin", MAIN).unwrap();
    let head = sandbox.forge_head(MAIN);
    assert!(repo.is_ancestor(&base, &head).unwrap());
    for (lane, tip) in &lanes {
        assert_eq!(repo.is_ancestor(tip, &head).unwrap(), *lane != "bad", "{lane}");
    }

    assert_eq!(ctl(&socket, &["shutdown"])["reply"], "shutting_down");
    let exit = daemon.wait().unwrap();
    assert!(exit.success());
    assert!(!socket.exists());
}

#[test]
fn replay_prints_markdown_and_json() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("land_runs.jsonl");
    let row = |ts: u32, head: &str, outcome: &str| {
        format!("{{\"kind\":\"land\",\"ts\":{ts},\"apply\":true,\"head\":\"{head}\",\"outcome\":\"{outcome}\",\"modules\":{{\"tests.t\":20}},\"cpu_s\":20,\"wall_s\":25}}\n")
    };
    std::fs::write(&ledger, [row(0, "h1", "refused:push"), row(60, "h1", "landed"), row(61, "h2", "landed"), "garbage\n".into()].concat()).unwrap();
    let costs = dir.path().join("costs.json");
    std::fs::write(&costs, r#"{"tests.t": 10}"#).unwrap();

    let out = landd(&["replay", "--ledger", text(&ledger), "--module-costs", text(&costs), "--json", "--set", "runner_concurrency=1"]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let report = json(&out);
    assert_eq!((report["ledger_rows"].as_u64(), report["ledger_malformed"].as_u64()), (Some(4), Some(1)));
    assert_eq!((report["actual_fleet"]["total_cpu_s"].as_f64(), report["actual_fleet"]["lost_races"].as_u64()), (Some(60.0), Some(1)));
    assert_eq!((report["landd"]["total_cpu_s"].as_f64(), report["landd"]["landed"].as_u64()), (Some(20.0), Some(2)));

    let markdown = String::from_utf8(landd(&["replay", "--ledger", text(&ledger)]).stdout).unwrap();
    assert!(markdown.contains("| lost races | 1 | 0 |"), "{markdown}");
}

/// A forge guarded by `landd pre-receive`: a plain push to main is refused,
/// a push through landd carries a receipt and is accepted.
#[test]
fn pre_receive_hook_admits_only_receipted_fast_forwards() {
    let dir = tempfile::tempdir().unwrap();
    let sandbox = manifest_repo(dir.path());
    let key = SigningKey::ed25519_from_seed([21; 32]);
    let key_file = dir.path().join("seat.key.json");
    std::fs::write(&key_file, format!(r#"{{"key_id":"seat-1","alg":"ed25519","key":"{}"}}"#, hex_encode(&[21; 32]))).unwrap();
    let mut trusted = TrustedKeys::new();
    trusted.insert("seat-1", key.trusted());
    let trusted_file = dir.path().join("trusted.json");
    std::fs::write(&trusted_file, trusted.to_json()).unwrap();

    let hook = sandbox.forge.join("hooks/pre-receive");
    std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
    std::fs::write(&hook, format!("#!/bin/sh\nexec '{BIN}' pre-receive --trusted-keys '{}'\n", trusted_file.display())).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    sandbox.forge_git(&["config", "receive.advertisePushOptions", "true"]);

    let base = sandbox.forge_head(MAIN);
    let lane = sandbox.lane("lane", "main", &[("src/a.txt", "ok lane\n")]);
    let plain = Command::new("git")
        .arg("-C")
        .arg(&sandbox.work)
        .args(["push", "--quiet", "origin", &format!("{lane}:{MAIN}")])
        .output()
        .unwrap();
    assert!(!plain.status.success(), "a push without a receipt must be refused");
    assert!(String::from_utf8_lossy(&plain.stderr).contains("no verified land receipt"));
    assert_eq!(sandbox.forge_head(MAIN), base);
    // Other refs are not guarded.
    sandbox.git(&["push", "--quiet", "origin", "lane:refs/heads/lane"]);

    let config = write_config(dir.path(), &format!("custody_mode = \"ed25519\"\ncustody_key = \"{}\"\n", key_file.display()));
    let landed = landd(&["land", "--repo", text(&sandbox.work), "--lane", "lane", "--config", text(&config), "--apply"]);
    assert_eq!(landed.status.code(), Some(0), "{}{}", String::from_utf8_lossy(&landed.stdout), String::from_utf8_lossy(&landed.stderr));
    let report = json(&landed);
    assert_eq!(report["outcomes"][0][1]["outcome"], "landed");
    assert_eq!(report["receipt"]["header"]["kind"], "land-receipt");
    assert_ne!(sandbox.forge_head(MAIN), base);

    // A signer the forge does not trust is refused by the hook; landd reads
    // the forge afterwards and reports the refusal instead of a landing.
    let stranger = dir.path().join("stranger.key.json");
    std::fs::write(&stranger, format!(r#"{{"key_id":"seat-1","alg":"ed25519","key":"{}"}}"#, hex_encode(&[22; 32]))).unwrap();
    sandbox.lane("second", "main", &[("docs/second.md", "second\n")]);
    let before = sandbox.forge_head(MAIN);
    let config = write_config(dir.path(), &format!("custody_mode = \"ed25519\"\ncustody_key = \"{}\"\n", stranger.display()));
    let refused = landd(&["land", "--repo", text(&sandbox.work), "--lane", "second", "--config", text(&config), "--apply"]);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(json(&refused)["outcomes"][0][1]["outcome"], "refused");
    assert_eq!(sandbox.forge_head(MAIN), before);
}

/// The `ast-sweep` benchmark against a real repository. Set
/// `LANDD_BENCH_REPO` (and optionally `LANDD_BENCH_REV`) to run it; it only
/// reads the repository and writes its cache to a temporary directory.
#[test]
fn bench_sweep_cold_vs_warm() {
    let Some(repo) = std::env::var_os("LANDD_BENCH_REPO") else {
        eprintln!("LANDD_BENCH_REPO is not set; skipping the sweep benchmark");
        return;
    };
    let rev = std::env::var("LANDD_BENCH_REV").unwrap_or_else(|_| "HEAD".into());
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    let mut args = vec!["sweep", "--repo", repo.to_str().unwrap(), "--rev", &rev, "--cache-dir", text(&cache), "--json"];
    let rules = std::env::var("LANDD_BENCH_RULES").ok();
    if let Some(rules) = &rules {
        args.extend(["--rules", rules]);
    }
    let timed = |label: &str| {
        let started = Instant::now();
        let out = landd(&args);
        let wall = started.elapsed().as_secs_f64() * 1000.0;
        assert!(matches!(out.status.code(), Some(0 | 1)), "{}", String::from_utf8_lossy(&out.stderr));
        let report = json(&out);
        eprintln!(
            "bench {label}: process {wall:.1} ms | list {:.1} map {:.1} graph {:.1} reduce {:.1} cones {:.1} total {:.1} ms | {} files, {} parsed, {} packs hit | {} findings, {} cones",
            report["stats"]["list_ms"].as_f64().unwrap(), report["stats"]["map_ms"].as_f64().unwrap(),
            report["graph_ms"].as_f64().unwrap(), report["reduce_ms"].as_f64().unwrap(),
            report["cones_ms"].as_f64().unwrap(), report["total_ms"].as_f64().unwrap(),
            report["stats"]["files"], report["stats"]["blobs_parsed"], report["stats"]["packs_hit"],
            report["findings"], report["cones"].as_array().map(Vec::len).unwrap_or(0),
        );
        report
    };
    // With LANDD_BENCH_PREV: warm the cache on an earlier revision, then
    // sweep the benchmark revision. Only blobs that changed are parsed.
    if let Ok(previous) = std::env::var("LANDD_BENCH_PREV") {
        let scratch = tempfile::tempdir().unwrap();
        let cache = scratch.path().join("cache");
        let sweep = |rev: &str| {
            let mut args = vec!["sweep", "--repo", repo.to_str().unwrap(), "--rev", rev, "--cache-dir", text(&cache), "--json"];
            if let Some(rules) = &rules {
                args.extend(["--rules", rules]);
            }
            json(&landd(&args))
        };
        sweep(&previous);
        let next = sweep(&rev);
        eprintln!(
            "bench incremental {previous} -> {rev}: {} blobs parsed, {} re-read singly, {}/{} packs hit | list {:.1} map {:.1} (load {:.1} parse {:.1}) total {:.1} ms",
            next["stats"]["blobs_parsed"], next["stats"]["blobs_from_cache"], next["stats"]["packs_hit"], next["stats"]["packs"],
            next["stats"]["list_ms"].as_f64().unwrap(), next["stats"]["map_ms"].as_f64().unwrap(),
            next["stats"]["load_ms"].as_f64().unwrap(), next["stats"]["parse_ms"].as_f64().unwrap(), next["total_ms"].as_f64().unwrap(),
        );
        assert!(next["stats"]["blobs_parsed"].as_u64().unwrap() < next["stats"]["fact_files"].as_u64().unwrap());
    }

    let cold = timed("cold");
    let warm = timed("warm");
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
