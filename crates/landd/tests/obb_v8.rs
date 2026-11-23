//! Run with OBB_BIN pointing at the v8 binary used by the issuing station.
use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn check(out: Output) -> String {
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

#[test]
#[ignore = "cross-project acceptance requires OBB_BIN"]
fn transport_real_obb_v2_onto_speculative_merge() {
    let obb = std::env::var("OBB_BIN").expect("set OBB_BIN to the obb v8 executable");
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let repo = root.join("repo");
    let remote = root.join("dest.git");
    let state = root.join("state");
    fs::create_dir(&repo).unwrap();
    let git = |args: &[&str]| check(Command::new("git").current_dir(&repo).args(args).output().unwrap());
    git(&["init", "-b", "main"]);
    git(&["config", "user.name", "Builder"]);
    git(&["config", "user.email", "builder@example.org"]);
    git(&["init", "--bare", "-b", "main", remote.to_str().unwrap()]);
    git(&["remote", "add", "origin", remote.to_str().unwrap()]);
    let write = |p: &str, data: &str| fs::write(repo.join(p), data).unwrap();
    write("check.sh", "test \"$(cat value)\" = good\n");
    write("value", "old\n");
    write("units.json", r#"{"units":{"quality":{"path":"check.sh","inputs":["value"]}}}"#);
    git(&["add", "check.sh", "value", "units.json"]);
    git(&["commit", "-m", "base"]);
    git(&["push", "origin", "main"]);
    git(&["switch", "-c", "candidate"]);
    write("value", "good\n");
    git(&["commit", "-am", "candidate"]);
    let gate = root.join("gate.json");
    let receipt = root.join("receipt.json");
    fs::write(
        &gate,
        json!({"name":"quality","formats":["cone-unit@1"],
        "floors":[{"floor":"quality","inputs":["units.json","check.sh","value"],"command":"sh check.sh"}],
        "methods":[{"format":"cone-unit@1","floor":"quality","method":"eval:external:shell"}],"basis":["external:shell"]})
        .to_string(),
    )
    .unwrap();
    let key = "cross-project fixture verification key";
    check(
        Command::new(&obb)
            .env("OBB_RECEIPT_KEY", key)
            .args(["judge", "check", "--judge"])
            .arg(gate)
            .arg("--repo")
            .arg(&repo)
            .arg("--emit-receipt")
            .arg(&receipt)
            .output()
            .unwrap(),
    );
    let issued: Value = serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(issued["receipt_version"], 2);
    let config = root.join("station.json");
    let mut cfg = json!({"cache_dir":state,"isolation":"none","cone_source":"manifest","unit_manifest":"units.json","test_command":["/bin/sh","{path}"]});
    fs::write(&config, cfg.to_string()).unwrap();
    let land = |verb: &str, args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_landd"))
            .arg(verb)
            .arg("--repo")
            .arg(&repo)
            .arg("--config")
            .arg(&config)
            .args(args)
            .output()
            .unwrap()
    };
    let local: Value = serde_json::from_str(&check(land("unit-policy", &["--rev", "candidate", "--unit", "quality"]))).unwrap();
    cfg["obb_grants"] = json!({"quality":{"gate_sha256":issued["gate_sha256"],"toolchain_sha256":issued["toolchain_sha256"],
        "local_gate_sha256":local["gate_sha256"],"local_toolchain_sha256":local["toolchain_sha256"]}});
    fs::write(&config, cfg.to_string()).unwrap();
    fs::write(state.join("obb-receipt.key"), key).unwrap();
    git(&["switch", "main"]);
    write("unrelated", "advance\n");
    git(&["add", "unrelated"]);
    git(&["commit", "-m", "advance"]);
    git(&["push", "origin", "main"]);
    let verify = |p: &Path, tree: &str| {
        Command::new(&obb)
            .env("OBB_RECEIPT_KEY", key)
            .arg("verify-transport")
            .arg("--repo")
            .arg(&repo)
            .arg("--receipt")
            .arg(p)
            .args(["--target-tree", tree])
            .output()
            .unwrap()
    };
    let merged = git(&["merge-tree", "--write-tree", "main", "candidate"]);
    assert_eq!(check(verify(&receipt, &merged)), r#""Transported""#);
    let invalid = verify(&receipt, &git(&["rev-parse", "main^{tree}"]));
    assert!(!invalid.status.success());
    assert_eq!(serde_json::from_slice::<Value>(&invalid.stdout).unwrap(), json!({"Invalidated":{"changed_paths":["value"]}}));
    let args = ["--receipt", receipt.to_str().unwrap(), "candidate"];
    let result: Value = serde_json::from_str(&check(land("train-step", &args))).unwrap();
    assert_eq!(result["tally"]["candidate_units_run"], 0);
    assert_eq!(result["tally"]["external_receipts"]["quality"]["original_tree"], issued["tree_oid"]);
    fs::write(state.join("obb-receipt.key"), "another trusted key").unwrap();
    assert!(!land("train-step", &args).status.success());
}
