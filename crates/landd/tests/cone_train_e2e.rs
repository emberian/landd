//! Exercise the shipped proof-fabric bridge and CLI over their external wire interface.
#[test]
fn eight_branch_train_and_fenced_pods() {
    let test = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/proof_fabric_bridge.test.mjs");
    let status = std::process::Command::new("node")
        .args(["--test"])
        .arg(test)
        .env("LANDD_BIN", env!("CARGO_BIN_EXE_landd"))
        .status()
        .expect("node on PATH");
    assert!(status.success());
}
