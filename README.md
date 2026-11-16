# landd

A speculative Git merge train and content-addressed tree checker, written in Rust.

`landd` composes candidate branches with `git merge-tree`, evaluates checks on the prospective tree, and advances the destination with a compare-and-swap push. It records external delivery attempts and checks destination ancestry after sending. `ast-sweep` maps Git blobs to cached facts and reduces those facts through a configurable rule pack.

## Development status

This is an experimental implementation. Audits of its first version and subsequent takeover reviews found gaps in runner isolation, dependency tracking, delivery recovery and daemon handling; [HARDENING.md](HARDENING.md) lists every finding with what was done and the tests that show it. Read that file before relying on anything here.

Initial measurements on one private Python repository of about 4,000 files and 1,216 test modules:

- **No test reuse.** Under the default strict cone model every test cone on that repository depends on the whole tree, because the support module every test imports reads the whole tree. None of that repository's 37 dynamic-loader declarations can be verified from source. Those initial results predate scoped symbol analysis; subsequent results and their limits are recorded in HARDENING.md.
- **Sweep time.** About 0.9 s cold and 0.16 s warm for a one-shot `landd sweep`; an incremental sweep parses only the changed blobs. The latency figures in the first SPEC were goals, were not met, and have been withdrawn.
- **No savings claim.** The real land ledger does not record which test modules each run selected, so the replay reports itself unavailable instead of estimating. The simulator's model is exercised on synthetic ledgers only.

Static Python analysis is not a proof that every possible input was found. Cone views enforce the selected file set; whole-tree views bind every tracked file into the verdict. Adopting restricted views still requires checking that the project's tests retain their intended behavior.

Units run in a `bwrap` sandbox by default and receipts can only be signed in that mode. `isolation = "none"` runs units as ordinary child processes and is for trusted code only. The example rules are a starter pack, not a port of any project's checks.

## Build and inspect

Use a Linux build host with Rust, Git 2.40 or newer and, for the default isolation mode, bubblewrap:

```sh
cargo build --release --locked -p landd
./target/release/landd --help
./target/release/landd sweep --repo /path/to/repository --rev HEAD --json
./target/release/landd cones --repo /path/to/repository --base HEAD~1 --head HEAD --json
```

The workspace contains `landd-core`, `ast-sweep`, `landd-train`, `landd-sim`, and the `landd` CLI/daemon. See [SPEC.md](SPEC.md) for the design contract and [examples/landd.toml](examples/landd.toml) for configuration. Measurements are in [HARDENING.md](HARDENING.md).

## License

Licensed under either the [MIT license](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option.
