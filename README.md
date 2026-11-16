# landd

A speculative Git merge train and content-addressed tree checker, written in Rust.

`landd` composes candidate branches with `git merge-tree`, evaluates checks on the prospective tree, and advances the destination with a compare-and-swap push. It records external delivery attempts and checks destination ancestry after sending. `ast-sweep` maps Git blobs to cached facts and reduces those facts through a configurable rule pack.

## Development status

This is an experimental implementation undergoing hardening. The initial suite passes, but audits identified gaps in runner isolation, dependency tracking, delivery recovery, and daemon handling. Do not use the current train to enforce an adversarial admission boundary.

The initial Fleet corpus benchmark measured about 650–700 ms cold and 27 ms warm in a persistent process. All 1,216 Fleet test cones currently widen to the whole tree, so this version has demonstrated no test reuse on that corpus. The example rules are a starter pack, not a complete port of Fleet's checks. The replay simulator has only been tested on synthetic ledgers.

## Build and inspect

Use a Linux build host with Rust and Git installed:

```sh
cargo build --release --locked -p landd
./target/release/landd --help
./target/release/landd sweep --repo /path/to/repository --rev HEAD --json
./target/release/landd cones --repo /path/to/repository --base HEAD~1 --head HEAD --json
```

The workspace contains `landd-core`, `ast-sweep`, `landd-train`, `landd-sim`, and the `landd` CLI/daemon. See [SPEC.md](SPEC.md) for the design contract and [examples/landd.toml](examples/landd.toml) for configuration. SPEC latency figures are targets, not benchmark results.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the [Apache License, Version 2.0](LICENSE-APACHE), at your option.
