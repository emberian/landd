# `landd` + `ast-sweep` Specification (`SPEC.md`)

A Rust workspace providing:

1. **`ast-sweep`**: a single-pass, content-addressed `Map(git_blob_oid -> FileFacts) -> Reduce(AllFacts -> Vec<RuleVerdict>)` static tree checker meant to replace many separate whole-tree Python walkers. Per-blob summaries are cached forever (no wall-clock TTL), so a land touching N files parses N blobs.
2. **`landd`**: a speculative `git merge-tree --write-tree` batch merge train, a value-addressed admissibility engine, a durable `Delivery` CAS outbox, an extensible signed custody envelope, and an offline `land_runs.jsonl` reader and replay.

This document is the design contract. Where it gives a number, the number is either labelled a **goal** or cited from [HARDENING.md](HARDENING.md), which records what was measured and on what. The first version of this document stated latency figures (a `<5 ms` incremental sweep, a `<80 ms` cold sweep, a `<10 ms` cone export) as if they were properties of the design. They are not achieved: `git ls-tree` alone costs about 10 ms on the benchmark tree, and a cold sweep is bounded by parsing. They are removed here rather than repeated.

---

## 1. Hard Compatibility Contract

1. **No force-push and no rewriting pushed history.** Every landed merge is a fast-forward of the target ref through ordinary 2-parent merge commits (`git commit-tree` over `git merge-tree --write-tree` output), pushed with `--force-with-lease=<ref>:<expected_old_oid>`. The chain is built on `expected_old`, so the lease makes the update a compare-and-swap.
2. **Ancestry is read from the push destination after every push.** After `git push` exits, times out, or is found unread after a restart, `landd` reads the target ref at the *push* URL (not the fetch URL) and checks ancestry before recording anything. This train's own merge on the destination is `landed`; the lane tip on the destination through some other commit is `carried`.
3. **Destination completion dominates (`Delivery` law).**
   - State machine `Fresh | Unknown | Refused { attempts, not_before } | Declined { evidence } | Completed { evidence }`, persisted (exclusive create of a new revision, synced with its directory chain) *before* the network send, keyed by a domain-separated BLAKE3 of the canonical binding `{ repo, target_ref, lane_tip, expected_old, merged_head }`.
   - `Declined` is terminal against `start()`, `refused()` and `declined()`, and can only be entered from `Fresh` or `Refused`: an outstanding send (`Unknown`) must be settled by reading the destination. `complete(evidence)` succeeds from every state when the evidence names this repository, ref and lane tip.
   - Merge commits are a function of their parents (fixed committer, date = the later parent date), so a retry of the same composition is the same binding: refusals accumulate and `max_refusals` is reachable. A per-lane-tip pointer finds the latest binding after a restart or a moved base.
4. **Per-seat signed custody (`CustodyEnvelope`).**
   - `sign(key, "landd-custody/v2\n" || BLAKE3(canonical_header) || BLAKE3(canonical_claims))` with Ed25519, SSHSIG-Ed25519 or HMAC-SHA256. Claims are open-ended: a verifier needs no list of permitted claim names, and any change to header or claims after sealing fails closed.
   - A trusted key carries the seats and envelope kinds it may attest; a valid signature outside that grant is refused. A land receipt's subject binds the repository identity, the ref, and the old and new commits.
   - Receipts are sealed only when units ran in the sandbox (§1.5); the configuration, the runner and the train each refuse otherwise.
5. **Out-of-process, isolated test execution.**
   - `isolation = "bwrap"` (default): each unit runs in its own user, mount, pid, ipc and uts namespaces (and network namespace unless configured), seeing read-only system directories, its own view of the tree under a throw-away overlay, a private `/tmp` and home, and one writable directory for its result frame. A signing key or state directory that a sandbox mount would expose is refused at start.
   - `isolation = "none"`: an ordinary child process with a cleared environment. It can read whatever the supervisor's user can. For trusted code only; receipts cannot be signed.
   - The tree is materialized from the object store with exact blob bytes and git modes (no `git archive`, so no attribute rewriting). With `unit_view = "cone"` a unit sees only its cone's files. With `unit_view = "tree"` every verdict binds the entire tracked tree, even when the static analysis found a narrower cone.
   - Recorded verdicts are valid for one runtime image. `landd` hashes the test program and the output of the configured profile commands, not every library the sandbox mounts; `runtime_id` is the operator's declaration that the image changed.
6. **Differential admissibility ("no redder than base").**
   - `Observation { unit_id, cone_digest, status }` with `status: Pass | Fail { items } | Crash | Timeout`, keyed by content, never by wall-clock age. The cone digest covers each input's path, git mode and blob, whether the cone was widened, and a context digest (rule pack, runner profile).
   - A candidate is admissible iff every unit of either tree is accounted for: same cone digest as base (transported, 0 runs); `Pass` at the candidate cone; or `Fail { items }` whose items are a subset of the base's `Fail { items }` (inherited). A crash or timeout is not comparable with anything unless the operator sets `inherit_coarse_failures`. A unit present on the base and absent from the candidate blocks unless `allow_unit_removal`.
   - `why_not` names every blocking unit and the input paths that moved under it.
7. **Operational limits are runtime settings** (`LandConfig` TOML/JSON plus `--set key=value`); see `examples/landd.toml`.

### Pod ledger

The pod service and each authenticated `pod-step --stream` session hold one SQLite connection. The database must enter WAL mode. Claims and completions commit at `synchronous=NORMAL` before acknowledgement, so they survive a daemon SIGKILL. A power loss can roll back recent claims or completions. Each open reserves a new epoch at `FULL`, and every claim uses the database's current epoch under its write transaction. Reclaiming an expired task therefore issues a higher fencing token even when an older connection performs the reclaim. Lead changes commit at `FULL`. The HTTP service returns tokens as decimal strings. The stream also uses decimal strings for tokens beyond JavaScript's exact integer range.

---

## 2. Cones

A cone is a proposed set of repository inputs. `ast-sweep` derives it from recognized Python syntax:

- the imports reached by the test and every `conftest.py` above it, including literal-path loads and Python child processes with a literal script or `-m` module; module initialization is always included, while imported symbols follow their own recorded dependencies rather than every unused helper;
- files those modules read as data (opens, existence probes, listings, walks, globs) when the path is built from `__file__`, the working directory or literals;
- `guards` (unit pattern → paths) and `domains` from a trusted `gateaudits.json`, and the pack's `always` list;
- what a declared dynamic loader can load, **only while the loader's own source shows a literal prefix the declaration covers**. The check is made on every tree, so an edit to a loader cannot hide behind an old declaration.

Recognized reads and loaders that cannot be resolved widen the cone to the whole tree, with the cause recorded. Under the default `cone_model = "strict"` that includes every read through a path the analysis cannot follow (a parameter, an attribute, a computed name), every child process that is not a literal Python invocation, every undeclared or unverifiable dynamic load, a file that does not parse, an unresolved relative import, and a symbolic link that leaves the tree. `cone_model = "hermetic"` instead relies on `unit_view = "cone"` to make unaccounted reads fail closed; it is not the default and still widens for scans it cannot bound.

This analysis does not prove the absence of hidden Python effects. It tracks a finite set of constructs; arbitrary reflection, monkey-patching and runtime plugins can hide inputs from it. The runtime boundary is therefore essential: sandboxed `unit_view = "cone"` exposes only the recorded repository files, and `unit_view = "tree"` binds all tracked files into every verdict. A narrow view can change test behavior; before adopting it, compare the project's actual checks under the original and restricted views. Neither a static cone comparison nor passing synthetic tests establishes that equivalence. External mounted runtime contents still depend on the operator's `runtime_id` contract.

The symbol graph conservatively includes import-time default arguments, class bodies, descriptors, subclass hooks, custom decorators and escaped instances. Direct function calls can propagate known file arguments within a module; externally callable parameters remain opaque. Dynamic introspection and wildcard or bare-module references widen to the relevant module's recorded effects. These are supported cases, not a complete model of Python.

The rule pack is an operator path and is never read from the tree under test. A manifest-declared unit's inputs are the union of what the base's and the candidate's manifests declare.

---

## 3. Workspace Crate Layout

- **`crates/landd-core`**: `Oid`, `Digest32`, canonical JSON, `LandConfig`, the `Delivery` journal, `CustodyEnvelope`, the admissibility engine, git plumbing (`ls-tree -z`, pooled `cat-file --batch`, `merge-tree`, lease push, network deadlines).
- **`crates/ast-sweep`**: tree reader (git or directory), the per-blob facts cache, the tree-sitter extractor, the dependency graph and cones, and eight declarative rule kinds (`no_tracked_bytecode`, `no_bare_python_recipe`, `flock_bounded`, `atomic_replace_owner`, `uncatalogued_settings_keys`, `forbidden_symbol_or_call`, `single_owner_pattern`, `python_import_graph`).
- **`crates/landd-train`**: composition, the runner, the train (judge, bisect, deliver), the lane queue.
- **`crates/landd-sim`**: ledger reader (real `fleet` schema), observed metrics, and a discrete-event replay that runs only when the ledger records per-run module sets and costs.
- **`crates/landd`**: CLI and Unix-socket daemon.
  - `landd sweep --repo <path> [--rev HEAD] [--rules <pack>] [--gateaudits <json>] [--cache-dir <dir>] [--json]`
  - `landd cones --repo <path> --base <rev> --head <rev> [--json]`
  - `landd land --repo <path> --lane <branch_or_sha> [--target refs/heads/main] [--apply]`
  - `landd daemon --socket <path> --config <landd.toml>` and `landd ctl --socket <path> enqueue|status|shutdown`
  - `landd replay --ledger <land_runs.jsonl> [--timings <json>] [--module-costs <json>] [--json]`
  - `landd pre-receive --trusted-keys <file> --repo-id <id> [--protect <ref>]…`

Daemon queues are namespaced by canonical destination identity and target ref, with a lifetime writer lock independent of socket name. Enqueue acknowledgments follow durable persistence; a newer queued tip survives an older in-flight snapshot. Nonempty legacy `queue.json` files are preserved and refused with explicit migration instructions. Trusted state requires safe directory ancestry and cannot be placed inside the repository or its Git directories.

The train: compose `T_1..T_k`; a candidate that cannot join (conflict, unmergeable, already on the base, contained in an earlier candidate, no change) leaves the chain without delaying its peers. Judge the tip against the base, running only units whose cones moved. On a new red, split the batch to isolate culprits; a lane that conflicted only with a culprit, or was contained in one, is judged again against the chain that stands. Push once under a lease, read the destination, record what it holds.

---

## 4. Required `#tooth` / Adversarial Self-Tests

Every subsystem carries positive and negative (`tooth_`) tests. The ones this contract names:

- **Cone cache**: one byte in a transitive dependency changes the cone digest; a disjoint change preserves it byte for byte; a revert restores it and hits a verdict whose file is ten years old; a data file a test opens is in its cone; mode changes and gitlink bumps move cones.
- **`Delivery`**: a lost reply refuses `start()`; `Declined` refuses `start()` at `u64::MAX` yet completes on destination evidence; an outstanding send cannot be declined unread; a mismatched binding under one key errors; a saturated send counter refuses instead of wrapping.
- **`CustodyEnvelope`**: unknown claims verify with the original signature; any change to claims, header or domain tag fails closed; a key outside its grant, a receipt for another repository, and non-canonical wire bytes are refused.
- **Train**: `[good1, bad2, conflict3, good4]` isolates `bad2`, declines `conflict3`, and lands `good1 + good4` as a 2-parent chain with no force-push; stacked lanes; carried vs landed; unit removal; an unread send settled from the destination.
- **Runner**: a sandboxed unit cannot reach the signing key, the state directory, the repository, sibling results or the host process table; hostile result files do not hang the supervisor.
- **Benchmark**: `landd sweep` cold vs warm against a pinned commit of a real repository, reporting milliseconds and findings (env-gated; results in HARDENING.md).
