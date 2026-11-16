# `landd` + `ast-sweep` Specification (`SPEC.md`)

A standalone, zero-slop Rust workspace providing:
1. **`ast-sweep`**: A single-pass, content-addressed `Map(git_blob_oid -> FileFacts) -> Reduce(AllFacts -> Vec<RuleVerdict>)` static tree checker that replaces ~60 separate whole-tree Python walkers, caching per-blob summaries forever (zero wall-clock TTL) so a 6-commit land touching 10 files parses only 10 blobs (`<5 ms` incremental, `<80 ms` cold).
2. **`landd`**: A speculative `git merge-tree --write-tree` batch merge train + `Obend.Reasons`-grade value-addressed admissibility engine + durable `Delivery` CAS outbox + extensible v2 custody envelope + offline `land_runs.jsonl` trace simulator.

---

## 1. Hard Compatibility Contract (Must Preserve 100%)

1. **No force-push and no rewriting pushed history**: Every landed merge is an ordinary fast-forward of the target ref (`refs/heads/main`) via standard 2-parent merge commits (`git commit-tree` over `git merge-tree --write-tree` output), pushed with `--force-with-lease=<ref>:<expected_old_oid>` (strict CAS, never `--force`).
2. **Ancestry proven on the forge after every push**: After `git push` exits (or after a lost reply / `Unknown` state), `landd` queries the forge (`git ls-remote` / `fetch` + `merge-base --is-ancestor <candidate_tip> <remote_ref>`) before recording `Completed`.
3. **Destination completion dominates (`Delivery` law)**:
   - External CAS state machine (`Fresh | Unknown | Refused { attempts, not_before } | Declined { evidence } | Completed { evidence }`), persisted atomically (`O_EXCL` / temp-and-rename) *before* network send, keyed by `BLAKE3(canonical_binding)` where `binding = { repo, target_ref, lane_tip, expected_old, merged_head }`.
   - `Declined` is terminal against `start()`, `refused()`, and `declined()`, **but `complete(evidence)` succeeds from both `Unknown` and `Declined`** whenever destination ancestry proves `lane_tip` is on `target_ref` (eliminating split-brain from flaky checks, lost replies, or sibling carries).
4. **Per-seat signed custody & out-of-process runner attestation (`CustodyEnvelopeV2`)**:
   - Replaces brittle closed JSON key whitelists with a canonical versioned envelope:
     `Ed25519.sign(key, "landd-custody/v2\n" || BLAKE3(canonical_header) || BLAKE3(canonical_claims))`
     so arbitrary telemetry counters (`rung_cpu_s`, `audit_cones`, `batch_size`, etc.) live in `claims` without ever breaking signature verification or downgrading verdicts to `UNKNOWN`.
   - Test execution runs in an isolated child process (`env_clear` + explicit allowlist, `.git` hidden/unmounted where configured); receipt sealing happens solely in the parent supervisor.
5. **Keeper verdicts & `"no redder than main"` differential admissibility (`landd-reasons`)**:
   - Models `Obend.Slot` + `Obend.Reasons` 3-valued admissibility (`Supported | Undefined | Unsupported`):
     - A check verdict `Observation { unit_id, cone_digest, status: Pass | Fail(items) }` is keyed strictly by **content (`cone_digest`)**, NEVER by wall-clock age.
     - Reverting a bad commit on `main` restores prior blob OIDs and **instantly re-activates prior `Pass` observations with zero test reruns**.
     - Candidate tree `T_cand` is admissible relative to `T_base` (`main` + optional keeper verdict store) iff every required check unit `u` either:
       (a) has `ConeDigest(u, T_cand) == ConeDigest(u, T_base)` (trivial transport — **0 runs**), OR
       (b) evaluates `Pass` at `ConeDigest(u, T_cand)`, OR
       (c) evaluates `Fail(items_cand)` where `items_cand` is a subset of `Fail(items_base)` already recorded/verified on `T_base` (`INHERITED` red, never blocking unrelated lanes; `NEW RED` blocks and `why_not` names *every* blocking unit + moved input path at once).
6. **Every limit is a runtime setting (`LandConfig` TOML/JSON + CLI overrides)**:
   - `max_batch_size` (e.g. 8), `batch_coalesce_ms` (e.g. 250 — nobody waits idle when queue depth is 1!), `test_timeout_s`, `max_reruns_on_flake`, `runner_concurrency`, `cache_dir`, `custody_mode`, `ast_sweep_enabled`.

---

## 2. Workspace Crate Layout

- **`crates/landd-core`**:
  - Content-addressed types (`Oid`, `Digest32`, `CanonicalJson`), `LandConfig` (all limits configurable), `Delivery` 5-state CAS journal (`confirmation_wins` proved by unit + property tests), `CustodyEnvelopeV2` (Ed25519 sign/verify + SSHSIG / HMAC support), and `Reasons` / `Slot` cone admissibility engine (`why_not` exact blocker reporting).
- **`crates/ast-sweep`**:
  - Reads any Git commit/tree OID directly via streaming `git ls-tree -r -z` + persistent `git cat-file --batch` (plus a filesystem fallback mode for working dirs).
  - Sharded on-disk `BlobFactsCache` (`<cache_dir>/blobs/ab/<oid>.bin` or `bincode`/`serde_json`, immutable once written, zero `listdir` sweeps on write!).
  - **Per-blob `Map` pass** (parallelized via `rayon` on cold blobs, using `rustpython-parser` or `tree-sitter-python` + fast line/token scanner): extracts imports, `os.walk`/`glob`/`ls-files` scan calls, `flock` calls (checking `LOCK_NB` & poll-sleep loops), `os.replace`/`os.rename` sites, `strftime` format strings, `sys.executable` references, settings-reader literal keys (`setting(...)`, `or_default(...)`, `.get("a.b")`), caught-exception-stored-on-self patterns, bare `python ` in recipes, and function AST hashes for single-owner checks.
  - **In-memory `Reduce` pass (`<5 ms`)**: Evaluates declarative TOML/JSON rule packs (compatible with `gateaudits.json` migration!) covering:
    1. `no_tracked_bytecode` (`*.pyc`, `__pycache__`)
    2. `no_bare_python_recipe`
    3. `flock_bounded` (no blocking `flock` without `LOCK_NB` outside owner; no `while` sleep-poll without bound)
    4. `atomic_replace_owner` (flags unapproved `os.replace`/`os.rename` without brittle line/function-count censuses that break on refactors!)
    5. `uncatalogued_settings_keys` (verifies dotted literal settings reads exist in configured catalog JSON files)
    6. `forbidden_symbol_or_call` (configurable path-scoped rules replacing `test_front_interpreter`, `test_bones_land_owners`, `test_chatread_owners`, `test_no_stopfacts_reader`, `test_reviewrows`, etc.)
    7. `single_owner_pattern` (flags duplicate implementations outside declared owner module)
    8. `python_import_graph` (exports exact transitive static import cones + `dynamic_loads` taint bit so `landd` computes sound `ConeDigest`s for every Python test module in `<10 ms`!).
- **`crates/landd-train`**:
  - Speculative batch merge train (`enqueue -> build cumulative merge trees T_1..T_k via git merge-tree --write-tree`):
    - If `C_i` merge-conflicts with `T_{i-1}`, `C_i` is immediately declined (`Conflict { conflicting_paths }`) and dropped from the batch *without* delaying `C_{i+1}` (`T_i` aliases `T_{i-1}`)!
    - Computes union of uncached test modules across `T_k` (after `ast-sweep` + `ConeDigest` transport from `T_0` and from any pre-warmed lane cone verdicts!).
    - Runs uncached modules once on `T_k`. If green (or no redder than `T_0`), creates the chain of 2-parent merge commits `M_1 -> M_2 -> ... -> M_k`, pushes `M_k` once with `--force-with-lease`, proves ancestry on the forge, and marks all `k` deliveries `Completed`!
    - If `T_k` has a `NEW RED`, runs logarithmic bisection (`ddmin` / binary split over `1..k`) reusing cone digests to isolate the exact breaking candidate(s), declines only the culprit(s) with exact `why_not` diagnostics, and lands all healthy peers!
- **`crates/landd-sim` (Offline `land_runs.jsonl` Replay & Benchmark Engine)**:
  - Parses real `fleet` `land_runs.jsonl` (+ optional selection/module-cost tables) and replays the exact arrival timestamps, base/head/changed files, race losses, and module costs against `landd`'s speculative batch train + timeless cone cache + `ast-sweep`, outputting a side-by-side Markdown & JSON report (`actual_fleet` vs `landd`: total CPU-s, rung CPU p50/p95, commit-to-main lead time p50/p95, lost races, test module runs saved).
- **`crates/landd` (CLI & Unix-Socket Daemon)**:
  - Subcommands:
    - `landd sweep --repo <path> [--rev HEAD] [--rules <pack.toml>] [--cache-dir <dir>] [--json]`
    - `landd cones --repo <path> --base <rev> --head <rev> [--json]` (prints changed vs transported test cones)
    - `landd land --repo <path> --lane <branch_or_sha> [--target refs/heads/main] [--apply]`
    - `landd daemon --socket <path> --config <landd.toml>` (accepts concurrent `enqueue` / `status` requests)
    - `landd replay --ledger <land_runs.jsonl> [--module-costs <json>] [--json]`
    - `landd pre-receive --trusted-keys <file>` (optional forge hook verifying `CustodyEnvelopeV2` before ref update)

---

## 3. Required `#tooth` / Adversarial Self-Tests

Every subsystem must carry positive AND negative (`#tooth`) tests:
- **Cone cache teeth**: mutating 1 byte of a transitive dependency changes `ConeDigest`; advancing `main` on a disjoint file preserves `ConeDigest` byte-for-byte; reverting a commit restores the exact prior `ConeDigest` and hits cache even 10 years later (simulated clock +10y!).
- **`Delivery` teeth**: lost reply (`Unknown`) refuses `start()`; `Declined` refuses `start()` at `u64::MAX`, **yet `Declined.complete(evidence)` succeeds** when forge ancestry confirms the commit landed; mismatched binding under same key errors.
- **`CustodyEnvelopeV2` teeth**: adding 5 new unknown telemetry keys in `claims` still verifies cleanly with the *exact* original signature, while flipping 1 bit in `claims` or `header` or wrong domain tag fails closed.
- **Train bisection teeth**: batch `[good1, bad2, conflict3, good4]` drops `conflict3` at compose (<10 ms), isolates `bad2` via bisection, and lands `good1 + good4` in a clean 2-parent merge chain with zero force-push!
- **`ast-sweep` benchmark test**: run `landd sweep` read-only against `/Users/ember/pug/fleet-gen3` (`origin/lane/pr7-final-candidate`) on a warm vs cold cache and measure exact wall-clock ms and findings!
