# Hardening record

This file records what two audits of the first version found, what was done about each numbered item, and what was measured afterwards. Pointers are to symbols and test names; inspect those rather than line numbers.

## Initial published build verification

Run on a 32-core Linux build host, Rust 1.99, git 2.47, bubblewrap 0.12:

| check | result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | clean |
| `cargo test --workspace --locked` | 219 passed, 0 failed (four consecutive full runs) |

Per crate: `landd-core` 73, `ast-sweep` 75, `landd-train` 43, `landd-sim` 12, `landd` 16 (6 unit, 10 end to end). Tests that need a sandbox run `bwrap` for real; nothing is mocked.

## Initial published build measurements

The corpus is a private Python repository ("Fleet") of 4,015 tracked files, 2,438 of them carrying facts, with 1,216 test modules. All figures are at commit `959b02f775cf4348899ee1a9dbad8d9c4d1ac44a`; "previous" is `7609f212e264f158b7ea5585fceb4b98b698d79d`, six commits earlier (64 files changed, 53 of them fact-bearing). The repository's own `gateaudits.json` at that commit was used as the trusted metadata.

### Cones

Under the default strict model:

| | |
|---|---:|
| test cones | 1,216 |
| cones that depend on the whole tree | 1,216 |
| units transported between "previous" and the benchmark commit | 0 (1,211 changed, 5 added) |
| loader declarations in `gateaudits.json` | 37 |
| … verified against the loader's source | 0 |
| … unverifiable (no literal target, or only a prefix wider than the declaration) | 31 |
| … contradicted | 1 |
| … naming a file with no dynamic load | 5 |

**The initial build transported no cones on this corpus.** Every test imports one shared support module, and that module by itself reads the whole tree, reads through paths the analysis cannot resolve, and starts child processes. Cones widened, by cause (a cone usually has several):

| cause | cones |
|---|---:|
| whole-tree read | 1,216 |
| read below a known place through a non-literal | 1,216 |
| read through a path of unknown origin | 1,216 |
| child process | 1,216 |
| undeclared dynamic load | 1,134 |
| loader declared but unverifiable | 1,123 |
| module loaded from an unresolved path | 792 |
| symbolic link leaving the tree | 91 |
| loader declaration contradicted | 88 |
| guard declares "reads everything" | 41 |
| call the pack lists as a whole-tree reader | 5 |
| file that does not parse | 1 |

The same sweep under `cone_model = "hermetic"`, and under hermetic with `unverified_loaders = "trust"`, also widens all 1,216 cones: the shared support module's whole-tree read and unresolved reads remain. These non-default models were run for comparison only. Nothing here shows that restricting a unit's view to its cone preserves this repository's checks; that would need each test run both ways and compared, which was not done.

Mutation checks at the benchmark commit (one synthetic commit each): changing a data file that two families of tests read through a `gateaudits.json` domain, changing a top-level document, and changing one library module. In all three, all 1,216 cones changed, including the 16 units of those two families. On this corpus that is true but uninformative, since every cone is the whole tree. That a data file invalidates exactly its readers is shown where cones are bounded: `tooth_a_data_file_a_test_opens_is_in_its_cone`, `tooth_listings_and_walks_see_files_that_appear` (`ast-sweep`), `cones_show_changed_transported_and_widened_units` (CLI), and `tooth_python_checks_run_through_the_train_and_data_changes_reach_their_readers`, which runs Python checks through the sandboxed train.

### Sweep timings

One-shot `landd sweep` (release build, jemalloc), strict model, example rule pack plus `gateaudits.json`:

| run | process wall | in-process total | of which |
|---|---:|---:|---|
| cold (empty cache) | 971 ms | 886 ms | parse 738 ms |
| warm (same tree) | 160–184 ms | 158 ms | list 15, load 17, graph 28, cones 20 |
| incremental from "previous" | 344 ms | 286 ms | 53 blobs parsed in 153 ms, 334 unchanged neighbours re-read |

In a long-lived process with the cache handle kept: the same tree again, 124 ms; incremental from "previous", 285 ms with 53 blobs parsed and nothing else read from disk. `git ls-tree -r` alone takes about 10 ms on this tree.

The original specification's latency figures are not met and are withdrawn from SPEC.md. Cold time is bounded by tree-sitter parsing (about 45 MB of Python). The warm path is slower than in the first version (about 54 ms there) because the graph now resolves 18,369 data-read sites and verifies loaders; that is the cost of the soundness work below. The reduce pass alone stays at 2–5 ms.

### Ledger replay

A private projection of the repository's real land ledger was read: the latest day (370 rows) and the full set (2,473 rows), with the timing tables that accompany them.

| observed, latest day | value |
|---|---:|
| applied land runs | 313 |
| distinct lanes (tips) | 300 |
| lanes landed | 214 (215 landing runs) |
| runs refused by checks / by merge conflict | 50 / 18 |
| lost pushes / carried | 10 / 7 |
| refused attempts inside runs | 60 |
| landed run wall, p50 / p95 | 563.7 s / 2,119.3 s |
| landed push phase, p50 / p95 | 341.0 s / 1,135.0 s |
| first observed applied attempt to destination confirmation, p50 / p95 | 563.2 s / 2,118.8 s |

The elapsed-time field is `pushed_ts - min(ts)` grouped by lane tip: source `land/lander.py` records `ts` at applied-run creation and `pushed_ts` after destination confirmation. It is not commit-to-main development lead time; the observation window may omit earlier attempts.

Over the full ledger: 2,220 applied runs, 2,102 lanes, 1,493 landed; first observed applied attempt to destination confirmation p50 248.1 s, p95 1,312.3 s. One outcome word (`refused:red-cap`, 63 runs) is not in the classification table and is reported as unclassified rather than guessed. The timing tables hold a wall time for 1,142 modules (4,562 s for one run of each) and 5,567 push records, 3,058 of which carry a module *count* (352,116 module runs in total); they do not say which modules.

**No saving is claimed.** Every row of the real ledger has `selected: []` and `modules: {}`, so which modules each lane ran is unknown, and `cpu_s` is the hub's CPU for the whole run. `landd replay` therefore reports the replay as unavailable, with those reasons, and reports no CPU or module figure for landd. The discrete-event replay is exercised only on synthetic ledgers that do carry module sets (`landd-sim` tests); that is a test of the model, not evidence about this repository. The initial build therefore offered no cone-based skip on this corpus. Later static cone comparisons are reported separately below; no actual test-runtime saving has been measured.

---

## Audit 1: `landd-core` and `ast-sweep`

| # | finding | disposition |
|---|---|---|
| C1 | Cones ignore data reads and tree scans | **Fixed.** The extractor records every open, probe, listing, walk, glob, module loaded by path and child process with the reach of its path (`extract.rs`, `Walker::reach`, `Walker::read`); the graph turns resolved reads into cone inputs and everything else into a recorded widening cause (`imports.rs`, `ImportGraph::node`, `Cause`). `shutil.copytree`, `Path.walk`, `sys.path` mutation and `site.addsitedir` are covered; whole-tree census helpers are a pack setting (`whole_tree_calls`). Tests: `tooth_a_data_file_a_test_opens_is_in_its_cone`, `tooth_listings_and_walks_see_files_that_appear`, `tooth_unbounded_reads_widen_strictly_and_are_bounded_only_by_an_enforced_view`. |
| C2 | `with_gateaudits` adopts only `guards` | **Fixed.** `guards`, `domains` and `dynamic` are parsed (`rules.rs`, `RulePack::with_gateaudits`); guard keys are unit-name patterns (`imports::cones`); module-keyed loaders are translated to paths; a declaration that names nothing is reported (`LoaderStatus::Missing`), not dropped. `unrun`, `ledgers`, `absent` and `carries` are deliberately not consumed, and `unrun` is not used to shrink whole-tree cones. Tests: `gateaudits_guards_become_cone_reads`, `guards_match_units_by_pattern_and_star_reads_everything`, `tooth_loader_declarations_are_verified_against_the_loaders_source`. |
| C3 | Cone/verdict key omits what produced the verdict | **Fixed.** A leaf is `(path, git mode, oid)`; the cone digest includes a context digest made of the rule-pack digest and the runner profile: argv, allowed environment values, test-program hash, sandbox description, unit view, profile-command output, `runtime_id`, runner source digest (`reasons.rs` `cone_leaf`/`cone_digest`, `rules.rs` `RulePack::digest`, `runner.rs` `RunnerProfile`). The pack is loaded from an operator path only. Tests: `cone_digest_binds_unit_path_content_mode_taint_and_context`, `tooth_the_runner_profile_moves_with_what_produces_verdicts`, `tooth_a_candidate_manifest_cannot_weaken_the_bases`. |
| H1 | Parse errors, truncation, non-UTF-8 do not taint | **Fixed.** `Cause::ParseError` / `TooLarge` widen; a UTF-8 BOM is stripped; any non-UTF-8 text sets `parse_error`. Tests: `tooth_broken_syntax_and_bad_bytes_are_flagged_not_trusted`, `tooth_files_that_did_not_parse_widen`. |
| H2 | Symlinks and gitlinks invisible | **Fixed.** Links are entries with their target as a fact; in-tree targets are followed (file and directory), links that leave the tree widen (`Cause::LinkEscape`); gitlinks stay in the listing. Tests: `tooth_symbolic_links_are_followed_inside_the_tree`, `tooth_links_that_leave_the_tree_widen_whoever_reaches_them`, `tooth_mode_changes_and_gitlink_bumps_move_cones`. |
| H3 | Unresolved relative imports and off-root files dropped | **Fixed.** Relative imports resolve by directory (`ImportGraph::by_path`); an unresolved one widens; a top-level name no root explains is linked to every in-tree file or package of that name (`ImportGraph::loose`); `sys.path` mutation is a dynamic load. Tests: `tooth_a_dangling_relative_import_widens`, `tooth_imports_outside_every_root_reach_in_tree_files_of_that_name`. |
| H4 | Escaped literals mis-decoded | **Fixed.** `Walker::literal` decodes escapes as Python does and honours raw prefixes; an escape it does not know makes the literal non-static. Test: `tooth_escaped_literals_mean_what_python_says`. |
| H5 | Panic on non-ASCII module names | **Fixed.** `with_prefixes` iterates `match_indices('.')`. Test: the unicode case in `tooth_imports_outside_every_root_reach_in_tree_files_of_that_name`. |
| H6 | `export_tree` uses `git archive` | **Fixed.** Removed. `runner.rs` `materialize` writes exact blobs and modes from `ls-tree` and `cat-file` into a directory it creates fresh. Test: `tooth_materialization_is_exact_and_ignores_export_attributes`. |
| H7 | Coarse or empty failures mask new reds | **Fixed.** `Status` is `Pass | Fail{items} | Crash | Timeout`; only named items inherit; stores refuse an empty failure. Tests: `tooth_coarse_failures_are_not_comparable`, `tooth_stores_refuse_a_contradicting_or_empty_verdict`. |
| H8 | Deleted or hidden units are "not required" | **Fixed.** `UnitReason::Removed` blocks unless `allow_unit_removal`. Tests: `tooth_removed_units_block_unless_the_policy_allows_removal`, `tooth_removing_a_unit_blocks_unless_the_operator_allows_it`. |
| H9 | `cat-file` framing | **Fixed.** End of stream is an I/O error and the stream is discarded; the reply must be the requested blob; a size limit applies and an oversized object is consumed in sync; the trailing newline is checked (`git.rs` `CatFile::object`). Test: `ls_tree_and_blob_reader_read_objects_directly`. |
| M1 | Tree id and listing resolved separately | **Fixed.** `sweep_git` resolves the tree once and lists that id. |
| M2 | `ls-tree` without `--full-tree` | **Fixed.** Test: `ls_tree_lists_from_the_root_whatever_directory_is_opened`. |
| M3 | Lossy non-UTF-8 paths | **Fixed.** Refused (`GitError::NonUtf8Path`, `SweepError::NonUtf8Path`). Test: `tooth_paths_that_are_not_utf8_are_refused`. |
| M4 | Inherited git environment | **Fixed.** Location variables are removed from every command; the receive hook keeps only what names the repository and quarantine (`GitRepo::open_in_hook`). Test: `tooth_inherited_git_location_variables_are_ignored`. |
| M5 | Delivery state edges | **Fixed.** `declined` only from `Fresh`/`Refused`; evidence names the repository; the repository id is the canonical push destination; the binding key is domain-separated. Tests: `tooth_an_outstanding_send_cannot_be_declined_unread`, `tooth_completion_needs_evidence_for_this_binding`, `binding_keys_are_domain_separated`. |
| M6 | Directory durability and swallowed fsync errors | **Fixed.** `fsx::create_dirs` syncs the chain and every sync error propagates (see also L-P3). |
| M7 | Temp names by pid and counter | **Fixed.** Random 64-bit names with retry. Test: `tooth_stale_temporaries_do_not_block_writers`. |
| M8 | Any trusted key may claim any seat or kind | **Fixed.** `Grant { seats, kinds }` per key, enforced in `verify`. Test: `tooth_a_valid_signature_outside_the_keys_grant_is_refused`. |
| M9 | Receipt subject has no repository | **Fixed.** `ref_update_subject(repo_id, …)` v2. Tests: `receipt_subjects_name_the_repository`, `pre_receive_hook_admits_only_receipted_fast_forwards_for_this_repository`. |
| M10 | `from_wire` accepts duplicate keys | **Fixed.** Only canonical bytes parse. Test: `tooth_wire_bytes_must_be_canonical`. |
| M11 | Cache poisoning | **Fixed, with one part refuted.** The state directory is absolute, never inside the repository, private to the user, and refused if another user owns it or others can write it; decoding is bounded by the entry's size. A keyed checksum was *not* added: a key stored beside the cache protects against nobody who can write the cache, so it would be ceremony. Tests: `tooth_state_inside_the_repository_is_refused`, `tooth_private_dir_refuses_group_or_world_writable`, the loose-cache case in `sweep_reports_findings_exit_codes_and_a_warm_cache`. |
| M12 | Hand-bumped facts version | **Fixed.** `facts_version()` is derived from the crate version, the grammar and the source of the extractor, fact types and reducer. |
| M13 | Forbidden-rule bypasses | **Fixed.** Relative imports and relative-imported names are resolved to absolute names; every dotted prefix is matched; a wildcard import of a module that can hide a loader or a scan is a dynamic load. Tests: `tooth_forbidden_imports_see_relative_and_deeper_spellings`, `tooth_what_can_hide_a_loader_or_a_scan_is_a_dynamic_load`. |
| M14 | Kind by suffix only | **Fixed.** Executable and extensionless files are sniffed for a `#!` line. Tests: `executables_are_sniffed_and_links_keep_their_target`, `rules_see_python_without_a_py_suffix`. |
| M15 | `fs::read` on FIFOs and devices | **Fixed.** Only regular files and links are read. Test: `tooth_directory_mode_skips_what_is_not_content`. |
| M16 | Weak ref and remote validation | **Fixed.** `valid_ref_name`, `valid_remote`. Test: `tooth_ref_and_remote_names_cannot_smuggle_options_or_refspecs`. |
| L1 | Key loading and key files | **Fixed.** Weak keys and duplicate ids are refused; HMAC secrets are never written to a public file and are wiped on drop; a signing key file must be mode 0600 or stricter. Test: `tooth_key_stores_refuse_duplicates_weak_keys_and_readable_secrets`. |
| L2 | Canonical JSON is not JCS | **Documented** in `canon.rs`: landd's own form, internal only. |
| L3 | Exponential glob backtracking | **Fixed.** Table-walk matcher. Test: `tooth_many_stars_match_in_linear_time`. |
| L4 | `ends_with("__init__.py")` | **Fixed.** File names are compared whole. |
| L5 | `fromlist`, anchored `import_module` | **Fixed.** A literal `fromlist` is read; a relative name anchored anywhere but `__package__` is dynamic. Test: `tooth_literal_import_module_is_static_and_computed_is_dynamic`. |
| L6 | Lint heuristics | **Fixed.** A loop condition is no longer a bound; flags held in a variable are reported as unknown, not as blocking. Tests: `flock_sites_know_nonblocking_and_poll_loops`, `flock_flags_in_a_variable_are_reported_as_unknown_not_as_blocking`. These feed a lint only. |
| L7 | `Ok` on an equal-but-stale read | **Documented** on `DeliveryJournal::transition`. |
| L8 | stderr read after stdout | **Fixed.** Drained concurrently and bounded. |

## Audit 2: `landd-train`, simulator, CLI

| # | finding | disposition |
|---|---|---|
| 1 | The test child can read the signing key and write the verdict store | **Fixed.** `bwrap` sandbox (`runner.rs`, `Runner::sandboxed`); scratch is outside the state directory; a secret under a sandbox mount is refused; signing needs the sandbox at three layers (config, runner, train); the key is loaded once at start. Tests: `tooth_sandboxed_units_cannot_reach_the_supervisor` (which also shows the same script reaching the key when unsandboxed), `tooth_a_secret_under_a_sandbox_mount_is_refused`, `tooth_signing_requires_the_sandbox`, `tooth_receipts_cannot_be_signed_without_the_sandbox`. |
| 2 | A stacked or duplicate lane is marked landed | **Fixed.** `Dropped::OnBase` only for tips reachable from the base; `Dropped::Subsumed` otherwise, settled by reading the destination. Tests: `tooth_stacked_and_duplicate_lanes_are_subsumed_not_on_base`, `tooth_a_stacked_lane_shares_its_carriers_fate`. |
| 3 | Carried reported as landed | **Fixed.** `CandidateOutcome::Carried`; the CLI exits 1. Test: `tooth_a_lane_someone_else_carried_is_carried_not_landed`. |
| 4 | Result and log reads can hang or exhaust the daemon | **Fixed.** No-follow, non-blocking, regular-file, size-bounded frame read; stderr is drained through a pipe keeping only its tail. Test: `tooth_hostile_result_files_do_not_hang_or_exhaust_the_supervisor`. |
| 5 | Deleting a unit passes the gate | **Fixed.** See H8; a missing manifest is three removed units, not zero checks. |
| 6 | The binding changes with the clock | **Fixed.** Deterministic merge identity; tip pointer; settle before composing. Tests: `tooth_merge_commits_are_a_function_of_their_parents`, `tooth_retries_of_one_composition_are_one_delivery_with_a_refusal_limit`, `tooth_an_unread_send_is_settled_from_the_destination_before_resending`. |
| 7 | One bad candidate fails the batch | **Fixed.** `Dropped::Unmergeable`; a candidate whose cones cannot be computed is blocked alone; a verdict conflict keeps the first verdict and is reported. Tests: `tooth_one_unmergeable_candidate_does_not_fail_the_batch`, `tooth_one_bad_candidate_does_not_fail_its_peers`. |
| 8 | Ancestry read from the fetch URL | **Fixed.** `GitRepo::push_destination`. Test: `tooth_destination_reads_use_the_push_url`. |
| 9 | Network commands have no timeout | **Fixed.** Process-group deadline on `ls-remote`, `fetch`, `push`, plus HTTP low-speed settings; a push that times out is unread. SSH options are left to the operator's SSH configuration; the deadline is what bounds the train. Test: `tooth_network_commands_die_at_their_deadline`. |
| 10 | `status` breaks as history grows | **Fixed.** Bounded ring, cursor, reply sized to one frame. Tests: `tooth_settled_history_is_bounded`, the daemon end-to-end test. |
| 11 | Hot retry loop, partial journal start | **Fixed.** Queue entries carry `not_before`; every binding is checked before any is started. Tests: `tooth_entries_are_not_taken_before_their_time`, the backoff case in `tooth_retries_of_one_composition_…`. |
| 12 | A conflict with a culprit is declined | **Fixed.** Second look after isolation. Test: `tooth_a_conflict_with_a_culprit_is_reconsidered_once_the_culprit_is_out`. |
| 13 | Stale lane tips can land | **Fixed.** The queue is keyed by lane; the daemon resolves a lane at the push destination, or takes an explicit tip. Tests: `tooth_a_resubmitted_lane_replaces_its_stale_tip`, the daemon end-to-end test. |
| 14 | Verdicts depend on more than the cone | **Fixed.** Per-attempt views, private home and temp, exact materialization, runner profile in the key. See C3, H6. |
| 15 | Daemon socket open to denial of service | **Fixed.** Connection limit, total deadline, small request frames, buffers that grow with data received. Test: `tooth_slow_and_oversized_clients_are_cut_off`. |
| 16 | Unsafe daemon lifecycle | **Fixed.** Lock file held for life; only a stale socket is unlinked; mode 0600 and peer-uid check; the listener stops if the train thread dies; the queue is saved on every change. Tests: the daemon end-to-end test, `the_queue_survives_a_restart`. |
| 17 | Contract gaps against fleet | **Fixed.** No empty merge is pushed (`NoChange`); a lane with nothing to land exits 1 (`OnBase`); `push_no_verify` and `push_env` are settings. Tests: `a_lane_that_changes_nothing_is_not_pushed`, `land_dry_run_apply_decline_and_exit_codes`. |
| 18 | The replay misreads real ledgers | **Fixed.** Lanes are keyed by `tip`; outcomes go through an explicit table; inner refused attempts are counted; elapsed time runs from the first observed applied attempt; both sides of a replay use the same unit and hub CPU is never compared; input is read as bytes by line. See "Ledger replay" above. Tests: all of `landd-sim`. |
| 19 | Lane text in the commit message | **Fixed.** `valid_lane`; control characters are replaced. Test: `tooth_lane_names_cannot_carry_revision_syntax_or_trailers`. |
| 20 | Receipts and the hook | **Fixed.** Repository in the subject; `--protect` adds to `refs/heads/main`; the push option size is checked. |
| 21 | Zombie, kill after reap | **Fixed.** `wait_deadline` kills the group before reaping, and always reaps. |
| 22 | Small train and test issues | **Fixed.** An ancestry error after a push is `Unknown`; the tautological fast-forward check is gone (the lease on the chain's own base is the guarantee); merges pin attribute source and merge settings and git ≥ 2.40 is required; the flaky batch-count assertion is removed. |

## Follow-up review

| # | finding | disposition |
|---|---|---|
| L-P1 | `Delivery::start` increments a `u32` unchecked | **Fixed.** `checked_add`, `DeliveryError::SendsExhausted`, the record untouched. Test: `tooth_a_saturated_send_counter_refuses_instead_of_wrapping`. |
| L-P2 | Runtime mounts and identity | **Fixed, with a stated limit.** A key or state directory under any sandbox mount (the defaults include `/etc`) is refused, including not-yet-existing paths and `..` spellings (`RunnerError::Exposed`, `tooth_a_secret_under_a_sandbox_mount_is_refused`). Identity: the profile hashes the test program and profile-command output and carries an operator `runtime_id`; it does not hash every library under the mounted directories. SPEC states that verdicts are valid for one runtime image and that `runtime_id` is how a change is declared. No claim is made that source imports alone make a verdict eternal. |
| L-P3 | `create_dirs` does not sync existing ancestors | **Fixed.** Every writer syncs the directory chain it relies on, bounded to the store's depth. A singleton would not have ruled the race out: `landd land` and the daemon can share a state directory. Test: `tooth_every_writer_syncs_the_directory_chain_it_relies_on`. |

## Known limits

- Static dependency analysis recognizes a finite set of Python constructs; it is not a proof of all possible effects. Hidden reads outside the recorded cone cannot reach omitted repository files under a sandboxed cone view. Tree views bind the whole tracked tree. Neither implies that a restricted view preserves a project's original test behavior; that needs actual comparison runs.
- The sandbox is a namespace sandbox run by the supervisor's own user. It is not a defence against kernel exploits, and what is mounted read-only (`sandbox_ro`) is readable by units.
- `isolation = "none"` protects nothing and says so.
- A crash on both base and candidate blocks by default; set `inherit_coarse_failures` to accept that such failures cannot be compared.
- When two lanes are only red together, the later one is declined.


## Takeover hardening

The subsequent implementation combines the independent hardening review with the recovered symbol-analysis work:

- Whole-tree views bind whole-tree verdicts; the cone memo also includes the trusted base. Allowed environment values are snapshotted once for both the profile and execution. Symlink-before-`..` resolution detects mounted key/state aliases.
- Durable enqueue failures reach the actual Unix client. Newer queued tips survive restart, queues are bound to destination/ref and held by a lifetime writer lock, and nonempty unbound legacy queues are preserved/refused.
- Trusted state validates directory ancestry, and state inside repository or Git directories is refused before creation. Temporary fixture roots are explicitly private, independent of host umask.
- Recovered delivery records read fresh destination ancestry before deciding a remembered refusal or re-running a stale-base check. Proven completion overrides local refusal and unread-send states. Tests: `tooth_destination_completion_wins_over_stale_base_and_local_refusals` and `tooth_a_lane_someone_else_carried_is_carried_not_landed`.
- Network subprocess groups are killed before the leader is reaped, including when the leader exits while a descendant still holds a pipe. Tests: `tooth_exited_network_leaders_do_not_leave_pipe_holders_alive` and `tooth_network_commands_die_at_their_deadline`. Test child guards reap daemons on failure. The receiving hook bounds both input and push-option decoding.
- Python facts record module initialization and deferred symbol effects separately. Import-time descriptors, subclass hooks and shadowed decorators remain eager; self escaping a constructor conservatively reaches instance methods. Name-based `WeakSet.add(self)` exemptions were removed because a syntactic name does not prove the runtime object is safe.

The physical runner boundary, not universal Python static-analysis completeness, is the safety contract described in SPEC. No deployment or Fleet test-equivalence run is claimed.

### Takeover verification and corpus comparison

On Linux with Rust 1.99, the completed batch passes `cargo test --locked --workspace`: **240 passed, 0 failed**, including actual sandboxed runners, signed receiving hooks, Unix client persistence failures and Git transport child cleanup. Per crate: `ast-sweep` 83, `landd` 22, `landd-core` 76, `landd-sim` 12, `landd-train` 47. `cargo clippy --locked --workspace --all-targets -- -D warnings` and `cargo fmt --all -- --check` are clean. No `landd` process remained after the test run.

A fresh release-build comparison of the same private corpus revisions and rule pack reports **1,216 units: 9 unchanged cone digests, 1,202 changed, 5 added, 0 removed; 1,205 cones still whole-tree**. The scoped analysis removes the blanket dependency on unused support functions in a small subset of units. This is a static comparison only: no real Fleet tests were skipped or timed, no production gate was replaced, and no equivalence between its original and restricted test views was established. The earlier full-tree counts and timings above describe the initial published build, not this implementation. There is still no measured test-runtime saving.
