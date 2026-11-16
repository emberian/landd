# `landd` Engineering Rules (`AGENTS.md`)

1. **Zero macOS Compilation Rule**:
   - **NEVER** execute `cargo`, `rustc`, `lake`, or `lean` locally on macOS.
   - Run all compilation, clippy, and test commands remotely over SSH on a designated Linux build host (`BUILD_HOST`) using an isolated remote directory (`/tmp/landd-build`) wrapped in `SWARM_MEM_MAX=12G timeout --kill-after=10s 600s`:
     ```bash
     rsync -az --delete --exclude target --exclude .git ./ "$BUILD_HOST":/tmp/landd-build/
     ssh "$BUILD_HOST" 'cd /tmp/landd-build && CARGO_TARGET_DIR=/tmp/landd-build/target timeout --kill-after=10s 600s cargo test --workspace'
     ```
2. **Zero Computer-Science Atrocities (TigerStyle)**:
   - **Never** expire content-addressed verdicts by wall-clock age (`BLAKE3`/`SHA-256` over exact input blobs is pure and timeless).
   - **Never** scan directories with `read_dir` on the hot path; use indexed storage or two-level content-addressed shard paths (`ab/cd...`) with bounded journals.
   - **Never** copy working trees to inspect Git commits: read trees and blobs directly via `git ls-tree -r -z` and persistent `git cat-file --batch` worker streams (or `gix`/`git2`), and construct speculative merges via `git merge-tree --write-tree` (`<10 ms`, zero working-tree lock).
   - **Never** parse subprocess CLI prose with regexes to drive state machines; use length-prefixed or canonical JSON wire frames with explicit exit/outcome enums.
   - **Never** run untrusted candidate tests inside the same process that holds signing keys or seals receipts.
   - **Never** include private tailnet IPs or internal hostnames in source, tests, docs, or commit messages.
3. **Commit Discipline**:
   - Inspect `git diff` before committing named files with clear prose messages. No `git stash`, no blanket `git add .`.
