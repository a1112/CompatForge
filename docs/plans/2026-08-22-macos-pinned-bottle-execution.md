# Pinned Bottle Execution Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Launch the fixed SumatraPDF acceptance executable from verified anonymous bytes instead of reopening a mutable Bottle pathname.

**Architecture:** Add an opt-in, in-process Rust execution lease that captures a no-follow Bottle executable into an anonymous unlinked file, inspects and plans against those bytes, and passes the inherited descriptor to Wine. Keep the ordinary `LaunchPlan` JSON, FFI ABI, default `BottleInPlace`, 7-Zip, and Notepad++ behavior unchanged; only the SumatraPDF acceptance runner selects the new CLI command.

**Tech Stack:** Rust 2021, Python 3.12 contracts, `std::fs::File`, Unix descriptor inheritance, Wine Unix-path launch, existing CompatForge inspection/orchestration/process crates.

---

### Task 1: Freeze the public compatibility boundary

**Files:**
- Modify: `tests/test_gui_baseline_contracts.py`
- Modify: `crates/compatforge-domain/src/lib.rs`
- Reference: `crates/compatforge-ffi/src/lib.rs`

**Step 1: Write the failing compatibility tests**

Add literal tests that serialize the current `LaunchPlan` and assert that the key set remains exactly:

```text
schemaVersion, requestId, runtime, translator, graphics, process,
guestArtifact?, bottleExecutable?, mounts, sandbox, lifecycle, decisionTrace
```

Add a Python source contract asserting that the pinned Sumatra command is private to the CLI/runner and does not add a `LaunchPlan` field or FFI symbol.

**Step 2: Run the tests and record RED only if the new implementation has already leaked schema**

Run:

```powershell
cargo test -p compatforge-domain --all-targets --locked
& '<python-3.12>' -S -B -m unittest tests.test_gui_baseline_contracts -v
```

Expected before implementation: existing schema test passes; the new private-command source contract fails because the command does not exist yet.

**Step 3: Keep the domain model unchanged**

Do not add a field to `LaunchPlan`, `BottleExecutableBinding`, `LaunchRequest`, or an exported FFI structure. If implementation pressure requires such a field, stop and revise the design instead of weakening this test.

**Step 4: Commit the compatibility oracle**

```bash
git add tests/test_gui_baseline_contracts.py crates/compatforge-domain/src/lib.rs
git commit -s -m "test: freeze pinned launch compatibility"
```

### Task 2: Inspect an already-open regular file

**Files:**
- Modify: `crates/compatforge-inspect/src/lib.rs`

**Step 1: Write handle-inspection RED tests**

Add an internal API with this shape:

```rust
pub fn inspect_file(file: &mut std::fs::File) -> Result<PeInspectionReport, InspectionError>;
```

Tests must prove:

- inspection reads from offset zero and restores or documents the final offset;
- a renamed/replaced pathname cannot redirect an already-open file;
- a short read or in-place size change is `ChangedDuringRead`;
- non-regular files and files over 64 MiB are rejected; and
- `inspect_path()` remains byte-compatible and delegates to the same bounded parser.

**Step 2: Run RED**

```bash
cargo test -p compatforge-inspect --all-targets --locked inspect_file
```

Expected: compile failure because `inspect_file` does not exist.

**Step 3: Implement the minimal handle reader**

Use `stream_position`, `seek(SeekFrom::Start(0))`, `file.metadata()`, and `take(MAX_PE_FILE_BYTES + 1)`. Validate regular-file kind before allocating, compare the number of bytes read with the metadata length, then call `inspect_bytes`.

The implementation must never resolve `/dev/fd`, reopen a pathname, map the file, or execute it.

**Step 4: Run GREEN and existing inspection races**

```bash
cargo test -p compatforge-inspect --all-targets --locked
cargo clippy -p compatforge-inspect --all-targets --locked -- -D warnings
```

**Step 5: Commit**

```bash
git add crates/compatforge-inspect/src/lib.rs
git commit -s -m "feat: inspect held PE files"
```

### Task 3: Capture an anonymous pinned Bottle lease

**Files:**
- Modify: `crates/compatforge-guest-artifact/src/lib.rs`
- Modify: `crates/compatforge-guest-artifact/Cargo.toml` only if an existing workspace dependency is required

**Step 1: Write lease RED tests**

Define an opaque non-serializable type:

```rust
pub struct PinnedBottleExecutable {
    binding: BottleExecutableBinding,
    inspection: PeInspectionReport,
    execution_file: std::fs::File,
}
```

Expose read-only accessors and no raw pathname for the anonymous file. Tests must cover:

- source opened no-follow and complete Bottle ancestry validated;
- regular file, `nlink == 1`, bounded size, and expected fixed logical path;
- same-inode overwrite during capture is detected by length/digest consistency;
- rename/substitution after capture does not change lease bytes;
- the anonymous file has no usable directory entry before return;
- failure closes the file and removes any staging name; and
- 7-Zip/Notepad++ default bindings are unaffected.

**Step 2: Run RED**

```bash
cargo test -p compatforge-guest-artifact --all-targets --locked pinned_bottle
```

**Step 3: Implement capture**

Add an opt-in method similar to:

```rust
pub fn pin_bottle_in_place(
    &self,
    bottle_id: &str,
    source: &Path,
) -> Result<PinnedBottleExecutable, GuestArtifactError>;
```

Open the source atomically without following links. Create a random `create_new` staging file in an external process-private temporary directory, copy at most 64 MiB from the opened source, sync, rewind, inspect with `inspect_file`, and unlink the staging directory entry before returning on Unix. Windows may retain a delete-on-close staging entry for test compilation, but the CLI must reject this acceptance-only command off macOS.

The binding digest and size come from the anonymous bytes, not a later pathname read.

**Step 4: Run GREEN**

```bash
cargo test -p compatforge-guest-artifact --all-targets --locked
cargo clippy -p compatforge-guest-artifact --all-targets --locked -- -D warnings
```

**Step 5: Commit**

```bash
git add crates/compatforge-guest-artifact/src/lib.rs crates/compatforge-guest-artifact/Cargo.toml
git commit -s -m "feat: pin Bottle executable bytes"
```

### Task 4: Prepare and authorize against the lease

**Files:**
- Modify: `crates/compatforge-orchestrator/src/lib.rs`

**Step 1: Write prepared-lease RED tests**

Add a private/explicit constructor such as:

```rust
pub fn prepare_pinned_bottle(
    config: &CoreConfig,
    request: &LaunchRequest,
    pinned: &PinnedBottleExecutable,
) -> Result<Self, PreparationError>;
```

Tests assert exact logical source equality, Bottle id, requested architecture/digest constraints, ordinary policy decisions, and byte-identical serialized plan versus an equivalent stable `BottleInPlace` plan.

Mutants for a different logical path, Bottle id, digest, architecture, or changed config must reject before process creation.

**Step 2: Run RED**

```bash
cargo test -p compatforge-orchestrator --all-targets --locked pinned
```

**Step 3: Implement without adding schema**

Reuse `compile_prepared_plan`. Store no file descriptor in the plan. The caller continues to own the lease; the prepared launch only binds the lease inspection and `BottleExecutableBinding` into its existing private fields.

**Step 4: Run GREEN**

```bash
cargo test -p compatforge-orchestrator --all-targets --locked
cargo clippy -p compatforge-orchestrator --all-targets --locked -- -D warnings
```

**Step 5: Commit**

```bash
git add crates/compatforge-orchestrator/src/lib.rs
git commit -s -m "feat: prepare pinned Bottle launches"
```

### Task 5: Start Wine with the inherited anonymous descriptor

**Files:**
- Modify: `crates/compatforge-process/src/lib.rs`

**Step 1: Write process RED tests**

Add an opt-in API:

```rust
pub fn start_pinned_bottle(
    plan: &LaunchPlan,
    pinned: &PinnedBottleExecutable,
) -> Result<LaunchHandle, ProcessError>;
```

Use a fake Wine helper in tests to assert:

- the child receives a fixed inherited descriptor;
- the execution argument is `/dev/fd/<fixed-number>` and the naked Bottle path is absent from the child argv;
- the working directory remains the logical Sumatra directory;
- descriptor bytes equal the lease digest even after source rename/overwrite;
- no descriptor number enters the plan or emitted evidence;
- descriptor setup, spawn, attach, timeout, and cleanup failures close all parent copies; and
- ordinary `ProcessSupervisor::start()` remains unchanged.

**Step 2: Run RED**

```bash
cargo test -p compatforge-process --all-targets --locked pinned_bottle
```

**Step 3: Implement the Unix descriptor path**

On Unix, duplicate the lease file onto one reserved descriptor in `pre_exec`, clear close-on-exec for that descriptor, and substitute the first process argument with the descriptor path. Preserve the existing process-group preparation and Wine-session lifecycle. Reject non-Wine plans, extra guest arguments if Wine's Unix-path entry point cannot preserve them, and mismatched plan/binding/digest.

Use the approved Wine Unix-path command form for the macOS-only acceptance entry point. Never fall back to the naked path if descriptor preparation or Wine launch fails.

On non-macOS targets the public opt-in API must return a fixed unsupported-platform error without spawning. Unit tests may exercise command construction through a pure helper.

**Step 4: Run GREEN and regress process cleanup**

```bash
cargo test -p compatforge-process --all-targets --locked
cargo clippy -p compatforge-process --all-targets --locked -- -D warnings
```

**Step 5: Commit**

```bash
git add crates/compatforge-process/src/lib.rs
git commit -s -m "feat: supervise pinned Bottle descriptors"
```

### Task 6: Add the closed acceptance-only CLI command

**Files:**
- Modify: `apps/cli/src/main.rs`
- Modify: `apps/cli/Cargo.toml` only if required by existing crate APIs

**Step 1: Write parser and forwarding RED tests**

Add one closed command shape, for example:

```text
prepared-pinned-launch-terminate <config> <logical-executable> <request> <milliseconds>
```

Tests reject missing/extra/combined/options/relative arguments and non-macOS execution. They assert the command calls lease capture, pinned preparation, authorization, and pinned supervision in that order. The existing prepared commands stay byte-compatible.

**Step 2: Run RED**

```bash
cargo test -p compatforge-cli --all-targets --locked pinned
```

**Step 3: Implement the command**

The command reads the ordinary config/request files, verifies the logical path, captures one lease, prepares and authorizes against it, then passes the same lease to `start_pinned_bottle`. It prints only the existing runtime events. It must not print inspection bytes, descriptor numbers, temporary paths, or raw OS errors containing host paths.

**Step 4: Run GREEN**

```bash
cargo test -p compatforge-cli --all-targets --locked
cargo clippy -p compatforge-cli --all-targets --locked -- -D warnings
```

**Step 5: Commit**

```bash
git add apps/cli/src/main.rs apps/cli/Cargo.toml
git commit -s -m "feat: launch pinned Bottle acceptance executables"
```

### Task 7: Select pinned execution only for SumatraPDF

**Files:**
- Modify: `tools/run_gui_baseline.py`
- Modify: `tests/test_gui_baseline_contracts.py`
- Modify: `tests/test_macos_dual_runtime_acceptance.py`
- Modify: `tests/test_macos_headless_preview.py`
- Modify: `scripts/validate_repository.py` only if the reviewed CLI surface requires an exact new command contract

**Step 1: Write runner RED tests**

Assert that SumatraPDF uses the exact pinned command for launch while 7-Zip and Notepad++ retain `prepared-launch-terminate`. Reject a mutant that falls back to the naked command after a pinned failure. Assert compact/full evidence and stdout contain neither `/dev/fd`, descriptor integers, anonymous temporary paths, nor developer paths.

Add mutation hooks proving original-path overwrite or replacement after binding does not change bytes consumed by the fake Wine helper.

**Step 2: Run RED**

```powershell
& '<python-3.12>' -S -B -m unittest tests.test_gui_baseline_contracts tests.test_macos_dual_runtime_acceptance -v
```

**Step 3: Implement the narrow selection**

Select the pinned command only when `asset.app_id == "sumatra-pdf"` and the installed path equals the fixed reviewed location. A pinned-command error remains a closed application/core failure; there is no fallback.

**Step 4: Run GREEN**

```powershell
& '<python-3.12>' -S -B -m unittest tests.test_gui_baseline_contracts tests.test_macos_dual_runtime_acceptance tests.test_macos_interaction_acknowledgements -v
& '<python-3.12>' -S -B scripts/validate_repository.py
```

Run the stable headless subset and record the known Windows executable-bit baseline separately.

**Step 5: Commit**

```bash
git add tools/run_gui_baseline.py tests/test_gui_baseline_contracts.py tests/test_macos_dual_runtime_acceptance.py tests/test_macos_headless_preview.py scripts/validate_repository.py
git commit -s -m "fix: launch pinned SumatraPDF bytes"
```

### Task 8: Full verification and real-Mac handoff gate

**Files:**
- Modify: `docs/guides/macos-local-dual-runtime-acceptance.md` only if the operator command or compatibility warning changes
- Modify: `docs/plans/2026-08-22-macos-pinned-bottle-execution-design.md` only to record verified results, not aspirations

**Step 1: Run repository gates**

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Run all acknowledgement, GUI, dual-Runtime, headless stable, validator, converter, `py_compile`, diff-check, DCO, LF, and status gates. Do not use network to fill npm or Runtime caches.

**Step 2: Independent reviews**

Require a specification review and a quality review to both report `C0 / I0 / M0`. Replay same-inode overwrite, pathname replacement during child calls, descriptor inheritance failure, naked-path fallback, and evidence-leak mutants.

**Step 3: Real macOS checkpoint**

On the Apple Silicon host, run the focused command against CrossOver and Whisky with the fixed SumatraPDF asset. Both must launch from the inherited descriptor, show the expected window, accept the post-window acknowledgement, and clean up with no residual processes.

If either Runtime cannot execute the inherited descriptor, stop and revise the design. Do not fall back to pathname execution and do not report the matrix accepted.

**Step 4: Commit verified documentation only after the Mac run**

```bash
git add docs/guides/macos-local-dual-runtime-acceptance.md docs/plans/2026-08-22-macos-pinned-bottle-execution-design.md
git commit -s -m "docs: record pinned macOS execution evidence"
```

