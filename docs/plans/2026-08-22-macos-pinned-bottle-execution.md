# Pinned Bottle Execution Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Launch the fixed SumatraPDF acceptance executable from one verified anonymous lease instead of reopening a mutable Bottle pathname.

**Architecture:** A closed macOS-only CLI session captures the fixed Bottle executable through a held no-follow directory chain, immediately anonymizes a private execution file, and uses the same lease for inspection, planning, authorization, and Wine process creation. The ordinary `LaunchPlan` JSON, FFI ABI, default `BottleInPlace`, 7-Zip, and Notepad++ behavior remain unchanged.

**Tech Stack:** Rust 2021, Python 3.12 contracts, audited Unix `openat`/`fstatat`, anonymous files, inherited descriptors, Wine `start.exe /unix`, existing CompatForge process supervision.

---

### Task 1: Freeze compatibility and the closed command contract

**Files:**
- Modify: `crates/compatforge-domain/src/lib.rs`
- Modify: `apps/cli/src/main.rs`
- Modify: `tests/test_gui_baseline_contracts.py`

**Step 1: Add RED compatibility tests**

Assert that serialized `LaunchPlan`, `LaunchRequest`, `BottleExecutableBinding`, and existing FFI exports remain byte-compatible. Add a parser RED test for exactly:

```text
prepared-pinned-sumatrapdf-launch-terminate \
  <config.json> <fixed-logical-executable> <request.json> \
  <external-work-root> <milliseconds>
```

Reject missing, extra, option-shaped, relative, combined, non-macOS, or ordinary-Bottle uses. Pin the future command to:

- Bottle id `gui-sumatrapdf`;
- mode `bottleInPlace`;
- architecture `x86_64`;
- logical suffix `CompatForge/SumatraPDF/SumatraPDF.exe`;
- no guest arguments; and
- a held external work root with fixed create-new inspection/plan output names.

**Step 2: Run RED**

```bash
cargo test -p compatforge-domain -p compatforge-cli --all-targets --locked pinned
```

Expected: the schema snapshots pass and the command parser tests fail because the command does not exist.

**Step 3: Add only the closed parser shape**

Parse the command into a private enum variant, but return a fixed unsupported/not-implemented error before any file access. Do not add domain fields or FFI symbols.

**Step 4: Run GREEN and commit**

```bash
cargo test -p compatforge-domain -p compatforge-cli --all-targets --locked
git add crates/compatforge-domain/src/lib.rs apps/cli/src/main.rs tests/test_gui_baseline_contracts.py
git commit -s -m "test: freeze pinned launch compatibility"
```

### Task 2: Inspect a caller-owned file handle

**Files:**
- Modify: `crates/compatforge-inspect/src/lib.rs`

**Step 1: Add RED tests**

Introduce:

```rust
pub fn inspect_file(file: &mut std::fs::File) -> Result<PeInspectionReport, InspectionError>;
```

Tests cover offset zero, renamed source identity, regular-file and 64 MiB bounds, short/change-during-read failure, and unchanged `inspect_path()` bytes.

**Step 2: Run RED**

```bash
cargo test -p compatforge-inspect --all-targets --locked inspect_file
```

**Step 3: Implement**

Seek to zero, validate metadata, read through `take(MAX_PE_FILE_BYTES + 1)`, compare read length with metadata, and call `inspect_bytes`. Never reopen a pathname or resolve `/dev/fd`.

**Step 4: Run GREEN and commit**

```bash
cargo test -p compatforge-inspect --all-targets --locked
cargo clippy -p compatforge-inspect --all-targets --locked -- -D warnings
git add crates/compatforge-inspect/src/lib.rs
git commit -s -m "feat: inspect held PE files"
```

### Task 3: Capture a held and anonymous Bottle lease

**Files:**
- Modify: `crates/compatforge-guest-artifact/src/lib.rs`
- Create: `crates/compatforge-guest-artifact/src/pinned_platform.rs`
- Modify: `crates/compatforge-guest-artifact/Cargo.toml`

**Step 1: Add RED platform and capture tests**

Define an opaque, non-serializable `PinnedBottleExecutable` containing:

- the existing `BottleExecutableBinding`;
- `PeInspectionReport`;
- caller-owned anonymous execution `File`;
- opened source `File`;
- each held directory handle and its identity from storage root through the executable parent; and
- the source entry identity and link count.

Tests prove component-by-component `openat(O_NOFOLLOW)` capture, reparse/symlink/hardlink rejection, same/ancestor substitution detection, and exact fixed path containment.

On macOS, create the execution object with `shm_open` under a 256-bit `arc4random_buf` name, call `shm_unlink` immediately, and copy no source byte until anonymity is confirmed. Darwin exposes no filesystem directory entry for the object. The name must never be logged, serialized, or returned. Add injected tests for name-collision retry bounds, random-source failure, unlink failure, short copy, sync, rewind, and inspection failures.

**Step 2: Run RED**

```bash
cargo test -p compatforge-guest-artifact --all-targets --locked pinned
```

**Step 3: Implement the audited platform boundary**

Replace crate-wide `forbid(unsafe_code)` with `deny(unsafe_op_in_unsafe_fn)`. Confine all unsafe calls to `pinned_platform.rs`, with one safety comment per call. Use only `openat`, `fstatat`, `fstat`, `fcntl`, `arc4random_buf`, `shm_open`, and `shm_unlink`; expose safe RAII wrappers to the rest of the crate. Reference Apple's documented no-visible-filesystem-entry shared-memory behavior in the safety contract.

The Windows implementation is a fixed unsupported-platform branch plus pure helper tests. It must compile without accessing a source path.

**Step 4: Implement capture and revalidation**

```rust
pub fn pin_sumatra_bottle_executable(
    &self,
    bottle_id: &str,
    source: &Path,
) -> Result<PinnedBottleExecutable, GuestArtifactError>;
```

Require `gui-sumatrapdf` and the fixed relative path. Revalidate every held identity, link count, size, ctime/mtime, and a fresh digest of the held source before returning and at every pre-spawn lease boundary. A mutation observed by final revalidation rejects with zero child creation. The anonymous digest/size/inspection are the execution binding of record; mutation after successful spawn cannot redirect those bytes and is reported by post-spawn integrity revalidation.

**Step 5: Run GREEN and commit**

```bash
cargo test -p compatforge-guest-artifact --all-targets --locked
cargo clippy -p compatforge-guest-artifact --all-targets --locked -- -D warnings
git add crates/compatforge-guest-artifact
git commit -s -m "feat: pin SumatraPDF Bottle bytes"
```

### Task 4: Prepare and authorize only with the same lease

**Files:**
- Modify: `crates/compatforge-orchestrator/src/lib.rs`

**Step 1: Add RED tests**

Add private prepared state:

```rust
enum PreparedExecutable {
    Immutable(GuestArtifactBinding),
    Bottle(BottleExecutableBinding),
    PinnedBottle(BottleExecutableBinding),
}
```

Add APIs shaped like:

```rust
pub fn prepare_pinned_bottle(
    config: &CoreConfig,
    request: &LaunchRequest,
    pinned: &PinnedBottleExecutable,
) -> Result<Self, PreparationError>;

pub fn authorize_pinned<'a>(
    &'a self,
    config: &CoreConfig,
    pinned: &PinnedBottleExecutable,
) -> Result<&'a LaunchPlan, PreparationError>;
```

Tests require the same binding, inspection, Bottle id, logical path, digest, architecture, and context. Ordinary `authorize()` must reject a `PinnedBottle` state instead of reopening the pathname.

**Step 2: Run RED**

```bash
cargo test -p compatforge-orchestrator --all-targets --locked pinned
```

**Step 3: Implement without schema changes**

Reuse `compile_prepared_plan`; the resulting serialized plan must be byte-identical to the equivalent stable Bottle plan. Call `pinned.revalidate()` at prepare and authorize boundaries.

**Step 4: Run GREEN and commit**

```bash
cargo test -p compatforge-orchestrator --all-targets --locked
cargo clippy -p compatforge-orchestrator --all-targets --locked -- -D warnings
git add crates/compatforge-orchestrator/src/lib.rs
git commit -s -m "feat: authorize pinned Bottle leases"
```

### Task 5: Supervise the inherited descriptor

**Files:**
- Modify: `crates/compatforge-process/src/lib.rs`
- Modify: `crates/compatforge-process/Cargo.toml`

**Step 1: Add RED command/ownership tests**

Add:

```rust
pub fn start_pinned_bottle(
    plan: &LaunchPlan,
    pinned: &PinnedBottleExecutable,
) -> Result<LaunchHandle, ProcessError>;
```

Pure command tests require exactly:

```text
<reviewed-wine> start.exe /unix /dev/fd/<actual-duplicated-fd>
```

and the existing Bottle directory as `current_dir`. Reject non-Wine plans, extra guest arguments, mismatched binding, or any attempt to fall back to the logical path.

Ownership tests cover:

- caller-owned lease remains valid;
- process-owned duplicate is created in the parent;
- duplicate is rewound before spawn and has `CLOEXEC` cleared;
- existing `setpgid` remains the only `pre_exec` callback;
- duplicate closes after spawn, attach failure, spawn failure, timeout, and cleanup;
- descriptor number never enters plan/events; and
- normal `ProcessSupervisor::start` is byte-compatible.

**Step 2: Run RED**

```bash
cargo test -p compatforge-process --all-targets --locked pinned
```

**Step 3: Implement macOS-only execution**

Use `dup` and `fcntl` in the parent to obtain the actual descriptor number. The child inherits that descriptor naturally; do not guess a fixed descriptor and do not call non-async-signal-safe code from `pre_exec`. Immediately after `spawn`, close the parent duplicate while retaining the caller lease.

Non-macOS calls return a stable unsupported-platform error before spawning. No raw path-bearing OS error may escape the pinned API.

**Step 4: Run GREEN and commit**

```bash
cargo test -p compatforge-process --all-targets --locked
cargo clippy -p compatforge-process --all-targets --locked -- -D warnings
git add crates/compatforge-process
git commit -s -m "feat: supervise pinned SumatraPDF descriptors"
```

### Task 6: Complete one closed CLI capture-to-launch session

**Files:**
- Modify: `apps/cli/src/main.rs`
- Modify: `apps/cli/Cargo.toml`
- Modify: `tests/test_gui_baseline_contracts.py`

**Step 1: Add RED orchestration tests**

The command must execute, in order:

1. closed argument and platform validation;
2. no-follow lease capture;
3. pinned prepare;
4. pinned authorize;
5. bind the supplied external work root, reject physical/lexical overlap with storage, Bottle and source, then publish fixed-name inspection and plan files with fd-relative `openat(O_CREAT|O_EXCL|O_NOFOLLOW)` plus canonical readback; the Python caller separately proves the root is external to the repository before invoking the command;
6. pinned process start and existing event supervision.

Mutation tests replace or overwrite the logical path before final revalidation and assert integrity failure with zero child creation. A separate post-spawn hook changes the source and proves the already-created child still consumes only anonymous bytes before the integrity shutdown path runs.

**Step 2: Add stable error mapping tests**

Every open, component, capture, unlink, copy, sync, inspect, authorize, evidence-write, descriptor, spawn, and cleanup error maps to one fixed `compatforge-cli: pinned SumatraPDF launch failed\n` message. Errors, stdout and compact evidence contain no storage, source, work, developer, shared-memory or descriptor detail. Canonical plan and external full evidence may retain only the authorized logical Bottle/Runtime/storage paths already present in an ordinary `LaunchPlan`; neither may contain descriptor numbers, shared-memory names, anonymous paths, or temporary paths.

**Step 3: Run RED**

```bash
cargo test -p compatforge-cli --all-targets --locked pinned
& '<python-3.12>' -S -B -m unittest tests.test_gui_baseline_contracts -v
```

**Step 4: Implement and run GREEN**

Use held-parent fd-relative create-new/no-follow output publication with canonical readback. Revalidate the external work root before and after each publication. Do not add stdin, PATH, shell, ambient environment, network, or fallback behavior.

```bash
cargo test -p compatforge-cli --all-targets --locked
cargo clippy -p compatforge-cli --all-targets --locked -- -D warnings
git add apps/cli tests/test_gui_baseline_contracts.py
git commit -s -m "feat: launch a pinned SumatraPDF session"
```

### Task 7: Stop for the real macOS Wine spike

**Files:**
- Create: `docs/testing/macos-pinned-sumatrapdf-spike.md` only as a local handoff until evidence exists

**Step 1: Build the exact branch on Apple Silicon**

Build the CLI with the existing locked toolchain and run only the closed pinned command against the fixed SumatraPDF asset in CrossOver and Whisky. Keep the source pathname stable through final lease revalidation. After the child is successfully created, mutate the source through the focused hook; the launched window must still come from the anonymous digest and the post-spawn integrity path must close the run.

**Step 2: Verify both Runtimes**

For CrossOver and Whisky independently require:

- the Wine child inherits the descriptor;
- `start.exe /unix /dev/fd/<n>` opens the Sumatra window;
- the expected title is observed;
- source overwrite/substitution does not change executed bytes; and
- zero residual process and cleanup failures.

**Step 3: Gate the remainder**

If either Runtime fails, stop and revise the design. Do not integrate the command into `run_gui_baseline.py`, do not fall back to pathname execution, and do not claim Task 4 complete.

If both pass, record only redacted descriptor/window/cleanup evidence and continue. The production acknowledgement path is verified after runner integration in Task 8.

### Task 8: Select the pinned session only for SumatraPDF

**Files:**
- Modify: `tools/run_gui_baseline.py`
- Modify: `tests/test_gui_baseline_contracts.py`
- Modify: `tests/test_macos_dual_runtime_acceptance.py`
- Modify: `tests/test_macos_headless_preview.py`
- Modify: `scripts/validate_repository.py` only for an exact reviewed command contract

**Step 1: Add RED runner tests**

Use exact app id `sumatrapdf`. Assert that Sumatra omits the separate GUI `inspect` and `prepared-plan` calls and instead invokes the single pinned session. The runner reads the create-new inspection/plan outputs after completion. 7-Zip and Notepad++ remain byte-compatible.

Reject naked-path fallback, wrong app id, wrong fixed path, missing output evidence, dynamic descriptor/path leakage, and pinned errors rewritten as ordinary accepted evidence.

**Step 2: Run RED**

```powershell
& '<python-3.12>' -S -B -m unittest tests.test_gui_baseline_contracts tests.test_macos_dual_runtime_acceptance -v
```

**Step 3: Implement narrow selection and run GREEN**

```powershell
& '<python-3.12>' -S -B -m unittest tests.test_gui_baseline_contracts tests.test_macos_dual_runtime_acceptance tests.test_macos_interaction_acknowledgements -v
& '<python-3.12>' -S -B scripts/validate_repository.py
```

Run the stable headless subset and preserve the known Windows executable-bit baseline separately.

**Step 4: Commit**

```bash
git add tools/run_gui_baseline.py tests/test_gui_baseline_contracts.py tests/test_macos_dual_runtime_acceptance.py tests/test_macos_headless_preview.py scripts/validate_repository.py
git commit -s -m "fix: launch pinned SumatraPDF bytes"
```

### Task 9: Full verification and reviews

**Files:**
- Modify: `docs/guides/macos-local-dual-runtime-acceptance.md` only to record verified behavior
- Modify: `docs/plans/2026-08-22-macos-pinned-bottle-execution-design.md` only to record verified behavior

**Step 1: Run full gates**

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Run all acknowledgement, GUI, dual-Runtime, stable headless, validator, converter, `py_compile`, diff-check, DCO, LF, and status gates without network access.

**Step 2: Independent reviews**

Require specification and quality reviews to both report `C0 / I0 / M0`. Replay initial capture, pre-final-revalidation overwrite/path replacement, post-spawn source mutation, shared-memory randomness/anonymity failures, work-root substitution, descriptor inheritance/cleanup, naked fallback, and evidence-leak mutants.

**Step 3: Commit verified documentation**

```bash
git add docs/guides/macos-local-dual-runtime-acceptance.md docs/plans/2026-08-22-macos-pinned-bottle-execution-design.md
git commit -s -m "docs: record pinned macOS execution evidence"
```
