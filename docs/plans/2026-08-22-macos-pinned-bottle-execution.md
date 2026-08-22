# Pinned Bottle Execution Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Launch the fixed SumatraPDF acceptance executable from one verified unlinked-file lease instead of reopening a mutable Bottle pathname.

**Architecture:** A closed macOS-only CLI session captures the fixed Bottle executable through a held no-follow directory chain, creates and immediately unlinks a private ordinary file beneath one held external work root, and uses the same lease for inspection, planning, authorization, and Wine process creation. The ordinary `LaunchPlan` JSON, FFI ABI, default `BottleInPlace`, 7-Zip, and Notepad++ behavior remain unchanged.

**Tech Stack:** Rust 2021, Python 3.12 contracts, audited Unix `openat`/`fstatat`/`unlinkat`, unlinked ordinary files, inherited descriptors, Wine `start.exe /unix`, existing CompatForge process supervision.

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
  <external-work-root> <inherited-work-root-fd> <milliseconds>
```

Reject missing, extra, option-shaped, relative, combined, non-macOS, or ordinary-Bottle uses. Pin the future command to:

- Bottle id `gui-sumatrapdf`;
- mode `bottleInPlace`;
- architecture `x86_64`;
- logical suffix `CompatForge/SumatraPDF/SumatraPDF.exe`;
- no guest arguments; and
- a pre-created empty external work root, owned by the effective user with mode `0700`, held for the
  full session and used for both the unlinked execution file and fixed create-new inspection/plan
  output names; the numeric descriptor must be inherited by the CLI, must resolve to that exact
  path identity, and is never echoed.

**Step 2: Run RED**

```bash
cargo test -p compatforge-domain -p compatforge-cli --all-targets --locked pinned
& '<python-3.12>' -S -B -m unittest tests.test_gui_baseline_contracts -v
```

Expected: the schema snapshots pass and the command parser tests fail because the command does not exist.

**Step 3: Add only the closed parser shape**

Parse the command into a private enum variant, but return a fixed unsupported/not-implemented error before any file access. Do not add domain fields or FFI symbols.

**Step 4: Run GREEN and commit**

```bash
cargo test -p compatforge-domain -p compatforge-cli --all-targets --locked
& '<python-3.12>' -S -B -m unittest tests.test_gui_baseline_contracts -v
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

### Task 3: Bind the work root and capture an unlinked Bottle lease

**Files:**
- Modify: `crates/compatforge-guest-artifact/src/lib.rs`
- Create: `crates/compatforge-guest-artifact/src/pinned_platform.rs`
- Modify: `crates/compatforge-guest-artifact/Cargo.toml`

**Step 1: Add RED platform and capture tests**

Define an opaque, non-serializable `PinnedBottleExecutable` containing:

- the existing `BottleExecutableBinding`;
- `PeInspectionReport`;
- caller-owned unlinked execution `File`;
- opened source `File`;
- each held directory handle and its identity from storage root through the executable parent; and
- the source entry identity and link count.

Tests prove component-by-component `openat(O_NOFOLLOW)` capture, reparse/symlink/hardlink rejection, same/ancestor substitution detection, and exact fixed path containment.

Add a safe opaque `HeldExternalWorkRoot` that binds a caller-created real directory with a held
descriptor. Require effective-user ownership, exact mode `0700`, emptiness, no symlink/reparse, and
lexical plus physical non-overlap with the storage root, Bottle root, source, Runtime roots, and
other CLI-known writable roots. The Python integration contract separately proves repository
externality because the CLI has no repository-root input. The safe wrapper exposes only fixed-name
create-new publication, canonical readback, identity revalidation, and unlinked-file capture;
callers never receive its raw descriptor. Pin the safe surface before implementation:

```rust
pub enum PinnedEvidenceFile {
    Inspection, // pinned-inspection.json
    Plan,       // pinned-plan.json
}

pub struct PublishedEvidenceBinding {
    pub byte_length: u64,
    pub sha256: String,
}

impl HeldExternalWorkRoot {
    pub fn from_inherited(
        raw_fd: i32,
        reviewed_path: &Path,
        forbidden_roots: &[&Path],
    ) -> Result<Self, GuestArtifactError>;
    pub fn create_unlinked_execution_file(&self) -> Result<File, GuestArtifactError>;
    pub fn publish_canonical(
        &self,
        kind: PinnedEvidenceFile,
        bytes: &[u8],
    ) -> Result<PublishedEvidenceBinding, GuestArtifactError>;
    pub fn read_canonical(
        &self,
        kind: PinnedEvidenceFile,
    ) -> Result<Vec<u8>, GuestArtifactError>;
    pub fn revalidate(&self) -> Result<(), GuestArtifactError>;
}
```

Do not expose a method accepting a caller-selected filename or absolute output path, and do not
expose a raw-descriptor accessor. `from_inherited` consumes the inherited descriptor on success and
closes it on every failure; the CLI must not reconstruct the directory by pathname.

On macOS, generate exactly 128 bits with `arc4random_buf`, encode them as a fixed 32-lowercase-hex
suffix, and create `.compatforge-pinned-<suffix>` relative to the held work-root descriptor with
`openat(O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600)`. Retry collisions at most 16 times. After
an initial `fstat` proves an empty, single-link, owned regular file, call `unlinkat` immediately and
require a second `fstat` to prove the same inode, size zero, and `st_nlink == 0`. Copy no source byte
before that second check. The name necessarily exists briefly as filesystem metadata; it must never
enter a log, serialized evidence, return value, or retained directory entry after `unlinkat`. Add
injected tests for collision exhaustion, unlink failure, identity drift, nonzero pre-copy size,
short copy, sync, rewind, and inspection failures.

Document the accepted trust boundary in the tests: this phase does not claim protection from a
malicious directory-search-capable principal that guesses or enumerates the random name and opens it
during the successful `openat`-to-`unlinkat` interval. Tests must still prove that pre-created names
lose to `O_EXCL`, mode/owner checks are enforced without claiming they override ACL or filesystem
configuration, and no pathname can acquire the inode after unlink.

**Step 2: Run RED**

```bash
cargo test -p compatforge-guest-artifact --all-targets --locked pinned
```

**Step 3: Implement the audited platform boundary**

Replace crate-wide `forbid(unsafe_code)` with `deny(unsafe_op_in_unsafe_fn)`. Confine all unsafe
calls to `pinned_platform.rs`, with one safety comment per call. Use only `openat`, `fstatat`,
`fstat`, `unlinkat`, `fcntl`, `arc4random_buf`, and the exact owned-fd conversion needed by the safe
RAII wrappers. Do not use `shm_open`, `shm_unlink`, a named temporary-file API, or a pathname reopen.
Expose the safe `HeldExternalWorkRoot`, held source-chain, and unlinked-file wrappers to the rest of
the crate.

The Windows implementation is a fixed unsupported-platform branch plus pure helper tests. It must compile without accessing a source path.

**Step 4: Implement capture and revalidation**

```rust
pub fn pin_sumatra_bottle_executable(
    &self,
    bottle_id: &str,
    source: &Path,
    work_root: &HeldExternalWorkRoot,
) -> Result<PinnedBottleExecutable, GuestArtifactError>;
```

Require `gui-sumatrapdf` and the fixed relative path. Revalidate every held identity, link count,
size, ctime/mtime, and a fresh digest of the held source before returning and at every pre-spawn
lease boundary. A mutation observed by final revalidation rejects with zero child creation. The
unlinked-file digest/size/inspection are the execution binding of record; mutation after successful
spawn cannot redirect those bytes and is reported by post-spawn integrity revalidation.

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
2. consume the inherited work-root descriptor, bind it to the supplied path, require the directory
   is initially empty, and reject physical/lexical overlap with storage, Bottle, source, Runtime and
   other CLI-known writable roots; the Python caller separately proves repository externality before
   invoking the command;
3. no-follow source capture into an ordinary file created and immediately unlinked relative to that
   held root;
4. pinned prepare;
5. pinned authorize;
6. publish fixed-name inspection and plan files through `HeldExternalWorkRoot` create-new methods
   plus canonical readback; and
7. pinned process start, immediate post-spawn source revalidation, and existing event supervision.

Mutation tests replace or overwrite the logical path before final revalidation and assert integrity
failure with zero child creation. A test-only callback in the internal session function changes the
source after fake child creation but before post-spawn revalidation and proves the already-created
child still receives only the unlinked captured bytes before the integrity shutdown path runs. The
production parser and CLI expose no hook, stdin, environment switch, or delay.

**Step 2: Add stable error mapping tests**

Every open, component, capture, unlink, copy, sync, inspect, authorize, evidence-write, descriptor,
spawn, and cleanup error maps to one fixed
`compatforge-cli: pinned SumatraPDF launch failed\n` message. Errors, stdout and compact evidence
contain no storage, source, work, developer, random staging-name or descriptor detail. Canonical plan
and external full evidence may retain only the authorized logical Bottle/Runtime/storage paths
already present in an ordinary `LaunchPlan`; neither may contain descriptor numbers, random staging
names, anonymous paths, or temporary paths.

On success the existing RuntimeEvent JSON lines remain byte-compatible. After the terminal event,
stdout contains exactly one final compact canonical receipt line with fixed field order and no path:

```json
{"outputs":[{"byteLength":123,"kind":"inspection","sha256":"sha256:<64-lower-hex>"},{"byteLength":456,"kind":"plan","sha256":"sha256:<64-lower-hex>"}],"recordType":"pinned-evidence-receipt","schemaVersion":1}
```

Require literal output order `inspection`, then `plan`; bounded positive integer lengths; exact
digest syntax; and no extra keys, non-event records, text, stderr, or receipt line. The receipt is
mandatory and last. These digests bind the post-CLI Python readback, not the executable-content
digest in the plan.

**Step 3: Run RED**

```bash
cargo test -p compatforge-cli --all-targets --locked pinned
& '<python-3.12>' -S -B -m unittest tests.test_gui_baseline_contracts -v
```

**Step 4: Implement and run GREEN**

Use only `HeldExternalWorkRoot` fixed-name create-new/no-follow output publication with canonical
readback. Revalidate the held root before and after each publication and once more before returning
the final session result. The CLI takes ownership only of its inherited descriptor duplicate; the
Python parent keeps its original descriptor open. Do not add stdin, PATH, shell, ambient environment,
network, or fallback behavior.

```bash
cargo test -p compatforge-cli --all-targets --locked
cargo clippy -p compatforge-cli --all-targets --locked -- -D warnings
git add apps/cli tests/test_gui_baseline_contracts.py
git commit -s -m "feat: launch a pinned SumatraPDF session"
```

### Task 7: Stop for the real macOS Wine spike

**Files:**
- Modify: `crates/compatforge-process/Cargo.toml`
- Create: `crates/compatforge-process/tests/macos_pinned_sumatrapdf_spike.rs`
- Create: `docs/testing/macos-pinned-sumatrapdf-spike.md` only as a local handoff until redacted
  evidence exists

**Step 1: Add the test-only macOS harness before using the Mac**

Add `compatforge-orchestrator` as a dev-dependency only; this does not change the production
dependency graph. Create host-independent fake-process ordering tests in the integration-test file
without a file-level macOS cfg. Give only the real test function
`#[cfg(target_os = "macos")]` and `#[ignore]`. That function calls the same
`HeldExternalWorkRoot`, capture, prepare, authorize, `start_pinned_bottle`, source revalidation, and
managed termination APIs as the CLI. It may read exactly one test-only
`COMPATFORGE_PINNED_SPIKE_INPUT` variable naming a repository-external canonical JSON manifest. The
manifest supplies two reviewed Runtime executable paths, a dedicated disposable Bottle, fixed
Sumatra source, and private empty work roots; it is never committed and the production CLI does not
read this variable.

The harness must have two explicit phases per Runtime:

1. a stable source run that starts the child and observes the fixed Sumatra window; and
2. a mutation run in which `start_pinned_bottle` first returns a live managed handle, the harness
   then overwrites or substitutes the disposable logical source, observes that the launched window
   still corresponds to the captured digest, calls the production source revalidation, and requires
   the production integrity termination and process-tree cleanup path.

Add host-independent fake-process tests for this ordering before running the ignored test. The
production command must contain no corresponding hook or environment branch.

**Step 2: Build the exact branch on Apple Silicon**

Build the CLI with the existing locked toolchain and first run only the closed pinned command against
the fixed SumatraPDF asset in CrossOver and Whisky with a stable source. Then run the ignored harness
against a dedicated disposable copy:

```bash
COMPATFORGE_PINNED_SPIKE_INPUT=/private/.../pinned-spike.json \
  cargo test -p compatforge-process --test macos_pinned_sumatrapdf_spike \
  --locked -- --ignored --nocapture
```

**Step 3: Verify both Runtimes**

For CrossOver and Whisky independently require:

- the Wine child inherits the descriptor;
- `start.exe /unix /dev/fd/<n>` opens the Sumatra window;
- the expected title is observed;
- source overwrite/substitution does not change executed bytes; and
- zero residual process and cleanup failures.

**Step 4: Gate the remainder**

If either Runtime fails, stop and revise the design. Do not integrate the command into
`run_gui_baseline.py`, do not fall back to pathname execution, and do not claim the pinned-execution
phase complete.

If both pass, record only redacted Runtime-id/window/cleanup results and continue. Never record the
manifest path, source path, work root, random staging name, or descriptor number. The production
acknowledgement path is verified after runner integration in Task 8.

### Task 8: Select the pinned session only for SumatraPDF

**Files:**
- Modify: `tools/run_gui_baseline.py`
- Modify: `tests/test_gui_baseline_contracts.py`
- Modify: `tests/test_macos_dual_runtime_acceptance.py`
- Modify: `tests/test_macos_headless_preview.py`
- Modify: `scripts/validate_repository.py` only for an exact reviewed command contract

**Step 1: Add RED runner tests**

Use exact app id `sumatrapdf`. Assert that Sumatra omits the separate GUI `inspect` and
`prepared-plan` calls and instead invokes the single pinned session. 7-Zip and Notepad++ remain
byte-compatible.

The existing GUI `arguments.work_root` is already nonempty and is not the pinned root. For each
Sumatra launch, create exactly one unique child directory beneath that already-bound external root
using create-new semantics and explicit mode `0700`; open it no-follow, verify owner/mode/identity and
emptiness, and keep the parent and child directory descriptors through subprocess completion,
evidence verification, and cleanup. Pass the child descriptor with `pass_fds` and include its number
only in the closed CLI argv; never include it in evidence or diagnostics.

Preserve the existing RuntimeEvent JSONL observation and acknowledgement flow. After its terminal
event, require exactly one final `pinned-evidence-receipt` record and no later line. Then open only
`pinned-inspection.json` and `pinned-plan.json` fd-relative/no-follow, require regular single-link
files and bounded canonical bytes, and compare exact byte length and SHA-256 before consuming either
document. Revalidate the parent/child identities before and after both reads. An inode/path/root
replacement, digest/size mismatch, extra/missing file, link/reparse, stdout drift, or cleanup failure
is fatal. A replacement containing byte-identical canonical content is evidence-equivalent.

Extend the work-tree allowlist only for the dedicated session directory and the two fixed filenames.
On success remove only still-owned files and the still-owned empty child directory. On foreign
substitution do not delete foreign bytes; raise the existing cleanup-fatal classification. Tests
cover consecutive sessions and prove no stale file is reused.

Reject naked-path fallback, wrong app id, wrong fixed path, missing output evidence, dynamic
descriptor/path leakage, and pinned errors rewritten as ordinary accepted evidence. Add explicit
mutants for the current nonempty work root being passed directly, omitted `pass_fds`, parent or child
root swap, ACL/mode assumptions used as a substitute for digest verification, post-CLI output
replacement, same-size content replacement, and premature descriptor close.

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

Require specification and quality reviews to both report `C0 / I0 / M0`. Replay initial capture,
pre-final-revalidation overwrite/path replacement, post-spawn source mutation, random-name collision,
create-before-unlink and zero-link failures, work-root substitution, descriptor inheritance/cleanup,
naked fallback, and evidence-leak mutants. Confirm that the review does not claim protection against
the explicitly excluded directory-search-capable create-to-unlink opener. Separately prove that
post-CLI evidence replacement is detected by held-fd length/digest verification even when the writer
has the same UID or ACL-granted directory access.

**Step 3: Commit verified documentation**

```bash
git add docs/guides/macos-local-dual-runtime-acceptance.md docs/plans/2026-08-22-macos-pinned-bottle-execution-design.md
git commit -s -m "docs: record pinned macOS execution evidence"
```
