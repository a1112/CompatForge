# macOS Local Dual-Runtime Acceptance Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build and execute a developer-local Apple Silicon acceptance workflow that proves CrossOver and Whisky can each run the CompatForge Console baseline plus 7-Zip, SumatraPDF, and Notepad++ twice with complete interaction and cleanup evidence.

**Architecture:** Keep Rust Core, the Service API, PreparedLaunch, and ProcessSupervisor as the only execution authority. Add bounded developer tooling around the existing single-Runtime runners: enumerate exactly one verified CrossOver and Whisky candidate, pass an explicit Runtime quartet into both the runner and Tauri shell, isolate every Runtime/application/round, and compare only a redacted deterministic evidence projection. Do not change public schemas, ABI major, ForgeOS, ForgeTools, or Mac-Win.

**Tech Stack:** Rust stable, Python 3.11+, Tauri 2, TypeScript/Vite, macOS Apple Silicon, Rosetta 2, CrossOver, Whisky, MinGW-w64, GitHub Actions contract tests.

---

## Preconditions and execution rules

- Work only in the dedicated `agent/macos-local-dual-runtime-acceptance` worktree.
- Use @superpowers:test-driven-development for every behavior change.
- Use @superpowers:systematic-debugging for every unexpected local or real-Mac failure.
- Use @superpowers:verification-before-completion before every commit, push, PR, or completion claim.
- On Windows, invoke an explicit Python 3.11+ interpreter. The ambient `python` may be Python 3.9 and is unsupported.
- Keep Cargo targets, Node modules, downloads, Bottles, screenshots, and acceptance evidence outside the repository.
- Never mutate the real CrossOver or Whisky installation. Negative checks use isolated copies only.
- Do not begin a later task while the current task's focused tests are red.

### Task 1: Freeze the dual-Runtime acceptance contract

**Files:**
- Create: `tests/test_macos_dual_runtime_acceptance.py`
- Create: `tools/run_macos_dual_runtime_acceptance.py`
- Modify: `scripts/validate_repository.py`
- Reference: `docs/plans/2026-08-21-macos-local-dual-runtime-acceptance-design.md`

**Step 1: Write the failing closed-contract tests**

Add tests that import the wished-for module and require an exact matrix:

```python
EXPECTED_MATRIX = {
    "crossover": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
    "whisky": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
}

def test_acceptance_matrix_is_exact_and_has_two_rounds(self) -> None:
    self.assertEqual(acceptance.RUNTIME_MATRIX, EXPECTED_MATRIX)
    self.assertEqual(acceptance.ROUNDS, ("round-1", "round-2"))

def test_python_preflight_rejects_unsupported_interpreters(self) -> None:
    with self.assertRaisesRegex(acceptance.AcceptanceError, "Python 3.11 or newer"):
        acceptance.require_python((3, 9, 11))
```

Also require the repository validator to include the new tool and test in its reviewed macOS acceptance surface.

**Step 2: Run the focused tests and verify RED**

Run on Windows with the explicit Python 3.12 executable:

```powershell
& 'C:\Users\10428\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' `
  -S -B -m unittest tests.test_macos_dual_runtime_acceptance -v
```

Expected: import failure because `tools/run_macos_dual_runtime_acceptance.py` does not exist.

**Step 3: Add the minimal closed module**

Create a dependency-free module with only constants, a closed error, and the version check:

```python
RUNTIME_MATRIX = {
    "crossover": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
    "whisky": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
}
ROUNDS = ("round-1", "round-2")

class AcceptanceError(Exception):
    pass

def require_python(version: tuple[int, int, int]) -> None:
    if version < (3, 11, 0):
        raise AcceptanceError("Python 3.11 or newer is required")
```

Add a validator allowlist entry rather than broad directory discovery.

**Step 4: Run focused GREEN and repository validation**

Run:

```bash
python3 -S -B -m unittest tests.test_macos_dual_runtime_acceptance -v
python3 -S -B scripts/validate_repository.py
```

Expected: focused tests pass and validator reports `repository contracts are internally consistent`.

**Step 5: Commit**

```bash
git add tools/run_macos_dual_runtime_acceptance.py tests/test_macos_dual_runtime_acceptance.py scripts/validate_repository.py
git commit -s -m "test: define dual-runtime macOS acceptance"
```

### Task 2: Enumerate one verified CrossOver and one verified Whisky Runtime

**Files:**
- Modify: `tools/discover_macos_wine.py:24-220`
- Modify: `tests/test_macos_headless_preview.py`
- Test: `tests/test_macos_dual_runtime_acceptance.py`

**Step 1: Write failing enumeration tests**

Add tests for a new pure function:

```python
def test_discover_all_selects_one_candidate_per_required_runtime(self) -> None:
    result = discovery.discover_all(candidates, runner=fake_runner)
    self.assertEqual([item["runtimeId"] for item in result], ["crossover", "whisky"])

def test_discover_all_fails_when_either_runtime_is_missing(self) -> None:
    with self.assertRaisesRegex(discovery.DiscoveryError, "required Runtime is unavailable"):
        discovery.discover_all(crossover_only, runner=fake_runner)
```

Cover duplicate CrossOver layouts, duplicate Whisky layouts, invalid Mach-O, failing `--version`, symlinks escaping the candidate root, and a Mac-Win development build that must not satisfy the Whisky requirement.

**Step 2: Run and verify RED**

Run:

```bash
python3 -S -B -m unittest \
  tests.test_macos_headless_preview \
  tests.test_macos_dual_runtime_acceptance -v
```

Expected: failure because `discover_all` and `runtimeId` do not exist.

**Step 3: Implement minimal source classification and enumeration**

Keep `discover()` backward compatible. Add:

```python
def runtime_id(candidate: Candidate) -> str | None:
    if candidate.source == "crossover-app":
        return "crossover"
    if candidate.source in ("whisky-app", "whisky-library"):
        return "whisky"
    return None

def discover_all(...):
    selected: dict[str, dict[str, str]] = {}
    for candidate in selected_candidates:
        identifier = runtime_id(candidate)
        if identifier is None or identifier in selected:
            continue
        verified = verify_candidate(candidate, runner)
        if verified is not None:
            selected[identifier] = {**verified, "runtimeId": identifier}
    if set(selected) != {"crossover", "whisky"}:
        raise DiscoveryError("required Runtime is unavailable")
    return [selected[identifier] for identifier in ("crossover", "whisky")]
```

Add a closed CLI option `--all`; default output remains the current single object. `--all` emits:

```json
{"runtimes":[...],"schemaVersion":"1"}
```

**Step 4: Run GREEN and default-output regression**

Run the focused tests plus the existing discovery CLI tests. Expected: default single discovery remains byte-compatible; `--all` is sorted and closed.

**Step 5: Commit**

```bash
git add tools/discover_macos_wine.py tests/test_macos_headless_preview.py tests/test_macos_dual_runtime_acceptance.py
git commit -s -m "feat: enumerate macOS preview runtimes"
```

### Task 3: Add an explicit developer acceptance Runtime to the Tauri shell

**Files:**
- Modify: `apps/desktop/src-tauri/src/lib.rs:34-225,283-348`
- Modify: `apps/desktop/src-tauri/src/main.rs`
- Test: `apps/desktop/src-tauri/src/lib.rs`
- Test: `tests/test_gui_baseline_contracts.py`

**Step 1: Write failing Rust tests for a closed argument quartet**

Define the desired parser API in tests:

```rust
#[test]
fn acceptance_runtime_requires_an_exact_argument_quartet() {
    let options = DesktopLaunchOptions::parse([
        "compatforge-desktop",
        "--acceptance-root", "/absolute/evidence/crossover",
        "--wine-root", "/Applications/CrossOver.app/Contents/SharedSupport/CrossOver",
        "--wine", "bin/wine",
        "--wineserver", "bin/wineserver",
        "--version", "25.0",
    ]).unwrap();
    assert!(options.runtime_override.is_some());
}

#[test]
fn partial_or_relative_acceptance_arguments_are_rejected() {
    assert!(DesktopLaunchOptions::parse(["app", "--wine", "bin/wine"]).is_err());
    assert!(DesktopLaunchOptions::parse(["app", "--acceptance-root", "relative"]).is_err());
}
```

Also add a Python source-contract test proving the desktop does not use PATH lookup, shell commands, or a new environment variable for the Runtime override.

**Step 2: Run RED**

Run:

```bash
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml acceptance_runtime --locked
python3 -S -B -m unittest tests.test_gui_baseline_contracts -v
```

Expected: Rust compile failure because `DesktopLaunchOptions` does not exist.

**Step 3: Implement the minimal developer-only launch options**

Add a private `DesktopLaunchOptions` containing an absolute acceptance root and an optional complete Runtime quartet. Parse only the documented flags, reject duplicates/unknowns, validate relative entrypoints through the existing Core request, and keep normal zero-argument launch unchanged.

Change `DesktopRuntime` to retain the optional quartet. Change `bootstrap_core` to build the existing `MacOsLocalContextRequest` from either automatic discovery or the complete explicit quartet. Do not add a public DTO, schema, FFI symbol, UI Runtime picker, or environment fallback.

**Step 4: Run GREEN and desktop build checks**

Run:

```bash
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --locked
cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets --locked -- -D warnings
npm ci --prefix apps/desktop
npm run build --prefix apps/desktop
```

Expected: all pass; normal app startup still uses automatic discovery.

**Step 5: Commit**

```bash
git add apps/desktop/src-tauri/src/lib.rs apps/desktop/src-tauri/src/main.rs tests/test_gui_baseline_contracts.py
git commit -s -m "feat: select explicit macOS runtime for local acceptance"
```

### Task 4: Make single-Runtime GUI evidence runtime-bound and classifiable

**Files:**
- Modify: `tools/run_gui_baseline.py:50-689`
- Modify: `tests/test_gui_baseline_contracts.py`
- Reference: `tools/download_gui_assets.py`

**Step 1: Write failing evidence tests**

Require `--runtime-id` with the closed choices `crossover` and `whisky` whenever an explicit quartet is supplied. Require each application record to contain:

```json
{
  "runtimeId": "crossover",
  "status": "failed",
  "failureClass": "core"
}
```

Add table-driven tests for `environment`, `runtime`, `core`, `desktop`, `application`, and `cleanup`. Reject absolute local paths in the compact summary.

**Step 2: Run RED**

Run:

```bash
python3 -S -B -m unittest tests.test_gui_baseline_contracts -v
```

Expected: failures because runtime identity and failure classification are absent.

**Step 3: Implement minimal additive evidence fields**

Keep the current internal `schemaVersion: "1"`. Add `runtimeId` to receipt and application evidence, plus a closed `failureClass` only when status is not `accepted`. Preserve full local diagnostics in the external evidence file, but emit only a stable closed reason code in the compact summary.

Do not change fixed asset URLs or hashes in this task.

**Step 4: Run GREEN plus downloader tests**

Run:

```bash
python3 -S -B -m unittest \
  tests.test_gui_baseline_contracts \
  tests.test_macos_headless_preview -v
```

Expected: all pass, with zero network access.

**Step 5: Commit**

```bash
git add tools/run_gui_baseline.py tests/test_gui_baseline_contracts.py
git commit -s -m "test: bind GUI evidence to macOS runtime"
```

### Task 5: Implement the bounded two-round orchestrator

**Files:**
- Modify: `tools/run_macos_dual_runtime_acceptance.py`
- Modify: `tests/test_macos_dual_runtime_acceptance.py`
- Reference: `tools/run_macos_headless_preview.py`
- Reference: `tools/run_gui_baseline.py`

**Step 1: Write failing orchestration tests with fake subprocesses**

Test exact argv and directory layout without starting Wine:

```text
work-root/
  round-1/crossover/{console,gui,desktop}/
  round-1/whisky/{console,gui,desktop}/
  round-2/crossover/{console,gui,desktop}/
  round-2/whisky/{console,gui,desktop}/
```

Require:

- all roots are absolute, external, non-overlapping, and initially empty;
- the discovery command runs once and yields exactly two Runtime descriptors;
- each descriptor is passed as the complete explicit quartet;
- Console precedes GUI for a Runtime;
- a failed Console marks that Runtime's GUI paths `blocked` without falling back;
- all eight paths are attempted per round when preconditions pass.

**Step 2: Run RED**

Run the focused module. Expected: failures because parser, preflight, layout, and orchestration functions are absent.

**Step 3: Implement parser and preflight**

Add required arguments:

```text
--compatforge-cli
--desktop-app
--cc
--cache-root
--runtime-store-root
--storage-root
--work-root
--interaction-evidence-root
--allow-network
```

Refuse repository-internal roots, symlinks, overlaps, non-empty Work Root, unsupported Python, non-Darwin/arm64, or incomplete interaction evidence files. Do not read PATH to find Wine or the compiler.

**Step 4: Implement orchestration using existing tools**

For each round and Runtime:

1. invoke the existing headless runner with the explicit Runtime quartet;
2. invoke the GUI runner with `--runtime-id`, a Runtime-specific store, and the round-specific interaction evidence;
3. print the exact Tauri command using the same quartet and Runtime-specific acceptance root;
4. require the tester to close the desktop app before continuing;
5. collect child summaries without copying screenshots or absolute paths into the aggregate.

Use direct argv subprocesses, fixed timeouts, empty explicit environments where supported, and no shell.

**Step 5: Run focused GREEN**

Expected: all fake-process orchestration tests pass on Windows/Linux without Wine, network, or Tauri.

**Step 6: Commit**

```bash
git add tools/run_macos_dual_runtime_acceptance.py tests/test_macos_dual_runtime_acceptance.py
git commit -s -m "feat: orchestrate dual-runtime macOS acceptance"
```

### Task 6: Compare deterministic redacted evidence across rounds

**Files:**
- Modify: `tools/run_macos_dual_runtime_acceptance.py`
- Modify: `tests/test_macos_dual_runtime_acceptance.py`

**Step 1: Write failing projection tests**

Build two fixtures that differ only in request IDs, PIDs, timestamps, absolute roots, screenshot paths, and RuntimeEvent timing. Require equal projections. Mutate Runtime digest, application status, interaction checks, exit status, window availability, or cleanup and require inequality.

Desired projection shape:

```json
{
  "runtimeId": "crossover",
  "runtimeVersion": "...",
  "packDigest": "sha256:...",
  "applications": [
    {
      "appId": "7zip",
      "assetSha256": "...",
      "status": "accepted",
      "interactionChecks": {"fileList": true, "menus": true},
      "exitCode": 0,
      "windowAvailable": true,
      "cleanup": true
    }
  ]
}
```

**Step 2: Run RED**

Expected: projection/comparison API is missing.

**Step 3: Implement an allowlist projection**

Construct the projection from named fields only. Never recursively delete suspicious fields from arbitrary input. Sort Runtime and application records by fixed IDs. Write `round-projection.json` per round and `comparison.json` at the aggregate root.

**Step 4: Run GREEN and mutation tests**

Expected: dynamic-only differences compare equal; every security/behavior mutation compares unequal.

**Step 5: Commit**

```bash
git add tools/run_macos_dual_runtime_acceptance.py tests/test_macos_dual_runtime_acceptance.py
git commit -s -m "test: compare redacted macOS acceptance evidence"
```

### Task 7: Add isolated negative Runtime and asset checks

**Files:**
- Modify: `tools/run_macos_dual_runtime_acceptance.py`
- Modify: `tests/test_macos_dual_runtime_acceptance.py`
- Modify: `tests/test_gui_baseline_contracts.py`
- Reference: `tools/download_gui_assets.py`

**Step 1: Write failing negative-check tests**

Require four independent isolated-copy checks:

1. changed Wine bytes;
2. changed wineserver bytes;
3. changed Console Guest PE bytes;
4. changed cached installer bytes.

Each check must fail before process creation and preserve the real Runtime/cache file. Add sentinels outside the owned negative root and assert they remain byte-identical.

**Step 2: Run RED**

Expected: no negative-check orchestration exists.

**Step 3: Implement copy-bound negative checks**

Materialize only required files under `work-root/negative/<runtime-id>/<case>`, bind original digests before copying, mutate only the owned copy, call the existing Core/downloader boundary, and require the expected closed refusal. Never recursively copy or modify the full commercial Runtime.

**Step 4: Run GREEN**

Run focused tests and verify source/sentinel preservation assertions.

**Step 5: Commit**

```bash
git add tools/run_macos_dual_runtime_acceptance.py tests/test_macos_dual_runtime_acceptance.py tests/test_gui_baseline_contracts.py
git commit -s -m "test: reject mutated macOS acceptance inputs"
```

### Task 8: Document the Mac operator handoff and evidence template

**Files:**
- Create: `docs/guides/macos-local-dual-runtime-acceptance.md`
- Create: `examples/macos-dual-runtime-interactions.json`
- Modify: `README.md`
- Modify: `docs/testing.md`
- Modify: `scripts/validate_repository.py`
- Test: `tests/test_macos_dual_runtime_acceptance.py`

**Step 1: Write failing documentation-contract tests**

Require the guide to contain:

- Python 3.11+ and an explicit interpreter check;
- Apple Silicon, Rosetta, CrossOver, Whisky, MinGW, Rust, Node, and disk-space preflight;
- the exact no-network discovery command;
- the exact opt-in asset-fetch command;
- the exact two-round orchestration command;
- external-root and safe-cleanup rules;
- the 16-run exit gate and non-claims.

Require the example interaction document to be closed and to contain separate records for each round and Runtime.

**Step 2: Run RED**

Expected: missing guide and example.

**Step 3: Write the guide and reviewed example**

Use placeholders such as `/absolute/external/...`; never check in a developer path. Make the operator confirm each app interaction immediately after the run rather than copying one boolean set across all combinations.

**Step 4: Run documentation GREEN and repository validation**

Run focused tests and validator. Expected: both pass and no repository artifact is created.

**Step 5: Commit**

```bash
git add docs/guides/macos-local-dual-runtime-acceptance.md examples/macos-dual-runtime-interactions.json README.md docs/testing.md scripts/validate_repository.py tests/test_macos_dual_runtime_acceptance.py
git commit -s -m "docs: guide dual-runtime macOS acceptance"
```

### Task 9: Close default CI without running commercial Runtimes

**Files:**
- Modify: `.github/workflows/ci.yml`
- Modify: `tests/test_macos_dual_runtime_acceptance.py`
- Modify: `apps/desktop/tests/smoke.py`

**Step 1: Write failing workflow-contract tests**

Require default CI to run:

- dual-Runtime Python contract tests on Windows and macOS;
- Tauri Rust tests/clippy;
- Vite build;
- desktop smoke with no Runtime;
- repository validator and existing GUI/headless tests.

Require CI to contain no `--allow-network`, CrossOver download, Whisky download, real installer execution, screenshot acceptance, or `--accept-interactive` command.

**Step 2: Run RED**

Expected: workflow lacks the new focused suite.

**Step 3: Add only contract/smoke jobs**

Reuse existing jobs where possible. Pin Python 3.12 and Node 24 as the repository already does. Do not add secrets, commercial binaries, or self-hosted runners.

**Step 4: Run local workflow oracle and full gates**

Run:

```bash
python3 -S -B -m unittest tests.test_macos_dual_runtime_acceptance tests.test_gui_baseline_contracts tests.test_macos_headless_preview -v
python3 -S -B scripts/validate_repository.py
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
npm ci --prefix apps/desktop
npm run build --prefix apps/desktop
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --locked
```

Expected: all pass without real Runtime or network.

**Step 5: Commit**

```bash
git add .github/workflows/ci.yml tests/test_macos_dual_runtime_acceptance.py apps/desktop/tests/smoke.py
git commit -s -m "ci: gate macOS acceptance contracts"
```

### Task 10: Execute the real two-Runtime matrix on the Mac

**Files:**
- External only: asset cache, Runtime Store, storage roots, Work Root, interaction evidence, screenshots
- Verify: repository-wide

**Step 1: Synchronize and verify the exact branch on the Mac**

Run:

```bash
git fetch origin --prune
git switch agent/macos-local-dual-runtime-acceptance
git pull --ff-only
git status --short --branch
python3 --version
uname -m
sw_vers
```

Expected: clean branch, Python 3.11+, `arm64`, recorded macOS version.

**Step 2: Run all automatic gates before network or Wine**

Run the complete Task 9 local matrix. Stop and use @superpowers:systematic-debugging if any gate fails.

**Step 3: Build the CLI and Tauri app outside the repository**

```bash
CARGO_TARGET_DIR=/absolute/external/cargo-target cargo build -p compatforge-cli --locked
npm ci --prefix apps/desktop
npm run tauri --prefix apps/desktop -- build --bundles app
```

Record executable and app-bundle SHA-256 values.

**Step 4: Discover both Runtimes without network**

```bash
python3 -S -B tools/discover_macos_wine.py --all > /absolute/external/evidence/runtimes.json
```

Expected: exactly `crossover` then `whisky`, each x86_64 and executable-verified.

**Step 5: Fetch the three official assets once**

```bash
python3 -S -B tools/download_gui_assets.py fetch \
  --cache-root /absolute/external/cache \
  --allow-network
```

Expected: three fixed asset receipts with matching SHA-256 values. Disable network for all later runs.

**Step 6: Prepare four separate interaction documents**

Copy the reviewed template to:

```text
interactions/round-1/crossover.json
interactions/round-1/whisky.json
interactions/round-2/crossover.json
interactions/round-2/whisky.json
```

Complete each document only while observing that exact run.

**Step 7: Run the two-round orchestrator**

```bash
python3 -S -B tools/run_macos_dual_runtime_acceptance.py \
  --compatforge-cli /absolute/external/cargo-target/debug/compatforge-cli \
  --desktop-app /absolute/path/CompatForge.app/Contents/MacOS/CompatForge \
  --cc /opt/homebrew/bin/x86_64-w64-mingw32-gcc \
  --cache-root /absolute/external/cache \
  --runtime-store-root /absolute/external/runtime-stores \
  --storage-root /absolute/external/storage \
  --work-root /absolute/empty/dual-runtime-evidence \
  --interaction-evidence-root /absolute/external/interactions
```

Expected: 16 `accepted` results, equal round projections, zero cleanup failures, exit 0.

**Step 8: Run isolated negative checks**

Run the documented negative mode. Expected: all four mutation classes are rejected before process creation and real Runtime/cache digests remain unchanged.

**Step 9: Preserve evidence and clean only owned roots**

Archive the external evidence directory. Verify repository status remains clean. Remove only explicitly named, reviewed storage/work roots; retain the cache unless the operator deliberately chooses to remove it.

**Step 10: Do not commit real evidence yet**

Only the redacted stage report from Task 11 may enter Git.

### Task 11: Diagnose real failures with minimal TDD fixes

**Files:**
- Modify only files proven responsible by Task 10 evidence
- Add focused regression tests beside the responsible component

**Step 1: Classify each failure**

Assign exactly one primary class: `environment`, `runtime`, `core`, `desktop`, `application`, or `cleanup`. Do not change CompatForge for environment or third-party Runtime failures.

**Step 2: Reproduce the smallest responsible boundary**

Use @superpowers:systematic-debugging. Reduce a real GUI failure to the smallest Core, desktop command, runner, or cleanup test that still fails.

**Step 3: Write and verify RED**

Add one focused regression and run it before production changes. Confirm it fails for the observed reason.

**Step 4: Implement the minimal fix and verify GREEN**

Do not bundle UI polish, schema widening, refactors, or other application fixes.

**Step 5: Run the full automatic matrix and affected real path**

If the real path passes, rerun both complete rounds. A partial rerun cannot satisfy the exit gate.

**Step 6: Commit each independent fix**

```bash
git add <focused-files>
git commit -s -m "fix: <specific macOS acceptance boundary>"
```

### Task 12: Publish the redacted stage report and integration handoff

**Files:**
- Create: `docs/reports/2026-08-21-macos-local-dual-runtime-acceptance.md`
- Modify: `docs/testing.md`
- Test: `tests/test_macos_dual_runtime_acceptance.py`

**Step 1: Write a failing report-contract test**

Require the report to include exact CompatForge commit, Mac model/OS/architecture, Rosetta status, Rust/Node/Python versions, Runtime source/version/digest, application versions/digests, 16-result table, comparison digest, negative-check results, cleanup result, limitations, and next-stage decision.

Reject absolute developer paths, usernames, screenshots, installer bytes, Bottle contents, marketing compatibility claims, or claims of signing/notarization/Tier 1.

**Step 2: Run RED**

Expected: report missing.

**Step 3: Generate and review the redacted report**

Build the report from allowlisted fields in the aggregate summary. Manually inspect the staged diff for local paths and unsupported claims.

**Step 4: Run final verification**

Run all Task 9 gates, report-contract tests, `git diff --check`, DCO checks, LF checks, and a clean artifact scan. Verify the corresponding Windows/macOS GitHub jobs for the exact head SHA.

**Step 5: Commit**

```bash
git add docs/reports/2026-08-21-macos-local-dual-runtime-acceptance.md docs/testing.md tests/test_macos_dual_runtime_acceptance.py
git commit -s -m "docs: report macOS dual-runtime acceptance"
```

**Step 6: Request independent review**

Use @superpowers:requesting-code-review. Require separate specification and quality reviews. Fix every Critical or Important finding through a new RED/GREEN cycle and rerun the full gate.

**Step 7: Open a PR only after local evidence closes**

The PR description must state that evidence is developer-local, Runtime-specific, unsigned, unnotarized, and not a public compatibility claim.

## Completion handoff

When all tasks pass, choose the next design track rather than implementing it in this branch:

1. Developer ID signing, notarization, DMG, and internal tester distribution; or
2. ForgeOS integration against CompatForge 0.12 Service API and PreparedLaunch.

Do not combine either next track with this acceptance PR.
