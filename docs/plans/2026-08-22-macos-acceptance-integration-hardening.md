# macOS Acceptance Integration Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close the four final integration findings so the branch can safely begin the real Apple Silicon dual-Runtime acceptance matrix.

**Architecture:** Replace pre-run interaction booleans with a file-based challenge/acknowledgement protocol consumed by a second-terminal watch helper. Keep the orchestrator non-interactive, bind every acknowledgement to the current round, Runtime, application, Runtime Pack, asset, and nonce, and retain the existing no-follow and bounded-process boundaries. Separately make SumatraPDF materialization deterministic, restore the legacy workflow oracle, and remove the tracked developer path.

**Tech Stack:** Dependency-free Python 3.11+, canonical JSON, no-follow filesystem operations, `unittest`, GitHub Actions YAML contract tests, Rust/Cargo and Tauri regression gates.

---

### Task 1: Define the acknowledgement protocol and watch helper

**Files:**
- Create: `tools/confirm_macos_gui_interactions.py`
- Create: `tests/test_macos_interaction_acknowledgements.py`
- Modify: `scripts/validate_repository.py`

**Step 1: Write closed-schema RED tests**

Add literal-oracle tests for a challenge with exactly:

```python
{
    "schemaVersion": "1",
    "roundId": "round-1",
    "runtimeId": "crossover",
    "runtimeVersion": "24.0",
    "appId": "7zip",
    "packDigest": "sha256:" + "a" * 64,
    "assetDigest": "sha256:" + "b" * 64,
    "requiredChecks": ["fileList", "menus"],
    "nonce": "c" * 64,
}
```

and an acknowledgement with exactly the same identity fields plus `challengeDigest` and literal-true `interactionChecks`. Reject duplicate keys, unknown keys, wrong ordering, wrong types, extra checks, missing checks, false checks, invalid digest/nonce, invalid round/Runtime/application, oversized input, deep JSON, and non-canonical bytes.

Run:

```powershell
& '<absolute-path-to-python-3.12.exe>' -S -B -m unittest tests.test_macos_interaction_acknowledgements -v
```

Expected: RED because the helper and protocol do not exist.

**Step 2: Implement the dependency-free protocol**

In `tools/confirm_macos_gui_interactions.py`, add:

- fixed Runtime, round, application, and required-check literals;
- duplicate-key rejecting and bounded canonical JSON parsing;
- canonical challenge and acknowledgement encoders;
- SHA-256 challenge digest calculation;
- create-new, no-follow, regular-file, single-link writes;
- no-follow bounded reads with before/after identity revalidation; and
- closed `AcknowledgementError` messages that do not reflect paths or input.

Do not add network, shell, environment, PATH lookup, or repository writes.

**Step 3: Write watch-mode RED tests**

Test one helper process handling twelve challenges in deterministic order. Inject `input`, a fake clock, and a deterministic nonce source. Require:

- each prompt occurs only after its challenge exists;
- a negative answer writes no receipt;
- an interrupted helper leaves no partial file;
- an existing, linked, hardlinked, substituted, replayed, or wrong-identity receipt is rejected; and
- the helper exits only after twelve valid receipts.

Expected: RED because watch mode is absent.

**Step 4: Implement watch mode**

Add CLI arguments:

```text
--interaction-plan-root <absolute external root>
--acknowledgement-root <absolute external root>
```

Watch the fixed twelve challenge names. Prompt each required check with a fixed yes/no question. Write one canonical receipt only when every answer is yes. Use a bounded poll interval and permit operator cancellation without writing partial evidence.

**Step 5: Bind the new files into repository validation**

Add the helper and its test to the reviewed macOS acceptance surface. Require regular no-follow files, safe ancestors, bounded reads, and no forbidden side-effect capability.

**Step 6: Run GREEN and commit**

Run the focused tests, repository validator, `py_compile`, and `git diff --check`.

```bash
git add tools/confirm_macos_gui_interactions.py tests/test_macos_interaction_acknowledgements.py scripts/validate_repository.py
git commit -s -m "feat: acknowledge observed macOS interactions"
```

### Task 2: Require post-window acknowledgements in the GUI runner

**Files:**
- Modify: `tools/run_gui_baseline.py`
- Modify: `tests/test_gui_baseline_contracts.py`
- Reference: `tools/confirm_macos_gui_interactions.py`

**Step 1: Write timing and binding RED tests**

Prove that prefilled interaction-plan booleans cannot produce `accepted`. Add tests for:

- challenge creation only after the expected application window is observed;
- acknowledgement creation before the challenge;
- wrong round, Runtime, Runtime version, app, Pack digest, asset digest, nonce, challenge digest, or check set;
- receipt replay across applications or rounds;
- timeout and explicit negative confirmation;
- linked/reparse/substituted challenge and receipt entries; and
- a deterministic injected acknowledgement callback that does not read stdin.

Expected: RED because the runner still consumes prefilled booleans before launch.

**Step 2: Replace the CLI boundary**

Replace `--interaction-evidence` with:

```text
--interaction-plan <absolute read-only JSON>
--acknowledgement-root <absolute external directory>
--round-id round-1|round-2
```

Retain `--accept-interactive` only as the explicit opt-in that enables challenge creation. It must still be absent from default CI commands.

**Step 3: Create and await the challenge after window validation**

For each GUI app:

1. install and launch it;
2. verify its expected window;
3. create the bound challenge;
4. wait a fixed, bounded time for its acknowledgement;
5. validate and consume the acknowledgement once; and
6. derive `interactionChecks` only from that receipt.

Inject nonce, clock, and acknowledgement wait functions in tests. Production uses `secrets.token_hex(32)` and a fixed deadline.

**Step 4: Close failure semantics**

- no/timeout -> `unverified / application-interaction-unverified`;
- malformed/replayed/mismatched/unsafe receipt -> `failed / application-interaction-invalid`;
- unsafe root or directory identity drift -> integrity-fatal; and
- cleanup failure remains fatal.

Update the closed reason/status/class maps and compact/full evidence validators. Compact output must not expose paths, nonces, or raw diagnostics.

**Step 5: Run GREEN and commit**

Run GUI contracts, the new acknowledgement tests, validator, `py_compile`, and diff checks.

```bash
git add tools/run_gui_baseline.py tests/test_gui_baseline_contracts.py
git commit -s -m "fix: bind GUI evidence to observed interactions"
```

### Task 3: Integrate acknowledgements into the dual-Runtime orchestrator and docs

**Files:**
- Modify: `tools/run_macos_dual_runtime_acceptance.py`
- Modify: `tests/test_macos_dual_runtime_acceptance.py`
- Modify: `examples/macos-dual-runtime-interactions.json`
- Modify: `docs/guides/macos-local-dual-runtime-acceptance.md`
- Modify: `README.md`
- Modify: `docs/testing.md`
- Modify: `scripts/validate_repository.py`

**Step 1: Write orchestrator RED tests**

Require closed CLI arguments `--interaction-plan-root` and `--acknowledgement-root`. Reject the old evidence-root spelling, overlapping roots, unsafe ancestors, linked entries, non-empty foreign roots, extra plan records, and prefilled evidence booleans.

Assert the four plan records bind exact round/Runtime identity and exact required-check names, but contain no observed booleans.

**Step 2: Forward the current identity to each GUI child**

Pass the current round, Runtime identity, plan file, and acknowledgement root to `run_gui_baseline.py`. Revalidate all roots and plan identities before and after every child, after Desktop, and before any projection or summary write.

Do not add stdin, ambient environment, PATH lookup, network, or shell fallback.

**Step 3: Update aggregation and projection tests**

Require twelve valid GUI receipts and four automatic Console results before the sixteen-path aggregate can be accepted. Missing, false, invalid, replayed, or cross-bound receipts must prevent acceptance. Dynamic challenge nonce/digest fields must not enter deterministic round projections.

**Step 4: Update the example and guide**

Change the example to a closed interaction plan containing required-check names rather than truth claims. Document:

1. start the second-terminal helper once;
2. start the orchestrator offline;
3. perform each displayed interaction only after its challenge appears;
4. confirm each prompt immediately; and
5. require twelve receipts plus four Console results.

Update exact fenced commands and validator/parser-binding tests. Keep only the three fixed asset-fetch commands network-enabled.

**Step 5: Run GREEN and commit**

Run the dual-runtime, GUI, acknowledgement, validator, and documentation contracts.

```bash
git add tools/run_macos_dual_runtime_acceptance.py tests/test_macos_dual_runtime_acceptance.py examples/macos-dual-runtime-interactions.json docs/guides/macos-local-dual-runtime-acceptance.md README.md docs/testing.md scripts/validate_repository.py
git commit -s -m "feat: orchestrate observed macOS acknowledgements"
```

### Task 4: Make SumatraPDF materialization deterministic

**Files:**
- Modify: `tools/download_gui_assets.py`
- Modify: `tools/run_gui_baseline.py`
- Modify: `tests/test_macos_headless_preview.py`
- Modify: `tests/test_gui_baseline_contracts.py`
- Modify: `tests/test_macos_dual_runtime_acceptance.py`

**Step 1: Write fixed-artifact RED tests**

Require the official SumatraPDF 3.6.1 portable artifact, fixed SHA-256, and a bounded no-argument preparation launch.

Require exclusive no-follow materialization at `CompatForge/SumatraPDF/SumatraPDF.exe`. Test digest mismatch, source symlink, duplicate target, partial-target cleanup, and an empty child environment; prove no `USER`, `HOME`, profile enumeration, or Public fallback is consulted.

Expected: RED until the runner owns a fixed portable copy inside the current Bottle.

**Step 2: Implement the fixed portable path**

Update the asset descriptor, materialize the fixed portable bytes exactly once, run the bounded Bottle-in-place preparation smoke, and remove the Sumatra user-profile fallback from `installed_executable()`. Keep 7-Zip and Notepad++ paths unchanged.

**Step 3: Add path-safety regressions**

Reject linked, hardlinked, missing, multiple, escaping, or wrong-location executables. Confirm the fixed path is resolved beneath the current Bottle only.

**Step 4: Run GREEN and commit**

Run headless, GUI, dual-runtime, asset downloader, validator, and `py_compile` tests.

```bash
git add tools/download_gui_assets.py tools/run_gui_baseline.py tests/test_macos_headless_preview.py tests/test_gui_baseline_contracts.py tests/test_macos_dual_runtime_acceptance.py
git commit -s -m "fix: pin SumatraPDF installation path"
```

### Task 5: Restore repository and CI integration contracts

**Files:**
- Modify: `docs/plans/2026-08-21-macos-local-dual-runtime-acceptance.md`
- Modify: `scripts/validate_repository.py`
- Modify: `tests/test_macos_dual_runtime_acceptance.py`
- Modify: `tests/test_macwin_asset_migration.py`
- Modify: `.github/workflows/ci.yml`

**Step 1: Write developer-path RED tests**

Replace the tracked developer-specific Python command with an explicit environment-independent Python 3.12 placeholder. Add validator tests that mutate the reviewed macOS acceptance planning documents with Windows user, macOS user, Linux home, workspace, and tool-cache absolute paths and require fixed no-leak errors.

**Step 2: Write legacy workflow RED tests**

Run:

```powershell
& '<absolute-path-to-python-3.12.exe>' -S -B -m unittest tests.test_macwin_asset_migration.MacWinMigrationWorkflowTests.test_workflow_changes_only_pins_and_read_only_migration_checks -v
```

Expected: RED because the Mac-Win oracle does not recognize the new macOS contract job.

Update it narrowly to recognize exactly the reviewed job and commands. Do not loosen existing Mac-Win pins, migration commands, or read-only checks.

**Step 3: Add the legacy contract to default CI**

Add one active focused step to the existing contracts job. Update the Task 9 workflow structure/step signature oracle and all mutation tests. Keep the exact no-network, no-commercial-Runtime, no-installer, no-interactive, no-secret, and no-self-hosted closure.

**Step 4: Run GREEN and commit**

Run focused legacy and macOS CI contracts, repository validator, all related Python suites, diff checks, and DCO checks.

```bash
git add docs/plans/2026-08-21-macos-local-dual-runtime-acceptance.md scripts/validate_repository.py tests/test_macos_dual_runtime_acceptance.py tests/test_macwin_asset_migration.py .github/workflows/ci.yml
git commit -s -m "test: close macOS acceptance integration contracts"
```

### Task 6: Run full gates and independent reviews

**Files:**
- Verify: repository-wide

**Step 1: Run Python gates**

Run the acknowledgement, dual-runtime, GUI, headless, Mac-Win workflow, repository validator, and full discovery suites with Python 3.12 and `-S -B`.

Expected: all branch-induced tests pass. Record the existing Windows POSIX executable-bit exclusions separately; do not hide new failures.

**Step 2: Run Rust and desktop gates**

```bash
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --locked
cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets --locked -- -D warnings
```

Run `npm ci --prefix apps/desktop` and `npm run build --prefix apps/desktop` only when the locked Vite dependency is available without weakening the no-network acceptance boundary. Otherwise retain the exact `ENOTCACHED` handoff note and require the real Mac/default CI to execute it.

**Step 3: Verify repository hygiene**

Check:

- repository validator;
- `git diff --check`;
- LF and file modes;
- DCO trailers;
- no tracked caches, target output, evidence, secrets, or developer paths;
- clean worktree; and
- fresh `origin/main` divergence.

**Step 4: Request independent specification and quality reviews**

Require both reviews to report `C0 / I0 / M0`. Replay acknowledgement timing, replay, filesystem substitution, Sumatra empty-environment, legacy workflow, developer-path, and CI structure mutants.

Only then update the Mac handoff and begin Task 10.
