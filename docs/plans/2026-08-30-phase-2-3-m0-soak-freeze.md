# Phase 2.3 M0 Soak Freeze Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make the five-application, 60-cycle fresh-Bottle soak bind one explicit CrossOver Runtime, fail closed on asset or Runtime drift, and produce path-free evidence that can close Phase 2.3 M0 after a real Apple Silicon run.

**Architecture:** Keep the existing GUI baseline runner as the per-cycle executor and make `run_gui_soak.py` the closed-set orchestrator. The soak configuration records the requested Runtime quartet and fixed asset digests, every cycle forwards that exact selection, and the first valid cycle establishes a safe Runtime projection that all later and resumed cycles must match. Repository implementation and exact-head CI complete first; one Mac canary and a separate 60-cycle external run then supply the evidence for a final redacted report.

**Tech Stack:** Python 3.11+ standard library and `unittest`, existing CompatForge CLI/Rust workspace, Tauri/TypeScript desktop build, GitHub Actions, Apple Silicon macOS with CrossOver.

---

## Execution Rules

- Work only in `L:\project\FOS\.worktrees\compatforge-phase-2-3-m0-soak-freeze` on `agent/phase-2-3-m0-soak-freeze`.
- Use @superpowers:test-driven-development for Tasks 1-5 and @superpowers:verification-before-completion before every completion claim.
- Do not edit FOS, ForgeOS, ForgeTools, or Mac-Win.
- Do not add installers, archives, screenshots, Bottles, Runtime files, or raw soak evidence to Git.
- Do not mark M0 complete until Task 9 has real `60/60` and `300/300` evidence.
- A failed or unverified formal output root is terminal. Fix the cause and start a new empty root at cycle 1.

### Task 1: Close the Runtime selection and persisted configuration

**Files:**
- Modify: `tests/test_gui_baseline_contracts.py:4524-4625`
- Modify: `tools/run_gui_soak.py:1-205`

**Step 1: Add failing parser and selection tests**

Add a small fixture method near the current soak tests:

```python
def soak_runtime_selection(self, root: Path) -> dict[str, str]:
    return {
        "runtimeId": "crossover",
        "wineRoot": str(root / "CrossOver Runtime"),
        "wine": "Contents/SharedSupport/CrossOver/bin/wine",
        "wineserver": "Contents/SharedSupport/CrossOver/bin/wineserver",
        "version": "11.0-8726-g2e2f5fca349",
    }
```

Add `test_soak_runtime_selection_is_required_closed_and_unique`. Build the common required arguments, then assert:

```python
with self.assertRaises(SystemExit):
    self.soak_tool.parser().parse_args(common)

with self.assertRaises(SystemExit):
    self.soak_tool.parser().parse_args(common + ["--runtime-id", "unknown"])

with self.assertRaises(SystemExit):
    self.soak_tool.parser().parse_args(
        common
        + quartet
        + ["--version", "different"]
    )
```

Parse the valid command and assert `runtime_selection(arguments)` returns the exact five-field mapping above. Also construct an `argparse.Namespace` with one quartet field missing and assert `AcceptanceError`; this unit-level check keeps all-or-nothing semantics independently of `argparse`'s required-option messages.

**Step 2: Run the focused test and confirm red**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_runtime_selection_is_required_closed_and_unique -v
```

Expected: FAIL because the soak parser has no Runtime arguments and `runtime_selection` does not exist.

**Step 3: Implement the minimal closed selection**

In `tools/run_gui_soak.py`, import the existing contract rather than creating a second Runtime ID list:

```python
from run_gui_baseline import (
    AcceptanceError,
    RUNTIME_IDS,
    TEST_SUITE_VERSION,
    UniqueValueAction,
    absolute,
    utc_now,
    validate_runtime_selection,
)
```

Make the parser non-abbreviating and require each identity option exactly once:

```python
value = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
value.add_argument("--runtime-id", required=True, choices=RUNTIME_IDS, action=UniqueValueAction)
value.add_argument("--wine-root", required=True, action=UniqueValueAction)
value.add_argument("--wine", required=True, action=UniqueValueAction)
value.add_argument("--wineserver", required=True, action=UniqueValueAction)
value.add_argument("--version", required=True, action=UniqueValueAction)
```

Add a pure normalizer. The root is an absolute external path; the executable entrypoints remain the exact relative strings expected by the baseline bootstrap contract:

```python
def runtime_selection(arguments: argparse.Namespace) -> dict[str, str]:
    runtime_id = validate_runtime_selection(arguments)
    if runtime_id is None:
        raise AcceptanceError("the GUI soak requires an explicit Runtime quartet")
    root = absolute(arguments.wine_root, "wine-root", external=True)
    for field in ("wine", "wineserver"):
        value = getattr(arguments, field)
        path = Path(value)
        if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
            raise AcceptanceError(f"{field} must be a relative non-traversing Runtime entrypoint")
    return {
        "runtimeId": runtime_id,
        "wineRoot": str(root),
        "wine": arguments.wine,
        "wineserver": arguments.wineserver,
        "version": arguments.version,
    }
```

**Step 4: Add a failing exact-configuration test**

Replace the current `test_soak_resume_configuration_is_closed` setup with the Runtime fixture and assert the persisted JSON has exactly these top-level keys:

```python
{
    "schemaVersion",
    "testSuiteVersion",
    "applications",
    "assets",
    "cycles",
    "runtimeSelection",
}
```

Assert `assets` contains the selected app IDs and their current `sha256:<hex>` values. Validate the unchanged configuration, then independently change each of `runtimeId`, `wineRoot`, `wine`, `wineserver`, `version`, selected app set, and cycle count and assert `AcceptanceError`.

**Step 5: Run the configuration test and confirm red**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_resume_configuration_is_closed -v
```

Expected: FAIL because the current configuration omits Runtime selection and asset digests.

**Step 6: Persist the exact closed configuration**

Add a deterministic asset projection:

```python
def selected_assets(selected: set[str]) -> list[dict[str, str]]:
    projected = [
        {"appId": asset.app_id, "sha256": f"sha256:{asset.sha256}"}
        for asset in CERTIFICATION_ASSETS
        if asset.app_id in selected
    ]
    if {value["appId"] for value in projected} != selected:
        raise AcceptanceError("selected certification asset set is invalid")
    return sorted(projected, key=lambda value: value["appId"])
```

Change `write_configuration` and `validate_configuration` to accept the normalized Runtime mapping and compare one exact object:

```python
def configuration_value(
    selected: set[str], cycles: int, runtime: dict[str, str]
) -> dict[str, object]:
    return {
        "schemaVersion": "1",
        "testSuiteVersion": TEST_SUITE_VERSION,
        "applications": sorted(selected),
        "assets": selected_assets(selected),
        "cycles": cycles,
        "runtimeSelection": runtime,
    }
```

Use `configuration_value(...)` from both read and write paths so resume cannot drift through duplicated comparison logic.

**Step 7: Run the focused soak tests**

Run:

```text
python -S -B -m unittest \
  tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_runtime_selection_is_required_closed_and_unique \
  tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_resume_configuration_is_closed -v
```

Expected: 2 tests PASS.

**Step 8: Commit**

```text
git add tools/run_gui_soak.py tests/test_gui_baseline_contracts.py
git commit -m "feat: bind soak runtime selection"
```

### Task 2: Bind every cycle to one safe Runtime projection

**Files:**
- Modify: `tests/test_gui_baseline_contracts.py:4524-4625`
- Modify: `tools/run_gui_soak.py:60-145`

**Step 1: Add a failing Runtime projection test**

Add `test_soak_runtime_projection_is_closed_and_path_free`. Start from a one-app compatibility result and a full summary containing:

```python
"receipt": {
    "schemaVersion": "1",
    "runtimeId": "crossover",
    "packId": "macos-explicit",
    "version": runtime["version"],
    "packDigest": "sha256:" + "d" * 64,
    "source": "explicit-override",
},
```

Set `compatibilityResults[0]["host"]` to `{"os": "macos", "version": "15.6", "architecture": "arm64"}`. Assert classification contains exactly:

```python
{
    "runtimeId": "crossover",
    "version": "11.0-8726-g2e2f5fca349",
    "architecture": "arm64",
    "packDigest": "sha256:" + "d" * 64,
}
```

Serialize that projection and assert it contains neither `wineRoot` nor the external root string. Mutate Runtime ID, requested version, digest syntax, missing receipt, inconsistent host architecture across applications, and the receipt key set beyond the established optional `activated` field; each must raise `AcceptanceError`.

**Step 2: Run the test and confirm red**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_runtime_projection_is_closed_and_path_free -v
```

Expected: FAIL because `classify_summary` currently ignores the Runtime receipt.

**Step 3: Implement the safe projection**

Add `RUNTIME_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")` and:

```python
def runtime_projection(
    summary: dict[str, object], expected_runtime: dict[str, str]
) -> dict[str, str]:
    receipt = summary.get("receipt")
    if not isinstance(receipt, dict):
        raise AcceptanceError("cycle summary omitted the Runtime receipt")
    required = {"schemaVersion", "runtimeId", "packId", "version", "packDigest", "source"}
    if set(receipt) not in (required, required | {"activated"}):
        raise AcceptanceError("cycle Runtime receipt key set is invalid")
    if receipt["schemaVersion"] != "1":
        raise AcceptanceError("cycle Runtime receipt schema is unsupported")
    if receipt["runtimeId"] != expected_runtime["runtimeId"]:
        raise AcceptanceError("cycle Runtime identity differs from the request")
    if receipt["version"] != expected_runtime["version"]:
        raise AcceptanceError("cycle Runtime version differs from the request")
    digest = receipt["packDigest"]
    if not isinstance(digest, str) or RUNTIME_DIGEST.fullmatch(digest) is None:
        raise AcceptanceError("cycle Runtime Pack digest is invalid")
    if "activated" in receipt and not isinstance(receipt["activated"], bool):
        raise AcceptanceError("cycle Runtime activation state is invalid")
    raw_results = summary.get("compatibilityResults")
    if not isinstance(raw_results, list) or not raw_results:
        raise AcceptanceError("cycle compatibility result set is invalid")
    architectures = {
        result["host"]["architecture"]
        for result in raw_results
        if isinstance(result, dict)
        and isinstance(result.get("host"), dict)
        and result["host"].get("os") == "macos"
        and isinstance(result["host"].get("architecture"), str)
    }
    if len(architectures) != 1 or len(raw_results) == 0:
        raise AcceptanceError("cycle host architecture evidence is invalid")
    return {
        "runtimeId": expected_runtime["runtimeId"],
        "version": expected_runtime["version"],
        "architecture": architectures.pop(),
        "packDigest": digest,
    }
```

Validate that every member supplied the same macOS architecture; do not rely on the abbreviated comprehension alone. The projected `architecture` is the architecture of the Mac host that executed the bound receipt, because the established receipt schema does not expose a separate Runtime-binary architecture. Extend `classify_summary` to accept `expected_runtime` and optional `stable_runtime`, include the projection in its result, and reject a projection unequal to the stable value.

**Step 4: Add failing closed-classification cases**

Extend `test_soak_distinguishes_verified_lifecycle_from_acceptance_and_infrastructure` so all summaries include the receipt and Runtime mapping. Assert:

- `policy-blocked` plus all six passed checks is `verified` but not application `accepted`;
- `test-infrastructure` is always `unverified`, even if malformed evidence claims all six checks passed;
- `runtime-regression` or any failed lifecycle check is a hard failure;
- an unknown failure classification, unknown outcome, duplicate check, or missing soak check raises `AcceptanceError`.

**Step 5: Run the classification test and confirm red**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_distinguishes_verified_lifecycle_from_acceptance_and_infrastructure -v
```

Expected: FAIL on the newly closed classification cases.

**Step 6: Close classification minimally**

In `classify_summary`, accept only:

```python
SOAK_FAILURE_CLASSIFICATIONS = {None, "policy-blocked", "test-infrastructure", "runtime-regression"}
SOAK_OUTCOMES = {"passed", "blocked", "failed"}
```

Set `infrastructure_blocked` whenever classification is `test-infrastructure`. Set `hard_failure` for `runtime-regression` or any non-infrastructure lifecycle failure. Preserve the rule that a policy-blocked application is lifecycle-verified only when all six checks passed.

**Step 7: Run all four existing/new soak contract tests**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_runtime_projection_is_closed_and_path_free tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_distinguishes_verified_lifecycle_from_acceptance_and_infrastructure -v
```

Expected: all tests PASS.

**Step 8: Commit**

```text
git add tools/run_gui_soak.py tests/test_gui_baseline_contracts.py
git commit -m "feat: bind soak runtime receipts"
```

### Task 3: Preflight fixed assets and build one exact per-cycle command

**Files:**
- Modify: `tests/test_gui_baseline_contracts.py:4524-4660`
- Modify: `tools/run_gui_soak.py:1-45,226-330`

**Step 1: Add a failing offline asset preflight test**

Add `test_soak_offline_preflight_validates_every_selected_digest`. In a temporary cache, write fixture bytes for two synthetic assets or patch `fetch` and assert:

```python
with mock.patch.object(self.soak_tool, "fetch") as fetch:
    self.soak_tool.validate_cached_assets(cache_root, selected)
    self.assertEqual(fetch.call_count, len(selected))
    self.assertTrue(all(call.args[2] is False for call in fetch.call_args_list))
```

Make the patched `fetch` raise `AssetError("digest mismatch")` and assert the soak converts it to a stable `AcceptanceError` before any runner command can be invoked.

**Step 2: Run the test and confirm red**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_offline_preflight_validates_every_selected_digest -v
```

Expected: FAIL because `validate_cached_assets` does not exist.

**Step 3: Implement strictly offline preflight**

Import `AssetError` and `fetch` from `download_gui_assets`, then add:

```python
def validate_cached_assets(cache_root: Path, selected: set[str]) -> None:
    for asset in sorted(CERTIFICATION_ASSETS, key=lambda value: value.app_id):
        if asset.app_id not in selected:
            continue
        try:
            fetch(asset, cache_root, False)
        except AssetError as error:
            raise AcceptanceError(f"offline asset preflight failed for {asset.app_id}") from error
```

Call this once after configuration validation and before creating `runtime/`, starting `caffeinate`, or creating `runs/cycle-001`. The soak may retain its explicit `--allow-network` compatibility option for non-M0 use, but the M0 commands in Tasks 8-9 never pass it; preflight itself is always offline.

**Step 4: Add a failing exact command test**

Add `test_soak_cycle_command_forwards_the_exact_runtime_quartet`. Call a new pure `cycle_command(...)` helper and assert each of these options occurs exactly once with the requested value:

```text
--runtime-id crossover
--wine-root <exact external root>
--wine <exact relative entrypoint>
--wineserver <exact relative entrypoint>
--version 11.0-8726-g2e2f5fca349
```

Also assert applications are sorted, no `--allow-network` appears when false, and all cycle-local storage/work roots differ between two calls.

**Step 5: Run the command test and confirm red**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_cycle_command_forwards_the_exact_runtime_quartet -v
```

Expected: FAIL because command construction is embedded in `main` and does not forward Runtime options.

**Step 6: Extract and use the pure command builder**

Implement:

```python
def cycle_command(
    cli: Path,
    cache_root: Path,
    runtime_store: Path,
    storage_root: Path,
    work_root: Path,
    selected: set[str],
    runtime: dict[str, str],
    allow_network: bool,
) -> list[str]:
    command = [
        sys.executable, "-S", "-B", str(RUNNER),
        "--compatforge-cli", str(cli),
        "--cache-root", str(cache_root),
        "--runtime-store", str(runtime_store),
        "--storage-root", str(storage_root),
        "--work-root", str(work_root),
        "--runtime-id", runtime["runtimeId"],
        "--wine-root", runtime["wineRoot"],
        "--wine", runtime["wine"],
        "--wineserver", runtime["wineserver"],
        "--version", runtime["version"],
    ]
    if allow_network:
        command.append("--allow-network")
    for app_id in sorted(selected):
        command.extend(("--app", app_id))
    return command
```

Replace the inline list in `main` with this helper.

**Step 7: Run both focused tests**

Run:

```text
python -S -B -m unittest \
  tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_offline_preflight_validates_every_selected_digest \
  tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_cycle_command_forwards_the_exact_runtime_quartet -v
```

Expected: 2 tests PASS.

**Step 8: Commit**

```text
git add tools/run_gui_soak.py tests/test_gui_baseline_contracts.py
git commit -m "feat: preflight offline soak inputs"
```

### Task 4: Make resume, drift, and aggregate accounting fail closed

**Files:**
- Modify: `tests/test_gui_baseline_contracts.py:4584-4660`
- Modify: `tools/run_gui_soak.py:45-225,226-355`

**Step 1: Add failing verified-prefix tests**

Add `test_soak_resume_accepts_only_one_verified_runtime_prefix`. Construct two verified cycle entries with the exact selected applications and Runtime projection. Assert the helper returns that projection. Then mutate each case independently and assert `AcceptanceError`:

- non-contiguous cycle number;
- changed application set;
- status `failed` or `unverified`;
- missing Runtime projection;
- changed Runtime ID, version, architecture, or Pack digest in cycle 2.

The intended helper signature is:

```python
stable = self.soak_tool.validate_verified_prefix(entries, selected)
```

**Step 2: Run the prefix test and confirm red**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_resume_accepts_only_one_verified_runtime_prefix -v
```

Expected: FAIL because prefix identity is not currently validated.

**Step 3: Implement verified-prefix validation**

Add a closed validator that checks every entry schema, test-suite version, ordinal, selected applications, verified status, and exact Runtime projection. The first entry establishes `stable_runtime`; every later entry must equal it. Return `None` for an empty prefix and the stable projection otherwise.

Call it for every resume, including configurations newly created from legacy logs. Remove the legacy behavior that accepts records without Runtime identity; this M0 branch intentionally requires a new output root and must not upgrade old evidence in place.

**Step 4: Add failing Runtime-drift integration behavior**

Add `test_soak_runtime_drift_writes_a_terminal_failed_cycle`. Patch one cycle summary so its valid receipt differs from the verified prefix. Assert the root receives a second cycle record with:

```python
{
    "status": "failed",
    "hardFailure": True,
    "infrastructureBlocked": False,
    "reason": "cycle summary contract or Runtime identity is invalid",
}
```

Assert `summary.json.releaseGate == "failed"`, and a subsequent `--resume` is rejected. Do not copy exception text or a local path into the cycle record.

**Step 5: Run the drift test and confirm red**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_runtime_drift_writes_a_terminal_failed_cycle -v
```

Expected: FAIL because a classification exception currently exits without a terminal record.

**Step 6: Record a safe terminal failure**

Around summary decoding and classification, convert malformed/identity-drift evidence to one stable path-free projection:

```python
projection = {
    "status": "failed",
    "hardFailure": True,
    "infrastructureBlocked": False,
    "applications": [],
    "reason": "cycle summary contract or Runtime identity is invalid",
}
```

Keep missing `summary.json` as a distinct stable reason. Append and fsync the record, atomically update the aggregate report, and return 1. Never continue to a later cycle.

**Step 7: Add failing 60-by-5 accounting and path-redaction tests**

Extend `test_soak_report_records_fail_fast_reason` and add `test_soak_report_counts_300_verified_lifecycles`. For 60 synthetic verified entries, assert:

```python
report["requestedCycles"] == 60
report["completedCycles"] == 60
report["requestedApplicationExecutions"] == 300
report["completedApplicationExecutions"] == 300
report["verifiedApplicationExecutions"] == 300
report["cleanupFailures"] == 0
report["residualProcessFailures"] == 0
report["hardFailures"] == 0
report["infrastructureBlocked"] == 0
report["releaseGate"] == "passed"
```

Assert `report["runtime"]` is the four-field safe projection. Serialize it and assert none of the external Runtime, cache, output, storage, work, screenshot, or executable paths are present. Change one cleanup check and one residual-process check and assert the corresponding counters increment and `releaseGate` is not passed.

**Step 8: Run the report tests and confirm red**

Run:

```text
python -S -B -m unittest \
  tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_report_records_fail_fast_reason \
  tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_report_counts_300_verified_lifecycles -v
```

Expected: FAIL because the current report lacks application, cleanup, residual, and Runtime totals.

**Step 9: Implement aggregate accounting**

Change `write_report` to also receive `selected`. Count only structurally valid application records and use the already projected six checks. Gate `passed` only when:

```python
finished
and statuses == {"verified": requested_cycles}
and completed_application_executions == requested_cycles * len(selected)
and verified_application_executions == requested_cycles * len(selected)
and cleanup_failures == 0
and residual_process_failures == 0
and hard_failures == 0
and infrastructure_blocked == 0
and stable_runtime is not None
```

The JSON report must contain only counts, sorted application IDs, the four safe Runtime fields, stable reason codes/text, schema/test-suite identity, and booleans. It must not include `configuration.json` or any filesystem path.

**Step 10: Run all soak tests**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests -k soak -v
```

If Python's local `unittest` does not support `-k`, run each `test_soak_*` test by its full dotted name. Expected: all soak tests PASS.

**Step 11: Commit**

```text
git add tools/run_gui_soak.py tests/test_gui_baseline_contracts.py
git commit -m "feat: fail closed on soak identity drift"
```

### Task 5: Exercise `main` end to end without a real GUI

**Files:**
- Modify: `tests/test_gui_baseline_contracts.py:4524-4700`
- Modify: `tools/run_gui_soak.py:226-355`

**Step 1: Add a failing one-cycle orchestration test**

Add `test_soak_main_runs_one_offline_cycle_with_bound_runtime`. Use a temporary external root, patch `sys.argv`, `validate_cached_assets`, `start_power_assertion`, `utc_now`, and `subprocess.run`. The fake `subprocess.run` must inspect the command, create a valid path-free `work/summary.json` for all five selected applications, and return exit code 0.

Assert:

- `main()` returns 0;
- preflight was called once before `subprocess.run`;
- the exact Runtime quartet occurred once in the child command;
- `configuration.json` binds Runtime selection and all five asset digests;
- `cycles.jsonl` has one verified record and safe Runtime projection;
- `summary.json` says `1/1`, `5/5`, and `releaseGate=passed`;
- neither output JSON file contains the Runtime root or any cycle-local path.

**Step 2: Run the test and confirm red**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_main_runs_one_offline_cycle_with_bound_runtime -v
```

Expected: FAIL until all new helpers are wired into `main` in the correct order.

**Step 3: Wire the orchestration path**

In `main`:

1. parse and normalize Runtime selection;
2. validate CLI/cache/output paths and closed app set;
3. write or validate exact configuration;
4. load and validate the verified prefix;
5. run offline asset preflight;
6. create the reusable Runtime Store;
7. start the bounded power assertion;
8. build each child command from the pure helper;
9. classify against the requested and stable Runtime identities;
10. append/fsync the cycle record and atomically write the aggregate report;
11. stop immediately on any non-verified result.

Do not add new environment variables, fallback Runtime discovery, network fallback, or evidence-copy behavior.

**Step 4: Run the focused test and full contract module**

Run:

```text
python -S -B -m unittest tests.test_gui_baseline_contracts.GuiBaselineContractTests.test_soak_main_runs_one_offline_cycle_with_bound_runtime -v
python -S -B -m unittest tests.test_gui_baseline_contracts -v
```

Expected: focused test PASS; full module PASS with no regression to baseline, pinned execution, interaction acknowledgement, cleanup, or compact-summary contracts.

**Step 5: Check syntax and diff hygiene**

Run:

```text
python -S -B -m py_compile tools/run_gui_soak.py tests/test_gui_baseline_contracts.py
git diff --check
```

Expected: both commands exit 0 with no output from `git diff --check`.

**Step 6: Commit**

```text
git add tools/run_gui_soak.py tests/test_gui_baseline_contracts.py
git commit -m "test: cover bound soak orchestration"
```

### Task 6: Update operator docs without prematurely closing M0

**Files:**
- Modify: `docs/testing.md:175-189`
- Modify: `docs/implementation/phase-2-1-interactive-certification.md:32-38`
- Modify: `docs/reports/2026-08-21-macos-local-dual-runtime-acceptance.md:99-108`
- Modify: `docs/plans/2026-08-22-macos-pinned-bottle-execution-design.md:185-195`
- Modify: `docs/plans/2026-08-18-phase-2-3-cross-host-validation-design.md:3-9,198-207`
- Test: `scripts/validate_repository.py`

**Step 1: Update the soak command contract**

In `docs/testing.md`, replace the Runtime-discovering soak example with the exact explicit form:

```text
python3 -S -B tools/run_gui_soak.py \
  --compatforge-cli /absolute/external/build/compatforge-cli \
  --cache-root /absolute/external/cache \
  --output-root /absolute/external/soak-canary \
  --cycles 1 \
  --runtime-id crossover \
  --wine-root /absolute/external/runtime-root \
  --wine Contents/SharedSupport/CrossOver/bin/wine \
  --wineserver Contents/SharedSupport/CrossOver/bin/wineserver \
  --version fixed-discovered-version
```

Document that the formal command changes only output root and `--cycles 60`; it does not use `--allow-network`. State the `60/60`, `300/300`, zero failure/block/cleanup/residual, stable Runtime projection gate.

**Step 2: Update implementation semantics**

In `docs/implementation/phase-2-1-interactive-certification.md`, explain:

- the exact Runtime quartet is persisted and forwarded every cycle;
- `configuration.json` may contain local paths and stays external;
- `summary.json` is path-free;
- only a continuous verified prefix can resume;
- Runtime drift writes a terminal failed record;
- formal M0 asset validation is offline before cycle 1.

**Step 3: Add chronological history notes**

Append, without rewriting the historical findings:

- to `docs/reports/2026-08-21-macos-local-dual-runtime-acceptance.md`, a dated closure note recording merge commit `7c9561257fe21e0c9e077f3046c3b3785c1c30f2`, exact-head CI success, and that the next gate is M0;
- to `docs/plans/2026-08-22-macos-pinned-bottle-execution-design.md`, a dated resolution note that later local dual-Runtime acceptance produced the required Whisky GUI evidence, while the earlier failed checkpoint remains historically accurate;
- to `docs/plans/2026-08-18-phase-2-3-cross-host-validation-design.md`, change only the planning status to “M0 implementation/evidence rerun in progress.” Do not claim M0 passed.

**Step 4: Run repository and doc checks**

Run:

```text
python -S -B scripts/validate_repository.py
python -S -B -m unittest tests.test_macos_dual_runtime_acceptance -v
git diff --check
```

Expected: validator PASS, dual-Runtime contract suite PASS, diff check clean.

**Step 5: Commit**

```text
git add docs/testing.md docs/implementation/phase-2-1-interactive-certification.md docs/reports/2026-08-21-macos-local-dual-runtime-acceptance.md docs/plans/2026-08-22-macos-pinned-bottle-execution-design.md docs/plans/2026-08-18-phase-2-3-cross-host-validation-design.md
git commit -m "docs: prepare phase 2.3 M0 soak"
```

### Task 7: Verify and publish the implementation head before real-host execution

**Files:**
- Verify only; no source edits expected

**Step 1: Run all Python repository contracts**

Run:

```text
python -S -B scripts/validate_repository.py
python -S -B -m unittest tests.test_gui_baseline_contracts -v
python -S -B -m unittest tests.test_macos_headless_preview -v
python -S -B -m unittest tests.test_macos_dual_runtime_acceptance -v
python -S -B -m unittest tests.test_phase_2_3_contracts -v
python -S -B -m unittest tests.test_bottle_migration_contracts -v
```

Expected: every suite PASS, with only documented platform skips.

**Step 2: Run Rust workspace gates with an external target directory**

On PowerShell:

```text
$env:CARGO_TARGET_DIR='L:\project\FOS\.verification\cargo-m0-soak-freeze'
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: all commands exit 0.

**Step 3: Run desktop gates**

```text
npm ci --offline --prefix apps/desktop
npm run build --prefix apps/desktop
cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml -- --check
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --locked
cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets --locked -- -D warnings
```

Expected: all commands exit 0. The packaged `.app` build remains a macOS/CI gate if unavailable on Windows.

**Step 4: Verify the exact branch state**

```text
git diff --check
git status --short
git log -1 --format=%H
```

Expected: no diff errors, no uncommitted files, and one recorded implementation head SHA.

**Step 5: Push and open/update the CompatForge PR**

```text
git push -u origin agent/phase-2-3-m0-soak-freeze
gh pr create --base main --head agent/phase-2-3-m0-soak-freeze --title "Phase 2.3 M0 soak freeze" --body-file /absolute/external/m0-pr-body.md
```

Use an external temporary PR body that summarizes scope, test evidence, and the fact that the 60-cycle real-host gate is still pending. If a PR already exists, use `gh pr edit` rather than creating a duplicate.

**Step 6: Require exact-head GitHub Actions success**

```text
gh pr checks --watch
git log -1 --format=%H
```

Expected: all required CI jobs pass for the exact SHA printed in Step 4. Do not start the formal Mac run against a different commit.

### Task 8: Run the Apple Silicon one-cycle canary

**Files:**
- External Mac evidence only; no repository files

**Step 1: Sync the exact implementation head on the Mac**

Fetch the branch, check out the exact SHA from Task 7, and verify:

```text
git rev-parse HEAD
git status --short
uname -m
python3 -S -B -c 'import platform,sys; assert sys.version_info >= (3,11); assert platform.machine() == "arm64"'
```

Expected: SHA equals the CI-passed implementation head, worktree clean, host `arm64`.

**Step 2: Run local source/build gates on that head**

```text
python3 -S -B scripts/validate_repository.py
python3 -S -B -m unittest tests.test_gui_baseline_contracts -v
cargo fmt --all -- --check
cargo test --offline --workspace --all-targets --locked
npm ci --offline --prefix apps/desktop
npm run build --prefix apps/desktop
cargo build --offline --release --locked -p compatforge-cli
```

Expected: all commands pass. Keep build outputs outside Git.

**Step 3: Resolve and record the CrossOver descriptor**

```text
python3 -S -B tools/discover_macos_wine.py --all
```

Select one `crossover` candidate and record its absolute root, relative Wine entrypoint, relative wineserver entrypoint, and exact version in an external operator note. Do not infer or shorten these values.

**Step 4: Validate all five cached assets offline**

```text
python3 -S -B tools/download_gui_assets.py fetch 7zip-x86 --cache-root /absolute/external/cache
python3 -S -B tools/download_gui_assets.py fetch vlc --cache-root /absolute/external/cache
python3 -S -B tools/download_gui_assets.py fetch winmerge --cache-root /absolute/external/cache
python3 -S -B tools/download_gui_assets.py fetch audacity-x86 --cache-root /absolute/external/cache
python3 -S -B tools/download_gui_assets.py fetch everything-x86 --cache-root /absolute/external/cache
```

Expected: all five exit 0 without `--allow-network`.

**Step 5: Verify the interactive desktop**

Confirm the Mac is unlocked, the GUI session is foreground, screen capture is permitted, no sleep/lock policy will interrupt the bounded run, and no prior CompatForge/Wine test process is active. This is an operator precondition, not a repository claim.

**Step 6: Run one independent canary**

Use the exact values from Step 3:

```text
python3 -S -B tools/run_gui_soak.py \
  --compatforge-cli /absolute/external/build/compatforge-cli \
  --cache-root /absolute/external/cache \
  --output-root /absolute/external/m0-canary-001 \
  --cycles 1 \
  --runtime-id crossover \
  --wine-root /absolute/external/exact-crossover-root \
  --wine exact/relative/wine \
  --wineserver exact/relative/wineserver \
  --version exact-discovered-version
```

Expected: process exit 0; `requestedCycles=1`, `completedCycles=1`, `5/5` verified lifecycles, zero hard/infrastructure/cleanup/residual failures, `releaseGate=passed`.

**Step 7: Inspect canary evidence**

Check all five target-window screenshots are non-empty and correspond to the named application, every Bottle directory was deleted, no Bottle-scoped process remains, and `cycles.jsonl.runtime` equals `summary.json.runtime`. Confirm the Runtime projection is `crossover`, the requested version, `arm64`, and one fixed Pack digest. The canary does not count toward the 60-cycle formal gate.

If any check fails or is unverified, preserve the canary root, diagnose it under @superpowers:systematic-debugging, and do not start Task 9.

### Task 9: Run the formal 60 cycles and close M0 with redacted evidence

**Files:**
- Create after success: `docs/reports/2026-08-30-phase-2-3-m0-soak-freeze.md`
- Modify after success: `docs/plans/2026-08-18-phase-2-3-cross-host-validation-design.md:3-9,198-207`
- Modify after success: `docs/testing.md:175-189`

**Step 1: Create a new empty formal root**

Choose a new external path that has never held a canary or failed run. Verify it does not exist. Do not copy `configuration.json`, `cycles.jsonl`, Runtime Store, Bottle state, or work directories from the canary.

**Step 2: Start the offline 60-cycle run**

Run the same command as Task 8 with only these deliberate changes:

```text
--output-root /absolute/external/m0-formal-001
--cycles 60
```

Do not pass `--allow-network`, do not change the Runtime quartet, and do not add or remove applications.

**Step 3: Apply exact interruption semantics**

For a clean process interruption only, resume with the identical full command plus `--resume`. Resume is valid only when the existing log is a continuous verified prefix. If any committed cycle is failed/unverified or any Runtime/configuration field differs, preserve that root as terminal and restart from cycle 1 in a new empty root after fixing the cause.

**Step 4: Validate the raw completion gate**

Require `summary.json` to state exactly:

```json
{
  "requestedCycles": 60,
  "completedCycles": 60,
  "requestedApplicationExecutions": 300,
  "completedApplicationExecutions": 300,
  "verifiedApplicationExecutions": 300,
  "hardFailures": 0,
  "infrastructureBlocked": 0,
  "cleanupFailures": 0,
  "residualProcessFailures": 0,
  "finished": true,
  "stoppedEarly": false,
  "releaseGate": "passed"
}
```

Also require 60 contiguous JSONL records, each with five applications, all six lifecycle checks passed, and one identical safe Runtime projection. Independently inspect the external `runs/` roots for expected screenshots/logs and absence of Bottle/residual leakage.

**Step 5: Write the redacted report only after Step 4 passes**

Create `docs/reports/2026-08-30-phase-2-3-m0-soak-freeze.md` containing:

- execution date and exact source commit from Task 7;
- Host OS version and `arm64` architecture;
- path-free Runtime ID, version, Pack digest, and source identity;
- the five application IDs and fixed asset digests;
- exact `60/60`, `300/300`, and zero failure/block/cleanup/residual totals;
- canary outcome, formal start/end timestamps, interruption/resume count;
- repository/local/CI verification evidence;
- the external-evidence retention rule without any local path;
- closed non-claims: no public beta/release/signing/notarization/DMG, no Whisky 60-cycle claim, no Linux/MSI/.NET/WPF/D3D claim.

Do not include usernames, volume names, absolute paths, screenshot paths, executable paths, Bottle IDs, raw logs, or acknowledgement material.

**Step 6: Mark M0 complete and name the next checkpoint**

Only now update the Phase 2.3 design status to record M0 passed with a link to the redacted report. In `docs/testing.md`, link the report from the soak section. State that the next design checkpoint is the real x86_64 Win32 capability probe on macOS; do not start that probe in this task.

**Step 7: Validate the report and repository**

Run on the Mac and again on the integration host:

```text
python3 -S -B scripts/validate_repository.py
python3 -S -B -m unittest tests.test_gui_baseline_contracts -v
python3 -S -B -m unittest tests.test_macos_dual_runtime_acceptance -v
cargo fmt --all -- --check
cargo test --offline --workspace --all-targets --locked
cargo clippy --offline --workspace --all-targets --locked -- -D warnings
npm ci --offline --prefix apps/desktop
npm run build --prefix apps/desktop
git diff --check
git status --short
```

Expected: every gate passes and only the intended report/status docs are uncommitted before the next step.

**Step 8: Commit the evidence closure**

```text
git add docs/reports/2026-08-30-phase-2-3-m0-soak-freeze.md docs/plans/2026-08-18-phase-2-3-cross-host-validation-design.md docs/testing.md
git commit -m "docs: close phase 2.3 M0 soak"
```

**Step 9: Push and require exact report-head CI**

```text
git push
gh pr checks --watch
git log -1 --format=%H
git status --short
```

Expected: all required GitHub Actions pass for the exact report-head SHA and the branch is clean.

**Step 10: Review, merge, and clean up**

Use @superpowers:requesting-code-review before merge and @superpowers:finishing-a-development-branch after all review findings are resolved. Merge only the CompatForge PR, fast-forward local `main`, verify it matches `origin/main`, then remove this worktree and its external verification build cache by exact validated path. Preserve the external raw Mac evidence according to the operator retention policy; do not delete it as part of Git cleanup.
