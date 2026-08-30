#!/usr/bin/env python3
"""Run a resumable fresh-Bottle GUI lifecycle soak outside the repository."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import uuid
from collections import Counter
from pathlib import Path

from download_gui_assets import AssetError, CERTIFICATION_ASSETS, fetch
from run_gui_baseline import (
    AcceptanceError,
    RUNTIME_IDS,
    TEST_SUITE_VERSION,
    UniqueValueAction,
    absolute,
    utc_now,
    validate_runtime_selection,
)

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools" / "run_gui_baseline.py"
SOAK_CHECKS = {
    "installer-inspection",
    "window-visible",
    "screenshot",
    "lifecycle-exit",
    "bottle-cleanup",
    "no-residual-processes",
}
SOAK_FAILURE_CLASSIFICATIONS = {
    None,
    "policy-blocked",
    "test-infrastructure",
    "runtime-regression",
}
SOAK_OUTCOMES = {"passed", "blocked", "failed"}
SOAK_ARCHITECTURES = {"arm64", "x86_64"}
MAX_CYCLES = 1000
MAX_LOG_BYTES = 16 * 1024 * 1024
RUNTIME_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
RUNTIME_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+() -]*")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    value.add_argument("--compatforge-cli", required=True)
    value.add_argument("--cache-root", required=True)
    value.add_argument("--output-root", required=True)
    value.add_argument(
        "--runtime-id",
        required=True,
        choices=RUNTIME_IDS,
        action=UniqueValueAction,
    )
    value.add_argument("--wine-root", required=True, action=UniqueValueAction)
    value.add_argument("--wine", required=True, action=UniqueValueAction)
    value.add_argument("--wineserver", required=True, action=UniqueValueAction)
    value.add_argument("--version", required=True, action=UniqueValueAction)
    value.add_argument("--cycles", type=int, default=60)
    value.add_argument("--app", action="append", dest="applications")
    value.add_argument("--allow-network", action="store_true")
    value.add_argument("--resume", action="store_true")
    return value


def runtime_selection(arguments: argparse.Namespace) -> dict[str, str]:
    runtime_id = validate_runtime_selection(arguments)
    if runtime_id is None:
        raise AcceptanceError("runtime-id is required")
    wine_root = absolute(arguments.wine_root, "wine-root", external=True)

    entrypoints: dict[str, str] = {}
    for field in ("wine", "wineserver"):
        entrypoint = getattr(arguments, field)
        if (
            not isinstance(entrypoint, str)
            or not entrypoint
            or entrypoint.startswith(("/", "\\"))
            or "\\" in entrypoint
            or ":" in entrypoint
            or any(component in ("", ".", "..") for component in entrypoint.split("/"))
        ):
            raise AcceptanceError(f"{field} must be a portable relative path")
        entrypoints[field] = entrypoint

    return {
        "runtimeId": runtime_id,
        "wineRoot": str(wine_root),
        "wine": entrypoints["wine"],
        "wineserver": entrypoints["wineserver"],
        "version": arguments.version,
    }


def load_cycle_log(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_LOG_BYTES:
        raise AcceptanceError("cycles.jsonl must be a bounded regular file")
    entries: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise AcceptanceError("cycles.jsonl contains invalid JSON") from error
        if not isinstance(value, dict) or value.get("schemaVersion") != "1":
            raise AcceptanceError("cycles.jsonl contains an invalid cycle record")
        if value.get("cycle") != len(entries) + 1:
            raise AcceptanceError("cycles.jsonl cycle sequence is not contiguous")
        entries.append(value)
    return entries


def _runtime_version(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or RUNTIME_VERSION.fullmatch(value) is None
    ):
        raise AcceptanceError("cycle Runtime version is invalid")
    return value


def runtime_projection(
    summary: dict[str, object],
    expected_runtime: dict[str, str],
) -> dict[str, str]:
    expected_version = _runtime_version(expected_runtime.get("version"))
    receipt = summary.get("receipt")
    required_receipt = {
        "schemaVersion",
        "runtimeId",
        "packId",
        "version",
        "packDigest",
        "source",
    }
    if (
        not isinstance(receipt, dict)
        or not required_receipt.issubset(receipt)
        or not set(receipt).issubset(required_receipt | {"activated"})
        or receipt.get("schemaVersion") != "1"
        or receipt.get("runtimeId") != expected_runtime["runtimeId"]
        or not isinstance(receipt.get("packId"), str)
        or not receipt["packId"]
        or not isinstance(receipt.get("source"), str)
        or not receipt["source"]
        or not isinstance(receipt.get("packDigest"), str)
        or RUNTIME_DIGEST.fullmatch(receipt["packDigest"]) is None
        or ("activated" in receipt and type(receipt["activated"]) is not bool)
    ):
        raise AcceptanceError("cycle summary contains an invalid runtime receipt")
    receipt_version = _runtime_version(receipt["version"])
    if receipt_version != expected_version:
        raise AcceptanceError("cycle summary contains an invalid runtime receipt")

    raw_results = summary.get("compatibilityResults")
    if not isinstance(raw_results, list) or not raw_results:
        raise AcceptanceError("cycle summary omitted compatibility host evidence")
    receipt_digest = receipt["packDigest"]
    architecture: str | None = None
    for raw in raw_results:
        if not isinstance(raw, dict):
            raise AcceptanceError("cycle compatibility result is not an object")
        result_digest = raw.get("runtimePackDigest")
        if not isinstance(result_digest, str) or RUNTIME_DIGEST.fullmatch(result_digest) is None:
            raise AcceptanceError("cycle compatibility result has an invalid Runtime digest")
        if result_digest != receipt_digest:
            raise AcceptanceError("cycle compatibility result Runtime digest differs from receipt")
        host = raw.get("host")
        if not isinstance(host, dict) or host.get("os") != "macos":
            raise AcceptanceError("cycle compatibility result has invalid host evidence")
        host_version = host.get("version")
        if not isinstance(host_version, str) or not host_version:
            raise AcceptanceError("cycle compatibility result has invalid host version")
        current_architecture = host.get("architecture")
        if (
            not isinstance(current_architecture, str)
            or current_architecture not in SOAK_ARCHITECTURES
        ):
            raise AcceptanceError("cycle compatibility result has invalid host architecture")
        if architecture is None:
            architecture = current_architecture
        elif current_architecture != architecture:
            raise AcceptanceError("cycle compatibility results have inconsistent host architecture")

    if architecture is None:
        raise AcceptanceError("cycle summary omitted compatibility host evidence")
    return {
        "runtimeId": expected_runtime["runtimeId"],
        "version": expected_version,
        "architecture": architecture,
        "packDigest": receipt_digest,
    }


def classify_summary(
    summary: dict[str, object],
    expected_apps: set[str],
    expected_runtime: dict[str, str],
    stable_runtime: dict[str, str] | None = None,
) -> dict[str, object]:
    if summary.get("schemaVersion") != "1" or summary.get("testSuiteVersion") != TEST_SUITE_VERSION:
        raise AcceptanceError("cycle summary uses an unsupported contract")
    runtime = runtime_projection(summary, expected_runtime)
    if stable_runtime is not None and runtime != stable_runtime:
        raise AcceptanceError("cycle summary runtime changed during soak")
    raw_results = summary.get("compatibilityResults")
    if not isinstance(raw_results, list) or len(raw_results) != len(expected_apps):
        raise AcceptanceError("cycle summary does not contain the selected application set")
    applications: list[dict[str, object]] = []
    seen: set[str] = set()
    infrastructure_blocked = False
    hard_failure = False
    for raw in raw_results:
        if not isinstance(raw, dict):
            raise AcceptanceError("cycle compatibility result is not an object")
        recipe_id = raw.get("recipeId")
        if not isinstance(recipe_id, str) or recipe_id not in expected_apps or recipe_id in seen:
            raise AcceptanceError("cycle compatibility result has an invalid recipeId")
        seen.add(recipe_id)
        checks = raw.get("checks")
        if not isinstance(checks, list):
            raise AcceptanceError("cycle compatibility result omitted checks")
        projected: dict[str, str] = {}
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("id"), str):
                raise AcceptanceError("cycle compatibility check is invalid")
            check_id = str(check["id"])
            if check_id in projected:
                raise AcceptanceError("cycle compatibility result contains a duplicate check")
            outcome = check.get("outcome")
            if outcome not in {"passed", "failed", "blocked", "skipped"}:
                raise AcceptanceError("cycle compatibility check has an invalid outcome")
            projected[check_id] = str(outcome)
        if not SOAK_CHECKS.issubset(projected):
            raise AcceptanceError("cycle compatibility result omitted a soak check")
        outcome = raw.get("outcome")
        if not isinstance(outcome, str) or outcome not in SOAK_OUTCOMES:
            raise AcceptanceError("cycle compatibility result has an invalid outcome")
        classification_present = "failureClassification" in raw
        classification = raw.get("failureClassification")
        if outcome == "passed":
            if classification_present:
                raise AcceptanceError(
                    "passed cycle compatibility result has a failure classification"
                )
        elif (
            not classification_present
            or not isinstance(classification, str)
            or classification not in SOAK_FAILURE_CLASSIFICATIONS
        ):
            raise AcceptanceError(
                "non-passing cycle compatibility result requires a failure classification"
            )
        lifecycle_passed = all(projected[name] == "passed" for name in SOAK_CHECKS)
        if classification == "test-infrastructure":
            infrastructure_blocked = True
        if (
            outcome == "failed"
            or classification == "runtime-regression"
            or (classification != "test-infrastructure" and not lifecycle_passed)
        ):
            hard_failure = True
        applications.append(
            {
                "recipeId": recipe_id,
                "outcome": outcome,
                **({"failureClassification": classification} if classification_present else {}),
                "lifecyclePassed": lifecycle_passed,
                "checks": {name: projected[name] for name in sorted(SOAK_CHECKS)},
            }
        )
    if seen != expected_apps:
        raise AcceptanceError("cycle compatibility result set is incomplete")
    status = "failed" if hard_failure else ("unverified" if infrastructure_blocked else "verified")
    return {
        "status": status,
        "hardFailure": hard_failure,
        "infrastructureBlocked": infrastructure_blocked,
        "runtime": runtime,
        "applications": applications,
    }


def write_report(
    path: Path,
    entries: list[dict[str, object]],
    requested_cycles: int,
    stop_reason: str | None = None,
) -> dict[str, object]:
    statuses = Counter(str(entry.get("status")) for entry in entries)
    report = {
        "schemaVersion": "1",
        "testSuiteVersion": TEST_SUITE_VERSION,
        "requestedCycles": requested_cycles,
        "completedCycles": len(entries),
        "statuses": dict(sorted(statuses.items())),
        "hardFailures": sum(entry.get("hardFailure") is True for entry in entries),
        "infrastructureBlocked": sum(entry.get("infrastructureBlocked") is True for entry in entries),
        "finished": len(entries) == requested_cycles,
        "stoppedEarly": stop_reason is not None,
        **({"stopReason": stop_reason} if stop_reason is not None else {}),
        "releaseGate": (
            "failed"
            if any(entry.get("hardFailure") is True for entry in entries)
            else (
                "blocked"
                if len(entries) != requested_cycles
                or any(entry.get("status") != "verified" for entry in entries)
                else "passed"
            )
        ),
    }
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    return report


def cycle_application_ids(entry: dict[str, object]) -> set[str]:
    applications = entry.get("applications")
    if not isinstance(applications, list):
        raise AcceptanceError("cycle record omitted applications")
    result = {
        str(application["recipeId"])
        for application in applications
        if isinstance(application, dict) and isinstance(application.get("recipeId"), str)
    }
    if len(result) != len(applications):
        raise AcceptanceError("cycle record application set is invalid")
    return result


def selected_assets(selected: set[str]) -> list[dict[str, str]]:
    projected = [
        {"appId": asset.app_id, "sha256": f"sha256:{asset.sha256}"}
        for asset in CERTIFICATION_ASSETS
        if asset.app_id in selected
    ]
    if {value["appId"] for value in projected} != selected:
        raise AcceptanceError("selected certification asset set is invalid")
    return sorted(projected, key=lambda value: value["appId"])


def validate_cached_assets(cache_root: Path, selected: set[str]) -> None:
    selected_assets(selected)
    for asset in sorted(CERTIFICATION_ASSETS, key=lambda value: value.app_id):
        if asset.app_id not in selected:
            continue
        try:
            fetch(asset, cache_root, False)
        except AssetError as error:
            raise AcceptanceError(
                f"offline asset preflight failed for {asset.app_id}"
            ) from error


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
        sys.executable,
        "-S",
        "-B",
        str(RUNNER),
        "--compatforge-cli",
        str(cli),
        "--cache-root",
        str(cache_root),
        "--runtime-store",
        str(runtime_store),
        "--storage-root",
        str(storage_root),
        "--work-root",
        str(work_root),
        "--runtime-id",
        runtime["runtimeId"],
        "--wine-root",
        runtime["wineRoot"],
        "--wine",
        runtime["wine"],
        "--wineserver",
        runtime["wineserver"],
        "--version",
        runtime["version"],
    ]
    if allow_network:
        command.append("--allow-network")
    for app_id in sorted(selected):
        command.extend(("--app", app_id))
    return command


def configuration_value(
    selected: set[str],
    cycles: int,
    runtime: dict[str, str],
) -> dict[str, object]:
    return {
        "schemaVersion": "1",
        "testSuiteVersion": TEST_SUITE_VERSION,
        "applications": sorted(selected),
        "assets": selected_assets(selected),
        "cycles": cycles,
        "runtimeSelection": runtime,
    }


def write_configuration(
    path: Path,
    selected: set[str],
    cycles: int,
    runtime: dict[str, str],
) -> None:
    value = configuration_value(selected, cycles, runtime)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def validate_configuration(
    path: Path,
    selected: set[str],
    cycles: int,
    runtime: dict[str, str],
) -> None:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024:
        raise AcceptanceError("configuration.json must be a bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AcceptanceError("configuration.json is unreadable") from error
    if (
        not isinstance(value, dict)
        or type(value.get("cycles")) is not int
        or value != configuration_value(selected, cycles, runtime)
    ):
        raise AcceptanceError("resume configuration does not match the requested soak")


def start_power_assertion() -> subprocess.Popen[bytes] | None:
    """Keep the interactive display awake only for this bounded soak process."""
    if platform.system() != "Darwin":
        return None
    try:
        return subprocess.Popen(
            ["/usr/bin/caffeinate", "-d", "-i", "-w", str(os.getpid())],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={},
            start_new_session=True,
        )
    except OSError as error:
        raise AcceptanceError("caffeinate is unavailable for the GUI soak") from error


def stop_power_assertion(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    power_assertion: subprocess.Popen[bytes] | None = None
    try:
        arguments = parser().parse_args()
        runtime = runtime_selection(arguments)
        if not 1 <= arguments.cycles <= MAX_CYCLES:
            raise AcceptanceError("cycles must be in the range 1..1000")
        cli = absolute(arguments.compatforge_cli, "compatforge-cli")
        cache_root = absolute(arguments.cache_root, "cache-root", external=True)
        output_root = absolute(arguments.output_root, "output-root", external=True)
        if output_root.exists() and (not output_root.is_dir() or output_root.is_symlink()):
            raise AcceptanceError("output-root must be a real directory")
        output_root.mkdir(parents=True, exist_ok=True)
        known = {asset.app_id for asset in CERTIFICATION_ASSETS}
        selected = set(arguments.applications or known)
        unknown = selected - known
        if unknown:
            raise AcceptanceError(f"unknown certification application: {sorted(unknown)[0]}")
        cycles_path = output_root / "cycles.jsonl"
        report_path = output_root / "summary.json"
        configuration_path = output_root / "configuration.json"
        entries = load_cycle_log(cycles_path) if arguments.resume else []
        if not arguments.resume and any(output_root.iterdir()):
            raise AcceptanceError("output-root must be empty unless --resume is used")
        if arguments.resume:
            if configuration_path.exists():
                validate_configuration(
                    configuration_path,
                    selected,
                    arguments.cycles,
                    runtime,
                )
            else:
                if any(cycle_application_ids(entry) != selected for entry in entries):
                    raise AcceptanceError("legacy cycle records do not match the requested application set")
                write_configuration(
                    configuration_path,
                    selected,
                    arguments.cycles,
                    runtime,
                )
        else:
            write_configuration(
                configuration_path,
                selected,
                arguments.cycles,
                runtime,
            )
        validate_cached_assets(cache_root, selected)
        if len(entries) > arguments.cycles:
            raise AcceptanceError("cycles.jsonl already exceeds the requested cycle count")
        if arguments.resume and any(entry.get("status") != "verified" for entry in entries):
            raise AcceptanceError("cannot resume a soak containing a non-verified cycle; use a new output-root")
        runtime_root = output_root / "runtime"
        runtime_root.mkdir(exist_ok=True)
        if runtime_root.is_symlink():
            raise AcceptanceError("runtime directory must not be a symbolic link")
        power_assertion = start_power_assertion()
        for cycle in range(len(entries) + 1, arguments.cycles + 1):
            cycle_root = output_root / "runs" / f"cycle-{cycle:03d}"
            if cycle_root.exists() or cycle_root.is_symlink():
                aborted_root = output_root / "aborted"
                aborted_root.mkdir(exist_ok=True)
                os.replace(cycle_root, aborted_root / f"cycle-{cycle:03d}-{uuid.uuid4()}")
            work_root = cycle_root / "work"
            storage_root = cycle_root / "storage"
            work_root.mkdir(parents=True)
            storage_root.mkdir(parents=True)
            stdout_path = cycle_root / "runner.stdout"
            stderr_path = cycle_root / "runner.stderr"
            started_at = utc_now()
            command = cycle_command(
                cli,
                cache_root,
                runtime_root,
                storage_root,
                work_root,
                selected,
                runtime,
                arguments.allow_network,
            )
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                completed = subprocess.run(command, cwd=ROOT, stdout=stdout, stderr=stderr, check=False)
            summary_path = work_root / "summary.json"
            if not summary_path.is_file() or summary_path.is_symlink():
                projection: dict[str, object] = {
                    "status": "failed",
                    "hardFailure": True,
                    "infrastructureBlocked": False,
                    "applications": [],
                    "reason": "GUI runner did not produce summary.json",
                }
            else:
                try:
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    raise AcceptanceError("GUI runner produced unreadable summary.json") from error
                if not isinstance(summary, dict):
                    raise AcceptanceError("GUI runner summary is not an object")
                projection = classify_summary(summary, selected)
            entry = {
                "schemaVersion": "1",
                "testSuiteVersion": TEST_SUITE_VERSION,
                "cycle": cycle,
                "startedAt": started_at,
                "finishedAt": utc_now(),
                "runnerExitCode": completed.returncode,
                **projection,
            }
            with cycles_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
                log.flush()
                os.fsync(log.fileno())
            entries.append(entry)
            stop_reason = None
            if entry["status"] != "verified":
                stop_reason = f"cycle {cycle} completed with status {entry['status']}"
            report = write_report(report_path, entries, arguments.cycles, stop_reason)
            print(
                json.dumps(
                    {
                        "cycle": cycle,
                        "status": entry["status"],
                        "hardFailure": entry["hardFailure"],
                        "releaseGate": report["releaseGate"],
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                flush=True,
            )
            if stop_reason is not None:
                print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")), flush=True)
                return 1
        report = write_report(report_path, entries, arguments.cycles)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")), flush=True)
        return 0 if report["releaseGate"] == "passed" else 1
    except (AcceptanceError, OSError, ValueError) as error:
        print(f"compatforge-gui-soak: {error}", file=sys.stderr)
        return 2
    finally:
        stop_power_assertion(power_assertion)


if __name__ == "__main__":
    raise SystemExit(main())
