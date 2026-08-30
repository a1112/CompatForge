#!/usr/bin/env python3
"""Run a resumable fresh-Bottle GUI lifecycle soak outside the repository."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
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
SOAK_CHECK_OUTCOMES = {"passed", "failed", "blocked", "skipped"}
SOAK_ARCHITECTURES = {"arm64", "x86_64"}
MAX_CYCLES = 1000
MAX_LOG_BYTES = 16 * 1024 * 1024
MAX_CONFIGURATION_BYTES = 64 * 1024
MAX_SUMMARY_BYTES = 16 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 100_000
MAX_JSON_STRING_CHARS = 64 * 1024
MAX_JSON_TEXT_CHARS = 8 * 1024 * 1024
RUNTIME_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
RUNTIME_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+() -]*")
SOAK_STOP_REASON = re.compile(
    r"cycle [1-9][0-9]* completed with status (?:verified|unverified|failed)"
)
SOAK_TIMESTAMP = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z"
)
SOAK_TERMINAL_REASONS = {
    "GUI runner did not produce summary.json",
    "cycle summary contract or Runtime identity is invalid",
}
SOAK_CYCLE_COMMON_FIELDS = {
    "schemaVersion",
    "testSuiteVersion",
    "cycle",
    "startedAt",
    "finishedAt",
    "runnerExitCode",
    "status",
    "hardFailure",
    "infrastructureBlocked",
    "applications",
}
SOAK_APPLICATION_FIELDS = {
    "recipeId",
    "outcome",
    "lifecyclePassed",
    "checks",
}


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
    version = _runtime_version(arguments.version)
    wine_root = absolute(arguments.wine_root, "wine-root", external=True)

    entrypoints: dict[str, str] = {}
    for field in ("wine", "wineserver"):
        entrypoint = getattr(arguments, field)
        if (
            not isinstance(entrypoint, str)
            or not entrypoint
            or entrypoint.startswith(("-", "/", "\\"))
            or not entrypoint.isprintable()
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
        "version": version,
    }


def _reject_json_constant(_: str) -> object:
    raise ValueError("non-finite JSON constant")


def _closed_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _validate_bounded_json_structure(value: object) -> None:
    nodes = 0
    text_chars = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("JSON structure exceeds its bound")
        if isinstance(current, dict):
            for key, item in current.items():
                if (
                    not isinstance(key, str)
                    or not key
                    or len(key) > MAX_JSON_STRING_CHARS
                    or any(ord(character) < 32 or ord(character) == 127 for character in key)
                ):
                    raise ValueError("JSON object key is invalid")
                key.encode("utf-8")
                nodes += 1
                text_chars += len(key)
                if nodes > MAX_JSON_NODES or text_chars > MAX_JSON_TEXT_CHARS:
                    raise ValueError("JSON structure exceeds its bound")
                stack.append((item, depth + 1))
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            text_chars += len(current)
            current.encode("utf-8")
            if (
                len(current) > MAX_JSON_STRING_CHARS
                or any(
                    ord(character) < 32 or ord(character) == 127
                    for character in current
                )
                or text_chars > MAX_JSON_TEXT_CHARS
            ):
                raise ValueError("JSON text is invalid or exceeds its bound")
        elif current is None or type(current) in (bool, int):
            continue
        else:
            raise ValueError("JSON value type is unsupported")


def _parse_strict_json(text: str, label: str) -> object:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_closed_json_object,
            parse_constant=_reject_json_constant,
        )
        _validate_bounded_json_structure(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        raise AcceptanceError(f"{label} contains invalid JSON") from error


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
    )


def _file_snapshot(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        *_file_identity(metadata),
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _safe_regular_metadata(metadata: os.stat_result, maximum_bytes: int) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and not _is_reparse_point(metadata)
        and 0 <= metadata.st_size <= maximum_bytes
    )


def _read_bounded_regular_file(
    path: Path,
    label: str,
    maximum_bytes: int,
) -> bytes:
    error_message = f"{label} must be a bounded regular file"
    try:
        before = path.lstat()
        if not _safe_regular_metadata(before, maximum_bytes):
            raise AcceptanceError(error_message)
        flags = os.O_RDONLY
        for name in ("O_NOFOLLOW", "O_CLOEXEC", "O_BINARY"):
            flags |= getattr(os, name, 0)
        descriptor = os.open(path, flags)
    except AcceptanceError:
        raise
    except OSError as error:
        raise AcceptanceError(error_message) from error

    try:
        opened = os.fstat(descriptor)
        if (
            not _safe_regular_metadata(opened, maximum_bytes)
            or _file_snapshot(opened) != _file_snapshot(before)
        ):
            raise AcceptanceError(error_message)
        chunks: list[bytes] = []
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > maximum_bytes:
            raise AcceptanceError(error_message)
        after_open = os.fstat(descriptor)
        after_path = path.lstat()
        if (
            not _safe_regular_metadata(after_open, maximum_bytes)
            or not _safe_regular_metadata(after_path, maximum_bytes)
            or _file_snapshot(after_open) != _file_snapshot(opened)
            or _file_snapshot(after_path) != _file_snapshot(opened)
            or after_open.st_size != total
        ):
            raise AcceptanceError(error_message)
        return b"".join(chunks)
    except AcceptanceError:
        raise
    except OSError as error:
        raise AcceptanceError(error_message) from error
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _read_strict_json_file(
    path: Path,
    label: str,
    maximum_bytes: int,
) -> object:
    data = _read_bounded_regular_file(path, label, maximum_bytes)
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise AcceptanceError(f"{label} contains invalid JSON") from error
    return _parse_strict_json(text, label)


def load_cycle_log(path: Path) -> list[dict[str, object]]:
    try:
        path.lstat()
    except FileNotFoundError:
        return []
    except OSError as error:
        raise AcceptanceError("cycles.jsonl must be a bounded regular file") from error
    data = _read_bounded_regular_file(path, "cycles.jsonl", MAX_LOG_BYTES)
    try:
        lines = data.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as error:
        raise AcceptanceError("cycles.jsonl contains invalid JSON") from error
    entries: list[dict[str, object]] = []
    for line in lines:
        value = _parse_strict_json(line, "cycles.jsonl")
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


def safe_runtime_projection(value: object) -> dict[str, str]:
    if (
        not isinstance(value, dict)
        or set(value) != {"runtimeId", "version", "architecture", "packDigest"}
        or not isinstance(value.get("runtimeId"), str)
        or value["runtimeId"] not in RUNTIME_IDS
        or not isinstance(value.get("architecture"), str)
        or value["architecture"] not in SOAK_ARCHITECTURES
        or not isinstance(value.get("packDigest"), str)
        or RUNTIME_DIGEST.fullmatch(value["packDigest"]) is None
    ):
        raise AcceptanceError("cycle Runtime projection is invalid")
    return {
        "runtimeId": value["runtimeId"],
        "version": _runtime_version(value.get("version")),
        "architecture": value["architecture"],
        "packDigest": value["packDigest"],
    }


def _project_application(
    application: object,
    selected: set[str],
) -> dict[str, object]:
    if not isinstance(application, dict):
        raise AcceptanceError("cycle contains an invalid projected application")
    outcome = application.get("outcome")
    expected_fields = set(SOAK_APPLICATION_FIELDS)
    if outcome != "passed":
        expected_fields.add("failureClassification")
    if set(application) != expected_fields:
        raise AcceptanceError("cycle contains an invalid projected application")
    recipe_id = application.get("recipeId")
    lifecycle_passed = application.get("lifecyclePassed")
    checks = application.get("checks")
    if (
        not isinstance(recipe_id, str)
        or recipe_id not in selected
        or not isinstance(outcome, str)
        or outcome not in SOAK_OUTCOMES
        or type(lifecycle_passed) is not bool
        or not isinstance(checks, dict)
        or set(checks) != SOAK_CHECKS
        or any(
            not isinstance(checks[check_id], str)
            or checks[check_id] not in SOAK_CHECK_OUTCOMES
            for check_id in SOAK_CHECKS
        )
    ):
        raise AcceptanceError("cycle contains an invalid projected application")
    classification = application.get("failureClassification")
    if outcome == "passed":
        if "failureClassification" in application:
            raise AcceptanceError("cycle contains an invalid projected application")
    elif (
        not isinstance(classification, str)
        or classification not in SOAK_FAILURE_CLASSIFICATIONS
    ):
        raise AcceptanceError("cycle contains an invalid projected application")

    derived_lifecycle = all(
        checks[check_id] == "passed" for check_id in SOAK_CHECKS
    )
    if lifecycle_passed is not derived_lifecycle:
        raise AcceptanceError("cycle projected lifecycle evidence is inconsistent")
    infrastructure_blocked = classification == "test-infrastructure"
    hard_failure = (
        outcome == "failed"
        or classification == "runtime-regression"
        or (classification != "test-infrastructure" and not derived_lifecycle)
    )
    return {
        "recipeId": recipe_id,
        "lifecyclePassed": derived_lifecycle,
        "hardFailure": hard_failure,
        "infrastructureBlocked": infrastructure_blocked,
        "cleanupFailure": checks["bottle-cleanup"] != "passed",
        "residualProcessFailure": checks["no-residual-processes"] != "passed",
    }


def project_cycle_evidence(
    entry: object,
    ordinal: int,
    selected: set[str],
    *,
    allow_terminal: bool,
) -> dict[str, object]:
    if not isinstance(entry, dict):
        raise AcceptanceError("cycle record is not an object")
    if (
        entry.get("schemaVersion") != "1"
        or entry.get("testSuiteVersion") != TEST_SUITE_VERSION
        or type(entry.get("cycle")) is not int
        or entry["cycle"] != ordinal
        or not isinstance(entry.get("startedAt"), str)
        or SOAK_TIMESTAMP.fullmatch(entry["startedAt"]) is None
        or not isinstance(entry.get("finishedAt"), str)
        or SOAK_TIMESTAMP.fullmatch(entry["finishedAt"]) is None
        or type(entry.get("runnerExitCode")) is not int
        or not -(2**31) <= entry["runnerExitCode"] < 2**31
        or type(entry.get("hardFailure")) is not bool
        or type(entry.get("infrastructureBlocked")) is not bool
        or not isinstance(entry.get("applications"), list)
    ):
        raise AcceptanceError("cycle record structure is invalid")

    applications = entry["applications"]
    terminal = "reason" in entry or not applications
    if terminal:
        terminal_fields = SOAK_CYCLE_COMMON_FIELDS | {"reason"}
        if "runtime" in entry:
            terminal_fields = terminal_fields | {"runtime"}
        if (
            not allow_terminal
            or set(entry) != terminal_fields
            or entry.get("status") != "failed"
            or entry["hardFailure"] is not True
            or entry["infrastructureBlocked"] is not False
            or applications != []
            or not isinstance(entry.get("reason"), str)
            or entry.get("reason") not in SOAK_TERMINAL_REASONS
        ):
            raise AcceptanceError("cycle terminal evidence is invalid")
        runtime = (
            safe_runtime_projection(entry["runtime"])
            if "runtime" in entry
            else None
        )
        return {
            "status": "failed",
            "hardFailure": True,
            "infrastructureBlocked": False,
            "runtime": runtime,
            "completedApplications": 0,
            "verifiedApplications": 0,
            "cleanupFailures": 0,
            "residualProcessFailures": 0,
            "terminal": True,
        }

    if set(entry) != SOAK_CYCLE_COMMON_FIELDS | {"runtime"}:
        raise AcceptanceError("cycle record structure is invalid")
    runtime = safe_runtime_projection(entry.get("runtime"))
    if len(applications) != len(selected):
        raise AcceptanceError("cycle contains an invalid application set")
    projected_applications = [
        _project_application(application, selected) for application in applications
    ]
    recipe_ids = [
        str(application["recipeId"]) for application in projected_applications
    ]
    if len(set(recipe_ids)) != len(recipe_ids) or set(recipe_ids) != selected:
        raise AcceptanceError("cycle contains an invalid application set")

    hard_failure = any(
        application["hardFailure"] is True
        for application in projected_applications
    )
    infrastructure_blocked = any(
        application["infrastructureBlocked"] is True
        for application in projected_applications
    )
    status = (
        "failed"
        if hard_failure
        else ("unverified" if infrastructure_blocked else "verified")
    )
    if (
        entry.get("status") != status
        or entry["hardFailure"] is not hard_failure
        or entry["infrastructureBlocked"] is not infrastructure_blocked
    ):
        raise AcceptanceError("cycle projected status is inconsistent")
    return {
        "status": status,
        "hardFailure": hard_failure,
        "infrastructureBlocked": infrastructure_blocked,
        "runtime": runtime,
        "completedApplications": len(projected_applications),
        "verifiedApplications": sum(
            application["lifecyclePassed"] is True
            for application in projected_applications
        ),
        "cleanupFailures": sum(
            application["cleanupFailure"] is True
            for application in projected_applications
        ),
        "residualProcessFailures": sum(
            application["residualProcessFailure"] is True
            for application in projected_applications
        ),
        "terminal": False,
    }


def validate_verified_prefix(
    entries: list[dict[str, object]],
    selected: set[str],
    expected_runtime: dict[str, str],
) -> dict[str, str] | None:
    expected_version = _runtime_version(expected_runtime.get("version"))
    stable_runtime: dict[str, str] | None = None
    for ordinal, entry in enumerate(entries, start=1):
        try:
            projected = project_cycle_evidence(
                entry,
                ordinal,
                selected,
                allow_terminal=False,
            )
        except AcceptanceError as error:
            raise AcceptanceError(
                "cycles.jsonl does not contain a verified cycle prefix"
            ) from error
        if projected["status"] != "verified":
            raise AcceptanceError("cycles.jsonl does not contain a verified cycle prefix")
        projected_runtime = projected["runtime"]
        if not isinstance(projected_runtime, dict):
            raise AcceptanceError("cycles.jsonl contains invalid Runtime identity evidence")
        if (
            projected_runtime["runtimeId"] != expected_runtime.get("runtimeId")
            or projected_runtime["version"] != expected_version
        ):
            raise AcceptanceError("cycles.jsonl contains invalid Runtime identity evidence")
        if stable_runtime is None:
            stable_runtime = projected_runtime
        elif projected_runtime != stable_runtime:
            raise AcceptanceError("cycles.jsonl Runtime identity is not stable")
    return stable_runtime


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
            if not isinstance(outcome, str) or outcome not in SOAK_CHECK_OUTCOMES:
                raise AcceptanceError("cycle compatibility check has an invalid outcome")
            projected[check_id] = outcome
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
    selected: set[str],
    stop_reason: str | None = None,
) -> dict[str, object]:
    if (
        type(requested_cycles) is not int
        or requested_cycles < 1
        or not isinstance(selected, set)
        or not selected
        or any(not isinstance(recipe_id, str) or not recipe_id for recipe_id in selected)
    ):
        raise AcceptanceError("soak report request is invalid")
    selected_assets(selected)
    if stop_reason is not None and (
        not isinstance(stop_reason, str)
        or SOAK_STOP_REASON.fullmatch(stop_reason) is None
    ):
        raise AcceptanceError("soak report stop reason is invalid")
    statuses: Counter[str] = Counter()
    completed_applications = 0
    verified_applications = 0
    cleanup_failures = 0
    residual_process_failures = 0
    hard_failures = 0
    infrastructure_blocked = 0
    cycles_valid = True
    runtime_complete = True
    runtime_consistent = True
    stable_runtime: dict[str, str] | None = None

    for ordinal, entry in enumerate(entries, start=1):
        try:
            projected = project_cycle_evidence(
                entry,
                ordinal,
                selected,
                allow_terminal=True,
            )
        except AcceptanceError:
            statuses["invalid"] += 1
            cycles_valid = False
            runtime_complete = False
            continue
        statuses[str(projected["status"])] += 1
        hard_failures += int(projected["hardFailure"] is True)
        infrastructure_blocked += int(
            projected["infrastructureBlocked"] is True
        )
        completed_applications += int(projected["completedApplications"])
        verified_applications += int(projected["verifiedApplications"])
        cleanup_failures += int(projected["cleanupFailures"])
        residual_process_failures += int(
            projected["residualProcessFailures"]
        )
        projected_runtime = projected["runtime"]
        if not isinstance(projected_runtime, dict):
            runtime_complete = False
        else:
            if stable_runtime is None:
                stable_runtime = projected_runtime
            elif projected_runtime != stable_runtime:
                runtime_consistent = False

    finished = len(entries) == requested_cycles
    expected_applications = requested_cycles * len(selected)
    passed = (
        finished
        and cycles_valid
        and statuses == Counter({"verified": requested_cycles})
        and completed_applications == expected_applications
        and verified_applications == expected_applications
        and cleanup_failures == 0
        and residual_process_failures == 0
        and hard_failures == 0
        and infrastructure_blocked == 0
        and runtime_complete
        and runtime_consistent
        and stable_runtime is not None
    )
    release_gate = (
        "failed"
        if hard_failures or cleanup_failures or residual_process_failures
        else ("passed" if passed else "blocked")
    )
    report = {
        "schemaVersion": "1",
        "testSuiteVersion": TEST_SUITE_VERSION,
        "requestedCycles": requested_cycles,
        "completedCycles": len(entries),
        "requestedApplications": sorted(selected),
        "requestedApplicationExecutions": expected_applications,
        "completedApplicationExecutions": completed_applications,
        "verifiedApplicationExecutions": verified_applications,
        "cleanupFailures": cleanup_failures,
        "residualProcessFailures": residual_process_failures,
        "statuses": dict(sorted(statuses.items())),
        "hardFailures": hard_failures,
        "infrastructureBlocked": infrastructure_blocked,
        "finished": finished,
        "stoppedEarly": stop_reason is not None,
        **({"stopReason": stop_reason} if stop_reason is not None else {}),
        **(
            {"runtime": stable_runtime}
            if stable_runtime is not None and runtime_consistent
            else {}
        ),
        "releaseGate": release_gate,
    }
    serialized = (
        json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    descriptor_open = True
    try:
        created = os.fstat(descriptor)
        if not stat.S_ISREG(created.st_mode) or _is_reparse_point(created):
            raise AcceptanceError("soak report temporary file is invalid")
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor_open = False
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        closed = temporary.lstat()
        if (
            not stat.S_ISREG(closed.st_mode)
            or _is_reparse_point(closed)
            or _file_identity(closed) != _file_identity(created)
            or closed.st_size != len(serialized)
        ):
            raise AcceptanceError("soak report temporary file is invalid")
        os.replace(temporary, path)
    except Exception:
        if descriptor_open:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return report


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
        except (AssetError, OSError) as error:
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
    if path.is_symlink():
        raise AcceptanceError("configuration.json must be a bounded regular file")
    value = configuration_value(selected, cycles, runtime)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def validate_configuration(
    path: Path,
    selected: set[str],
    cycles: int,
    runtime: dict[str, str],
) -> None:
    value = _read_strict_json_file(
        path,
        "configuration.json",
        MAX_CONFIGURATION_BYTES,
    )
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
        if output_root.is_symlink() or (
            output_root.exists() and not output_root.is_dir()
        ):
            raise AcceptanceError("output-root must be a real directory")
        known = {asset.app_id for asset in CERTIFICATION_ASSETS}
        selected = set(arguments.applications or known)
        unknown = selected - known
        if unknown:
            raise AcceptanceError(f"unknown certification application: {sorted(unknown)[0]}")
        cycles_path = output_root / "cycles.jsonl"
        report_path = output_root / "summary.json"
        configuration_path = output_root / "configuration.json"
        entries = load_cycle_log(cycles_path) if arguments.resume else []
        if not arguments.resume and output_root.exists() and any(output_root.iterdir()):
            raise AcceptanceError("output-root must be empty unless --resume is used")
        try:
            configuration_metadata = configuration_path.lstat()
        except FileNotFoundError:
            configuration_metadata = None
        except OSError as error:
            raise AcceptanceError(
                "configuration.json must be a bounded regular file"
            ) from error
        if configuration_metadata is not None and (
            not stat.S_ISREG(configuration_metadata.st_mode)
            or _is_reparse_point(configuration_metadata)
        ):
            raise AcceptanceError("configuration.json must be a bounded regular file")
        configuration_exists = configuration_metadata is not None
        stable_runtime: dict[str, str] | None = None
        if arguments.resume:
            if not configuration_exists:
                raise AcceptanceError(
                    "resume requires configuration.json; use a new output-root"
                )
            validate_configuration(
                configuration_path,
                selected,
                arguments.cycles,
                runtime,
            )
            stable_runtime = validate_verified_prefix(entries, selected, runtime)
        if len(entries) > arguments.cycles:
            raise AcceptanceError("cycles.jsonl already exceeds the requested cycle count")
        validate_cached_assets(cache_root, selected)
        output_root.mkdir(parents=True, exist_ok=True)
        if not arguments.resume:
            write_configuration(
                configuration_path,
                selected,
                arguments.cycles,
                runtime,
            )
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
            try:
                summary_path.lstat()
            except FileNotFoundError:
                projection: dict[str, object] = {
                    "status": "failed",
                    "hardFailure": True,
                    "infrastructureBlocked": False,
                    "applications": [],
                    "reason": "GUI runner did not produce summary.json",
                }
            except OSError:
                projection = {
                    "status": "failed",
                    "hardFailure": True,
                    "infrastructureBlocked": False,
                    "applications": [],
                    "reason": "cycle summary contract or Runtime identity is invalid",
                }
            else:
                try:
                    summary = _read_strict_json_file(
                        summary_path,
                        "GUI runner summary",
                        MAX_SUMMARY_BYTES,
                    )
                    if not isinstance(summary, dict):
                        raise AcceptanceError("GUI runner summary is not an object")
                    projection = classify_summary(
                        summary,
                        selected,
                        runtime,
                        stable_runtime,
                    )
                except AcceptanceError:
                    projection = {
                        "status": "failed",
                        "hardFailure": True,
                        "infrastructureBlocked": False,
                        "applications": [],
                        "reason": "cycle summary contract or Runtime identity is invalid",
                    }
                if projection["status"] == "verified" and stable_runtime is None:
                    stable_runtime = dict(projection["runtime"])
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
            report = write_report(
                report_path,
                entries,
                arguments.cycles,
                selected,
                stop_reason,
            )
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
        report = write_report(report_path, entries, arguments.cycles, selected)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")), flush=True)
        return 0 if report["releaseGate"] == "passed" else 1
    except (AcceptanceError, OSError, ValueError) as error:
        print(f"compatforge-gui-soak: {error}", file=sys.stderr)
        return 2
    finally:
        stop_power_assertion(power_assertion)


if __name__ == "__main__":
    raise SystemExit(main())
