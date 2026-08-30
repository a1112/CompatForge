#!/usr/bin/env python3
"""Aggregate a GUI baseline summary into a bounded release-gate report."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from download_gui_assets import ASSETS
from run_gui_baseline import AcceptanceError, TEST_SUITE_VERSION, absolute, matrix_entry_digest

FAILURE_CLASSIFICATIONS = {
    "unsupported",
    "runtime-regression",
    "recipe-regression",
    "host-driver",
    "translator",
    "graphics",
    "installer-upstream",
    "policy-blocked",
    "test-infrastructure",
}
OUTCOMES = {"passed", "failed", "blocked", "skipped"}
MAX_RESULTS = 4096
MAX_INPUT_BYTES = 16 * 1024 * 1024


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--input", required=True)
    value.add_argument("--output")
    return value


def load_summary(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_INPUT_BYTES:
        raise AcceptanceError("input must be a bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("input is not readable JSON") from error
    if not isinstance(value, dict) or value.get("schemaVersion") != "1":
        raise AcceptanceError("input must be a GUI summary using schemaVersion 1")
    return value


def aggregate(summary: dict[str, object]) -> dict[str, object]:
    if summary.get("testSuiteVersion") != TEST_SUITE_VERSION:
        raise AcceptanceError("summary testSuiteVersion is not supported")
    raw_results = summary.get("compatibilityResults")
    if not isinstance(raw_results, list) or not raw_results or len(raw_results) > MAX_RESULTS:
        raise AcceptanceError("summary compatibilityResults must contain 1..4096 entries")
    assets = {asset.app_id: asset for asset in ASSETS}
    run_ids: set[str] = set()
    outcomes: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    applications: list[dict[str, object]] = []
    for raw in raw_results:
        if not isinstance(raw, dict):
            raise AcceptanceError("compatibility result must be an object")
        run_id = raw.get("runId")
        recipe_id = raw.get("recipeId")
        outcome = raw.get("outcome")
        classification = raw.get("failureClassification")
        if not isinstance(run_id, str) or run_id in run_ids:
            raise AcceptanceError("compatibility result runId is invalid or duplicated")
        run_ids.add(run_id)
        if not isinstance(recipe_id, str) or recipe_id not in assets:
            raise AcceptanceError("compatibility result recipeId is outside the fixed matrix")
        asset = assets[recipe_id]
        if raw.get("recipeDigest") != matrix_entry_digest(asset):
            raise AcceptanceError("compatibility result recipeDigest does not bind the fixed matrix")
        if raw.get("installerDigest") != "sha256:" + asset.sha256:
            raise AcceptanceError("compatibility result installerDigest does not bind the fixed asset")
        if raw.get("testSuiteVersion") != TEST_SUITE_VERSION:
            raise AcceptanceError("compatibility result testSuiteVersion is not supported")
        if outcome not in OUTCOMES:
            raise AcceptanceError("compatibility result outcome is invalid")
        if outcome == "passed" and classification is not None:
            raise AcceptanceError("passed compatibility result cannot have a failure classification")
        if outcome in {"failed", "blocked"} and classification not in FAILURE_CLASSIFICATIONS:
            raise AcceptanceError("non-passing compatibility result requires a closed failure classification")
        checks = raw.get("checks")
        if not isinstance(checks, list) or not checks:
            raise AcceptanceError("compatibility result checks are missing")
        check_outcomes = Counter(
            check.get("outcome") for check in checks if isinstance(check, dict) and check.get("outcome") in OUTCOMES
        )
        if sum(check_outcomes.values()) != len(checks):
            raise AcceptanceError("compatibility result check outcome is invalid")
        outcomes[str(outcome)] += 1
        if isinstance(classification, str):
            failures[classification] += 1
        applications.append(
            {
                "recipeId": recipe_id,
                "category": asset.category,
                "toolkit": asset.toolkit,
                "guestArchitecture": asset.guest_architecture,
                "outcome": outcome,
                **({"failureClassification": classification} if classification is not None else {}),
                "checks": dict(sorted(check_outcomes.items())),
            }
        )
    release_gate = (
        "failed"
        if outcomes["failed"]
        else ("blocked" if outcomes["blocked"] or outcomes["skipped"] else "passed")
    )
    return {
        "schemaVersion": "1",
        "testSuiteVersion": summary.get("testSuiteVersion"),
        "releaseGate": release_gate,
        "total": len(applications),
        "outcomes": dict(sorted(outcomes.items())),
        "failureClassifications": dict(sorted(failures.items())),
        "infrastructureBlocked": failures["test-infrastructure"],
        "policyBlocked": failures["policy-blocked"],
        "applications": applications,
    }


def main() -> int:
    try:
        arguments = parser().parse_args()
        input_path = absolute(arguments.input, "input", external=True)
        report = aggregate(load_summary(input_path))
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if arguments.output:
            output = absolute(arguments.output, "output", external=True)
            if output.exists():
                raise AcceptanceError("output already exists")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0 if report["releaseGate"] == "passed" else 1
    except (AcceptanceError, OSError) as error:
        print(f"compatforge-gui-summary: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
