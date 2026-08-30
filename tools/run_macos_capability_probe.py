#!/usr/bin/env python3
"""Run one fixed capability probe through the macOS PreparedLaunch path."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import uuid
from pathlib import Path

from run_gui_baseline import (
    AcceptanceError,
    InfrastructureUnavailable,
    absolute,
    cleanup_bottle,
    desktop_session_state,
    exit_observation,
    invoke,
    json_object,
    observed_launch,
    process_snapshot,
    utc_now,
    write_json,
)
from validate_capability_probe import canonical_digest, load_document, validate_manifest, validate_result

TEST_SUITE_VERSION = "cross-host-capability-v3"
MAX_PROBE_BYTES = 64 * 1024 * 1024


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--compatforge-cli", required=True)
    value.add_argument("--manifest", required=True)
    value.add_argument("--artifact", required=True)
    value.add_argument("--runtime-store", required=True)
    value.add_argument("--storage-root", required=True)
    value.add_argument("--work-root", required=True)
    value.add_argument("--wine-root")
    value.add_argument("--wine")
    value.add_argument("--wineserver")
    value.add_argument("--version")
    return value


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bound_artifact(manifest: dict[str, object], path: Path) -> None:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise AcceptanceError("probe artifact must be an absolute regular file")
    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict):
        raise AcceptanceError("probe manifest omitted artifact binding")
    metadata = path.stat()
    if metadata.st_size > MAX_PROBE_BYTES or metadata.st_size != artifact.get("sizeBytes"):
        raise AcceptanceError("probe artifact size does not match the manifest")
    if path.name != artifact.get("fileName"):
        raise AcceptanceError("probe artifact name does not match the manifest")
    if file_sha256(path) != artifact.get("sha256"):
        raise AcceptanceError("probe artifact digest does not match the manifest")


def check_outcome(passed: bool, *, blocked: bool = False) -> str:
    return "passed" if passed else ("blocked" if blocked else "failed")


def host_result() -> dict[str, object]:
    return {
        "os": "macos",
        "version": platform.mac_ver()[0],
        "architecture": platform.machine(),
        "displayProtocol": "appkit",
    }


def main() -> int:
    cleanup_context: dict[str, object] | None = None
    cleanup_storage: Path | None = None
    cleanup_bottle_id: str | None = None
    try:
        arguments = parser().parse_args()
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise AcceptanceError("capability probe runner requires Darwin/arm64")
        cli = absolute(arguments.compatforge_cli, "compatforge-cli")
        manifest_path = absolute(arguments.manifest, "manifest", external=True)
        artifact_path = absolute(arguments.artifact, "artifact", external=True)
        runtime_store = absolute(arguments.runtime_store, "runtime-store", external=True)
        storage_root = absolute(arguments.storage_root, "storage-root", external=True)
        work_root = absolute(arguments.work_root, "work-root", external=True)
        manifest = validate_manifest(load_document(manifest_path))
        bound_artifact(manifest, artifact_path)
        work_root.mkdir(parents=True, exist_ok=True)
        if any(work_root.iterdir()):
            raise AcceptanceError("work-root must be empty")
        explicit = [arguments.wine_root, arguments.wine, arguments.wineserver, arguments.version]
        if any(explicit) and not all(explicit):
            raise AcceptanceError("wine-root, wine, wineserver and version must be provided together")
        desktop = desktop_session_state()
        if desktop.get("observable") is not True:
            raise InfrastructureUnavailable(f"desktop session is {desktop.get('state')}")

        request: dict[str, object] = {
            "schemaVersion": "1",
            "runtimeStoreRoot": str(runtime_store),
            "storageRoot": str(storage_root),
        }
        if all(explicit):
            request.update(
                {
                    "materializedRoot": str(absolute(arguments.wine_root, "wine-root")),
                    "wine": arguments.wine,
                    "wineserver": arguments.wineserver,
                    "version": arguments.version,
                }
            )
        bootstrap_request = work_root / "bootstrap-request.json"
        context_path = work_root / "context.json"
        write_json(bootstrap_request, request)
        receipt = json_object(
            invoke([str(cli), "local", "macos", "context", str(bootstrap_request), str(context_path)]),
            "probe bootstrap",
        )
        context = json.loads(context_path.read_text(encoding="utf-8"))
        if not isinstance(context, dict) or not isinstance(context.get("storageRoot"), str):
            raise AcceptanceError("probe context omitted storageRoot")
        storage_root = Path(context["storageRoot"])
        cleanup_context = context
        cleanup_storage = storage_root
        supervisor = context.get("supervisor")
        if isinstance(supervisor, dict):
            supervisor["maximumRuntimeMilliseconds"] = 60_000
        write_json(context_path, context)

        inspection = json_object(invoke([str(cli), "inspect", str(artifact_path)]), "probe inspection")
        artifact = manifest["artifact"]
        assert isinstance(artifact, dict)
        expected_architecture = "x86" if artifact["architecture"] == "i386" else artifact["architecture"]
        if inspection.get("architecture") != expected_architecture or inspection.get("subsystem") != artifact["subsystem"]:
            raise AcceptanceError("probe inspection does not match the manifest")

        probe_id = str(manifest["probeId"])
        bottle_id = f"probe-{probe_id}"
        cleanup_bottle_id = bottle_id
        bottle_root = storage_root / "bottles" / bottle_id / "prefix" / "drive_c"
        bottle_root.mkdir(parents=True, exist_ok=True)
        started_at = utc_now()
        screenshot_path = work_root / f"{probe_id}.png"
        launch_request = {
            "schemaVersion": "1",
            "requestId": str(uuid.uuid4()),
            "bottleId": bottle_id,
            "executable": {
                "path": str(artifact_path),
                "architecture": manifest["guestArchitecture"],
                "mode": "immutableArtifact",
            },
            "arguments": [],
            "environment": {},
            "constraints": {
                "allowVirtualMachine": False,
                "allowRemote": False,
                "networkPolicy": "deny",
            },
        }
        launch_request_path = work_root / "launch-request.json"
        write_json(launch_request_path, launch_request)
        plan = json_object(
            invoke([str(cli), "prepared-plan", str(context_path), str(artifact_path), str(launch_request_path)]),
            "probe prepared plan",
        )
        events, windows, screenshot, process_group_id = observed_launch(
            [
                str(cli),
                "prepared-launch-terminate",
                str(context_path),
                str(artifact_path),
                str(launch_request_path),
                "20000",
            ],
            screenshot_path,
            ("CompatForge Win32 Probe",),
            window_appearance_seconds=30,
        )
        exit_value = exit_observation(events)
        residual = process_snapshot(bottle_root, process_group_id)
        cleanup_evidence = cleanup_bottle(context, storage_root, bottle_id)
        cleanup = cleanup_evidence.get("success") is True
        if cleanup:
            cleanup_bottle_id = None

        observations: dict[str, object] = {}
        if windows.get("available") is True and "window-created" in manifest["requiredObservations"]:
            observations["window-created"] = True
        required = set(manifest["requiredObservations"])
        lifecycle_passed = (
            windows.get("available") is True
            and screenshot.get("available") is True
            and exit_value.get("present") is True
            and not residual
            and cleanup
        )
        complete = set(observations) == required
        if lifecycle_passed and complete:
            outcome = "passed"
            classification = None
        elif lifecycle_passed:
            outcome = "blocked"
            classification = "policy-blocked"
        else:
            outcome = "failed"
            classification = "runtime-regression"
        artifacts: list[dict[str, object]] = []
        if screenshot_path.is_file() and screenshot_path.stat().st_size > 0:
            artifacts.append(
                {
                    "name": screenshot_path.name,
                    "sha256": "sha256:" + file_sha256(screenshot_path),
                    "sizeBytes": screenshot_path.stat().st_size,
                }
            )
        result = {
            "schemaVersion": "1",
            "runId": str(uuid.uuid4()),
            "probeId": probe_id,
            "probeManifestDigest": canonical_digest(manifest),
            "artifactDigest": "sha256:" + str(artifact["sha256"]),
            "testSuiteVersion": TEST_SUITE_VERSION,
            "host": host_result(),
            "runtimePackDigest": receipt.get("packDigest"),
            "translator": "rosetta",
            "graphicsBackend": "none" if manifest["category"] == "win32" else "wined3d",
            "guestArchitecture": manifest["guestArchitecture"],
            "outcome": outcome,
            **({"failureClassification": classification} if classification is not None else {}),
            "startedAt": started_at,
            "finishedAt": utc_now(),
            "observations": observations,
            "checks": [
                {"id": "launch", "outcome": check_outcome(bool(events))},
                {"id": "window-visible", "outcome": check_outcome(windows.get("available") is True)},
                {"id": "screenshot", "outcome": check_outcome(screenshot.get("available") is True)},
                {"id": "exit", "outcome": check_outcome(exit_value.get("present") is True)},
                {"id": "no-residual-processes", "outcome": check_outcome(not residual)},
                {"id": "bottle-cleanup", "outcome": check_outcome(cleanup)},
                {"id": "observation-completeness", "outcome": check_outcome(complete, blocked=True)},
            ],
            "artifacts": artifacts,
        }
        validate_result(result, manifest)
        evidence = {
            "schemaVersion": "1",
            "desktopPreflight": desktop,
            "inspection": inspection,
            "plan": plan,
            "events": events,
            "windows": windows,
            "screenshot": screenshot,
            "exit": exit_value,
            "residualProcesses": residual,
            "cleanup": cleanup,
            "cleanupEvidence": cleanup_evidence,
        }
        write_json(work_root / "probe-evidence.json", evidence)
        write_json(work_root / "capability-probe-result.json", result)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0 if outcome == "passed" else 1
    except (AcceptanceError, InfrastructureUnavailable, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"compatforge-macos-capability-probe: {error}", file=sys.stderr)
        return 2
    finally:
        if cleanup_context is not None and cleanup_storage is not None and cleanup_bottle_id is not None:
            recovery = cleanup_bottle(cleanup_context, cleanup_storage, cleanup_bottle_id)
            if recovery.get("success") is not True:
                print(
                    f"compatforge-macos-capability-probe: recovery cleanup failed: {recovery.get('reason')}",
                    file=sys.stderr,
                )


if __name__ == "__main__":
    raise SystemExit(main())
