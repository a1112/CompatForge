#!/usr/bin/env python3
"""Validate a closed capability probe manifest and optional bound result."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path, PurePosixPath

MAX_DOCUMENT_BYTES = 1024 * 1024
ID = re.compile(r"[a-z0-9][a-z0-9._-]{1,127}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PREFIXED_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
FAILURE_CLASSIFICATIONS = {
    "unsupported",
    "runtime-regression",
    "recipe-regression",
    "host-driver",
    "translator",
    "graphics",
    "policy-blocked",
    "test-infrastructure",
}


class ContractError(Exception):
    pass


def duplicate_rejecting_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ContractError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load_document(path: Path) -> dict[str, object]:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise ContractError("document must be an absolute regular file")
    if path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ContractError("document exceeds the 1 MiB bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=duplicate_rejecting_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError("document is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ContractError("document root must be an object")
    return value


def exact_keys(value: dict[str, object], required: set[str], optional: set[str] = set()) -> None:
    if set(value) - required - optional:
        raise ContractError("document contains an unknown field")
    if required - set(value):
        raise ContractError("document omits a required field")


def identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or ID.fullmatch(value) is None:
        raise ContractError(f"{field} is not a canonical identifier")
    return value


def digest(value: object, field: str, *, prefixed: bool = False) -> str:
    pattern = PREFIXED_SHA256 if prefixed else SHA256
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ContractError(f"{field} is not a canonical SHA-256")
    return value


def bounded_text(value: object, field: str, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ContractError(f"{field} is outside its text bound")
    return value


def portable_component(value: object, field: str) -> str:
    text = bounded_text(value, field, 255)
    path = PurePosixPath(text)
    if len(path.parts) != 1 or text in {".", ".."} or "\\" in text:
        raise ContractError(f"{field} is not a portable file name")
    return text


def portable_relative(value: object, field: str) -> str:
    text = bounded_text(value, field, 1024)
    path = PurePosixPath(text)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or "\\" in text:
        raise ContractError(f"{field} is not a portable relative path")
    return text


def canonical_digest(value: dict[str, object]) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def validate_manifest(value: dict[str, object]) -> dict[str, object]:
    exact_keys(
        value,
        {
            "schemaVersion",
            "probeId",
            "displayName",
            "category",
            "guestArchitecture",
            "source",
            "build",
            "artifact",
            "requiredObservations",
        },
    )
    if value["schemaVersion"] != "1":
        raise ContractError("manifest schemaVersion is unsupported")
    identifier(value["probeId"], "probeId")
    bounded_text(value["displayName"], "displayName", 256)
    if value["category"] not in {"win32", "dotnet-wpf", "d3d9", "d3d11", "d3d12", "msi"}:
        raise ContractError("manifest category is unsupported")
    if value["guestArchitecture"] not in {"i386", "x86_64"}:
        raise ContractError("manifest guestArchitecture is unsupported")

    source = value["source"]
    if not isinstance(source, dict):
        raise ContractError("source must be an object")
    exact_keys(source, {"repository", "commit", "path", "sha256"})
    if not isinstance(source["repository"], str) or not source["repository"].startswith("https://"):
        raise ContractError("source repository must use HTTPS")
    if not isinstance(source["commit"], str) or COMMIT.fullmatch(source["commit"]) is None:
        raise ContractError("source commit must contain 40 lowercase hex characters")
    portable_relative(source["path"], "source.path")
    digest(source["sha256"], "source.sha256")

    build = value["build"]
    if not isinstance(build, dict):
        raise ContractError("build must be an object")
    exact_keys(build, {"toolchain", "toolchainVersion", "arguments"})
    bounded_text(build["toolchain"], "build.toolchain", 128)
    bounded_text(build["toolchainVersion"], "build.toolchainVersion", 256)
    arguments = build["arguments"]
    if not isinstance(arguments, list) or len(arguments) > 64:
        raise ContractError("build.arguments exceeds its bound")
    if any(not isinstance(argument, str) or len(argument.encode("utf-8")) > 4096 for argument in arguments):
        raise ContractError("build.arguments contains an invalid value")

    artifact = value["artifact"]
    if not isinstance(artifact, dict):
        raise ContractError("artifact must be an object")
    exact_keys(artifact, {"fileName", "sha256", "sizeBytes", "architecture", "subsystem"})
    portable_component(artifact["fileName"], "artifact.fileName")
    digest(artifact["sha256"], "artifact.sha256")
    if not isinstance(artifact["sizeBytes"], int) or not 1 <= artifact["sizeBytes"] <= 64 * 1024 * 1024:
        raise ContractError("artifact size is outside the fixed bound")
    if artifact["architecture"] != value["guestArchitecture"]:
        raise ContractError("artifact architecture does not match the manifest")
    if artifact["subsystem"] not in {"windowsConsole", "windowsGui"}:
        raise ContractError("artifact subsystem is unsupported")

    observations = value["requiredObservations"]
    if not isinstance(observations, list) or not 1 <= len(observations) <= 64:
        raise ContractError("requiredObservations is outside its bound")
    normalized = [identifier(item, "requiredObservations") for item in observations]
    if len(set(normalized)) != len(normalized):
        raise ContractError("requiredObservations contains duplicates")
    return value


def timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ContractError(f"{field} must be a UTC date-time")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ContractError(f"{field} must be a UTC date-time") from error


def validate_result(value: dict[str, object], manifest: dict[str, object]) -> dict[str, object]:
    required = {
        "schemaVersion",
        "runId",
        "probeId",
        "probeManifestDigest",
        "artifactDigest",
        "testSuiteVersion",
        "host",
        "runtimePackDigest",
        "translator",
        "graphicsBackend",
        "guestArchitecture",
        "outcome",
        "startedAt",
        "finishedAt",
        "observations",
        "checks",
        "artifacts",
    }
    exact_keys(value, required, {"failureClassification"})
    if value["schemaVersion"] != "1":
        raise ContractError("result schemaVersion is unsupported")
    try:
        run_id = uuid.UUID(str(value["runId"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise ContractError("runId is not a UUID") from error
    if str(run_id) != value["runId"]:
        raise ContractError("runId is not canonical")
    if value["probeId"] != manifest["probeId"]:
        raise ContractError("result probeId does not match the manifest")
    if value["probeManifestDigest"] != canonical_digest(manifest):
        raise ContractError("result probeManifestDigest does not match the manifest")
    artifact = manifest["artifact"]
    assert isinstance(artifact, dict)
    if value["artifactDigest"] != "sha256:" + str(artifact["sha256"]):
        raise ContractError("result artifactDigest does not match the manifest")
    identifier(value["testSuiteVersion"], "testSuiteVersion")

    host = value["host"]
    if not isinstance(host, dict):
        raise ContractError("host must be an object")
    exact_keys(host, {"os", "version", "architecture", "displayProtocol"}, {"gpu", "driver"})
    if host["os"] not in {"macos", "linux"} or host["architecture"] not in {"x86_64", "arm64"}:
        raise ContractError("host platform is unsupported")
    if host["displayProtocol"] not in {"appkit", "x11", "wayland", "headless"}:
        raise ContractError("host displayProtocol is unsupported")
    bounded_text(host["version"], "host.version", 256)
    for field in ("gpu", "driver"):
        if field in host:
            bounded_text(host[field], f"host.{field}", 256)
    digest(value["runtimePackDigest"], "runtimePackDigest", prefixed=True)
    if value["translator"] not in {"native", "rosetta", "fex", "box64", "qemu"}:
        raise ContractError("translator is unsupported")
    if value["graphicsBackend"] not in {"none", "wined3d", "dxvk", "vkd3d-proton", "d3dmetal", "moltenvk"}:
        raise ContractError("graphicsBackend is unsupported")
    if value["guestArchitecture"] != manifest["guestArchitecture"]:
        raise ContractError("result guestArchitecture does not match the manifest")
    outcome = value["outcome"]
    if outcome not in {"passed", "failed", "blocked", "unsupported"}:
        raise ContractError("result outcome is unsupported")
    classification = value.get("failureClassification")
    if outcome == "passed" and classification is not None:
        raise ContractError("passed result must not contain failureClassification")
    if outcome != "passed" and classification not in FAILURE_CLASSIFICATIONS:
        raise ContractError("non-passed result requires a closed failureClassification")
    if outcome == "unsupported" and classification != "unsupported":
        raise ContractError("unsupported outcome requires unsupported classification")
    if timestamp(value["finishedAt"], "finishedAt") < timestamp(value["startedAt"], "startedAt"):
        raise ContractError("finishedAt precedes startedAt")

    required_observations = set(manifest["requiredObservations"])
    observations = value["observations"]
    if not isinstance(observations, dict) or set(observations) - required_observations:
        raise ContractError("result observations are not bound to the manifest")
    for key, item in observations.items():
        identifier(key, "observation id")
        if isinstance(item, (dict, list)) or item is None or not isinstance(item, (str, int, float, bool)):
            raise ContractError("result observation contains a non-scalar value")
        if isinstance(item, str) and len(item.encode("utf-8")) > 4096:
            raise ContractError("result observation text exceeds its bound")
    if outcome == "passed" and set(observations) != required_observations:
        raise ContractError("passed result omits a required observation")

    checks = value["checks"]
    if not isinstance(checks, list) or not 3 <= len(checks) <= 64:
        raise ContractError("result checks are outside the fixed bound")
    check_outcomes: dict[str, str] = {}
    for check in checks:
        if not isinstance(check, dict):
            raise ContractError("result check is not an object")
        exact_keys(check, {"id", "outcome"}, {"message"})
        check_id = identifier(check["id"], "check.id")
        if check_id in check_outcomes:
            raise ContractError("result contains a duplicate check")
        if check["outcome"] not in {"passed", "failed", "blocked", "skipped"}:
            raise ContractError("result check outcome is unsupported")
        if "message" in check:
            bounded_text(check["message"], "check.message")
        check_outcomes[check_id] = str(check["outcome"])
    if not {"launch", "exit", "no-residual-processes"}.issubset(check_outcomes):
        raise ContractError("result omits a lifecycle check")
    if outcome == "passed" and any(item != "passed" for item in check_outcomes.values()):
        raise ContractError("passed result contains a non-passed check")

    artifacts = value["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) > 64:
        raise ContractError("result artifacts exceed the fixed bound")
    names: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise ContractError("result artifact is not an object")
        exact_keys(item, {"name", "sha256", "sizeBytes"})
        name = portable_component(item["name"], "artifact.name")
        if name.casefold() in names:
            raise ContractError("result artifacts contain a duplicate name")
        names.add(name.casefold())
        digest(item["sha256"], "artifact.sha256", prefixed=True)
        if not isinstance(item["sizeBytes"], int) or not 1 <= item["sizeBytes"] <= 1024 * 1024 * 1024:
            raise ContractError("result artifact size is outside the fixed bound")
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("manifest")
    value.add_argument("--result")
    return value


def main() -> int:
    try:
        arguments = parser().parse_args()
        manifest_path = Path(arguments.manifest)
        manifest = validate_manifest(load_document(manifest_path))
        receipt: dict[str, object] = {
            "schemaVersion": "1",
            "probeId": manifest["probeId"],
            "probeManifestDigest": canonical_digest(manifest),
        }
        if arguments.result:
            validate_result(load_document(Path(arguments.result)), manifest)
            receipt["resultValidated"] = True
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0
    except (ContractError, OSError) as error:
        print(f"compatforge-capability-probe: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
