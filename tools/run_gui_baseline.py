#!/usr/bin/env python3
"""Opt-in macOS GUI acceptance for the fixed CompatForge baseline apps.

This script intentionally uses only ``accepted``, ``failed``, ``unverified``
or ``blocked`` per application. A visible process or a blank window is never
promoted to an acceptance claim. Downloads, screenshots and evidence live in
caller-owned external directories and are excluded from the repository.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import secrets
import selectors
import shutil
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_COMMAND_SECONDS = 180
WINDOW_APPEARANCE_SECONDS = 30
INTERACTIVE_RUNTIME_MILLISECONDS = 60_000
ACKNOWLEDGEMENT_WAIT_SECONDS = 5 * 60
ACKNOWLEDGEMENT_POLL_SECONDS = 0.25
MAX_DIAGNOSTICS = 16
MAX_DIAGNOSTIC_CHARS = 4096
MAX_COMPACT_DEPTH = 8
MAX_COMPACT_NODES = 256
MAX_COMPACT_TEXT_CHARS = 4096

REQUIRED_INTERACTIONS = {
    "7zip": ("fileList", "menus"),
    "sumatrapdf": ("mainWindow", "openDialog"),
    "notepad-plus-plus": ("open", "edit", "saveUtf8Chinese", "rereadMatches"),
}

RUNTIME_IDS = ("crossover", "whisky")
STATUSES = ("accepted", "failed", "unverified", "blocked")
FAILURE_CLASSES = ("environment", "runtime", "core", "desktop", "application", "cleanup")
FAILURE_CLASS_BY_REASON_CODE = {
    "platform-unsupported": "environment",
    "tool-unavailable": "environment",
    "network-unavailable": "environment",
    "rosetta-unavailable": "environment",
    "asset-fetch-failed": "environment",
    "runtime-descriptor-invalid": "runtime",
    "runtime-start-failed": "runtime",
    "runtime-version-invalid": "runtime",
    "core-snapshot-failed": "core",
    "core-plan-failed": "core",
    "core-import-failed": "core",
    "core-inspection-failed": "core",
    "core-launch-failed": "core",
    "core-verification-failed": "core",
    "core-rollback-failed": "core",
    "desktop-launch-failed": "desktop",
    "desktop-window-unobserved": "desktop",
    "application-install-failed": "application",
    "application-interaction-unverified": "application",
    "application-interaction-invalid": "application",
    "application-content-verification-failed": "application",
    "cleanup-residual-processes": "cleanup",
    "cleanup-termination-failed": "cleanup",
    "cleanup-delete-failed": "cleanup",
}
STATUS_BY_REASON_CODE = {
    "platform-unsupported": "blocked",
    "tool-unavailable": "blocked",
    "network-unavailable": "blocked",
    "rosetta-unavailable": "blocked",
    "asset-fetch-failed": "failed",
    "runtime-descriptor-invalid": "blocked",
    "runtime-start-failed": "failed",
    "runtime-version-invalid": "failed",
    "core-snapshot-failed": "failed",
    "core-plan-failed": "failed",
    "core-import-failed": "failed",
    "core-inspection-failed": "failed",
    "core-launch-failed": "failed",
    "core-verification-failed": "failed",
    "core-rollback-failed": "failed",
    "desktop-launch-failed": "failed",
    "desktop-window-unobserved": "failed",
    "application-install-failed": "failed",
    "application-interaction-unverified": "unverified",
    "application-interaction-invalid": "failed",
    "application-content-verification-failed": "failed",
    "cleanup-residual-processes": "failed",
    "cleanup-termination-failed": "failed",
    "cleanup-delete-failed": "failed",
}
FAILURE_REASON_BY_STAGE = {
    "preflight-platform": "platform-unsupported",
    "preflight-tool": "tool-unavailable",
    "preflight-network": "network-unavailable",
    "preflight-rosetta": "rosetta-unavailable",
    "asset-fetch": "asset-fetch-failed",
    "runtime-descriptor": "runtime-descriptor-invalid",
    "runtime-start": "runtime-start-failed",
    "runtime-version": "runtime-version-invalid",
    "core-snapshot": "core-snapshot-failed",
    "core-plan": "core-plan-failed",
    "core-import": "core-import-failed",
    "core-inspection": "core-inspection-failed",
    "core-launch": "core-launch-failed",
    "core-verification": "core-verification-failed",
    "core-rollback": "core-rollback-failed",
    "desktop-launch": "desktop-launch-failed",
    "desktop-window": "desktop-window-unobserved",
    "installer-launch": "application-install-failed",
    "application-interaction": "application-interaction-unverified",
    "application-interaction-invalid": "application-interaction-invalid",
    "application-content": "application-content-verification-failed",
    "cleanup-residual": "cleanup-residual-processes",
    "cleanup-termination": "cleanup-termination-failed",
    "cleanup-delete": "cleanup-delete-failed",
}
BLOCKED_STAGES = {
    "preflight-platform",
    "preflight-tool",
    "preflight-network",
    "preflight-rosetta",
    "runtime-descriptor",
}
UNVERIFIED_STAGES = {"application-interaction"}


class AcceptanceError(Exception):
    pass


class InvocationError(AcceptanceError):
    closed_code = "command-failed"

    def __init__(self, returncode: int, diagnostic: str) -> None:
        self.returncode = returncode
        self.diagnostic = diagnostic[:MAX_DIAGNOSTIC_CHARS]
        super().__init__(f"command returned {returncode}: {self.diagnostic}")


class NetworkUnavailableError(AcceptanceError):
    pass


class AssetFetchError(AcceptanceError):
    pass


class InteractionUnverifiedError(AcceptanceError):
    pass


class InteractionInvalidError(AcceptanceError):
    pass


class InteractionIntegrityError(AcceptanceError):
    pass


class InteractionCleanupError(AcceptanceError):
    pass


class UniqueValueAction(argparse.Action):
    """Reject repeated identity arguments instead of accepting the last value."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string or self.dest} may be provided only once")
        setattr(namespace, self.dest, values)


def absolute(value: str, field: str, *, external: bool = False) -> Path:
    path = Path(value)
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise AcceptanceError(f"{field} must be an absolute non-traversing path")
    if external and (path == ROOT or ROOT in path.parents):
        raise AcceptanceError(f"{field} must be outside the repository")
    return path


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    value.add_argument("--compatforge-cli", required=True)
    value.add_argument("--cache-root", required=True)
    value.add_argument("--runtime-store", required=True)
    value.add_argument("--storage-root", required=True)
    value.add_argument("--work-root", required=True)
    value.add_argument("--allow-network", action="store_true")
    value.add_argument("--runtime-id", choices=RUNTIME_IDS, action=UniqueValueAction)
    value.add_argument("--wine-root", action=UniqueValueAction)
    value.add_argument("--wine", action=UniqueValueAction)
    value.add_argument("--wineserver", action=UniqueValueAction)
    value.add_argument("--version", action=UniqueValueAction)
    value.add_argument(
        "--accept-interactive",
        action="store_true",
        help="create post-window challenges for explicit operator acknowledgement",
    )
    value.add_argument(
        "--interaction-plan",
        action=UniqueValueAction,
        help="absolute read-only JSON plan naming the required interactions",
    )
    value.add_argument(
        "--acknowledgement-root",
        action=UniqueValueAction,
        help="absolute external root containing challenges and receipts",
    )
    value.add_argument(
        "--round-id",
        choices=("round-1", "round-2"),
        action=UniqueValueAction,
    )
    return value


def validate_runtime_selection(arguments: argparse.Namespace) -> str | None:
    explicit = [arguments.wine_root, arguments.wine, arguments.wineserver, arguments.version]
    provided = [value is not None for value in explicit]
    if any(provided) and not all(provided):
        raise AcceptanceError("wine-root, wine, wineserver and version must be provided together")
    if any(provided) and arguments.runtime_id is None:
        raise AcceptanceError("--runtime-id is required with an explicit Runtime quartet")
    if arguments.runtime_id is not None and not all(provided):
        raise AcceptanceError("--runtime-id requires an explicit Runtime quartet")
    if all(provided) and any(not isinstance(value, str) or not value for value in explicit):
        raise AcceptanceError("explicit Runtime quartet values must be non-empty")
    return arguments.runtime_id


def validate_interaction_selection(
    arguments: argparse.Namespace,
    runtime_id: str | None,
) -> None:
    fields = (
        arguments.interaction_plan,
        arguments.acknowledgement_root,
        arguments.round_id,
    )
    if arguments.accept_interactive:
        if any(value is None for value in fields):
            raise AcceptanceError(
                "--accept-interactive requires interaction-plan, acknowledgement-root and round-id"
            )
        if runtime_id not in RUNTIME_IDS:
            raise AcceptanceError("--accept-interactive requires an explicit Runtime identity")
    elif any(value is not None for value in fields):
        raise AcceptanceError(
            "interaction-plan, acknowledgement-root and round-id require --accept-interactive"
        )


def failure_class(reason_code: str) -> str:
    try:
        return FAILURE_CLASS_BY_REASON_CODE[reason_code]
    except KeyError as error:
        raise AcceptanceError("failure reason code is not recognized") from error


def failure_status(reason_code: str) -> str:
    try:
        return STATUS_BY_REASON_CODE[reason_code]
    except KeyError as error:
        raise AcceptanceError("failure reason status is not recognized") from error


def failure_reason(stage: str) -> str:
    try:
        return FAILURE_REASON_BY_STAGE[stage]
    except KeyError as error:
        raise AcceptanceError("failure stage is not recognized") from error


def set_application_outcome(
    evidence: dict[str, object],
    status_value: str,
    reason_code: str | None = None,
    *,
    diagnostic: str | None = None,
) -> None:
    if status_value not in STATUSES:
        raise AcceptanceError("application status is not recognized")
    if status_value == "accepted":
        if reason_code is not None:
            raise AcceptanceError("accepted application must not include a reason code")
        evidence["status"] = status_value
        evidence.pop("failureClass", None)
        evidence.pop("reasonCode", None)
        evidence.pop("reason", None)
        evidence.pop("diagnostics", None)
        return
    if reason_code is None:
        raise AcceptanceError("non-accepted application status requires a reason code")
    expected_status = failure_status(reason_code)
    if status_value != expected_status:
        raise AcceptanceError("application status and reason code do not match")
    class_value = failure_class(reason_code)
    _validate_diagnostic_history(evidence)
    evidence["status"] = status_value
    evidence["reasonCode"] = reason_code
    evidence["failureClass"] = class_value
    if diagnostic is not None:
        _append_diagnostic(evidence, status_value, reason_code, diagnostic)
        evidence["reason"] = diagnostic[:MAX_DIAGNOSTIC_CHARS]


def _append_diagnostic(
    evidence: dict[str, object],
    status_value: str,
    reason_code: str,
    diagnostic: str,
) -> None:
    if not isinstance(diagnostic, str):
        raise AcceptanceError("diagnostic detail must be text")
    if status_value != failure_status(reason_code):
        raise AcceptanceError("diagnostic status and reason code do not match")
    class_value = failure_class(reason_code)
    existing = _validate_diagnostic_history(evidence)
    if "diagnostics" not in evidence:
        evidence["diagnostics"] = existing
    sequence = existing[-1]["sequence"] + 1 if existing else 1
    if len(existing) >= MAX_DIAGNOSTICS:
        del existing[1 if len(existing) > 1 else 0]
    existing.append(
        {
            "sequence": sequence,
            "status": status_value,
            "failureClass": class_value,
            "reasonCode": reason_code,
            "detail": diagnostic[:MAX_DIAGNOSTIC_CHARS],
        }
    )


def _validate_diagnostic_history(evidence: dict[str, object]) -> list[dict[str, object]]:
    if "diagnostics" not in evidence:
        return []
    existing = evidence["diagnostics"]
    if not isinstance(existing, list):
        raise AcceptanceError("diagnostic history must be an array")
    if len(existing) > MAX_DIAGNOSTICS:
        raise AcceptanceError("diagnostic history exceeds its bound")
    previous_sequence = 0
    for item in existing:
        if not isinstance(item, dict) or set(item) != {
            "sequence",
            "status",
            "failureClass",
            "reasonCode",
            "detail",
        }:
            raise AcceptanceError("diagnostic history entry is invalid")
        if (
            not isinstance(item["sequence"], int)
            or isinstance(item["sequence"], bool)
            or item["sequence"] <= previous_sequence
            or item["status"] not in STATUSES[1:]
            or item["failureClass"] not in FAILURE_CLASSES
            or not isinstance(item["reasonCode"], str)
            or item["reasonCode"] not in FAILURE_CLASS_BY_REASON_CODE
            or item["failureClass"] != FAILURE_CLASS_BY_REASON_CODE[item["reasonCode"]]
            or not isinstance(item["detail"], str)
            or len(item["detail"]) > MAX_DIAGNOSTIC_CHARS
        ):
            raise AcceptanceError("diagnostic history entry is invalid")
        if item["status"] != failure_status(item["reasonCode"]):
            raise AcceptanceError("diagnostic history entry is invalid")
        previous_sequence = item["sequence"]
    return existing


def apply_stage_outcome(
    evidence: dict[str, object],
    stage: str,
    *,
    diagnostic: str,
) -> None:
    reason_code = failure_reason(stage)
    if stage in BLOCKED_STAGES:
        status_value = "blocked"
    elif stage in UNVERIFIED_STAGES:
        status_value = "unverified"
    else:
        status_value = "failed"
    set_application_outcome(evidence, status_value, reason_code, diagnostic=diagnostic)


def bind_runtime_identity(
    runtime_id: str | None,
    receipt: dict[str, object],
    applications: list[dict[str, object]],
) -> None:
    if runtime_id is not None and runtime_id not in RUNTIME_IDS:
        raise AcceptanceError("Runtime identity is not recognized")
    if "runtimeId" in receipt and receipt["runtimeId"] != runtime_id:
        raise AcceptanceError("bootstrap receipt Runtime identity does not match the request")
    receipt["runtimeId"] = runtime_id
    for application in applications:
        if "runtimeId" in application and application["runtimeId"] != runtime_id:
            raise AcceptanceError("application Runtime identity does not match the request")
        application["runtimeId"] = runtime_id


def validate_runtime_descriptor(
    receipt: dict[str, object],
    context: object,
    requested_storage: Path,
) -> tuple[dict[str, object], Path]:
    if receipt.get("schemaVersion") != "1":
        raise AcceptanceError("bootstrap receipt schemaVersion is invalid")
    for field in ("source", "version", "packId"):
        if not isinstance(receipt.get(field), str) or not receipt[field]:
            raise AcceptanceError("bootstrap receipt omitted Runtime identity")
    pack_digest = receipt.get("packDigest")
    if not isinstance(pack_digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", pack_digest) is None:
        raise AcceptanceError("bootstrap receipt pack digest is invalid")
    if not isinstance(context, dict):
        raise AcceptanceError("bootstrap context is not an object")
    if context.get("schemaVersion") != "1":
        raise AcceptanceError("bootstrap context schemaVersion is invalid")
    storage_value = context.get("storageRoot")
    if not isinstance(storage_value, str):
        raise AcceptanceError("bootstrap context omitted storageRoot")
    canonical_storage = absolute(storage_value, "bootstrap context storageRoot")
    try:
        requested_resolved = requested_storage.resolve(strict=False)
        canonical_resolved = canonical_storage.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise AcceptanceError("bootstrap context storageRoot could not be resolved") from error
    if canonical_resolved != requested_resolved:
        raise AcceptanceError("bootstrap context storageRoot does not match the request")
    if not isinstance(context.get("supervisor"), dict):
        raise AcceptanceError("bootstrap context omitted supervisor policy")
    bindings = context.get("runtimeBindings")
    if not isinstance(bindings, list) or len(bindings) != 1 or not isinstance(bindings[0], dict):
        raise AcceptanceError("bootstrap context Runtime binding is invalid")
    binding = bindings[0]
    if binding.get("packId") != receipt["packId"] or binding.get("packDigest") != pack_digest:
        raise AcceptanceError("bootstrap receipt and context Runtime bindings differ")
    return context, canonical_storage


def _compact_exit(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    present = value.get("present")
    code = value.get("code")
    success = value.get("success")
    if present is not None and not isinstance(present, bool):
        raise AcceptanceError("compact exit present flag is invalid")
    if code is not None and (not isinstance(code, int) or isinstance(code, bool)):
        raise AcceptanceError("compact exit code is invalid")
    if success is not None and not isinstance(success, bool):
        raise AcceptanceError("compact exit success flag is invalid")
    return {
        "present": present is True,
        "code": code,
        "success": success is True,
    }


def _scan_compact_scalars(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        if depth > MAX_COMPACT_DEPTH:
            raise AcceptanceError("compact summary exceeds structural bounds")
        visited += 1
        if visited > MAX_COMPACT_NODES:
            raise AcceptanceError("compact summary exceeds structural bounds")
        if isinstance(current, dict):
            children = len(current) * 2
            remaining = MAX_COMPACT_NODES - visited - len(stack)
            if children > remaining or (current and depth >= MAX_COMPACT_DEPTH):
                raise AcceptanceError("compact summary exceeds structural bounds")
            for key, nested in current.items():
                if not isinstance(key, str):
                    raise AcceptanceError("compact summary text is invalid")
                stack.append((nested, depth + 1))
                stack.append((key, depth + 1))
        elif isinstance(current, list):
            children = len(current)
            remaining = MAX_COMPACT_NODES - visited - len(stack)
            if children > remaining or (current and depth >= MAX_COMPACT_DEPTH):
                raise AcceptanceError("compact summary exceeds structural bounds")
            for nested in current:
                stack.append((nested, depth + 1))
        elif isinstance(current, str):
            _validate_compact_text(current)
        elif current is not None and not isinstance(current, (bool, int)):
            raise AcceptanceError("compact summary contains an unsupported value type")


def _validate_compact_text(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise AcceptanceError("compact summary text is invalid")
    if len(value) > MAX_COMPACT_TEXT_CHARS:
        raise AcceptanceError("compact summary text exceeds its bound")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise AcceptanceError("compact summary text contains control characters")
    if "/" in value or "\\" in value or "file:" in value.casefold():
        raise AcceptanceError("compact summary text contains path material")
    return value


def _require_exact_keys(
    value: dict[str, object],
    required: set[str],
    optional: set[str],
    label: str,
) -> None:
    keys = set(value)
    if not required.issubset(keys) or not keys.issubset(required | optional):
        raise AcceptanceError(f"{label} keys are invalid")


def _require_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise AcceptanceError(f"{label} must be a boolean")
    return value


def _require_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AcceptanceError(f"{label} must be non-empty text")
    return value


def _validate_exit_projection(value: object, label: str) -> None:
    if not isinstance(value, dict):
        raise AcceptanceError(f"{label} must be an object")
    _require_exact_keys(value, {"present", "code", "success"}, set(), label)
    _require_bool(value["present"], f"{label}.present")
    code = value["code"]
    if code is not None and (not isinstance(code, int) or isinstance(code, bool)):
        raise AcceptanceError(f"{label}.code must be an integer or null")
    _require_bool(value["success"], f"{label}.success")


def validate_compact_summary(value: object) -> None:
    if not isinstance(value, dict):
        raise AcceptanceError("compact summary must be an object")
    _require_exact_keys(value, {"schemaVersion", "receipt", "applications"}, set(), "compact summary")
    if value["schemaVersion"] != "1":
        raise AcceptanceError("compact summary schemaVersion must be 1")
    receipt = value["receipt"]
    if not isinstance(receipt, dict):
        raise AcceptanceError("compact receipt must be an object")
    _require_exact_keys(
        receipt,
        {"schemaVersion", "runtimeId", "packId", "version", "packDigest", "source"},
        {"activated"},
        "compact receipt",
    )
    if receipt["schemaVersion"] != "1":
        raise AcceptanceError("compact receipt schemaVersion must be 1")
    runtime_id = receipt["runtimeId"]
    if runtime_id is not None and runtime_id not in RUNTIME_IDS:
        raise AcceptanceError("compact receipt Runtime identity is invalid")
    for field in ("packId", "version", "source"):
        _require_text(receipt[field], f"compact receipt {field}")
    digest = receipt["packDigest"]
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise AcceptanceError("compact receipt packDigest is invalid")
    if "activated" in receipt:
        _require_bool(receipt["activated"], "compact receipt activated")

    applications = value["applications"]
    if not isinstance(applications, list):
        raise AcceptanceError("compact applications must be an array")
    seen: set[str] = set()
    for application in applications:
        if not isinstance(application, dict):
            raise AcceptanceError("compact application must be an object")
        _require_exact_keys(
            application,
            {"schemaVersion", "runtimeId", "appId", "status", "cleanup"},
            {
                "assetSha256",
                "failureClass",
                "reasonCode",
                "interactionChecks",
                "installerExit",
                "exit",
                "windowAvailable",
                "screenshotAvailable",
            },
            "compact application",
        )
        if application["schemaVersion"] != "1" or application["runtimeId"] != runtime_id:
            raise AcceptanceError("compact application identity is invalid")
        app_id = application["appId"]
        if not isinstance(app_id, str) or app_id not in REQUIRED_INTERACTIONS or app_id in seen:
            raise AcceptanceError("compact application id is invalid")
        seen.add(app_id)
        status_value = application["status"]
        if status_value not in STATUSES:
            raise AcceptanceError("compact application status is invalid")
        _require_bool(application["cleanup"], "compact application cleanup")
        if status_value == "accepted":
            if "failureClass" in application or "reasonCode" in application:
                raise AcceptanceError("accepted compact application includes failure metadata")
        else:
            reason_code = application.get("reasonCode")
            class_value = application.get("failureClass")
            if (
                not isinstance(reason_code, str)
                or class_value != failure_class(reason_code)
                or status_value != failure_status(reason_code)
            ):
                raise AcceptanceError("compact application failure metadata is invalid")
        asset_sha256 = application.get("assetSha256")
        if asset_sha256 is not None and (
            not isinstance(asset_sha256, str) or re.fullmatch(r"[0-9a-f]{64}", asset_sha256) is None
        ):
            raise AcceptanceError("compact application assetSha256 is invalid")
        interactions = application.get("interactionChecks")
        if interactions is not None:
            if not isinstance(interactions, dict):
                raise AcceptanceError("compact interaction checks must be an object")
            required = set(REQUIRED_INTERACTIONS[app_id])
            _require_exact_keys(interactions, required, set(), "compact interaction checks")
            for checked in interactions.values():
                if _require_bool(checked, "compact interaction check") is not True:
                    raise AcceptanceError("compact interaction check must be true")
        for field in ("installerExit", "exit"):
            if field in application:
                _validate_exit_projection(application[field], f"compact application {field}")
        for field in ("windowAvailable", "screenshotAvailable"):
            if field in application:
                _require_bool(application[field], f"compact application {field}")
    _scan_compact_scalars(value)


def compact_summary(
    receipt: dict[str, object],
    applications: list[dict[str, object]],
) -> dict[str, object]:
    if not isinstance(receipt, dict) or not isinstance(applications, list):
        raise AcceptanceError("full summary inputs are invalid")
    runtime_id = receipt.get("runtimeId")
    if runtime_id is not None and runtime_id not in RUNTIME_IDS:
        raise AcceptanceError("receipt Runtime identity is not recognized")
    required_receipt = ("schemaVersion", "runtimeId", "packId", "version", "packDigest", "source")
    if any(key not in receipt for key in required_receipt):
        raise AcceptanceError("bootstrap receipt omitted compact identity")
    compact_receipt = {key: receipt[key] for key in required_receipt}
    if "activated" in receipt:
        compact_receipt["activated"] = receipt["activated"]
    compact_applications: list[dict[str, object]] = []
    for application in applications:
        if not isinstance(application, dict) or not isinstance(application.get("appId"), str):
            raise AcceptanceError("application evidence identity is invalid")
        if application.get("runtimeId") != runtime_id:
            raise AcceptanceError("receipt and application Runtime identities differ")
        status_value = application.get("status")
        if status_value not in STATUSES:
            raise AcceptanceError("application status is not recognized")
        projected = {
            key: application[key]
            for key in ("schemaVersion", "runtimeId", "appId", "assetSha256", "status", "cleanup")
            if key in application
        }
        if status_value == "accepted":
            if any(
                key in application
                for key in ("failureClass", "reasonCode", "reason", "diagnostics")
            ):
                raise AcceptanceError("accepted application includes failure metadata")
        else:
            reason_code = application.get("reasonCode")
            class_value = application.get("failureClass")
            if (
                not isinstance(reason_code, str)
                or class_value != failure_class(reason_code)
                or status_value != failure_status(reason_code)
            ):
                raise AcceptanceError("application failure metadata is invalid")
            history = _validate_diagnostic_history(application)
            if history and (
                history[-1]["status"] != status_value
                or history[-1]["failureClass"] != class_value
                or history[-1]["reasonCode"] != reason_code
            ):
                raise AcceptanceError("application diagnostic history does not match final outcome")
            projected["failureClass"] = class_value
            projected["reasonCode"] = reason_code
        interactions = application.get("interactionChecks")
        required_interactions = REQUIRED_INTERACTIONS.get(application.get("appId"))
        if interactions is not None:
            if not isinstance(interactions, dict) or required_interactions is None:
                raise AcceptanceError("application interaction checks are invalid")
            if (
                set(interactions) != set(required_interactions)
                or any(interactions.get(name) is not True for name in required_interactions)
            ):
                raise AcceptanceError("application interaction checks are invalid")
            projected["interactionChecks"] = dict(interactions)
        for source_key, target_key in (("installerExit", "installerExit"), ("exit", "exit")):
            compact_exit = _compact_exit(application.get(source_key))
            if compact_exit is not None:
                projected[target_key] = compact_exit
        windows = application.get("windows")
        if isinstance(windows, dict):
            projected["windowAvailable"] = windows.get("available") is True
        screenshot_value = application.get("screenshot")
        if isinstance(screenshot_value, dict):
            projected["screenshotAvailable"] = screenshot_value.get("available") is True
        compact_applications.append(projected)
    summary = {"schemaVersion": "1", "receipt": compact_receipt, "applications": compact_applications}
    validate_compact_summary(summary)
    return summary


def compact_json(value: object) -> str:
    validate_compact_summary(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def compact_preflight(evidence: dict[str, object]) -> dict[str, object]:
    projected = {
        key: evidence[key]
        for key in ("schemaVersion", "runtimeId", "status", "failureClass", "reasonCode")
        if key in evidence
    }
    _require_exact_keys(
        projected,
        {"schemaVersion", "runtimeId", "status", "failureClass", "reasonCode"},
        set(),
        "compact preflight",
    )
    if projected["schemaVersion"] != "1" or projected["status"] != "blocked":
        raise AcceptanceError("compact preflight identity is invalid")
    runtime_id = projected["runtimeId"]
    if runtime_id is not None and runtime_id not in RUNTIME_IDS:
        raise AcceptanceError("compact preflight Runtime identity is invalid")
    reason_code = projected["reasonCode"]
    if (
        not isinstance(reason_code, str)
        or projected["failureClass"] != failure_class(reason_code)
        or failure_status(reason_code) != "blocked"
    ):
        raise AcceptanceError("compact preflight failure metadata is invalid")
    _scan_compact_scalars(projected)
    return projected


def emit_blocked_preflight(
    work_root: Path,
    runtime_id: str | None,
    stage: str,
    diagnostic: str,
) -> int:
    evidence: dict[str, object] = {"schemaVersion": "1", "runtimeId": runtime_id}
    apply_stage_outcome(evidence, stage, diagnostic=diagnostic)
    if evidence["status"] != "blocked":
        raise AcceptanceError("preflight outcome must be blocked")
    summary = compact_preflight(evidence)
    write_json(work_root / "preflight-evidence.json", evidence)
    write_json(work_root / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 1


def rosetta_available() -> bool:
    try:
        result = subprocess.run(
            ["/usr/bin/arch", "-x86_64", "/usr/bin/true"],
            cwd=ROOT,
            env={},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def invoke(argv: list[str], *, timeout: int = MAX_COMMAND_SECONDS) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or f"{Path(argv[0]).name} returned no diagnostic"
        raise InvocationError(result.returncode, diagnostic)
    return result


def json_object(result: subprocess.CompletedProcess[str], label: str) -> dict[str, object]:
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AcceptanceError(f"{label} did not return JSON") from error
    if not isinstance(value, dict):
        raise AcceptanceError(f"{label} did not return an object")
    return value


def run_events(result: subprocess.CompletedProcess[str], label: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for line in result.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise AcceptanceError(f"{label} emitted invalid RuntimeEvent JSON") from error
        if not isinstance(value, dict):
            raise AcceptanceError(f"{label} emitted a non-object RuntimeEvent")
        events.append(value)
    if not events:
        raise AcceptanceError(f"{label} emitted no RuntimeEvent")
    return events


def exit_observation(events: list[dict[str, object]]) -> dict[str, object]:
    """Return the terminal exit evidence in a stable, compact projection."""
    event = next((value for value in reversed(events) if value.get("kind") == "exited"), None)
    if event is None:
        return {"present": False}
    exit_value = event.get("exit")
    if not isinstance(exit_value, dict):
        return {"present": False}
    return {
        "present": True,
        "code": exit_value.get("code"),
        "success": exit_value.get("success") is True,
    }


def process_table() -> list[tuple[int, int, str]]:
    """Return a bounded macOS process table projection without shelling out."""
    if platform.system() != "Darwin":
        return []
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,pgid=,command="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows: list[tuple[int, int, str]] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(maxsplit=2)
        if len(parts) != 3:
            continue
        try:
            rows.append((int(parts[0]), int(parts[1]), parts[2]))
        except ValueError:
            continue
    return rows


def process_snapshot(marker: str, process_group_id: int | None = None) -> list[str]:
    """List residual commands tied to either the Bottle path or launch group."""
    current = os.getpid()
    rows = process_table()
    if not rows:
        return ["process observation unavailable"]
    return [
        f"{pid} {command}"
        for pid, pgid, command in rows
        if pid != current and (marker in command or (process_group_id is not None and pgid == process_group_id))
    ]


def process_group_ids(process_group_id: int) -> list[int]:
    return [pid for pid, pgid, _command in process_table() if pgid == process_group_id]


def matching_windows(output: str, title_tokens: tuple[str, ...]) -> list[dict[str, object]]:
    matching: list[dict[str, object]] = []
    for line in output.splitlines():
        parts = line.strip().split("|", 2)
        if len(parts) != 3 or not any(token.casefold() in parts[1].casefold() for token in title_tokens):
            continue
        dimensions = parts[2].split("x", 1)
        try:
            process_id = int(parts[0])
            width = int(dimensions[0])
            height = int(dimensions[1])
        except (ValueError, IndexError):
            continue
        if width <= 0 or height <= 0:
            continue
        matching.append({"processId": process_id, "title": parts[1], "width": width, "height": height})
    return matching


def parse_event_line(line: str, label: str) -> dict[str, object]:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as error:
        raise AcceptanceError(f"{label} emitted invalid RuntimeEvent JSON") from error
    if not isinstance(value, dict):
        raise AcceptanceError(f"{label} emitted a non-object RuntimeEvent")
    return value


def observed_launch(
    argv: list[str],
    screenshot_path: Path,
    title_tokens: tuple[str, ...],
    *,
    timeout: int = MAX_COMMAND_SECONDS,
) -> tuple[list[dict[str, object]], dict[str, object], dict[str, object], int | None]:
    """Keep the Core launch process alive while collecting visual evidence."""
    process = subprocess.Popen(
        argv,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        raise AcceptanceError("GUI launch pipes were not created")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    started = time.monotonic()
    windows: dict[str, object] = {"available": False, "reason": "observation pending"}
    shot: dict[str, object] = {"available": False, "path": str(screenshot_path)}
    events: list[dict[str, object]] = []
    root_process_id: int | None = None
    next_observation = started
    while process.poll() is None:
        elapsed = time.monotonic() - started
        for key, _mask in selector.select(timeout=0.1):
            line = key.fileobj.readline()
            if not line:
                continue
            event = parse_event_line(line, "GUI launch")
            events.append(event)
            if event.get("kind") == "started" and isinstance(event.get("processId"), int):
                root_process_id = event["processId"]
        now = time.monotonic()
        if (
            root_process_id is not None
            and not windows.get("available")
            and elapsed <= WINDOW_APPEARANCE_SECONDS
            and now >= next_observation
        ):
            windows = observer(root_process_id, title_tokens)
            if windows.get("available") is True:
                shot = screenshot(screenshot_path)
            next_observation = now + 0.5
        if elapsed >= timeout:
            process.kill()
            process.wait(timeout=10)
            raise AcceptanceError("GUI launch exceeded the bounded observation timeout")
        time.sleep(0.1)
    selector.unregister(process.stdout)
    selector.close()
    for line in process.stdout.read().splitlines():
        if line.strip():
            events.append(parse_event_line(line, "GUI launch"))
    stderr = process.stderr.read()
    process.wait(timeout=10)
    if process.returncode != 0:
        detail = stderr.strip().splitlines()[-1] if stderr.strip() else "no stderr"
        raise AcceptanceError(f"GUI launch failed: {detail}")
    if not events:
        raise AcceptanceError("GUI launch emitted no RuntimeEvent")
    return events, windows, shot, root_process_id


def status(events: list[dict[str, object]]) -> str:
    exit_event = next((event for event in reversed(events) if event.get("kind") == "exited"), None)
    if exit_event is None:
        return "accepted" if any(event.get("kind") == "terminate-requested" for event in events) else "failed"
    exit_value = exit_event.get("exit")
    if isinstance(exit_value, dict) and exit_value.get("success") is True:
        return "accepted"
    return "failed"


def evaluate_application_outcome(
    evidence: dict[str, object],
    app_id: str,
    events: list[dict[str, object]],
    windows: dict[str, object],
    shot: dict[str, object],
    residual: list[str],
    checks: dict[str, bool],
) -> None:
    if residual:
        apply_stage_outcome(
            evidence,
            "cleanup-residual",
            diagnostic="launch left residual processes",
        )
        return
    if status(events) != "accepted":
        stage = (
            "cleanup-termination"
            if any(event.get("kind") == "terminate-requested" for event in events)
            else "application-content"
        )
        apply_stage_outcome(
            evidence,
            stage,
            diagnostic=(
                "requested application termination was not successful"
                if stage == "cleanup-termination"
                else "application exit evidence is not successful"
            ),
        )
        return
    if windows.get("available") is not True or shot.get("available") is not True:
        apply_stage_outcome(
            evidence,
            "desktop-window",
            diagnostic="target window or screenshot evidence is incomplete",
        )
        return
    interactions_complete = all(checks.get(name) is True for name in REQUIRED_INTERACTIONS[app_id])
    if not interactions_complete:
        apply_stage_outcome(
            evidence,
            "application-interaction",
            diagnostic="required per-application interaction evidence was not supplied",
        )
        return
    set_application_outcome(evidence, "accepted")


def installer_succeeded(
    evidence: dict[str, object],
    events: list[dict[str, object]],
    installed: Path,
) -> bool:
    if status(events) != "accepted":
        stage = (
            "cleanup-termination"
            if any(event.get("kind") == "terminate-requested" for event in events)
            else "installer-launch"
        )
        apply_stage_outcome(
            evidence,
            stage,
            diagnostic=(
                "requested installer termination was not successful"
                if stage == "cleanup-termination"
                else "installer exit evidence is not successful"
            ),
        )
        return False
    if not installed.is_file() or installed.is_symlink():
        apply_stage_outcome(
            evidence,
            "installer-launch",
            diagnostic="installer exited but expected GUI executable was not found",
        )
        return False
    return True


def asset_preflight(
    evidence: dict[str, object],
    cache_entry: Path,
    allow_network: bool,
) -> bool:
    if not allow_network and not cache_entry.exists():
        apply_stage_outcome(
            evidence,
            "preflight-network",
            diagnostic="asset is not cached and network access was not enabled",
        )
        return False
    return True


def observer(process_group_id: int, title_tokens: tuple[str, ...]) -> dict[str, object]:
    if platform.system() != "Darwin":
        return {"available": False, "reason": "window observation requires macOS"}
    target_ids = process_group_ids(process_group_id)
    if not target_ids:
        return {"available": False, "reason": "launch process group is no longer visible", "processGroupId": process_group_id}
    ids = ",".join(str(value) for value in target_ids)
    script = (
        'tell application "System Events"\n'
        "set resultText to {}\n"
        f"set targetIds to {{{ids}}}\n"
        "repeat with p in (every process whose background only is false)\n"
        "if targetIds contains (unix id of p) then\n"
        "repeat with w in (every window of p)\n"
        "set t to title of w\n"
        "set windowSize to size of w\n"
        "if t is not missing value and t is not \"\" then set end of resultText to ((unix id of p as text) & \"|\" & t & \"|\" & (item 1 of windowSize as text) & \"x\" & (item 2 of windowSize as text))\n"
        "end repeat\n"
        "end if\n"
        "end repeat\n"
        "set AppleScript's text item delimiters to linefeed\n"
        "return resultText as text\n"
        "end tell"
    )
    try:
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", script],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "reason": "osascript unavailable"}
    if result.returncode != 0:
        return {"available": False, "reason": "Accessibility permission unavailable"}
    matching = matching_windows(result.stdout, title_tokens)
    if matching:
        return {
            "available": True,
            "processGroupId": process_group_id,
            "processIds": target_ids,
            "expectedTitleTokens": list(title_tokens),
            "windows": matching[:32],
        }
    fallback_script = (
        "tell application \"System Events\"\\n"
        "set resultText to {}\\n"
        "repeat with p in (every application process whose background only is false)\\n"
        "repeat with w in (every window of p)\\n"
        "set t to title of w\\n"
        "set windowSize to size of w\\n"
        "if t is not missing value and t is not \"\" then\\n"
        "set end of resultText to ((name of p as text) & \"|\" & (unix id of p as text) & \"|\" & t & \"|\" & (item 1 of windowSize as text) & \"x\" & (item 2 of windowSize as text))\\n"
        "end if\\n"
        "end repeat\\n"
        "end repeat\\n"
        "set AppleScript's text item delimiters to linefeed\\n"
        "return resultText as text\\n"
        "end tell"
    )
    fallback = subprocess.run(
        ["/usr/bin/osascript", "-e", fallback_script],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if fallback.returncode == 0:
        matching_all = matching_windows(fallback.stdout, title_tokens)
        if matching_all:
            return {
                "available": True,
                "processGroupId": process_group_id,
                "processIds": target_ids,
                "expectedTitleTokens": list(title_tokens),
                "windows": matching_all[:32],
            }
    return {
        "available": False,
        "reason": "launch process group is no longer visible",
        "processGroupId": process_group_id,
    }


def screenshot(path: Path) -> dict[str, object]:
    try:
        result = subprocess.run(
            ["/usr/sbin/screencapture", "-x", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "reason": "screencapture unavailable"}
    return {"available": result.returncode == 0 and path.is_file() and path.stat().st_size > 0, "path": str(path)}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _acknowledgement_protocol():  # type: ignore[no-untyped-def]
    import confirm_macos_gui_interactions  # type: ignore[import-not-found]

    return confirm_macos_gui_interactions


def _interaction_failure(error: BaseException) -> AcceptanceError:
    message = str(error)
    if "cleanup" in message:
        return InteractionCleanupError("application interaction cleanup failed")
    if "root identity changed" in message or "parent identity changed" in message:
        return InteractionIntegrityError("application interaction root identity changed")
    return InteractionInvalidError("application interaction acknowledgement is invalid")


def read_interaction_plan(
    path: Path,
    round_id: str,
    runtime_id: str,
    directory: object | None = None,
) -> dict[str, dict[str, list[str]]]:
    protocol = _acknowledgement_protocol()
    try:
        raw = protocol._read_file(path, "interaction plan", directory)
        value = protocol._parse_json(raw, "interaction plan")
        if raw != protocol._canonical_bytes(value, "interaction plan"):
            raise InteractionInvalidError("interaction plan bytes are non-canonical")
    except InteractionInvalidError:
        raise
    except (protocol.AcknowledgementError, OSError) as error:
        raise InteractionInvalidError("interaction plan is invalid") from error
    if (
        type(value) is not dict
        or set(value) != {"schemaVersion", "roundId", "runtimeId", "applications"}
        or value["schemaVersion"] != "1"
        or value["roundId"] != round_id
        or value["runtimeId"] != runtime_id
    ):
        raise InteractionInvalidError("interaction plan is invalid")
    applications = value.get("applications")
    if type(applications) is not dict or set(applications) != set(REQUIRED_INTERACTIONS):
        raise InteractionInvalidError("interaction plan is invalid")
    result: dict[str, dict[str, list[str]]] = {}
    for app_id, required in REQUIRED_INTERACTIONS.items():
        application = applications.get(app_id)
        if (
            type(application) is not dict
            or set(application) != {"requiredChecks"}
            or type(application["requiredChecks"]) is not list
            or application["requiredChecks"] != list(required)
        ):
            raise InteractionInvalidError("interaction plan is invalid")
        result[app_id] = {"requiredChecks": list(required)}
    return result


@dataclass(slots=True)
class InteractionSession:
    plan_path: Path
    acknowledgement_root: Path
    round_id: str
    runtime_id: str
    plan: dict[str, dict[str, list[str]]]
    bindings: tuple[object, ...]
    closed: bool = False

    @property
    def challenge_binding(self) -> object:
        return self.bindings[3]

    @property
    def receipt_binding(self) -> object:
        return self.bindings[4]

    def _revalidate(self) -> None:
        if self.closed:
            raise InteractionIntegrityError("application interaction session is closed")
        protocol = _acknowledgement_protocol()
        labels = (
            "repository root",
            "interaction plan root",
            "acknowledgement root",
            "challenges root",
            "receipts root",
        )
        try:
            for binding, label in zip(self.bindings, labels):
                protocol._revalidate_directory(binding, label)
        except protocol.AcknowledgementError as error:
            raise InteractionIntegrityError(
                "application interaction root identity changed"
            ) from error

    def _entry_identity(self, binding: object, name: str, label: str) -> tuple[int, int, int, int, int]:
        protocol = _acknowledgement_protocol()
        try:
            metadata = protocol._relative_stat(binding, name)
        except OSError as error:
            raise InteractionInvalidError(
                "application interaction acknowledgement is invalid"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or protocol._is_reparse(metadata)
            or metadata.st_nlink != 1
        ):
            raise InteractionInvalidError(f"{label} entry is invalid")
        return protocol._file_identity(metadata)

    def _entry_absent(self, binding: object, name: str) -> None:
        protocol = _acknowledgement_protocol()
        self._revalidate()
        try:
            protocol._relative_stat(binding, name)
        except FileNotFoundError:
            return
        except OSError as error:
            raise InteractionInvalidError(
                "application interaction acknowledgement is invalid"
            ) from error
        raise InteractionInvalidError("application interaction acknowledgement is invalid")

    def _assert_challenge_unchanged(
        self,
        name: str,
        path: Path,
        challenge: dict[str, object],
        identity: tuple[int, int, int, int, int],
    ) -> None:
        protocol = _acknowledgement_protocol()
        try:
            if (
                self._entry_identity(self.challenge_binding, name, "challenge")
                != identity
                or protocol.read_challenge(path, self.challenge_binding)
                != challenge
            ):
                raise InteractionInvalidError(
                    "application interaction challenge is invalid"
                )
        except protocol.AcknowledgementError as error:
            raise InteractionInvalidError(
                "application interaction challenge is invalid"
            ) from error

    def _consume_owned(
        self,
        binding: object,
        name: str,
        identity: tuple[int, int, int, int, int],
        *,
        tolerate_substitution: bool,
    ) -> None:
        protocol = _acknowledgement_protocol()
        try:
            self._revalidate()
            metadata = protocol._relative_stat(binding, name)
            current = protocol._file_identity(metadata)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or protocol._is_reparse(metadata)
                or metadata.st_nlink != 1
                or current != identity
            ):
                if tolerate_substitution:
                    return
                raise InteractionCleanupError("application interaction cleanup failed")
            invalidated = protocol._invalidate_relative_if_owned(
                binding, name, identity[:3]
            )
            if not invalidated:
                if tolerate_substitution:
                    return
                raise InteractionCleanupError("application interaction cleanup failed")
            protocol._sync_directory(binding)
            try:
                final = protocol._relative_stat(binding, name)
            except OSError as error:
                raise InteractionCleanupError(
                    "application interaction cleanup failed"
                ) from error
            if (
                not stat.S_ISREG(final.st_mode)
                or stat.S_ISLNK(final.st_mode)
                or protocol._is_reparse(final)
                or final.st_nlink != 1
                or protocol._node_identity(final) != identity[:3]
                or final.st_size != identity[3]
                or protocol._read_file(
                    binding.path / name,
                    "consumed interaction",
                    binding,
                )[:1]
                != b"!"
            ):
                raise InteractionCleanupError("application interaction cleanup failed")
            self._revalidate()
        except InteractionIntegrityError:
            raise
        except InteractionCleanupError:
            raise
        except OSError as error:
            raise InteractionCleanupError("application interaction cleanup failed") from error

    def acknowledge_application(
        self,
        *,
        app_id: str,
        runtime_version: str,
        pack_digest: str,
        asset_digest: str,
        window_observed: bool,
        nonce_source: Callable[[int], str] = secrets.token_hex,
        monotonic: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
        deadline_seconds: float = ACKNOWLEDGEMENT_WAIT_SECONDS,
        wait_for_acknowledgement: (
            Callable[[dict[str, object], Path, Path], bool | None] | None
        ) = None,
    ) -> dict[str, bool]:
        if window_observed is not True:
            return {}
        if (
            app_id not in REQUIRED_INTERACTIONS
            or type(deadline_seconds) not in (int, float)
            or isinstance(deadline_seconds, bool)
            or not 0 < deadline_seconds <= ACKNOWLEDGEMENT_WAIT_SECONDS
            or not callable(nonce_source)
            or not callable(monotonic)
            or not callable(sleeper)
            or (
                wait_for_acknowledgement is not None
                and not callable(wait_for_acknowledgement)
            )
        ):
            raise InteractionInvalidError("application interaction request is invalid")
        protocol = _acknowledgement_protocol()
        name = f"{self.round_id}--{self.runtime_id}--{app_id}.json"
        challenge_path = self.acknowledgement_root / "challenges" / name
        receipt_path = self.acknowledgement_root / "receipts" / name
        challenge_identity: tuple[int, int, int, int, int] | None = None
        receipt_identity: tuple[int, int, int, int, int] | None = None
        challenge_consumed = False
        receipt_consumed = False
        try:
            self._entry_absent(self.challenge_binding, name)
            self._entry_absent(self.receipt_binding, name)
            challenge = protocol.make_challenge(
                round_id=self.round_id,
                runtime_id=self.runtime_id,
                runtime_version=runtime_version,
                app_id=app_id,
                pack_digest=pack_digest,
                asset_digest=asset_digest,
                nonce_source=nonce_source,
            )
            if challenge["requiredChecks"] != self.plan[app_id]["requiredChecks"]:
                raise InteractionInvalidError("application interaction plan is invalid")
            protocol.write_challenge(
                challenge_path, challenge, self.challenge_binding
            )
            challenge_identity = self._entry_identity(
                self.challenge_binding, name, "challenge"
            )
            deadline = monotonic() + float(deadline_seconds)
            if wait_for_acknowledgement is not None:
                callback_result = wait_for_acknowledgement(
                    dict(challenge), challenge_path, receipt_path
                )
                self._assert_challenge_unchanged(
                    name, challenge_path, challenge, challenge_identity
                )
                if callback_result is False:
                    raise InteractionUnverifiedError(
                        "application interaction was not acknowledged"
                    )
                if callback_result is not None and callback_result is not True:
                    raise InteractionInvalidError(
                        "application interaction acknowledgement is invalid"
                    )
            while True:
                self._revalidate()
                self._assert_challenge_unchanged(
                    name, challenge_path, challenge, challenge_identity
                )
                try:
                    protocol._relative_stat(self.receipt_binding, name)
                except FileNotFoundError:
                    now = monotonic()
                    if now >= deadline:
                        raise InteractionUnverifiedError(
                            "application interaction acknowledgement timed out"
                        )
                    sleeper(min(ACKNOWLEDGEMENT_POLL_SECONDS, deadline - now))
                    continue
                except OSError as error:
                    raise InteractionInvalidError(
                        "application interaction acknowledgement is invalid"
                    ) from error
                break
            receipt_identity = self._entry_identity(
                self.receipt_binding, name, "acknowledgement"
            )
            acknowledgement = protocol.read_acknowledgement(
                receipt_path, self.receipt_binding
            )
            checks = protocol.validate_acknowledgement(
                challenge, acknowledgement
            )
            self._consume_owned(
                self.receipt_binding,
                name,
                receipt_identity,
                tolerate_substitution=False,
            )
            receipt_consumed = True
            self._consume_owned(
                self.challenge_binding,
                name,
                challenge_identity,
                tolerate_substitution=False,
            )
            challenge_consumed = True
            return checks
        except InteractionIntegrityError:
            raise
        except InteractionCleanupError:
            raise
        except InteractionUnverifiedError:
            if challenge_identity is not None and not challenge_consumed:
                self._consume_owned(
                    self.challenge_binding,
                    name,
                    challenge_identity,
                    tolerate_substitution=False,
                )
            raise
        except (InteractionInvalidError, protocol.AcknowledgementError, OSError) as error:
            converted = (
                error
                if isinstance(error, InteractionInvalidError)
                else _interaction_failure(error)
            )
            if receipt_identity is not None and not receipt_consumed:
                self._consume_owned(
                    self.receipt_binding,
                    name,
                    receipt_identity,
                    tolerate_substitution=True,
                )
            if challenge_identity is not None and not challenge_consumed:
                self._consume_owned(
                    self.challenge_binding,
                    name,
                    challenge_identity,
                    tolerate_substitution=True,
                )
            raise converted from error

    def close(self) -> None:
        if self.closed:
            return
        protocol = _acknowledgement_protocol()
        for binding in reversed(self.bindings):
            protocol._close_directory(binding)
        self.closed = True


def open_interaction_session(
    plan_path: Path,
    acknowledgement_root: Path,
    round_id: str,
    runtime_id: str,
) -> InteractionSession:
    protocol = _acknowledgement_protocol()
    if (
        not isinstance(plan_path, Path)
        or not isinstance(acknowledgement_root, Path)
        or round_id not in ("round-1", "round-2")
        or runtime_id not in RUNTIME_IDS
        or not plan_path.is_absolute()
        or not protocol._is_external_root(plan_path.parent)
        or not protocol._is_external_root(acknowledgement_root)
    ):
        raise InteractionIntegrityError("application interaction roots are invalid")
    held: list[object] = []
    try:
        repository, plan_root, acknowledgement = protocol._bind_watch_roots(
            plan_path.parent, acknowledgement_root
        )
        held.extend((repository, plan_root, acknowledgement))
        challenges = protocol._bind_directory(
            acknowledgement_root / "challenges", "challenges root"
        )
        held.append(challenges)
        receipts = protocol._bind_directory(
            acknowledgement_root / "receipts", "receipts root"
        )
        held.append(receipts)
        plan = read_interaction_plan(
            plan_path, round_id, runtime_id, plan_root
        )
        return InteractionSession(
            plan_path,
            acknowledgement_root,
            round_id,
            runtime_id,
            plan,
            tuple(held),
        )
    except InteractionInvalidError:
        for binding in reversed(held):
            protocol._close_directory(binding)
        raise
    except protocol.AcknowledgementError as error:
        for binding in reversed(held):
            protocol._close_directory(binding)
        raise InteractionIntegrityError(
            "application interaction roots are invalid"
        ) from error


def installed_executable(asset, bottle_root: Path) -> Path:  # type: ignore[no-untyped-def]
    """Resolve only fixed, application-specific install locations."""
    primary = bottle_root / Path(asset.installed_executable)
    candidates = [primary]
    if asset.app_id == "sumatrapdf":
        candidates.append(
            bottle_root
            / "users"
            / os.environ.get("USER", "Public")
            / "AppData"
            / "Local"
            / "SumatraPDF"
            / "SumatraPDF.exe"
        )
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return primary


def request_architecture(value: str) -> str:
    # PE inspection uses the human-readable x86 label; the public schema
    # intentionally uses the stable i386 enum.
    return "i386" if value == "x86" else value


def fetch_asset(arguments: argparse.Namespace, app_id: str) -> Path:
    from download_gui_assets import (  # type: ignore[import-not-found]
        AssetError,
        NetworkUnavailable,
        asset_for,
        fetch_classified,
    )

    try:
        path = fetch_classified(asset_for(app_id), arguments.cache_root, arguments.allow_network)
    except NetworkUnavailable as error:
        raise NetworkUnavailableError(error.diagnostic) from error
    except (AssetError, OSError) as error:
        raise AssetFetchError(str(error)) from error
    return absolute(str(path), f"{app_id} asset")


def main() -> int:
    interaction_session: InteractionSession | None = None
    try:
        arguments = parser().parse_args()
        runtime_id = validate_runtime_selection(arguments)
        validate_interaction_selection(arguments, runtime_id)
        arguments.compatforge_cli = absolute(arguments.compatforge_cli, "compatforge-cli")
        arguments.cache_root = absolute(arguments.cache_root, "cache-root", external=True)
        arguments.runtime_store = absolute(arguments.runtime_store, "runtime-store", external=True)
        arguments.storage_root = absolute(arguments.storage_root, "storage-root", external=True)
        arguments.work_root = absolute(arguments.work_root, "work-root", external=True)
        if arguments.interaction_plan is not None:
            arguments.interaction_plan = absolute(
                arguments.interaction_plan, "interaction-plan", external=True
            )
        if arguments.acknowledgement_root is not None:
            arguments.acknowledgement_root = absolute(
                arguments.acknowledgement_root,
                "acknowledgement-root",
                external=True,
            )
        arguments.work_root.mkdir(parents=True, exist_ok=True)
        if any(arguments.work_root.iterdir()):
            raise AcceptanceError("work-root must be empty")
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            return emit_blocked_preflight(
                arguments.work_root,
                runtime_id,
                "preflight-platform",
                "GUI baseline requires Darwin/arm64",
            )
        if (
            not arguments.compatforge_cli.is_file()
            or arguments.compatforge_cli.is_symlink()
            or not os.access(arguments.compatforge_cli, os.X_OK)
        ):
            return emit_blocked_preflight(
                arguments.work_root,
                runtime_id,
                "preflight-tool",
                "CompatForge CLI is unavailable or not executable",
            )
        if not rosetta_available():
            return emit_blocked_preflight(
                arguments.work_root,
                runtime_id,
                "preflight-rosetta",
                "Rosetta x86_64 execution is unavailable",
            )
        explicit = [arguments.wine_root, arguments.wine, arguments.wineserver, arguments.version]
        request = {
            "schemaVersion": "1",
            "runtimeStoreRoot": str(arguments.runtime_store),
            "storageRoot": str(arguments.storage_root),
        }
        if all(value is not None for value in explicit):
            request.update(
                {
                    "materializedRoot": str(absolute(arguments.wine_root, "wine-root")),
                    "wine": arguments.wine,
                    "wineserver": arguments.wineserver,
                    "version": arguments.version,
                }
            )
        request_path = arguments.work_root / "bootstrap-request.json"
        context_path = arguments.work_root / "context.json"
        write_json(request_path, request)
        try:
            receipt = json_object(
                invoke(
                    [str(arguments.compatforge_cli), "local", "macos", "context", str(request_path), str(context_path)]
                ),
                "bootstrap receipt",
            )
            context_value = json.loads(context_path.read_text(encoding="utf-8"))
            context, canonical_storage = validate_runtime_descriptor(
                receipt,
                context_value,
                arguments.storage_root,
            )
            bind_runtime_identity(runtime_id, receipt, [])
        except (
            AcceptanceError,
            OSError,
            UnicodeError,
            subprocess.TimeoutExpired,
            json.JSONDecodeError,
        ) as error:
            return emit_blocked_preflight(
                arguments.work_root,
                runtime_id,
                "runtime-descriptor",
                str(error),
            )
        # Rust bootstrap canonicalizes macOS aliases such as /tmp ->
        # /private/tmp. Reuse that authoritative root for Bottle paths so
        # string-boundary validation and the filesystem observe the same path.
        arguments.storage_root = canonical_storage
        supervisor = context["supervisor"]
        supervisor["maximumRuntimeMilliseconds"] = 120_000  # type: ignore[index]
        write_json(context_path, context)
        write_json(arguments.work_root / "bootstrap-receipt.json", receipt)
        if arguments.accept_interactive:
            interaction_session = open_interaction_session(
                arguments.interaction_plan,
                arguments.acknowledgement_root,
                arguments.round_id,
                runtime_id,
            )

        from download_gui_assets import ASSETS, asset_for  # type: ignore[import-not-found]

        results: list[dict[str, object]] = []
        for asset in ASSETS:
            bottle_id = f"gui-{asset.app_id}"
            bottle_root = arguments.storage_root / "bottles" / bottle_id / "prefix" / "drive_c"
            bottle_root.mkdir(parents=True, exist_ok=True)
            evidence: dict[str, object] = {
                "schemaVersion": "1",
                "runtimeId": runtime_id,
                "appId": asset.app_id,
                "assetSha256": asset.sha256,
                "bottleId": bottle_id,
                "cleanup": False,
            }
            failure_stage = "asset-fetch"
            try:
                cache_entry = arguments.cache_root / asset.filename
                if not asset_preflight(evidence, cache_entry, arguments.allow_network):
                    continue
                installer = fetch_asset(arguments, asset.app_id)
                failure_stage = "core-inspection"
                installer_inspection = json_object(
                    invoke([str(arguments.compatforge_cli), "inspect", str(installer)]),
                    f"{asset.app_id} installer inspection",
                )
                installer_architecture = installer_inspection.get("architecture")
                if not isinstance(installer_architecture, str):
                    raise AcceptanceError(f"{asset.app_id} installer inspection omitted architecture")
                evidence["installerInspection"] = installer_inspection
                inspection_request = {
                    "schemaVersion": "1",
                    "requestId": str(uuid.uuid4()),
                    "bottleId": bottle_id,
                    "executable": {
                        "path": str(installer),
                        "architecture": request_architecture(installer_architecture),
                        "mode": "immutableArtifact",
                    },
                    "arguments": list(asset.install_args),
                    "constraints": {
                        "allowVirtualMachine": False,
                        "allowRemote": False,
                        "networkPolicy": "deny",
                    },
                }
                installer_request_path = arguments.work_root / f"{asset.app_id}-installer-request.json"
                write_json(installer_request_path, inspection_request)
                failure_stage = "core-plan"
                plan = json_object(
                    invoke(
                        [
                            str(arguments.compatforge_cli),
                            "prepared-plan",
                            str(context_path),
                            str(installer),
                            str(installer_request_path),
                        ]
                    ),
                    f"{asset.app_id} installer plan",
                )
                evidence["installerPlan"] = plan
                failure_stage = "installer-launch"
                installer_events = run_events(
                    invoke(
                        [
                            str(arguments.compatforge_cli),
                            "prepared-launch-terminate",
                            str(context_path),
                            str(installer),
                            str(installer_request_path),
                            "8000",
                        ]
                    ),
                    f"{asset.app_id} installer",
                )
                evidence["installerEvents"] = installer_events
                evidence["installerExit"] = exit_observation(installer_events)
                installed = installed_executable(asset, bottle_root)
                if not installer_succeeded(evidence, installer_events, installed):
                    continue
                launch_request = {
                    "schemaVersion": "1",
                    "requestId": str(uuid.uuid4()),
                    "bottleId": bottle_id,
                    "executable": {
                        "path": str(installed),
                        "architecture": "x86_64",
                        "mode": "bottleInPlace",
                    },
                    "constraints": {
                        "allowVirtualMachine": False,
                        "allowRemote": False,
                        "networkPolicy": "deny",
                    },
                }
                launch_request_path = arguments.work_root / f"{asset.app_id}-launch-request.json"
                failure_stage = "core-inspection"
                gui_inspection = json_object(
                    invoke([str(arguments.compatforge_cli), "inspect", str(installed)]),
                    f"{asset.app_id} GUI inspection",
                )
                gui_architecture = gui_inspection.get("architecture")
                if not isinstance(gui_architecture, str):
                    raise AcceptanceError(f"{asset.app_id} GUI inspection omitted architecture")
                launch_request["executable"]["architecture"] = request_architecture(gui_architecture)  # type: ignore[index]
                write_json(launch_request_path, launch_request)
                evidence["inspection"] = gui_inspection
                failure_stage = "core-plan"
                evidence["plan"] = json_object(
                    invoke(
                        [
                            str(arguments.compatforge_cli),
                            "prepared-plan",
                            str(context_path),
                            str(installed),
                            str(launch_request_path),
                        ]
                    ),
                    f"{asset.app_id} GUI plan",
                )
                failure_stage = "desktop-launch"
                events, windows, shot, process_group_id = observed_launch(
                    [
                        str(arguments.compatforge_cli),
                        "prepared-launch-terminate",
                        str(context_path),
                        str(installed),
                        str(launch_request_path),
                        str(INTERACTIVE_RUNTIME_MILLISECONDS if arguments.accept_interactive else 30_000),
                    ],
                    arguments.work_root / f"{asset.app_id}.png",
                    asset.window_title_tokens,
                )
                evidence["events"] = events
                evidence["exit"] = exit_observation(events)
                evidence["windows"] = windows
                evidence["screenshot"] = shot
                evidence["residualProcesses"] = process_snapshot(str(bottle_root), process_group_id)
                can_acknowledge = (
                    interaction_session is not None
                    and not evidence["residualProcesses"]
                    and status(events) == "accepted"
                    and windows.get("available") is True
                    and shot.get("available") is True
                )
                if can_acknowledge:
                    try:
                        checks = interaction_session.acknowledge_application(
                            app_id=asset.app_id,
                            runtime_version=receipt["version"],
                            pack_digest=receipt["packDigest"],
                            asset_digest="sha256:" + asset.sha256,
                            window_observed=True,
                        )
                    except InteractionUnverifiedError:
                        apply_stage_outcome(
                            evidence,
                            "application-interaction",
                            diagnostic="required application interactions were not acknowledged",
                        )
                    except InteractionInvalidError:
                        apply_stage_outcome(
                            evidence,
                            "application-interaction-invalid",
                            diagnostic="application interaction acknowledgement was invalid",
                        )
                    else:
                        evidence["interactionChecks"] = checks
                        evaluate_application_outcome(
                            evidence,
                            asset.app_id,
                            events,
                            windows,
                            shot,
                            evidence["residualProcesses"],
                            checks,
                        )
                else:
                    evaluate_application_outcome(
                        evidence,
                        asset.app_id,
                        events,
                        windows,
                        shot,
                        evidence["residualProcesses"],
                        {},
                    )
            except NetworkUnavailableError as error:
                apply_stage_outcome(
                    evidence,
                    "preflight-network",
                    diagnostic=str(error),
                )
            except AssetFetchError as error:
                apply_stage_outcome(
                    evidence,
                    "asset-fetch",
                    diagnostic=str(error),
                )
            except (InteractionIntegrityError, InteractionCleanupError):
                raise
            except (AcceptanceError, OSError, subprocess.TimeoutExpired) as error:
                apply_stage_outcome(
                    evidence,
                    failure_stage,
                    diagnostic=str(error),
                )
            finally:
                cleanup_diagnostic = "Bottle cleanup failed"
                try:
                    if bottle_root.exists() or bottle_root.is_symlink():
                        if bottle_root.is_symlink():
                            raise AcceptanceError("Bottle root became a symlink")
                        shutil.rmtree(arguments.storage_root / "bottles" / bottle_id)
                    evidence["cleanup"] = True
                except (OSError, AcceptanceError) as error:
                    evidence["cleanup"] = False
                    evidence["cleanupError"] = str(error)
                    cleanup_diagnostic = str(error)
                if evidence["cleanup"] is not True:
                    apply_stage_outcome(
                        evidence,
                        "cleanup-delete",
                        diagnostic=cleanup_diagnostic,
                    )
                write_json(arguments.work_root / f"{asset.app_id}-evidence.json", evidence)
                results.append(evidence)

        bind_runtime_identity(runtime_id, receipt, results)
        summary = compact_summary(receipt, results)
        write_json(arguments.work_root / "summary.json", summary)
        print(compact_json(summary))
        return 0 if all(value["status"] == "accepted" for value in results) else 1
    except (AcceptanceError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError, ImportError) as error:
        print(f"compatforge-gui-baseline: {error}", file=sys.stderr)
        return 1
    finally:
        if interaction_session is not None:
            interaction_session.close()


if __name__ == "__main__":
    raise SystemExit(main())
