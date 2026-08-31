#!/usr/bin/env python3
"""Opt-in macOS GUI acceptance for the fixed CompatForge baseline apps.

This script intentionally uses only ``accepted``, ``failed``, ``unverified``
or ``blocked`` per application. A visible process or a blank window is never
promoted to an acceptance claim. Downloads, screenshots and evidence live in
caller-owned external directories and are excluded from the repository.
"""

from __future__ import annotations

import argparse
import hashlib
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
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
MAX_COMMAND_SECONDS = 180
WINDOW_APPEARANCE_SECONDS = 30
INTERACTIVE_RUNTIME_MILLISECONDS = 600_000
CERTIFICATION_INTERACTIVE_RUNTIME_MILLISECONDS = 60_000
ACKNOWLEDGEMENT_WAIT_SECONDS = 300
ACKNOWLEDGEMENT_POLL_SECONDS = 0.25
MAX_DIAGNOSTICS = 16
MAX_DIAGNOSTIC_CHARS = 4096
MAX_COMPACT_DEPTH = 8
MAX_COMPACT_NODES = 256
MAX_COMPACT_TEXT_CHARS = 4096
MAX_PINNED_EVIDENCE_BYTES = 1_048_576
PINNED_OUTPUT_NAME_ATTEMPTS = 16
PINNED_RECEIPT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
PREPARED_WINDOW_OWNERS = frozenset(
    {"CompatForgeCrossoverAcceptance", "CompatForgeWhiskyAcceptance"}
)
MAX_INTERACTION_EVIDENCE_BYTES = 1024 * 1024
MAX_ARCHIVE_ENTRIES = 4096
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
TEST_SUITE_VERSION = "gui-interactive-v2"

LIVE_REQUIRED_INTERACTIONS = {
    "7zip": ("fileList", "menus"),
    "sumatrapdf": ("mainWindow", "openDialog"),
    "notepad-plus-plus": (
        "open",
        "edit",
        "saveUtf8Chinese",
        "cjkTextReadable",
        "rereadMatches",
    ),
}

REQUIRED_INTERACTIONS = {
    "7zip": ("fileList", "menus", "cjkTextReadable"),
    "sumatrapdf": ("mainWindow", "openDialog", "cjkTextReadable"),
    "notepad-plus-plus": ("open", "edit", "saveUtf8Chinese", "rereadMatches", "cjkTextReadable"),
    "firefox": ("mainWindow", "browserContentRendered", "cjkTextReadable"),
    "krita": ("mainWindow", "workspaceVisible", "cjkTextReadable"),
    "7zip-x86": ("fileList", "menus", "cjkTextReadable"),
    "vlc": ("mainWindow", "mediaControls", "cjkTextReadable"),
    "winmerge": ("mainWindow", "compareDialog", "cjkTextReadable"),
    "audacity-x86": ("mainWindow", "waveformWorkspace", "cjkTextReadable"),
    "everything-x86": ("mainWindow", "searchField", "cjkTextReadable"),
}
BASELINE_APPLICATION_IDS = {"7zip", "sumatrapdf", "notepad-plus-plus"}

MACOS_CJK_FONT_CANDIDATES = (
    (
        Path("/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
        "CompatForgeCJK.ttf",
    ),
    (
        Path("/System/Library/Fonts/Hiragino Sans GB.ttc"),
        "CompatForgeCJK.ttc",
    ),
    (
        Path("/System/Library/Fonts/STHeiti Light.ttc"),
        "CompatForgeCJK.ttc",
    ),
)
CJK_FONT_REGISTRY_VALUES = (
    (
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Fonts",
        "Arial Unicode MS (TrueType)",
        "CompatForgeCJK.ttf",
    ),
    (
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\FontSubstitutes",
        "MS Shell Dlg",
        "Arial Unicode MS",
    ),
    (
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\FontSubstitutes",
        "MS Shell Dlg 2",
        "Arial Unicode MS",
    ),
    (
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\FontSubstitutes",
        "SimSun",
        "Arial Unicode MS",
    ),
    (
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\FontSubstitutes",
        "NSimSun",
        "Arial Unicode MS",
    ),
    (
        r"HKCU\Software\Wine\Fonts\Replacements",
        "Tahoma",
        "Arial Unicode MS",
    ),
    (
        r"HKCU\Software\Wine\Fonts\Replacements",
        "Segoe UI",
        "Arial Unicode MS",
    ),
    (
        r"HKCU\Software\Wine\Fonts\Replacements",
        "SimSun",
        "Arial Unicode MS",
    ),
    (
        r"HKCU\Software\Wine\Fonts\Replacements",
        "NSimSun",
        "Arial Unicode MS",
    ),
)
MAX_CJK_FONT_BYTES = 128 * 1024 * 1024
MAX_NOTEPAD_STYLE_BYTES = 4 * 1024 * 1024

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
    "desktop-font-unavailable": "environment",
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
    "desktop-font-unavailable": "blocked",
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
    "font-stage": "desktop-font-unavailable",
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
    "font-stage",
}
UNVERIFIED_STAGES = {"application-interaction"}


class AcceptanceError(Exception):
    pass


class ExecutableIntegrityError(AcceptanceError):
    """The installed executable or its fixed Bottle path changed identity."""


class CjkFontIntegrityError(AcceptanceError):
    """The local macOS CJK font could not be staged safely in the Bottle."""


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


class InfrastructureUnavailable(AcceptanceError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


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
        "--app",
        action="append",
        dest="applications",
        help="run only the named baseline application; repeat for multiple applications",
    )
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
    value.add_argument(
        "--interaction-evidence",
        action=UniqueValueAction,
        help="absolute v2 JSON attestation for the extended certification matrix",
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
    live_fields = (
        arguments.interaction_plan,
        arguments.acknowledgement_root,
        arguments.round_id,
    )
    live_requested = any(value is not None for value in live_fields)
    static_requested = arguments.interaction_evidence is not None
    if live_requested and static_requested:
        raise AcceptanceError("live acknowledgement and static interaction evidence are mutually exclusive")
    if arguments.accept_interactive:
        if not live_requested and not static_requested:
            raise AcceptanceError(
                "--accept-interactive requires live acknowledgement fields or interaction-evidence"
            )
        if live_requested and any(value is None for value in live_fields):
            raise AcceptanceError(
                "--accept-interactive requires interaction-plan, acknowledgement-root and round-id"
            )
        if live_requested and runtime_id not in RUNTIME_IDS:
            raise AcceptanceError("--accept-interactive requires an explicit Runtime identity")
        if static_requested and runtime_id is not None:
            raise AcceptanceError(
                "static interaction evidence cannot replace explicit Runtime live acknowledgement"
            )
    elif live_requested or static_requested:
        raise AcceptanceError(
            "interaction evidence fields require --accept-interactive"
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


def _validated_interaction_checks(
    app_id: str,
    status_value: str,
    reason_code: object,
    interactions: object,
    label: str,
) -> dict[str, bool] | None:
    if interactions is None:
        if status_value == "accepted":
            raise AcceptanceError(f"accepted {label} omitted interaction checks")
        return None
    if not isinstance(interactions, dict):
        raise AcceptanceError(f"{label} interaction checks must be an object")
    required = LIVE_REQUIRED_INTERACTIONS[app_id]
    if set(interactions) != set(required) or any(
        interactions.get(name) is not True for name in required
    ):
        raise AcceptanceError(f"{label} interaction checks are invalid")
    if reason_code in {
        "application-interaction-unverified",
        "application-interaction-invalid",
    }:
        raise AcceptanceError(f"{label} interaction failure claimed checks")
    return {name: True for name in required}


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
                "installerTerminationRequested",
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
        if not isinstance(app_id, str) or app_id not in LIVE_REQUIRED_INTERACTIONS or app_id in seen:
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
        _validated_interaction_checks(
            app_id,
            status_value,
            application.get("reasonCode"),
            application.get("interactionChecks"),
            "compact application",
        )
        for field in ("installerExit", "exit"):
            if field in application:
                _validate_exit_projection(application[field], f"compact application {field}")
        if "installerTerminationRequested" in application:
            if (
                app_id != "sumatrapdf"
                or application["installerTerminationRequested"] is not True
                or application.get("installerExit")
                != {"present": True, "code": None, "success": False}
            ):
                raise AcceptanceError(
                    "compact application installer termination relation is invalid"
                )
        for field in ("windowAvailable", "screenshotAvailable"):
            if field in application:
                _require_bool(application[field], f"compact application {field}")
    _scan_compact_scalars(value)


def compact_runtime_receipt(receipt: dict[str, object]) -> dict[str, object]:
    if not isinstance(receipt, dict):
        raise AcceptanceError("bootstrap receipt is invalid")
    required_receipt = (
        "schemaVersion",
        "runtimeId",
        "packId",
        "version",
        "packDigest",
        "source",
    )
    if any(key not in receipt for key in required_receipt):
        raise AcceptanceError("bootstrap receipt omitted compact identity")
    compact_receipt = {key: receipt[key] for key in required_receipt}
    if "activated" in receipt:
        compact_receipt["activated"] = receipt["activated"]
    validate_compact_summary(
        {
            "schemaVersion": "1",
            "receipt": compact_receipt,
            "applications": [],
        }
    )
    return compact_receipt


def compact_summary(
    receipt: dict[str, object],
    applications: list[dict[str, object]],
) -> dict[str, object]:
    if not isinstance(receipt, dict) or not isinstance(applications, list):
        raise AcceptanceError("full summary inputs are invalid")
    compact_receipt = compact_runtime_receipt(receipt)
    runtime_id = compact_receipt["runtimeId"]
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
        required_interactions = LIVE_REQUIRED_INTERACTIONS.get(application.get("appId"))
        if required_interactions is None:
            raise AcceptanceError("application interaction checks are invalid")
        validated_interactions = _validated_interaction_checks(
            application["appId"],
            status_value,
            application.get("reasonCode"),
            interactions,
            "application",
        )
        if validated_interactions is not None:
            projected["interactionChecks"] = validated_interactions
        for source_key, target_key in (("installerExit", "installerExit"), ("exit", "exit")):
            compact_exit = _compact_exit(application.get(source_key))
            if compact_exit is not None:
                projected[target_key] = compact_exit
        installer_events = application.get("installerEvents")
        if isinstance(installer_events, list) and any(
            isinstance(event, dict) and event.get("kind") == "terminate-requested"
            for event in installer_events
        ):
            projected["installerTerminationRequested"] = True
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


def certification_summary(
    receipt: dict[str, object],
    applications: list[dict[str, object]],
    compatibility_results: list[dict[str, object]],
) -> dict[str, object]:
    if not isinstance(applications, list) or not isinstance(compatibility_results, list):
        raise AcceptanceError("certification summary inputs are invalid")
    return {
        "schemaVersion": "1",
        "testSuiteVersion": TEST_SUITE_VERSION,
        "receipt": compact_runtime_receipt(receipt),
        "applications": applications,
        "compatibilityResults": compatibility_results,
    }


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


def prefix_process_ids(bottle_root: Path) -> set[int] | None:
    """Return macOS clients retaining this exact prefix marker/directory."""
    if platform.system() != "Darwin":
        return set()
    system32 = bottle_root / "windows" / "system32"
    marker = system32 / "ntdll.dll"
    if not system32.is_dir() or system32.is_symlink() or not marker.is_file() or marker.is_symlink():
        return None
    try:
        result = subprocess.run(
            ["/usr/sbin/lsof", "-t", "--", str(marker), str(system32)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
            env={},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode not in (0, 1) or len(result.stdout.encode("utf-8")) > 64 * 1024:
        return None
    process_ids: set[int] = set()
    for line in result.stdout.splitlines():
        try:
            process_id = int(line)
        except ValueError:
            return None
        if process_id > 1:
            process_ids.add(process_id)
    return process_ids


def process_snapshot(bottle_root: Path | str, process_group_id: int | None = None) -> list[str]:
    """List residual commands or loaded clients tied to the exact Bottle."""
    current = os.getpid()
    rows = process_table()
    if not rows:
        return ["process observation unavailable"]
    if isinstance(bottle_root, str):
        return [
            f"{pid} {command}"
            for pid, pgid, command in rows
            if pid != current
            and (
                bottle_root in command
                or (process_group_id is not None and pgid == process_group_id)
            )
        ]
    loaded = prefix_process_ids(bottle_root)
    if loaded is None:
        return ["prefix process observation unavailable"]
    marker = str(bottle_root)
    return [
        f"{pid} {command}"
        for pid, pgid, command in rows
        if pid != current
        and (pid in loaded or marker in command or (process_group_id is not None and pgid == process_group_id))
    ]


def process_group_ids(process_group_id: int) -> list[int]:
    return [pid for pid, pgid, _command in process_table() if pgid == process_group_id]


def stop_bottle_wineserver(wineserver: Path, prefix: Path) -> None:
    """Stop and reap the Wine server bound to one exact Bottle prefix."""

    if (
        not isinstance(wineserver, Path)
        or not wineserver.is_absolute()
        or not wineserver.is_file()
        or wineserver.is_symlink()
        or not os.access(wineserver, os.X_OK)
        or not isinstance(prefix, Path)
        or not prefix.is_absolute()
        or not prefix.is_dir()
        or prefix.is_symlink()
    ):
        raise AcceptanceError("Bottle wineserver cleanup inputs are invalid")
    environment = {"WINEPREFIX": str(prefix)}
    for command in ("-k", "-w"):
        try:
            result = subprocess.run(
                [str(wineserver), command],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AcceptanceError("Bottle wineserver cleanup failed") from error
        if result.returncode != 0:
            raise AcceptanceError("Bottle wineserver cleanup failed")


def executable_process_ids(executable: Path) -> list[int]:
    """Find detached clients bound to one exact Bottle executable path."""

    if not isinstance(executable, Path) or not executable.is_absolute():
        return []
    marker = str(executable)
    return [
        pid
        for pid, _pgid, command in process_table()
        if marker in command
    ]


def cleanup_bottle(context: dict[str, object], storage_root: Path, bottle_id: str) -> dict[str, object]:
    """Stop only the bound Bottle's Wine server, verify, then remove its directory."""
    if not bottle_id or bottle_id in {".", ".."} or "/" in bottle_id or "\\" in bottle_id:
        return {"success": False, "reason": "Bottle identifier is not a single path component"}
    bottle_directory = storage_root / "bottles" / bottle_id
    prefix = bottle_directory / "prefix"
    drive_c = prefix / "drive_c"
    if not bottle_directory.exists() and not bottle_directory.is_symlink():
        return {"success": True, "method": "already-absent", "residualProcessIds": []}
    if bottle_directory.is_symlink() or not bottle_directory.is_dir():
        return {"success": False, "reason": "Bottle directory is not a regular directory"}

    bindings = context.get("runtimeBindings")
    if not isinstance(bindings, list) or len(bindings) != 1 or not isinstance(bindings[0], dict):
        return {"success": False, "reason": "context must contain exactly one runtime binding"}
    binding = bindings[0]
    wineserver_value = binding.get("wineserverExecutable")
    environment_value = binding.get("environment")
    if not isinstance(wineserver_value, str) or not isinstance(environment_value, dict):
        return {"success": False, "reason": "runtime binding omitted wineserver cleanup data"}
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in environment_value.items()):
        return {"success": False, "reason": "runtime binding environment must contain only strings"}
    wineserver = Path(wineserver_value)
    if not wineserver.is_absolute() or not wineserver.is_file() or wineserver.is_symlink() or not os.access(wineserver, os.X_OK):
        return {"success": False, "reason": "bound wineserver is not an absolute regular executable"}
    expected_digest = environment_value.get("COMPATFORGE_WINESERVER_EXECUTABLE_SHA256")
    if not isinstance(expected_digest, str) or expected_digest != f"sha256:{file_sha256(wineserver)}":
        return {"success": False, "reason": "bound wineserver digest changed before cleanup"}

    cleanup_environment = dict(environment_value)
    cleanup_environment["WINEPREFIX"] = str(prefix)
    try:
        terminated = subprocess.run(
            [str(wineserver), "-k"],
            cwd=bottle_directory,
            env=cleanup_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"success": False, "reason": f"Bottle-scoped wineserver cleanup failed: {error}"}
    if terminated.returncode not in (0, 1):
        return {"success": False, "reason": f"Bottle-scoped wineserver returned {terminated.returncode}"}

    time.sleep(0.5)
    loaded = prefix_process_ids(drive_c)
    command_residuals = [pid for pid, _pgid, command in process_table() if str(prefix) in command]
    residuals = sorted((loaded or set()).union(command_residuals))
    if residuals:
        return {
            "success": False,
            "reason": "Bottle-scoped processes remained after wineserver cleanup",
            "wineserverReturnCode": terminated.returncode,
            "residualProcessIds": residuals,
        }
    try:
        shutil.rmtree(bottle_directory)
    except OSError as error:
        return {"success": False, "reason": f"Bottle directory removal failed: {error}"}
    return {
        "success": not bottle_directory.exists() and not bottle_directory.is_symlink(),
        "method": "bound-wineserver-kill-and-remove",
        "wineserverReturnCode": terminated.returncode,
        "residualProcessIds": [],
    }


def matching_windows(output: str, title_tokens: tuple[str, ...]) -> list[dict[str, object]]:
    matching: list[dict[str, object]] = []
    for line in output.splitlines():
        parts = line.strip().split("|")
        if len(parts) == 3:
            process_id_value, title, dimensions_value = parts
        elif len(parts) == 4:
            _process_name, process_id_value, title, dimensions_value = parts
        else:
            continue
        if not any(token.casefold() in title.casefold() for token in title_tokens):
            continue
        dimensions = dimensions_value.split("x", 1)
        try:
            process_id = int(process_id_value)
            width = int(dimensions[0])
            height = int(dimensions[1])
        except (ValueError, IndexError):
            continue
        if width <= 0 or height <= 0:
            continue
        matching.append({"processId": process_id, "title": title, "width": width, "height": height})
    return matching


def core_graphics_window_list() -> list[dict[str, object]] | None:
    """Read the macOS window list without Accessibility automation."""

    try:
        import ctypes
        import plistlib

        core_graphics = ctypes.CDLL(
            "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics"
        )
        core_foundation = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        core_graphics.CGWindowListCopyWindowInfo.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        core_graphics.CGWindowListCopyWindowInfo.restype = ctypes.c_void_p
        core_foundation.CFPropertyListCreateData.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        core_foundation.CFPropertyListCreateData.restype = ctypes.c_void_p
        core_foundation.CFDataGetLength.argtypes = [ctypes.c_void_p]
        core_foundation.CFDataGetLength.restype = ctypes.c_long
        core_foundation.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
        core_foundation.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)
        core_foundation.CFRelease.argtypes = [ctypes.c_void_p]

        window_list = core_graphics.CGWindowListCopyWindowInfo(1 | 16, 0)
        if not window_list:
            return None
        data = None
        error = ctypes.c_void_p()
        try:
            data = core_foundation.CFPropertyListCreateData(
                None,
                window_list,
                100,
                0,
                ctypes.byref(error),
            )
            if not data:
                return None
            length = core_foundation.CFDataGetLength(data)
            pointer = core_foundation.CFDataGetBytePtr(data)
            if length <= 0 or not pointer:
                return None
            decoded = plistlib.loads(ctypes.string_at(pointer, length))
            if not isinstance(decoded, list) or not all(
                isinstance(item, dict) for item in decoded
            ):
                return None
            return decoded
        finally:
            if data:
                core_foundation.CFRelease(data)
            if error.value:
                core_foundation.CFRelease(error)
            core_foundation.CFRelease(window_list)
    except (ImportError, OSError, ValueError, TypeError):
        return None


def matching_core_graphics_windows(
    windows: list[dict[str, object]],
    process_ids: list[int],
    title_tokens: tuple[str, ...],
) -> list[dict[str, object]]:
    matching: list[dict[str, object]] = []
    allowed_processes = set(process_ids)
    for window in windows:
        process_id = window.get("kCGWindowOwnerPID")
        title = window.get("kCGWindowName")
        bounds = window.get("kCGWindowBounds")
        window_id = window.get("kCGWindowNumber")
        if (
            type(process_id) is not int
            or process_id not in allowed_processes
            or not isinstance(title, str)
            or not any(token.casefold() in title.casefold() for token in title_tokens)
            or not isinstance(bounds, dict)
            or type(window_id) is not int
            or window.get("kCGWindowLayer") != 0
        ):
            continue
        width = bounds.get("Width")
        height = bounds.get("Height")
        if (
            not isinstance(width, (int, float))
            or not isinstance(height, (int, float))
            or width <= 0
            or height <= 0
        ):
            continue
        matching.append(
            {
                "processId": process_id,
                "title": title,
                "width": int(width),
                "height": int(height),
                "windowId": window_id,
            }
        )
    return matching


def matching_prepared_core_graphics_windows(
    windows: list[dict[str, object]],
    title_tokens: tuple[str, ...],
) -> list[dict[str, object]]:
    """Find one unique detached prepared-Runtime application window."""

    candidate_ids = sorted(
        {
            process_id
            for window in windows
            if window.get("kCGWindowOwnerName") in PREPARED_WINDOW_OWNERS
            and type(process_id := window.get("kCGWindowOwnerPID")) is int
        }
    )
    matching = matching_core_graphics_windows(windows, candidate_ids, title_tokens)
    if len({window["processId"] for window in matching}) != 1:
        return []
    return matching


def parse_event_line(line: str, label: str) -> dict[str, object]:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as error:
        raise AcceptanceError(f"{label} emitted invalid RuntimeEvent JSON") from error
    if not isinstance(value, dict):
        raise AcceptanceError(f"{label} emitted a non-object RuntimeEvent")
    return value


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise AcceptanceError("pinned evidence JSON is invalid") from error


def parse_pinned_receipt(value: object) -> list[dict[str, object]]:
    if (
        type(value) is not dict
        or set(value) != {"outputs", "recordType", "schemaVersion"}
        or value.get("recordType") != "pinned-evidence-receipt"
        or type(value.get("schemaVersion")) is not int
        or value.get("schemaVersion") != 1
    ):
        raise AcceptanceError("pinned evidence receipt is invalid")
    outputs = value.get("outputs")
    if type(outputs) is not list or len(outputs) != 2:
        raise AcceptanceError("pinned evidence receipt outputs are invalid")
    result: list[dict[str, object]] = []
    for output, expected_kind in zip(outputs, ("inspection", "plan"), strict=True):
        if (
            type(output) is not dict
            or set(output) != {"byteLength", "kind", "sha256"}
            or output.get("kind") != expected_kind
            or type(output.get("byteLength")) is not int
            or not 1 <= output["byteLength"] <= MAX_PINNED_EVIDENCE_BYTES
            or type(output.get("sha256")) is not str
            or PINNED_RECEIPT_DIGEST.fullmatch(output["sha256"]) is None
        ):
            raise AcceptanceError("pinned evidence receipt output is invalid")
        result.append(output)
    return result


@dataclass(frozen=True, slots=True)
class PinnedEvidenceBinding:
    descriptor: int
    identity: tuple[int, int]


def create_anonymous_pinned_output(directory_descriptor: int) -> PinnedEvidenceBinding:
    import fcntl

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    for _attempt in range(PINNED_OUTPUT_NAME_ATTEMPTS):
        name = ".compatforge-pinned-output-" + secrets.token_hex(16)
        descriptor: int | None = None
        linked = False
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
            linked = True
            before = os.fstat(descriptor)
            status_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
            descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFD)
            identity = (before.st_dev, before.st_ino)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or before.st_size != 0
                or before.st_uid != os.geteuid()
                or status_flags & os.O_ACCMODE != os.O_RDWR
                or bool(status_flags & os.O_APPEND)
                or not bool(descriptor_flags & fcntl.FD_CLOEXEC)
            ):
                raise AcceptanceError("pinned evidence output creation failed")
            os.unlink(name, dir_fd=directory_descriptor)
            linked = False
            after = os.fstat(descriptor)
            if (
                (after.st_dev, after.st_ino) != identity
                or after.st_nlink != 0
                or after.st_size != 0
            ):
                raise AcceptanceError("pinned evidence output unlink failed")
            return PinnedEvidenceBinding(descriptor, identity)
        except FileExistsError:
            continue
        except AcceptanceError:
            if descriptor is not None:
                os.close(descriptor)
            raise
        except OSError as error:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise AcceptanceError("pinned evidence output creation failed") from error
        finally:
            if linked:
                try:
                    os.unlink(name, dir_fd=directory_descriptor)
                except OSError:
                    pass
    raise AcceptanceError("pinned evidence output collision bound exhausted")


def create_pinned_evidence_work_root(work_root: Path) -> tuple[Path, tuple[int, int, int]]:
    """Create a private directory whose metadata remains stable during launch."""

    for _attempt in range(PINNED_OUTPUT_NAME_ATTEMPTS):
        path = work_root / f".pinned-sumatrapdf-{secrets.token_hex(16)}"
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            continue
        except OSError as error:
            raise AcceptanceError("pinned evidence work root creation failed") from error
        try:
            metadata = path.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or _is_reparse(metadata)
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != os.geteuid()
            ):
                raise AcceptanceError("pinned evidence work root is unsafe")
            return path, _installed_node_identity(metadata)
        except BaseException:
            try:
                path.rmdir()
            except OSError:
                pass
            raise
    raise AcceptanceError("pinned evidence work root collision bound exhausted")


def remove_pinned_evidence_work_root(
    path: Path | None,
    identity: tuple[int, int, int] | None,
) -> None:
    if path is None and identity is None:
        return
    if path is None or identity is None:
        raise AcceptanceError("pinned evidence work root cleanup state is invalid")
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or _installed_node_identity(metadata) != identity
        ):
            raise AcceptanceError("pinned evidence work root identity changed")
        path.rmdir()
    except AcceptanceError:
        raise
    except OSError as error:
        raise AcceptanceError("pinned evidence work root cleanup failed") from error


def revalidate_pinned_work_root(binding: object) -> None:
    protocol = _acknowledgement_protocol()
    try:
        protocol._revalidate_directory(binding, "pinned evidence work root")
    except (protocol.AcknowledgementError, OSError) as error:
        raise AcceptanceError("pinned evidence work root identity changed") from error


def read_pinned_evidence(
    binding: PinnedEvidenceBinding,
    receipt: dict[str, object],
) -> dict[str, object]:
    import fcntl

    try:
        before = os.fstat(binding.descriptor)
        status_flags = fcntl.fcntl(binding.descriptor, fcntl.F_GETFL)
        descriptor_flags = fcntl.fcntl(binding.descriptor, fcntl.F_GETFD)
    except OSError as error:
        raise AcceptanceError("pinned evidence descriptor is invalid") from error
    if (
        (before.st_dev, before.st_ino) != binding.identity
        or not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_nlink != 0
        or status_flags & os.O_ACCMODE != os.O_RDWR
        or bool(status_flags & os.O_APPEND)
        or not bool(descriptor_flags & fcntl.FD_CLOEXEC)
        or before.st_size != receipt["byteLength"]
    ):
        raise AcceptanceError("pinned evidence descriptor identity changed")
    try:
        os.lseek(binding.descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = MAX_PINNED_EVIDENCE_BYTES + 1
        while remaining:
            chunk = os.read(binding.descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(binding.descriptor)
    except OSError as error:
        raise AcceptanceError("pinned evidence could not be read") from error
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if (
        len(payload) != receipt["byteLength"]
        or digest != receipt["sha256"]
        or (after.st_dev, after.st_ino) != binding.identity
        or after.st_nlink != 0
        or after.st_size != before.st_size
    ):
        raise AcceptanceError("pinned evidence disagrees with its receipt")
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise AcceptanceError("pinned evidence JSON is invalid") from error
    if type(value) is not dict or canonical_json_bytes(value) != payload:
        raise AcceptanceError("pinned evidence JSON is not canonical")
    return value


def observed_launch(
    argv: list[str],
    screenshot_path: Path,
    title_tokens: tuple[str, ...],
    *,
    screenshot_delay_seconds: int = 0,
    window_appearance_seconds: int = WINDOW_APPEARANCE_SECONDS,
    on_window_observed: Callable[[subprocess.Popen[str], float], None] | None = None,
    pass_fds: tuple[int, ...] = (),
    terminal_records: list[dict[str, object]] | None = None,
    require_empty_stderr: bool = False,
    forbidden_transcript_values: tuple[str, ...] = (),
    observed_executable: Path | None = None,
    timeout: int = MAX_COMMAND_SECONDS,
) -> tuple[list[dict[str, object]], dict[str, object], dict[str, object], int | None]:
    """Keep the Core launch process alive while collecting visual evidence."""
    if on_window_observed is not None and not callable(on_window_observed):
        raise AcceptanceError("window acknowledgement hook is invalid")
    if observed_executable is not None and (
        not isinstance(observed_executable, Path)
        or not observed_executable.is_absolute()
    ):
        raise AcceptanceError("window executable binding is invalid")
    process = subprocess.Popen(
        argv,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
        close_fds=True,
        pass_fds=pass_fds,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        raise AcceptanceError("GUI launch pipes were not created")
    selector = selectors.DefaultSelector()
    selector_registered = False
    selector_closed = False
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        selector_registered = True
        started = time.monotonic()
        outer_deadline = started + float(timeout)
        application_deadline = (
            started + INTERACTIVE_RUNTIME_MILLISECONDS / 1000
        )
        windows: dict[str, object] = {
            "available": False,
            "reason": "observation pending",
        }
        shot: dict[str, object] = {"available": False, "path": str(screenshot_path)}
        events: list[dict[str, object]] = []
        root_process_id: int | None = None
        next_observation = started
        window_id: int | None = None
        acknowledgement_hook_called = False
        terminal_record_seen = False

        def consume_line(line: str) -> None:
            nonlocal root_process_id, terminal_record_seen
            if any(value and value in line for value in forbidden_transcript_values):
                raise AcceptanceError("GUI launch transcript leaked a private binding")
            record = parse_event_line(line, "GUI launch")
            if record.get("recordType") == "pinned-evidence-receipt":
                if terminal_records is None or terminal_record_seen:
                    raise AcceptanceError("GUI launch emitted an unexpected terminal record")
                if canonical_json_bytes(record).decode("utf-8") != line.rstrip("\r\n"):
                    raise AcceptanceError("pinned evidence receipt is not canonical")
                terminal_record_seen = True
                terminal_records.append(record)
                return
            if terminal_record_seen:
                raise AcceptanceError("GUI launch emitted data after its terminal record")
            events.append(record)
            if record.get("kind") == "started" and isinstance(
                record.get("processId"), int
            ):
                root_process_id = record["processId"]

        while process.poll() is None:
            elapsed = time.monotonic() - started
            for key, _mask in selector.select(timeout=0.1):
                line = key.fileobj.readline()
                if not line:
                    continue
                consume_line(line)
            now = time.monotonic()
            if (
                root_process_id is not None
                and not windows.get("available")
                and elapsed <= window_appearance_seconds
                and now >= next_observation
            ):
                windows = (
                    observer(root_process_id, title_tokens)
                    if observed_executable is None
                    else observer(
                        root_process_id,
                        title_tokens,
                        observed_executable,
                    )
                )
                if windows.get("available") is True:
                    if (
                        on_window_observed is not None
                        and not acknowledgement_hook_called
                    ):
                        acknowledgement_hook_called = True
                        hook_started = time.monotonic()
                        hook_deadline = min(
                            outer_deadline,
                            application_deadline,
                            hook_started + ACKNOWLEDGEMENT_WAIT_SECONDS,
                        )
                        remaining_budget = max(0.0, hook_deadline - hook_started)
                        on_window_observed(process, remaining_budget)
                        after_hook = time.monotonic()
                        if after_hook >= outer_deadline:
                            raise AcceptanceError(
                                "GUI launch exceeded the bounded observation timeout"
                            )
                        if after_hook >= hook_deadline:
                            raise InteractionUnverifiedError(
                                "application interaction acknowledgement timed out"
                            )
                    observed_windows = windows.get("windows")
                    if isinstance(observed_windows, list) and observed_windows:
                        first_window = observed_windows[0]
                        if isinstance(first_window, dict):
                            candidate = first_window.get("windowId")
                            if type(candidate) is int:
                                window_id = candidate
                next_observation = now + 0.5
            if (
                windows.get("available") is True
                and shot.get("available") is not True
                and elapsed >= screenshot_delay_seconds
            ):
                shot = screenshot(screenshot_path, window_id)
            if time.monotonic() >= outer_deadline:
                raise AcceptanceError(
                    "GUI launch exceeded the bounded observation timeout"
                )
            time.sleep(0.1)
        selector.unregister(process.stdout)
        selector_registered = False
        selector.close()
        selector_closed = True
        for line in process.stdout.read().splitlines():
            if line.strip():
                consume_line(line)
        stderr = process.stderr.read()
        process.wait(timeout=10)
        if process.returncode != 0:
            detail = stderr.strip().splitlines()[-1] if stderr.strip() else "no stderr"
            raise AcceptanceError(f"GUI launch failed: {detail}")
        if require_empty_stderr and stderr:
            raise AcceptanceError("GUI launch emitted unexpected stderr")
        if terminal_records is not None and len(terminal_records) != 1:
            raise AcceptanceError("GUI launch terminal record is missing")
        if not events:
            raise AcceptanceError("GUI launch emitted no RuntimeEvent")
        return events, windows, shot, root_process_id
    except BaseException as primary_error:
        cleanup_error: BaseException | None = None
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        except BaseException as error:
            cleanup_error = error
        try:
            if selector_registered:
                selector.unregister(process.stdout)
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
        try:
            if not selector_closed:
                selector.close()
        except BaseException as error:
            if cleanup_error is None:
                cleanup_error = error
        if cleanup_error is not None:
            raise InteractionCleanupError("GUI launch cleanup failed") from primary_error
        raise


def launch_runtime_milliseconds(
    window_appearance_seconds: int,
    screenshot_delay_seconds: int,
    accept_interactive: bool,
) -> int:
    """Keep the guest alive long enough to consume its visual evidence budget."""
    minimum = CERTIFICATION_INTERACTIVE_RUNTIME_MILLISECONDS if accept_interactive else 30_000
    visual_budget = (max(window_appearance_seconds, screenshot_delay_seconds) + 5) * 1_000
    return max(minimum, visual_budget)


def status(
    events: list[dict[str, object]],
    *,
    allow_requested_termination: bool = False,
) -> str:
    exit_event = next((event for event in reversed(events) if event.get("kind") == "exited"), None)
    if exit_event is None:
        return "accepted" if any(event.get("kind") == "terminate-requested" for event in events) else "failed"
    exit_value = exit_event.get("exit")
    if isinstance(exit_value, dict) and exit_value.get("success") is True:
        return "accepted"
    if allow_requested_termination and any(
        event.get("kind") == "terminate-requested" for event in events
    ):
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
    if status(events, allow_requested_termination=True) != "accepted":
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
    interactions_complete = all(
        checks.get(name) is True for name in LIVE_REQUIRED_INTERACTIONS[app_id]
    )
    if not interactions_complete:
        apply_stage_outcome(
            evidence,
            "application-interaction",
            diagnostic="required per-application interaction evidence was not supplied",
        )
        return
    set_application_outcome(evidence, "accepted")


def evaluate_live_interaction_outcome(
    evidence: dict[str, object],
    app_id: str,
    events: list[dict[str, object]],
    windows: dict[str, object],
    shot: dict[str, object],
    residual: list[str],
    checks: dict[str, bool] | None,
    interaction_error: AcceptanceError | None,
) -> None:
    """Apply process and desktop failures before acknowledgement failures."""

    effective_checks = checks if interaction_error is None else None
    if effective_checks is not None:
        evidence["interactionChecks"] = effective_checks
    evaluate_application_outcome(
        evidence,
        app_id,
        events,
        windows,
        shot,
        residual,
        effective_checks or {},
    )
    if evidence.get("reasonCode") != "application-interaction-unverified":
        return
    if isinstance(interaction_error, InteractionInvalidError):
        apply_stage_outcome(
            evidence,
            "application-interaction-invalid",
            diagnostic="application interaction acknowledgement was invalid",
        )


def evaluate_certification_outcome(
    evidence: dict[str, object],
    app_id: str,
    events: list[dict[str, object]],
    windows: dict[str, object],
    shot: dict[str, object],
    residual: list[str],
    checks: dict[str, bool],
) -> None:
    required = REQUIRED_INTERACTIONS.get(app_id)
    if required is None:
        raise AcceptanceError("certification application is not recognized")
    evidence["interactionChecks"] = checks
    basic = (
        status(events, allow_requested_termination=True) == "accepted"
        and windows.get("available") is True
        and shot.get("available") is True
        and not residual
    )
    interactions_complete = all(checks.get(name) is True for name in required)
    evidence["status"] = "accepted" if basic and interactions_complete else "unverified"
    if not basic:
        evidence["reason"] = "target window/screenshot/exit cleanup evidence is incomplete"
        diagnostic = observation_diagnostic(windows, shot)
        evidence["observation"] = diagnostic
        evidence["failureClassification"] = diagnostic.get(
            "failureClassification", "runtime-regression"
        )
    elif not interactions_complete:
        evidence["reason"] = "required per-application interaction evidence was not supplied"
        evidence["failureClassification"] = "policy-blocked"


def installer_allows_requested_termination(
    asset,  # type: ignore[no-untyped-def]
    *,
    certification_mode: bool,
) -> bool:
    return certification_mode or asset.app_id == "sumatrapdf"


def installer_succeeded(
    evidence: dict[str, object],
    events: list[dict[str, object]],
    installed: Path | InstalledExecutableBinding,
    *,
    allow_requested_termination: bool = False,
) -> bool:
    if status(
        events,
        allow_requested_termination=allow_requested_termination,
    ) != "accepted":
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
    revalidate_installed_executable(installed)
    if isinstance(installed, InstalledExecutableBinding):
        return True
    installed_path = installed
    if not installed_path.is_file() or installed_path.is_symlink():
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


def desktop_session_state() -> dict[str, object]:
    """Classify whether macOS can currently provide interactive GUI evidence."""
    if platform.system() != "Darwin":
        return {
            "observable": False,
            "state": "unsupported-host",
            "failureClassification": "test-infrastructure",
        }
    try:
        session_result = subprocess.run(
            ["/usr/sbin/ioreg", "-n", "Root", "-d1"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        power_result = subprocess.run(
            ["/usr/bin/pmset", "-g", "assertions"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {
            "observable": False,
            "state": "session-probe-unavailable",
            "failureClassification": "test-infrastructure",
        }
    locked = any(
        marker in session_result.stdout
        for marker in (
            '"CGSSessionScreenIsLocked"=Yes',
            '"CGSSessionScreenIsLocked" = Yes',
            '"CGSSessionScreenIsLocked"=true',
            '"CGSSessionScreenIsLocked" = true',
            '"IOConsoleLocked"=Yes',
            '"IOConsoleLocked" = Yes',
        )
    )
    on_console = '"kCGSSessionOnConsoleKey"=Yes' in session_result.stdout
    assertions = {
        parts[0]: parts[1] == "1"
        for line in power_result.stdout.splitlines()
        if len(parts := line.split()) == 2 and parts[1] in {"0", "1"}
    }
    user_active = assertions.get("UserIsActive") is True
    display_held_awake = assertions.get("PreventUserIdleDisplaySleep") is True
    observable = (
        session_result.returncode == 0
        and power_result.returncode == 0
        and on_console
        and not locked
        and (user_active or display_held_awake)
    )
    if locked:
        state = "locked"
    elif not on_console:
        state = "not-console-session"
    elif not user_active and not display_held_awake:
        state = "display-inactive"
    elif session_result.returncode != 0 or power_result.returncode != 0:
        state = "session-probe-unavailable"
    else:
        state = "interactive"
    return {
        "observable": observable,
        "state": state,
        "onConsole": on_console,
        "userActive": user_active,
        "displayHeldAwake": display_held_awake,
        **({"failureClassification": "test-infrastructure"} if not observable else {}),
    }


def observation_diagnostic(windows: dict[str, object], shot: dict[str, object]) -> dict[str, object]:
    if windows.get("available") is True and shot.get("available") is True:
        return {"state": "observed"}
    reason = str(windows.get("reason") or shot.get("reason") or "visual evidence incomplete")
    infrastructure = windows.get("failureClassification") == "test-infrastructure" or any(
        token in reason.casefold()
        for token in ("locked", "inactive", "console-session", "accessibility", "osascript", "screencapture", "unavailable")
    )
    return {
        "state": "infrastructure-unavailable" if infrastructure else "target-not-observed",
        "failureClassification": "test-infrastructure" if infrastructure else "runtime-regression",
        "reason": reason,
    }


def observer(
    process_group_id: int,
    title_tokens: tuple[str, ...],
    observed_executable: Path | None = None,
) -> dict[str, object]:
    if platform.system() != "Darwin":
        return {
            "available": False,
            "reason": "window observation requires macOS",
            "failureClassification": "test-infrastructure",
        }
    session = desktop_session_state()
    if session.get("observable") is not True:
        return {
            "available": False,
            "reason": f"desktop session is {session.get('state')}",
            "session": session,
            "failureClassification": "test-infrastructure",
        }
    target_ids = process_group_ids(process_group_id)
    if observed_executable is not None:
        target_ids = sorted(
            set(target_ids) | set(executable_process_ids(observed_executable))
        )
    if not target_ids:
        return {"available": False, "reason": "launch process group is no longer visible", "processGroupId": process_group_id}
    native_windows = core_graphics_window_list()
    if native_windows is not None:
        matching_native = matching_core_graphics_windows(
            native_windows,
            target_ids,
            title_tokens,
        )
        if matching_native:
            return {
                "available": True,
                "processGroupId": process_group_id,
                "processIds": target_ids,
                "expectedTitleTokens": list(title_tokens),
                "windows": matching_native[:32],
            }
        matching_detached = matching_prepared_core_graphics_windows(
            native_windows,
            title_tokens,
        )
        if matching_detached:
            detached_ids = sorted(
                set(target_ids)
                | {int(window["processId"]) for window in matching_detached}
            )
            return {
                "available": True,
                "processGroupId": process_group_id,
                "processIds": detached_ids,
                "expectedTitleTokens": list(title_tokens),
                "windows": matching_detached[:32],
            }
        return {
            "available": False,
            "reason": "target CoreGraphics window is not visible",
            "processGroupId": process_group_id,
        }
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
        return {
            "available": False,
            "reason": "osascript unavailable",
            "failureClassification": "test-infrastructure",
        }
    if result.returncode != 0:
        return {
            "available": False,
            "reason": "Accessibility permission unavailable",
            "failureClassification": "test-infrastructure",
        }
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
        "reason": "target window was not observed",
        "processGroupId": process_group_id,
        "processIds": target_ids,
        "failureClassification": "runtime-regression",
    }


def screenshot(path: Path, window_id: int | None = None) -> dict[str, object]:
    try:
        command = ["/usr/sbin/screencapture", "-x"]
        if type(window_id) is int and window_id > 0:
            command.append(f"-l{window_id}")
        command.append(str(path))
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {
            "available": False,
            "reason": "screencapture unavailable",
            "failureClassification": "test-infrastructure",
        }
    available = result.returncode == 0 and path.is_file() and path.stat().st_size > 0
    return {
        "available": available,
        "path": str(path),
        **(
            {}
            if available
            else {"reason": "screencapture returned no image", "failureClassification": "test-infrastructure"}
        ),
    }


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
    if type(applications) is not dict or set(applications) != set(LIVE_REQUIRED_INTERACTIONS):
        raise InteractionInvalidError("interaction plan is invalid")
    result: dict[str, dict[str, list[str]]] = {}
    for app_id, required in LIVE_REQUIRED_INTERACTIONS.items():
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

    def revalidate(self) -> None:
        """Revalidate every held root at an application boundary."""

        self._revalidate()

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
                or final.st_size != 1
                or protocol._read_file(
                    binding.path / name,
                    "consumed interaction",
                    binding,
                )
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
        application_alive: Callable[[], bool] | None = None,
        deadline_seconds: float = ACKNOWLEDGEMENT_WAIT_SECONDS,
        wait_for_acknowledgement: (
            Callable[[dict[str, object], Path, Path], bool | None] | None
        ) = None,
    ) -> dict[str, bool]:
        self._revalidate()
        if window_observed is not True:
            return {}
        if (
            app_id not in LIVE_REQUIRED_INTERACTIONS
            or type(deadline_seconds) not in (int, float)
            or isinstance(deadline_seconds, bool)
            or not 0 < deadline_seconds <= ACKNOWLEDGEMENT_WAIT_SECONDS
            or not callable(nonce_source)
            or not callable(monotonic)
            or not callable(sleeper)
            or (application_alive is not None and not callable(application_alive))
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

            def require_open_acceptance_boundary() -> float:
                now = monotonic()
                if now >= deadline:
                    raise InteractionUnverifiedError(
                        "application interaction acknowledgement timed out"
                    )
                if application_alive is not None:
                    try:
                        alive = application_alive()
                    except Exception as error:
                        raise InteractionUnverifiedError(
                            "application closed before interaction acknowledgement"
                        ) from error
                    if alive is not True:
                        raise InteractionUnverifiedError(
                            "application closed before interaction acknowledgement"
                        )
                return now

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
                now = require_open_acceptance_boundary()
                try:
                    protocol._relative_stat(self.receipt_binding, name)
                except FileNotFoundError:
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

            require_open_acceptance_boundary()
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
            require_open_acceptance_boundary()
            return checks
        except InteractionIntegrityError:
            raise
        except InteractionCleanupError:
            raise
        except InteractionUnverifiedError:
            if receipt_identity is not None and not receipt_consumed:
                self._consume_owned(
                    self.receipt_binding,
                    name,
                    receipt_identity,
                    tolerate_substitution=False,
                )
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


def load_interaction_evidence(
    path: Path | None,
    accept_interactive: bool,
    application_ids: set[str] | None = None,
) -> tuple[dict[str, dict[str, bool]], dict[str, str]]:
    application_ids = application_ids or BASELINE_APPLICATION_IDS
    if not accept_interactive:
        if path is not None:
            raise AcceptanceError("--interaction-evidence requires --accept-interactive")
        return {}, {}
    if path is None:
        raise AcceptanceError("--accept-interactive requires --interaction-evidence")
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_INTERACTION_EVIDENCE_BYTES:
        raise AcceptanceError("interaction evidence must be a bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AcceptanceError("interaction evidence is not readable JSON") from error
    if not isinstance(value, dict) or value.get("schemaVersion") != "2":
        raise AcceptanceError("interaction evidence must use schemaVersion 2")
    if set(value) != {"schemaVersion", "attestation", "applications"}:
        raise AcceptanceError("interaction evidence contains unknown fields")
    attestation = value.get("attestation")
    if not isinstance(attestation, dict) or set(attestation) != {"mode", "observer", "observedAt"}:
        raise AcceptanceError("interaction evidence omitted the closed attestation")
    if attestation.get("mode") != "human":
        raise AcceptanceError("interactive acceptance requires a human attestation")
    observer_name = attestation.get("observer")
    observed_at = attestation.get("observedAt")
    if not isinstance(observer_name, str) or not observer_name.strip() or len(observer_name.encode("utf-8")) > 256:
        raise AcceptanceError("interaction observer is invalid")
    if not isinstance(observed_at, str):
        raise AcceptanceError("interaction observedAt is invalid")
    try:
        parsed_observed_at = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise AcceptanceError("interaction observedAt is invalid") from error
    if parsed_observed_at.tzinfo is None:
        raise AcceptanceError("interaction observedAt must include a timezone")
    applications = value.get("applications")
    if not isinstance(applications, dict):
        raise AcceptanceError("interaction evidence omitted applications")
    result: dict[str, dict[str, bool]] = {}
    for app_id in application_ids:
        required = REQUIRED_INTERACTIONS[app_id]
        checks = applications.get(app_id)
        if (
            not isinstance(checks, dict)
            or set(checks) != set(required)
            or any(checks.get(name) is not True for name in required)
        ):
            raise AcceptanceError(f"interaction evidence is incomplete for {app_id}")
        result[app_id] = {name: True for name in required}
    return result, {
        "mode": "human",
        "observer": observer_name.strip(),
        "observedAt": observed_at,
    }


def interaction_evidence(
    path: Path | None,
    accept_interactive: bool,
    application_ids: set[str] | None = None,
) -> dict[str, dict[str, bool]]:
    """Return validated checks for callers that do not need attestation metadata."""
    return load_interaction_evidence(path, accept_interactive, application_ids)[0]


EXPECTED_INSTALLED_EXECUTABLES = {
    "7zip": "Program Files/7-Zip/7zFM.exe",
    "sumatrapdf": "CompatForge/SumatraPDF/SumatraPDF.exe",
    "notepad-plus-plus": "Program Files/Notepad++/notepad++.exe",
    "firefox": "Program Files/Mozilla Firefox/firefox.exe",
    "krita": "Program Files/Krita (x64)/bin/krita.exe",
    "7zip-x86": "Program Files (x86)/7-Zip/7zFM.exe",
    "vlc": "Program Files/VideoLAN/VLC/vlc.exe",
    "winmerge": "WinMerge/WinMergeU.exe",
    "audacity-x86": "Program Files (x86)/Audacity/Audacity.exe",
    "everything-x86": "Program Files (x86)/Everything/Everything.exe",
}

EXPECTED_ALTERNATE_INSTALLED_EXECUTABLES = {
    "7zip-x86": ("Program Files/7-Zip/7zFM.exe",),
    "audacity-x86": ("Program Files/Audacity/Audacity.exe",),
    "everything-x86": ("Program Files/Everything/Everything.exe",),
}

KNOWN_LEGACY_INSTALLED_EXECUTABLES = {
    "sumatrapdf": (
        "Program Files/SumatraPDF/SumatraPDF.exe",
        "users/Public/AppData/Local/SumatraPDF/SumatraPDF.exe",
    ),
}


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _installed_node_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


@dataclass(slots=True)
class InstalledExecutableBinding:
    path: Path
    directories: tuple[object, ...]
    descriptor: int
    identity: tuple[int, int, int]
    legacy_paths: tuple[Path, ...]
    closed: bool = False

    def __fspath__(self) -> str:
        return str(self.path)

    def __str__(self) -> str:
        return str(self.path)

    def revalidate(self) -> None:
        if self.closed:
            raise ExecutableIntegrityError(
                "installed GUI executable binding is closed"
            )
        protocol = _acknowledgement_protocol()
        try:
            for binding in self.directories:
                protocol._revalidate_directory(
                    binding, "installed GUI executable directory"
                )
            for legacy in self.legacy_paths:
                try:
                    legacy.lstat()
                except FileNotFoundError:
                    pass
                except OSError as error:
                    raise ExecutableIntegrityError(
                        "legacy GUI executable location cannot be verified"
                    ) from error
                else:
                    raise ExecutableIntegrityError(
                        "multiple GUI executable locations are present"
                    )
            parent = self.directories[-1]
            current = protocol._relative_stat(parent, self.path.name)
            opened = os.fstat(self.descriptor)
            for metadata in (current, opened):
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or _is_reparse(metadata)
                    or metadata.st_nlink != 1
                    or _installed_node_identity(metadata) != self.identity
                ):
                    raise ExecutableIntegrityError(
                        "installed GUI executable identity changed"
                    )
        except ExecutableIntegrityError:
            raise
        except (OSError, protocol.AcknowledgementError) as error:
            raise ExecutableIntegrityError(
                "installed GUI executable identity changed"
            ) from error

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            os.close(self.descriptor)
        except OSError:
            pass
        protocol = _acknowledgement_protocol()
        for binding in reversed(self.directories):
            protocol._close_directory(binding)


def revalidate_installed_executable(
    installed: Path | InstalledExecutableBinding,
) -> None:
    if isinstance(installed, InstalledExecutableBinding):
        installed.revalidate()


def close_installed_executable(
    installed: Path | InstalledExecutableBinding | None,
) -> None:
    if isinstance(installed, InstalledExecutableBinding):
        installed.close()


def materialize_sumatrapdf_portable(
    source: Path,
    bottle_root: Path,
    expected_sha256: str,
) -> Path:
    """Copy the fixed portable bytes once into the owned Bottle location."""

    relative = Path(EXPECTED_INSTALLED_EXECUTABLES["sumatrapdf"])
    destination = bottle_root.joinpath(*relative.parts)
    if (
        not source.is_absolute()
        or not bottle_root.is_absolute()
        or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
    ):
        raise ExecutableIntegrityError("SumatraPDF portable input is invalid")
    current = bottle_root
    source_descriptor: int | None = None
    parent_descriptor: int | None = None
    target_descriptor: int | None = None
    target_created = False
    complete = False
    try:
        for part in relative.parts[:-1]:
            current /= part
            current.mkdir(mode=0o700, exist_ok=True)
            entry = current.lstat()
            if not stat.S_ISDIR(entry.st_mode) or stat.S_ISLNK(entry.st_mode):
                raise ExecutableIntegrityError(
                    "SumatraPDF portable destination is unsafe"
                )
        source_flags = os.O_RDONLY
        source_flags |= getattr(os, "O_CLOEXEC", 0)
        source_flags |= getattr(os, "O_NOFOLLOW", 0)
        source_flags |= getattr(os, "O_BINARY", 0)
        source_flags |= getattr(os, "O_NOINHERIT", 0)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        target_flags |= getattr(os, "O_CLOEXEC", 0)
        target_flags |= getattr(os, "O_NOFOLLOW", 0)
        target_flags |= getattr(os, "O_BINARY", 0)
        target_flags |= getattr(os, "O_NOINHERIT", 0)
        source_descriptor = os.open(source, source_flags)
        parent_descriptor = os.open(destination.parent, directory_flags)
        target_descriptor = os.open(
            destination.name,
            target_flags,
            0o700,
            dir_fd=parent_descriptor,
        )
        target_created = True
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= 128 * 1024 * 1024
        ):
            raise ExecutableIntegrityError(
                "SumatraPDF portable source is unsafe"
            )
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_descriptor, 65_536)
            if not chunk:
                break
            copied += len(chunk)
            if copied > 128 * 1024 * 1024:
                raise ExecutableIntegrityError(
                    "SumatraPDF portable source exceeds its bound"
                )
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                if written <= 0:
                    raise OSError("short portable write")
                view = view[written:]
        os.fsync(target_descriptor)
        after = os.fstat(source_descriptor)
        target = os.fstat(target_descriptor)
        if (
            digest.hexdigest() != expected_sha256
            or copied != before.st_size
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            or not stat.S_ISREG(target.st_mode)
            or target.st_nlink != 1
            or target.st_size != copied
            or stat.S_IMODE(target.st_mode) != 0o700
        ):
            raise ExecutableIntegrityError(
                "SumatraPDF portable materialization changed"
            )
        os.fsync(parent_descriptor)
        complete = True
        return destination
    except ExecutableIntegrityError:
        raise
    except OSError as error:
        raise ExecutableIntegrityError(
            "SumatraPDF portable materialization failed"
        ) from error
    finally:
        if target_created and not complete and parent_descriptor is not None:
            try:
                os.unlink(destination.name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
            except OSError:
                pass
        for descriptor in (target_descriptor, parent_descriptor, source_descriptor):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def stage_macos_cjk_font(bottle_root: Path) -> dict[str, object]:
    """Copy one fixed local system font into this temporary Bottle only."""

    if platform.system() != "Darwin" or not bottle_root.is_absolute():
        raise CjkFontIntegrityError("macOS CJK font staging is unavailable")
    try:
        bottle_metadata = bottle_root.lstat()
    except OSError as error:
        raise CjkFontIntegrityError("Bottle font destination is unavailable") from error
    if not stat.S_ISDIR(bottle_metadata.st_mode) or stat.S_ISLNK(
        bottle_metadata.st_mode
    ):
        raise CjkFontIntegrityError("Bottle font destination is unsafe")

    source_descriptor: int | None = None
    source_path: Path | None = None
    destination_name: str | None = None
    source_flags = os.O_RDONLY
    source_flags |= getattr(os, "O_CLOEXEC", 0)
    source_flags |= getattr(os, "O_NOFOLLOW", 0)
    source_flags |= getattr(os, "O_BINARY", 0)
    source_flags |= getattr(os, "O_NOINHERIT", 0)
    for candidate, fixed_name in MACOS_CJK_FONT_CANDIDATES:
        try:
            descriptor = os.open(candidate, source_flags)
            metadata = os.fstat(descriptor)
        except OSError:
            continue
        if (
            not candidate.is_absolute()
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= MAX_CJK_FONT_BYTES
            or re.fullmatch(r"CompatForgeCJK\.(?:ttf|ttc)", fixed_name) is None
        ):
            os.close(descriptor)
            continue
        source_descriptor = descriptor
        source_path = candidate
        destination_name = fixed_name
        break
    if source_descriptor is None or source_path is None or destination_name is None:
        raise CjkFontIntegrityError("no safe local macOS CJK font is available")

    current = bottle_root
    parent_descriptor: int | None = None
    target_descriptor: int | None = None
    target_created = False
    complete = False
    destination = bottle_root / "windows" / "Fonts" / destination_name
    try:
        for part in ("windows", "Fonts"):
            current /= part
            current.mkdir(mode=0o700, exist_ok=True)
            metadata = current.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise CjkFontIntegrityError("Bottle font destination is unsafe")
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        target_flags |= getattr(os, "O_CLOEXEC", 0)
        target_flags |= getattr(os, "O_NOFOLLOW", 0)
        target_flags |= getattr(os, "O_BINARY", 0)
        target_flags |= getattr(os, "O_NOINHERIT", 0)
        parent_descriptor = os.open(destination.parent, directory_flags)
        target_descriptor = os.open(
            destination.name,
            target_flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        target_created = True
        before = os.fstat(source_descriptor)
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(source_descriptor, 65_536)
            if not chunk:
                break
            copied += len(chunk)
            if copied > MAX_CJK_FONT_BYTES:
                raise CjkFontIntegrityError("local macOS CJK font exceeds its bound")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(target_descriptor, view)
                if written <= 0:
                    raise OSError("short CJK font write")
                view = view[written:]
        os.fsync(target_descriptor)
        after = os.fstat(source_descriptor)
        target = os.fstat(target_descriptor)
        if (
            copied != before.st_size
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            or not stat.S_ISREG(target.st_mode)
            or target.st_nlink != 1
            or target.st_size != copied
            or stat.S_IMODE(target.st_mode) != 0o600
        ):
            raise CjkFontIntegrityError("Bottle-local CJK font changed during staging")
        os.fsync(parent_descriptor)
        complete = True
        return {
            "schemaVersion": "1",
            "scope": "bottle-local",
            "registration": "windows-fonts-directory",
            "fileName": destination_name,
            "sizeBytes": copied,
            "sha256": "sha256:" + digest.hexdigest(),
        }
    except CjkFontIntegrityError:
        raise
    except OSError as error:
        raise CjkFontIntegrityError("Bottle-local CJK font staging failed") from error
    finally:
        if target_created and not complete and parent_descriptor is not None:
            try:
                os.unlink(destination.name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
            except OSError:
                pass
        for descriptor in (target_descriptor, parent_descriptor, source_descriptor):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def register_macos_cjk_font(
    wine: Path,
    wineserver: Path,
    prefix: Path,
) -> dict[str, object]:
    """Register and select the staged family inside one owned Wine prefix."""

    if platform.system() != "Darwin":
        raise CjkFontIntegrityError("macOS CJK font registration is unavailable")
    for executable, label in ((wine, "Wine"), (wineserver, "wineserver")):
        try:
            metadata = executable.lstat()
        except OSError as error:
            raise CjkFontIntegrityError(f"{label} executable is unavailable") from error
        if (
            not executable.is_absolute()
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or not os.access(executable, os.X_OK)
        ):
            raise CjkFontIntegrityError(f"{label} executable is unsafe")
    try:
        prefix_metadata = prefix.lstat()
        font_metadata = (prefix / "drive_c" / "windows" / "Fonts" / "CompatForgeCJK.ttf").lstat()
    except OSError as error:
        raise CjkFontIntegrityError("Bottle-local CJK font is unavailable") from error
    if (
        not prefix.is_absolute()
        or not stat.S_ISDIR(prefix_metadata.st_mode)
        or stat.S_ISLNK(prefix_metadata.st_mode)
        or not stat.S_ISREG(font_metadata.st_mode)
        or stat.S_ISLNK(font_metadata.st_mode)
        or _is_reparse(font_metadata)
        or font_metadata.st_nlink != 1
        or not 1 <= font_metadata.st_size <= MAX_CJK_FONT_BYTES
    ):
        raise CjkFontIntegrityError("Bottle-local CJK font is unsafe")

    environment = {"WINEPREFIX": str(prefix)}
    try:
        for key, name, value in CJK_FONT_REGISTRY_VALUES:
            result = subprocess.run(
                [
                    str(wine),
                    "reg",
                    "add",
                    key,
                    "/v",
                    name,
                    "/d",
                    value,
                    "/f",
                ],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            if result.returncode != 0:
                raise CjkFontIntegrityError("Bottle-local CJK font registration failed")
        for command in ("-k", "-w"):
            result = subprocess.run(
                [str(wineserver), command],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=10,
            )
            accepted_codes = {0, 1} if command == "-k" else {0}
            if result.returncode not in accepted_codes:
                raise CjkFontIntegrityError("Bottle-local CJK font cleanup failed")
        if process_snapshot(str(prefix)):
            raise CjkFontIntegrityError("Bottle-local CJK font cleanup failed")
    except CjkFontIntegrityError:
        raise
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CjkFontIntegrityError("Bottle-local CJK font registration failed") from error

    after = (prefix / "drive_c" / "windows" / "Fonts" / "CompatForgeCJK.ttf").lstat()
    if (
        not stat.S_ISREG(after.st_mode)
        or _installed_node_identity(after) != _installed_node_identity(font_metadata)
    ):
        raise CjkFontIntegrityError("Bottle-local CJK font changed during registration")
    return {
        "schemaVersion": "1",
        "scope": "bottle-local",
        "family": "Arial Unicode MS",
        "registration": "wine-registry",
        "replacementCount": len(CJK_FONT_REGISTRY_VALUES) - 1,
    }


def configure_notepad_cjk_font(bottle_root: Path) -> dict[str, object]:
    """Set the fixed Notepad++ default editor style to the staged CJK font."""

    style_path = (
        bottle_root / "Program Files" / "Notepad++" / "stylers.model.xml"
    )
    try:
        style_metadata = style_path.lstat()
    except OSError as error:
        raise CjkFontIntegrityError("Notepad++ style template is unavailable") from error
    if (
        not stat.S_ISREG(style_metadata.st_mode)
        or stat.S_ISLNK(style_metadata.st_mode)
        or _is_reparse(style_metadata)
        or style_metadata.st_nlink != 1
        or not 1 <= style_metadata.st_size <= MAX_NOTEPAD_STYLE_BYTES
    ):
        raise CjkFontIntegrityError("Notepad++ style template is unsafe")
    current = bottle_root
    for part in style_path.relative_to(bottle_root).parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise CjkFontIntegrityError("Notepad++ style path is unavailable") from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise CjkFontIntegrityError("Notepad++ style path is unsafe")

    source_descriptor: int | None = None
    parent_descriptor: int | None = None
    target_descriptor: int | None = None
    temporary_name = f".compatforge-stylers-{secrets.token_hex(16)}.xml"
    temporary_created = False
    replaced = False
    try:
        source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        source_flags |= getattr(os, "O_NOFOLLOW", 0)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_flags |= getattr(os, "O_CLOEXEC", 0)
        directory_flags |= getattr(os, "O_NOFOLLOW", 0)
        target_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        target_flags |= getattr(os, "O_CLOEXEC", 0)
        target_flags |= getattr(os, "O_NOFOLLOW", 0)
        source_descriptor = os.open(style_path, source_flags)
        before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= MAX_NOTEPAD_STYLE_BYTES
        ):
            raise CjkFontIntegrityError("Notepad++ style file is unsafe")
        payload = b""
        while len(payload) <= MAX_NOTEPAD_STYLE_BYTES:
            chunk = os.read(source_descriptor, 65_536)
            if not chunk:
                break
            payload += chunk
        if len(payload) != before.st_size or len(payload) > MAX_NOTEPAD_STYLE_BYTES:
            raise CjkFontIntegrityError("Notepad++ style file exceeds its bound")
        source_token = b'fontName="Courier New"'
        target_token = b'fontName="Arial Unicode MS"'
        if payload.count(source_token) != 2 or target_token in payload:
            raise CjkFontIntegrityError("Notepad++ default font style is unexpected")
        updated = payload.replace(source_token, target_token)
        parent_descriptor = os.open(style_path.parent, directory_flags)
        target_descriptor = os.open(
            temporary_name,
            target_flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        temporary_created = True
        view = memoryview(updated)
        while view:
            written = os.write(target_descriptor, view)
            if written <= 0:
                raise OSError("short Notepad++ style write")
            view = view[written:]
        os.fsync(target_descriptor)
        after = os.fstat(source_descriptor)
        target = os.fstat(target_descriptor)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            or not stat.S_ISREG(target.st_mode)
            or target.st_nlink != 1
            or target.st_size != len(updated)
            or stat.S_IMODE(target.st_mode) != 0o600
        ):
            raise CjkFontIntegrityError("Notepad++ style changed during update")
        os.replace(
            temporary_name,
            style_path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        replaced = True
        os.fsync(parent_descriptor)
        final = os.stat(style_path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_nlink != 1
            or final.st_size != len(updated)
        ):
            raise CjkFontIntegrityError("Notepad++ style update was not durable")
        return {
            "schemaVersion": "1",
            "scope": "bottle-local",
            "editorFont": "Arial Unicode MS",
            "sha256": "sha256:" + hashlib.sha256(updated).hexdigest(),
        }
    except CjkFontIntegrityError:
        raise
    except OSError as error:
        raise CjkFontIntegrityError("Notepad++ CJK style update failed") from error
    finally:
        if temporary_created and not replaced and parent_descriptor is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
                os.fsync(parent_descriptor)
            except OSError:
                pass
        for descriptor in (target_descriptor, parent_descriptor, source_descriptor):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def installed_executable(  # type: ignore[no-untyped-def]
    asset, bottle_root: Path
) -> InstalledExecutableBinding:
    """Return the one verified executable path fixed by the asset descriptor."""
    expected_relative = EXPECTED_INSTALLED_EXECUTABLES.get(asset.app_id)
    expected_alternates = EXPECTED_ALTERNATE_INSTALLED_EXECUTABLES.get(
        asset.app_id, ()
    )
    if (
        expected_relative is None
        or asset.installed_executable != expected_relative
        or tuple(asset.alternate_installed_executables) != expected_alternates
    ):
        raise ExecutableIntegrityError(
            "GUI asset installed executable location is invalid"
        )
    if not bottle_root.is_absolute():
        raise ExecutableIntegrityError("Bottle root must be absolute")

    allowed_relatives = tuple(
        Path(value) for value in (expected_relative, *expected_alternates)
    )
    present_relatives = tuple(
        relative
        for relative in allowed_relatives
        if bottle_root.joinpath(*relative.parts).exists()
        or bottle_root.joinpath(*relative.parts).is_symlink()
    )
    if len(present_relatives) > 1:
        raise ExecutableIntegrityError(
            "multiple GUI executable locations are present"
        )
    relative = present_relatives[0] if present_relatives else allowed_relatives[0]
    candidate = bottle_root.joinpath(*relative.parts)
    legacy_paths = tuple(
        bottle_root.joinpath(*Path(value).parts)
        for value in KNOWN_LEGACY_INSTALLED_EXECUTABLES.get(asset.app_id, ())
    )
    directories: list[object] = []
    descriptor: int | None = None
    binding: InstalledExecutableBinding | None = None
    complete = False
    protocol = _acknowledgement_protocol()
    try:
        current = bottle_root
        directories.append(protocol._bind_directory(current, "Bottle root"))
        for part in relative.parts[:-1]:
            current /= part
            directories.append(
                protocol._bind_directory(
                    current, "installed GUI executable directory"
                )
            )
        for legacy in legacy_paths:
            try:
                legacy.lstat()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise ExecutableIntegrityError(
                    "legacy GUI executable location cannot be verified"
                ) from error
            else:
                raise ExecutableIntegrityError(
                    "multiple GUI executable locations are present"
                )
        parent = directories[-1]
        entry = protocol._relative_stat(parent, candidate.name)
        if (
            not stat.S_ISREG(entry.st_mode)
            or stat.S_ISLNK(entry.st_mode)
            or _is_reparse(entry)
            or entry.st_nlink != 1
        ):
            raise ExecutableIntegrityError(
                "installed GUI executable is not a unique regular file"
            )
        descriptor = protocol._relative_open(
            parent,
            candidate.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOINHERIT", 0),
        )
        opened = os.fstat(descriptor)
        identity = _installed_node_identity(entry)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _installed_node_identity(opened) != identity
        ):
            raise ExecutableIntegrityError(
                "installed GUI executable changed while it was bound"
            )
        binding = InstalledExecutableBinding(
            candidate,
            tuple(directories),
            descriptor,
            identity,
            legacy_paths,
        )
        descriptor = None
        binding.revalidate()
        complete = True
        return binding
    except ExecutableIntegrityError:
        raise
    except (OSError, protocol.AcknowledgementError) as error:
        raise ExecutableIntegrityError(
            "expected installed GUI executable is missing or unsafe"
        ) from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if binding is not None and not complete:
            binding.close()
        elif binding is None:
            for directory in reversed(directories):
                protocol._close_directory(directory)


def file_sha256(path: Path) -> str:
    with path.open("rb") as source:
        return stream_sha256(source)


def stream_sha256(source) -> str:  # type: ignore[no-untyped-def]
    digest = hashlib.sha256()
    for chunk in iter(lambda: source.read(64 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def materialize_portable_zip(archive: Path, bottle_root: Path, expected_sha256: str) -> dict[str, object]:
    """Extract a fixed-digest portable ZIP without links, traversal, or overwrites."""
    descriptor = os.open(archive, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as pinned:
        metadata = os.fstat(pinned.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise AcceptanceError("portable archive is not a regular file")
        if stream_sha256(pinned) != expected_sha256:
            raise AcceptanceError("portable archive digest changed before materialization")
        pinned.seek(0)
        with zipfile.ZipFile(pinned) as bundle:
            entries = bundle.infolist()
            if not entries or len(entries) > MAX_ARCHIVE_ENTRIES:
                raise AcceptanceError("portable archive entry count is outside the fixed bound")
            total = sum(entry.file_size for entry in entries)
            if total > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise AcceptanceError("portable archive exceeds the uncompressed size bound")
            seen: set[str] = set()
            for entry in entries:
                if "\\" in entry.filename:
                    raise AcceptanceError("portable archive contains a non-canonical path")
                relative = PurePosixPath(entry.filename)
                if relative.is_absolute() or not relative.parts or any(
                    part in ("", ".", "..") for part in relative.parts
                ):
                    raise AcceptanceError("portable archive contains path traversal")
                folded = "/".join(relative.parts).casefold().rstrip("/")
                if folded in seen and not entry.is_dir():
                    raise AcceptanceError("portable archive contains a duplicate path")
                seen.add(folded)
                mode = entry.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise AcceptanceError("portable archive contains a symbolic link")
                destination = bottle_root.joinpath(*relative.parts)
                if entry.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    if destination.is_symlink():
                        raise AcceptanceError("portable archive directory became a symbolic link")
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists() or destination.is_symlink():
                    raise AcceptanceError("portable archive would overwrite an existing path")
                with bundle.open(entry) as source, destination.open("xb") as output:
                    shutil.copyfileobj(source, output, length=64 * 1024)
                if destination.stat().st_size != entry.file_size:
                    raise AcceptanceError("portable archive entry size changed during extraction")
        final_metadata = os.fstat(pinned.fileno())
        if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_size,
        ):
            raise AcceptanceError("portable archive identity changed during materialization")
    return {
        "schemaVersion": "1",
        "format": "zip",
        "fileDigest": "sha256:" + expected_sha256,
        "fileSizeBytes": metadata.st_size,
        "entryCount": len(entries),
        "uncompressedBytes": total,
    }


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


def matrix_entry_digest(asset) -> str:  # type: ignore[no-untyped-def]
    value = {
        "appId": asset.app_id,
        "displayName": asset.display_name,
        "installerSha256": asset.sha256,
        "installArgs": list(asset.install_args),
        "installedExecutable": asset.installed_executable,
        "alternateInstalledExecutables": list(asset.alternate_installed_executables),
        "launchArgs": list(asset.launch_args),
        "runtimeEnvironment": dict(asset.runtime_environment),
        "installWaitMilliseconds": asset.install_wait_milliseconds,
        "screenshotDelaySeconds": asset.screenshot_delay_seconds,
        "windowAppearanceSeconds": asset.window_appearance_seconds,
        "category": asset.category,
        "toolkit": asset.toolkit,
        "guestArchitecture": asset.guest_architecture,
        "packageKind": asset.package_kind,
        "requiredInteractions": list(REQUIRED_INTERACTIONS[asset.app_id]),
    }
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def check_outcome(passed: bool, *, blocked: bool = False) -> str:
    if passed:
        return "passed"
    return "blocked" if blocked else "failed"


def compatibility_result(
    asset,  # type: ignore[no-untyped-def]
    evidence: dict[str, object],
    receipt: dict[str, object],
    started_at: str,
    finished_at: str,
) -> dict[str, object]:
    status_value = evidence.get("status")
    blocked = status_value == "unverified"
    accepted = status_value == "accepted"
    windows = evidence.get("windows") if isinstance(evidence.get("windows"), dict) else {}
    shot = evidence.get("screenshot") if isinstance(evidence.get("screenshot"), dict) else {}
    exit_value = evidence.get("exit") if isinstance(evidence.get("exit"), dict) else {}
    interactions = evidence.get("interactionChecks") if isinstance(evidence.get("interactionChecks"), dict) else {}
    residual = evidence.get("residualProcesses") if isinstance(evidence.get("residualProcesses"), list) else []
    failure_classification = evidence.get("failureClassification")
    if not accepted and failure_classification is None:
        failure_classification = "policy-blocked" if blocked else "runtime-regression"
    checks = [
        {
            "id": "installer-inspection",
            "outcome": check_outcome(isinstance(evidence.get("installerInspection"), dict)),
        },
        {
            "id": "window-visible",
            "outcome": check_outcome(windows.get("available") is True, blocked=blocked),
            **({"message": str(windows.get("reason"))} if windows.get("reason") else {}),
        },
        {
            "id": "screenshot",
            "outcome": check_outcome(shot.get("available") is True, blocked=blocked),
            **(
                {"artifacts": [Path(str(shot["path"])).name]}
                if shot.get("available") is True and isinstance(shot.get("path"), str)
                else {}
            ),
        },
        {
            "id": "interactive-behavior",
            "outcome": check_outcome(
                all(interactions.get(name) is True for name in REQUIRED_INTERACTIONS[asset.app_id]),
                blocked=True,
            ),
        },
        {
            "id": "lifecycle-exit",
            "outcome": check_outcome(exit_value.get("present") is True),
        },
        {
            "id": "bottle-cleanup",
            "outcome": check_outcome(evidence.get("cleanup") is True),
        },
        {
            "id": "no-residual-processes",
            "outcome": check_outcome(not residual),
        },
    ]
    return {
        "schemaVersion": "1",
        "runId": str(uuid.uuid4()),
        "recipeId": asset.app_id,
        "recipeDigest": matrix_entry_digest(asset),
        "installerDigest": "sha256:" + asset.sha256,
        "testSuiteVersion": TEST_SUITE_VERSION,
        "host": {
            "os": "macos",
            "version": platform.mac_ver()[0],
            "architecture": platform.machine(),
        },
        "runtimePackDigest": receipt.get("packDigest"),
        "outcome": "passed" if accepted else ("blocked" if blocked else "failed"),
        **({"failureClassification": failure_classification} if failure_classification is not None else {}),
        "startedAt": started_at,
        "finishedAt": finished_at,
        "checks": checks,
    }


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
        static_evidence_path = (
            absolute(arguments.interaction_evidence, "interaction-evidence", external=True)
            if arguments.interaction_evidence
            else None
        )
        from download_gui_assets import ASSETS, BASELINE_ASSETS  # type: ignore[import-not-found]

        known_applications = {asset.app_id for asset in ASSETS}
        default_applications = tuple(
            asset.app_id
            for asset in BASELINE_ASSETS
            if asset.app_id in known_applications
        )
        selected_applications = set(arguments.applications or default_applications)
        unknown_applications = selected_applications - known_applications
        if unknown_applications:
            raise AcceptanceError(f"unknown baseline application: {sorted(unknown_applications)[0]}")
        live_interaction = arguments.interaction_plan is not None
        certification_mode = arguments.applications is not None or static_evidence_path is not None
        if live_interaction and selected_applications != BASELINE_APPLICATION_IDS:
            raise AcceptanceError("live acknowledgement requires the complete baseline application set")
        manual_checks, manual_attestation = load_interaction_evidence(
            static_evidence_path,
            static_evidence_path is not None,
            selected_applications,
        )
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
            runtime_binding = context["runtimeBindings"][0]  # type: ignore[index]
            cleanup_wineserver_value = runtime_binding.get("wineserverExecutable")  # type: ignore[union-attr]
            cleanup_wineserver = (
                Path(cleanup_wineserver_value)
                if isinstance(cleanup_wineserver_value, str)
                and Path(cleanup_wineserver_value).is_absolute()
                else None
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
        supervisor["maximumRuntimeMilliseconds"] = (  # type: ignore[index]
            INTERACTIVE_RUNTIME_MILLISECONDS
            if live_interaction
            else CERTIFICATION_INTERACTIVE_RUNTIME_MILLISECONDS
        )
        write_json(context_path, context)
        write_json(arguments.work_root / "bootstrap-receipt.json", receipt)
        if live_interaction:
            interaction_session = open_interaction_session(
                arguments.interaction_plan,
                arguments.acknowledgement_root,
                arguments.round_id,
                runtime_id,
            )

        results: list[dict[str, object]] = []
        compatibility_results: list[dict[str, object]] = []
        for asset in ASSETS:
            if asset.app_id not in selected_applications:
                continue
            bottle_id = f"gui-{asset.app_id}"
            bottle_root = arguments.storage_root / "bottles" / bottle_id / "prefix" / "drive_c"
            bottle_root.mkdir(parents=True, exist_ok=True)
            started_at = utc_now()
            evidence: dict[str, object] = {
                "schemaVersion": "1",
                "runtimeId": runtime_id,
                "appId": asset.app_id,
                "assetSha256": asset.sha256,
                "bottleId": bottle_id,
                "matrix": {
                    "category": asset.category,
                    "toolkit": asset.toolkit,
                    "guestArchitecture": asset.guest_architecture,
                    "recipeDigest": matrix_entry_digest(asset),
                },
                "startedAt": started_at,
                "status": "unverified",
                "cleanup": False,
            }
            failure_stage = "asset-fetch"
            installed: Path | InstalledExecutableBinding | None = None
            pinned_descriptors: list[int] = []
            pinned_work_root: Path | None = None
            pinned_work_root_identity: tuple[int, int, int] | None = None
            try:
                if interaction_session is not None:
                    interaction_session.revalidate()
                if static_evidence_path is not None:
                    desktop_preflight = desktop_session_state()
                    evidence["desktopPreflight"] = desktop_preflight
                    if desktop_preflight.get("observable") is not True:
                        raise InfrastructureUnavailable(
                            f"desktop session is {desktop_preflight.get('state')}"
                        )
                cache_entry = arguments.cache_root / asset.filename
                if not asset_preflight(evidence, cache_entry, arguments.allow_network):
                    continue
                installer = fetch_asset(arguments, asset.app_id)
                if asset.package_kind not in {"installer", "portable-zip"}:
                    raise AcceptanceError(f"{asset.app_id} package kind is unsupported")
                if asset.package_kind == "portable-zip":
                    evidence["packageMaterialization"] = materialize_portable_zip(
                        installer,
                        bottle_root,
                        asset.sha256,
                    )
                    installer = bottle_root.joinpath(*Path(asset.installed_executable).parts)
                if arguments.accept_interactive:
                    # Wine inventories fonts while it initializes a fresh prefix. Stage
                    # the Bottle-local CJK font before the installer performs that first
                    # launch so every application can resolve the copied family.
                    failure_stage = "font-stage"
                    evidence["cjkFont"] = stage_macos_cjk_font(bottle_root)
                failure_stage = "core-inspection"
                installer_inspection = json_object(
                    invoke([str(arguments.compatforge_cli), "inspect", str(installer)]),
                    f"{asset.app_id} installer inspection",
                )
                installer_architecture = installer_inspection.get("architecture")
                if not isinstance(installer_architecture, str):
                    raise AcceptanceError(f"{asset.app_id} installer inspection omitted architecture")
                evidence["installerInspection"] = installer_inspection
                if asset.package_kind == "portable-zip":
                    installed = installed_executable(asset, bottle_root)
                else:
                    preparation_mode = "immutableArtifact"
                    if asset.app_id == "sumatrapdf":
                        installer = materialize_sumatrapdf_portable(
                            installer,
                            bottle_root,
                            asset.sha256,
                        )
                        preparation_mode = "bottleInPlace"
                    inspection_request = {
                        "schemaVersion": "1",
                        "requestId": str(uuid.uuid4()),
                        "bottleId": bottle_id,
                        "executable": {
                            "path": str(installer),
                            "architecture": request_architecture(installer_architecture),
                            "mode": preparation_mode,
                        },
                        "arguments": list(asset.install_args),
                        "environment": dict(asset.runtime_environment),
                        "constraints": {
                            "allowVirtualMachine": False,
                            "allowRemote": False,
                            "networkPolicy": "deny",
                        },
                    }
                    installer_request_path = (
                        arguments.work_root / f"{asset.app_id}-installer-request.json"
                    )
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
                                str(asset.install_wait_milliseconds),
                            ]
                        ),
                        f"{asset.app_id} installer",
                    )
                    evidence["installerEvents"] = installer_events
                    evidence["installerExit"] = exit_observation(installer_events)
                    installed = installed_executable(asset, bottle_root)
                    if not installer_succeeded(
                        evidence,
                        installer_events,
                        installed,
                        allow_requested_termination=installer_allows_requested_termination(
                            asset,
                            certification_mode=certification_mode,
                        ),
                    ):
                        continue
                if arguments.accept_interactive:
                    failure_stage = "font-stage"
                    registration_wineserver = cleanup_wineserver
                    if registration_wineserver is None and all(
                        value is not None
                        for value in (arguments.wine_root, arguments.wineserver)
                    ):
                        registration_wineserver = Path(arguments.wine_root) / arguments.wineserver
                    if registration_wineserver is None:
                        raise CjkFontIntegrityError("wineserver executable is unavailable")
                    wine_value = runtime_binding.get("executable")  # type: ignore[union-attr]
                    if not isinstance(wine_value, str) and all(
                        value is not None
                        for value in (arguments.wine_root, arguments.wine)
                    ):
                        wine_value = str(Path(arguments.wine_root) / arguments.wine)
                    if not isinstance(wine_value, str) or not Path(wine_value).is_absolute():
                        raise CjkFontIntegrityError("Wine executable is unavailable")
                    evidence["cjkFontRegistration"] = register_macos_cjk_font(
                        Path(wine_value),
                        registration_wineserver,
                        bottle_root.parent,
                    )
                    if asset.app_id == "notepad-plus-plus":
                        evidence["notepadCjkStyle"] = configure_notepad_cjk_font(
                            bottle_root
                        )
                launch_request = {
                    "schemaVersion": "1",
                    "requestId": (
                        "pinned-sumatrapdf"
                        if asset.app_id == "sumatrapdf"
                        else str(uuid.uuid4())
                    ),
                    "bottleId": bottle_id,
                    "executable": {
                        "path": str(installed),
                        "architecture": "x86_64",
                        "mode": "bottleInPlace",
                    },
                    "arguments": list(asset.launch_args),
                    "environment": dict(asset.runtime_environment),
                    "constraints": {
                        "allowVirtualMachine": False,
                        "allowRemote": False,
                        "networkPolicy": "deny",
                    },
                }
                launch_request_path = arguments.work_root / f"{asset.app_id}-launch-request.json"
                if asset.app_id == "sumatrapdf":
                    write_json(launch_request_path, launch_request)
                else:
                    failure_stage = "core-inspection"
                    revalidate_installed_executable(installed)
                    gui_inspection = json_object(
                        invoke([str(arguments.compatforge_cli), "inspect", str(installed)]),
                        f"{asset.app_id} GUI inspection",
                    )
                    revalidate_installed_executable(installed)
                    gui_architecture = gui_inspection.get("architecture")
                    if not isinstance(gui_architecture, str):
                        raise AcceptanceError(f"{asset.app_id} GUI inspection omitted architecture")
                    if request_architecture(gui_architecture) != asset.guest_architecture:
                        raise AcceptanceError(
                            f"{asset.app_id} GUI architecture does not match the fixed matrix"
                        )
                    launch_request["executable"]["architecture"] = request_architecture(gui_architecture)  # type: ignore[index]
                    write_json(launch_request_path, launch_request)
                    evidence["inspection"] = gui_inspection
                    failure_stage = "core-plan"
                    revalidate_installed_executable(installed)
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
                    revalidate_installed_executable(installed)
                failure_stage = "desktop-launch"
                interaction_state: dict[str, object] = {
                    "checks": None,
                    "error": None,
                }

                def acknowledge_live_window(
                    process: subprocess.Popen[str],
                    remaining_budget: float,
                ) -> None:
                    if interaction_session is None:
                        return
                    try:
                        interaction_session.revalidate()
                        if process.poll() is not None:
                            raise InteractionUnverifiedError(
                                "application closed before interaction acknowledgement"
                            )
                        if remaining_budget <= 0:
                            raise InteractionUnverifiedError(
                                "application interaction acknowledgement timed out"
                            )
                        interaction_state["checks"] = (
                            interaction_session.acknowledge_application(
                                app_id=asset.app_id,
                                runtime_version=receipt["version"],
                                pack_digest=receipt["packDigest"],
                                asset_digest="sha256:" + asset.sha256,
                                window_observed=True,
                                application_alive=lambda: process.poll() is None,
                                deadline_seconds=min(
                                    float(ACKNOWLEDGEMENT_WAIT_SECONDS),
                                    remaining_budget,
                                ),
                            )
                        )
                    except (
                        InteractionUnverifiedError,
                        InteractionInvalidError,
                        InteractionIntegrityError,
                        InteractionCleanupError,
                    ) as error:
                        interaction_state["error"] = error
                    finally:
                        try:
                            interaction_session.revalidate()
                        except InteractionIntegrityError as error:
                            interaction_state["error"] = error

                if interaction_session is not None:
                    interaction_session.revalidate()
                revalidate_installed_executable(installed)
                terminal_records: list[dict[str, object]] | None = None
                pass_fds: tuple[int, ...] = ()
                launch_command = "prepared-launch-terminate"
                launch_arguments = [
                    str(arguments.compatforge_cli),
                    launch_command,
                    str(context_path),
                    str(installed),
                    str(launch_request_path),
                ]
                forbidden_transcript_values: tuple[str, ...] = ()
                if asset.app_id == "sumatrapdf":
                    protocol = _acknowledgement_protocol()
                    pinned_work_root, pinned_work_root_identity = (
                        create_pinned_evidence_work_root(arguments.work_root)
                    )
                    try:
                        work_binding = protocol._bind_directory(
                            pinned_work_root, "pinned evidence work root"
                        )
                    except protocol.AcknowledgementError as error:
                        raise AcceptanceError(
                            "pinned evidence work root is invalid"
                        ) from error
                    work_descriptor = work_binding.handle
                    if type(work_descriptor) is not int or work_descriptor < 3:
                        protocol._close_directory(work_binding)
                        raise AcceptanceError("pinned evidence work root is invalid")
                    pinned_descriptors.append(work_descriptor)
                    try:
                        inspection_output = create_anonymous_pinned_output(
                            work_descriptor
                        )
                        pinned_descriptors.append(inspection_output.descriptor)
                        plan_output = create_anonymous_pinned_output(work_descriptor)
                        pinned_descriptors.append(plan_output.descriptor)
                    except BaseException:
                        raise
                    if (
                        len(set(pinned_descriptors)) != 3
                        or inspection_output.identity == plan_output.identity
                        or any(descriptor < 3 for descriptor in pinned_descriptors)
                    ):
                        raise AcceptanceError("pinned evidence descriptors alias")
                    revalidate_pinned_work_root(work_binding)
                    launch_command = "prepared-pinned-sumatrapdf-launch-terminate"
                    launch_arguments = [
                        str(arguments.compatforge_cli),
                        launch_command,
                        str(context_path),
                        str(installed),
                        str(launch_request_path),
                        str(pinned_work_root),
                        str(work_descriptor),
                        str(inspection_output.descriptor),
                        str(plan_output.descriptor),
                    ]
                    pass_fds = tuple(pinned_descriptors)
                    terminal_records = []
                    forbidden_transcript_values = (
                        str(context_path),
                        str(installed),
                        str(launch_request_path),
                        str(pinned_work_root),
                        *(f'"{descriptor}"' for descriptor in pinned_descriptors),
                    )
                launch_arguments.append(
                    str(
                        INTERACTIVE_RUNTIME_MILLISECONDS
                        if live_interaction
                        else launch_runtime_milliseconds(
                            asset.window_appearance_seconds,
                            asset.screenshot_delay_seconds,
                            arguments.accept_interactive,
                        )
                    )
                )
                events, windows, shot, process_group_id = observed_launch(
                    launch_arguments,
                    arguments.work_root / f"{asset.app_id}.png",
                    asset.window_title_tokens,
                    on_window_observed=(
                        acknowledge_live_window
                        if interaction_session is not None
                        else None
                    ),
                    pass_fds=pass_fds,
                    terminal_records=terminal_records,
                    require_empty_stderr=asset.app_id == "sumatrapdf",
                    forbidden_transcript_values=forbidden_transcript_values,
                    observed_executable=Path(os.fspath(installed)),
                    screenshot_delay_seconds=asset.screenshot_delay_seconds,
                    window_appearance_seconds=asset.window_appearance_seconds,
                )
                if interaction_session is not None:
                    interaction_session.revalidate()
                if asset.app_id == "sumatrapdf":
                    revalidate_pinned_work_root(work_binding)
                    if terminal_records is None or len(terminal_records) != 1:
                        raise AcceptanceError("pinned evidence receipt is missing")
                    outputs = parse_pinned_receipt(terminal_records[0])
                    evidence["inspection"] = read_pinned_evidence(
                        inspection_output, outputs[0]
                    )
                    revalidate_pinned_work_root(work_binding)
                    evidence["plan"] = read_pinned_evidence(plan_output, outputs[1])
                    revalidate_pinned_work_root(work_binding)
                revalidate_installed_executable(installed)
                evidence["events"] = events
                evidence["exit"] = exit_observation(events)
                evidence["windows"] = windows
                evidence["screenshot"] = shot
                evidence["observation"] = observation_diagnostic(windows, shot)
                process_marker: Path | str = (
                    bottle_root if certification_mode else str(bottle_root)
                )
                evidence["residualProcesses"] = process_snapshot(
                    process_marker, process_group_id
                )
                if not certification_mode:
                    interaction_error = interaction_state["error"]
                    checks = interaction_state["checks"]
                    if isinstance(
                        interaction_error,
                        (InteractionIntegrityError, InteractionCleanupError),
                    ):
                        raise interaction_error
                    evaluate_live_interaction_outcome(
                        evidence,
                        asset.app_id,
                        events,
                        windows,
                        shot,
                        evidence["residualProcesses"],
                        checks if isinstance(checks, dict) else None,
                        interaction_error
                        if isinstance(interaction_error, AcceptanceError)
                        else None,
                    )
                else:
                    if manual_attestation:
                        evidence["interactionAttestation"] = manual_attestation
                    evaluate_certification_outcome(
                        evidence,
                        asset.app_id,
                        events,
                        windows,
                        shot,
                        evidence["residualProcesses"],
                        manual_checks.get(asset.app_id, {}),
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
            except ExecutableIntegrityError:
                raise
            except (InteractionIntegrityError, InteractionCleanupError):
                raise
            except InfrastructureUnavailable as error:
                evidence["status"] = "unverified"
                evidence["reason"] = str(error)
                evidence["failureClassification"] = "test-infrastructure"
            except (AcceptanceError, OSError, subprocess.TimeoutExpired, zipfile.BadZipFile) as error:
                apply_stage_outcome(
                    evidence,
                    failure_stage,
                    diagnostic=str(error),
                )
            finally:
                descriptor_cleanup_failed = False
                for descriptor in reversed(pinned_descriptors):
                    try:
                        os.close(descriptor)
                    except OSError:
                        descriptor_cleanup_failed = True
                pinned_descriptors.clear()
                if descriptor_cleanup_failed:
                    apply_stage_outcome(
                        evidence,
                        "cleanup-termination",
                        diagnostic="pinned evidence descriptor cleanup failed",
                    )
                try:
                    remove_pinned_evidence_work_root(
                        pinned_work_root,
                        pinned_work_root_identity,
                    )
                except AcceptanceError as error:
                    apply_stage_outcome(
                        evidence,
                        "cleanup-termination",
                        diagnostic=str(error),
                    )
                close_installed_executable(installed)
                cleanup_diagnostic = "Bottle cleanup failed"
                try:
                    bottle_prefix = arguments.storage_root / "bottles" / bottle_id / "prefix"
                    cleanup_marker: Path | str = (
                        bottle_root if certification_mode else str(bottle_root)
                    )
                    residual_before_delete = process_snapshot(cleanup_marker)
                    if residual_before_delete:
                        if cleanup_wineserver is None:
                            raise AcceptanceError(
                                "Bottle wineserver cleanup binding is unavailable"
                            )
                        stop_bottle_wineserver(cleanup_wineserver, bottle_prefix)
                        residual_before_delete = process_snapshot(cleanup_marker)
                    if residual_before_delete:
                        evidence["residualProcesses"] = residual_before_delete
                        raise AcceptanceError("Bottle cleanup left residual processes")
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
                if interaction_session is not None:
                    interaction_session.revalidate()
                finished_at = utc_now()
                evidence["finishedAt"] = finished_at
                result = compatibility_result(asset, evidence, receipt, started_at, finished_at)
                write_json(arguments.work_root / f"{asset.app_id}-evidence.json", evidence)
                write_json(arguments.work_root / f"{asset.app_id}-compatibility-result.json", result)
                results.append(evidence)
                compatibility_results.append(result)

        if not certification_mode:
            if interaction_session is not None:
                interaction_session.revalidate()
            bind_runtime_identity(runtime_id, receipt, results)
            summary = compact_summary(receipt, results)
            stdout = compact_json(summary)
        else:
            summary = certification_summary(
                receipt,
                results,
                compatibility_results,
            )
            stdout = json.dumps(
                summary,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        write_json(arguments.work_root / "summary.json", summary)
        print(stdout)
        return 0 if all(value["status"] == "accepted" for value in results) else 1
    except (
        AcceptanceError,
        OSError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
        ImportError,
        zipfile.BadZipFile,
    ) as error:
        print(f"compatforge-gui-baseline: {error}", file=sys.stderr)
        return 1
    finally:
        if interaction_session is not None:
            interaction_session.close()


if __name__ == "__main__":
    raise SystemExit(main())
