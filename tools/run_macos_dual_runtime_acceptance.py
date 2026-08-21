#!/usr/bin/env python3
"""Run the bounded developer-local dual-Runtime macOS acceptance matrix."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Sequence


ROOT = Path(__file__).resolve().parents[1]
DISCOVERY_TOOL = ROOT / "tools" / "discover_macos_wine.py"
HEADLESS_TOOL = ROOT / "tools" / "run_macos_headless_preview.py"
GUI_TOOL = ROOT / "tools" / "run_gui_baseline.py"

RUNTIME_MATRIX = {
    "crossover": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
    "whisky": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
}
ROUNDS = ("round-1", "round-2")
RUNTIME_IDS = tuple(RUNTIME_MATRIX)
GUI_APPLICATIONS = ("7zip", "sumatrapdf", "notepad-plus-plus")
PHASES = ("console", "gui", "desktop")

REQUIRED_INTERACTIONS = {
    "7zip": ("fileList", "menus"),
    "sumatrapdf": ("mainWindow", "openDialog"),
    "notepad-plus-plus": ("open", "edit", "saveUtf8Chinese", "rereadMatches"),
}
STATUSES = ("accepted", "failed", "unverified", "blocked")
FAILURE_CLASSES = ("environment", "runtime", "core", "desktop", "application", "cleanup")
GUI_FAILURE_RELATIONS = {
    "platform-unsupported": ("blocked", "environment"),
    "tool-unavailable": ("blocked", "environment"),
    "network-unavailable": ("blocked", "environment"),
    "rosetta-unavailable": ("blocked", "environment"),
    "asset-fetch-failed": ("failed", "environment"),
    "runtime-descriptor-invalid": ("blocked", "runtime"),
    "runtime-start-failed": ("failed", "runtime"),
    "runtime-version-invalid": ("failed", "runtime"),
    "core-snapshot-failed": ("failed", "core"),
    "core-plan-failed": ("failed", "core"),
    "core-import-failed": ("failed", "core"),
    "core-inspection-failed": ("failed", "core"),
    "core-launch-failed": ("failed", "core"),
    "core-verification-failed": ("failed", "core"),
    "core-rollback-failed": ("failed", "core"),
    "desktop-launch-failed": ("failed", "desktop"),
    "desktop-window-unobserved": ("failed", "desktop"),
    "application-install-failed": ("failed", "application"),
    "application-interaction-unverified": ("unverified", "application"),
    "application-content-verification-failed": ("failed", "application"),
    "cleanup-residual-processes": ("failed", "cleanup"),
    "cleanup-termination-failed": ("failed", "cleanup"),
    "cleanup-delete-failed": ("failed", "cleanup"),
}

MAX_JSON_BYTES = 64 * 1024
MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 512
MAX_TEXT_CHARS = 4096
DISCOVERY_TIMEOUT_SECONDS = 30
CHILD_TIMEOUT_SECONDS = 20 * 60
DESKTOP_TIMEOUT_SECONDS = 20 * 60
CHILD_ENV = {"LANG": "C", "LC_ALL": "C"}
RUNTIME_DESCRIPTOR_KEYS = {
    "schemaVersion",
    "runtimeId",
    "source",
    "materializedRoot",
    "wine",
    "wineserver",
    "version",
    "architecture",
}


class AcceptanceError(Exception):
    """Report a closed developer-local acceptance failure."""


class ClosedArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        raise AcceptanceError("invalid command-line arguments")


class UniqueValueAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error("duplicate argument")
        if not isinstance(values, str) or not values:
            parser.error("empty argument")
        setattr(namespace, self.dest, values)


class UniqueFlagAction(argparse.Action):
    def __init__(self, option_strings: Sequence[str], dest: str, **kwargs: object) -> None:
        super().__init__(option_strings, dest, nargs=0, default=None, **kwargs)

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        del values, option_string
        if getattr(namespace, self.dest, None) is not None:
            parser.error("duplicate flag")
        setattr(namespace, self.dest, True)


@dataclass(frozen=True)
class AcceptancePaths:
    compatforge_cli: Path
    desktop_app: Path
    cc: Path
    cache_root: Path
    runtime_store_root: Path
    storage_root: Path
    work_root: Path
    interaction_evidence_root: Path
    allow_network: bool


Runner = Callable[..., subprocess.CompletedProcess[str]]
Launcher = Callable[..., object]
Waiter = Callable[[object, int], int]
Printer = Callable[[str], object]


def require_python(version: tuple[int, int, int]) -> None:
    """Reject interpreters below the repository's supported Python floor."""

    if version < (3, 11, 0):
        raise AcceptanceError("Python 3.11 or newer is required")


def parser() -> argparse.ArgumentParser:
    value = ClosedArgumentParser(description=__doc__, allow_abbrev=False)
    for flag in (
        "compatforge-cli",
        "desktop-app",
        "cc",
        "cache-root",
        "runtime-store-root",
        "storage-root",
        "work-root",
        "interaction-evidence-root",
    ):
        value.add_argument(f"--{flag}", required=True, action=UniqueValueAction)
    value.add_argument("--allow-network", action=UniqueFlagAction)
    return value


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    require_python(sys.version_info[:3])
    parsed = parser().parse_args(list(arguments))
    parsed.allow_network = parsed.allow_network is True
    return parsed


def _absolute(value: object, field: str) -> Path:
    if not isinstance(value, str) or not value:
        raise AcceptanceError(f"{field} must be an absolute non-traversing path")
    path = Path(value)
    if not path.is_absolute() or any(part in ("", ".", "..") for part in path.parts[1:]):
        raise AcceptanceError(f"{field} must be an absolute non-traversing path")
    return path


def _is_reparse(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & marker)


def _reject_unsafe_components(path: Path, field: str) -> None:
    for component in reversed((path, *path.parents)):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise AcceptanceError(f"{field} has an unreadable path component") from error
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            raise AcceptanceError(f"{field} has an unsafe path component")


def _canonical(path: Path, field: str) -> Path:
    _reject_unsafe_components(path, field)
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise AcceptanceError(f"{field} could not be resolved") from error


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _regular_executable(path: Path, field: str) -> None:
    try:
        metadata = path.stat()
    except OSError as error:
        raise AcceptanceError(f"{field} must be a regular executable") from error
    if not stat.S_ISREG(metadata.st_mode) or os.access(path, os.X_OK) is False:
        raise AcceptanceError(f"{field} must be a regular executable")


def _empty_or_absent_directory(path: Path, field: str) -> None:
    if not path.exists():
        return
    if not path.is_dir():
        raise AcceptanceError(f"{field} must be an empty directory or absent")
    try:
        if next(path.iterdir(), None) is not None:
            raise AcceptanceError(f"{field} must be empty")
    except OSError as error:
        raise AcceptanceError(f"{field} could not be read") from error


def _bounded_structure(value: object, label: str) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    visited = 0
    while stack:
        current, depth = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise AcceptanceError(f"{label} exceeds its structural bound")
        visited += 1
        if visited > MAX_JSON_NODES:
            raise AcceptanceError(f"{label} exceeds its structural bound")
        if isinstance(current, dict):
            if any(not isinstance(key, str) or not key for key in current):
                raise AcceptanceError(f"{label} contains an invalid key")
            stack.extend((key, depth + 1) for key in current)
            stack.extend((nested, depth + 1) for nested in current.values())
        elif isinstance(current, list):
            stack.extend((nested, depth + 1) for nested in current)
        elif isinstance(current, str):
            if len(current) > MAX_TEXT_CHARS or any(
                ord(character) < 32 or ord(character) == 127 for character in current
            ):
                raise AcceptanceError(f"{label} contains invalid text")
        elif current is not None and not isinstance(current, (bool, int)):
            raise AcceptanceError(f"{label} contains an unsupported value")


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, nested in pairs:
        if key in value:
            raise AcceptanceError("JSON contains a duplicate key")
        value[key] = nested
    return value


def parse_closed_json(text: object, label: str) -> object:
    if not isinstance(text, str):
        raise AcceptanceError(f"{label} JSON is invalid")
    try:
        size = len(text.encode("utf-8"))
    except UnicodeError as error:
        raise AcceptanceError(f"{label} JSON is invalid") from error
    if size > MAX_JSON_BYTES:
        raise AcceptanceError(f"{label} JSON exceeds its size bound")
    try:
        value = json.loads(text, object_pairs_hook=_closed_object)
    except AcceptanceError:
        raise
    except (json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise AcceptanceError(f"{label} JSON is invalid") from error
    _bounded_structure(value, label)
    return value


def _read_closed_json(path: Path, label: str) -> object:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise AcceptanceError(f"{label} is missing") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or metadata.st_size > MAX_JSON_BYTES
    ):
        raise AcceptanceError(f"{label} must be a bounded regular file")
    try:
        with path.open("rb") as source:
            data = source.read(MAX_JSON_BYTES + 1)
        if len(data) > MAX_JSON_BYTES:
            raise AcceptanceError(f"{label} JSON exceeds its size bound")
        text = data.decode("utf-8")
    except AcceptanceError:
        raise
    except (OSError, UnicodeError) as error:
        raise AcceptanceError(f"{label} could not be read") from error
    return parse_closed_json(text, label)


def _validate_interaction_document(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "applications"}:
        raise AcceptanceError("interaction evidence schema is invalid")
    if value["schemaVersion"] != "1" or not isinstance(value["applications"], dict):
        raise AcceptanceError("interaction evidence schema is invalid")
    applications = value["applications"]
    if set(applications) != set(GUI_APPLICATIONS):
        raise AcceptanceError("interaction evidence applications are incomplete")
    for application_id, required in REQUIRED_INTERACTIONS.items():
        checks = applications[application_id]
        if (
            not isinstance(checks, dict)
            or set(checks) != set(required)
            or any(not isinstance(checked, bool) for checked in checks.values())
        ):
            raise AcceptanceError("interaction evidence checks are incomplete")


def _bounded_entries(root: Path, limit: int, label: str) -> list[Path]:
    entries: list[Path] = []
    try:
        with os.scandir(root) as iterator:
            for entry in iterator:
                if len(entries) >= limit:
                    raise AcceptanceError(f"{label} contains too many entries")
                entries.append(root / entry.name)
    except AcceptanceError:
        raise
    except OSError as error:
        raise AcceptanceError(f"{label} could not be read") from error
    return entries


def _validate_interaction_root(root: Path) -> None:
    if not root.is_dir():
        raise AcceptanceError("interaction-evidence-root must be a directory")
    entries = _bounded_entries(root, len(ROUNDS), "interaction evidence root")
    if len(entries) != len(ROUNDS) or {entry.name for entry in entries} != set(ROUNDS):
        raise AcceptanceError("interaction evidence layout is incomplete or contains extras")
    for round_id in ROUNDS:
        round_root = root / round_id
        _reject_unsafe_components(round_root, "interaction evidence")
        if not round_root.is_dir():
            raise AcceptanceError("interaction evidence round must be a directory")
        expected = {f"{runtime_id}.json" for runtime_id in RUNTIME_IDS}
        round_entries = _bounded_entries(
            round_root, len(expected), "interaction evidence round"
        )
        if len(round_entries) != len(expected) or {entry.name for entry in round_entries} != expected:
            raise AcceptanceError("interaction evidence layout is incomplete or contains extras")
        for runtime_id in RUNTIME_IDS:
            document = _read_closed_json(
                round_root / f"{runtime_id}.json", "interaction evidence"
            )
            _validate_interaction_document(document)


def preflight(
    arguments: argparse.Namespace,
    *,
    host_system: str,
    host_machine: str,
) -> AcceptancePaths:
    require_python(sys.version_info[:3])
    if host_system != "Darwin" or host_machine != "arm64":
        raise AcceptanceError("host must be Darwin/arm64")

    named = {
        "compatforge-cli": _absolute(arguments.compatforge_cli, "compatforge-cli"),
        "desktop-app": _absolute(arguments.desktop_app, "desktop-app"),
        "cc": _absolute(arguments.cc, "cc"),
        "cache-root": _absolute(arguments.cache_root, "cache-root"),
        "runtime-store-root": _absolute(arguments.runtime_store_root, "runtime-store-root"),
        "storage-root": _absolute(arguments.storage_root, "storage-root"),
        "work-root": _absolute(arguments.work_root, "work-root"),
        "interaction-evidence-root": _absolute(
            arguments.interaction_evidence_root, "interaction-evidence-root"
        ),
    }
    resolved = {field: _canonical(path, field) for field, path in named.items()}
    repository = ROOT.resolve(strict=True)
    tools = [resolved["compatforge-cli"], resolved["desktop-app"], resolved["cc"]]
    roots = [
        resolved["cache-root"],
        resolved["runtime-store-root"],
        resolved["storage-root"],
        resolved["work-root"],
        resolved["interaction-evidence-root"],
    ]
    for tool, field in zip(tools, ("compatforge-cli", "desktop-app", "cc")):
        _regular_executable(tool, field)
    if len(set(tools)) != len(tools):
        raise AcceptanceError("tool paths must be distinct")
    for root in roots:
        if _overlaps(root, repository):
            raise AcceptanceError("acceptance roots must be outside the repository")
        if any(_overlaps(root, tool) for tool in tools):
            raise AcceptanceError("acceptance roots overlap a tool path")
    for index, left in enumerate(roots):
        if any(_overlaps(left, right) for right in roots[index + 1 :]):
            raise AcceptanceError("acceptance roots overlap")

    cache_root = resolved["cache-root"]
    if cache_root.exists() and not cache_root.is_dir():
        raise AcceptanceError("cache-root must be a directory or absent")
    _empty_or_absent_directory(resolved["runtime-store-root"], "runtime-store-root")
    _empty_or_absent_directory(resolved["storage-root"], "storage-root")
    _empty_or_absent_directory(resolved["work-root"], "work-root")
    _validate_interaction_root(resolved["interaction-evidence-root"])

    return AcceptancePaths(
        compatforge_cli=resolved["compatforge-cli"],
        desktop_app=resolved["desktop-app"],
        cc=resolved["cc"],
        cache_root=cache_root,
        runtime_store_root=resolved["runtime-store-root"],
        storage_root=resolved["storage-root"],
        work_root=resolved["work-root"],
        interaction_evidence_root=resolved["interaction-evidence-root"],
        allow_network=arguments.allow_network is True,
    )


def _portable_entrypoint(value: object, field: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise AcceptanceError(f"Runtime {field} is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise AcceptanceError(f"Runtime {field} is invalid")
    return path


def _safe_text(value: object, field: str, *, max_chars: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_chars
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise AcceptanceError(f"{field} is invalid")
    return value


def parse_discovery(text: object, arguments: argparse.Namespace) -> list[dict[str, str]]:
    value = parse_closed_json(text, "Runtime discovery")
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "runtimes"}:
        raise AcceptanceError("Runtime discovery keys are invalid")
    runtimes = value["runtimes"]
    if value["schemaVersion"] != "1" or not isinstance(runtimes, list) or len(runtimes) != 2:
        raise AcceptanceError("Runtime discovery schema is invalid")
    if [runtime.get("runtimeId") if isinstance(runtime, dict) else None for runtime in runtimes] != list(
        RUNTIME_IDS
    ):
        raise AcceptanceError("Runtime order is invalid")

    protected = [
        ROOT.resolve(strict=True),
        *(
            _canonical(_absolute(getattr(arguments, field), field), field)
            for field in (
                "compatforge_cli",
                "desktop_app",
                "cc",
                "cache_root",
                "runtime_store_root",
                "storage_root",
                "work_root",
                "interaction_evidence_root",
            )
        ),
    ]
    validated: list[dict[str, str]] = []
    runtime_roots: list[Path] = []
    for runtime_id, descriptor in zip(RUNTIME_IDS, runtimes):
        if not isinstance(descriptor, dict) or set(descriptor) != RUNTIME_DESCRIPTOR_KEYS:
            raise AcceptanceError("Runtime descriptor keys are invalid")
        if (
            descriptor["schemaVersion"] != "1"
            or descriptor["runtimeId"] != runtime_id
            or descriptor["architecture"] != "x86_64"
        ):
            raise AcceptanceError("Runtime descriptor identity is invalid")
        source = _safe_text(descriptor["source"], "Runtime source")
        expected_sources = {
            "crossover": {"crossover-app"},
            "whisky": {"whisky-app", "whisky-library"},
        }
        if source not in expected_sources[runtime_id]:
            raise AcceptanceError("Runtime descriptor source is invalid")
        version = _safe_text(descriptor["version"], "Runtime version")
        root = _canonical(_absolute(descriptor["materializedRoot"], "Runtime root"), "Runtime root")
        if not root.is_dir() or any(_overlaps(root, protected_path) for protected_path in protected):
            raise AcceptanceError("Runtime root is invalid or overlaps protected input")
        if any(_overlaps(root, other) for other in runtime_roots):
            raise AcceptanceError("Runtime roots overlap")
        runtime_roots.append(root)
        wine = _portable_entrypoint(descriptor["wine"], "wine")
        wineserver = _portable_entrypoint(descriptor["wineserver"], "wineserver")
        for entrypoint, field in ((wine, "wine"), (wineserver, "wineserver")):
            executable = root.joinpath(*entrypoint.parts)
            _reject_unsafe_components(executable, f"Runtime {field}")
            try:
                resolved_executable = executable.resolve(strict=True)
            except OSError as error:
                raise AcceptanceError(f"Runtime {field} is invalid") from error
            if root not in resolved_executable.parents:
                raise AcceptanceError(f"Runtime {field} escapes its root")
            _regular_executable(resolved_executable, f"Runtime {field}")
        validated.append(
            {
                "runtimeId": runtime_id,
                "source": source,
                "materializedRoot": str(root),
                "wine": wine.as_posix(),
                "wineserver": wineserver.as_posix(),
                "version": version,
            }
        )
    return validated


def _invoke(
    arguments: Sequence[str],
    runner: Runner,
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    try:
        result = runner(
            list(arguments),
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env=dict(CHILD_ENV),
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AcceptanceError("bounded child process failed") from error
    if not isinstance(result.stdout, str) or not isinstance(result.stderr, str):
        raise AcceptanceError("child process output is invalid")
    try:
        stdout_size = len(result.stdout.encode("utf-8"))
        stderr_size = len(result.stderr.encode("utf-8"))
    except UnicodeError as error:
        raise AcceptanceError("child process output is invalid") from error
    if stdout_size > MAX_JSON_BYTES or stderr_size > MAX_JSON_BYTES:
        raise AcceptanceError("child process output exceeds its size bound")
    return result


def discover_runtimes(arguments: argparse.Namespace, runner: Runner) -> list[dict[str, str]]:
    result = _invoke(
        [sys.executable, "-S", "-B", str(DISCOVERY_TOOL), "--all"],
        runner,
        timeout=DISCOVERY_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise AcceptanceError("Runtime discovery failed")
    return parse_discovery(result.stdout, arguments)


def _prepare_layout(paths: AcceptancePaths) -> None:
    for root, field in (
        (paths.runtime_store_root, "runtime-store-root"),
        (paths.storage_root, "storage-root"),
        (paths.work_root, "work-root"),
    ):
        _reject_unsafe_components(root, field)
        _empty_or_absent_directory(root, field)
    try:
        for root in (paths.cache_root, paths.runtime_store_root, paths.storage_root, paths.work_root):
            root.mkdir(parents=True, exist_ok=True)
        for round_id in ROUNDS:
            for runtime_id in RUNTIME_IDS:
                for phase in PHASES:
                    (paths.work_root / round_id / runtime_id / phase).mkdir(parents=True)
                for phase in ("console", "gui"):
                    (paths.runtime_store_root / round_id / runtime_id / phase).mkdir(parents=True)
                    (paths.storage_root / round_id / runtime_id / phase).mkdir(parents=True)
    except OSError as error:
        raise AcceptanceError("acceptance layout could not be created") from error


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise AcceptanceError(f"{field} is invalid")
    return value


def _project_console(value: object, descriptor: dict[str, str]) -> dict[str, object]:
    required = {
        "schemaVersion",
        "packId",
        "packVersion",
        "packDigest",
        "guestDigest",
        "hostArchitecture",
        "runtime",
        "runtimeSource",
        "translator",
        "graphics",
        "eventKinds",
        "exitCode",
        "success",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise AcceptanceError("Console summary keys are invalid")
    expected_pack = f"wine-macos-{descriptor['runtimeId']}-preview"
    if (
        value["schemaVersion"] != "1"
        or value["packId"] != expected_pack
        or value["packVersion"] != descriptor["version"]
        or value["hostArchitecture"] != "arm64"
        or value["runtime"] != "wine"
        or value["runtimeSource"] != "explicit"
        or value["translator"] != "rosetta"
        or value["graphics"] != "wined3d"
        or value["exitCode"] != 0
        or value["success"] is not True
    ):
        raise AcceptanceError("Console summary identity is invalid")
    kinds = value["eventKinds"]
    if (
        not isinstance(kinds, list)
        or not kinds
        or any(not isinstance(kind, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", kind) for kind in kinds)
    ):
        raise AcceptanceError("Console event kinds are invalid")
    return {
        "schemaVersion": "1",
        "runtimeId": descriptor["runtimeId"],
        "appId": "console",
        "status": "accepted",
        "packDigest": _digest(value["packDigest"], "Console pack digest"),
        "guestDigest": _digest(value["guestDigest"], "Console guest digest"),
        "eventKinds": list(kinds),
        "exitCode": 0,
    }


def _failure(application_id: str, runtime_id: str, failure_class: str, reason_code: str) -> dict[str, object]:
    if failure_class not in FAILURE_CLASSES:
        raise AcceptanceError("internal failure class is invalid")
    return {
        "schemaVersion": "1",
        "runtimeId": runtime_id,
        "appId": application_id,
        "status": "blocked" if reason_code == "console-precondition-failed" else "failed",
        "failureClass": failure_class,
        "reasonCode": reason_code,
    }


def _exact_keys(value: object, required: set[str], optional: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not required.issubset(value) or not set(value).issubset(required | optional):
        raise AcceptanceError(f"{label} keys are invalid")
    return value


def _project_exit(value: object) -> dict[str, object]:
    exit_value = _exact_keys(value, {"present", "code", "success"}, set(), "GUI exit")
    if not isinstance(exit_value["present"], bool) or not isinstance(exit_value["success"], bool):
        raise AcceptanceError("GUI exit flags are invalid")
    code = exit_value["code"]
    if code is not None and (not isinstance(code, int) or isinstance(code, bool)):
        raise AcceptanceError("GUI exit code is invalid")
    return {"present": exit_value["present"], "code": code, "success": exit_value["success"]}


def _project_gui(
    value: object, descriptor: dict[str, str]
) -> tuple[dict[str, object], list[dict[str, object]]]:
    summary = _exact_keys(value, {"schemaVersion", "receipt", "applications"}, set(), "GUI summary")
    if summary["schemaVersion"] != "1":
        raise AcceptanceError("GUI summary schema is invalid")
    receipt = _exact_keys(
        summary["receipt"],
        {"schemaVersion", "runtimeId", "packId", "version", "packDigest", "source"},
        {"activated"},
        "GUI receipt",
    )
    if (
        receipt["schemaVersion"] != "1"
        or receipt["runtimeId"] != descriptor["runtimeId"]
        or receipt["version"] != descriptor["version"]
    ):
        raise AcceptanceError("GUI receipt identity is invalid")
    _safe_text(receipt["packId"], "GUI pack id")
    _safe_text(receipt["source"], "GUI Runtime source")
    receipt_projection: dict[str, object] = {
        "runtimeVersion": descriptor["version"],
        "packDigest": _digest(receipt["packDigest"], "GUI pack digest"),
    }
    if "activated" in receipt and not isinstance(receipt["activated"], bool):
        raise AcceptanceError("GUI receipt activated flag is invalid")

    applications = summary["applications"]
    if not isinstance(applications, list) or len(applications) != len(GUI_APPLICATIONS):
        raise AcceptanceError("GUI applications are incomplete")
    projected: list[dict[str, object]] = []
    optional = {
        "assetSha256",
        "failureClass",
        "reasonCode",
        "interactionChecks",
        "installerExit",
        "exit",
        "windowAvailable",
        "screenshotAvailable",
    }
    for application_id, raw in zip(GUI_APPLICATIONS, applications):
        application = _exact_keys(
            raw,
            {"schemaVersion", "runtimeId", "appId", "status", "cleanup"},
            optional,
            "GUI application",
        )
        status_value = application["status"]
        if (
            application["schemaVersion"] != "1"
            or application["runtimeId"] != descriptor["runtimeId"]
            or application["appId"] != application_id
            or status_value not in STATUSES
            or not isinstance(application["cleanup"], bool)
        ):
            raise AcceptanceError("GUI application identity is invalid")
        output = {
            "schemaVersion": "1",
            "runtimeId": descriptor["runtimeId"],
            "appId": application_id,
            "status": status_value,
            "cleanup": application["cleanup"],
        }
        if status_value == "accepted":
            if "failureClass" in application or "reasonCode" in application:
                raise AcceptanceError("accepted GUI result contains failure metadata")
        else:
            failure_class = application.get("failureClass")
            reason_code = application.get("reasonCode")
            if not isinstance(reason_code, str) or GUI_FAILURE_RELATIONS.get(reason_code) != (
                status_value,
                failure_class,
            ):
                raise AcceptanceError("GUI failure relation is invalid")
            output["failureClass"] = failure_class
            output["reasonCode"] = reason_code
        asset_digest = application.get("assetSha256")
        if asset_digest is not None:
            if not isinstance(asset_digest, str) or re.fullmatch(r"[0-9a-f]{64}", asset_digest) is None:
                raise AcceptanceError("GUI asset digest is invalid")
            output["assetSha256"] = asset_digest
        interactions = application.get("interactionChecks")
        if interactions is not None:
            required_checks = set(REQUIRED_INTERACTIONS[application_id])
            if (
                not isinstance(interactions, dict)
                or set(interactions) != required_checks
                or any(not isinstance(checked, bool) for checked in interactions.values())
            ):
                raise AcceptanceError("GUI interaction checks are invalid")
            output["interactionChecks"] = {
                name: interactions[name] for name in REQUIRED_INTERACTIONS[application_id]
            }
        for field in ("installerExit", "exit"):
            if field in application:
                output[field] = _project_exit(application[field])
        for field in ("windowAvailable", "screenshotAvailable"):
            if field in application:
                if not isinstance(application[field], bool):
                    raise AcceptanceError("GUI observation flag is invalid")
                output[field] = application[field]
        projected.append(output)
    return receipt_projection, projected


def _headless_command(paths: AcceptancePaths, round_id: str, descriptor: dict[str, str]) -> list[str]:
    runtime_id = descriptor["runtimeId"]
    return [
        sys.executable,
        "-S",
        "-B",
        str(HEADLESS_TOOL),
        "--compatforge-cli",
        str(paths.compatforge_cli),
        "--cc",
        str(paths.cc),
        "--wine-root",
        descriptor["materializedRoot"],
        "--wine",
        descriptor["wine"],
        "--wineserver",
        descriptor["wineserver"],
        "--runtime-store",
        str(paths.runtime_store_root / round_id / runtime_id / "console"),
        "--storage-root",
        str(paths.storage_root / round_id / runtime_id / "console"),
        "--work-root",
        str(paths.work_root / round_id / runtime_id / "console"),
        "--pack-id",
        f"wine-macos-{runtime_id}-preview",
        "--version",
        descriptor["version"],
    ]


def _gui_command(paths: AcceptancePaths, round_id: str, descriptor: dict[str, str]) -> list[str]:
    runtime_id = descriptor["runtimeId"]
    command = [
        sys.executable,
        "-S",
        "-B",
        str(GUI_TOOL),
        "--compatforge-cli",
        str(paths.compatforge_cli),
        "--cache-root",
        str(paths.cache_root),
        "--runtime-store",
        str(paths.runtime_store_root / round_id / runtime_id / "gui"),
        "--storage-root",
        str(paths.storage_root / round_id / runtime_id / "gui"),
        "--work-root",
        str(paths.work_root / round_id / runtime_id / "gui"),
        "--runtime-id",
        runtime_id,
        "--wine-root",
        descriptor["materializedRoot"],
        "--wine",
        descriptor["wine"],
        "--wineserver",
        descriptor["wineserver"],
        "--version",
        descriptor["version"],
        "--accept-interactive",
        "--interaction-evidence",
        str(paths.interaction_evidence_root / round_id / f"{runtime_id}.json"),
    ]
    if paths.allow_network:
        command.append("--allow-network")
    return command


def _desktop_command(paths: AcceptancePaths, round_id: str, descriptor: dict[str, str]) -> list[str]:
    runtime_id = descriptor["runtimeId"]
    return [
        str(paths.desktop_app),
        "--acceptance-root",
        str(paths.work_root / round_id / runtime_id / "desktop"),
        "--wine-root",
        descriptor["materializedRoot"],
        "--wine",
        descriptor["wine"],
        "--wineserver",
        descriptor["wineserver"],
        "--version",
        descriptor["version"],
    ]


def _default_waiter(process: object, timeout: int) -> int:
    wait = getattr(process, "wait", None)
    if not callable(wait):
        raise AcceptanceError("desktop launcher did not return a waitable process")
    return int(wait(timeout=timeout))


def _launch_desktop(
    command: list[str],
    launcher: Launcher,
    waiter: Waiter,
    printer: Printer,
) -> dict[str, object]:
    printer("compatforge-desktop-command: " + json.dumps(command, ensure_ascii=False, separators=(",", ":")))
    try:
        process = launcher(
            command,
            cwd=ROOT,
            env=dict(CHILD_ENV),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        returncode = waiter(process, DESKTOP_TIMEOUT_SECONDS)
    except (OSError, subprocess.TimeoutExpired, AcceptanceError):
        return {
            "status": "failed",
            "failureClass": "desktop",
            "reasonCode": "desktop-launch-failed",
        }
    if not isinstance(returncode, int) or isinstance(returncode, bool) or returncode != 0:
        return {
            "status": "failed",
            "failureClass": "desktop",
            "reasonCode": "desktop-exit-failed",
        }
    return {"status": "accepted", "exitCode": 0}


def orchestrate(
    arguments: argparse.Namespace,
    *,
    runner: Runner = subprocess.run,
    launcher: Launcher = subprocess.Popen,
    waiter: Waiter = _default_waiter,
    host_system: str | None = None,
    host_machine: str | None = None,
    printer: Printer = print,
) -> dict[str, object]:
    paths = preflight(
        arguments,
        host_system=platform.system() if host_system is None else host_system,
        host_machine=platform.machine() if host_machine is None else host_machine,
    )
    runtimes = discover_runtimes(arguments, runner)
    _prepare_layout(paths)
    rounds: list[dict[str, object]] = []
    for round_id in ROUNDS:
        runtime_results: list[dict[str, object]] = []
        for descriptor in runtimes:
            runtime_id = descriptor["runtimeId"]
            applications: list[dict[str, object]] = []
            runtime_evidence: dict[str, object] = {}
            try:
                console_result = _invoke(
                    _headless_command(paths, round_id, descriptor),
                    runner,
                    timeout=CHILD_TIMEOUT_SECONDS,
                )
                if console_result.returncode != 0:
                    raise AcceptanceError("Console runner failed")
                console = _project_console(
                    parse_closed_json(console_result.stdout, "Console summary"), descriptor
                )
            except AcceptanceError:
                console = _failure("console", runtime_id, "core", "console-runner-failed")
            applications.append(console)
            if console["status"] != "accepted":
                applications.extend(
                    _failure(application_id, runtime_id, "core", "console-precondition-failed")
                    for application_id in GUI_APPLICATIONS
                )
                desktop = {
                    "status": "blocked",
                    "failureClass": "core",
                    "reasonCode": "console-precondition-failed",
                }
            else:
                try:
                    gui_result = _invoke(
                        _gui_command(paths, round_id, descriptor),
                        runner,
                        timeout=CHILD_TIMEOUT_SECONDS,
                    )
                    runtime_evidence, gui_applications = _project_gui(
                        parse_closed_json(gui_result.stdout, "GUI summary"), descriptor
                    )
                    if gui_result.returncode == 0 and any(
                        application["status"] != "accepted" for application in gui_applications
                    ):
                        raise AcceptanceError("GUI exit status disagrees with its summary")
                    if gui_result.returncode != 0 and all(
                        application["status"] == "accepted" for application in gui_applications
                    ):
                        raise AcceptanceError("GUI exit status disagrees with its summary")
                except AcceptanceError:
                    gui_applications = [
                        _failure(application_id, runtime_id, "application", "gui-summary-invalid")
                        for application_id in GUI_APPLICATIONS
                    ]
                applications.extend(gui_applications)
                desktop = _launch_desktop(
                    _desktop_command(paths, round_id, descriptor), launcher, waiter, printer
                )
            runtime_results.append(
                {
                    "runtimeId": runtime_id,
                    **runtime_evidence,
                    "applications": applications,
                    "desktop": desktop,
                }
            )
        rounds.append({"roundId": round_id, "runtimes": runtime_results})
    accepted = all(
        runtime["desktop"]["status"] == "accepted"
        and all(application["status"] == "accepted" for application in runtime["applications"])
        for round_entry in rounds
        for runtime in round_entry["runtimes"]
    )
    summary: dict[str, object] = {
        "schemaVersion": "1",
        "status": "accepted" if accepted else "failed",
        "rounds": rounds,
    }
    encoded = json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
        raise AcceptanceError("aggregate summary exceeds its size bound")
    try:
        (paths.work_root / "summary.json").write_text(encoded + "\n", encoding="utf-8")
    except OSError as error:
        raise AcceptanceError("aggregate summary could not be written") from error
    return summary


def main() -> int:
    try:
        arguments = parse_arguments(sys.argv[1:])
        summary = orchestrate(arguments)
    except AcceptanceError as error:
        print(f"compatforge-dual-runtime-acceptance: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return 0 if summary["status"] == "accepted" else 1


if __name__ == "__main__":
    raise SystemExit(main())
