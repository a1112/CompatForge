#!/usr/bin/env python3
"""Run the bounded developer-local dual-Runtime macOS acceptance matrix."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Callable, Sequence


ROOT = Path(__file__).resolve().parents[1]
DISCOVERY_TOOL = ROOT / "tools" / "discover_macos_wine.py"
HEADLESS_TOOL = ROOT / "tools" / "run_macos_headless_preview.py"
GUI_TOOL = ROOT / "tools" / "run_gui_baseline.py"
GUI_ASSET_TOOL = ROOT / "tools" / "download_gui_assets.py"

RUNTIME_MATRIX = {
    "crossover": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
    "whisky": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
}
ROUNDS = ("round-1", "round-2")
RUNTIME_IDS = tuple(RUNTIME_MATRIX)
GUI_APPLICATIONS = ("7zip", "sumatrapdf", "notepad-plus-plus")
PHASES = ("console", "gui", "desktop")
GUI_PROVIDER_PACK_ID = "wine-macos-auto-preview"
GUI_EXPLICIT_SOURCE = "explicit-override"

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
APPLICATION_FAILURE_RELATIONS = {
    **GUI_FAILURE_RELATIONS,
    "console-runner-failed": ("failed", "core"),
    "console-precondition-failed": ("blocked", "core"),
    "gui-summary-invalid": ("failed", "application"),
}
DESKTOP_FAILURE_RELATIONS = {
    "console-precondition-failed": ("blocked", "core"),
    "desktop-launch-failed": ("failed", "desktop"),
    "desktop-timeout-failed": ("failed", "desktop"),
    "desktop-exit-failed": ("failed", "desktop"),
}

ROUND_DYNAMIC_KEYS = {"requestId", "startedAt", "durationMs", "workRoot", "runtimeEvents"}
RUNTIME_DYNAMIC_KEYS = {
    "requestId",
    "processIds",
    "startedAt",
    "durationMs",
    "runtimeRoot",
    "runtimeEvents",
}
APPLICATION_DYNAMIC_KEYS = {
    "requestId",
    "pid",
    "startedAt",
    "durationMs",
    "workRoot",
    "screenshotPath",
    "runtimeEvents",
}
RUNTIME_EVENT_KEYS = {"kind", "requestId", "pid", "timestampNs", "durationNs", "root"}
MAX_RUNTIME_EVENTS = 64
MAX_PROCESS_IDS = 32
MAX_DYNAMIC_INTEGER = (1 << 63) - 1

MAX_JSON_BYTES = 64 * 1024
MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 512
MAX_TEXT_CHARS = 4096
MAX_PROCESS_STREAM_BYTES = 64 * 1024
MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
PROCESS_READ_CHUNK_BYTES = 8192
PROCESS_POLL_SECONDS = 0.01
PROCESS_STOP_TIMEOUT_SECONDS = 5
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
NEGATIVE_CASES = (
    ("crossover", "wine-bytes-changed", "runtime", "runtime-architecture-invalid"),
    ("whisky", "wineserver-bytes-changed", "runtime", "runtime-architecture-invalid"),
    ("crossover", "console-guest-bytes-changed", "core", "core-inspection-refused"),
    ("whisky", "cached-installer-bytes-changed", "environment", "cached-asset-digest-mismatch"),
)
MAX_NEGATIVE_FILE_BYTES = 128 * 1024 * 1024
MAX_NEGATIVE_SENTINEL_BYTES = 1024 * 1024
NEGATIVE_READ_CHUNK_BYTES = 64 * 1024
NEGATIVE_READ_SECONDS = 30


class AcceptanceError(Exception):
    """Report a closed developer-local acceptance failure."""


class IntegrityError(AcceptanceError):
    """Report that a preflight-bound input changed during orchestration."""


class CleanupError(AcceptanceError):
    """Report that a managed child or process group could not be reaped."""


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
class NodeIdentity:
    device: int
    inode: int
    kind: int


@dataclass(frozen=True)
class PathBinding:
    path: Path
    components: tuple[tuple[Path, NodeIdentity], ...]
    absent_components: tuple[Path, ...]
    target_existed: bool
    target_size: int | None
    target_mtime_ns: int | None


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
    bindings: dict[str, PathBinding]


@dataclass(frozen=True)
class SourceBinding:
    path: Path
    identity: NodeIdentity
    size: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True)
class OwnedDirectoryIdentity:
    label: str
    path: Path
    identity: NodeIdentity


@dataclass(frozen=True)
class OwnedNode:
    path: Path
    identity: NodeIdentity
    directory_chain: tuple[OwnedDirectoryIdentity, ...]


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
    value.add_argument("--negative-checks", action=UniqueFlagAction)
    value.add_argument("--console-guest", action=UniqueValueAction)
    value.add_argument("--negative-sentinel", action=UniqueValueAction)
    return value


def parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    require_python(sys.version_info[:3])
    parsed = parser().parse_args(list(arguments))
    parsed.allow_network = parsed.allow_network is True
    parsed.negative_checks = parsed.negative_checks is True
    negative_inputs = (parsed.console_guest, parsed.negative_sentinel)
    if parsed.negative_checks:
        if not all(isinstance(value, str) and value for value in negative_inputs):
            raise AcceptanceError("negative checks require explicit guest and sentinel inputs")
        if parsed.allow_network:
            raise AcceptanceError("negative checks are always offline")
    elif any(value is not None for value in negative_inputs):
        raise AcceptanceError("negative inputs require --negative-checks")
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


def _node_identity(metadata: os.stat_result) -> NodeIdentity:
    return NodeIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        kind=stat.S_IFMT(metadata.st_mode),
    )


def _capture_binding(path: Path, field: str) -> PathBinding:
    _reject_unsafe_components(path, field)
    components: list[tuple[Path, NodeIdentity]] = []
    absent_components: list[Path] = []
    target_metadata: os.stat_result | None = None
    for component in reversed((path, *path.parents)):
        try:
            metadata = component.lstat()
        except FileNotFoundError:
            absent_components.append(component)
            continue
        except OSError as error:
            raise AcceptanceError(f"{field} identity could not be captured") from error
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            raise AcceptanceError(f"{field} has an unsafe path component")
        components.append((component, _node_identity(metadata)))
        if component == path:
            target_metadata = metadata
    is_regular = target_metadata is not None and stat.S_ISREG(target_metadata.st_mode)
    return PathBinding(
        path=path,
        components=tuple(components),
        absent_components=tuple(absent_components),
        target_existed=target_metadata is not None,
        target_size=target_metadata.st_size if is_regular else None,
        target_mtime_ns=target_metadata.st_mtime_ns if is_regular else None,
    )


def _revalidate_binding(binding: PathBinding, field: str) -> None:
    for component, expected in binding.components:
        try:
            metadata = component.lstat()
        except OSError as error:
            raise IntegrityError(f"{field} identity changed") from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or _node_identity(metadata) != expected
        ):
            raise IntegrityError(f"{field} identity changed")
    for component in binding.absent_components:
        try:
            component.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise IntegrityError(f"{field} identity changed") from error
        raise IntegrityError(f"{field} identity changed")
    try:
        target_metadata = binding.path.lstat()
    except FileNotFoundError:
        target_metadata = None
    except OSError as error:
        raise IntegrityError(f"{field} identity changed") from error
    if (target_metadata is not None) != binding.target_existed:
        raise IntegrityError(f"{field} identity changed")
    if target_metadata is not None and binding.target_size is not None:
        if (
            target_metadata.st_size != binding.target_size
            or target_metadata.st_mtime_ns != binding.target_mtime_ns
        ):
            raise IntegrityError(f"{field} identity changed")


def _revalidate_bindings(paths: AcceptancePaths) -> None:
    for field, binding in paths.bindings.items():
        _revalidate_binding(binding, field)


def _refresh_root_bindings(paths: AcceptancePaths) -> None:
    for field, path in (
        ("cache-root", paths.cache_root),
        ("runtime-store-root", paths.runtime_store_root),
        ("storage-root", paths.storage_root),
        ("work-root", paths.work_root),
    ):
        paths.bindings[field] = _capture_binding(path, field)


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
            try:
                current.encode("utf-8")
            except UnicodeError as error:
                raise AcceptanceError(f"{label} contains invalid text") from error
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


def _reject_json_constant(_constant: str) -> object:
    raise ValueError("non-standard JSON constant")


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
        value = json.loads(
            text,
            object_pairs_hook=_closed_object,
            parse_constant=_reject_json_constant,
        )
    except AcceptanceError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
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
            or any(checked is not True for checked in checks.values())
        ):
            raise AcceptanceError("interaction evidence checks must all be true")


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

    bindings = {
        field: _capture_binding(path, field) for field, path in resolved.items()
    }
    for round_id in ROUNDS:
        for runtime_id in RUNTIME_IDS:
            field = f"interaction-evidence:{round_id}:{runtime_id}"
            path = resolved["interaction-evidence-root"] / round_id / f"{runtime_id}.json"
            bindings[field] = _capture_binding(path, field)
    _validate_interaction_root(resolved["interaction-evidence-root"])
    for field, binding in bindings.items():
        _revalidate_binding(binding, field)

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
        bindings=bindings,
    )


def _portable_entrypoint(value: object, field: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise AcceptanceError(f"Runtime {field} is invalid")
    raw_parts = value.split("/")
    if any(part in ("", ".", "..") for part in raw_parts):
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


def _runtime_version(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+() -]*", value) is None
    ):
        raise AcceptanceError("Runtime version is invalid")
    return value


def parse_discovery(text: object, arguments: argparse.Namespace) -> list[dict[str, object]]:
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
    validated: list[dict[str, object]] = []
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
        version = _runtime_version(descriptor["version"])
        root = _canonical(_absolute(descriptor["materializedRoot"], "Runtime root"), "Runtime root")
        if not root.is_dir() or any(_overlaps(root, protected_path) for protected_path in protected):
            raise AcceptanceError("Runtime root is invalid or overlaps protected input")
        if any(_overlaps(root, other) for other in runtime_roots):
            raise AcceptanceError("Runtime roots overlap")
        runtime_roots.append(root)
        root_binding = _capture_binding(root, "Runtime root")
        wine = _portable_entrypoint(descriptor["wine"], "wine")
        wineserver = _portable_entrypoint(descriptor["wineserver"], "wineserver")
        if wine == wineserver:
            raise AcceptanceError("Runtime entrypoints must be distinct")
        resolved_entrypoints: list[Path] = []
        entrypoint_bindings: list[PathBinding] = []
        for entrypoint, field in ((wine, "wine"), (wineserver, "wineserver")):
            executable = root.joinpath(*entrypoint.parts)
            _reject_unsafe_components(executable, f"Runtime {field}")
            try:
                resolved_executable = executable.resolve(strict=True)
            except OSError as error:
                raise AcceptanceError(f"Runtime {field} is invalid") from error
            if root not in resolved_executable.parents:
                raise AcceptanceError(f"Runtime {field} escapes its root")
            entrypoint_bindings.append(
                _capture_binding(resolved_executable, f"Runtime {field}")
            )
            _regular_executable(resolved_executable, f"Runtime {field}")
            resolved_entrypoints.append(resolved_executable)
        try:
            if resolved_entrypoints[0].samefile(resolved_entrypoints[1]):
                raise AcceptanceError("Runtime entrypoints must be distinct")
        except OSError as error:
            raise AcceptanceError("Runtime entrypoint identity is invalid") from error
        _revalidate_binding(root_binding, "Runtime root")
        _revalidate_binding(entrypoint_bindings[0], "Runtime wine")
        _revalidate_binding(entrypoint_bindings[1], "Runtime wineserver")
        validated.append(
            {
                "runtimeId": runtime_id,
                "source": source,
                "materializedRoot": str(root),
                "wine": wine.as_posix(),
                "wineserver": wineserver.as_posix(),
                "version": version,
                "_bindings": {
                    "Runtime root": root_binding,
                    "Runtime wine": entrypoint_bindings[0],
                    "Runtime wineserver": entrypoint_bindings[1],
                },
            }
        )
    return validated


def _revalidate_runtime(descriptor: dict[str, object]) -> None:
    bindings = descriptor.get("_bindings")
    if not isinstance(bindings, dict):
        raise AcceptanceError("Runtime identity binding is missing")
    for field, binding in bindings.items():
        if not isinstance(field, str) or not isinstance(binding, PathBinding):
            raise AcceptanceError("Runtime identity binding is invalid")
        _revalidate_binding(binding, field)


def _descriptor_text(descriptor: dict[str, object], field: str) -> str:
    value = descriptor.get(field)
    if not isinstance(value, str) or not value:
        raise AcceptanceError("Runtime identity binding is invalid")
    return value


def _process_poll(process: object) -> int | None:
    poll = getattr(process, "poll", None)
    if not callable(poll):
        return None
    try:
        value = poll()
    except Exception:
        return None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _process_group_options(host_system: str | None = None) -> dict[str, object]:
    system = platform.system() if host_system is None else host_system
    if system == "Windows":
        creation_flag = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", None)
        if isinstance(creation_flag, int):
            return {"creationflags": creation_flag}
        return {}
    return {"start_new_session": True}


def _posix_process_group(process: object, options: dict[str, object]) -> int | None:
    if os.name != "posix" or options.get("start_new_session") is not True:
        return None
    if not isinstance(process, subprocess.Popen):
        return None
    process_id = getattr(process, "pid", None)
    if (
        not isinstance(process_id, int)
        or isinstance(process_id, bool)
        or process_id <= 1
        or process_id == os.getpgrp()
    ):
        raise CleanupError("managed process group is invalid")
    return process_id


def _process_group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except (OSError, ValueError):
        return True
    return True


def _signal_process_group(process_group: int, requested_signal: int) -> bool:
    if process_group <= 1 or process_group == os.getpgrp():
        return False
    try:
        os.killpg(process_group, requested_signal)
    except ProcessLookupError:
        return True
    except (OSError, ValueError):
        return False
    return True


def _stop_posix_process_group(process: object, process_group: int) -> bool:
    wait = getattr(process, "wait", None)
    if not callable(wait):
        raise CleanupError("managed process group cleanup failed")
    cleanup_failed = False
    if not _signal_process_group(process_group, signal.SIGTERM):
        cleanup_failed = True
    try:
        wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        cleanup_failed = True
    if _process_group_exists(process_group):
        if not _signal_process_group(process_group, signal.SIGKILL):
            cleanup_failed = True
        try:
            wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
        except Exception:
            cleanup_failed = True
    deadline = time.monotonic() + PROCESS_STOP_TIMEOUT_SECONDS
    while _process_group_exists(process_group) and time.monotonic() < deadline:
        time.sleep(PROCESS_POLL_SECONDS)
    if _process_poll(process) is None or _process_group_exists(process_group):
        cleanup_failed = True
    if cleanup_failed:
        raise CleanupError("managed process group cleanup failed")
    return True


def _stop_process(process: object, *, process_group: int | None = None) -> bool:
    if process_group is not None:
        return _stop_posix_process_group(process, process_group)
    terminate = getattr(process, "terminate", None)
    kill = getattr(process, "kill", None)
    wait = getattr(process, "wait", None)
    if not callable(wait):
        raise CleanupError("child process cleanup failed")
    if _process_poll(process) is not None:
        return True
    cleanup_failed = False
    if callable(terminate):
        try:
            terminate()
        except Exception:
            cleanup_failed = True
    else:
        cleanup_failed = True
    try:
        wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        if callable(kill):
            try:
                kill()
            except Exception:
                cleanup_failed = True
        else:
            cleanup_failed = True
        try:
            wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
        except Exception:
            cleanup_failed = True
    except Exception:
        cleanup_failed = True
    if _process_poll(process) is None:
        if callable(kill):
            try:
                kill()
                wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
            except Exception:
                cleanup_failed = True
        else:
            cleanup_failed = True
    if _process_poll(process) is None:
        cleanup_failed = True
    if cleanup_failed:
        raise CleanupError("child process cleanup failed")
    return True


def _reap_residual_process_group(process: object, process_group: int | None) -> bool:
    if process_group is None or not _process_group_exists(process_group):
        return True
    if not _stop_process(process, process_group=process_group):
        raise CleanupError("managed process group cleanup failed")
    return True


def _close_process_streams(process: object) -> None:
    for name in ("stdout", "stderr"):
        stream = getattr(process, name, None)
        close = getattr(stream, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass


def _bounded_run(arguments: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    if timeout <= 0:
        raise AcceptanceError("child process timeout is invalid")
    group_options = _process_group_options()
    try:
        process = subprocess.Popen(
            list(arguments),
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(CHILD_ENV),
            shell=False,
            **group_options,
        )
    except OSError as error:
        raise AcceptanceError("child process could not be started") from error
    try:
        process_group = _posix_process_group(process, group_options)
    except CleanupError:
        try:
            _stop_process(process)
        finally:
            _close_process_streams(process)
        raise
    if process.stdout is None or process.stderr is None:
        try:
            if not _stop_process(process, process_group=process_group):
                raise CleanupError("child process cleanup failed")
        finally:
            _close_process_streams(process)
        raise AcceptanceError("child process capture is unavailable")

    try:
        stream_descriptors: dict[str, int] = {}
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            fileno = getattr(stream, "fileno", None)
            if not callable(fileno):
                raise AcceptanceError("child process capture is unavailable")
            descriptor = fileno()
            if not isinstance(descriptor, int) or isinstance(descriptor, bool) or descriptor < 0:
                raise AcceptanceError("child process capture is unavailable")
            os.set_blocking(descriptor, False)
            stream_descriptors[name] = descriptor
    except (AcceptanceError, OSError, ValueError):
        try:
            _stop_process(process, process_group=process_group)
        finally:
            _close_process_streams(process)
        raise AcceptanceError("child process capture is unavailable")

    captured = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    overflow = False
    reader_failed = False

    def drain_available() -> bool:
        nonlocal total, overflow, reader_failed
        progressed = False
        for name, descriptor in tuple(stream_descriptors.items()):
            while name in stream_descriptors:
                try:
                    chunk = os.read(descriptor, PROCESS_READ_CHUNK_BYTES)
                except BlockingIOError:
                    break
                except OSError:
                    reader_failed = True
                    del stream_descriptors[name]
                    break
                if not chunk:
                    del stream_descriptors[name]
                    break
                progressed = True
                stream_remaining = MAX_PROCESS_STREAM_BYTES - len(captured[name])
                total_remaining = MAX_PROCESS_OUTPUT_BYTES - total
                accepted = min(len(chunk), max(0, stream_remaining), max(0, total_remaining))
                if accepted:
                    captured[name].extend(chunk[:accepted])
                    total += accepted
                if accepted != len(chunk):
                    overflow = True
                    return progressed
        return progressed

    try:
        deadline = time.monotonic() + timeout
        timed_out = False
        residual_checked = False
        while True:
            progressed = drain_available()
            if overflow or reader_failed:
                break
            returncode = _process_poll(process)
            if returncode is not None and not residual_checked:
                _reap_residual_process_group(process, process_group)
                residual_checked = True
                progressed = drain_available() or progressed
            if returncode is not None and not stream_descriptors:
                break
            if time.monotonic() >= deadline:
                timed_out = True
                break
            if not progressed:
                time.sleep(PROCESS_POLL_SECONDS)
        if timed_out or overflow or reader_failed:
            if not _stop_process(process, process_group=process_group):
                raise CleanupError("child process cleanup failed")
        if overflow:
            raise AcceptanceError("child process exceeded output limit")
        if timed_out:
            raise AcceptanceError("child process timed out")
        if reader_failed:
            raise AcceptanceError("child process capture failed")
        returncode = _process_poll(process)
        if returncode is None:
            if not _stop_process(process, process_group=process_group):
                raise CleanupError("child process cleanup failed")
            raise AcceptanceError("child process did not report an exit status")
        if not residual_checked and not _reap_residual_process_group(process, process_group):
            raise CleanupError("child process cleanup failed")
        try:
            stdout = bytes(captured["stdout"]).decode("utf-8")
            stderr = bytes(captured["stderr"]).decode("utf-8")
        except UnicodeError as error:
            raise AcceptanceError("child process output is invalid") from error
        return subprocess.CompletedProcess(list(arguments), returncode, stdout, stderr)
    finally:
        _close_process_streams(process)


def _invoke(
    arguments: Sequence[str],
    runner: Runner | None,
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    if runner is None:
        return _bounded_run(arguments, timeout=timeout)
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


def discover_runtimes(
    arguments: argparse.Namespace, runner: Runner | None
) -> list[dict[str, object]]:
    result = _invoke(
        [sys.executable, "-S", "-B", str(DISCOVERY_TOOL), "--all"],
        runner,
        timeout=DISCOVERY_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise AcceptanceError("Runtime discovery failed")
    return parse_discovery(result.stdout, arguments)


def _load_tool_module(name: str, path: Path) -> object:
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AcceptanceError("negative validation boundary is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        sys.modules.pop(name, None)
        raise AcceptanceError("negative validation boundary is unavailable") from error
    return module


def _read_bound_source(
    path: Path,
    label: str,
    *,
    max_bytes: int = MAX_NEGATIVE_FILE_BYTES,
) -> tuple[SourceBinding, bytes]:
    _reject_unsafe_components(path, label)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor: int | None = None
    try:
        entry = path.lstat()
        if (
            not stat.S_ISREG(entry.st_mode)
            or stat.S_ISLNK(entry.st_mode)
            or _is_reparse(entry)
            or entry.st_nlink != 1
            or entry.st_size <= 0
            or entry.st_size > max_bytes
        ):
            raise AcceptanceError(f"{label} must be a private bounded regular file")
        deadline = time.monotonic() + NEGATIVE_READ_SECONDS
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _node_identity(entry) != _node_identity(opened)
            or opened.st_size != entry.st_size
            or opened.st_mtime_ns != entry.st_mtime_ns
        ):
            raise AcceptanceError(f"{label} must be a private bounded regular file")
        if time.monotonic() >= deadline:
            raise AcceptanceError(f"{label} read exceeded its time bound")
        chunks: list[bytes] = []
        total = 0
        while total < opened.st_size:
            if time.monotonic() >= deadline:
                raise AcceptanceError(f"{label} read exceeded its time bound")
            chunk = os.read(
                descriptor,
                min(NEGATIVE_READ_CHUNK_BYTES, opened.st_size - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        current = os.fstat(descriptor)
        current_entry = path.lstat()
        if (
            total != opened.st_size
            or current.st_size != opened.st_size
            or current.st_mtime_ns != opened.st_mtime_ns
            or current_entry.st_size != opened.st_size
            or current_entry.st_mtime_ns != opened.st_mtime_ns
            or _node_identity(current) != _node_identity(opened)
            or _node_identity(current_entry) != _node_identity(opened)
            or current.st_nlink != 1
            or current_entry.st_nlink != 1
        ):
            raise IntegrityError(f"{label} identity changed")
        payload = b"".join(chunks)
        return (
            SourceBinding(
                path=path,
                identity=_node_identity(opened),
                size=opened.st_size,
                mtime_ns=opened.st_mtime_ns,
                sha256=hashlib.sha256(payload).hexdigest(),
            ),
            payload,
        )
    except (AcceptanceError, IntegrityError):
        raise
    except OSError as error:
        raise AcceptanceError(f"{label} could not be read safely") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _revalidate_source(binding: SourceBinding, label: str) -> bytes:
    current, payload = _read_bound_source(
        binding.path,
        label,
        max_bytes=max(binding.size, MAX_NEGATIVE_SENTINEL_BYTES),
    )
    if current != binding:
        raise IntegrityError(f"{label} identity or digest changed")
    return payload


def _owned_directory(
    path: Path,
    label: str,
    *,
    create: bool,
    parent: OwnedNode | None = None,
) -> OwnedNode:
    if parent is not None:
        if path.parent != parent.path:
            raise AcceptanceError(f"{label} parent is invalid")
        _verify_owned_directory(parent, IntegrityError)
    try:
        if create:
            os.mkdir(path, 0o700)
        metadata = path.lstat()
    except OSError as error:
        raise AcceptanceError(f"{label} could not be created safely") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
        raise AcceptanceError(f"{label} is unsafe")
    identity = _node_identity(metadata)
    chain = (
        parent.directory_chain if parent is not None else ()
    ) + (OwnedDirectoryIdentity(label, path, identity),)
    owned = OwnedNode(path, identity, chain)
    if parent is not None:
        _verify_owned_directory(parent, IntegrityError)
    _verify_owned_directory(owned, IntegrityError)
    return owned


def _verify_owned_chain(
    owned: OwnedNode,
    error_type: type[AcceptanceError],
) -> None:
    previous: Path | None = None
    for component in owned.directory_chain:
        if previous is not None and component.path.parent != previous:
            raise error_type("owned directory chain is invalid")
        try:
            metadata = component.path.lstat()
        except OSError as error:
            raise error_type(f"{component.label} identity changed") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or _node_identity(metadata) != component.identity
        ):
            raise error_type(f"{component.label} identity changed")
        previous = component.path


def _verify_owned_directory(
    owned: OwnedNode,
    error_type: type[AcceptanceError] = CleanupError,
) -> None:
    _verify_owned_chain(owned, error_type)
    if (
        not owned.directory_chain
        or owned.directory_chain[-1].path != owned.path
        or owned.directory_chain[-1].identity != owned.identity
    ):
        raise error_type("owned directory binding is invalid")


def _verify_owned_file(
    owned: OwnedNode,
    error_type: type[AcceptanceError] = CleanupError,
) -> os.stat_result:
    _verify_owned_chain(owned, error_type)
    try:
        metadata = owned.path.lstat()
    except OSError as error:
        raise error_type("negative copy identity changed") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or metadata.st_nlink != 1
        or _node_identity(metadata) != owned.identity
    ):
        raise error_type("negative copy identity changed")
    return metadata


def _create_private_copy(
    case_root: OwnedNode,
    payload: bytes,
    *,
    filename: str = "payload.bin",
) -> OwnedNode:
    _verify_owned_directory(case_root, IntegrityError)
    if Path(filename).name != filename or not filename:
        raise AcceptanceError("negative copy filename is invalid")
    target = case_root.path / filename
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    descriptor: int | None = None
    trusted_identity: NodeIdentity | None = None
    owned: OwnedNode | None = None
    failure: BaseException | None = None
    try:
        descriptor = os.open(target, flags, 0o600)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise OSError("negative copy is not private")
        trusted_identity = _node_identity(opened)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        entry = target.lstat()
        current = os.fstat(descriptor)
        if (
            trusted_identity != _node_identity(entry)
            or trusted_identity != _node_identity(current)
            or entry.st_nlink != 1
            or current.st_nlink != 1
            or entry.st_size != len(payload)
            or current.st_size != len(payload)
        ):
            raise IntegrityError("negative copy identity changed")
        owned = OwnedNode(target, trusted_identity, case_root.directory_chain)
        _verify_owned_file(owned, IntegrityError)
    except IntegrityError as error:
        failure = error
    except OSError as error:
        failure = AcceptanceError("negative copy could not be created safely")
        failure.__cause__ = error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if failure is not None:
        if trusted_identity is not None:
            _cleanup_partial_private_copy(case_root, target, trusted_identity)
        raise failure
    if owned is None:
        raise AcceptanceError("negative copy could not be created safely")
    return owned


def _mutate_owned_copy(owned: OwnedNode) -> None:
    _verify_owned_file(owned, IntegrityError)
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(owned.path, flags)
        opened = os.fstat(descriptor)
        entry = owned.path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or entry.st_nlink != 1
            or _node_identity(opened) != owned.identity
            or _node_identity(entry) != owned.identity
            or opened.st_size <= 0
        ):
            raise IntegrityError("negative copy identity changed")
        _verify_owned_file(owned, IntegrityError)
        original = os.read(descriptor, 1)
        if len(original) != 1:
            raise OSError("negative copy is empty")
        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.write(descriptor, bytes((original[0] ^ 0xFF,))) != 1:
            raise OSError("negative mutation did not advance")
        os.fsync(descriptor)
        current = os.fstat(descriptor)
        current_entry = owned.path.lstat()
        if (
            _node_identity(current) != owned.identity
            or _node_identity(current_entry) != owned.identity
            or current.st_nlink != 1
            or current_entry.st_nlink != 1
            or current.st_size != opened.st_size
        ):
            raise IntegrityError("negative copy identity changed")
        _verify_owned_file(owned, IntegrityError)
    except IntegrityError:
        raise
    except OSError as error:
        raise AcceptanceError("negative copy mutation failed") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _verify_cleaned_case_parent(case_root: OwnedNode) -> None:
    parent_chain = OwnedNode(
        case_root.path.parent,
        case_root.directory_chain[-2].identity,
        case_root.directory_chain[:-1],
    )
    _verify_owned_directory(parent_chain)


def _cleanup_partial_private_copy(
    case_root: OwnedNode,
    target: Path,
    trusted_identity: NodeIdentity,
) -> None:
    """Remove only a partially written file whose opened identity we own."""

    try:
        _verify_owned_directory(case_root)
        entries = _bounded_entries(case_root.path, 1, "negative case root")
        if not entries:
            return
        if entries != [target]:
            raise CleanupError("negative case contents changed")
        metadata = target.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or metadata.st_nlink != 1
            or _node_identity(metadata) != trusted_identity
        ):
            raise CleanupError("negative copy identity changed")
        target.unlink()
        _verify_owned_directory(case_root)
        if _bounded_entries(case_root.path, 1, "negative case root"):
            raise CleanupError("negative case cleanup is incomplete")
    except CleanupError:
        raise
    except AcceptanceError as error:
        raise CleanupError("negative case contents changed") from error
    except OSError as error:
        raise CleanupError("negative case cleanup failed") from error


def _cleanup_empty_owned_case(case_root: OwnedNode) -> None:
    """Remove an owned case directory only when it is still bound and empty."""

    try:
        _verify_owned_directory(case_root)
        if _bounded_entries(case_root.path, 1, "negative case root"):
            raise CleanupError("negative case contents changed")
        case_root.path.rmdir()
        _verify_cleaned_case_parent(case_root)
    except CleanupError:
        raise
    except AcceptanceError as error:
        raise CleanupError("negative case contents changed") from error
    except OSError as error:
        raise CleanupError("negative case cleanup failed") from error


def _cleanup_owned_case(case_root: OwnedNode, owned_file: OwnedNode) -> None:
    _verify_owned_directory(case_root)
    try:
        entries = _bounded_entries(case_root.path, 1, "negative case root")
        if entries != [owned_file.path]:
            raise CleanupError("negative case contents changed")
        _verify_owned_file(owned_file)
        owned_file.path.unlink()
        _verify_owned_directory(case_root)
        if _bounded_entries(case_root.path, 1, "negative case root"):
            raise CleanupError("negative case cleanup is incomplete")
        case_root.path.rmdir()
        _verify_cleaned_case_parent(case_root)
    except CleanupError:
        raise
    except AcceptanceError as error:
        raise CleanupError("negative case contents changed") from error
    except OSError as error:
        raise CleanupError("negative case cleanup failed") from error


def _prepare_negative_layout(paths: AcceptancePaths) -> dict[str, OwnedNode]:
    _revalidate_bindings(paths)
    _empty_or_absent_directory(paths.work_root, "work-root")
    work_binding = paths.bindings.get("work-root")
    if work_binding is None or not work_binding.target_existed:
        raise AcceptanceError("negative checks require a bound empty work-root")
    work_metadata = paths.work_root.lstat()
    work_identity = _node_identity(work_metadata)
    if dict(work_binding.components).get(paths.work_root) != work_identity:
        raise IntegrityError("work-root identity changed")
    work_root = OwnedNode(
        paths.work_root,
        work_identity,
        (OwnedDirectoryIdentity("work-root", paths.work_root, work_identity),),
    )
    _verify_owned_directory(work_root, IntegrityError)
    negative = _owned_directory(
        paths.work_root / "negative",
        "negative root",
        create=True,
        parent=work_root,
    )
    runtime_roots: dict[str, OwnedNode] = {}
    for runtime_id in RUNTIME_IDS:
        runtime_roots[runtime_id] = _owned_directory(
            negative.path / runtime_id,
            "negative Runtime root",
            create=True,
            parent=negative,
        )
    entries = _bounded_entries(negative.path, len(RUNTIME_IDS), "negative root")
    if {entry.name for entry in entries} != set(RUNTIME_IDS):
        raise IntegrityError("negative layout changed")
    return runtime_roots


def _default_runtime_validator(path: Path) -> object:
    module = _load_tool_module("_compatforge_negative_discovery", DISCOVERY_TOOL)
    validator = getattr(module, "macho_architectures", None)
    if not callable(validator):
        raise AcceptanceError("negative Runtime boundary is unavailable")
    return validator(path)


def _default_asset_boundary() -> tuple[object, Callable[..., Path], type[Exception]]:
    module = _load_tool_module("_compatforge_negative_gui_assets", GUI_ASSET_TOOL)
    asset_for = getattr(module, "asset_for", None)
    fetch = getattr(module, "fetch", None)
    asset_error = getattr(module, "AssetError", None)
    if (
        not callable(asset_for)
        or not callable(fetch)
        or not isinstance(asset_error, type)
        or not issubclass(asset_error, Exception)
    ):
        raise AcceptanceError("negative asset boundary is unavailable")
    return asset_for("7zip"), fetch, asset_error


def _runtime_negative_boundary(path: Path, validator: Callable[[Path], object]) -> str | None:
    try:
        architectures = validator(path)
    except Exception:
        return "negative-boundary-error-invalid"
    if not isinstance(architectures, set) or any(not isinstance(value, str) for value in architectures):
        return "negative-boundary-error-invalid"
    if not architectures:
        return None
    if architectures == {"x86_64"}:
        return "negative-boundary-unexpectedly-accepted"
    return "negative-boundary-error-invalid"


def _guest_negative_boundary(
    path: Path,
    cli: Path,
    runner: Runner | None,
) -> str | None:
    try:
        result = _invoke(
            [str(cli), "inspect", str(path)],
            runner,
            timeout=DISCOVERY_TIMEOUT_SECONDS,
        )
    except (AcceptanceError, CleanupError):
        return "negative-boundary-error-invalid"
    if not isinstance(result.returncode, int) or isinstance(result.returncode, bool):
        return "negative-boundary-error-invalid"
    if result.returncode == 0:
        return "negative-boundary-unexpectedly-accepted"
    if (
        result.returncode != 1
        or result.stdout != ""
        or result.stderr != "compatforge-cli: invalid DOS header\n"
    ):
        return "negative-boundary-error-invalid"
    return None


def _asset_negative_boundary(
    case_root: Path,
    asset: object,
    fetcher: Callable[..., Path],
    asset_error: type[Exception],
) -> str | None:
    try:
        fetcher(asset, case_root, False)
    except Exception as error:
        if type(error) is asset_error and str(error) == "cached 7zip digest mismatch":
            return None
        return "negative-boundary-error-invalid"
    return "negative-boundary-unexpectedly-accepted"


def run_negative_checks(
    paths: AcceptancePaths,
    runtimes: list[dict[str, object]],
    *,
    console_guest: Path,
    sentinel: Path,
    runtime_validator: Callable[[Path], object] | None = None,
    guest_runner: Runner | None = None,
    asset: object | None = None,
    asset_fetcher: Callable[..., Path] | None = None,
    asset_error: type[Exception] | None = None,
) -> dict[str, object]:
    """Run four copy-bound negative checks without executing a mutant payload."""

    if len(runtimes) != len(RUNTIME_IDS) or [
        descriptor.get("runtimeId") for descriptor in runtimes
    ] != list(RUNTIME_IDS):
        raise AcceptanceError("negative Runtime descriptors are incomplete")
    _revalidate_bindings(paths)
    for descriptor in runtimes:
        _revalidate_runtime(descriptor)
    if runtime_validator is None:
        runtime_validator = _default_runtime_validator

    if asset is None or asset_fetcher is None or asset_error is None:
        if any(value is not None for value in (asset, asset_fetcher, asset_error)):
            raise AcceptanceError("negative asset boundary is incomplete")
        asset, asset_fetcher, asset_error = _default_asset_boundary()
    filename = getattr(asset, "filename", None)
    expected_asset_digest = getattr(asset, "sha256", None)
    if (
        not isinstance(filename, str)
        or not filename
        or Path(filename).name != filename
        or not isinstance(expected_asset_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_asset_digest) is None
        or not isinstance(asset_error, type)
        or not issubclass(asset_error, Exception)
    ):
        raise AcceptanceError("negative asset contract is invalid")

    guest_path = _canonical(_absolute(str(console_guest), "console guest"), "console guest")
    sentinel_path = _canonical(_absolute(str(sentinel), "negative sentinel"), "negative sentinel")
    installer_path = paths.cache_root / filename
    protected = (
        ROOT.resolve(strict=True),
        paths.work_root,
        paths.runtime_store_root,
        paths.storage_root,
        paths.interaction_evidence_root,
        paths.compatforge_cli,
        paths.desktop_app,
        paths.cc,
    )
    if any(_overlaps(guest_path, value) for value in protected):
        raise AcceptanceError("console guest overlaps a protected path")
    if any(_overlaps(sentinel_path, value) for value in (*protected, paths.cache_root, guest_path)):
        raise AcceptanceError("negative sentinel overlaps a protected path")

    descriptor_by_id = {str(value["runtimeId"]): value for value in runtimes}
    source_paths: dict[str, Path] = {}
    for runtime_id, descriptor in descriptor_by_id.items():
        root = Path(_descriptor_text(descriptor, "materializedRoot"))
        for field in ("wine", "wineserver"):
            relative = PurePosixPath(_descriptor_text(descriptor, field))
            source_paths[f"{runtime_id}:{field}"] = root.joinpath(*relative.parts)
    source_paths["console-guest"] = guest_path
    source_paths["cached-installer"] = installer_path
    source_paths["sentinel"] = sentinel_path
    if len(set(source_paths.values())) != len(source_paths):
        raise AcceptanceError("negative sources must be distinct")

    bindings: dict[str, SourceBinding] = {}
    guest_header = b""
    for key, path in source_paths.items():
        maximum = MAX_NEGATIVE_SENTINEL_BYTES if key == "sentinel" else MAX_NEGATIVE_FILE_BYTES
        binding, payload = _read_bound_source(
            path,
            f"negative source {key}",
            max_bytes=maximum,
        )
        bindings[key] = binding
        if key == "console-guest":
            guest_header = payload[:2]
    if guest_header != b"MZ":
        raise AcceptanceError("console guest is not a PE input")
    if bindings["cached-installer"].sha256 != expected_asset_digest:
        raise AcceptanceError("cached installer digest is invalid")

    runtime_roots = _prepare_negative_layout(paths)
    case_results: list[dict[str, object]] = []
    for runtime_id, case_id, expected_class, expected_reason in NEGATIVE_CASES:
        if case_id == "wine-bytes-changed":
            source_key = f"{runtime_id}:wine"
        elif case_id == "wineserver-bytes-changed":
            source_key = f"{runtime_id}:wineserver"
        elif case_id == "console-guest-bytes-changed":
            source_key = "console-guest"
        else:
            source_key = "cached-installer"
        source_payload = _revalidate_source(
            bindings[source_key], f"negative source {source_key}"
        )
        _revalidate_source(bindings["sentinel"], "negative sentinel")
        _verify_owned_directory(runtime_roots[runtime_id], IntegrityError)
        if _bounded_entries(
            runtime_roots[runtime_id].path,
            1,
            "negative Runtime root",
        ):
            raise IntegrityError("negative Runtime root contains an unexpected case")
        case_root: OwnedNode | None = None
        owned_file: OwnedNode | None = None
        failure_reason: str | None = None
        case_result: dict[str, object] | None = None
        try:
            case_root = _owned_directory(
                runtime_roots[runtime_id].path / case_id,
                "negative case root",
                create=True,
                parent=runtime_roots[runtime_id],
            )
            owned_file = _create_private_copy(
                case_root,
                source_payload,
                filename=(
                    filename
                    if case_id == "cached-installer-bytes-changed"
                    else "payload.bin"
                ),
            )
            _mutate_owned_copy(owned_file)
            _verify_owned_file(owned_file, IntegrityError)
            _revalidate_source(bindings[source_key], f"negative source {source_key}")
            _revalidate_source(bindings["sentinel"], "negative sentinel")
            _verify_owned_file(owned_file, IntegrityError)
            if case_id in ("wine-bytes-changed", "wineserver-bytes-changed"):
                failure_reason = _runtime_negative_boundary(owned_file.path, runtime_validator)
            elif case_id == "console-guest-bytes-changed":
                failure_reason = _guest_negative_boundary(
                    owned_file.path,
                    paths.compatforge_cli,
                    guest_runner,
                )
            else:
                failure_reason = _asset_negative_boundary(
                    case_root.path,
                    asset,
                    asset_fetcher,
                    asset_error,
                )
            _verify_owned_file(owned_file, IntegrityError)
            case_result = {
                "runtimeId": runtime_id,
                "caseId": case_id,
                "status": "accepted" if failure_reason is None else "failed",
                "failureClass": expected_class if failure_reason is None else "core",
                "reasonCode": expected_reason if failure_reason is None else failure_reason,
            }
        finally:
            cleanup_failure: AcceptanceError | None = None
            if case_root is not None:
                try:
                    if owned_file is None:
                        _cleanup_empty_owned_case(case_root)
                    else:
                        _cleanup_owned_case(case_root, owned_file)
                except AcceptanceError as error:
                    cleanup_failure = error
            post_cleanup_failure: AcceptanceError | None = None
            try:
                _verify_owned_directory(runtime_roots[runtime_id], CleanupError)
                if _bounded_entries(
                    runtime_roots[runtime_id].path,
                    1,
                    "negative Runtime root",
                ):
                    raise CleanupError("negative case cleanup is incomplete")
            except AcceptanceError as error:
                post_cleanup_failure = error
            try:
                _revalidate_source(bindings[source_key], f"negative source {source_key}")
            except AcceptanceError as error:
                if post_cleanup_failure is None:
                    post_cleanup_failure = error
            try:
                _revalidate_source(bindings["sentinel"], "negative sentinel")
            except AcceptanceError as error:
                if post_cleanup_failure is None:
                    post_cleanup_failure = error
            if cleanup_failure is not None:
                raise cleanup_failure
            if post_cleanup_failure is not None:
                raise post_cleanup_failure
        if case_result is None:
            raise AcceptanceError("negative case evidence is incomplete")
        case_results.append(case_result)

    _revalidate_bindings(paths)
    for descriptor in runtimes:
        _revalidate_runtime(descriptor)
    for runtime_id in RUNTIME_IDS:
        _verify_owned_directory(runtime_roots[runtime_id], CleanupError)
        if _bounded_entries(
            runtime_roots[runtime_id].path,
            1,
            "negative Runtime root",
        ):
            raise CleanupError("negative case cleanup is incomplete")
    for key, binding in bindings.items():
        _revalidate_source(binding, f"negative source {key}")
    accepted = all(value["status"] == "accepted" for value in case_results)
    summary: dict[str, object] = {
        "schemaVersion": "1",
        "status": "accepted" if accepted else "failed",
        "cases": case_results,
    }
    encoded = json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
        raise AcceptanceError("negative summary exceeds its size bound")
    return summary


def _prepare_layout(paths: AcceptancePaths) -> None:
    _revalidate_bindings(paths)
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
    _refresh_root_bindings(paths)
    for round_id in ROUNDS:
        field = f"work-output:{round_id}"
        paths.bindings[field] = _capture_binding(paths.work_root / round_id, field)


def _write_all(file_descriptor: int, payload: bytes) -> None:
    written = 0
    while written < len(payload):
        count = os.write(file_descriptor, payload[written:])
        if count <= 0:
            raise OSError("summary output write did not advance")
        written += count


def _same_private_output_identity(
    opened: os.stat_result, entry: os.stat_result
) -> bool:
    return (
        stat.S_ISREG(opened.st_mode)
        and stat.S_ISREG(entry.st_mode)
        and opened.st_nlink == 1
        and entry.st_nlink == 1
        and _node_identity(opened) == _node_identity(entry)
    )


def _verify_output_entry(
    paths: AcceptancePaths,
    relative_parts: tuple[str, ...],
    file_descriptor: int,
    opened_metadata: os.stat_result,
    parent_directory_descriptor: int | None,
) -> None:
    try:
        current_metadata = os.fstat(file_descriptor)
        if parent_directory_descriptor is not None:
            entry_metadata = os.stat(
                relative_parts[-1],
                dir_fd=parent_directory_descriptor,
                follow_symlinks=False,
            )
        else:
            entry_metadata = paths.work_root.joinpath(*relative_parts).lstat()
    except OSError as error:
        raise IntegrityError("output identity changed") from error
    if not _same_private_output_identity(
        opened_metadata, current_metadata
    ) or not _same_private_output_identity(opened_metadata, entry_metadata):
        raise IntegrityError("output identity changed")

    parent_path = paths.work_root.joinpath(*relative_parts[:-1])
    binding_key = (
        "work-root"
        if len(relative_parts) == 1
        else f"work-output:{relative_parts[0]}"
    )
    binding = paths.bindings.get(binding_key)
    if binding is None:
        raise IntegrityError("output parent identity changed")
    if parent_directory_descriptor is not None:
        expected = dict(binding.components).get(parent_path)
        if (
            expected is None
            or _node_identity(os.fstat(parent_directory_descriptor)) != expected
        ):
            raise IntegrityError("output parent identity changed")
    else:
        _revalidate_binding(binding, "output parent")
    _revalidate_bindings(paths)


def _safe_create_output(
    paths: AcceptancePaths,
    relative_parts: tuple[str, ...],
    encoded: str,
    label: str,
) -> None:
    if (
        not relative_parts
        or len(relative_parts) > 2
        or any(re.fullmatch(r"[a-z0-9][a-z0-9.-]*", part) is None for part in relative_parts)
    ):
        raise AcceptanceError("acceptance output target is invalid")
    _revalidate_bindings(paths)
    payload = (encoded + "\n").encode("utf-8")
    if len(payload) > MAX_JSON_BYTES + 1:
        raise AcceptanceError(f"{label} exceeds its size bound")
    create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    create_flags |= getattr(os, "O_CLOEXEC", 0)
    create_flags |= getattr(os, "O_NOFOLLOW", 0)
    file_descriptor: int | None = None
    directory_descriptors: list[int] = []
    try:
        if os.name == "posix":
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_flags |= getattr(os, "O_CLOEXEC", 0)
            directory_flags |= getattr(os, "O_NOFOLLOW", 0)
            directory_descriptor = os.open(paths.work_root, directory_flags)
            directory_descriptors.append(directory_descriptor)
            binding = paths.bindings.get("work-root")
            if binding is None or _node_identity(os.fstat(directory_descriptor)) != dict(
                binding.components
            ).get(paths.work_root):
                raise IntegrityError("work-root identity changed")
            for part in relative_parts[:-1]:
                child_descriptor = os.open(part, directory_flags, dir_fd=directory_descriptor)
                directory_descriptors.append(child_descriptor)
                directory_descriptor = child_descriptor
                child_binding = paths.bindings.get(f"work-output:{part}")
                if child_binding is None or _node_identity(os.fstat(directory_descriptor)) != dict(
                    child_binding.components
                ).get(paths.work_root / part):
                    raise IntegrityError("work output identity changed")
            file_descriptor = os.open(
                relative_parts[-1],
                create_flags,
                0o600,
                dir_fd=directory_descriptor,
            )
        else:
            create_flags |= getattr(os, "O_BINARY", 0)
            create_flags |= getattr(os, "O_NOINHERIT", 0)
            parent = paths.work_root.joinpath(*relative_parts[:-1])
            _reject_unsafe_components(parent, "acceptance output")
            if len(relative_parts) == 2:
                _revalidate_binding(
                    paths.bindings[f"work-output:{relative_parts[0]}"],
                    "work output",
                )
            file_descriptor = os.open(
                paths.work_root.joinpath(*relative_parts), create_flags, 0o600
            )
        opened_metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode) or opened_metadata.st_nlink != 1:
            raise OSError("acceptance output is not a private regular file")
        _write_all(file_descriptor, payload)
        os.fsync(file_descriptor)
        _verify_output_entry(
            paths,
            relative_parts,
            file_descriptor,
            opened_metadata,
            directory_descriptors[-1] if directory_descriptors else None,
        )
        if directory_descriptors:
            os.fsync(directory_descriptors[-1])
        _verify_output_entry(
            paths,
            relative_parts,
            file_descriptor,
            opened_metadata,
            directory_descriptors[-1] if directory_descriptors else None,
        )
    except IntegrityError:
        raise
    except (OSError, ValueError) as error:
        raise AcceptanceError(f"{label} is unsafe") from error
    finally:
        if file_descriptor is not None:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
        for directory_descriptor in reversed(directory_descriptors):
            try:
                os.close(directory_descriptor)
            except OSError:
                pass


def _safe_create_summary(paths: AcceptancePaths, encoded: str) -> None:
    _safe_create_output(paths, ("summary.json",), encoded, "summary output")


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
        raise AcceptanceError(f"{field} is invalid")
    return value


def _project_console(value: object, descriptor: dict[str, object]) -> dict[str, object]:
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
    runtime_id = _descriptor_text(descriptor, "runtimeId")
    version = _descriptor_text(descriptor, "version")
    expected_pack = f"wine-macos-{runtime_id}-preview"
    if (
        value["schemaVersion"] != "1"
        or value["packId"] != expected_pack
        or value["packVersion"] != version
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
        "runtimeId": runtime_id,
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
    if code is not None and (
        not isinstance(code, int)
        or isinstance(code, bool)
        or abs(code) > MAX_DYNAMIC_INTEGER
    ):
        raise AcceptanceError("GUI exit code is invalid")
    return {"present": exit_value["present"], "code": code, "success": exit_value["success"]}


def _successful_exit(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"present", "code", "success"}
        and value["present"] is True
        and value["code"] == 0
        and not isinstance(value["code"], bool)
        and value["success"] is True
    )


def _closed_exit_relation(value: dict[str, object]) -> bool:
    present = value["present"]
    code = value["code"]
    success = value["success"]
    return (
        present is False
        and code is None
        and success is False
    ) or (
        present is True
        and isinstance(code, int)
        and not isinstance(code, bool)
        and success is (code == 0)
    )


def _complete_accepted_gui(application: object) -> bool:
    if not isinstance(application, dict) or application.get("status") != "accepted":
        return False
    application_id = application.get("appId")
    if application_id not in REQUIRED_INTERACTIONS:
        return False
    asset_digest = application.get("assetSha256")
    interactions = application.get("interactionChecks")
    return (
        isinstance(asset_digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", asset_digest) is not None
        and application.get("cleanup") is True
        and isinstance(interactions, dict)
        and tuple(interactions) == REQUIRED_INTERACTIONS[application_id]
        and all(checked is True for checked in interactions.values())
        and _successful_exit(application.get("installerExit"))
        and _successful_exit(application.get("exit"))
        and application.get("windowAvailable") is True
    )


def _project_gui(
    value: object, descriptor: dict[str, object]
) -> tuple[dict[str, object], list[dict[str, object]]]:
    runtime_id = _descriptor_text(descriptor, "runtimeId")
    runtime_version = _descriptor_text(descriptor, "version")
    summary = _exact_keys(value, {"schemaVersion", "receipt", "applications"}, set(), "GUI summary")
    if summary["schemaVersion"] != "1":
        raise AcceptanceError("GUI summary schema is invalid")
    receipt = _exact_keys(
        summary["receipt"],
        {
            "schemaVersion",
            "runtimeId",
            "packId",
            "version",
            "packDigest",
            "source",
        },
        {"activated"},
        "GUI receipt",
    )
    if (
        receipt["schemaVersion"] != "1"
        or receipt["runtimeId"] != runtime_id
        or receipt["version"] != runtime_version
        or receipt["packId"] != GUI_PROVIDER_PACK_ID
        or receipt["source"] != GUI_EXPLICIT_SOURCE
        or ("activated" in receipt and receipt["activated"] is not True)
    ):
        raise AcceptanceError("GUI receipt identity is invalid")
    receipt_projection: dict[str, object] = {
        "runtimeVersion": runtime_version,
        "packDigest": _digest(receipt["packDigest"], "GUI pack digest"),
    }

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
            or application["runtimeId"] != runtime_id
            or application["appId"] != application_id
            or status_value not in STATUSES
            or not isinstance(application["cleanup"], bool)
        ):
            raise AcceptanceError("GUI application identity is invalid")
        output = {
            "schemaVersion": "1",
            "runtimeId": runtime_id,
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
        if status_value == "accepted" and not _complete_accepted_gui(output):
            raise AcceptanceError("accepted GUI application evidence is incomplete")
        projected.append(output)
    return receipt_projection, projected


def _projection_input_object(
    value: object,
    required: set[str],
    dynamic: set[str],
    label: str,
) -> dict[str, object]:
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or not set(value).issubset(required | dynamic)
    ):
        raise AcceptanceError(f"{label} keys are invalid")
    return value


def _bounded_dynamic_integer(value: object, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > MAX_DYNAMIC_INTEGER
    ):
        raise AcceptanceError(f"{label} is invalid")
    return value


def _dynamic_path(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_TEXT_CHARS
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or not (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute())
    ):
        raise AcceptanceError(f"{label} is invalid")


def _validate_runtime_events(value: object) -> None:
    if not isinstance(value, list) or len(value) > MAX_RUNTIME_EVENTS:
        raise AcceptanceError("dynamic Runtime events are invalid")
    for event in value:
        if not isinstance(event, dict) or set(event) != RUNTIME_EVENT_KEYS:
            raise AcceptanceError("dynamic Runtime event keys are invalid")
        _safe_text(event["kind"], "dynamic Runtime event kind")
        _safe_text(event["requestId"], "dynamic Runtime event request ID")
        _bounded_dynamic_integer(event["pid"], "dynamic Runtime event PID", positive=True)
        _bounded_dynamic_integer(event["timestampNs"], "dynamic Runtime event timestamp")
        _bounded_dynamic_integer(event["durationNs"], "dynamic Runtime event duration")
        _dynamic_path(event["root"], "dynamic Runtime event root")


def _validate_dynamic_fields(value: dict[str, object], allowed: set[str]) -> None:
    for key in set(value) & allowed:
        nested = value[key]
        if key == "requestId":
            _safe_text(nested, "dynamic request ID")
        elif key == "pid":
            _bounded_dynamic_integer(nested, "dynamic PID", positive=True)
        elif key == "processIds":
            if not isinstance(nested, list) or len(nested) > MAX_PROCESS_IDS:
                raise AcceptanceError("dynamic process IDs are invalid")
            process_ids = [
                _bounded_dynamic_integer(process_id, "dynamic process ID", positive=True)
                for process_id in nested
            ]
            if len(process_ids) != len(set(process_ids)):
                raise AcceptanceError("dynamic process IDs are invalid")
        elif key == "startedAt":
            _safe_text(nested, "dynamic timestamp")
        elif key == "durationMs":
            _bounded_dynamic_integer(nested, "dynamic duration")
        elif key in {"workRoot", "runtimeRoot", "screenshotPath"}:
            _dynamic_path(nested, f"dynamic {key}")
        elif key == "runtimeEvents":
            _validate_runtime_events(nested)
        else:
            raise AcceptanceError("dynamic evidence key is invalid")


def _failure_projection(
    application: dict[str, object], runtime_id: str, application_id: str
) -> dict[str, object]:
    status_value = application.get("status")
    failure_class = application.get("failureClass")
    reason_code = application.get("reasonCode")
    if (
        not isinstance(reason_code, str)
        or failure_class not in FAILURE_CLASSES
        or application.get("schemaVersion") != "1"
        or application["runtimeId"] != runtime_id
        or application["appId"] != application_id
        or APPLICATION_FAILURE_RELATIONS.get(reason_code) != (status_value, failure_class)
    ):
        raise AcceptanceError("projected application failure is invalid")
    return {
        "appId": application_id,
        "assetSha256": None,
        "status": status_value,
        "failureClass": failure_class,
        "reasonCode": reason_code,
        "interactionChecks": {},
        "installerExitPresent": None,
        "installerExitCode": None,
        "exitPresent": None,
        "exitCode": None,
        "windowAvailable": None,
        "cleanup": None,
    }


def _project_console_evidence(
    application: object, runtime_id: str
) -> dict[str, object]:
    common = {"schemaVersion", "runtimeId", "appId", "status"}
    if not isinstance(application, dict):
        raise AcceptanceError("projected Console application is invalid")
    status_value = application.get("status")
    if status_value != "accepted":
        failure = _projection_input_object(
            application,
            common | {"failureClass", "reasonCode"},
            APPLICATION_DYNAMIC_KEYS,
            "projected Console failure",
        )
        _validate_dynamic_fields(failure, APPLICATION_DYNAMIC_KEYS)
        return _failure_projection(failure, runtime_id, "console")

    accepted = _projection_input_object(
        application,
        common | {"packDigest", "guestDigest", "eventKinds", "exitCode"},
        APPLICATION_DYNAMIC_KEYS,
        "projected Console application",
    )
    _validate_dynamic_fields(accepted, APPLICATION_DYNAMIC_KEYS)
    if (
        accepted["schemaVersion"] != "1"
        or accepted["runtimeId"] != runtime_id
        or accepted["appId"] != "console"
        or accepted["exitCode"] != 0
        or isinstance(accepted["exitCode"], bool)
    ):
        raise AcceptanceError("projected Console application is invalid")
    event_kinds = accepted["eventKinds"]
    if (
        not isinstance(event_kinds, list)
        or not event_kinds
        or len(event_kinds) > MAX_RUNTIME_EVENTS
        or any(
            not isinstance(kind, str)
            or re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", kind) is None
            for kind in event_kinds
        )
    ):
        raise AcceptanceError("projected Console event kinds are invalid")
    guest_digest = _digest(accepted["guestDigest"], "projected Console guest digest")
    return {
        "appId": "console",
        "assetSha256": guest_digest.removeprefix("sha256:"),
        "packDigest": _digest(accepted["packDigest"], "projected Console pack digest"),
        "status": "accepted",
        "interactionChecks": {},
        "eventKinds": list(event_kinds),
        "installerExitPresent": None,
        "installerExitCode": None,
        "exitPresent": True,
        "exitCode": 0,
        "windowAvailable": False,
        "cleanup": True,
    }


def _project_gui_evidence(
    application: object, runtime_id: str, application_id: str
) -> dict[str, object]:
    common = {"schemaVersion", "runtimeId", "appId", "status"}
    stable_optional = {
        "assetSha256",
        "failureClass",
        "reasonCode",
        "interactionChecks",
        "installerExit",
        "exit",
        "windowAvailable",
        "screenshotAvailable",
        "cleanup",
    }
    if not isinstance(application, dict):
        raise AcceptanceError("projected GUI application is invalid")
    value = _projection_input_object(
        application,
        common,
        stable_optional | APPLICATION_DYNAMIC_KEYS,
        "projected GUI application",
    )
    _validate_dynamic_fields(value, APPLICATION_DYNAMIC_KEYS)
    if (
        value["schemaVersion"] != "1"
        or value["runtimeId"] != runtime_id
        or value["appId"] != application_id
        or value["status"] not in STATUSES
    ):
        raise AcceptanceError("projected GUI application identity is invalid")

    if value["status"] != "accepted":
        failure = _failure_projection(value, runtime_id, application_id)
        asset_digest = value.get("assetSha256")
        if asset_digest is not None:
            if not isinstance(asset_digest, str) or re.fullmatch(r"[0-9a-f]{64}", asset_digest) is None:
                raise AcceptanceError("projected GUI asset digest is invalid")
            failure["assetSha256"] = asset_digest
        interactions = value.get("interactionChecks")
        if interactions is not None:
            required = REQUIRED_INTERACTIONS[application_id]
            if (
                not isinstance(interactions, dict)
                or tuple(interactions) != required
                or any(not isinstance(checked, bool) for checked in interactions.values())
            ):
                raise AcceptanceError("projected GUI interaction checks are invalid")
            failure["interactionChecks"] = {name: interactions[name] for name in required}
        if "installerExit" in value:
            installer_exit = _project_exit(value["installerExit"])
            if not _closed_exit_relation(installer_exit):
                raise AcceptanceError("projected GUI installer exit relation is invalid")
            failure["installerExitPresent"] = installer_exit["present"]
            failure["installerExitCode"] = installer_exit["code"]
        if "exit" in value:
            exit_value = _project_exit(value["exit"])
            if not _closed_exit_relation(exit_value):
                raise AcceptanceError("projected GUI exit relation is invalid")
            failure["exitPresent"] = exit_value["present"]
            failure["exitCode"] = exit_value["code"]
        if "windowAvailable" in value:
            if not isinstance(value["windowAvailable"], bool):
                raise AcceptanceError("projected GUI window flag is invalid")
            failure["windowAvailable"] = value["windowAvailable"]
        if "cleanup" in value:
            if not isinstance(value["cleanup"], bool):
                raise AcceptanceError("projected GUI cleanup is invalid")
            failure["cleanup"] = value["cleanup"]
        if "screenshotAvailable" in value and not isinstance(value["screenshotAvailable"], bool):
            raise AcceptanceError("projected GUI screenshot flag is invalid")
        return failure

    stable = {key: nested for key, nested in value.items() if key not in APPLICATION_DYNAMIC_KEYS}
    if "failureClass" in stable or "reasonCode" in stable or not _complete_accepted_gui(stable):
        raise AcceptanceError("projected accepted GUI evidence is incomplete")
    if "screenshotAvailable" in stable and not isinstance(stable["screenshotAvailable"], bool):
        raise AcceptanceError("projected GUI screenshot flag is invalid")
    installer_exit = _project_exit(stable["installerExit"])
    exit_value = _project_exit(stable["exit"])
    return {
        "appId": application_id,
        "assetSha256": stable["assetSha256"],
        "status": "accepted",
        "interactionChecks": {
            name: stable["interactionChecks"][name]
            for name in REQUIRED_INTERACTIONS[application_id]
        },
        "installerExitPresent": installer_exit["present"],
        "installerExitCode": installer_exit["code"],
        "exitPresent": exit_value["present"],
        "exitCode": exit_value["code"],
        "windowAvailable": stable["windowAvailable"],
        "cleanup": stable["cleanup"],
    }


def _project_desktop_evidence(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AcceptanceError("projected desktop evidence is invalid")
    if value.get("status") == "accepted":
        if set(value) != {"status", "exitCode"} or value["exitCode"] != 0 or isinstance(
            value["exitCode"], bool
        ):
            raise AcceptanceError("projected desktop evidence is invalid")
        return {"status": "accepted", "exitCode": 0}
    reason_code = value.get("reasonCode")
    failure_class = value.get("failureClass")
    if (
        set(value) != {"status", "failureClass", "reasonCode"}
        or not isinstance(reason_code, str)
        or failure_class not in FAILURE_CLASSES
        or DESKTOP_FAILURE_RELATIONS.get(reason_code)
        != (value.get("status"), failure_class)
    ):
        raise AcceptanceError("projected desktop failure is invalid")
    return {
        "status": value["status"],
        "failureClass": value["failureClass"],
        "reasonCode": value["reasonCode"],
    }


def project_round_evidence(value: object) -> dict[str, object]:
    """Build the deterministic redacted projection from one closed aggregate round."""

    _bounded_structure(value, "round evidence")
    round_value = _projection_input_object(
        value,
        {"roundId", "runtimes"},
        ROUND_DYNAMIC_KEYS,
        "round evidence",
    )
    _validate_dynamic_fields(round_value, ROUND_DYNAMIC_KEYS)
    if round_value["roundId"] not in ROUNDS:
        raise AcceptanceError("round evidence identity is invalid")
    runtimes = round_value["runtimes"]
    if not isinstance(runtimes, list) or len(runtimes) != len(RUNTIME_IDS):
        raise AcceptanceError("round evidence Runtime records are incomplete")

    runtime_records: dict[str, dict[str, object]] = {}
    for raw_runtime in runtimes:
        runtime = _projection_input_object(
            raw_runtime,
            {"runtimeId", "runtimeVersion", "packDigest", "applications", "desktop"},
            RUNTIME_DYNAMIC_KEYS,
            "round Runtime evidence",
        )
        _validate_dynamic_fields(runtime, RUNTIME_DYNAMIC_KEYS)
        runtime_id = runtime["runtimeId"]
        if runtime_id not in RUNTIME_IDS or runtime_id in runtime_records:
            raise AcceptanceError("round Runtime identities are invalid")
        runtime_version = _runtime_version(runtime["runtimeVersion"])
        pack_digest = _digest(runtime["packDigest"], "round Runtime pack digest")
        applications = runtime["applications"]
        if not isinstance(applications, list) or len(applications) != len(
            RUNTIME_MATRIX[runtime_id]
        ):
            raise AcceptanceError("round application records are incomplete")
        by_application: dict[str, object] = {}
        for application in applications:
            if not isinstance(application, dict):
                raise AcceptanceError("round application evidence is invalid")
            application_id = application.get("appId")
            if application_id not in RUNTIME_MATRIX[runtime_id] or application_id in by_application:
                raise AcceptanceError("round application identities are invalid")
            by_application[application_id] = application
        projected_applications: list[dict[str, object]] = []
        for application_id in RUNTIME_MATRIX[runtime_id]:
            application = by_application.get(application_id)
            if application_id == "console":
                projected = _project_console_evidence(application, runtime_id)
            else:
                projected = _project_gui_evidence(application, runtime_id, application_id)
            projected_applications.append(projected)
        runtime_records[runtime_id] = {
            "runtimeId": runtime_id,
            "runtimeVersion": runtime_version,
            "packDigest": pack_digest,
            "applications": projected_applications,
            "desktop": _project_desktop_evidence(runtime["desktop"]),
        }
    if set(runtime_records) != set(RUNTIME_IDS):
        raise AcceptanceError("round Runtime records are incomplete")
    return {
        "schemaVersion": "1",
        "runtimes": [runtime_records[runtime_id] for runtime_id in RUNTIME_IDS],
    }


def _validate_canonical_application(
    application: object, runtime_id: str, application_id: str
) -> None:
    accepted_keys = {
        "appId",
        "assetSha256",
        "status",
        "interactionChecks",
        "installerExitPresent",
        "installerExitCode",
        "exitPresent",
        "exitCode",
        "windowAvailable",
        "cleanup",
    }
    failure_keys = accepted_keys | {"failureClass", "reasonCode"}
    console_keys = accepted_keys | {"packDigest", "eventKinds"}
    if not isinstance(application, dict) or application.get("appId") != application_id:
        raise AcceptanceError("round projection application identity is invalid")
    status_value = application.get("status")
    expected_keys = (
        console_keys
        if application_id == "console" and status_value == "accepted"
        else accepted_keys
        if status_value == "accepted"
        else failure_keys
    )
    if set(application) != expected_keys:
        raise AcceptanceError("round projection application schema is invalid")

    asset_digest = application["assetSha256"]
    if asset_digest is not None and (
        not isinstance(asset_digest, str) or re.fullmatch(r"[0-9a-f]{64}", asset_digest) is None
    ):
        raise AcceptanceError("round projection asset digest is invalid")
    interactions = application["interactionChecks"]
    required_interactions = () if application_id == "console" else REQUIRED_INTERACTIONS[application_id]
    if (
        not isinstance(interactions, dict)
        or tuple(interactions) not in ((), required_interactions)
        or any(not isinstance(checked, bool) for checked in interactions.values())
    ):
        raise AcceptanceError("round projection interaction checks are invalid")
    for field in ("installerExitCode", "exitCode"):
        code = application[field]
        if code is not None and (
            not isinstance(code, int)
            or isinstance(code, bool)
            or abs(code) > MAX_DYNAMIC_INTEGER
        ):
            raise AcceptanceError("round projection exit code is invalid")
    for field in ("installerExitPresent", "exitPresent"):
        present = application[field]
        if present is not None and not isinstance(present, bool):
            raise AcceptanceError("round projection exit presence is invalid")
    for prefix in ("installerExit", "exit"):
        present = application[f"{prefix}Present"]
        code = application[f"{prefix}Code"]
        if not (
            (present is None and code is None)
            or (present is False and code is None)
            or (present is True and isinstance(code, int) and not isinstance(code, bool))
        ):
            raise AcceptanceError("round projection exit relation is invalid")
    for field in ("windowAvailable", "cleanup"):
        flag = application[field]
        if flag is not None and not isinstance(flag, bool):
            raise AcceptanceError("round projection observation flag is invalid")

    if status_value == "accepted":
        if application_id == "console":
            event_kinds = application["eventKinds"]
            if (
                application["assetSha256"] is None
                or _digest(application["packDigest"], "round projection Console pack digest")
                != application["packDigest"]
                or not isinstance(event_kinds, list)
                or not event_kinds
                or len(event_kinds) > MAX_RUNTIME_EVENTS
                or any(
                    not isinstance(kind, str)
                    or re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]*", kind) is None
                    for kind in event_kinds
                )
                or application["installerExitCode"] is not None
                or application["installerExitPresent"] is not None
                or application["exitPresent"] is not True
                or application["exitCode"] != 0
                or application["windowAvailable"] is not False
                or application["cleanup"] is not True
                or interactions
            ):
                raise AcceptanceError("round projection Console result is invalid")
        elif (
            application["assetSha256"] is None
            or tuple(interactions) != required_interactions
            or any(checked is not True for checked in interactions.values())
            or application["installerExitCode"] != 0
            or application["installerExitPresent"] is not True
            or application["exitPresent"] is not True
            or application["exitCode"] != 0
            or application["windowAvailable"] is not True
            or application["cleanup"] is not True
        ):
            raise AcceptanceError("round projection GUI result is invalid")
        return

    failure_class = application.get("failureClass")
    reason_code = application.get("reasonCode")
    if (
        not isinstance(reason_code, str)
        or failure_class not in FAILURE_CLASSES
        or APPLICATION_FAILURE_RELATIONS.get(reason_code) != (status_value, failure_class)
    ):
        raise AcceptanceError("round projection application failure is invalid")


def _validate_canonical_projection(projection: object) -> None:
    if (
        not isinstance(projection, dict)
        or set(projection) != {"schemaVersion", "runtimes"}
        or projection.get("schemaVersion") != "1"
    ):
        raise AcceptanceError("round projection schema is invalid")
    runtimes = projection["runtimes"]
    if not isinstance(runtimes, list) or len(runtimes) != len(RUNTIME_IDS):
        raise AcceptanceError("round projection Runtime records are incomplete")
    for runtime_id, runtime in zip(RUNTIME_IDS, runtimes):
        if (
            not isinstance(runtime, dict)
            or set(runtime)
            != {"runtimeId", "runtimeVersion", "packDigest", "applications", "desktop"}
            or runtime.get("runtimeId") != runtime_id
        ):
            raise AcceptanceError("round projection Runtime identity is invalid")
        _runtime_version(runtime["runtimeVersion"])
        _digest(runtime["packDigest"], "round projection Runtime pack digest")
        applications = runtime["applications"]
        if not isinstance(applications, list) or len(applications) != len(
            RUNTIME_MATRIX[runtime_id]
        ):
            raise AcceptanceError("round projection applications are incomplete")
        for application_id, application in zip(RUNTIME_MATRIX[runtime_id], applications):
            _validate_canonical_application(application, runtime_id, application_id)
        _project_desktop_evidence(runtime["desktop"])


def canonical_projection_bytes(projection: object) -> bytes:
    """Encode one internally produced projection with a bounded canonical JSON form."""

    _bounded_structure(projection, "round projection")
    _validate_canonical_projection(projection)
    encoded = json.dumps(projection, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > MAX_JSON_BYTES:
        raise AcceptanceError("round projection exceeds its size bound")
    return encoded


def compare_round_evidence(first: object, second: object) -> bool:
    """Fail closed unless both rounds have byte-identical allowlist projections."""

    try:
        first_projection = project_round_evidence(first)
        second_projection = project_round_evidence(second)
        return canonical_projection_bytes(first_projection) == canonical_projection_bytes(
            second_projection
        )
    except (AcceptanceError, RecursionError, UnicodeError, ValueError, TypeError):
        return False


def build_round_comparison(
    rounds: object,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Project two fixed rounds and report whether the stable evidence is identical."""

    if not isinstance(rounds, list) or len(rounds) != len(ROUNDS):
        raise AcceptanceError("round comparison evidence is incomplete")
    if any(
        not isinstance(round_value, dict) or round_value.get("roundId") != round_id
        for round_id, round_value in zip(ROUNDS, rounds)
    ):
        raise AcceptanceError("round comparison identities are invalid")
    projections = [project_round_evidence(round_value) for round_value in rounds]
    rounds_equal = canonical_projection_bytes(projections[0]) == canonical_projection_bytes(
        projections[1]
    )
    accepted = rounds_equal and aggregate_is_accepted(rounds)
    return projections, {
        "schemaVersion": "1",
        "roundsEqual": rounds_equal,
        "status": "accepted" if accepted else "failed",
    }


def aggregate_is_accepted(rounds: object) -> bool:
    if not isinstance(rounds, list) or len(rounds) != len(ROUNDS):
        return False
    for round_id, round_entry in zip(ROUNDS, rounds):
        if not isinstance(round_entry, dict) or round_entry.get("roundId") != round_id:
            return False
        runtimes = round_entry.get("runtimes")
        if not isinstance(runtimes, list) or len(runtimes) != len(RUNTIME_IDS):
            return False
        for runtime_id, runtime in zip(RUNTIME_IDS, runtimes):
            if not isinstance(runtime, dict) or runtime.get("runtimeId") != runtime_id:
                return False
            if not isinstance(runtime.get("runtimeVersion"), str):
                return False
            if not isinstance(runtime.get("packDigest"), str) or re.fullmatch(
                r"sha256:[0-9a-f]{64}", runtime["packDigest"]
            ) is None:
                return False
            desktop = runtime.get("desktop")
            if not isinstance(desktop, dict) or desktop != {"status": "accepted", "exitCode": 0}:
                return False
            applications = runtime.get("applications")
            if not isinstance(applications, list) or len(applications) != 4:
                return False
            if [value.get("appId") if isinstance(value, dict) else None for value in applications] != list(
                RUNTIME_MATRIX[runtime_id]
            ):
                return False
            console = applications[0]
            if (
                not isinstance(console, dict)
                or console.get("status") != "accepted"
                or console.get("exitCode") != 0
                or not isinstance(console.get("eventKinds"), list)
                or not isinstance(console.get("packDigest"), str)
                or not isinstance(console.get("guestDigest"), str)
            ):
                return False
            if any(not _complete_accepted_gui(application) for application in applications[1:]):
                return False
    return True


def _headless_command(paths: AcceptancePaths, round_id: str, descriptor: dict[str, object]) -> list[str]:
    runtime_id = _descriptor_text(descriptor, "runtimeId")
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
        _descriptor_text(descriptor, "materializedRoot"),
        "--wine",
        _descriptor_text(descriptor, "wine"),
        "--wineserver",
        _descriptor_text(descriptor, "wineserver"),
        "--runtime-store",
        str(paths.runtime_store_root / round_id / runtime_id / "console"),
        "--storage-root",
        str(paths.storage_root / round_id / runtime_id / "console"),
        "--work-root",
        str(paths.work_root / round_id / runtime_id / "console"),
        "--pack-id",
        f"wine-macos-{runtime_id}-preview",
        "--version",
        _descriptor_text(descriptor, "version"),
    ]


def _gui_command(paths: AcceptancePaths, round_id: str, descriptor: dict[str, object]) -> list[str]:
    runtime_id = _descriptor_text(descriptor, "runtimeId")
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
        _descriptor_text(descriptor, "materializedRoot"),
        "--wine",
        _descriptor_text(descriptor, "wine"),
        "--wineserver",
        _descriptor_text(descriptor, "wineserver"),
        "--version",
        _descriptor_text(descriptor, "version"),
        "--accept-interactive",
        "--interaction-evidence",
        str(paths.interaction_evidence_root / round_id / f"{runtime_id}.json"),
    ]
    if paths.allow_network:
        command.append("--allow-network")
    return command


def _desktop_command(paths: AcceptancePaths, round_id: str, descriptor: dict[str, object]) -> list[str]:
    runtime_id = _descriptor_text(descriptor, "runtimeId")
    return [
        str(paths.desktop_app),
        "--acceptance-root",
        str(paths.work_root / round_id / runtime_id / "desktop"),
        "--wine-root",
        _descriptor_text(descriptor, "materializedRoot"),
        "--wine",
        _descriptor_text(descriptor, "wine"),
        "--wineserver",
        _descriptor_text(descriptor, "wineserver"),
        "--version",
        _descriptor_text(descriptor, "version"),
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
) -> tuple[dict[str, object], bool]:
    printer("compatforge-desktop-command: " + json.dumps(command, ensure_ascii=False, separators=(",", ":")))
    group_options = _process_group_options()
    try:
        process = launcher(
            command,
            cwd=ROOT,
            env=dict(CHILD_ENV),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            **group_options,
        )
    except Exception:
        return (
            {
                "status": "failed",
                "failureClass": "desktop",
                "reasonCode": "desktop-launch-failed",
            },
            True,
        )
    try:
        process_group = _posix_process_group(process, group_options)
    except CleanupError:
        _stop_process(process)
        raise
    try:
        returncode = waiter(process, DESKTOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _stop_process(process, process_group=process_group)
        return (
            {
                "status": "failed",
                "failureClass": "desktop",
                "reasonCode": "desktop-timeout-failed",
            },
            True,
        )
    except Exception as error:
        _stop_process(process, process_group=process_group)
        raise CleanupError("desktop process wait failed") from error
    polled = _process_poll(process)
    if polled is None:
        _stop_process(process, process_group=process_group)
        return (
            {
                "status": "failed",
                "failureClass": "desktop",
                "reasonCode": "desktop-exit-failed",
            },
            True,
        )
    _reap_residual_process_group(process, process_group)
    if (
        not isinstance(returncode, int)
        or isinstance(returncode, bool)
        or returncode != polled
        or returncode != 0
    ):
        return (
            {
                "status": "failed",
                "failureClass": "desktop",
                "reasonCode": "desktop-exit-failed",
            },
            True,
        )
    return {"status": "accepted", "exitCode": 0}, True


def orchestrate(
    arguments: argparse.Namespace,
    *,
    runner: Runner | None = None,
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
    _revalidate_bindings(paths)
    try:
        runtimes = discover_runtimes(arguments, runner)
    finally:
        _revalidate_bindings(paths)
    if arguments.negative_checks is True:
        summary = run_negative_checks(
            paths,
            runtimes,
            console_guest=Path(arguments.console_guest),
            sentinel=Path(arguments.negative_sentinel),
            guest_runner=runner,
        )
        encoded = json.dumps(
            summary,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        _safe_create_output(
            paths,
            ("negative-summary.json",),
            encoded,
            "negative summary output",
        )
        return summary
    _prepare_layout(paths)
    rounds: list[dict[str, object]] = []
    abort_remaining = False
    for round_id in ROUNDS:
        runtime_results: list[dict[str, object]] = []
        for descriptor in runtimes:
            runtime_id = _descriptor_text(descriptor, "runtimeId")
            applications: list[dict[str, object]] = []
            runtime_evidence: dict[str, object] = {}
            try:
                _revalidate_bindings(paths)
                _revalidate_runtime(descriptor)
                try:
                    console_result = _invoke(
                        _headless_command(paths, round_id, descriptor),
                        runner,
                        timeout=CHILD_TIMEOUT_SECONDS,
                    )
                finally:
                    _revalidate_bindings(paths)
                    _revalidate_runtime(descriptor)
                if console_result.returncode != 0:
                    raise AcceptanceError("Console runner failed")
                console = _project_console(
                    parse_closed_json(console_result.stdout, "Console summary"), descriptor
                )
            except (IntegrityError, CleanupError):
                raise
            except AcceptanceError:
                console = _failure("console", runtime_id, "core", "console-runner-failed")
            _revalidate_bindings(paths)
            _revalidate_runtime(descriptor)
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
                    _revalidate_bindings(paths)
                    _revalidate_runtime(descriptor)
                    try:
                        gui_result = _invoke(
                            _gui_command(paths, round_id, descriptor),
                            runner,
                            timeout=CHILD_TIMEOUT_SECONDS,
                        )
                    finally:
                        _revalidate_bindings(paths)
                        _revalidate_runtime(descriptor)
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
                except (IntegrityError, CleanupError):
                    raise
                except AcceptanceError:
                    gui_applications = [
                        _failure(application_id, runtime_id, "application", "gui-summary-invalid")
                        for application_id in GUI_APPLICATIONS
                    ]
                applications.extend(gui_applications)
                _revalidate_bindings(paths)
                _revalidate_runtime(descriptor)
                try:
                    desktop, continue_safe = _launch_desktop(
                        _desktop_command(paths, round_id, descriptor), launcher, waiter, printer
                    )
                finally:
                    _revalidate_bindings(paths)
                    _revalidate_runtime(descriptor)
                if not continue_safe:
                    abort_remaining = True
            _revalidate_bindings(paths)
            _revalidate_runtime(descriptor)
            runtime_results.append(
                {
                    "runtimeId": runtime_id,
                    **runtime_evidence,
                    "applications": applications,
                    "desktop": desktop,
                }
            )
            if abort_remaining:
                break
        _revalidate_bindings(paths)
        for descriptor in runtimes:
            _revalidate_runtime(descriptor)
        rounds.append({"roundId": round_id, "runtimes": runtime_results})
        if abort_remaining:
            break
    _revalidate_bindings(paths)
    for descriptor in runtimes:
        _revalidate_runtime(descriptor)
    matrix_accepted = aggregate_is_accepted(rounds)
    projections: list[dict[str, object]] | None = None
    comparison: dict[str, object] | None = None
    try:
        projections, comparison = build_round_comparison(rounds)
    except AcceptanceError:
        if matrix_accepted:
            raise
    accepted = comparison is not None and comparison["status"] == "accepted"
    summary: dict[str, object] = {
        "schemaVersion": "1",
        "status": "accepted" if accepted else "failed",
        "rounds": rounds,
    }
    encoded = json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_JSON_BYTES:
        raise AcceptanceError("aggregate summary exceeds its size bound")
    _revalidate_bindings(paths)
    for descriptor in runtimes:
        _revalidate_runtime(descriptor)
    if projections is not None and comparison is not None:
        for round_id, projection in zip(ROUNDS, projections):
            _safe_create_output(
                paths,
                (round_id, "round-projection.json"),
                canonical_projection_bytes(projection).decode("utf-8"),
                "round projection output",
            )
        comparison_encoded = json.dumps(
            comparison, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        _safe_create_output(
            paths,
            ("comparison.json",),
            comparison_encoded,
            "comparison output",
        )
    _safe_create_summary(paths, encoded)
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
