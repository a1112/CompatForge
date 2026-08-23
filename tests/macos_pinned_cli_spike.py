"""Test-only closed handoff driver for the pinned SumatraPDF macOS spike.

This module is deliberately independent from the production acceptance runner.
It performs no acknowledgement, network, installation, or source mutation.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable


MAX_MANIFEST_BYTES = 1_048_576
MAX_INPUT_BYTES = 134_217_728
MAX_EVIDENCE_BYTES = 1_048_576
MAX_TRANSCRIPT_BYTES = 1_048_576
MAX_PROCESS_STDOUT_BYTES = MAX_TRANSCRIPT_BYTES
MAX_PROCESS_STDERR_BYTES = MAX_TRANSCRIPT_BYTES
MAX_PROCESS_OUTPUT_BYTES = MAX_TRANSCRIPT_BYTES
MAX_WINDOW_PROBE_STDOUT_BYTES = 65_536
MAX_WINDOW_PROBE_STDERR_BYTES = 65_536
MAX_WINDOW_PROBE_OUTPUT_BYTES = 65_536
OUTPUT_NAME_ATTEMPTS = 16
WINDOW_POLL_SECONDS = 0.25
WINDOW_ABSENCE_SECONDS = 10.0
PROCESS_POLL_SECONDS = 0.025
PROCESS_TERMINATE_SECONDS = 1.0
PROCESS_CLEANUP_SECONDS = 10.0
WINDOW_PROBE_TIMEOUT_SECONDS = 10.0
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MANIFEST_KEYS = (
    "cli",
    "runtimes",
    "schemaVersion",
    "timeoutMilliseconds",
    "windowTitleTokens",
)
_RUNTIME_KEYS = (
    "config",
    "logicalExecutable",
    "mutationPayload",
    "request",
    "runtimeId",
    "workRoot",
)
_FILE_KEYS = ("path", "sha256")
_EVENT_BASE_KEYS = (
    "schemaVersion",
    "requestId",
    "sequence",
    "elapsedMilliseconds",
    "kind",
)
_EVENT_KINDS = {
    "started",
    "terminate-requested",
    "timed-out",
    "grace-period-expired",
    "wine-server-stop-requested",
    "exited",
}


class SpikeError(RuntimeError):
    """A closed, path-free spike failure."""


class WindowProbeState(Enum):
    ABSENT = "absent"
    PRESENT = "present"
    FAILED = "failed"


@dataclass(frozen=True)
class FileBinding:
    path: str
    identity: tuple[int, int]
    size: int
    mtime_ns: int
    sha256: str
    payload: bytes
    ctime_ns: int = 0
    owner: int = 0


@dataclass(frozen=True)
class WorkRootBinding:
    path: str
    descriptor: int
    identity: tuple[int, int]


@dataclass(frozen=True)
class EvidenceFileBinding:
    descriptor: int
    identity: tuple[int, int]


@dataclass(frozen=True)
class DescriptorSnapshot:
    identity: tuple[int, int]
    kind: str
    mode: int
    nlink: int
    size: int
    access_mode: int
    append: bool
    close_on_exec: bool = True


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, nested in pairs:
        if key in value:
            raise SpikeError("JSON contains a duplicate key")
        value[key] = nested
    return value


def _reject_constant(_value: str) -> object:
    raise ValueError("non-standard JSON value")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise SpikeError("JSON is not canonical") from error


def _parse_json(raw: bytes, label: str, maximum: int) -> object:
    if not raw or len(raw) > maximum:
        raise SpikeError(f"{label} exceeds its bound")
    try:
        text = raw.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except SpikeError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise SpikeError(f"{label} is invalid") from error


def _require_keys(value: object, expected: tuple[str, ...], label: str) -> dict[str, object]:
    if type(value) is not dict or tuple(sorted(value)) != expected:
        raise SpikeError(f"{label} shape is invalid")
    return value


def _closed_absolute_path(value: object, label: str) -> str:
    if type(value) is not str or not value.startswith("/") or value.startswith("//") or "\\" in value:
        raise SpikeError(f"{label} path is invalid")
    components = value[1:].split("/")
    if not components or any(not component or component in (".", "..") for component in components):
        raise SpikeError(f"{label} path is invalid")
    if str(PurePosixPath(value)) != value:
        raise SpikeError(f"{label} path is invalid")
    return value


def _file_reference(value: object, label: str) -> tuple[str, str]:
    reference = _require_keys(value, _FILE_KEYS, label)
    path = _closed_absolute_path(reference["path"], label)
    digest = reference["sha256"]
    if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
        raise SpikeError(f"{label} digest is invalid")
    return path, digest


def _validate_manifest(value: object) -> dict[str, object]:
    manifest = _require_keys(value, _MANIFEST_KEYS, "manifest")
    _file_reference(manifest["cli"], "CLI")
    cli_path = manifest["cli"]["path"]  # type: ignore[index]
    if PurePosixPath(cli_path).name != "compatforge-cli":
        raise SpikeError("CLI artifact is invalid")
    if (
        type(manifest["schemaVersion"]) is not int
        or manifest["schemaVersion"] != 1
        or type(manifest["timeoutMilliseconds"]) is not int
        or manifest["timeoutMilliseconds"] != 60_000
    ):
        raise SpikeError("manifest constants are invalid")
    if manifest["windowTitleTokens"] != ["SumatraPDF"]:
        raise SpikeError("window token is invalid")
    runtimes = manifest["runtimes"]
    if type(runtimes) is not list or len(runtimes) != 2:
        raise SpikeError("Runtime records are invalid")
    logical_paths: list[str] = []
    for index, expected_id in enumerate(("crossover", "whisky")):
        runtime = _require_keys(runtimes[index], _RUNTIME_KEYS, "Runtime")
        if runtime["runtimeId"] != expected_id:
            raise SpikeError("Runtime order is invalid")
        for field in ("config", "logicalExecutable", "mutationPayload", "request"):
            path, _digest = _file_reference(runtime[field], field)
            if field == "logicalExecutable":
                logical_paths.append(path)
        _closed_absolute_path(runtime["workRoot"], "work root")
    suffix = "/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe"
    if any(not path.endswith(suffix) for path in logical_paths):
        raise SpikeError("logical executable is invalid")
    return manifest


def parse_manifest_bytes(raw: bytes) -> dict[str, object]:
    value = _parse_json(raw, "manifest", MAX_MANIFEST_BYTES)
    manifest = _validate_manifest(value)
    if _canonical_json(manifest) != raw:
        raise SpikeError("manifest is not canonical")
    return manifest


def _paths_overlap(left: str, right: str) -> bool:
    left_prefix = left.rstrip("/") + "/"
    right_prefix = right.rstrip("/") + "/"
    return left == right or left.startswith(right_prefix) or right.startswith(left_prefix)


def _absolute_json_paths(raw: bytes) -> set[str]:
    try:
        value = _parse_json(raw, "reviewed input", MAX_INPUT_BYTES)
    except SpikeError:
        return set()
    paths: set[str] = set()
    stack = [value]
    while stack:
        nested = stack.pop()
        if type(nested) is dict:
            stack.extend(nested.values())
        elif type(nested) is list:
            stack.extend(nested)
        elif type(nested) is str and nested.startswith("/"):
            try:
                paths.add(_closed_absolute_path(nested, "reviewed input"))
            except SpikeError:
                continue
    return paths


def _runtime_protected_roots(raw: bytes) -> set[str]:
    value = _parse_json(raw, "Runtime config", MAX_INPUT_BYTES)
    if type(value) is not dict or type(value.get("runtimeBindings")) is not list or not value["runtimeBindings"]:
        raise SpikeError("Runtime config bindings are invalid")
    protected: set[str] = set()
    for binding in value["runtimeBindings"]:
        if type(binding) is not dict:
            raise SpikeError("Runtime config binding is invalid")
        executable = binding.get("executable")
        wineserver = binding.get("wineserverExecutable")
        paths = [executable]
        if wineserver is not None:
            paths.append(wineserver)
        for candidate in paths:
            path = _closed_absolute_path(candidate, "Runtime executable")
            parent = str(PurePosixPath(path).parent)
            if parent == "/":
                raise SpikeError("Runtime executable root is invalid")
            protected.add(parent)
    return protected


def _bind_manifest_inputs(
    manifest: dict[str, object],
    boundary: object,
) -> tuple[dict[str, FileBinding], list[dict[str, object]], set[str]]:
    references: list[tuple[str, str, str]] = []
    cli_path, cli_digest = _file_reference(manifest["cli"], "CLI")
    references.append((cli_path, cli_digest, "CLI"))
    runtimes = manifest["runtimes"]
    assert type(runtimes) is list
    runtime_values: list[dict[str, object]] = []
    for runtime_value in runtimes:
        runtime = _require_keys(runtime_value, _RUNTIME_KEYS, "Runtime")
        runtime_values.append(runtime)
        for field in ("config", "logicalExecutable", "mutationPayload", "request"):
            path, digest = _file_reference(runtime[field], field)
            references.append((path, digest, field))

    bindings: dict[str, FileBinding] = {}
    forbidden: set[str] = set()
    for path, digest, label in references:
        canonical = boundary.resolve_canonical(path, directory=False)
        if canonical != path:
            raise SpikeError("input path is not canonical")
        existing = bindings.get(path)
        if existing is not None:
            if existing.sha256 != digest:
                raise SpikeError("duplicate input binding disagrees")
            continue
        binding = boundary.bind_input(path, digest, label)
        bindings[path] = binding
        forbidden.add(path)
        if label in ("config", "request"):
            forbidden.update(_absolute_json_paths(binding.payload))
        if label == "config":
            forbidden.update(_runtime_protected_roots(binding.payload))
    return bindings, runtime_values, forbidden


def _validate_work_roots(
    runtime_values: list[dict[str, object]],
    forbidden: set[str],
    boundary: object,
) -> list[str]:
    repository_root = boundary.resolve_canonical(boundary.repository_root, directory=True)
    roots: list[str] = []
    resolved_forbidden = set(forbidden)
    for path in tuple(forbidden):
        try:
            resolved_forbidden.add(boundary.resolve_canonical(path, directory=False))
        except (OSError, SpikeError):
            try:
                resolved_forbidden.add(boundary.resolve_canonical(path, directory=True))
            except (OSError, SpikeError):
                pass
    for runtime in runtime_values:
        root = _closed_absolute_path(runtime["workRoot"], "work root")
        canonical = boundary.resolve_canonical(root, directory=True)
        if canonical != root or boundary.paths_physically_overlap(root, repository_root):
            raise SpikeError("work root is not external")
        if any(boundary.paths_physically_overlap(root, protected) for protected in resolved_forbidden):
            raise SpikeError("work root overlaps reviewed input")
        if any(boundary.paths_physically_overlap(root, other) for other in roots):
            raise SpikeError("work roots overlap")
        roots.append(root)
    return roots


def _validate_work_descriptor(work_root: WorkRootBinding, boundary: object) -> None:
    if work_root.descriptor <= 2:
        raise SpikeError("work descriptor is invalid")
    snapshot = boundary.describe_descriptor(work_root.descriptor)
    if (
        snapshot.kind != "directory"
        or snapshot.identity != work_root.identity
        or snapshot.nlink < 1
        or not snapshot.close_on_exec
    ):
        raise SpikeError("work descriptor is invalid")


def _validate_empty_output(binding: EvidenceFileBinding, boundary: object) -> None:
    if binding.descriptor <= 2:
        raise SpikeError("evidence descriptor is invalid")
    snapshot = boundary.describe_descriptor(binding.descriptor)
    if (
        snapshot.identity != binding.identity
        or snapshot.kind != "regular"
        or snapshot.mode != 0o600
        or snapshot.nlink != 0
        or snapshot.size != 0
        or snapshot.access_mode != os.O_RDWR
        or snapshot.append
        or not snapshot.close_on_exec
    ):
        raise SpikeError("evidence descriptor is invalid")


class SystemClock:
    @staticmethod
    def monotonic() -> float:
        return time.monotonic()

    @staticmethod
    def sleep(seconds: float) -> None:
        time.sleep(seconds)


class _BoundedOutputCapture:
    def __init__(
        self,
        stdout: object,
        stderr: object,
        *,
        stdout_limit: int = MAX_PROCESS_STDOUT_BYTES,
        stderr_limit: int = MAX_PROCESS_STDERR_BYTES,
        combined_limit: int = MAX_PROCESS_OUTPUT_BYTES,
    ) -> None:
        if min(stdout_limit, stderr_limit, combined_limit) < 0:
            raise SpikeError("CLI output bounds are invalid")
        self._streams = (stdout, stderr)
        try:
            self._descriptors = tuple(self._make_nonblocking(stream) for stream in self._streams)
        except SpikeError:
            for stream in self._streams:
                try:
                    stream.close()
                except BaseException:
                    pass
            raise
        self._limits = (stdout_limit, stderr_limit)
        self._combined_limit = combined_limit
        self._buffers = (bytearray(), bytearray())
        self._total = 0
        self._lock = threading.Lock()
        self._failed = threading.Event()
        self._cancel = threading.Event()
        self._closed = False
        self._threads = tuple(
            threading.Thread(
                target=self._read_stream,
                args=(index,),
                name=f"compatforge-spike-output-{index}",
            )
            for index in range(2)
        )
        started: list[threading.Thread] = []
        try:
            for thread in self._threads:
                thread.start()
                started.append(thread)
        except (OSError, RuntimeError):
            self._cancel.set()
            deadline = time.monotonic() + PROCESS_TERMINATE_SECONDS
            for thread in started:
                thread.join(max(0.0, deadline - time.monotonic()))
            self._close_streams()
            deadline = time.monotonic() + PROCESS_TERMINATE_SECONDS
            for thread in started:
                if thread.is_alive():
                    thread.join(max(0.0, deadline - time.monotonic()))
            raise SpikeError("CLI output reader could not start") from None

    @staticmethod
    def _make_nonblocking(stream: object) -> int | None:
        try:
            descriptor = stream.fileno()
        except (AttributeError, OSError):
            return None
        if type(descriptor) is not int or descriptor < 0:
            raise SpikeError("CLI output pipes are unavailable")
        try:
            os.set_blocking(descriptor, False)
        except OSError as error:
            raise SpikeError("CLI output pipes are unavailable") from error
        return descriptor

    def _read_stream(self, index: int) -> None:
        stream = self._streams[index]
        descriptor = self._descriptors[index]
        local_limit = self._limits[index]
        try:
            while not self._failed.is_set() and not self._cancel.is_set():
                try:
                    chunk = os.read(descriptor, 65_536) if descriptor is not None else stream.read(65_536)
                except BlockingIOError:
                    self._cancel.wait(0.001)
                    continue
                if type(chunk) is not bytes:
                    self._failed.set()
                    return
                if not chunk:
                    return
                with self._lock:
                    local_allowance = max(0, local_limit + 1 - len(self._buffers[index]))
                    combined_allowance = max(0, self._combined_limit + 1 - self._total)
                    retained = min(len(chunk), local_allowance, combined_allowance)
                    self._buffers[index].extend(chunk[:retained])
                    self._total += retained
                    if (
                        retained != len(chunk)
                        or len(self._buffers[index]) > local_limit
                        or self._total > self._combined_limit
                    ):
                        self._failed.set()
                        return
        except BaseException:
            self._failed.set()

    @property
    def readers_joined(self) -> bool:
        return all(not thread.is_alive() for thread in self._threads)

    def has_failed(self) -> bool:
        return self._failed.is_set()

    def _close_streams(self) -> bool:
        if self._closed:
            return True
        closed = True
        for stream in self._streams:
            try:
                stream.close()
            except BaseException:
                closed = False
        self._closed = True
        return closed

    def _join(self, timeout_seconds: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        for thread in self._threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        return self.readers_joined

    def cleanup(self, timeout_seconds: float) -> None:
        self._cancel.set()
        joined = self._join(timeout_seconds)
        closed = self._close_streams()
        if not closed or not joined:
            raise SpikeError("CLI output cleanup failed")

    def finish(self, timeout_seconds: float) -> tuple[bytes, bytes]:
        joined = self._join(timeout_seconds)
        timed_out = not joined
        if timed_out:
            self._cancel.set()
            joined = self._join(PROCESS_TERMINATE_SECONDS)
        closed = self._close_streams()
        if timed_out or not joined or not closed:
            raise SpikeError("CLI output cleanup failed")
        if self._failed.is_set():
            raise SpikeError("CLI output capture failed")
        return bytes(self._buffers[0]), bytes(self._buffers[1])


def _terminate_process(process: object) -> None:
    try:
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=PROCESS_TERMINATE_SECONDS)
            except (OSError, subprocess.TimeoutExpired):
                pass
        if process.poll() is None:
            process.kill()
        process.wait(timeout=PROCESS_CLEANUP_SECONDS - PROCESS_TERMINATE_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        raise SpikeError("child cleanup failed") from None


def _finish_process_output(
    process: object,
    capture: _BoundedOutputCapture,
    timeout_seconds: float,
    clock: object,
) -> tuple[bytes, bytes]:
    deadline = clock.monotonic() + timeout_seconds
    failure: SpikeError | None = None
    while process.poll() is None:
        if capture.has_failed():
            failure = SpikeError("CLI output capture failed")
            break
        if clock.monotonic() >= deadline:
            failure = SpikeError("CLI completion timed out")
            break
        clock.sleep(PROCESS_POLL_SECONDS)
    if failure is not None:
        cleanup_failed = False
        try:
            _terminate_process(process)
        except SpikeError:
            cleanup_failed = True
        try:
            capture.cleanup(PROCESS_CLEANUP_SECONDS)
        except SpikeError:
            cleanup_failed = True
        if cleanup_failed:
            raise SpikeError("child cleanup failed") from None
        raise failure
    try:
        process.wait(timeout=PROCESS_CLEANUP_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        try:
            capture.cleanup(PROCESS_CLEANUP_SECONDS)
        except SpikeError:
            pass
        raise SpikeError("child cleanup failed") from None
    return capture.finish(PROCESS_CLEANUP_SECONDS)


def _run_window_probe(
    spawn: Callable[[], object],
    tokens: tuple[str, ...],
    *,
    timeout_seconds: float = WINDOW_PROBE_TIMEOUT_SECONDS,
    stdout_limit: int = MAX_WINDOW_PROBE_STDOUT_BYTES,
    stderr_limit: int = MAX_WINDOW_PROBE_STDERR_BYTES,
    combined_limit: int = MAX_WINDOW_PROBE_OUTPUT_BYTES,
) -> WindowProbeState:
    process: object | None = None
    capture: _BoundedOutputCapture | None = None
    state = WindowProbeState.FAILED
    cleanup_failed = False
    try:
        process = spawn()
        stdout_stream, stderr_stream = process.take_output_streams()
        capture = _BoundedOutputCapture(
            stdout_stream,
            stderr_stream,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
            combined_limit=combined_limit,
        )
        stdout, stderr = _finish_process_output(process, capture, timeout_seconds, SystemClock())
        if process.returncode == 0 and stderr == b"":
            try:
                titles = stdout.decode("utf-8").splitlines()
            except UnicodeError:
                pass
            else:
                state = (
                    WindowProbeState.PRESENT
                    if any(token.casefold() in title.casefold() for title in titles for token in tokens)
                    else WindowProbeState.ABSENT
                )
    except (OSError, SpikeError):
        pass
    if process is not None:
        try:
            live = process.poll() is None
        except OSError:
            live = True
        if live:
            try:
                _terminate_process(process)
            except SpikeError:
                cleanup_failed = True
    if capture is not None:
        try:
            capture.cleanup(PROCESS_CLEANUP_SECONDS)
        except SpikeError:
            cleanup_failed = True
    return WindowProbeState.FAILED if cleanup_failed else state


def _observe_window(
    process: object,
    capture: _BoundedOutputCapture,
    tokens: tuple[str, ...],
    timeout_seconds: float,
    boundary: object,
) -> None:
    deadline = boundary.monotonic() + timeout_seconds
    while boundary.monotonic() < deadline:
        if capture.has_failed():
            raise SpikeError("CLI output capture failed")
        if process.poll() is not None:
            raise SpikeError("child exited before window observation")
        probe = boundary.probe_window(tokens)
        if type(probe) is not WindowProbeState or probe is WindowProbeState.FAILED:
            raise SpikeError("window probe failed")
        if probe is WindowProbeState.PRESENT:
            if capture.has_failed():
                raise SpikeError("CLI output capture failed")
            return
        boundary.sleep(WINDOW_POLL_SECONDS)
    raise SpikeError("window observation timed out")


def _require_window_absent(tokens: tuple[str, ...], boundary: object) -> None:
    deadline = boundary.monotonic() + WINDOW_ABSENCE_SECONDS
    while True:
        probe = boundary.probe_window(tokens)
        if type(probe) is not WindowProbeState or probe is WindowProbeState.FAILED:
            raise SpikeError("window probe failed")
        if probe is WindowProbeState.ABSENT:
            return
        if boundary.monotonic() >= deadline:
            raise SpikeError("matching window did not clear")
        boundary.sleep(WINDOW_POLL_SECONDS)


def _parse_transcript(raw: bytes, forbidden: Iterable[str]) -> list[dict[str, object]]:
    if not raw or len(raw) > MAX_TRANSCRIPT_BYTES or not raw.endswith(b"\n"):
        raise SpikeError("CLI transcript is invalid")
    for secret in forbidden:
        if secret and secret.encode("utf-8") in raw:
            raise SpikeError("CLI transcript leaked a path")
    if b'"/' in raw or b"/dev/fd/" in raw:
        raise SpikeError("CLI transcript leaked a path or descriptor")
    lines = raw.splitlines()
    if len(lines) < 2 or any(not line for line in lines):
        raise SpikeError("CLI transcript is incomplete")
    values = [_parse_json(line, "CLI record", MAX_TRANSCRIPT_BYTES) for line in lines]
    receipt = _require_keys(values[-1], ("outputs", "recordType", "schemaVersion"), "receipt")
    if (
        receipt["recordType"] != "pinned-evidence-receipt"
        or type(receipt["schemaVersion"]) is not int
        or receipt["schemaVersion"] != 1
    ):
        raise SpikeError("receipt is invalid")
    if _canonical_json(receipt) != lines[-1]:
        raise SpikeError("receipt is not canonical")
    events: list[dict[str, object]] = []
    terminal_seen = False
    previous_elapsed = -1
    process_id: int | None = None
    for index, event_value in enumerate(values[:-1]):
        if type(event_value) is not dict:
            raise SpikeError("RuntimeEvent shape is invalid")
        event = event_value
        kind = event.get("kind")
        expected_keys = {
            "started": _EVENT_BASE_KEYS + ("processId",),
            "terminate-requested": _EVENT_BASE_KEYS + ("processId", "message"),
            "timed-out": _EVENT_BASE_KEYS + ("processId", "message"),
            "grace-period-expired": _EVENT_BASE_KEYS + ("processId", "message"),
            "wine-server-stop-requested": _EVENT_BASE_KEYS + ("message",),
            "exited": _EVENT_BASE_KEYS + ("exit",),
        }.get(kind)
        if expected_keys is None or tuple(event) != expected_keys or terminal_seen:
            raise SpikeError("RuntimeEvent order is invalid")
        if (
            event.get("schemaVersion") != "1"
            or event.get("requestId") != "pinned-sumatrapdf"
            or type(event.get("sequence")) is not int
            or not 0 <= event["sequence"] <= 2**64 - 1
            or event.get("sequence") != index
            or type(event.get("elapsedMilliseconds")) is not int
            or not 0 <= event["elapsedMilliseconds"] <= 2**64 - 1
            or event["elapsedMilliseconds"] < previous_elapsed
            or kind not in _EVENT_KINDS
        ):
            raise SpikeError("RuntimeEvent is invalid")
        expected_message = {
            "started": None,
            "terminate-requested": "termination requested",
            "timed-out": "maximum runtime exceeded",
            "grace-period-expired": "graceful termination period expired; forcing process tree shutdown",
            "wine-server-stop-requested": "stopping wineserver",
            "exited": None,
        }[event["kind"]]
        if ("message" in event) != (expected_message is not None) or event.get("message") != expected_message:
            raise SpikeError("RuntimeEvent message changed")
        if index == 0 and event["kind"] != "started":
            raise SpikeError("started RuntimeEvent is missing")
        if index > 0 and event["kind"] == "started":
            raise SpikeError("started RuntimeEvent was repeated")
        if kind == "started":
            if type(event.get("processId")) is not int or not 1 <= event["processId"] <= 2**32 - 1:
                raise SpikeError("started RuntimeEvent process is invalid")
            process_id = event["processId"]  # type: ignore[assignment]
        elif "processId" in event and (
            type(event["processId"]) is not int
            or not 1 <= event["processId"] <= 2**32 - 1
            or event["processId"] != process_id
        ):
            raise SpikeError("RuntimeEvent process identity changed")
        if json.dumps(event, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8") != lines[index]:
            raise SpikeError("RuntimeEvent changed shape")
        previous_elapsed = event["elapsedMilliseconds"]  # type: ignore[assignment]
        if kind == "exited":
            exit_value = event.get("exit")
            if type(exit_value) is not dict or tuple(exit_value) not in (("code", "success"), ("success",)):
                raise SpikeError("terminal RuntimeEvent is invalid")
            if type(exit_value["success"]) is not bool or (
                "code" in exit_value
                and (type(exit_value["code"]) is not int or not -(2**31) <= exit_value["code"] <= 2**31 - 1)
            ):
                raise SpikeError("terminal RuntimeEvent is invalid")
            terminal_seen = True
        events.append(event)
    if not terminal_seen or events[-1]["kind"] != "exited":
        raise SpikeError("terminal RuntimeEvent is missing")
    return [receipt]


def _receipt_outputs(receipt: dict[str, object]) -> list[dict[str, object]]:
    outputs = receipt["outputs"]
    if type(outputs) is not list or len(outputs) != 2:
        raise SpikeError("receipt outputs are invalid")
    result: list[dict[str, object]] = []
    for index, expected_kind in enumerate(("inspection", "plan")):
        output = _require_keys(outputs[index], ("byteLength", "kind", "sha256"), "receipt output")
        if (
            output["kind"] != expected_kind
            or type(output["byteLength"]) is not int
            or not 1 <= output["byteLength"] <= MAX_EVIDENCE_BYTES
            or type(output["sha256"]) is not str
            or _DIGEST.fullmatch(output["sha256"]) is None
        ):
            raise SpikeError("receipt output is invalid")
        result.append(output)
    return result


def _read_published_evidence(
    binding: EvidenceFileBinding,
    receipt: dict[str, object],
    process: object,
    boundary: object,
) -> object:
    if process.poll() is None:
        raise SpikeError("evidence read began while child was live")
    snapshot = boundary.describe_descriptor(binding.descriptor)
    if (
        snapshot.identity != binding.identity
        or snapshot.kind != "regular"
        or snapshot.mode != 0o600
        or snapshot.nlink != 0
        or snapshot.access_mode != os.O_RDWR
        or snapshot.append
        or not snapshot.close_on_exec
        or not 1 <= snapshot.size <= MAX_EVIDENCE_BYTES
        or snapshot.size != receipt["byteLength"]
    ):
        raise SpikeError("published evidence identity is invalid")
    boundary.seek_descriptor(binding.descriptor, 0)
    chunks: list[bytes] = []
    remaining = MAX_EVIDENCE_BYTES + 1
    while remaining:
        chunk = boundary.read_descriptor(binding.descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    after = boundary.describe_descriptor(binding.descriptor)
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    if (
        len(payload) > MAX_EVIDENCE_BYTES
        or after.identity != snapshot.identity
        or after.nlink != 0
        or after.size != snapshot.size
        or after.mode != 0o600
        or after.access_mode != os.O_RDWR
        or after.append
        or not after.close_on_exec
        or len(payload) != receipt["byteLength"]
        or digest != receipt["sha256"]
    ):
        raise SpikeError("published evidence binding disagrees")
    value = _parse_json(payload, "published evidence", MAX_EVIDENCE_BYTES)
    if _canonical_json(value) != payload:
        raise SpikeError("published evidence is not canonical")
    return value


def _close_all(boundary: object, descriptors: list[int]) -> None:
    failed = False
    for descriptor in reversed(descriptors):
        try:
            boundary.close_descriptor(descriptor)
        except OSError:
            failed = True
    if failed:
        raise SpikeError("descriptor cleanup failed")


def run_spike_document(
    manifest_value: dict[str, object],
    boundary: object,
    *,
    additional_bindings: tuple[FileBinding, ...] = (),
) -> list[str]:
    if boundary.platform_name != "Darwin":
        raise SpikeError("spike requires macOS")
    manifest = _validate_manifest(manifest_value)
    bindings, runtimes, forbidden = _bind_manifest_inputs(manifest, boundary)
    for binding in additional_bindings:
        bindings.setdefault(binding.path, binding)
        forbidden.add(binding.path)
    work_roots = _validate_work_roots(runtimes, forbidden, boundary)
    cli_path = manifest["cli"]["path"]  # type: ignore[index]
    completed: list[str] = []
    for runtime, work_path in zip(runtimes, work_roots, strict=True):
        descriptors: list[int] = []
        process: object | None = None
        capture: _BoundedOutputCapture | None = None
        primary_error: BaseException | None = None
        try:
            _require_window_absent(("SumatraPDF",), boundary)
            work_root = boundary.open_work_root(work_path)
            descriptors.append(work_root.descriptor)
            boundary.revalidate_work_root(work_root)
            _validate_work_descriptor(work_root, boundary)
            inspection = boundary.create_anonymous_output(work_root, "inspection")
            descriptors.append(inspection.descriptor)
            _validate_empty_output(inspection, boundary)
            plan = boundary.create_anonymous_output(work_root, "plan")
            descriptors.append(plan.descriptor)
            _validate_empty_output(plan, boundary)
            if len(set(descriptors)) != 3 or inspection.identity == plan.identity:
                raise SpikeError("descriptor aliases are invalid")
            boundary.revalidate_work_root(work_root)

            config_path, _ = _file_reference(runtime["config"], "config")
            logical_path, _ = _file_reference(runtime["logicalExecutable"], "logical executable")
            request_path, _ = _file_reference(runtime["request"], "request")
            pass_fds = tuple(descriptors)
            for binding in bindings.values():
                boundary.revalidate_input(binding)
            argv = (
                cli_path,
                "prepared-pinned-sumatrapdf-launch-terminate",
                config_path,
                logical_path,
                request_path,
                work_path,
                str(work_root.descriptor),
                str(inspection.descriptor),
                str(plan.descriptor),
                str(manifest["timeoutMilliseconds"]),
            )
            process = boundary.spawn(
                argv,
                pass_fds=pass_fds,
                close_fds=True,
                cwd=None,
                env={},
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if tuple(process.inherited_fds) != pass_fds:
                _terminate_process(process)
                raise SpikeError("descriptor inheritance is invalid")
            stdout_stream, stderr_stream = process.take_output_streams()
            capture = _BoundedOutputCapture(stdout_stream, stderr_stream)
            timeout_seconds = manifest["timeoutMilliseconds"] / 1000.0  # type: ignore[operator]
            _observe_window(process, capture, ("SumatraPDF",), timeout_seconds, boundary)
            stdout, stderr = _finish_process_output(
                process,
                capture,
                timeout_seconds + PROCESS_CLEANUP_SECONDS,
                boundary,
            )
            if process.returncode != 0 or stderr != b"" or type(stdout) is not bytes:
                raise SpikeError("CLI process failed")
            receipt = _parse_transcript(
                stdout,
                tuple(forbidden) + tuple(work_roots) + tuple(f'"{descriptor}"' for descriptor in descriptors),
            )[0]
            outputs = _receipt_outputs(receipt)
            boundary.revalidate_work_root(work_root)
            _read_published_evidence(inspection, outputs[0], process, boundary)
            boundary.revalidate_work_root(work_root)
            _read_published_evidence(plan, outputs[1], process, boundary)
            boundary.revalidate_work_root(work_root)
            for binding in bindings.values():
                boundary.revalidate_input(binding)
            completed.append(runtime["runtimeId"])  # type: ignore[arg-type]
        except BaseException as error:
            primary_error = error
            if process is not None and process.poll() is None:
                try:
                    _terminate_process(process)
                except SpikeError:
                    primary_error = SpikeError("child cleanup failed")
            if capture is not None:
                try:
                    capture.cleanup(PROCESS_CLEANUP_SECONDS)
                except SpikeError:
                    primary_error = SpikeError("child cleanup failed")
        if process is not None:
            try:
                _require_window_absent(("SumatraPDF",), boundary)
            except SpikeError as error:
                primary_error = error
        try:
            _close_all(boundary, descriptors)
        except SpikeError as error:
            primary_error = error
        if primary_error is not None:
            if isinstance(primary_error, SpikeError):
                raise primary_error
            raise SpikeError("spike execution failed") from None
    return completed


class _SystemProcess:
    def __init__(self, process: subprocess.Popen[bytes], inherited_fds: tuple[int, ...]) -> None:
        self._process = process
        self.inherited_fds = inherited_fds

    @property
    def returncode(self) -> int | None:
        return self._process.returncode

    def poll(self) -> int | None:
        return self._process.poll()

    def take_output_streams(self) -> tuple[object, object]:
        if self._process.stdout is None or self._process.stderr is None:
            raise SpikeError("CLI output pipes are unavailable")
        return self._process.stdout, self._process.stderr

    def terminate(self) -> None:
        self._process.terminate()

    def kill(self) -> None:
        self._process.kill()

    def wait(self, timeout: float | None = None) -> int:
        return self._process.wait(timeout=timeout)


class SystemBoundary:
    platform_name = platform.system()
    repository_root = str(Path(__file__).resolve().parents[1])

    def __init__(self) -> None:
        if self.platform_name != "Darwin":
            raise SpikeError("spike requires macOS")
        import fcntl

        self._fcntl = fcntl

    def resolve_canonical(self, path: str, *, directory: bool) -> str:
        closed = _closed_absolute_path(path, "path")
        try:
            candidate = Path(closed)
            resolved = str(candidate.resolve(strict=True))
            metadata = candidate.lstat()
        except OSError as error:
            raise SpikeError("reviewed path is unavailable") from error
        if resolved != closed or stat.S_ISLNK(metadata.st_mode):
            raise SpikeError("reviewed path is not canonical")
        if directory and not stat.S_ISDIR(metadata.st_mode):
            raise SpikeError("reviewed directory is invalid")
        if not directory and not stat.S_ISREG(metadata.st_mode):
            raise SpikeError("reviewed file is invalid")
        return resolved

    @staticmethod
    def paths_physically_overlap(left: str, right: str) -> bool:
        if _paths_overlap(left, right):
            return True
        left_path = Path(left)
        right_path = Path(right)
        try:
            if os.path.samefile(left_path, right_path):
                return True
            if any(os.path.samefile(parent, right_path) for parent in left_path.parents):
                return True
            return any(os.path.samefile(left_path, parent) for parent in right_path.parents)
        except OSError:
            return False

    def _read_bound_file(self, path: str, expected_sha256: str | None) -> FileBinding:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        descriptor: int | None = None
        try:
            entry = os.lstat(path)
            if (
                not stat.S_ISREG(entry.st_mode)
                or stat.S_ISLNK(entry.st_mode)
                or entry.st_nlink != 1
                or not 1 <= entry.st_size <= MAX_INPUT_BYTES
                or entry.st_uid != os.geteuid()
            ):
                raise SpikeError("reviewed input is invalid")
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            identity = (opened.st_dev, opened.st_ino)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or identity != (entry.st_dev, entry.st_ino)
                or opened.st_size != entry.st_size
                or opened.st_mtime_ns != entry.st_mtime_ns
                or opened.st_ctime_ns != entry.st_ctime_ns
                or opened.st_uid != os.geteuid()
            ):
                raise SpikeError("reviewed input identity changed")
            chunks: list[bytes] = []
            remaining = opened.st_size + 1
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            current = os.fstat(descriptor)
            current_entry = os.lstat(path)
            digest = "sha256:" + hashlib.sha256(payload).hexdigest()
            if (
                len(payload) != opened.st_size
                or (current.st_dev, current.st_ino) != identity
                or (current_entry.st_dev, current_entry.st_ino) != identity
                or current.st_size != opened.st_size
                or current_entry.st_size != opened.st_size
                or current.st_mtime_ns != opened.st_mtime_ns
                or current_entry.st_mtime_ns != opened.st_mtime_ns
                or current.st_ctime_ns != opened.st_ctime_ns
                or current_entry.st_ctime_ns != opened.st_ctime_ns
                or current.st_nlink != 1
                or current_entry.st_nlink != 1
                or (expected_sha256 is not None and digest != expected_sha256)
            ):
                raise SpikeError("reviewed input binding disagrees")
            return FileBinding(
                path=path,
                identity=identity,
                size=opened.st_size,
                mtime_ns=opened.st_mtime_ns,
                ctime_ns=opened.st_ctime_ns,
                owner=opened.st_uid,
                sha256=digest,
                payload=payload,
            )
        except SpikeError:
            raise
        except OSError as error:
            raise SpikeError("reviewed input could not be read") from error
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as error:
                    raise SpikeError("reviewed input close failed") from error

    def bind_manifest(self, path: str) -> FileBinding:
        return self._read_bound_file(path, None)

    def bind_input(self, path: str, expected_sha256: str, label: str) -> FileBinding:
        binding = self._read_bound_file(path, expected_sha256)
        if label == "CLI":
            try:
                mode = os.stat(path, follow_symlinks=False).st_mode
            except OSError as error:
                raise SpikeError("CLI artifact is invalid") from error
            if mode & 0o111 == 0:
                raise SpikeError("CLI artifact is invalid")
        return binding

    def revalidate_input(self, binding: FileBinding) -> None:
        current = self._read_bound_file(binding.path, binding.sha256)
        if current != binding:
            raise SpikeError("reviewed input identity changed")

    def open_work_root(self, path: str) -> WorkRootBinding:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
        try:
            descriptor = os.open(path, flags)
            entry = os.lstat(path)
            opened = os.fstat(descriptor)
            identity = (opened.st_dev, opened.st_ino)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or identity != (entry.st_dev, entry.st_ino)
                or opened.st_uid != os.geteuid()
            ):
                os.close(descriptor)
                raise SpikeError("work root identity is invalid")
            return WorkRootBinding(path=path, descriptor=descriptor, identity=identity)
        except SpikeError:
            raise
        except OSError as error:
            raise SpikeError("work root could not be held") from error

    def revalidate_work_root(self, binding: WorkRootBinding) -> None:
        try:
            entry = os.lstat(binding.path)
            opened = os.fstat(binding.descriptor)
            if (
                not stat.S_ISDIR(entry.st_mode)
                or stat.S_ISLNK(entry.st_mode)
                or (entry.st_dev, entry.st_ino) != binding.identity
                or (opened.st_dev, opened.st_ino) != binding.identity
                or opened.st_uid != os.geteuid()
            ):
                raise SpikeError("work root identity changed")
        except SpikeError:
            raise
        except OSError as error:
            raise SpikeError("work root identity changed") from error

    def create_anonymous_output(self, work_root: WorkRootBinding, kind: str) -> EvidenceFileBinding:
        del kind
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        for _attempt in range(OUTPUT_NAME_ATTEMPTS):
            name = ".compatforge-pinned-output-" + secrets.token_hex(16)
            descriptor: int | None = None
            linked = False
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=work_root.descriptor)
                linked = True
                before = os.fstat(descriptor)
                identity = (before.st_dev, before.st_ino)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or before.st_nlink != 1
                    or before.st_size != 0
                    or before.st_uid != os.geteuid()
                ):
                    raise SpikeError("evidence file creation failed")
                os.unlink(name, dir_fd=work_root.descriptor)
                linked = False
                after = os.fstat(descriptor)
                if (
                    (after.st_dev, after.st_ino) != identity
                    or after.st_nlink != 0
                    or after.st_size != 0
                ):
                    raise SpikeError("evidence file unlink failed")
                return EvidenceFileBinding(descriptor=descriptor, identity=identity)
            except FileExistsError:
                continue
            except SpikeError:
                if descriptor is not None:
                    os.close(descriptor)
                raise
            except OSError as error:
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                raise SpikeError("evidence file creation failed") from error
            finally:
                if linked:
                    try:
                        os.unlink(name, dir_fd=work_root.descriptor)
                    except OSError:
                        pass
        raise SpikeError("evidence file collision bound exhausted")

    def describe_descriptor(self, descriptor: int) -> DescriptorSnapshot:
        try:
            metadata = os.fstat(descriptor)
            status_flags = self._fcntl.fcntl(descriptor, self._fcntl.F_GETFL)
            descriptor_flags = self._fcntl.fcntl(descriptor, self._fcntl.F_GETFD)
        except OSError as error:
            raise SpikeError("descriptor validation failed") from error
        kind = "directory" if stat.S_ISDIR(metadata.st_mode) else "regular" if stat.S_ISREG(metadata.st_mode) else "other"
        return DescriptorSnapshot(
            identity=(metadata.st_dev, metadata.st_ino),
            kind=kind,
            mode=stat.S_IMODE(metadata.st_mode),
            nlink=metadata.st_nlink,
            size=metadata.st_size,
            access_mode=status_flags & os.O_ACCMODE,
            append=bool(status_flags & os.O_APPEND),
            close_on_exec=bool(descriptor_flags & self._fcntl.FD_CLOEXEC),
        )

    def spawn(
        self,
        argv: tuple[str, ...],
        *,
        pass_fds: tuple[int, ...],
        **options: object,
    ) -> _SystemProcess:
        try:
            process = subprocess.Popen(list(argv), pass_fds=pass_fds, **options)
        except OSError as error:
            raise SpikeError("CLI process could not start") from error
        return _SystemProcess(process, pass_fds)

    def probe_window(self, tokens: tuple[str, ...]) -> WindowProbeState:
        script = (
            'tell application "System Events"\n'
            "set resultText to {}\n"
            "repeat with p in (every application process whose background only is false)\n"
            "repeat with w in (every window of p)\n"
            "set t to title of w\n"
            'if t is not missing value and t is not "" then set end of resultText to (t as text)\n'
            "end repeat\n"
            "end repeat\n"
            "set AppleScript's text item delimiters to linefeed\n"
            "return resultText as text\n"
            "end tell"
        )
        def spawn() -> _SystemProcess:
            process = subprocess.Popen(
                ["/usr/bin/osascript", "-e", script],
                close_fds=True,
                cwd=None,
                env={},
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return _SystemProcess(process, ())

        return _run_window_probe(spawn, tokens)

    @staticmethod
    def sleep(seconds: float) -> None:
        time.sleep(seconds)

    @staticmethod
    def monotonic() -> float:
        return time.monotonic()

    @staticmethod
    def seek_descriptor(descriptor: int, offset: int) -> None:
        os.lseek(descriptor, offset, os.SEEK_SET)

    @staticmethod
    def read_descriptor(descriptor: int, maximum: int) -> bytes:
        return os.read(descriptor, maximum)

    @staticmethod
    def close_descriptor(descriptor: int) -> None:
        os.close(descriptor)


def run_manifest(path: str) -> list[str]:
    if platform.system() != "Darwin":
        raise SpikeError("spike requires macOS")
    boundary = SystemBoundary()
    manifest_path = _closed_absolute_path(path, "manifest")
    if boundary.resolve_canonical(manifest_path, directory=False) != manifest_path:
        raise SpikeError("manifest path is not canonical")
    if _paths_overlap(manifest_path, boundary.repository_root):
        raise SpikeError("manifest must be repository-external")
    manifest_binding = boundary.bind_manifest(manifest_path)
    manifest = parse_manifest_bytes(manifest_binding.payload)
    return run_spike_document(manifest, boundary, additional_bindings=(manifest_binding,))


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        if len(arguments) != 2 or arguments[0] != "--manifest":
            raise SpikeError("arguments are invalid")
        completed = run_manifest(arguments[1])
        output = _canonical_json({"runtimes": completed, "schemaVersion": 1}) + b"\n"
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
        return 0
    except SpikeError:
        sys.stderr.write("compatforge pinned macOS CLI spike failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
