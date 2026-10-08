"""Explicit, fixed-fixture Linux Console Preview runner (not a sandbox)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
import hashlib
import base64
from pathlib import Path, PurePosixPath
import os
import json
import math
import selectors
import signal
import subprocess
import sys
import time
import platform as host_platform
import re
import stat
from typing import Mapping, Protocol, Sequence

BOTTLE_ID = "linux-console-preview"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class PlatformView(Protocol):
    def os_name(self) -> str: ...
    def machine(self) -> str: ...
    def current_uid(self) -> int: ...


class CommandRecorder(Protocol):
    def record(self, argv: Sequence[str], environment: Mapping[str, str]) -> None: ...


@dataclass(frozen=True)
class PathFacts:
    exists: bool
    kind: str = "missing"
    mode: int = 0
    uid: int = -1
    symlink: bool = False
    identity: tuple[int, int] | None = None


@dataclass(frozen=True)
class PhysicalAncestor:
    lexical: Path
    physical: Path
    identity: tuple[int, int]
    missing_parts: tuple[str, ...]

    @property
    def destination(self) -> Path:
        return self.physical.joinpath(*self.missing_parts)


class FileSystemView(Protocol):
    repository_root: Path
    def inspect(self, path: Path) -> PathFacts: ...
    def nearest_existing_ancestor(self, path: Path) -> PhysicalAncestor: ...
    def mkdir_exclusive(self, path: Path) -> tuple[int, int]: ...
    def remove_owned_empty_directory(self, path: Path, identity: tuple[int, int]) -> None: ...


class NativePlatform:
    def os_name(self) -> str:
        return host_platform.system()

    def machine(self) -> str:
        return host_platform.machine()

    def current_uid(self) -> int:
        return os.getuid()


class NativeFileSystem:
    repository_root = REPOSITORY_ROOT

    def inspect(self, path: Path) -> PathFacts:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return PathFacts(False)
        kind = ("file" if stat.S_ISREG(info.st_mode) else
                "directory" if stat.S_ISDIR(info.st_mode) else "other")
        return PathFacts(True, kind, stat.S_IMODE(info.st_mode), info.st_uid,
                         stat.S_ISLNK(info.st_mode) or path.resolve() != path,
                         (info.st_dev, info.st_ino))

    def nearest_existing_ancestor(self, path: Path) -> PhysicalAncestor:
        ancestor = path
        missing = []
        while not self.inspect(ancestor).exists:
            if ancestor.parent == ancestor:
                raise ValueError("missing-filesystem-anchor")
            missing.insert(0, ancestor.name)
            ancestor = ancestor.parent
        physical = ancestor.resolve(strict=True)
        info = physical.stat()
        if missing and not stat.S_ISDIR(info.st_mode):
            raise ValueError("ancestor-not-directory")
        return PhysicalAncestor(ancestor, physical, (info.st_dev, info.st_ino), tuple(missing))

    def mkdir_exclusive(self, path: Path) -> tuple[int, int]:
        path.mkdir(mode=0o700)
        info = path.lstat()
        return info.st_dev, info.st_ino

    def remove_owned_empty_directory(self, path: Path, identity: tuple[int, int]) -> None:
        facts = self.inspect(path)
        if facts.exists and not facts.symlink and facts.identity == identity:
            try:
                path.rmdir()
            except OSError:
                # Never recurse into product/caller data during setup rollback.
                pass

    def verify_private_file(self, path, identity):
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                             getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != identity
                    or self.inspect(path).identity != identity
                    or (sys.platform == "linux" and (info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600))):
                raise ValueError("nonprivate-compiler-output")
        finally:
            os.close(descriptor)
        getattr(self, "record_io", lambda *args: None)("private-mode", path)


@dataclass(frozen=True)
class RunnerInputs:
    cli: Path
    compiler: Path
    runtime_store_root: Path
    storage_root: Path
    materialized_root: Path
    evidence_root: Path
    wine_relative: PurePosixPath
    wineserver_relative: PurePosixPath
    declared_version: str


def _absolute(value: str) -> Path:
    path = Path(value)
    # Validate spelling before Path discards empty and dot components. Windows
    # paths are supported only for injected, non-executing portable tests.
    spelling = value.replace("\\", "/") if path.drive else value
    components = spelling[len(path.anchor.replace("\\", "/")):].split("/")
    if (not path.is_absolute() or path == Path(path.anchor)
            or any(c in value for c in "\0\r\n")
            or (not path.drive and any(c in value for c in "\\:"))
            or len(value) > 4096 or any(p in ("", ".", "..") for p in components)):
        raise ValueError("invalid-absolute-path")
    return path


def _relative(value: str) -> PurePosixPath:
    if (not value or len(value) > 1024 or any(c in value for c in "\\:\0\r\n")
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError("invalid-relative-entrypoint")
    return PurePosixPath(value)


def parse_closed_args(argv: Sequence[str]) -> RunnerInputs:
    flags = ("--cli", "--compiler", "--runtime-store-root", "--storage-root",
             "--materialized-root", "--evidence-root", "--wine", "--wineserver",
             "--version")
    if len(argv) != len(flags) * 2:
        raise ValueError("required-flags-exactly-once")
    values = {}
    for flag, value in zip(argv[::2], argv[1::2]):
        if flag not in flags or flag in values:
            raise ValueError("unknown-or-duplicate-flag")
        values[flag] = value
    version = values["--version"]
    if re.fullmatch(r"[0-9][A-Za-z0-9.+_-]{0,127}", version) is None:
        raise ValueError("invalid-version")
    return RunnerInputs(*(_absolute(values[flag]) for flag in flags[:6]),
                        _relative(values["--wine"]),
                        _relative(values["--wineserver"]), version)


@dataclass(frozen=True)
class PreflightResult:
    inputs: RunnerInputs
    roots: tuple[Path, ...]
    ancestors: tuple[PhysicalAncestor, ...] = ()


def _require_private(facts: PathFacts, kind: str, uid: int, executable=False):
    if (not facts.exists or facts.kind != kind or facts.symlink or facts.uid not in (0, uid)
            or facts.mode & 0o022 or (executable and not facts.mode & 0o111)):
        raise ValueError("unsafe-input-file-or-directory")


def _reject_overlaps(paths: Sequence[Path]) -> None:
    for index, left in enumerate(paths):
        for right in paths[index + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise ValueError("overlapping-roots")


def preflight(inputs: RunnerInputs, platform: PlatformView,
              filesystem: FileSystemView) -> PreflightResult:
    if platform.os_name() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("unsupported-host")
    for value in (inputs.cli, inputs.compiler, inputs.runtime_store_root,
                  inputs.storage_root, inputs.materialized_root, inputs.evidence_root):
        _absolute(str(value))
    _relative(str(inputs.wine_relative))
    _relative(str(inputs.wineserver_relative))
    if re.fullmatch(r"[0-9][A-Za-z0-9.+_-]{0,127}", inputs.declared_version) is None:
        raise ValueError("invalid-version")
    _require_private(filesystem.inspect(inputs.materialized_root), "directory",
                     platform.current_uid())
    for path in (inputs.cli, inputs.compiler,
                 inputs.materialized_root / inputs.wine_relative,
                 inputs.materialized_root / inputs.wineserver_relative):
        _require_private(filesystem.inspect(path), "file", platform.current_uid(), True)
    roots = (inputs.runtime_store_root, inputs.storage_root, inputs.evidence_root)
    _reject_overlaps((filesystem.repository_root, *roots, inputs.materialized_root))
    for path in (*roots, inputs.storage_root / "bottles" / BOTTLE_ID / "prefix"):
        if filesystem.inspect(path).exists:
            raise ValueError("destination-already-exists")
    all_paths = (filesystem.repository_root, *roots, inputs.materialized_root)
    physical = tuple(filesystem.nearest_existing_ancestor(path) for path in all_paths)
    _reject_overlaps(tuple(ancestor.destination for ancestor in physical))
    return PreflightResult(inputs, roots, physical[1:4])


@dataclass(frozen=True)
class CreatedRoots:
    roots: tuple[Path, ...]
    owned_directories: tuple[tuple[Path, tuple[int, int]], ...]

    def rollback_empty(self, filesystem: FileSystemView) -> None:
        for path, identity in reversed(self.owned_directories):
            filesystem.remove_owned_empty_directory(path, identity)


def create_exclusive_roots(preflight: PreflightResult,
                           filesystem: FileSystemView) -> CreatedRoots:
    for root, snapshot in zip(preflight.roots, preflight.ancestors):
        if filesystem.nearest_existing_ancestor(root) != snapshot:
            raise ValueError("ancestor-changed-after-preflight")
        if filesystem.inspect(root).exists:
            raise ValueError("destination-already-exists")
    owned = []
    try:
        for snapshot in preflight.ancestors:
            current = snapshot.physical
            for part in snapshot.missing_parts:
                current = current / part
                if current not in (p for p, _ in owned):
                    owned.append((current, filesystem.mkdir_exclusive(current)))
        return CreatedRoots(tuple(a.destination for a in preflight.ancestors), tuple(owned))
    except BaseException:
        CreatedRoots((), tuple(owned)).rollback_empty(filesystem)
        raise


JSON_LIMIT = 1024 * 1024
PRIVATE_NAMES = frozenset({"private-context.json", "bootstrap-request.json",
                          "bootstrap-context.json",
                          "console-preview.exe",
                          "bootstrap-receipt.json", "request.json", "inspection.json",
                          "pre-plan.json", "post-plan.json", "events.jsonl",
                          "command-diagnostics.json", "run-start.json", "failure.json",
                          "public-summary.json"})


class EvidenceStore:
    """Own exclusive private artifacts and the marker/finalizer transaction.

    The finalizer is injected by Task 13; this foundation never claims inner
    Wine/Guest cleanup or publishes a public success summary.
    """

    def __init__(self, root: Path, *, created_roots: CreatedRoots | None = None,
                 filesystem: FileSystemView | None = None):
        if not root.is_absolute() or root.resolve(strict=True) != root or not root.is_dir():
            raise ValueError("unsafe-evidence-root")
        self.root = root
        self.root_identity = self._identity(root)
        if sys.platform == "linux":
            info = root.stat()
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("nonprivate-evidence-root")
        self.created_roots = created_roots
        self.filesystem = filesystem or NativeFileSystem()
        self.owned_files = {}
        self.started = False

    @staticmethod
    def _identity(path):
        info = path.lstat()
        return info.st_dev, info.st_ino

    def _path(self, name):
        if name not in PRIVATE_NAMES:
            raise ValueError("unknown-private-evidence-name")
        if (self.root.resolve(strict=True) != self.root
                or self._identity(self.root) != self.root_identity):
            raise ValueError("evidence-root-changed")
        return self.root / name

    def _remove_owned(self, path, identity):
        try:
            if self._identity(path) == identity and not path.is_symlink():
                path.unlink()
        except FileNotFoundError:
            pass

    def write_json(self, name, value):
        if name in ("run-start.json", "public-summary.json"):
            raise ValueError("run-start-requires-fixed-cleanup-inputs")
        return self._write_json(name, value)

    def _write_json(self, name, value, *, mark_started=False):
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"
        if len(payload) > JSON_LIMIT:
            raise ValueError("json-size-limit")
        return self._write_payload(name, payload, mark_started=mark_started)

    def _write_payload(self, name, payload, *, mark_started=False):
        if len(payload) > JSON_LIMIT:
            raise ValueError("evidence-size-limit")
        path = self._path(name)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0), 0o600)
        identity = None
        try:
            info = os.fstat(descriptor)
            identity = info.st_dev, info.st_ino
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short-evidence-write")
                remaining = remaining[written:]
            # os.write is unbuffered; fsync is the completion boundary.
            os.fsync(descriptor)
            if mark_started:
                # A later close error cannot undo the durable start boundary.
                self.started = True
        except BaseException:
            try:
                os.close(descriptor)
            finally:
                if identity is not None:
                    self._remove_owned(path, identity)
            raise
        else:
            self.owned_files[path] = identity
            try:
                os.close(descriptor)
            except BaseException:
                if not mark_started:
                    self._remove_owned(path, identity)
                raise
        getattr(self.filesystem, "record_io", lambda *args: None)("write", path)
        return path

    def read_json(self, name, limit=JSON_LIMIT):
        if not 0 < limit <= JSON_LIMIT:
            raise ValueError("invalid-json-limit")
        path = self._path(name)
        if path.is_symlink():
            raise ValueError("symlink-evidence")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                             getattr(os, "O_NONBLOCK", 0) |
                             getattr(os, "O_BINARY", 0))
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValueError("nonregular-evidence")
            payload = handle.read(limit + 1)
        if len(payload) > limit:
            raise ValueError("json-size-limit")
        return _json(payload)

    def rollback_setup(self):
        if self.started:
            raise ValueError("cannot-rollback-started-run")
        for path, identity in self.owned_files.items():
            self._remove_owned(path, identity)
        self.owned_files.clear()
        if self.created_roots is not None:
            self.created_roots.rollback_empty(self.filesystem)

    def run_product(self, context, prefix, wineserver_digest, product, finalizer):
        if self.started:
            raise ValueError("run-already-started")
        failure = None
        try:
            if context != self.root / "private-context.json":
                raise ValueError("fixed-context-required")
            self.read_json("private-context.json")
            if (not prefix.is_absolute() or prefix.resolve() != prefix
                    or re.fullmatch(r"sha256:[0-9a-f]{64}", wineserver_digest) is None):
                raise ValueError("fixed-cleanup-inputs-required")
            self._write_json("run-start.json", {"schemaVersion": "1",
                            "context": str(context), "prefix": str(prefix),
                            "wineserverDigest": wineserver_digest}, mark_started=True)
        except BaseException as error:
            if not self.started:
                self.rollback_setup()
                raise
            failure = error
        result = None
        reason = "execution"
        try:
            if failure is None:
                result = product()
            if isinstance(result, CommandResult) and result.return_code != 0:
                raise CommandFailure("nonzero-exit", result.stdout, result.stderr,
                                     result.outer_pid, result.outer_process_group_id,
                                     OuterCleanupStatus("Complete", "none"))
        except BaseException as error:
            failure = error
        finally:
            try:
                finalizer(failure is not None)
            except BaseException as error:
                failure = error
                reason = "cleanup"
        if failure is not None:
            # Never serialize exception messages, paths, argv or environments.
            self.write_json("failure.json", {"schemaVersion": "1", "reason": reason})
            raise failure
        return result


@dataclass(frozen=True)
class CommandSpec:
    argv: Sequence[str]
    environment: Mapping[str, str]
    cwd: Path
    output_limit_bytes: int
    deadline: float
    creation_umask: int | None = None


@dataclass(frozen=True)
class OuterCleanupStatus:
    state: str
    stage: str

    def __post_init__(self):
        if self.state not in ("Complete", "Failed", "TimedOut"):
            raise ValueError("invalid-outer-cleanup-state")
        if self.stage not in ("none", "kill", "reap", "group", "start", "close"):
            raise ValueError("invalid-outer-cleanup-stage")


@dataclass(frozen=True)
class CommandResult:
    return_code: int
    stdout: bytes
    stderr: bytes
    outer_pid: int
    outer_process_group_id: int


class CommandFailure(RuntimeError):
    def __init__(self, reason, partial_stdout, partial_stderr, outer_pid,
                 outer_process_group_id, outer_cleanup_status):
        super().__init__(reason)
        self.reason = reason
        self.partial_stdout = partial_stdout
        self.partial_stderr = partial_stderr
        self.outer_pid = outer_pid
        self.outer_process_group_id = outer_process_group_id
        self.outer_cleanup_status = outer_cleanup_status


class CommandStreamObserver(Protocol):
    def on_chunk(self, stream: str, chunk: bytes) -> None: ...


@dataclass(frozen=True)
class CommandAction:
    kind: str
    stream: str = ""
    size: int = 0


class CommandStateMachine:
    def __init__(self, spec, running, execution_deadline):
        self.spec = spec
        self.running = running
        self.execution_deadline = execution_deadline
        self.buffers = {"stdout": bytearray(), "stderr": bytearray()}
        self.eof = set()
        self.reason = None
        self.outer_cleanup_status = OuterCleanupStatus("Failed", "reap")

    @property
    def remaining(self):
        return self.spec.output_limit_bytes - sum(map(len, self.buffers.values()))

    def step(self, readiness, now):
        if now >= self.execution_deadline:
            self.reason = "timeout"
            return []
        return [CommandAction("read", stream, min(65536, self.remaining + 1))
                for stream in readiness if stream not in self.eof]

    def consume(self, stream, chunk):
        if chunk is None:
            return b""  # EAGAIN: no bytes and no EOF were observed.
        if not chunk:
            self.eof.add(stream)
        accepted = chunk[:self.remaining]
        self.buffers[stream].extend(accepted)
        if len(accepted) != len(chunk):
            self.reason = "output-limit"
        return accepted

    def finish(self, return_code):
        if self.reason is not None or self.outer_cleanup_status.state != "Complete":
            raise CommandFailure(self.reason or "outer-cleanup", bytes(self.buffers["stdout"]),
                                 bytes(self.buffers["stderr"]), self.running.pid,
                                 self.running.process_group_id, self.outer_cleanup_status)
        return CommandResult(return_code, bytes(self.buffers["stdout"]),
                             bytes(self.buffers["stderr"]), self.running.pid,
                             self.running.process_group_id)


def run_bounded(spec, adapter, observer, clock):
    start = clock()
    if (not spec.argv or isinstance(spec.argv, (str, bytes))
            or not Path(spec.argv[0]).is_absolute()
            or any(not isinstance(arg, str) or "\0" in arg for arg in spec.argv)
            or not isinstance(spec.environment, Mapping)
            or any(not isinstance(key, str) or not isinstance(value, str)
                   or not key or "=" in key or "\0" in key + value
                   for key, value in spec.environment.items())
            or not spec.cwd.is_absolute() or not 0 < spec.output_limit_bytes <= JSON_LIMIT
            or getattr(spec, "creation_umask", None) not in (None, 0o177)
            or not math.isfinite(spec.deadline) or spec.deadline <= start):
        raise ValueError("invalid-command-spec")
    try:
        running = adapter.start(spec)
    except BaseException as error:
        if isinstance(error, CommandFailure):
            raise
        raise CommandFailure("start", b"", b"", None, None,
                             OuterCleanupStatus("Failed", "start")) from None
    # Reserve part of the SAME absolute budget for outer kill/reap. No failure
    # path gets a new deadline; inner product cleanup is a different transaction.
    execution_deadline = spec.deadline - min(1.0, max(0, spec.deadline - start) / 4)
    machine = CommandStateMachine(spec, running, execution_deadline)
    while not machine.reason:
        try:
            if machine.eof == {"stdout", "stderr"} and adapter.exited(running):
                break
            readiness = adapter.readiness(running, min(0.01, max(0, execution_deadline - clock())))
        except BaseException:
            machine.reason = "read"
            break
        for action in machine.step(readiness, clock()):
            try:
                # Earlier ready streams may have consumed the shared budget
                # since step() built this batch. Bound each actual read afresh.
                action = CommandAction(action.kind, action.stream,
                                       min(action.size, machine.remaining + 1))
                accepted = machine.consume(action.stream, adapter.apply(action, running))
            except BaseException:
                machine.reason = "read"
                break
            if observer is not None and accepted:
                try:
                    observer.on_chunk(action.stream, accepted)
                except BaseException:
                    machine.reason = "observer"
            if machine.reason:
                break
    status = None
    code = None
    try:
        adapter.apply(CommandAction("kill"), running)
    except BaseException:
        status = OuterCleanupStatus("Failed", "kill")
    for stage in ("reap", "group"):
        completed = False
        while clock() < spec.deadline:
            try:
                value = adapter.apply(CommandAction(stage), running)
            except BaseException:
                status = status or OuterCleanupStatus("Failed", stage)
                break
            if (stage == "reap" and value is not None) or (stage == "group" and value is False):
                completed = True
                if stage == "reap":
                    code = value
                break
            # Cleanup must not depend on a selector/readiness channel that may
            # have caused the command failure. Use an independent bounded pause
            # (injectable with the clock), retaining the same absolute deadline.
            try:
                pause = getattr(clock, "pause", time.sleep)
                pause(min(0.01, max(0, spec.deadline - clock())))
            except BaseException:
                status = status or OuterCleanupStatus("Failed", stage)
                break
        if not completed:
            status = status or OuterCleanupStatus("TimedOut", stage)
    machine.outer_cleanup_status = status or OuterCleanupStatus("Complete", "none")
    try:
        adapter.close(running)
    except BaseException:
        machine.outer_cleanup_status = OuterCleanupStatus("Failed", "close")
    return machine.finish(code)


@dataclass
class RunningCommand:
    process: subprocess.Popen
    selector: selectors.BaseSelector
    pid: int
    process_group_id: int
    reaped: bool = False
    return_code: int | None = None


class LinuxCommandAdapter:
    """Own one unreaped session leader; never signal a saved, reaped PGID."""

    def start(self, spec: CommandSpec) -> RunningCommand:
        if sys.platform != "linux":
            raise ValueError("linux-command-adapter-requires-linux")
        selector = selectors.DefaultSelector()
        try:
            process = subprocess.Popen(list(spec.argv), cwd=spec.cwd,
                                       env=dict(spec.environment), stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True, close_fds=True, bufsize=0,
                                       umask=spec.creation_umask if spec.creation_umask is not None else -1)
        except BaseException:
            selector.close()
            raise
        running = RunningCommand(process, selector, process.pid, process.pid)
        # Registration belongs to the running transaction: its failure must be
        # routed through run_bounded's kill/reap, not escape after spawning.
        return running

    def readiness(self, running: RunningCommand, timeout: float):
        if not getattr(running, "registered", False):
            for stream in ("stdout", "stderr"):
                pipe = getattr(running.process, stream)
                os.set_blocking(pipe.fileno(), False)
                running.selector.register(pipe, selectors.EVENT_READ, stream)
            running.registered = True
        return [key.data for key, _ in running.selector.select(timeout)]

    def exited(self, running: RunningCommand):
        # WNOWAIT preserves ownership until the final signal has been sent.
        return os.waitid(os.P_PID, running.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

    def apply(self, action: CommandAction, running: RunningCommand):
        if action.kind == "read":
            pipe = getattr(running.process, action.stream)
            try:
                chunk = os.read(pipe.fileno(), action.size)
            except BlockingIOError:
                return None
            if not chunk:
                running.selector.unregister(pipe)
            return chunk
        if action.kind == "kill":
            if running.reaped:
                raise ValueError("cannot-signal-reaped-outer-group")
            try:
                os.killpg(running.process_group_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif action.kind == "reap":
            if not running.reaped:
                pid, status = os.waitpid(running.pid, os.WNOHANG)
                if not pid:
                    return None
                running.return_code = os.waitstatus_to_exitcode(status)
                running.process.returncode = running.return_code
                running.reaped = True
            return running.return_code
        elif action.kind == "group":
            try:
                os.killpg(running.process_group_id, 0)
                return True
            except ProcessLookupError:
                return False
        else:
            raise ValueError("unknown-command-action")

    def close(self, running: RunningCommand):
        running.selector.close()
        running.process.stdout.close()
        running.process.stderr.close()


REQUEST_ID = "d58f7e4e-2a78-4c94-9862-12a5e8ac0913"
PACK_ID = "wine-linux-x86-64-local-preview"
PROVIDER_ID = "wine-linux-x86-64-preview"
CONSOLE_MARKER = "COMPATFORGE_WINDOWS_CONSOLE_OK\n"
OVERALL_SECONDS = 300.0
CLEANUP_SECONDS = 45.0


class ClosedCommandKind(Enum):
    PROC_OBSERVER_SELF_TEST = auto()
    COMPILE_GUEST = auto()
    INSPECT_GUEST = auto()
    BOOTSTRAP_CONTEXT = auto()
    PREPARED_PLAN_PRE = auto()
    PREPARED_LAUNCH = auto()
    PREPARED_PLAN_POST = auto()
    WINESERVER_VERSION = auto()
    WINESERVER_KILL = auto()
    WINESERVER_WAIT = auto()


@dataclass(frozen=True)
class EvidencePaths:
    root: Path

    @property
    def bootstrap_context(self): return self.root / "bootstrap-context.json"
    @property
    def execution_context(self): return self.root / "private-context.json"
    @property
    def launch_request(self): return self.root / "request.json"
    @property
    def pre_plan(self): return self.root / "pre-plan.json"
    @property
    def events(self): return self.root / "events.jsonl"
    @property
    def post_plan(self): return self.root / "post-plan.json"
    @property
    def private_failure(self): return self.root / "failure.json"
    @property
    def public_summary(self): return self.root / "public-summary.json"
    @property
    def guest(self): return self.root / "console-preview.exe"


class PreviewFailure(ValueError):
    def __init__(self, category):
        if category not in {"contract", "integrity", "unsupported-host", "test-infrastructure", "execution", "cleanup"}:
            raise ValueError("unknown-failure-category")
        self.category = category
        super().__init__(category)


@dataclass(frozen=True)
class Verified:
    pid: int
    uid: int
    start_time_ticks: int
    canonical_prefix: Path


@dataclass(frozen=True)
class ExitedBeforeSnapshot:
    pid: int


StartedProcessObservation = Verified | ExitedBeforeSnapshot


@dataclass(frozen=True)
class FinalizerOutcome:
    outer_cleanup: bool
    inner_group_cleanup: bool
    wineserver_cleanup: bool
    prefix_observation: bool

    @property
    def complete(self):
        return all((self.outer_cleanup, self.inner_group_cleanup,
                    self.wineserver_cleanup, self.prefix_observation))


@dataclass(frozen=True)
class PreviewResult:
    success: bool
    category: str | None
    finalizer: FinalizerOutcome | None = None


def _check_time(clock, deadline):
    if clock() >= deadline:
        raise PreviewFailure("execution")


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _json(payload):
    if len(payload) > JSON_LIMIT:
        raise PreviewFailure("contract")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PreviewFailure("contract")
            result[key] = value
        return result
    try:
        return json.loads(payload, object_pairs_hook=unique,
                          parse_constant=lambda value: (_ for _ in ()).throw(PreviewFailure("contract")))
    except (UnicodeError, ValueError, RecursionError):
        raise PreviewFailure("contract") from None


def _hash_file(path, filesystem, clock, deadline, limit=512 * 1024 * 1024):
    _check_time(clock, deadline)
    facts = filesystem.inspect(path)
    if not facts.exists or facts.kind != "file" or facts.symlink:
        raise PreviewFailure("integrity")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    digest = hashlib.sha256()
    total = 0
    with os.fdopen(descriptor, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise PreviewFailure("integrity")
        while True:
            _check_time(clock, deadline)
            chunk = handle.read(min(65536, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise PreviewFailure("integrity")
            digest.update(chunk)
        after = os.fstat(handle.fileno())
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or filesystem.inspect(path).identity != (before.st_dev, before.st_ino)):
        raise PreviewFailure("integrity")
    getattr(filesystem, "record_io", lambda *args: None)("hash", path)
    return "sha256:" + digest.hexdigest()


class PreviewLaunchObserver:
    """Strict bounded JSONL parser. Capture live identity before the next read."""

    def __init__(self, processes, prefix, clock, deadline):
        self.processes = processes
        self.prefix = prefix
        self.clock = clock
        self.deadline = deadline
        self.buffer = bytearray()
        self.total = 0
        self.events = []
        self.observation = None
        self.pid = None
        self.stdout = ""
        self.stderr = ""
        self.terminal = False
        self.stop = False
        self.invalid = False

    def started_observation(self):
        return self.observation

    def on_chunk(self, stream, chunk):
        _check_time(self.clock, self.deadline)
        self.total += len(chunk)
        if self.total > JSON_LIMIT:
            raise PreviewFailure("execution")
        if stream != "stdout":
            return
        self.buffer.extend(chunk)
        while b"\n" in self.buffer:
            line, _, remaining = self.buffer.partition(b"\n")
            self.buffer = bytearray(remaining)
            try:
                self._event(_json(line))
            except BaseException:
                self.invalid = True
                raise

    def _event(self, event):
        required = {"schemaVersion", "requestId", "sequence", "elapsedMilliseconds", "kind"}
        allowed = required | {"processId", "output", "exit", "message"}
        if (not isinstance(event, dict) or not required <= event.keys() or event.keys() - allowed
                or event["schemaVersion"] != "1" or event["requestId"] != REQUEST_ID
                or type(event["sequence"]) is not int or event["sequence"] != len(self.events)
                or type(event["elapsedMilliseconds"]) is not int or event["elapsedMilliseconds"] < 0
                or self.terminal):
            raise PreviewFailure("execution")
        kind = event["kind"]
        if not self.events and kind != "started":
            raise PreviewFailure("execution")
        if kind == "started":
            if self.events or type(event.get("processId")) is not int or not 1 < event["processId"] <= 0xffffffff:
                raise PreviewFailure("execution")
            self.pid = event["processId"]
            try:
                observation = self.processes.observe(self.pid, self.prefix)
            except OSError:
                raise PreviewFailure("test-infrastructure") from None
            if isinstance(observation, Verified):
                if (observation.pid != self.pid or observation.uid != self.processes.platform.current_uid()
                        or observation.canonical_prefix != self.prefix or observation.start_time_ticks <= 0):
                    raise PreviewFailure("test-infrastructure")
            elif not isinstance(observation, ExitedBeforeSnapshot) or observation.pid != self.pid:
                raise PreviewFailure("test-infrastructure")
            self.observation = observation
        elif kind == "output":
            output = event.get("output")
            if (not isinstance(output, dict) or set(output) != {"stream", "text"}
                    or output["stream"] not in ("stdout", "stderr") or not isinstance(output["text"], str)):
                raise PreviewFailure("execution")
            if output["stream"] == "stdout": self.stdout += output["text"]
            else: self.stderr += output["text"]
        elif kind == "wine-server-stop-requested":
            if self.stop:
                raise PreviewFailure("execution")
            self.stop = True
        elif kind == "exited":
            if not self.stop or event.get("exit") != {"code": 0, "success": True}:
                raise PreviewFailure("execution")
            if type(event["exit"]["code"]) is not int or type(event["exit"]["success"]) is not bool:
                raise PreviewFailure("execution")
            self.terminal = True
        else:
            raise PreviewFailure("execution")
        self.events.append(event)

    def finish(self):
        marker_lines = sum(line in (CONSOLE_MARKER, CONSOLE_MARKER[:-1] + "\r\n")
                           for line in self.stdout.splitlines(keepends=True))
        if (self.invalid or self.buffer or not self.terminal or marker_lines != 1
                or self.stdout.count(CONSOLE_MARKER.rstrip()) != 1
                or CONSOLE_MARKER.rstrip() in self.stderr):
            raise PreviewFailure("execution")
        return [event["kind"] for event in self.events]


class ProcSelfTestObserver:
    def __init__(self, processes, prefix):
        self.processes = processes
        self.prefix = prefix
        self.buffer = bytearray()
        self.identity = None

    def on_chunk(self, stream, chunk):
        if stream != "stdout" or len(self.buffer) + len(chunk) > 32 or self.identity is not None:
            raise PreviewFailure("test-infrastructure")
        self.buffer.extend(chunk)
        if b"\n" not in self.buffer:
            return
        if re.fullmatch(rb"[1-9][0-9]{0,9}\n", self.buffer) is None:
            raise PreviewFailure("test-infrastructure")
        identity = self.processes.observe(int(self.buffer), self.prefix)
        if (not isinstance(identity, Verified) or identity.uid != self.processes.platform.current_uid()
                or identity.canonical_prefix != self.prefix):
            raise PreviewFailure("test-infrastructure")
        self.identity = identity
        self.processes.signal_verified_group(identity, signal.SIGTERM)


class NativeProcView:
    """Preview evidence only. Unreadable eligible /proc state is never skipped."""

    def __init__(self, clock=time.monotonic, deadline=float("inf")):
        self.platform = NativePlatform()
        self.host_display_detected = bool(os.environ.get("DISPLAY"))
        self.clock = clock
        self.deadline = deadline

    def _read(self, path, limit):
        _check_time(self.clock, self.deadline)
        with path.open("rb") as handle:
            value = handle.read(limit + 1)
        if len(value) > limit:
            raise OSError("proc-size-limit")
        return value

    def _stat(self, pid):
        root = Path("/proc") / str(pid)
        uid = root.stat().st_uid
        value = self._read(root / "stat", 8192)
        parts = value[value.rfind(b")") + 2:].split()
        if len(parts) < 20:
            raise OSError("malformed-proc-stat")
        return uid, parts[0], int(parts[2]), int(parts[19])

    def observe(self, pid, prefix):
        try:
            before = self._stat(pid)
            if before[1] == b"Z":
                return ExitedBeforeSnapshot(pid)
            if before[0] != self.platform.current_uid() or before[2] != pid:
                raise OSError("unowned-process-group")
            environment = self._read(Path("/proc") / str(pid) / "environ", JSON_LIMIT)
            expected = os.fsencode("WINEPREFIX=" + str(prefix))
            if not environment or environment.split(b"\0").count(expected) != 1:
                raise OSError("unverified-prefix")
            after = self._stat(pid)
            if after[1] == b"Z":
                return ExitedBeforeSnapshot(pid)
            if (before[0], before[2], before[3]) != (after[0], after[2], after[3]):
                raise OSError("process-identity-changed")
            return Verified(pid, before[0], before[3], prefix)
        except FileNotFoundError:
            return ExitedBeforeSnapshot(pid)

    def exact_prefix_processes(self, prefix):
        _check_time(self.clock, self.deadline)
        matching = []
        expected = os.fsencode("WINEPREFIX=" + str(prefix))
        with os.scandir("/proc") as entries:
            for entry in entries:
                _check_time(self.clock, self.deadline)
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                try:
                    if entry.stat(follow_symlinks=False).st_uid != self.platform.current_uid():
                        continue
                    uid, state, group, ticks = self._stat(int(entry.name))
                    if state == b"Z":
                        continue
                    value = self._read(Path(entry.path) / "environ", JSON_LIMIT)
                    # Empty eligible live environments cannot establish visibility.
                    if not value:
                        raise OSError("unreadable-live-environment")
                    if expected in value.split(b"\0"):
                        matching.append(int(entry.name))
                except FileNotFoundError:
                    continue
        return matching

    def group_exists(self, pid):
        _check_time(self.clock, self.deadline)
        try:
            os.killpg(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def signal_verified_group(self, identity, signum):
        _check_time(self.clock, self.deadline)
        if self.observe(identity.pid, identity.canonical_prefix) != identity:
            raise OSError("identity-changed-before-signal")
        os.killpg(identity.pid, signum)


class NativePreviewCommands:
    def __init__(self, clock=time.monotonic):
        self.clock = clock

    def run(self, kind, spec, observer=None):
        if not isinstance(kind, ClosedCommandKind):
            raise PreviewFailure("contract")
        return run_bounded(spec, LinuxCommandAdapter(), observer, self.clock)


class PreviewCommandJournal:
    """Bounded private command evidence, independent of event parsing success."""

    def __init__(self, commands):
        self.commands = commands
        self.entries = []
        self.remaining = 256 * 1024
        self.launch_stdout = b""

    def run(self, kind, spec, observer=None):
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        class Capture:
            def on_chunk(self, stream, chunk):
                remaining = JSON_LIMIT - sum(map(len, buffers.values()))
                buffers[stream].extend(chunk[:remaining])
                if observer is not None:
                    observer.on_chunk(stream, chunk)
        result = None
        error = None
        try:
            result = self.commands.run(kind, spec, Capture() if observer is not None else None)
            return result
        except BaseException as caught:
            error = caught
            raise
        finally:
            if result is not None:
                stdout, stderr = result.stdout, result.stderr
                status = OuterCleanupStatus("Complete", "none")
                reason = "complete" if result.return_code == 0 else "nonzero-exit"
            elif isinstance(error, CommandFailure):
                stdout, stderr = error.partial_stdout, error.partial_stderr
                status = error.outer_cleanup_status
                reason = error.reason if error.reason in {"start", "read", "observer", "timeout", "output-limit", "outer-cleanup"} else "execution"
            else:
                stdout, stderr = bytes(buffers["stdout"]), bytes(buffers["stderr"])
                status = OuterCleanupStatus("Failed", "start")
                reason = "observer" if observer is not None else "execution"
            if kind == ClosedCommandKind.PREPARED_LAUNCH:
                self.launch_stdout = stdout[:JSON_LIMIT]
            record = {"commandKind": kind.name, "returnCode": result.return_code if result is not None else None,
                      "reason": reason, "outerCleanup": {"state": status.state, "stage": status.stage}}
            for stream, payload in (("stdout", stdout), ("stderr", stderr)):
                accepted = payload[:min(16384, self.remaining)]
                self.remaining -= len(accepted)
                record[stream + "Base64"] = base64.b64encode(accepted).decode("ascii")
                record[stream + "Truncated"] = len(accepted) != len(payload)
            if len(self.entries) < 32:
                self.entries.append(record)

    def document(self):
        return {"schemaVersion": "1", "commands": self.entries}


def _receipt(value, inputs):
    if (not isinstance(value, dict) or set(value) != {"schemaVersion", "source", "version", "architecture", "packId", "packDigest", "capabilities"}
            or value["schemaVersion"] != "1" or value["source"] != "explicit-override"
            or value["version"] != inputs.declared_version or value["architecture"] != "x86_64"
            or value["packId"] != PACK_ID or value["capabilities"] != ["guest-x86_64"]
            or not isinstance(value["packDigest"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value["packDigest"]) is None):
        raise PreviewFailure("integrity")
    return value


def _binding(context, inputs, receipt, wine_digest, server_digest):
    if (not isinstance(context, dict) or context.get("schemaVersion") != "1" or context.get("storageRoot") != str(inputs.storage_root)
            or len(context.get("runtimeBindings", [])) != 1):
        raise PreviewFailure("integrity")
    capabilities = context.get("capabilities", {})
    host = capabilities.get("host", {})
    if (capabilities.get("schemaVersion") != "1" or host.get("os") != "linux"
            or host.get("architecture") != "x86_64" or not host.get("osVersion")):
        raise PreviewFailure("integrity")
    for field, identifier, kind, version, caps in (
            ("runtimeProviders", PROVIDER_ID, "wine", inputs.declared_version, ["guest-x86_64"]),
            ("translators", "native-host", "native", "host", ["x86_64-on-x86_64"]),
            ("graphicsBackends", "linux-wined3d", "wined3d", inputs.declared_version, ["opengl"])):
        expected = {"id": identifier, "kind": kind, "version": version, "available": True, "capabilities": caps}
        if capabilities.get(field) != [expected]:
            raise PreviewFailure("integrity")
    binding = context["runtimeBindings"][0]
    expected_environment = {
        "COMPATFORGE_RUNTIME_PACK": PACK_ID, "COMPATFORGE_RUNTIME_PACK_DIGEST": receipt["packDigest"],
        "COMPATFORGE_RUNTIME_EXECUTABLE_SHA256": wine_digest,
        "COMPATFORGE_WINESERVER_EXECUTABLE_SHA256": server_digest,
        "WINEDEBUG": "-all", "WINESERVER": str(inputs.materialized_root / inputs.wineserver_relative),
        "WINEARCH": "win64", "WINEDLLOVERRIDES": "mscoree,mshtml="}
    if (binding.get("providerId") != PROVIDER_ID or binding.get("packId") != PACK_ID
            or binding.get("packDigest") != receipt["packDigest"]
            or binding.get("executable") != str(inputs.materialized_root / inputs.wine_relative)
            or binding.get("wineserverExecutable") != expected_environment["WINESERVER"]
            or binding.get("environment") != expected_environment or binding.get("workingDirectory") is not None):
        raise PreviewFailure("integrity")
    return binding


def _plan(value, receipt, guest_digest, inputs, prefix):
    try:
        valid = (value["schemaVersion"] == "1" and value["requestId"] == REQUEST_ID
            and value["runtime"] == {"provider": "wine", "packId": PACK_ID, "packDigest": receipt["packDigest"]}
            and value["translator"]["provider"] == "native" and value["graphics"]["backend"] == "wined3d"
            and value["guestArtifact"]["digest"] == guest_digest
            and value["guestArtifact"]["architecture"] == "x86_64"
            and value["lifecycle"]["maximumRuntimeMilliseconds"] == 60000
            and value["lifecycle"]["wineserver"] == {"executable": str(inputs.materialized_root / inputs.wineserver_relative), "prefix": str(prefix)}
            and value["process"]["executable"] == str(inputs.materialized_root / inputs.wine_relative)
            and value["process"]["environment"]["WINEPREFIX"] == str(prefix))
    except (TypeError, KeyError):
        valid = False
    if not valid:
        raise PreviewFailure("integrity")
    return _canonical_json(value)


def _finalize(abnormal, observer, outer_complete, inputs, server_digest,
              commands, processes, filesystem, clock, deadline):
    inner_ok = True
    server_ok = True
    prefix_ok = True
    category = None
    prefix = observer.prefix
    observation = observer.started_observation()
    server = inputs.materialized_root / inputs.wineserver_relative
    integrity = True
    try:
        if _hash_file(server, filesystem, clock, deadline) != server_digest:
            raise PreviewFailure("integrity")
    except BaseException as error:
        integrity = False
        server_ok = False
        inner_ok = False
        category = getattr(error, "category", "integrity")
    # No naked PGID is ever signalled: even Verified must match immediately now.
    if integrity and abnormal and isinstance(observation, Verified):
        try:
            current = processes.observe(observation.pid, prefix)
            if isinstance(current, Verified):
                if current != observation:
                    raise PreviewFailure("cleanup")
                # Linux signal numbers keep the portable policy executable on
                # Windows; only NativeProcView dispatches actual OS signals.
                for signum in (15, 9):
                    _check_time(clock, deadline)
                    if not processes.group_exists(observation.pid):
                        break
                    current = processes.observe(observation.pid, prefix)
                    if isinstance(current, ExitedBeforeSnapshot):
                        break
                    if current != observation:
                        raise PreviewFailure("cleanup")
                    processes.signal_verified_group(observation, signum)
                    grace_deadline = min(deadline, clock() + (0.5 if signum == 15 else 1.0))
                    while clock() < grace_deadline:
                        if not processes.group_exists(observation.pid):
                            break
                        getattr(clock, "pause", time.sleep)(min(0.01, max(0, grace_deadline - clock())))
            elif not isinstance(current, ExitedBeforeSnapshot):
                raise PreviewFailure("cleanup")
        except BaseException:
            inner_ok = False
            category = "cleanup"
    elif observer.pid is not None and observation is None:
        inner_ok = False
        category = "test-infrastructure"

    environment = {"WINEPREFIX": str(prefix), "WINEDEBUG": "-all", "WINEARCH": "win64",
                   "WINEDLLOVERRIDES": "mscoree,mshtml=", "WINESERVER": str(server)}
    kinds = [(ClosedCommandKind.WINESERVER_VERSION, "--version")]
    if abnormal:
        kinds.append((ClosedCommandKind.WINESERVER_KILL, "-k"))
    kinds.append((ClosedCommandKind.WINESERVER_WAIT, "-w"))
    for kind, argument in kinds:
        try:
            if not integrity:
                continue
            if _hash_file(server, filesystem, clock, deadline) != server_digest:
                integrity = False
                raise PreviewFailure("integrity")
            _check_time(clock, deadline)
            result = commands.run(kind, CommandSpec((str(server), argument), environment,
                inputs.materialized_root, JSON_LIMIT, min(deadline, clock() + 10.0)))
            if result.return_code != 0:
                raise PreviewFailure("cleanup")
            if kind == ClosedCommandKind.WINESERVER_VERSION:
                expected = ("Wine " + inputs.declared_version).encode()
                if result.stdout or result.stderr not in (expected, expected + b"\n", expected + b"\r\n"):
                    raise PreviewFailure("integrity")
        except BaseException as error:
            server_ok = False
            if isinstance(error, CommandFailure) and error.outer_cleanup_status.state != "Complete":
                outer_complete = False
            category = getattr(error, "category", "cleanup")
    # Non-signalling observations still run after command or integrity failures.
    try:
        _check_time(clock, deadline)
        if processes.exact_prefix_processes(prefix):
            prefix_ok = False
            category = category or "cleanup"
    except BaseException:
        prefix_ok = False
        category = category or "test-infrastructure"
    if observer.pid is not None:
        try:
            _check_time(clock, deadline)
            if processes.group_exists(observer.pid):
                inner_ok = False
                category = category or "cleanup"
        except BaseException:
            inner_ok = False
            category = category or "test-infrastructure"
    outcome = FinalizerOutcome(outer_complete, inner_ok, server_ok, prefix_ok)
    return outcome, category or (None if outcome.complete else "cleanup")


def execute_preview(inputs, paths, commands, processes, filesystem, clock):
    """Execute only the reviewed Console fixture; all post-marker exits finalize."""
    deadline = clock() + OVERALL_SECONDS
    work_deadline = deadline - CLEANUP_SECONDS
    if isinstance(processes, NativeProcView):
        processes.deadline = deadline
    created = None
    store = None
    observer = None
    outer_complete = True
    failure = None
    outcome = None
    finalized_abnormally = False
    journal = PreviewCommandJournal(commands)
    commands = journal
    snapshots = {}
    guest_identity = None
    bootstrap_identity = None

    def run(kind, argv, *, environment=None, cwd=None, observer=None):
        nonlocal outer_complete
        _check_time(clock, work_deadline)
        try:
            result = commands.run(kind, CommandSpec(tuple(map(str, argv)), environment or {},
                cwd or inputs.evidence_root, JSON_LIMIT, work_deadline,
                0o177 if kind == ClosedCommandKind.COMPILE_GUEST else None), observer)
        except CommandFailure as error:
            outer_complete = outer_complete and error.outer_cleanup_status.state == "Complete"
            raise
        finally:
            if kind == ClosedCommandKind.PREPARED_LAUNCH:
                store._write_payload("events.jsonl", journal.launch_stdout)
        if result.return_code != 0:
            raise PreviewFailure("execution")
        return result

    def snapshot(paths_to_hash):
        return {path: _hash_file(path, filesystem, clock, work_deadline) for path in paths_to_hash}

    def unchanged(values):
        if snapshot(values) != values:
            raise PreviewFailure("integrity")

    try:
        if paths.root != inputs.evidence_root:
            raise PreviewFailure("contract")
        checked = preflight(inputs, processes.platform, filesystem)
        created = create_exclusive_roots(checked, filesystem)
        store = EvidenceStore(paths.root, created_roots=created, filesystem=filesystem)
        prefix = inputs.storage_root / "bottles" / BOTTLE_ID / "prefix"
        observer = PreviewLaunchObserver(processes, prefix, clock, work_deadline)
        source = filesystem.repository_root / "tests" / "fixtures" / "windows_console_smoke.c"
        snapshots = snapshot((source, inputs.cli, inputs.compiler))
        wine_digest = _hash_file(inputs.materialized_root / inputs.wine_relative, filesystem, clock, work_deadline)
        server_digest = _hash_file(inputs.materialized_root / inputs.wineserver_relative, filesystem, clock, work_deadline)

        helper_prefix = paths.root / "observer-self-test-prefix"
        helper = ProcSelfTestObserver(processes, helper_prefix)
        helper_spec = CommandSpec((str(Path(sys.executable).resolve()), "-I", "-S", "-c",
            "import os,time; print(os.getpid(),flush=True); time.sleep(300)"),
            {"WINEPREFIX": str(helper_prefix)}, paths.root, 1024, min(work_deadline, clock() + 5.0))
        try:
            helper_result = commands.run(ClosedCommandKind.PROC_OBSERVER_SELF_TEST, helper_spec, helper)
            if (helper_result.return_code not in (0, -15) or helper.identity is None
                    or processes.group_exists(helper.identity.pid) or processes.exact_prefix_processes(helper_prefix)):
                raise PreviewFailure("test-infrastructure")
        except BaseException:
            raise PreviewFailure("test-infrastructure") from None

        # Reserve the exact output privately before handing its pathname to the
        # compiler. A linker may replace the inode; inspect its produced inode
        # afterwards rather than incorrectly requiring reservation identity.
        store._write_payload("console-preview.exe", b"")
        try:
            result = run(ClosedCommandKind.COMPILE_GUEST, (inputs.compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
                "-Wl,--subsystem,console,--no-insert-timestamp", source, "-o", paths.guest))
        finally:
            guest_facts = filesystem.inspect(paths.guest)
            if guest_facts.exists and guest_facts.kind == "file" and not guest_facts.symlink:
                guest_identity = guest_facts.identity
        if result.stdout or result.stderr:
            raise PreviewFailure("execution")
        filesystem.verify_private_file(paths.guest, guest_identity)
        guest_digest = _hash_file(paths.guest, filesystem, clock, work_deadline, 64 * 1024 * 1024)
        guest_identity = filesystem.inspect(paths.guest).identity
        unchanged(snapshots)
        inspection = _json(run(ClosedCommandKind.INSPECT_GUEST, (inputs.cli, "inspect", paths.guest)).stdout)
        if any(inspection.get(key) != value for key, value in {"schemaVersion": "1", "format": "pe32Plus",
            "architecture": "x86_64", "machineCode": 0x8664, "imageKind": "executable", "subsystem": "windowsConsole",
            "subsystemCode": 3, "fileDigest": guest_digest}.items()):
            raise PreviewFailure("integrity")
        store.write_json("inspection.json", inspection)
        bootstrap_request = {"schemaVersion": "1", "runtimeStoreRoot": str(inputs.runtime_store_root),
            "storageRoot": str(inputs.storage_root), "materializedRoot": str(inputs.materialized_root),
            "wine": str(inputs.wine_relative), "wineserver": str(inputs.wineserver_relative), "version": inputs.declared_version}
        bootstrap_path = store.write_json("bootstrap-request.json", bootstrap_request)
        try:
            receipt = _receipt(_json(run(ClosedCommandKind.BOOTSTRAP_CONTEXT,
                (inputs.cli, "local", "linux", "context", bootstrap_path, paths.bootstrap_context)).stdout), inputs)
        finally:
            bootstrap_facts = filesystem.inspect(paths.bootstrap_context)
            if bootstrap_facts.exists and bootstrap_facts.kind == "file" and not bootstrap_facts.symlink:
                bootstrap_identity = bootstrap_facts.identity
        context = store.read_json("bootstrap-context.json")
        _binding(context, inputs, receipt, wine_digest, server_digest)
        store.write_json("bootstrap-receipt.json", receipt)
        context.setdefault("supervisor", {})["maximumRuntimeMilliseconds"] = 60000
        store.write_json("private-context.json", context)
        request = {"schemaVersion": "1", "requestId": REQUEST_ID, "bottleId": BOTTLE_ID,
            "executable": {"path": str(paths.guest), "architecture": "x86_64", "sha256": guest_digest[7:]},
            "arguments": [], "environment": {}, "constraints": {"allowVirtualMachine": False, "allowRemote": False,
                "requiresKernelDriver": False, "requiresDirectX12": False, "networkPolicy": "deny", "requiredCapabilities": ["guest-x86_64"]}}
        store.write_json("request.json", request)
        input_hashes = snapshot((paths.execution_context, paths.launch_request, paths.guest))
        pre_plan = _json(run(ClosedCommandKind.PREPARED_PLAN_PRE,
            (inputs.cli, "prepared-plan", paths.execution_context, paths.guest, paths.launch_request)).stdout)
        canonical_plan = _plan(pre_plan, receipt, guest_digest, inputs, prefix)
        store.write_json("pre-plan.json", pre_plan)
        unchanged(input_hashes)
        unchanged(snapshots)
        if filesystem.inspect(prefix).exists:
            raise PreviewFailure("integrity")
        _check_time(clock, work_deadline)
        store._write_json("run-start.json", {"schemaVersion": "1", "context": str(paths.execution_context),
            "prefix": str(prefix), "wineserverDigest": server_digest}, mark_started=True)
        run(ClosedCommandKind.PREPARED_LAUNCH,
            (inputs.cli, "prepared-launch", paths.execution_context, paths.guest, paths.launch_request), observer=observer)
        event_kinds = observer.finish()
        unchanged(input_hashes)
        post_plan = _json(run(ClosedCommandKind.PREPARED_PLAN_POST,
            (inputs.cli, "prepared-plan", paths.execution_context, paths.guest, paths.launch_request)).stdout)
        store.write_json("post-plan.json", post_plan)
        if _plan(post_plan, receipt, guest_digest, inputs, prefix) != canonical_plan:
            raise PreviewFailure("integrity")
        unchanged(input_hashes)
    except BaseException as error:
        failure = getattr(error, "category", "execution")
        if isinstance(error, ValueError) and str(error) == "unsupported-host": failure = "unsupported-host"
    finally:
        if store is not None and store.started:
            finalized_abnormally = failure is not None
            outcome, cleanup_category = _finalize(failure is not None, observer, outer_complete,
                inputs, server_digest, commands, processes, filesystem, clock, deadline)
            if cleanup_category:
                failure = cleanup_category
        elif store is not None:
            # Only identified outputs and our own exclusive artifacts may be removed.
            for path, identity in ((paths.guest, guest_identity), (paths.bootstrap_context, bootstrap_identity)):
                if identity is not None:
                    store._remove_owned(path, identity)
            store.rollback_setup()
        elif created is not None:
            created.rollback_empty(filesystem)

    if failure is None:
        try:
            # Publication belongs to the work budget; the finalizer never lends
            # its reserved time to business work or extends the overall deadline.
            unchanged(snapshots)
            unchanged(input_hashes)
            if outcome is None or not outcome.complete:
                raise PreviewFailure("cleanup")
            summary = {"schemaVersion": "1", "checkpoint": "linux-x86_64-runtime-provider-preview",
                "hostOs": "linux", "hostArchitecture": "x86_64", "hostDisplayDetected": bool(processes.host_display_detected),
                "displayForwarded": False, "runtimePackId": PACK_ID, "runtimeVersion": inputs.declared_version,
                "runtimePackDigest": receipt["packDigest"], "guestDigest": guest_digest,
                "planDigest": "sha256:" + hashlib.sha256(canonical_plan).hexdigest(),
                "planCorrelation": "pre-post-canonical-match", "runtimeEventKinds": event_kinds, "exitCode": 0,
                "cleanupStatus": "complete", "consoleValidated": True, "graphicsValidated": False,
                "runtimeEvidenceScope": "entrypoints-only", "runtimeTreeValidated": False, "networkIsolationValidated": False}
            validate_public_summary(summary)
            store.write_json("command-diagnostics.json", journal.document())
            store._write_json("public-summary.json", summary)
            return PreviewResult(True, None, outcome)
        except BaseException as error:
            failure = getattr(error, "category", "execution")
    if store is not None and store.started:
        # A late integrity/publication failure escalates the same transaction
        # to its abnormal path. Reuse the original absolute deadline and retain
        # every incomplete earlier cleanup result; never mint another budget.
        if not finalized_abnormally:
            late_outcome, cleanup_category = _finalize(True, observer, outer_complete,
                inputs, server_digest, commands, processes, filesystem, clock, deadline)
            outcome = FinalizerOutcome(
                outcome.outer_cleanup and late_outcome.outer_cleanup,
                outcome.inner_group_cleanup and late_outcome.inner_group_cleanup,
                outcome.wineserver_cleanup and late_outcome.wineserver_cleanup,
                outcome.prefix_observation and late_outcome.prefix_observation)
            failure = failure or cleanup_category
        try:
            if paths.root / "command-diagnostics.json" not in store.owned_files:
                store.write_json("command-diagnostics.json", journal.document())
        except OSError:
            failure = "test-infrastructure"
        try:
            store.write_json("failure.json", {"schemaVersion": "1", "reason": failure})
        except OSError:
            # A storage failure cannot become success, and no exception text leaks.
            failure = "test-infrastructure"
    return PreviewResult(False, failure, outcome)


def validate_public_summary(value):
    """Closed recursive projection: no arbitrary nested payload is public."""
    constants = {"schemaVersion": "1", "checkpoint": "linux-x86_64-runtime-provider-preview",
        "hostOs": "linux", "hostArchitecture": "x86_64", "displayForwarded": False,
        "runtimePackId": PACK_ID, "planCorrelation": "pre-post-canonical-match", "exitCode": 0,
        "cleanupStatus": "complete", "consoleValidated": True, "graphicsValidated": False,
        "runtimeEvidenceScope": "entrypoints-only", "runtimeTreeValidated": False, "networkIsolationValidated": False}
    variable_fields = {"hostDisplayDetected", "runtimeVersion", "runtimePackDigest", "guestDigest", "planDigest", "runtimeEventKinds"}
    if not isinstance(value, dict) or set(value) != set(constants) | variable_fields:
        raise PreviewFailure("contract")
    for key, expected in constants.items():
        if type(value[key]) is not type(expected) or value[key] != expected:
            raise PreviewFailure("contract")
    if type(value["hostDisplayDetected"]) is not bool:
        raise PreviewFailure("contract")
    version = value["runtimeVersion"]
    if not isinstance(version, str) or re.fullmatch(r"[0-9][A-Za-z0-9.+_-]{0,127}", version) is None:
        raise PreviewFailure("contract")
    for key in ("runtimePackDigest", "guestDigest", "planDigest"):
        if not isinstance(value[key], str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]) is None:
            raise PreviewFailure("contract")
    kinds = value["runtimeEventKinds"]
    if (not isinstance(kinds, list) or len(kinds) > JSON_LIMIT or not kinds
            or any(type(kind) is not str or kind not in ("started", "output", "wine-server-stop-requested", "exited") for kind in kinds)
            or kinds[0] != "started" or kinds[-1] != "exited"
            or kinds.count("started") != 1 or kinds.count("exited") != 1 or kinds.count("wine-server-stop-requested") != 1):
        raise PreviewFailure("contract")


def main(argv=None):
    try:
        inputs = parse_closed_args(sys.argv[1:] if argv is None else argv)
        clock = time.monotonic
        result = execute_preview(inputs, EvidencePaths(inputs.evidence_root),
            NativePreviewCommands(clock), NativeProcView(clock), NativeFileSystem(), clock)
        print("linux-console-preview-passed" if result.success else result.category)
        return 0 if result.success else 1
    except (ValueError, OSError):
        print("contract")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
