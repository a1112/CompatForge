"""Explicit Linux Console preview foundations; the product pipeline is Task 13."""

from __future__ import annotations

from dataclasses import dataclass
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
                          "bootstrap-receipt.json", "request.json", "inspection.json",
                          "pre-plan.json", "post-plan.json", "events.jsonl",
                          "command-diagnostics.json", "run-start.json", "failure.json"})


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
        if name == "run-start.json":
            raise ValueError("run-start-requires-fixed-cleanup-inputs")
        return self._write_json(name, value)

    def _write_json(self, name, value, *, mark_started=False):
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("utf-8") + b"\n"
        if len(payload) > JSON_LIMIT:
            raise ValueError("json-size-limit")
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
            os.close(descriptor)
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
        return json.loads(payload)

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
            # Readiness waits also avoid spinning while root exit/group removal
            # propagates. The remaining absolute budget bounds each wait.
            try:
                adapter.readiness(running, min(0.01, max(0, spec.deadline - clock())))
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
                                       start_new_session=True, close_fds=True, bufsize=0)
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
