from __future__ import annotations

import copy
import gc
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import warnings
from dataclasses import dataclass
from pathlib import Path

from tests import macos_pinned_cli_spike as spike


def _sha256(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _compact(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass
class _Descriptor:
    identity: tuple[int, int]
    kind: str
    mode: int
    nlink: int
    size: int
    access_mode: int
    append: bool
    contents: bytes = b""
    offset: int = 0


class _FakeProcess:
    def __init__(
        self,
        boundary: "_FakeBoundary",
        argv: tuple[str, ...],
        inherited_fds: tuple[int, ...],
    ) -> None:
        self.boundary = boundary
        self.argv = argv
        self.inherited_fds = inherited_fds
        self.returncode: int | None = None
        self.killed = False
        self.terminated = False
        self.waited = False
        self.window_observed = False
        self._streams_taken = False

    def poll(self) -> int | None:
        if self.returncode is None and self.window_observed and not self.boundary.communication_timeout:
            self.returncode = self.boundary.returncode
        return self.returncode

    def take_output_streams(self) -> tuple[object, object]:
        if self._streams_taken:
            raise spike.SpikeError("output streams already taken")
        self._streams_taken = True
        inspection_fd, plan_fd = self.inherited_fds[-2:]
        inspection = self.boundary.inspection_bytes
        plan = self.boundary.plan_bytes
        if self.boundary.oversized_output:
            inspection = b"x" * (spike.MAX_EVIDENCE_BYTES + 1)
        self.boundary.descriptors[inspection_fd].contents = inspection
        self.boundary.descriptors[inspection_fd].size = len(inspection)
        self.boundary.descriptors[plan_fd].contents = plan
        self.boundary.descriptors[plan_fd].size = len(plan)
        if self.boundary.post_spawn_identity_drift:
            self.boundary.descriptors[inspection_fd].identity = (7, 999_999)
        if self.boundary.post_spawn_linked_output:
            self.boundary.descriptors[plan_fd].nlink = 1
        return io.BytesIO(self.boundary.transcript(inspection, plan)), io.BytesIO(self.boundary.stderr)

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.waited = True
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.argv, timeout)
        return self.returncode


class _FakeBoundary:
    platform_name = "Darwin"
    repository_root = "/repo"

    def __init__(self, manifest: dict[str, object], inputs: dict[str, bytes]) -> None:
        self.manifest = manifest
        self.inputs = inputs
        self.next_fd = 50001
        self.next_inode = 100
        self.descriptors: dict[int, _Descriptor] = {}
        self.processes: list[_FakeProcess] = []
        self.commands: list[tuple[str, ...]] = []
        self.pass_fds: list[tuple[int, ...]] = []
        self.popen_options: list[dict[str, object]] = []
        self.revalidated_inputs: list[str] = []
        self.work_revalidations: list[int] = []
        self.closed: list[int] = []
        self.created_identities: list[tuple[int, int]] = []
        self.seek_while_live = False
        self.window_probe_saw_live_process = False
        self.window_probe_calls = 0
        self.clock = 0.0
        self.window_missing = False
        self.named_output = False
        self.output_access_mode = os.O_RDWR
        self.output_append = False
        self.output_mode = 0o600
        self.output_initial_size = 0
        self.alias_outputs = False
        self.omit_pass_fd = False
        self.extra_pass_fd = False
        self.close_failure = False
        self.communication_timeout = False
        self.returncode = 0
        self.stderr = b""
        self.event_mutant: str | None = None
        self.receipt_mutant: str | None = None
        self.oversized_output = False
        self.post_spawn_identity_drift = False
        self.post_spawn_linked_output = False
        self.physical_overlaps: set[frozenset[str]] = set()
        self.inspection_bytes = _canonical({"architecture": "x86_64", "kind": "inspection"})
        self.plan_bytes = _canonical({"process": {"arguments": ["logical"]}, "schemaVersion": "1"})

    def resolve_canonical(self, path: str, *, directory: bool) -> str:
        del directory
        return path

    def paths_physically_overlap(self, left: str, right: str) -> bool:
        return spike._paths_overlap(left, right) or frozenset((left, right)) in self.physical_overlaps

    def bind_input(self, path: str, expected_sha256: str, label: str) -> spike.FileBinding:
        del label
        payload = self.inputs[path]
        if _sha256(payload) != expected_sha256:
            raise spike.SpikeError("input digest mismatch")
        self.next_inode += 1
        return spike.FileBinding(
            path=path,
            identity=(7, self.next_inode),
            size=len(payload),
            mtime_ns=self.next_inode,
            sha256=expected_sha256,
            payload=payload,
        )

    def revalidate_input(self, binding: spike.FileBinding) -> None:
        self.revalidated_inputs.append(binding.path)
        payload = self.inputs[binding.path]
        if len(payload) != binding.size or _sha256(payload) != binding.sha256:
            raise spike.SpikeError("input identity changed")

    def open_work_root(self, path: str) -> spike.WorkRootBinding:
        descriptor = self._allocate_descriptor(
            _Descriptor((7, self.next_inode), "directory", 0o700, 1, 0, os.O_RDONLY, False)
        )
        return spike.WorkRootBinding(path=path, descriptor=descriptor, identity=self.descriptors[descriptor].identity)

    def revalidate_work_root(self, binding: spike.WorkRootBinding) -> None:
        self.work_revalidations.append(binding.descriptor)
        descriptor = self.descriptors.get(binding.descriptor)
        if descriptor is None or descriptor.kind != "directory" or descriptor.identity != binding.identity:
            raise spike.SpikeError("work root identity changed")

    def create_anonymous_output(self, work_root: spike.WorkRootBinding, kind: str) -> spike.EvidenceFileBinding:
        del work_root, kind
        identity = (7, self.next_inode + 1)
        if self.alias_outputs and self.created_identities:
            identity = self.created_identities[0]
        descriptor = self._allocate_descriptor(
            _Descriptor(
                identity,
                "regular",
                self.output_mode,
                1 if self.named_output else 0,
                self.output_initial_size,
                self.output_access_mode,
                self.output_append,
                b"x" * self.output_initial_size,
            )
        )
        self.created_identities.append(identity)
        return spike.EvidenceFileBinding(descriptor=descriptor, identity=identity)

    def describe_descriptor(self, descriptor: int) -> spike.DescriptorSnapshot:
        value = self.descriptors[descriptor]
        return spike.DescriptorSnapshot(
            identity=value.identity,
            kind=value.kind,
            mode=value.mode,
            nlink=value.nlink,
            size=value.size,
            access_mode=value.access_mode,
            append=value.append,
        )

    def spawn(
        self,
        argv: tuple[str, ...],
        *,
        pass_fds: tuple[int, ...],
        **options: object,
    ) -> _FakeProcess:
        inherited = pass_fds
        if self.omit_pass_fd:
            inherited = inherited[:-1]
        if self.extra_pass_fd:
            inherited = inherited + (65000,)
        process = _FakeProcess(self, argv, inherited)
        self.processes.append(process)
        self.commands.append(argv)
        self.pass_fds.append(pass_fds)
        self.popen_options.append(options)
        return process

    def window_visible(self, tokens: tuple[str, ...]) -> bool:
        self.window_probe_calls += 1
        if not self.processes or self.processes[-1].poll() is not None:
            return False
        visible = not self.window_missing and tokens == ("SumatraPDF",)
        if visible:
            self.processes[-1].window_observed = True
            self.window_probe_saw_live_process = True
        return visible

    def sleep(self, seconds: float) -> None:
        self.clock += max(seconds, 1.0)

    def monotonic(self) -> float:
        return self.clock

    def seek_descriptor(self, descriptor: int, offset: int) -> None:
        if self.processes and self.processes[-1].poll() is None:
            self.seek_while_live = True
        self.descriptors[descriptor].offset = offset

    def read_descriptor(self, descriptor: int, maximum: int) -> bytes:
        value = self.descriptors[descriptor]
        start = value.offset
        payload = value.contents[start : start + maximum]
        value.offset += len(payload)
        return payload

    def close_descriptor(self, descriptor: int) -> None:
        self.closed.append(descriptor)
        if self.close_failure:
            self.close_failure = False
            raise OSError("injected close failure")

    def transcript(self, inspection: bytes, plan: bytes) -> bytes:
        event = {
            "schemaVersion": "1",
            "requestId": "pinned-sumatrapdf",
            "sequence": 0,
            "elapsedMilliseconds": 0,
            "kind": "started",
            "processId": 4242,
        }
        exited = {
            "schemaVersion": "1",
            "requestId": "pinned-sumatrapdf",
            "sequence": 1,
            "elapsedMilliseconds": 10,
            "kind": "exited",
            "exit": {"code": 0, "success": True},
        }
        receipt = {
            "outputs": [
                {"byteLength": len(inspection), "kind": "inspection", "sha256": _sha256(inspection)},
                {"byteLength": len(plan), "kind": "plan", "sha256": _sha256(plan)},
            ],
            "recordType": "pinned-evidence-receipt",
            "schemaVersion": 1,
        }
        records: list[object] = [event, exited, receipt]
        if self.event_mutant == "malformed":
            return b"not-json\n" + _canonical(receipt) + b"\n"
        if self.event_mutant == "nonterminal":
            records = [event, receipt]
        elif self.event_mutant == "after-terminal-event":
            records = [event, exited, event, receipt]
        elif self.event_mutant == "path-leak":
            event["message"] = "/private/work/secret"
        elif self.event_mutant == "wrong-message":
            event["message"] = "changed event meaning"
        elif self.event_mutant == "no-start":
            event["kind"] = "terminate-requested"
            event["message"] = "termination requested"
        elif self.event_mutant == "elapsed-negative":
            event["elapsedMilliseconds"] = -1
        elif self.event_mutant == "sequence-bool":
            exited["sequence"] = True
        elif self.event_mutant == "explicit-null-message":
            event["message"] = None
        elif self.event_mutant == "explicit-null-exit-code":
            exited["exit"]["code"] = None  # type: ignore[index]
        elif self.event_mutant == "process-id-bool":
            event["processId"] = True
        elif self.event_mutant == "process-id-max":
            event["processId"] = 2**32 - 1
        elif self.event_mutant == "process-id-overflow":
            event["processId"] = 2**32
        elif self.event_mutant == "exit-code-bool":
            exited["exit"]["code"] = True  # type: ignore[index]
        elif self.event_mutant == "exit-code-max":
            exited["exit"]["code"] = 2**31 - 1  # type: ignore[index]
        elif self.event_mutant == "exit-code-min":
            exited["exit"]["code"] = -(2**31)  # type: ignore[index]
        elif self.event_mutant == "exit-code-positive-overflow":
            exited["exit"]["code"] = 2**31  # type: ignore[index]
        elif self.event_mutant == "exit-code-negative-overflow":
            exited["exit"]["code"] = -(2**31) - 1  # type: ignore[index]
        if self.receipt_mutant == "missing":
            records = [event, exited]
        elif self.receipt_mutant == "not-last":
            records = [event, receipt, exited]
        elif self.receipt_mutant == "digest":
            receipt["outputs"][0]["sha256"] = "sha256:" + "0" * 64  # type: ignore[index]
        elif self.receipt_mutant == "size":
            receipt["outputs"][0]["byteLength"] = len(inspection) + 1  # type: ignore[index]
        elif self.receipt_mutant == "order":
            receipt["outputs"].reverse()  # type: ignore[union-attr]
        elif self.receipt_mutant == "extra-key":
            receipt["unexpected"] = True
        elif self.receipt_mutant == "schema-bool":
            receipt["schemaVersion"] = True
        return b"".join(_compact(record) + b"\n" for record in records)

    def _allocate_descriptor(self, value: _Descriptor) -> int:
        descriptor = self.next_fd
        self.next_fd += 1
        self.next_inode += 1
        self.descriptors[descriptor] = value
        return descriptor


class MacOsPinnedCliSpikeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inputs: dict[str, bytes] = {
            "/private/target/debug/compatforge-cli": b"compatforge-cli",
            "/private/inputs/crossover-config.json": _canonical(
                {
                    "runtimeBindings": [
                        {
                            "executable": "/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine",
                            "wineserverExecutable": "/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wineserver",
                        }
                    ],
                    "storageRoot": "/private/storage",
                }
            ),
            "/private/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe": b"sumatra",
            "/private/inputs/crossover-mutation.exe": b"mutation",
            "/private/inputs/crossover-request.json": _canonical({"requestId": "pinned-sumatrapdf"}),
            "/private/inputs/whisky-config.json": _canonical(
                {
                    "runtimeBindings": [
                        {
                            "executable": "/Applications/Whisky.app/Contents/Frameworks/Wine/bin/wine64",
                            "wineserverExecutable": "/Applications/Whisky.app/Contents/Frameworks/Wine/bin/wineserver",
                        }
                    ],
                    "storageRoot": "/private/storage",
                }
            ),
            "/private/inputs/whisky-mutation.exe": b"mutation-two",
            "/private/inputs/whisky-request.json": _canonical({"requestId": "pinned-sumatrapdf"}),
        }
        logical = "/private/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe"
        self.manifest: dict[str, object] = {
            "cli": {"path": "/private/target/debug/compatforge-cli", "sha256": _sha256(self.inputs["/private/target/debug/compatforge-cli"])},
            "runtimes": [
                self._runtime("crossover", logical),
                self._runtime("whisky", logical),
            ],
            "schemaVersion": 1,
            "timeoutMilliseconds": 60000,
            "windowTitleTokens": ["SumatraPDF"],
        }

    def _runtime(self, runtime_id: str, logical: str) -> dict[str, object]:
        return {
            "config": {
                "path": f"/private/inputs/{runtime_id}-config.json",
                "sha256": _sha256(self.inputs[f"/private/inputs/{runtime_id}-config.json"]),
            },
            "logicalExecutable": {"path": logical, "sha256": _sha256(self.inputs[logical])},
            "mutationPayload": {
                "path": f"/private/inputs/{runtime_id}-mutation.exe",
                "sha256": _sha256(self.inputs[f"/private/inputs/{runtime_id}-mutation.exe"]),
            },
            "request": {
                "path": f"/private/inputs/{runtime_id}-request.json",
                "sha256": _sha256(self.inputs[f"/private/inputs/{runtime_id}-request.json"]),
            },
            "runtimeId": runtime_id,
            "workRoot": f"/private/work/{runtime_id}",
        }

    @staticmethod
    def _real_output_process(stdout_bytes: int, stderr_bytes: int, delay_seconds: float = 0.0) -> subprocess.Popen[bytes]:
        script = (
            "import os,sys,time;"
            "out=int(sys.argv[1]);err=int(sys.argv[2]);delay=float(sys.argv[3]);"
            "os.write(1,b'o'*out);os.write(2,b'e'*err);time.sleep(delay)"
        )
        return subprocess.Popen(
            [sys.executable, "-S", "-B", "-c", script, str(stdout_bytes), str(stderr_bytes), str(delay_seconds)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_manifest_is_canonical_closed_and_literal(self) -> None:
        self.assertEqual(spike.parse_manifest_bytes(_canonical(self.manifest)), self.manifest)
        mutants: list[bytes] = []
        extra = copy.deepcopy(self.manifest)
        extra["extra"] = True
        mutants.append(_canonical(extra))
        reversed_runtimes = copy.deepcopy(self.manifest)
        reversed_runtimes["runtimes"].reverse()  # type: ignore[union-attr]
        mutants.append(_canonical(reversed_runtimes))
        wrong_timeout = copy.deepcopy(self.manifest)
        wrong_timeout["timeoutMilliseconds"] = 59999
        mutants.append(_canonical(wrong_timeout))
        boolean_schema = copy.deepcopy(self.manifest)
        boolean_schema["schemaVersion"] = True
        mutants.append(_canonical(boolean_schema))
        mutants.append(json.dumps(self.manifest, indent=2).encode("utf-8"))
        mutants.append(_canonical(self.manifest).replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1'))
        for mutant in mutants:
            with self.subTest(mutant=mutant[:80]), self.assertRaises(spike.SpikeError):
                spike.parse_manifest_bytes(mutant)

    def test_complete_run_uses_exact_closed_command_and_live_window(self) -> None:
        boundary = _FakeBoundary(self.manifest, self.inputs)
        results = spike.run_spike_document(self.manifest, boundary)
        self.assertEqual(results, ["crossover", "whisky"])
        self.assertEqual(len(boundary.commands), 2)
        for index, runtime_id in enumerate(("crossover", "whisky")):
            runtime = self.manifest["runtimes"][index]  # type: ignore[index]
            command = boundary.commands[index]
            passed = boundary.pass_fds[index]
            self.assertEqual(
                command,
                (
                    "/private/target/debug/compatforge-cli",
                    "prepared-pinned-sumatrapdf-launch-terminate",
                    runtime["config"]["path"],  # type: ignore[index]
                    runtime["logicalExecutable"]["path"],  # type: ignore[index]
                    runtime["request"]["path"],  # type: ignore[index]
                    runtime["workRoot"],  # type: ignore[index]
                    str(passed[0]),
                    str(passed[1]),
                    str(passed[2]),
                    "60000",
                ),
            )
            self.assertEqual(len(passed), 3)
            self.assertEqual(len(set(passed)), 3)
            self.assertEqual(
                boundary.popen_options[index],
                {
                    "close_fds": True,
                    "cwd": None,
                    "env": {},
                    "shell": False,
                    "stdin": subprocess.DEVNULL,
                    "stdout": subprocess.PIPE,
                    "stderr": subprocess.PIPE,
                },
            )
        self.assertTrue(boundary.window_probe_saw_live_process)
        self.assertFalse(boundary.seek_while_live)
        self.assertEqual(len(boundary.closed), 6)
        self.assertGreaterEqual(len(boundary.revalidated_inputs), 14)

    def test_each_runtime_rejects_a_lingering_window_from_the_previous_run(self) -> None:
        class LingeringWindowBoundary(_FakeBoundary):
            def window_visible(self, tokens: tuple[str, ...]) -> bool:
                self.window_probe_calls += 1
                if not self.processes:
                    return False
                if self.processes[-1].poll() is None:
                    self.window_probe_saw_live_process = True
                return tokens == ("SumatraPDF",)

        boundary = LingeringWindowBoundary(self.manifest, self.inputs)

        with self.assertRaises(spike.SpikeError):
            spike.run_spike_document(self.manifest, boundary)

        self.assertEqual(len(boundary.commands), 1)
        self.assertGreater(boundary.window_probe_calls, 2)
        self.assertLessEqual(boundary.window_probe_calls, 16)

    def test_initial_and_cleanup_window_absence_checks_are_bounded(self) -> None:
        class InitialWindowBoundary(_FakeBoundary):
            def window_visible(self, tokens: tuple[str, ...]) -> bool:
                self.window_probe_calls += 1
                return tokens == ("SumatraPDF",)

        initial = InitialWindowBoundary(self.manifest, self.inputs)
        with self.assertRaises(spike.SpikeError):
            spike.run_spike_document(self.manifest, initial)
        self.assertEqual(initial.commands, [])
        self.assertGreater(initial.window_probe_calls, 1)
        self.assertLessEqual(initial.window_probe_calls, 16)

        class CleanupWindowBoundary(_FakeBoundary):
            def window_visible(self, tokens: tuple[str, ...]) -> bool:
                self.window_probe_calls += 1
                if not self.processes:
                    return False
                return tokens == ("SumatraPDF",)

        cleanup = CleanupWindowBoundary(self.manifest, self.inputs)
        cleanup.communication_timeout = True
        with self.assertRaises(spike.SpikeError):
            spike.run_spike_document(self.manifest, cleanup)
        self.assertTrue(cleanup.processes[0].killed)
        self.assertTrue(cleanup.processes[0].waited)
        self.assertGreater(cleanup.window_probe_calls, 2)
        self.assertLessEqual(cleanup.window_probe_calls, 17)

    def test_real_subprocess_output_capture_enforces_stdout_stderr_and_combined_cap_plus_one(self) -> None:
        limit = 131_072
        cases = (
            ("stdout-exact", limit, 0, limit, False),
            ("stderr-exact", 0, limit, limit, False),
            ("combined-exact", limit // 2, limit // 2, limit, False),
            ("stdout-over", limit + 1, 0, limit * 2, True),
            ("stderr-over", 0, limit + 1, limit * 2, True),
            ("combined-over", limit // 2, limit // 2 + 1, limit, True),
        )
        for label, stdout_size, stderr_size, combined_limit, rejected in cases:
            raw = self._real_output_process(stdout_size, stderr_size)
            assert raw.stdout is not None and raw.stderr is not None
            process = spike._SystemProcess(raw, ())
            capture = spike._BoundedOutputCapture(
                raw.stdout,
                raw.stderr,
                stdout_limit=limit,
                stderr_limit=limit,
                combined_limit=combined_limit,
            )
            with self.subTest(label=label):
                if rejected:
                    with self.assertRaises(spike.SpikeError):
                        spike._finish_process_output(process, capture, 5.0, spike.SystemClock())
                else:
                    stdout, stderr = spike._finish_process_output(process, capture, 5.0, spike.SystemClock())
                    self.assertEqual(len(stdout), stdout_size)
                    self.assertEqual(len(stderr), stderr_size)
                self.assertIsNotNone(raw.poll())
                self.assertTrue(raw.stdout.closed)
                self.assertTrue(raw.stderr.closed)
                self.assertTrue(capture.readers_joined)

    def test_output_timeout_and_reader_failure_terminate_reap_close_and_join_without_leaks(self) -> None:
        class FailingReader:
            def __init__(self, wrapped: object) -> None:
                self.wrapped = wrapped

            @property
            def closed(self) -> bool:
                return self.wrapped.closed  # type: ignore[no-any-return]

            def read(self, maximum: int) -> bytes:
                del maximum
                raise OSError("secret reader detail")

            def close(self) -> None:
                self.wrapped.close()

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always", ResourceWarning)
            timeout_raw = self._real_output_process(0, 0, 30.0)
            assert timeout_raw.stdout is not None and timeout_raw.stderr is not None
            timeout_process = spike._SystemProcess(timeout_raw, ())
            timeout_capture = spike._BoundedOutputCapture(timeout_raw.stdout, timeout_raw.stderr)
            with self.assertRaises(spike.SpikeError):
                spike._finish_process_output(timeout_process, timeout_capture, 0.05, spike.SystemClock())
            self.assertIsNotNone(timeout_raw.poll())
            self.assertTrue(timeout_capture.readers_joined)
            self.assertTrue(timeout_raw.stdout.closed)
            self.assertTrue(timeout_raw.stderr.closed)

            failure_raw = self._real_output_process(0, 0, 30.0)
            assert failure_raw.stdout is not None and failure_raw.stderr is not None
            failing_stdout = FailingReader(failure_raw.stdout)
            failure_process = spike._SystemProcess(failure_raw, ())
            failure_capture = spike._BoundedOutputCapture(failing_stdout, failure_raw.stderr)
            with self.assertRaises(spike.SpikeError) as raised:
                spike._finish_process_output(failure_process, failure_capture, 5.0, spike.SystemClock())
            self.assertNotIn("secret", str(raised.exception))
            self.assertIsNotNone(failure_raw.poll())
            self.assertTrue(failure_capture.readers_joined)
            self.assertTrue(failing_stdout.closed)
            self.assertTrue(failure_raw.stderr.closed)

            del timeout_process, timeout_capture, failure_process, failure_capture
            gc.collect()
        self.assertFalse([warning for warning in recorded if warning.category is ResourceWarning])

    def test_open_nonblocking_pipe_reader_can_be_cancelled_and_joined_without_a_writer_eof(self) -> None:
        read_descriptor, write_descriptor = os.pipe()
        os.set_blocking(read_descriptor, False)
        read_stream = os.fdopen(read_descriptor, "rb", buffering=0)
        empty_stderr = io.BytesIO()
        capture = spike._BoundedOutputCapture(read_stream, empty_stderr)
        try:
            time.sleep(0.02)
            self.assertFalse(capture.has_failed())
            started = time.monotonic()
            capture.cleanup(0.2)
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertTrue(capture.readers_joined)
            self.assertTrue(read_stream.closed)
        finally:
            os.close(write_descriptor)

    def test_output_descriptors_are_anonymous_distinct_empty_mode_0600_rdwr_without_append(self) -> None:
        mutants = {
            "named": {"named_output": True},
            "read-only": {"output_access_mode": os.O_RDONLY},
            "write-only": {"output_access_mode": os.O_WRONLY},
            "append": {"output_append": True},
            "mode": {"output_mode": 0o640},
            "nonempty": {"output_initial_size": 1},
            "alias": {"alias_outputs": True},
        }
        for label, changes in mutants.items():
            boundary = _FakeBoundary(self.manifest, self.inputs)
            for name, value in changes.items():
                setattr(boundary, name, value)
            with self.subTest(label=label), self.assertRaises(spike.SpikeError):
                spike.run_spike_document(self.manifest, boundary)
            self.assertEqual(boundary.commands, [])

    def test_omitted_or_extra_inherited_fd_is_fatal_and_reaps_child(self) -> None:
        for field in ("omit_pass_fd", "extra_pass_fd"):
            boundary = _FakeBoundary(self.manifest, self.inputs)
            setattr(boundary, field, True)
            with self.subTest(field=field), self.assertRaises(spike.SpikeError):
                spike.run_spike_document(self.manifest, boundary)
            self.assertTrue(boundary.processes[0].killed)
            self.assertTrue(boundary.processes[0].waited)

    def test_window_communication_and_child_failure_paths_are_bounded_and_reaped(self) -> None:
        for field, value in (
            ("window_missing", True),
            ("communication_timeout", True),
            ("returncode", 1),
            ("stderr", b"unexpected"),
        ):
            boundary = _FakeBoundary(self.manifest, self.inputs)
            setattr(boundary, field, value)
            with self.subTest(field=field), self.assertRaises(spike.SpikeError):
                spike.run_spike_document(self.manifest, boundary)
            self.assertTrue(boundary.processes[0].killed or boundary.processes[0].poll() is not None)

    def test_runtime_event_and_receipt_mutants_fail_closed(self) -> None:
        cases = (
            ("event_mutant", "malformed"),
            ("event_mutant", "nonterminal"),
            ("event_mutant", "after-terminal-event"),
            ("event_mutant", "path-leak"),
            ("event_mutant", "wrong-message"),
            ("event_mutant", "no-start"),
            ("event_mutant", "elapsed-negative"),
            ("event_mutant", "sequence-bool"),
            ("event_mutant", "explicit-null-message"),
            ("event_mutant", "explicit-null-exit-code"),
            ("event_mutant", "process-id-bool"),
            ("event_mutant", "process-id-overflow"),
            ("event_mutant", "exit-code-bool"),
            ("event_mutant", "exit-code-positive-overflow"),
            ("event_mutant", "exit-code-negative-overflow"),
            ("receipt_mutant", "missing"),
            ("receipt_mutant", "not-last"),
            ("receipt_mutant", "digest"),
            ("receipt_mutant", "size"),
            ("receipt_mutant", "order"),
            ("receipt_mutant", "extra-key"),
            ("receipt_mutant", "schema-bool"),
        )
        for field, value in cases:
            boundary = _FakeBoundary(self.manifest, self.inputs)
            setattr(boundary, field, value)
            with self.subTest(field=field, value=value), self.assertRaises(spike.SpikeError):
                spike.run_spike_document(self.manifest, boundary)

    def test_runtime_event_integer_boundaries_are_accepted(self) -> None:
        for value in ("process-id-max", "exit-code-max", "exit-code-min"):
            boundary = _FakeBoundary(self.manifest, self.inputs)
            boundary.event_mutant = value
            with self.subTest(value=value):
                self.assertEqual(spike.run_spike_document(self.manifest, boundary), ["crossover", "whisky"])

    def test_output_bound_canonical_readback_and_close_failure_are_fatal(self) -> None:
        for field in ("oversized_output", "close_failure"):
            boundary = _FakeBoundary(self.manifest, self.inputs)
            setattr(boundary, field, True)
            with self.subTest(field=field), self.assertRaises(spike.SpikeError):
                spike.run_spike_document(self.manifest, boundary)
        boundary = _FakeBoundary(self.manifest, self.inputs)
        boundary.plan_bytes = b'{"schemaVersion": "1"}'
        with self.assertRaises(spike.SpikeError):
            spike.run_spike_document(self.manifest, boundary)

    def test_postspawn_output_identity_or_link_drift_is_fatal(self) -> None:
        for field in ("post_spawn_identity_drift", "post_spawn_linked_output"):
            boundary = _FakeBoundary(self.manifest, self.inputs)
            setattr(boundary, field, True)
            with self.subTest(field=field), self.assertRaises(spike.SpikeError):
                spike.run_spike_document(self.manifest, boundary)

    def test_work_roots_are_distinct_external_and_nonoverlapping(self) -> None:
        mutants = []
        duplicate = copy.deepcopy(self.manifest)
        duplicate["runtimes"][1]["workRoot"] = "/private/work/crossover"  # type: ignore[index]
        mutants.append(duplicate)
        repository = copy.deepcopy(self.manifest)
        repository["runtimes"][0]["workRoot"] = "/repo/spike"  # type: ignore[index]
        mutants.append(repository)
        storage = copy.deepcopy(self.manifest)
        storage["runtimes"][0]["workRoot"] = "/private/storage/spike"  # type: ignore[index]
        mutants.append(storage)
        for mutant in mutants:
            boundary = _FakeBoundary(mutant, self.inputs)
            with self.assertRaises(spike.SpikeError):
                spike.run_spike_document(mutant, boundary)
            self.assertEqual(boundary.commands, [])

    def test_runtime_binary_roots_reject_descendants_and_physical_aliases_but_not_siblings(self) -> None:
        runtime_parent = "/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin"

        descendant = copy.deepcopy(self.manifest)
        descendant["runtimes"][0]["workRoot"] = runtime_parent + "/work"  # type: ignore[index]
        boundary = _FakeBoundary(descendant, self.inputs)
        with self.assertRaises(spike.SpikeError):
            spike.run_spike_document(descendant, boundary)
        self.assertEqual(boundary.commands, [])

        alias = copy.deepcopy(self.manifest)
        alias_root = alias["runtimes"][0]["workRoot"]  # type: ignore[index]
        boundary = _FakeBoundary(alias, self.inputs)
        boundary.physical_overlaps.add(frozenset((alias_root, runtime_parent)))
        with self.assertRaises(spike.SpikeError):
            spike.run_spike_document(alias, boundary)
        self.assertEqual(boundary.commands, [])

        sibling = copy.deepcopy(self.manifest)
        sibling["runtimes"][0]["workRoot"] = runtime_parent.rsplit("/", 1)[0] + "/work"  # type: ignore[index]
        boundary = _FakeBoundary(sibling, self.inputs)
        self.assertEqual(spike.run_spike_document(sibling, boundary), ["crossover", "whisky"])

    def test_system_overlap_probe_detects_directory_symlink_alias_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            protected = Path(temporary, "runtime-bin")
            protected.mkdir()
            alias = Path(temporary, "runtime-bin-alias")
            try:
                alias.symlink_to(protected, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlink is unavailable: {error}")

            self.assertTrue(spike.SystemBoundary.paths_physically_overlap(str(alias), str(protected)))
            self.assertFalse(
                spike.SystemBoundary.paths_physically_overlap(
                    str(Path(temporary, "external-a")),
                    str(Path(temporary, "external-b")),
                )
            )

    def test_every_input_digest_is_bound_before_launch(self) -> None:
        mutant = copy.deepcopy(self.manifest)
        mutant["cli"]["sha256"] = "sha256:" + "0" * 64  # type: ignore[index]
        boundary = _FakeBoundary(mutant, self.inputs)
        with self.assertRaises(spike.SpikeError):
            spike.run_spike_document(mutant, boundary)
        self.assertEqual(boundary.commands, [])

    def test_consecutive_runs_never_reuse_descriptors_identities_or_stale_bytes(self) -> None:
        boundary = _FakeBoundary(self.manifest, self.inputs)
        spike.run_spike_document(self.manifest, boundary)
        first_fds = set(boundary.closed)
        first_identities = set(boundary.created_identities)
        boundary.closed.clear()
        boundary.created_identities.clear()
        boundary.inspection_bytes = _canonical({"architecture": "x86_64", "run": 2})
        spike.run_spike_document(self.manifest, boundary)
        self.assertTrue(first_fds.isdisjoint(boundary.closed))
        self.assertTrue(first_identities.isdisjoint(boundary.created_identities))

    def test_source_mutation_is_absent_and_postrun_revalidation_detects_drift(self) -> None:
        boundary = _FakeBoundary(self.manifest, self.inputs)
        original = dict(self.inputs)
        spike.run_spike_document(self.manifest, boundary)
        self.assertEqual(self.inputs, original)

        class DriftBoundary(_FakeBoundary):
            def revalidate_input(self, binding: spike.FileBinding) -> None:
                if self.processes and binding.path.endswith("SumatraPDF.exe"):
                    self.inputs[binding.path] = b"drift"
                super().revalidate_input(binding)

        drift = DriftBoundary(self.manifest, dict(self.inputs))
        with self.assertRaises(spike.SpikeError):
            spike.run_spike_document(self.manifest, drift)

    def test_module_has_no_runner_acknowledgement_or_network_side_effect(self) -> None:
        source = spike.__file__ and spike.Path(spike.__file__).read_text(encoding="utf-8")
        self.assertIsInstance(source, str)
        self.assertNotIn("run_gui_baseline", source)
        self.assertNotIn("confirm_macos_gui_interactions", source)
        self.assertNotIn("urllib", source)
        self.assertNotIn("requests", source)
        self.assertNotIn("socket", source)


if __name__ == "__main__":
    unittest.main()
