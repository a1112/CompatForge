from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import unittest
from dataclasses import dataclass

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
        self.waited = False

    def poll(self) -> int | None:
        return self.returncode

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        del timeout
        if self.boundary.communication_timeout:
            raise subprocess.TimeoutExpired(self.argv, 1)
        self.returncode = self.boundary.returncode
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
        return self.boundary.transcript(inspection, plan), self.boundary.stderr

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.waited = True
        if self.returncode is None:
            self.returncode = -9
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
        self.inspection_bytes = _canonical({"architecture": "x86_64", "kind": "inspection"})
        self.plan_bytes = _canonical({"process": {"arguments": ["logical"]}, "schemaVersion": "1"})

    def resolve_canonical(self, path: str, *, directory: bool) -> str:
        del directory
        return path

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
        self.window_probe_saw_live_process = bool(self.processes and self.processes[-1].poll() is None)
        return not self.window_missing and tokens == ("SumatraPDF",)

    def sleep(self, seconds: float) -> None:
        del seconds

    def monotonic(self) -> float:
        return float(self.window_probe_calls)

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
            "processId": 4242,
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
                    "runtime": "/Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wine",
                    "storageRoot": "/private/storage",
                }
            ),
            "/private/storage/bottles/gui-sumatrapdf/prefix/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe": b"sumatra",
            "/private/inputs/crossover-mutation.exe": b"mutation",
            "/private/inputs/crossover-request.json": _canonical({"requestId": "pinned-sumatrapdf"}),
            "/private/inputs/whisky-config.json": _canonical(
                {
                    "runtime": "/Applications/Whisky.app/Contents/Frameworks/Wine/bin/wine64",
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
            ("receipt_mutant", "missing"),
            ("receipt_mutant", "not-last"),
            ("receipt_mutant", "digest"),
            ("receipt_mutant", "size"),
            ("receipt_mutant", "order"),
            ("receipt_mutant", "extra-key"),
        )
        for field, value in cases:
            boundary = _FakeBoundary(self.manifest, self.inputs)
            setattr(boundary, field, value)
            with self.subTest(field=field, value=value), self.assertRaises(spike.SpikeError):
                spike.run_spike_document(self.manifest, boundary)

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
