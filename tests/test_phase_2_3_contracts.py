from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
PROBE_TOOL = TOOLS / "validate_capability_probe.py"
INSTALL_TOOL = TOOLS / "validate_install_request.py"
PROBE_RUNNER = TOOLS / "run_macos_capability_probe.py"
WIN32_PROBE_SOURCE = ROOT / "tests" / "fixtures" / "windows_gui_probe.c"
SCHEMAS = (
    ROOT / "schemas" / "capability-probe-manifest.schema.json",
    ROOT / "schemas" / "capability-probe-result.schema.json",
    ROOT / "schemas" / "install-request.schema.json",
)
sys.path.insert(0, str(TOOLS))


def load_tool(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = module
    spec.loader.exec_module(module)
    return module


class Phase23ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.probe = load_tool(PROBE_TOOL)
        cls.install = load_tool(INSTALL_TOOL)

    def manifest(self) -> dict[str, object]:
        return {
            "schemaVersion": "1",
            "probeId": "win32-window-text-x64",
            "displayName": "Win32 window and CJK text x64",
            "category": "win32",
            "guestArchitecture": "x86_64",
            "source": {
                "repository": "https://github.com/example/compatforge-probes",
                "commit": "c" * 40,
                "path": "probes/win32-window-text.c",
                "sha256": "a" * 64,
            },
            "build": {
                "toolchain": "llvm-mingw",
                "toolchainVersion": "fixture-1",
                "arguments": ["-mwindows", "-Werror"],
            },
            "artifact": {
                "fileName": "win32-window-text-x64.exe",
                "sha256": "b" * 64,
                "sizeBytes": 4096,
                "architecture": "x86_64",
                "subsystem": "windowsGui",
            },
            "requiredObservations": ["window-created", "cjk-text-readable"],
        }

    def result(self, manifest: dict[str, object]) -> dict[str, object]:
        return {
            "schemaVersion": "1",
            "runId": "11111111-2222-4333-8444-555555555555",
            "probeId": manifest["probeId"],
            "probeManifestDigest": self.probe.canonical_digest(manifest),
            "artifactDigest": "sha256:" + "b" * 64,
            "testSuiteVersion": "cross-host-capability-v3",
            "host": {
                "os": "macos",
                "version": "26.0",
                "architecture": "arm64",
                "displayProtocol": "appkit",
                "gpu": "fixture-gpu",
                "driver": "fixture-driver",
            },
            "runtimePackDigest": "sha256:" + "d" * 64,
            "translator": "rosetta",
            "graphicsBackend": "wined3d",
            "guestArchitecture": "x86_64",
            "outcome": "passed",
            "startedAt": "2026-08-18T10:00:00Z",
            "finishedAt": "2026-08-18T10:00:05Z",
            "observations": {
                "window-created": True,
                "cjk-text-readable": True,
            },
            "checks": [
                {"id": "launch", "outcome": "passed"},
                {"id": "exit", "outcome": "passed"},
                {"id": "no-residual-processes", "outcome": "passed"},
            ],
            "artifacts": [
                {
                    "name": "probe.png",
                    "sha256": "sha256:" + "e" * 64,
                    "sizeBytes": 8192,
                }
            ],
        }

    def install_request(self) -> dict[str, object]:
        return {
            "schemaVersion": "1",
            "requestId": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "bottleId": "msi-smoke-x64",
            "recipeId": "probe.msi-install-smoke",
            "package": {
                "path": "/external/fixtures/msi-install-smoke.msi",
                "fileName": "msi-install-smoke.msi",
                "sha256": "f" * 64,
                "sizeBytes": 16384,
                "mediaType": "application/x-msi",
            },
            "handler": {
                "kind": "msiexec",
                "action": "install",
                "ui": "none",
                "reboot": "suppress",
                "properties": {"INSTALLFOLDER": "C:\\CompatForgeProbe"},
            },
            "constraints": {
                "allowVirtualMachine": False,
                "allowRemote": False,
                "networkPolicy": "deny",
                "maximumRuntimeMilliseconds": 120000,
            },
        }

    def test_schemas_are_closed_and_unique(self) -> None:
        identifiers = []
        for path in SCHEMAS:
            value = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(value["additionalProperties"])
            identifiers.append(value["$id"])
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_probe_manifest_and_result_are_cross_bound(self) -> None:
        manifest = self.probe.validate_manifest(self.manifest())
        result = self.probe.validate_result(self.result(manifest), manifest)
        self.assertEqual(result["outcome"], "passed")

    def test_probe_manifest_rejects_traversal_and_architecture_drift(self) -> None:
        traversal = self.manifest()
        traversal["source"]["path"] = "../probe.c"
        with self.assertRaises(self.probe.ContractError):
            self.probe.validate_manifest(traversal)

        architecture = self.manifest()
        architecture["artifact"]["architecture"] = "i386"
        with self.assertRaises(self.probe.ContractError):
            self.probe.validate_manifest(architecture)

    def test_probe_result_rejects_digest_drift_duplicates_and_missing_observation(self) -> None:
        manifest = self.probe.validate_manifest(self.manifest())
        drift = self.result(manifest)
        drift["artifactDigest"] = "sha256:" + "0" * 64
        with self.assertRaises(self.probe.ContractError):
            self.probe.validate_result(drift, manifest)

        duplicate = self.result(manifest)
        duplicate["checks"].append(dict(duplicate["checks"][0]))
        with self.assertRaises(self.probe.ContractError):
            self.probe.validate_result(duplicate, manifest)

        incomplete = self.result(manifest)
        del incomplete["observations"]["cjk-text-readable"]
        with self.assertRaises(self.probe.ContractError):
            self.probe.validate_result(incomplete, manifest)

    def test_non_passed_probe_result_requires_closed_classification(self) -> None:
        manifest = self.probe.validate_manifest(self.manifest())
        result = self.result(manifest)
        result["outcome"] = "unsupported"
        result["failureClassification"] = "unsupported"
        result["observations"] = {}
        result["checks"] = [
            {"id": "launch", "outcome": "skipped"},
            {"id": "exit", "outcome": "skipped"},
            {"id": "no-residual-processes", "outcome": "passed"},
        ]
        self.probe.validate_result(result, manifest)
        result["failureClassification"] = "graphics"
        with self.assertRaises(self.probe.ContractError):
            self.probe.validate_result(result, manifest)

    def test_probe_cli_validates_absolute_bounded_documents(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-probe-contract-") as temporary:
            root = Path(temporary)
            manifest_path = root / "manifest.json"
            result_path = root / "result.json"
            manifest = self.manifest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            result_path.write_text(json.dumps(self.result(manifest)), encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-S", "-B", str(PROBE_TOOL), str(manifest_path), "--result", str(result_path)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(completed.stdout)["resultValidated"])

    def test_install_request_is_semantic_and_contains_no_arbitrary_argv(self) -> None:
        value = self.install.validate_install_request(self.install_request())
        self.assertEqual(value["handler"]["kind"], "msiexec")
        self.assertNotIn("arguments", value["handler"])

    def test_install_request_rejects_relative_path_arbitrary_fields_and_network_allow(self) -> None:
        relative = self.install_request()
        relative["package"]["path"] = "fixture.msi"
        with self.assertRaises(self.probe.ContractError):
            self.install.validate_install_request(relative)

        mismatched_name = self.install_request()
        mismatched_name["package"]["fileName"] = "different.msi"
        with self.assertRaises(self.probe.ContractError):
            self.install.validate_install_request(mismatched_name)

        arbitrary = self.install_request()
        arbitrary["handler"]["arguments"] = ["/i", "https://example.invalid/payload.msi"]
        with self.assertRaises(self.probe.ContractError):
            self.install.validate_install_request(arbitrary)

        network = self.install_request()
        network["constraints"]["networkPolicy"] = "allow"
        with self.assertRaises(self.probe.ContractError):
            self.install.validate_install_request(network)

    def test_install_request_cli_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-install-contract-") as temporary:
            path = Path(temporary) / "request.json"
            path.write_text(json.dumps(self.install_request()), encoding="utf-8")
            before = path.read_bytes()
            completed = subprocess.run(
                [sys.executable, "-S", "-B", str(INSTALL_TOOL), str(path)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(json.loads(completed.stdout)["handler"], "msiexec")

    def test_win32_probe_source_and_runner_keep_the_prepared_launch_boundary(self) -> None:
        source = WIN32_PROBE_SOURCE.read_text(encoding="utf-8")
        for symbol in (
            "CreateWindowExW",
            "CreateFontW",
            'L"Heiti SC"',
            "SelectObject",
            "DrawTextW",
            "CompatForge Win32 Probe",
            "ShowWindow(window, SW_SHOW)",
            "WM_PAINT",
            "WM_DESTROY",
        ):
            self.assertIn(symbol, source)
        for forbidden in ("WinHttp", "URLDownload", "ShellExecute", "system("):
            self.assertNotIn(forbidden, source)
        runner = PROBE_RUNNER.read_text(encoding="utf-8")
        for boundary in (
            '"prepared-plan"',
            '"prepared-launch-terminate"',
            '"immutableArtifact"',
            '"networkPolicy": "deny"',
            "process_snapshot",
            "validate_result",
        ):
            self.assertIn(boundary, runner)
        self.assertNotIn("shell=True", runner)
        self.assertNotIn("urllib", runner)

        repository_validator = (ROOT / "scripts" / "validate_repository.py").read_text(encoding="utf-8")
        for schema in SCHEMAS:
            self.assertIn(f'"{schema.name}"', repository_validator)


if __name__ == "__main__":
    unittest.main()
