from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
import argparse
import json
import subprocess
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE_TOOL = ROOT / "tools" / "run_macos_dual_runtime_acceptance.py"
VALIDATOR = ROOT / "scripts" / "validate_repository.py"

EXPECTED_MATRIX = {
    "crossover": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
    "whisky": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
}
EXPECTED_REVIEWED_PATHS = (
    "tests/test_macos_dual_runtime_acceptance.py",
    "tools/run_macos_dual_runtime_acceptance.py",
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


acceptance = load_module("run_macos_dual_runtime_acceptance", ACCEPTANCE_TOOL)
validator = load_module("validate_repository_for_macos_acceptance", VALIDATOR)


class MacOsDualRuntimeAcceptanceContractTests(unittest.TestCase):
    def test_acceptance_matrix_is_exact_and_has_two_rounds(self) -> None:
        self.assertEqual(acceptance.RUNTIME_MATRIX, EXPECTED_MATRIX)
        self.assertEqual(acceptance.ROUNDS, ("round-1", "round-2"))

        expanded = tuple(
            (round_id, runtime_id, application_id)
            for round_id in acceptance.ROUNDS
            for runtime_id, application_ids in acceptance.RUNTIME_MATRIX.items()
            for application_id in application_ids
        )
        self.assertEqual(len(expanded), 16)
        self.assertEqual(len(set(expanded)), 16)

    def test_python_preflight_rejects_unsupported_interpreters(self) -> None:
        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "^Python 3[.]11 or newer is required$"
        ):
            acceptance.require_python((3, 9, 11))

    def test_python_preflight_accepts_supported_interpreters(self) -> None:
        self.assertIsNone(acceptance.require_python((3, 11, 0)))
        self.assertIsNone(acceptance.require_python((3, 12, 13)))

    def test_repository_validator_binds_the_reviewed_acceptance_surface(self) -> None:
        self.assertEqual(
            validator.MACOS_ACCEPTANCE_REVIEWED_PATHS,
            EXPECTED_REVIEWED_PATHS,
        )
        self.assertEqual(validator.validate_macos_acceptance_surface(), [])

    def test_repository_validator_rejects_an_ancestor_link(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-macos-acceptance-validator-"
        ) as temporary:
            temporary_root = Path(temporary)
            repository_root = temporary_root / "repository"
            tests_root = repository_root / "tests"
            external_tools = temporary_root / "external-tools"
            tests_root.mkdir(parents=True)
            external_tools.mkdir()
            (tests_root / "test_macos_dual_runtime_acceptance.py").write_text(
                "# test fixture\n", encoding="utf-8"
            )
            (external_tools / "run_macos_dual_runtime_acceptance.py").write_text(
                "# external fixture\n", encoding="utf-8"
            )
            try:
                os.symlink(
                    external_tools,
                    repository_root / "tools",
                    target_is_directory=True,
                )
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")

            with mock.patch.object(validator, "ROOT", repository_root):
                errors = validator.validate_macos_acceptance_surface()

            self.assertEqual(len(errors), 1)
            self.assertIn("tools/run_macos_dual_runtime_acceptance.py", errors[0])
            self.assertIn("unsafe path component", errors[0])


class MacOsDualRuntimeOrchestratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="compatforge-dual-runtime-orchestrator-"
        )
        self.external = Path(self.temporary.name).resolve()
        self.tools = self.external / "built-tools"
        self.tools.mkdir()
        self.cli = self._tool("compatforge-cli")
        self.desktop = self._tool("CompatForge")
        self.cc = self._tool("x86_64-w64-mingw32-gcc")
        self.cache = self.external / "cache"
        self.cache.mkdir()
        self.runtime_store = self.external / "runtime-stores"
        self.storage = self.external / "storage"
        self.work = self.external / "work"
        self.interactions = self.external / "interactions"
        self._write_interactions()
        self.runtime_roots: dict[str, Path] = {}
        for runtime_id in ("crossover", "whisky"):
            runtime_root = self.external / f"{runtime_id}-runtime"
            (runtime_root / "bin").mkdir(parents=True)
            self._tool_at(runtime_root / "bin" / "wine")
            self._tool_at(runtime_root / "bin" / "wineserver")
            self.runtime_roots[runtime_id] = runtime_root

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _tool_at(self, path: Path) -> Path:
        path.write_text("fixture\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def _tool(self, name: str) -> Path:
        return self._tool_at(self.tools / name)

    def _write_interactions(self) -> None:
        document = {
            "schemaVersion": "1",
            "applications": {
                "7zip": {"fileList": True, "menus": True},
                "sumatrapdf": {"mainWindow": True, "openDialog": True},
                "notepad-plus-plus": {
                    "open": True,
                    "edit": True,
                    "saveUtf8Chinese": True,
                    "rereadMatches": True,
                },
            },
        }
        for round_id in ("round-1", "round-2"):
            round_root = self.interactions / round_id
            round_root.mkdir(parents=True)
            for runtime_id in ("crossover", "whisky"):
                (round_root / f"{runtime_id}.json").write_text(
                    json.dumps(document), encoding="utf-8"
                )

    def _argv(self, *extra: str) -> list[str]:
        return [
            "--compatforge-cli",
            str(self.cli),
            "--desktop-app",
            str(self.desktop),
            "--cc",
            str(self.cc),
            "--cache-root",
            str(self.cache),
            "--runtime-store-root",
            str(self.runtime_store),
            "--storage-root",
            str(self.storage),
            "--work-root",
            str(self.work),
            "--interaction-evidence-root",
            str(self.interactions),
            *extra,
        ]

    def _arguments(self, *extra: str) -> argparse.Namespace:
        return acceptance.parse_arguments(self._argv(*extra))

    def _discovery(self) -> dict[str, object]:
        return {
            "schemaVersion": "1",
            "runtimes": [
                {
                    "schemaVersion": "1",
                    "runtimeId": runtime_id,
                    "source": f"{runtime_id}-app",
                    "materializedRoot": str(self.runtime_roots[runtime_id]),
                    "wine": "bin/wine",
                    "wineserver": "bin/wineserver",
                    "version": "24.0" if runtime_id == "crossover" else "2.3",
                    "architecture": "x86_64",
                }
                for runtime_id in ("crossover", "whisky")
            ],
        }

    @staticmethod
    def _console_summary(runtime_id: str) -> dict[str, object]:
        return {
            "schemaVersion": "1",
            "packId": f"wine-macos-{runtime_id}-preview",
            "packVersion": "24.0" if runtime_id == "crossover" else "2.3",
            "packDigest": "sha256:" + "a" * 64,
            "guestDigest": "sha256:" + "b" * 64,
            "hostArchitecture": "arm64",
            "runtime": "wine",
            "runtimeSource": "explicit",
            "translator": "rosetta",
            "graphics": "wined3d",
            "eventKinds": ["started", "stdout", "exited"],
            "exitCode": 0,
            "success": True,
        }

    @staticmethod
    def _gui_summary(runtime_id: str) -> dict[str, object]:
        checks = {
            "7zip": {"fileList": True, "menus": True},
            "sumatrapdf": {"mainWindow": True, "openDialog": True},
            "notepad-plus-plus": {
                "open": True,
                "edit": True,
                "saveUtf8Chinese": True,
                "rereadMatches": True,
            },
        }
        return {
            "schemaVersion": "1",
            "receipt": {
                "schemaVersion": "1",
                "runtimeId": runtime_id,
                "packId": f"local-{runtime_id}",
                "version": "24.0" if runtime_id == "crossover" else "2.3",
                "packDigest": "sha256:" + "c" * 64,
                "source": f"{runtime_id}-app",
            },
            "applications": [
                {
                    "schemaVersion": "1",
                    "runtimeId": runtime_id,
                    "appId": app_id,
                    "status": "accepted",
                    "cleanup": True,
                    "interactionChecks": checks[app_id],
                    "exit": {"present": True, "code": 0, "success": True},
                    "windowAvailable": True,
                    "screenshotAvailable": True,
                }
                for app_id in ("7zip", "sumatrapdf", "notepad-plus-plus")
            ],
        }

    def test_closed_parser_rejects_missing_duplicate_unknown_positional_and_empty(self) -> None:
        invalid_argv = (
            self._argv()[:-2],
            self._argv("--work-root", str(self.external / "other")),
            self._argv("--unknown"),
            [*self._argv(), "positional"],
            [*self._argv()[:-1], ""],
            self._argv("--allow-network", "--allow-network"),
        )
        for argv in invalid_argv:
            with self.subTest(argv=argv), self.assertRaises(acceptance.AcceptanceError):
                acceptance.parse_arguments(argv)

        parsed = self._arguments("--allow-network")
        self.assertTrue(parsed.allow_network)

    def test_preflight_is_pure_and_rejects_unsafe_or_incomplete_inputs(self) -> None:
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        self.assertFalse(self.work.exists())
        self.assertEqual(paths.work_root, self.work)

        self.work.mkdir()
        (self.work / "foreign").write_text("do not delete", encoding="utf-8")
        with self.assertRaisesRegex(acceptance.AcceptanceError, "work-root must be empty"):
            acceptance.preflight(
                self._arguments(), host_system="Darwin", host_machine="arm64"
            )
        (self.work / "foreign").unlink()
        self.work.rmdir()

        for root, label in (
            (self.runtime_store, "runtime-store-root"),
            (self.storage, "storage-root"),
        ):
            root.mkdir()
            (root / "foreign").write_text("do not delete", encoding="utf-8")
            with self.subTest(label=label), self.assertRaisesRegex(
                acceptance.AcceptanceError, f"{label} must be empty"
            ):
                acceptance.preflight(
                    self._arguments(), host_system="Darwin", host_machine="arm64"
                )
            (root / "foreign").unlink()
            root.rmdir()

        (self.interactions / "round-2" / "whisky.json").unlink()
        with self.assertRaisesRegex(acceptance.AcceptanceError, "interaction evidence"):
            acceptance.preflight(
                self._arguments(), host_system="Darwin", host_machine="arm64"
            )
        (self.interactions / "round-2" / "whisky.json").write_text(
            (self.interactions / "round-1" / "whisky.json").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (self.interactions / "extra.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(acceptance.AcceptanceError, "too many entries"):
            acceptance.preflight(
                self._arguments(), host_system="Darwin", host_machine="arm64"
            )

    def test_preflight_rejects_overlap_symlink_and_wrong_platform(self) -> None:
        with self.assertRaisesRegex(acceptance.AcceptanceError, "Darwin/arm64"):
            acceptance.preflight(
                self._arguments(), host_system="Windows", host_machine="AMD64"
            )

        overlapping = self._argv()
        overlapping[overlapping.index("--storage-root") + 1] = str(self.runtime_store / "nested")
        with self.assertRaisesRegex(acceptance.AcceptanceError, "overlap"):
            acceptance.preflight(
                acceptance.parse_arguments(overlapping),
                host_system="Darwin",
                host_machine="arm64",
            )

        link = self.external / "work-link"
        try:
            os.symlink(self.external / "real-work", link, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"directory symlinks are unavailable: {error}")
        linked = self._argv()
        linked[linked.index("--work-root") + 1] = str(link)
        with self.assertRaisesRegex(acceptance.AcceptanceError, "unsafe path component"):
            acceptance.preflight(
                acceptance.parse_arguments(linked),
                host_system="Darwin",
                host_machine="arm64",
            )

    def test_orchestration_has_exact_order_argv_layout_and_one_discovery(self) -> None:
        calls: list[tuple[list[str], dict[str, object]]] = []
        desktop_calls: list[tuple[list[str], dict[str, object]]] = []
        desktop_timeouts: list[int] = []
        printed: list[str] = []
        source_snapshots = {
            path: path.read_bytes()
            for path in (
                self.cli,
                self.desktop,
                self.cc,
                *(root / "bin" / name for root in self.runtime_roots.values() for name in ("wine", "wineserver")),
                *(self.interactions / round_id / f"{runtime_id}.json" for round_id in ("round-1", "round-2") for runtime_id in ("crossover", "whisky")),
            )
        }

        def runner(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append((list(argv), dict(kwargs)))
            if argv[-1] == "--all":
                payload = self._discovery()
            elif str(argv[3]).endswith("run_macos_headless_preview.py"):
                pack_id = argv[argv.index("--pack-id") + 1]
                runtime_id = "crossover" if "crossover" in pack_id else "whisky"
                payload = self._console_summary(runtime_id)
            else:
                runtime_id = argv[argv.index("--runtime-id") + 1]
                payload = self._gui_summary(runtime_id)
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

        def launcher(argv: list[str], **kwargs: object) -> object:
            desktop_calls.append((list(argv), dict(kwargs)))
            return object()

        def waiter(_process: object, timeout: int) -> int:
            desktop_timeouts.append(timeout)
            return 0

        summary = acceptance.orchestrate(
            self._arguments(),
            runner=runner,
            launcher=launcher,
            waiter=waiter,
            host_system="Darwin",
            host_machine="arm64",
            printer=printed.append,
        )

        self.assertEqual(len([argv for argv, _ in calls if argv[-1] == "--all"]), 1)
        self.assertEqual(len(calls), 9)
        self.assertEqual(len(desktop_calls), 4)
        self.assertEqual(desktop_timeouts, [acceptance.DESKTOP_TIMEOUT_SECONDS] * 4)
        self.assertEqual(
            [Path(argv[3]).name for argv, _kwargs in calls],
            [
                "discover_macos_wine.py",
                "run_macos_headless_preview.py",
                "run_gui_baseline.py",
                "run_macos_headless_preview.py",
                "run_gui_baseline.py",
                "run_macos_headless_preview.py",
                "run_gui_baseline.py",
                "run_macos_headless_preview.py",
                "run_gui_baseline.py",
            ],
        )
        self.assertEqual(
            [entry["roundId"] for entry in summary["rounds"]],
            ["round-1", "round-2"],
        )
        self.assertEqual(
            sum(
                len(runtime["applications"])
                for round_entry in summary["rounds"]
                for runtime in round_entry["runtimes"]
            ),
            16,
        )

        expected_dirs = {
            self.work / round_id / runtime_id / phase
            for round_id in ("round-1", "round-2")
            for runtime_id in ("crossover", "whisky")
            for phase in ("console", "gui", "desktop")
        }
        actual_dirs = {path for path in self.work.rglob("*") if path.is_dir()}
        structural_dirs = {
            path
            for path in actual_dirs
            if path.name in {"console", "gui", "desktop"}
        }
        self.assertEqual(structural_dirs, expected_dirs)

        for index, (argv, kwargs) in enumerate(calls):
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["env"], acceptance.CHILD_ENV)
            self.assertEqual(
                kwargs["timeout"],
                acceptance.DISCOVERY_TIMEOUT_SECONDS
                if index == 0
                else acceptance.CHILD_TIMEOUT_SECONDS,
            )
            if index == 0:
                continue
            for flag in ("--wine-root", "--wine", "--wineserver", "--version"):
                self.assertEqual(argv.count(flag), 1)
            runtime_id = "crossover" if "crossover" in argv[argv.index("--wine-root") + 1] else "whisky"
            self.assertEqual(
                argv[argv.index("--wine-root") + 1], str(self.runtime_roots[runtime_id])
            )
            self.assertEqual(argv[argv.index("--wine") + 1], "bin/wine")
            self.assertEqual(argv[argv.index("--wineserver") + 1], "bin/wineserver")
            if "--runtime-id" in argv:
                self.assertEqual(argv[argv.index("--runtime-id") + 1], runtime_id)
                interaction = Path(argv[argv.index("--interaction-evidence") + 1])
                self.assertEqual(interaction.name, f"{runtime_id}.json")
                self.assertNotIn("--allow-network", argv)
        for argv, kwargs in desktop_calls:
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["env"], acceptance.CHILD_ENV)
            self.assertEqual(argv[0], str(self.desktop))
            self.assertEqual(argv.count("--acceptance-root"), 1)
            for flag in ("--wine-root", "--wine", "--wineserver", "--version"):
                self.assertEqual(argv.count(flag), 1)
        self.assertEqual(len(printed), 4)
        self.assertNotIn(str(self.external), json.dumps(summary))
        self.assertTrue(
            all(
                "runtimeVersion" in runtime and "packDigest" in runtime
                for round_entry in summary["rounds"]
                for runtime in round_entry["runtimes"]
            )
        )
        self.assertEqual(
            source_snapshots,
            {path: path.read_bytes() for path in source_snapshots},
        )

    def test_allow_network_is_forwarded_only_to_the_gui_runner(self) -> None:
        paths = acceptance.preflight(
            self._arguments("--allow-network"),
            host_system="Darwin",
            host_machine="arm64",
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments("--allow-network")
        )
        gui = acceptance._gui_command(paths, "round-1", descriptors[0])
        headless = acceptance._headless_command(paths, "round-1", descriptors[0])
        desktop = acceptance._desktop_command(paths, "round-1", descriptors[0])
        self.assertEqual(gui.count("--allow-network"), 1)
        self.assertNotIn("--allow-network", headless)
        self.assertNotIn("--allow-network", desktop)

    def test_console_failure_blocks_gui_without_fallback_and_continues(self) -> None:
        calls: list[list[str]] = []

        def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(list(argv))
            if argv[-1] == "--all":
                return subprocess.CompletedProcess(argv, 0, json.dumps(self._discovery()), "")
            if str(argv[3]).endswith("run_macos_headless_preview.py"):
                pack_id = argv[argv.index("--pack-id") + 1]
                runtime_id = "crossover" if "crossover" in pack_id else "whisky"
                if runtime_id == "crossover":
                    work_root = argv[argv.index("--work-root") + 1]
                    if "round-1" in work_root:
                        raise subprocess.TimeoutExpired(argv, acceptance.CHILD_TIMEOUT_SECONDS)
                    return subprocess.CompletedProcess(argv, 7, "/Users/secret", "private")
                return subprocess.CompletedProcess(
                    argv, 0, json.dumps(self._console_summary(runtime_id)), ""
                )
            runtime_id = argv[argv.index("--runtime-id") + 1]
            return subprocess.CompletedProcess(argv, 0, json.dumps(self._gui_summary(runtime_id)), "")

        summary = acceptance.orchestrate(
            self._arguments(),
            runner=runner,
            launcher=lambda *_args, **_kwargs: object(),
            waiter=lambda _process, _timeout: 0,
            host_system="Darwin",
            host_machine="arm64",
            printer=lambda _line: None,
        )
        gui_calls = [argv for argv in calls if "--runtime-id" in argv]
        self.assertEqual(len(gui_calls), 2)
        self.assertTrue(all("whisky" in argv for argv in gui_calls))
        crossover = [
            runtime
            for round_entry in summary["rounds"]
            for runtime in round_entry["runtimes"]
            if runtime["runtimeId"] == "crossover"
        ]
        for runtime in crossover:
            self.assertEqual(
                [application["status"] for application in runtime["applications"]],
                ["failed", "blocked", "blocked", "blocked"],
            )
        self.assertNotIn("/Users/secret", json.dumps(summary))
        self.assertNotIn("private", json.dumps(summary))

    def test_discovery_and_child_json_are_closed_bounded_and_runtime_ordered(self) -> None:
        reversed_discovery = self._discovery()
        reversed_discovery["runtimes"].reverse()
        with self.assertRaisesRegex(acceptance.AcceptanceError, "Runtime order"):
            acceptance.parse_discovery(json.dumps(reversed_discovery), self._arguments())

        polluted = self._discovery()
        polluted["runtimes"][0]["absoluteSecret"] = "/Users/developer"
        with self.assertRaisesRegex(acceptance.AcceptanceError, "descriptor keys"):
            acceptance.parse_discovery(json.dumps(polluted), self._arguments())

        duplicate = '{"schemaVersion":"1","schemaVersion":"1","runtimes":[]}'
        with self.assertRaisesRegex(acceptance.AcceptanceError, "duplicate"):
            acceptance.parse_discovery(duplicate, self._arguments())

        with self.assertRaisesRegex(acceptance.AcceptanceError, "size bound"):
            acceptance.parse_closed_json(" " * (acceptance.MAX_JSON_BYTES + 1), "child")

        descriptor = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )[0]
        poisoned_gui = self._gui_summary("crossover")
        poisoned_gui["applications"][0].update(
            status="blocked",
            failureClass="core",
            reasonCode="core-plan-failed",
        )
        with self.assertRaisesRegex(acceptance.AcceptanceError, "failure relation"):
            acceptance._project_gui(poisoned_gui, descriptor)

        screenshot_path = self._gui_summary("crossover")
        screenshot_path["applications"][0]["screenshot"] = {
            "path": "/Users/developer/private.png"
        }
        with self.assertRaisesRegex(acceptance.AcceptanceError, "application keys"):
            acceptance._project_gui(screenshot_path, descriptor)


if __name__ == "__main__":
    unittest.main()
