from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
import argparse
import json
import subprocess
import threading
import time
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
EXPECTED_REQUIRED_INTERACTIONS = {
    "7zip": ("fileList", "menus"),
    "sumatrapdf": ("mainWindow", "openDialog"),
    "notepad-plus-plus": ("open", "edit", "saveUtf8Chinese", "rereadMatches"),
}


class FinishedDesktopProcess:
    @staticmethod
    def poll() -> int:
        return 0


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
                "packId": "wine-macos-auto-preview",
                "version": "24.0" if runtime_id == "crossover" else "2.3",
                "packDigest": "sha256:" + "c" * 64,
                "source": "explicit-override",
                "activated": True,
            },
            "applications": [
                {
                    "schemaVersion": "1",
                    "runtimeId": runtime_id,
                    "appId": app_id,
                    "assetSha256": "d" * 64,
                    "status": "accepted",
                    "cleanup": True,
                    "interactionChecks": checks[app_id],
                    "installerExit": {"present": True, "code": 0, "success": True},
                    "exit": {"present": True, "code": 0, "success": True},
                    "windowAvailable": True,
                    "screenshotAvailable": True,
                }
                for app_id in ("7zip", "sumatrapdf", "notepad-plus-plus")
            ],
        }

    def _successful_runner(
        self, argv: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if argv[-1] == "--all":
            payload = self._discovery()
        elif Path(argv[3]).name == "run_macos_headless_preview.py":
            pack_id = argv[argv.index("--pack-id") + 1]
            runtime_id = "crossover" if "crossover" in pack_id else "whisky"
            payload = self._console_summary(runtime_id)
        else:
            runtime_id = argv[argv.index("--runtime-id") + 1]
            payload = self._gui_summary(runtime_id)
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

    def _run_final_wait_mutation(self, mutation) -> None:
        waits = 0

        def waiter(_process: object, _timeout: int) -> int:
            nonlocal waits
            waits += 1
            if waits == 4:
                mutation()
            return 0

        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "(?:identity changed|summary output)"
        ):
            acceptance.orchestrate(
                self._arguments(),
                runner=self._successful_runner,
                launcher=lambda *_args, **_kwargs: FinishedDesktopProcess(),
                waiter=waiter,
                host_system="Darwin",
                host_machine="arm64",
                printer=lambda _line: None,
            )

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
            return FinishedDesktopProcess()

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
            launcher=lambda *_args, **_kwargs: FinishedDesktopProcess(),
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

    def test_closed_json_rejects_large_integers_constants_and_invalid_text(self) -> None:
        large_integer = "9" * 5000
        for document in (
            large_integer,
            '{"nested":' + large_integer + "}",
            "NaN",
            "Infinity",
            "-Infinity",
            '{"nested":[NaN]}',
        ):
            with self.subTest(document=document[:16]):
                with self.assertRaises(acceptance.AcceptanceError) as raised:
                    acceptance.parse_closed_json(document, "child")
                self.assertEqual(str(raised.exception), "child JSON is invalid")

        for invalid_text in ('"\\ud800"', '"control\\u0001value"'):
            with self.subTest(invalid_text=invalid_text):
                with self.assertRaises(acceptance.AcceptanceError):
                    acceptance.parse_closed_json(invalid_text, "child")

        too_deep = "[" * (acceptance.MAX_JSON_DEPTH + 2) + "]" * (
            acceptance.MAX_JSON_DEPTH + 2
        )
        with self.assertRaisesRegex(acceptance.AcceptanceError, "structural bound"):
            acceptance.parse_closed_json(too_deep, "child")

    def test_interaction_preflight_requires_every_literal_check_to_be_true(self) -> None:
        target = self.interactions / "round-1" / "crossover.json"
        original = json.loads(target.read_text(encoding="utf-8"))
        cases: list[tuple[str, object]] = []

        false_check = json.loads(json.dumps(original))
        false_check["applications"]["7zip"]["menus"] = False
        cases.append(("false", false_check))
        integer_check = json.loads(json.dumps(original))
        integer_check["applications"]["sumatrapdf"]["mainWindow"] = 0
        cases.append(("integer", integer_check))
        string_check = json.loads(json.dumps(original))
        string_check["applications"]["notepad-plus-plus"]["edit"] = "true"
        cases.append(("string", string_check))
        missing_check = json.loads(json.dumps(original))
        del missing_check["applications"]["7zip"]["fileList"]
        cases.append(("missing", missing_check))
        extra_check = json.loads(json.dumps(original))
        extra_check["applications"]["sumatrapdf"]["extra"] = True
        cases.append(("extra", extra_check))

        self.assertEqual(
            EXPECTED_REQUIRED_INTERACTIONS,
            {
                "7zip": ("fileList", "menus"),
                "sumatrapdf": ("mainWindow", "openDialog"),
                "notepad-plus-plus": (
                    "open",
                    "edit",
                    "saveUtf8Chinese",
                    "rereadMatches",
                ),
            },
        )
        for label, document in cases:
            with self.subTest(label=label):
                target.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError, "interaction evidence"
                ):
                    acceptance.preflight(
                        self._arguments(), host_system="Darwin", host_machine="arm64"
                    )
                self.assertFalse(self.work.exists())
        target.write_text(json.dumps(original), encoding="utf-8")

    def test_runtime_descriptor_rejects_option_versions_and_aliased_entrypoints(self) -> None:
        for version in ("--allow-network", "--foo", "-1", "24.0\nsecret", "é"):
            with self.subTest(version=version):
                discovery = self._discovery()
                discovery["runtimes"][0]["version"] = version
                with self.assertRaisesRegex(
                    acceptance.AcceptanceError, "Runtime (?:version|discovery)"
                ):
                    acceptance.parse_discovery(json.dumps(discovery), self._arguments())

        same = self._discovery()
        same["runtimes"][0]["wineserver"] = "bin/wine"
        with self.assertRaisesRegex(acceptance.AcceptanceError, "entrypoints.*distinct"):
            acceptance.parse_discovery(json.dumps(same), self._arguments())

        normalized = self._discovery()
        normalized["runtimes"][0]["wineserver"] = "bin/./wine"
        with self.assertRaisesRegex(acceptance.AcceptanceError, "Runtime wineserver"):
            acceptance.parse_discovery(json.dumps(normalized), self._arguments())

    def test_root_identity_swaps_fail_before_layout_or_child_process(self) -> None:
        for field in ("cache", "interactions"):
            with self.subTest(field=field):
                target = self.cache if field == "cache" else self.interactions
                original = target.with_name(target.name + "-original")
                calls = 0

                def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                    nonlocal calls
                    calls += 1
                    if calls != 1:
                        self.fail("a child started after an input-root identity swap")
                    target.rename(original)
                    target.mkdir()
                    return subprocess.CompletedProcess(
                        argv, 0, json.dumps(self._discovery()), ""
                    )

                if field == "cache":
                    sentinel = target / "sentinel"
                    sentinel.write_text("unchanged", encoding="utf-8")
                    expected_source = b"unchanged"
                else:
                    sentinel = target / "round-1" / "crossover.json"
                    expected_source = sentinel.read_bytes()
                with self.assertRaisesRegex(acceptance.AcceptanceError, "identity changed"):
                    acceptance.orchestrate(
                        self._arguments(),
                        runner=runner,
                        host_system="Darwin",
                        host_machine="arm64",
                        printer=lambda _line: None,
                    )
                original_sentinel = (
                    original / "sentinel"
                    if field == "cache"
                    else original / "round-1" / "crossover.json"
                )
                self.assertEqual(original_sentinel.read_bytes(), expected_source)
                self.assertFalse(self.work.exists())
                target.rmdir()
                original.rename(target)

        self.work = self.external / "work-parent" / "work"
        self.work.parent.mkdir()
        (self.work.parent / "sentinel").write_text("unchanged", encoding="utf-8")
        original_parent = self.external / "work-parent-original"

        def swap_parent(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            self.work.parent.rename(original_parent)
            self.work.parent.mkdir()
            return subprocess.CompletedProcess(argv, 0, json.dumps(self._discovery()), "")

        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "(?:identity changed|unsafe path component)"
        ):
            acceptance.orchestrate(
                self._arguments(),
                runner=swap_parent,
                host_system="Darwin",
                host_machine="arm64",
                printer=lambda _line: None,
            )
        self.assertFalse(self.work.exists())
        self.assertEqual(
            (original_parent / "sentinel").read_text(encoding="utf-8"), "unchanged"
        )

    def test_cache_symlink_swap_and_tool_mutation_fail_before_the_next_child(self) -> None:
        original_cache = self.external / "cache-original"
        victim = self.external / "cache-victim"
        victim.mkdir()
        (victim / "sentinel").write_text("unchanged", encoding="utf-8")

        def symlink_swap(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            self.cache.rename(original_cache)
            try:
                os.symlink(victim, self.cache, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")
            return subprocess.CompletedProcess(argv, 0, json.dumps(self._discovery()), "")

        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "(?:identity changed|unsafe path component)"
        ):
            acceptance.orchestrate(
                self._arguments(),
                runner=symlink_swap,
                host_system="Darwin",
                host_machine="arm64",
                printer=lambda _line: None,
            )
        self.assertEqual((victim / "sentinel").read_text(encoding="utf-8"), "unchanged")
        self.assertFalse(self.work.exists())
        if self.cache.is_symlink():
            self.cache.unlink()
        original_cache.rename(self.cache)

        calls: list[str] = []

        def mutate_tool(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(Path(argv[3]).name)
            if argv[-1] == "--all":
                payload = self._discovery()
            elif Path(argv[3]).name == "run_macos_headless_preview.py":
                pack_id = argv[argv.index("--pack-id") + 1]
                runtime_id = "crossover" if "crossover" in pack_id else "whisky"
                payload = self._console_summary(runtime_id)
                self.cli.write_text("mutated", encoding="utf-8")
            else:
                self.fail("GUI child started after a tool identity mutation")
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

        with self.assertRaisesRegex(acceptance.AcceptanceError, "identity changed"):
            acceptance.orchestrate(
                self._arguments(),
                runner=mutate_tool,
                host_system="Darwin",
                host_machine="arm64",
                printer=lambda _line: None,
            )
        self.assertEqual(calls, ["discover_macos_wine.py", "run_macos_headless_preview.py"])

    def test_desktop_timeout_stops_process_before_another_launch(self) -> None:
        class Process:
            def __init__(self, terminate_timeout: bool = False) -> None:
                self.actions: list[str] = []
                self.running = True
                self.terminate_timeout = terminate_timeout

            def poll(self) -> int | None:
                return None if self.running else -9

            def terminate(self) -> None:
                self.actions.append("terminate")

            def kill(self) -> None:
                self.actions.append("kill")

            def wait(self, timeout: int) -> int:
                self.actions.append(f"wait:{timeout}")
                if self.terminate_timeout and "kill" not in self.actions:
                    raise subprocess.TimeoutExpired("desktop", timeout)
                self.running = False
                return -9

        first = Process()

        def timed_out(_process: object, timeout: int) -> int:
            raise subprocess.TimeoutExpired("desktop", timeout)

        evidence, safe = acceptance._launch_desktop(
            ["desktop"], lambda *_args, **_kwargs: first, timed_out, lambda _line: None
        )
        self.assertTrue(safe)
        self.assertEqual(evidence["status"], "failed")
        self.assertEqual(first.actions[0], "terminate")
        self.assertIsNotNone(first.poll())

        second = Process(terminate_timeout=True)
        evidence, safe = acceptance._launch_desktop(
            ["desktop"], lambda *_args, **_kwargs: second, timed_out, lambda _line: None
        )
        self.assertTrue(safe)
        self.assertEqual(evidence["status"], "failed")
        self.assertIn("kill", second.actions)
        self.assertIsNotNone(second.poll())

        launched: list[Process] = []

        def next_launcher(*_args: object, **_kwargs: object) -> Process:
            if launched:
                self.assertIsNotNone(launched[-1].poll())
            process = Process()
            launched.append(process)
            return process

        acceptance._launch_desktop(
            ["desktop"], next_launcher, timed_out, lambda _line: None
        )

        class Unstoppable(Process):
            def terminate(self) -> None:
                self.actions.append("terminate")
                raise OSError("closed test failure")

            def kill(self) -> None:
                self.actions.append("kill")
                raise OSError("closed test failure")

            def wait(self, timeout: int) -> int:
                self.actions.append(f"wait:{timeout}")
                raise subprocess.TimeoutExpired("desktop", timeout)

        unstoppable = Unstoppable()
        with self.assertRaises(acceptance.CleanupError):
            acceptance._launch_desktop(
                ["desktop"],
                lambda *_args, **_kwargs: unstoppable,
                timed_out,
                lambda _line: None,
            )
        child_calls: list[str] = []
        desktop_launches = 0

        def successful_runner(
            argv: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            child_calls.append(Path(argv[3]).name)
            if argv[-1] == "--all":
                payload = self._discovery()
            elif Path(argv[3]).name == "run_macos_headless_preview.py":
                pack_id = argv[argv.index("--pack-id") + 1]
                runtime_id = "crossover" if "crossover" in pack_id else "whisky"
                payload = self._console_summary(runtime_id)
            else:
                runtime_id = argv[argv.index("--runtime-id") + 1]
                payload = self._gui_summary(runtime_id)
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

        def unstoppable_launcher(*_args: object, **_kwargs: object) -> Unstoppable:
            nonlocal desktop_launches
            desktop_launches += 1
            return Unstoppable()

        with self.assertRaises(acceptance.CleanupError):
            acceptance.orchestrate(
                self._arguments(),
                runner=successful_runner,
                launcher=unstoppable_launcher,
                waiter=timed_out,
                host_system="Darwin",
                host_machine="arm64",
                printer=lambda _line: None,
            )
        self.assertEqual(desktop_launches, 1)
        self.assertEqual(
            child_calls,
            [
                "discover_macos_wine.py",
                "run_macos_headless_preview.py",
                "run_gui_baseline.py",
            ],
        )
        self.assertFalse((self.work / "summary.json").exists())
        acceptance._launch_desktop(
            ["desktop"], next_launcher, timed_out, lambda _line: None
        )

    def test_bounded_process_capture_terminates_overflow_and_timeout(self) -> None:
        endless = (
            "import sys\n"
            "while True:\n"
            " sys.stdout.buffer.write(b'x'*8192)\n"
            " sys.stdout.buffer.flush()\n"
        )
        with self.assertRaisesRegex(acceptance.AcceptanceError, "output limit"):
            acceptance._bounded_run(
                [sys.executable, "-S", "-B", "-c", endless], timeout=5
            )
        with self.assertRaisesRegex(acceptance.AcceptanceError, "timed out"):
            acceptance._bounded_run(
                [sys.executable, "-S", "-B", "-c", "import time; time.sleep(30)"],
                timeout=0.1,
            )

    def test_bounded_capture_cleanup_cannot_block_on_an_active_stream_reader(self) -> None:
        class BlockingStream:
            def __init__(self) -> None:
                self.read_descriptor, self.write_descriptor = os.pipe()
                self.lock = threading.Lock()
                self.entered = threading.Event()
                self.released = threading.Event()
                self.finished = threading.Event()
                self.closed = False

            def read(self, _size: int) -> bytes:
                with self.lock:
                    self.entered.set()
                    self.released.wait()
                    self.finished.set()
                    return b""

            def fileno(self) -> int:
                return self.read_descriptor

            def close(self) -> None:
                with self.lock:
                    if not self.closed:
                        os.close(self.read_descriptor)
                        self.closed = True

            def cleanup(self) -> None:
                self.released.set()
                if not self.closed:
                    try:
                        os.close(self.read_descriptor)
                    except OSError:
                        pass
                    self.closed = True
                try:
                    os.close(self.write_descriptor)
                except OSError:
                    pass

        class UnstoppableProcess:
            def __init__(self) -> None:
                self.stdout = BlockingStream()
                self.stderr = BlockingStream()

            def poll(self) -> None:
                return None

            def terminate(self) -> None:
                raise OSError("closed terminate failure")

            def kill(self) -> None:
                raise OSError("closed kill failure")

            def wait(self, timeout: int) -> int:
                raise subprocess.TimeoutExpired("child", timeout)

        process = UnstoppableProcess()
        errors: list[BaseException] = []

        def invoke() -> None:
            try:
                acceptance._bounded_run(["child"], timeout=0.05)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=invoke)

        try:
            with (
                mock.patch.object(acceptance.subprocess, "Popen", return_value=process),
                mock.patch.object(acceptance, "_posix_process_group", return_value=None),
            ):
                worker.start()
                worker.join(0.75)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], acceptance.CleanupError)
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)
            self.assertNotIn("daemon=True", ACCEPTANCE_TOOL.read_text(encoding="utf-8"))
        finally:
            process.stdout.cleanup()
            process.stderr.cleanup()
            worker.join(2)

    def test_accepted_gui_projection_is_complete_and_aggregate_checks_cleanup(self) -> None:
        descriptor = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )[0]
        receipt, applications = acceptance._project_gui(
            self._gui_summary("crossover"), descriptor
        )
        self.assertEqual(receipt["runtimeVersion"], "24.0")
        self.assertEqual([value["appId"] for value in applications], list(EXPECTED_REQUIRED_INTERACTIONS))

        mutations: list[tuple[str, dict[str, object]]] = []
        for label in (
            "cleanup-false",
            "missing-interactions",
            "check-false",
            "exit-nonzero",
            "window-false",
            "missing-asset",
            "missing-installer-exit",
        ):
            mutant = self._gui_summary("crossover")
            application = mutant["applications"][0]
            if label == "cleanup-false":
                application["cleanup"] = False
            elif label == "missing-interactions":
                del application["interactionChecks"]
            elif label == "check-false":
                application["interactionChecks"]["menus"] = False
            elif label == "exit-nonzero":
                application["exit"] = {"present": True, "code": 1, "success": False}
            elif label == "window-false":
                application["windowAvailable"] = False
            elif label == "missing-asset":
                del application["assetSha256"]
            else:
                del application["installerExit"]
            mutations.append((label, mutant))
        for label, mutant in mutations:
            with self.subTest(label=label), self.assertRaisesRegex(
                acceptance.AcceptanceError, "accepted GUI"
            ):
                acceptance._project_gui(mutant, descriptor)

        incomplete_rounds = [
            {
                "roundId": "round-1",
                "runtimes": [
                    {
                        "runtimeId": "crossover",
                        "applications": [
                            {
                                "schemaVersion": "1",
                                "runtimeId": "crossover",
                                "appId": "7zip",
                                "status": "accepted",
                                "cleanup": False,
                            }
                        ],
                        "desktop": {"status": "accepted", "exitCode": 0},
                    }
                ],
            }
        ]
        self.assertFalse(acceptance.aggregate_is_accepted(incomplete_rounds))

    def test_gui_receipt_is_bound_to_the_explicit_provider_identity(self) -> None:
        for runtime_id in ("crossover", "whisky"):
            with self.subTest(runtime_id=runtime_id, case="valid"):
                descriptor = acceptance.parse_discovery(
                    json.dumps(self._discovery()), self._arguments()
                )[0 if runtime_id == "crossover" else 1]
                receipt, applications = acceptance._project_gui(
                    self._gui_summary(runtime_id), descriptor
                )
                self.assertEqual(receipt["runtimeVersion"], descriptor["version"])
                self.assertTrue(
                    all(application["status"] == "accepted" for application in applications)
                )

            mutations: list[tuple[str, object]] = [
                ("packId", f"local-{runtime_id}"),
                ("packId-type", 1),
                ("source", f"{runtime_id}-app"),
                ("source-type", True),
                ("activated-false", False),
                ("activated-type", "true"),
                ("runtimeId", "whisky" if runtime_id == "crossover" else "crossover"),
                ("version", "0.0"),
            ]
            for label, value in mutations:
                with self.subTest(runtime_id=runtime_id, case=label):
                    mutant = self._gui_summary(runtime_id)
                    field = label.split("-", 1)[0]
                    mutant["receipt"][field] = value
                    with self.assertRaises(acceptance.AcceptanceError):
                        acceptance._project_gui(mutant, descriptor)

            missing = self._gui_summary(runtime_id)
            del missing["receipt"]["activated"]
            with self.subTest(runtime_id=runtime_id, case="activated-missing"):
                with self.assertRaises(acceptance.AcceptanceError):
                    acceptance._project_gui(missing, descriptor)

    def test_final_desktop_wait_work_root_swap_never_writes_the_victim(self) -> None:
        original_work = self.external / "work-original"
        victim = self.external / "work-victim"
        victim.mkdir()
        (victim / "sentinel").write_text("unchanged", encoding="utf-8")

        def mutation() -> None:
            self.work.rename(original_work)
            try:
                os.symlink(victim, self.work, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")

        self._run_final_wait_mutation(mutation)
        self.assertEqual((victim / "sentinel").read_text(encoding="utf-8"), "unchanged")
        self.assertFalse((victim / "summary.json").exists())
        self.assertFalse((original_work / "summary.json").exists())

    def test_final_desktop_wait_interaction_swap_is_integrity_fatal(self) -> None:
        interaction = self.interactions / "round-2" / "whisky.json"

        def mutation() -> None:
            interaction.write_text(
                interaction.read_text(encoding="utf-8") + " ", encoding="utf-8"
            )

        self._run_final_wait_mutation(mutation)
        self.assertFalse((self.work / "summary.json").exists())

    def test_final_desktop_wait_runtime_swap_is_integrity_fatal(self) -> None:
        runtime_entrypoint = self.runtime_roots["whisky"] / "bin" / "wine"

        def mutation() -> None:
            runtime_entrypoint.write_text("mutated", encoding="utf-8")

        self._run_final_wait_mutation(mutation)
        self.assertFalse((self.work / "summary.json").exists())

    def test_final_desktop_wait_tool_swap_is_integrity_fatal(self) -> None:
        def mutation() -> None:
            self.cli.write_text("mutated", encoding="utf-8")

        self._run_final_wait_mutation(mutation)
        self.assertFalse((self.work / "summary.json").exists())

    def test_failed_console_work_root_swap_is_not_downgraded_or_written(self) -> None:
        original_work = self.external / "failed-console-work-original"
        victim = self.external / "failed-console-victim"
        victim.mkdir()
        (victim / "sentinel").write_text("unchanged", encoding="utf-8")
        swapped = False

        def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            nonlocal swapped
            if argv[-1] == "--all":
                return self._successful_runner(argv)
            if not swapped and Path(argv[3]).name == "run_macos_headless_preview.py":
                swapped = True
                self.work.rename(original_work)
                try:
                    os.symlink(victim, self.work, target_is_directory=True)
                except OSError as error:
                    self.skipTest(f"directory symlinks are unavailable: {error}")
                return subprocess.CompletedProcess(argv, 9, "/private/output", "closed")
            self.fail("a child started after the work-root integrity failure")

        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "(?:identity changed|unsafe path component)"
        ):
            acceptance.orchestrate(
                self._arguments(),
                runner=runner,
                host_system="Darwin",
                host_machine="arm64",
                printer=lambda _line: None,
            )
        self.assertEqual((victim / "sentinel").read_text(encoding="utf-8"), "unchanged")
        self.assertFalse((victim / "summary.json").exists())
        self.assertFalse((original_work / "summary.json").exists())

    def test_console_cleanup_failure_is_fatal_and_starts_no_later_path(self) -> None:
        child_calls: list[str] = []
        desktop_calls = 0

        def bounded(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
            del timeout
            if argv[-1] == "--all":
                return self._successful_runner(argv)
            child_calls.append(Path(argv[3]).name)
            raise acceptance.CleanupError("child process cleanup failed")

        def launcher(*_args: object, **_kwargs: object) -> object:
            nonlocal desktop_calls
            desktop_calls += 1
            return FinishedDesktopProcess()

        with (
            mock.patch.object(acceptance, "_bounded_run", side_effect=bounded),
            self.assertRaises(acceptance.CleanupError),
        ):
            acceptance.orchestrate(
                self._arguments(),
                launcher=launcher,
                host_system="Darwin",
                host_machine="arm64",
                printer=lambda _line: None,
            )
        self.assertEqual(child_calls, ["run_macos_headless_preview.py"])
        self.assertEqual(desktop_calls, 0)
        self.assertFalse((self.work / "summary.json").exists())

    def test_gui_cleanup_failure_is_fatal_and_skips_desktop_and_later_paths(self) -> None:
        child_calls: list[str] = []
        desktop_calls = 0

        def bounded(argv: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
            del timeout
            if argv[-1] == "--all":
                return self._successful_runner(argv)
            child_calls.append(Path(argv[3]).name)
            if Path(argv[3]).name == "run_macos_headless_preview.py":
                return self._successful_runner(argv)
            raise acceptance.CleanupError("child process cleanup failed")

        def launcher(*_args: object, **_kwargs: object) -> object:
            nonlocal desktop_calls
            desktop_calls += 1
            return FinishedDesktopProcess()

        with (
            mock.patch.object(acceptance, "_bounded_run", side_effect=bounded),
            self.assertRaises(acceptance.CleanupError),
        ):
            acceptance.orchestrate(
                self._arguments(),
                launcher=launcher,
                host_system="Darwin",
                host_machine="arm64",
                printer=lambda _line: None,
            )
        self.assertEqual(
            child_calls,
            ["run_macos_headless_preview.py", "run_gui_baseline.py"],
        )
        self.assertEqual(desktop_calls, 0)
        self.assertFalse((self.work / "summary.json").exists())

    def test_desktop_wait_failure_is_cleanup_fatal_after_reaping_the_process(self) -> None:
        child_calls: list[str] = []
        desktop_calls = 0

        class Process:
            def __init__(self) -> None:
                self.running = True

            def poll(self) -> int | None:
                return None if self.running else -15

            def terminate(self) -> None:
                self.running = False

            def kill(self) -> None:
                self.running = False

            def wait(self, _timeout: int | None = None, **_kwargs: object) -> int:
                self.running = False
                return -15

        process = Process()

        def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            child_calls.append(Path(argv[3]).name)
            return self._successful_runner(argv)

        def launcher(*_args: object, **_kwargs: object) -> object:
            nonlocal desktop_calls
            desktop_calls += 1
            return process

        def waiter(_process: object, _timeout: int) -> int:
            raise OSError("closed wait failure")

        with self.assertRaises(acceptance.CleanupError):
            acceptance.orchestrate(
                self._arguments(),
                runner=runner,
                launcher=launcher,
                waiter=waiter,
                host_system="Darwin",
                host_machine="arm64",
                printer=lambda _line: None,
            )
        self.assertEqual(
            child_calls,
            [
                "discover_macos_wine.py",
                "run_macos_headless_preview.py",
                "run_gui_baseline.py",
            ],
        )
        self.assertEqual(desktop_calls, 1)
        self.assertIsNotNone(process.poll())
        self.assertFalse((self.work / "summary.json").exists())

    def test_summary_output_rejects_symlink_without_touching_victim(self) -> None:
        victim = self.external / "summary-victim"
        victim.write_text("unchanged", encoding="utf-8")

        def mutation() -> None:
            try:
                os.symlink(victim, self.work / "summary.json")
            except OSError as error:
                self.skipTest(f"file symlinks are unavailable: {error}")

        self._run_final_wait_mutation(mutation)
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")

    def test_summary_output_rejects_hardlink_without_touching_victim(self) -> None:
        victim = self.external / "summary-hardlink-victim"
        victim.write_text("unchanged", encoding="utf-8")

        def mutation() -> None:
            try:
                os.link(victim, self.work / "summary.json")
            except OSError as error:
                self.skipTest(f"hardlinks are unavailable: {error}")

        self._run_final_wait_mutation(mutation)
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")

    def test_summary_output_rejects_existing_foreign_file(self) -> None:
        foreign = self.work / "summary.json"

        def mutation() -> None:
            foreign.write_text("foreign", encoding="utf-8")

        self._run_final_wait_mutation(mutation)
        self.assertEqual(foreign.read_text(encoding="utf-8"), "foreign")

    def test_process_group_options_are_closed_for_darwin(self) -> None:
        self.assertEqual(
            acceptance._process_group_options("Darwin"), {"start_new_session": True}
        )

    def test_normal_child_and_desktop_returns_reap_a_residual_process_group(self) -> None:
        class EmptyStream:
            def __init__(self) -> None:
                self.descriptor, writer = os.pipe()
                os.close(writer)

            def close(self) -> None:
                if self.descriptor >= 0:
                    os.close(self.descriptor)
                    self.descriptor = -1

            def fileno(self) -> int:
                return self.descriptor

        class FinishedProcess:
            def __init__(self) -> None:
                self.stdout = EmptyStream()
                self.stderr = EmptyStream()

            def poll(self) -> int:
                return 0

            def wait(self, _timeout: int | None = None, **_kwargs: object) -> int:
                return 0

        for mode in ("child", "desktop"):
            with self.subTest(mode=mode):
                process = FinishedProcess()
                with (
                    mock.patch.object(acceptance, "_posix_process_group", return_value=4242),
                    mock.patch.object(acceptance, "_process_group_exists", return_value=True),
                    mock.patch.object(acceptance, "_stop_process", return_value=True) as stop,
                ):
                    if mode == "child":
                        with mock.patch.object(
                            acceptance.subprocess, "Popen", return_value=process
                        ):
                            result = acceptance._bounded_run(["child"], timeout=1)
                        self.assertEqual(result.returncode, 0)
                    else:
                        evidence, safe = acceptance._launch_desktop(
                            ["desktop"],
                            lambda *_args, **_kwargs: process,
                            lambda _process, _timeout: 0,
                            lambda _line: None,
                        )
                        self.assertTrue(safe)
                        self.assertEqual(evidence["status"], "accepted")
                stop.assert_called_once_with(process, process_group=4242)

    def test_normal_return_residual_cleanup_failure_is_fatal(self) -> None:
        class EmptyStream:
            def __init__(self) -> None:
                self.descriptor, writer = os.pipe()
                os.close(writer)

            def close(self) -> None:
                if self.descriptor >= 0:
                    os.close(self.descriptor)
                    self.descriptor = -1

            def fileno(self) -> int:
                return self.descriptor

        class FinishedProcess:
            def __init__(self) -> None:
                self.stdout = EmptyStream()
                self.stderr = EmptyStream()

            def poll(self) -> int:
                return 0

            def wait(self, _timeout: int | None = None, **_kwargs: object) -> int:
                return 0

        for mode in ("child", "desktop"):
            with self.subTest(mode=mode):
                process = FinishedProcess()
                with (
                    mock.patch.object(acceptance, "_posix_process_group", return_value=4242),
                    mock.patch.object(acceptance, "_process_group_exists", return_value=True),
                    mock.patch.object(
                        acceptance,
                        "_stop_process",
                        side_effect=acceptance.CleanupError("cleanup failed"),
                    ),
                ):
                    if mode == "child":
                        with mock.patch.object(
                            acceptance.subprocess, "Popen", return_value=process
                        ):
                            with self.assertRaises(acceptance.CleanupError):
                                acceptance._bounded_run(["child"], timeout=1)
                    else:
                        with self.assertRaises(acceptance.CleanupError):
                            acceptance._launch_desktop(
                                ["desktop"],
                                lambda *_args, **_kwargs: process,
                                lambda _process, _timeout: 0,
                                lambda _line: None,
                            )
        with (
            mock.patch.object(acceptance, "_process_group_exists", return_value=True),
            mock.patch.object(acceptance, "_stop_process", return_value=False),
            self.assertRaises(acceptance.CleanupError),
        ):
            acceptance._reap_residual_process_group(object(), 4242)

    @unittest.skipUnless(os.name == "posix", "real process-group probe requires POSIX")
    def test_timeout_reaps_grandchildren_for_child_and_desktop(self) -> None:
        for mode in ("child", "desktop"):
            with self.subTest(mode=mode):
                marker = self.external / f"{mode}-grandchild-marker"
                grandchild = (
                    "import pathlib,time; time.sleep(0.5); "
                    f"pathlib.Path({str(marker)!r}).write_text('escaped')"
                )
                parent = (
                    "import subprocess,sys,time; "
                    f"subprocess.Popen([sys.executable,'-S','-B','-c',{grandchild!r}]); "
                    "time.sleep(30)"
                )
                command = [sys.executable, "-S", "-B", "-c", parent]
                if mode == "child":
                    with self.assertRaisesRegex(acceptance.AcceptanceError, "timed out"):
                        acceptance._bounded_run(command, timeout=0.1)
                else:
                    evidence, safe = acceptance._launch_desktop(
                        command,
                        subprocess.Popen,
                        lambda process, _timeout: process.wait(timeout=0.1),
                        lambda _line: None,
                    )
                    self.assertTrue(safe)
                    self.assertEqual(evidence["status"], "failed")
                time.sleep(0.8)
                self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "posix", "real process-group probe requires POSIX")
    def test_normal_leader_exit_reaps_grandchildren_for_child_and_desktop(self) -> None:
        for mode in ("child", "desktop"):
            with self.subTest(mode=mode):
                marker = self.external / f"{mode}-normal-grandchild-marker"
                grandchild = (
                    "import pathlib,time; time.sleep(0.5); "
                    f"pathlib.Path({str(marker)!r}).write_text('escaped')"
                )
                parent = (
                    "import subprocess,sys; "
                    "subprocess.Popen([sys.executable,'-S','-B','-c',"
                    f"{grandchild!r}],stdin=subprocess.DEVNULL,"
                    "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)"
                )
                command = [sys.executable, "-S", "-B", "-c", parent]
                if mode == "child":
                    result = acceptance._bounded_run(command, timeout=5)
                    self.assertEqual(result.returncode, 0)
                else:
                    evidence, safe = acceptance._launch_desktop(
                        command,
                        subprocess.Popen,
                        lambda process, _timeout: process.wait(timeout=5),
                        lambda _line: None,
                    )
                    self.assertTrue(safe)
                    self.assertEqual(evidence["status"], "accepted")
                time.sleep(0.8)
                self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
