from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "tools" / "register_macos_local_wine.py"
HARNESS = ROOT / "tools" / "run_macos_headless_preview.py"
DISCOVER = ROOT / "tools" / "discover_macos_wine.py"
GUI_ASSETS = ROOT / "tools" / "download_gui_assets.py"
PREPARE_INTERACTIVE = ROOT / "tools" / "prepare_macos_interactive_runtime.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return f"sha256:{digest}"


class MacOsInteractiveRuntimePreparationTests(unittest.TestCase):
    def test_whisky_launcher_preserves_closed_pinned_descriptor_guests(self) -> None:
        prepare = load_module("interactive_runtime_preparation", PREPARE_INTERACTIVE)
        source = prepare.launcher_source(
            Path("/runtime/bin/wine64"),
            Path("/runtime/observer/CompatForgeWhiskyAcceptance.app"),
            Path(
                "/runtime/observer/CompatForgeWhiskyAcceptance.app/Contents/MacOS/wineloader"
            ),
            Path(
                "/runtime/observer/CompatForgeWhiskyAcceptance.app/Contents/Info.plist"
            ),
            "a" * 64,
            "b" * 64,
            "c" * 64,
        )
        self.assertIn('static const char prefix[] = "/dev/fd/";', source)
        self.assertIn("return value > 2;", source)
        self.assertIn(
            "return launch_inherited_descriptor_guest(argc, argv);",
            source,
        )
        self.assertIn("SCM_RIGHTS", source)
        self.assertIn('open_argv[index++] = "--compatforge-receive-fd";', source)
        self.assertIn("drive_c/windows/temp/compatforge-pinned-", source)
        self.assertIn('const char *guest_name = "SumatraPDF.exe";', source)
        self.assertNotIn("F_GETPATH", source)
        self.assertIn("cleanup_owned_directory", source)
        self.assertIn("remember_termination_signal", source)
        self.assertLess(
            source.index("return launch_inherited_descriptor_guest(argc, argv);"),
            source.rindex('open_argv[i++] = "/usr/bin/open";'),
        )

    def test_whisky_observer_receives_and_preserves_transferred_descriptor(self) -> None:
        prepare = load_module("interactive_runtime_observer", PREPARE_INTERACTIVE)
        source = prepare.observer_launcher_source(
            Path("/runtime/bin/wine64"), Path("/runtime/bin/wineserver")
        )
        self.assertIn('strcmp(argv[1], "--compatforge-receive-fd") == 0', source)
        self.assertIn("recvmsg(socket_descriptor, &message, 0)", source)
        self.assertIn("fcntl(descriptor, F_SETFD, 0)", source)
        self.assertIn('snprintf(descriptor_path, sizeof(descriptor_path), "/dev/fd/%d"', source)
        self.assertIn("symlink(descriptor_path, guest_path)", source)
        self.assertIn("argv[1] = guest_path;", source)
        self.assertIn("argv[argc - 2] = NULL;", source)


class MacOsHeadlessPreviewRegistrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="compatforge-macos-preview-")
        self.root = Path(self.temporary.name)
        self.materialized = self.root / "materialized"
        (self.materialized / "bin").mkdir(parents=True)
        self.wine = self.materialized / "bin" / "wine"
        self.wineserver = self.materialized / "bin" / "wineserver"
        self.wine.write_bytes(b"wine-entrypoint-fixture")
        self.wineserver.write_bytes(b"wineserver-entrypoint-fixture")
        for path in (self.wine, self.wineserver):
            path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_gui_asset_contract_pins_sumatrapdf_inside_drive_c(self) -> None:
        assets = load_module("headless_preview_gui_assets", GUI_ASSETS)
        sumatra = assets.asset_for("sumatrapdf")
        self.assertEqual(
            (sumatra.install_args, sumatra.installed_executable),
            (
                (),
                "CompatForge/SumatraPDF/SumatraPDF.exe",
            ),
        )

    def test_sumatrapdf_fixed_lookup_runs_with_an_empty_child_environment(self) -> None:
        bottle = self.root / "empty-environment" / "drive_c"
        expected = bottle / "CompatForge" / "SumatraPDF" / "SumatraPDF.exe"
        expected.parent.mkdir(parents=True)
        expected.write_bytes(b"MZsumatra")
        program = """
import pathlib
import sys
sys.path.insert(0, sys.argv[1])
import download_gui_assets
import run_gui_baseline
asset = download_gui_assets.asset_for("sumatrapdf")
print(run_gui_baseline.installed_executable(asset, pathlib.Path(sys.argv[2])))
"""
        result = subprocess.run(
            [
                sys.executable,
                "-S",
                "-B",
                "-c",
                program,
                str(ROOT / "tools"),
                str(bottle),
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()), expected)

    def run_register(self, output: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        arguments = [
            sys.executable,
            "-S",
            "-B",
            str(REGISTER),
            "--output-root",
            str(output),
            "--runtime-store-root",
            str(self.root / "runtime-store"),
            "--materialized-root",
            str(self.materialized),
            "--wine",
            "bin/wine",
            "--wineserver",
            "bin/wineserver",
            "--pack-id",
            "wine-macos-local-preview",
            "--version",
            "developer-local",
        ]
        arguments.extend(extra)
        return subprocess.run(
            arguments,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env={"PATH": os.environ.get("PATH", "")},
        )

    @unittest.skipIf(
        os.name == "nt",
        "POSIX executable modes and atomic directory fsync are required",
    )
    def test_registration_is_deterministic_source_read_only_and_rust_compatible(self) -> None:
        before = {path: path.read_bytes() for path in (self.wine, self.wineserver)}
        first = self.run_register(self.root / "first")
        second = self.run_register(self.root / "second")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)

        for relative in (
            "bundle/manifest.json",
            "bundle/components/wine-entrypoint.bin",
            "bundle/components/wineserver-entrypoint.bin",
        ):
            self.assertEqual((self.root / "first" / relative).read_bytes(), (self.root / "second" / relative).read_bytes())
        manifest = json.loads((self.root / "first/bundle/manifest.json").read_text())
        provider = json.loads((self.root / "first/provider.json").read_text())
        receipt = json.loads(first.stdout)
        unsigned = {key: value for key, value in manifest.items() if key != "digest"}
        canonical = json.dumps(unsigned, ensure_ascii=False, separators=(",", ":")).encode()
        self.assertEqual(manifest["digest"], f"sha256:{hashlib.sha256(canonical).hexdigest()}")
        self.assertEqual(provider["wineRuntime"]["packDigest"], manifest["digest"])
        self.assertEqual(receipt["packDigest"], manifest["digest"])
        self.assertNotIn("d3dmetal", provider["wineRuntime"])
        self.assertEqual(before, {path: path.read_bytes() for path in before})
        self.assertEqual(sha256(self.root / "first/bundle/components/wine-entrypoint.bin"), sha256(self.wine))

    @unittest.skipIf(
        os.name == "nt",
        "POSIX executable modes and atomic directory fsync are required",
    )
    def test_identical_existing_output_is_idempotent_but_foreign_output_fails(self) -> None:
        output = self.root / "output"
        self.assertEqual(self.run_register(output).returncode, 0)
        repeat = self.run_register(output)
        self.assertEqual(repeat.returncode, 0, repeat.stderr)
        (output / "foreign").write_text("foreign")
        collision = self.run_register(output)
        self.assertNotEqual(collision.returncode, 0)
        self.assertEqual(collision.stdout, "")
        self.assertIn("output-collision", collision.stderr)

        empty_foreign = self.root / "empty-foreign"
        self.assertEqual(self.run_register(empty_foreign).returncode, 0)
        (empty_foreign / "unexpected-directory").mkdir()
        collision = self.run_register(empty_foreign)
        self.assertNotEqual(collision.returncode, 0)

    def test_rejects_relative_traversing_and_overlapping_paths(self) -> None:
        cases = [
            ("--output-root", "relative-output"),
            ("--runtime-store-root", "relative-store"),
            ("--materialized-root", "relative-runtime"),
            ("--wine", "../wine"),
            ("--wineserver", "/bin/true"),
            ("--output-root", str(self.materialized / "generated")),
            ("--output-root", str(ROOT)),
            ("--pack-id", "Invalid ID"),
            ("--version", ""),
        ]
        for index, (name, value) in enumerate(cases):
            with self.subTest(name=name, value=value):
                result = self.run_register(self.root / f"bad-{index}", name, value)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_rejects_symlink_directory_and_non_executable_entrypoints(self) -> None:
        outside = self.root / "outside"
        outside.write_bytes(b"outside")
        outside.chmod(0o700)
        cases: list[tuple[str, Path]] = []
        symlink = self.materialized / "bin" / "symlink"
        symlink.symlink_to(outside)
        cases.append(("bin/symlink", symlink))
        directory = self.materialized / "bin" / "directory"
        directory.mkdir()
        cases.append(("bin/directory", directory))
        plain = self.materialized / "bin" / "plain"
        plain.write_bytes(b"plain")
        plain.chmod(0o600)
        cases.append(("bin/plain", plain))
        for index, (relative, _path) in enumerate(cases):
            with self.subTest(relative=relative):
                result = self.run_register(self.root / f"entry-{index}", "--wine", relative)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_tool_has_no_runtime_discovery_or_execution_surface(self) -> None:
        source = REGISTER.read_text()
        for forbidden in (
            "import subprocess",
            "import socket",
            "import urllib",
            "requests",
            "shutil.which",
            "Path.home",
            "os.system",
        ):
            self.assertNotIn(forbidden, source)


class MacOsHeadlessPreviewHarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("run_macos_headless_preview", HARNESS)
        assert spec is not None and spec.loader is not None
        cls.module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            spec.loader.exec_module(cls.module)
        finally:
            sys.path.remove(str(ROOT / "tools"))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="compatforge-preview-harness-")
        self.root = Path(self.temporary.name)
        self.wine_root = self.root / "wine-root"
        (self.wine_root / "bin").mkdir(parents=True)
        self.cli = self.root / "compatforge-cli"
        self.cc = self.root / "x86_64-w64-mingw32-gcc"
        self.wine = self.wine_root / "bin/wine"
        self.wineserver = self.wine_root / "bin/wineserver"
        for path in (self.cli, self.cc, self.wine, self.wineserver):
            path.write_bytes(b"fixture")
            path.chmod(0o700)
        self.work = self.root / "work"
        self.work.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self):
        return self.module.parser().parse_args(
            [
                "--compatforge-cli",
                str(self.cli),
                "--cc",
                str(self.cc),
                "--wine-root",
                str(self.wine_root),
                "--wine",
                "bin/wine",
                "--wineserver",
                "bin/wineserver",
                "--runtime-store",
                str(self.root / "runtime-store"),
                "--storage-root",
                str(self.root / "storage-root"),
                "--work-root",
                str(self.work),
                "--pack-id",
                "wine-macos-local-preview",
                "--version",
                "developer-local",
            ]
        )

    def test_harness_accepts_isolated_darwin_arm64_paths(self) -> None:
        validated = self.module.validate(self.arguments(), "Darwin", "arm64")
        self.assertEqual(validated["wine"].as_posix(), "bin/wine")
        for system, machine in (("Linux", "arm64"), ("Darwin", "x86_64")):
            with self.assertRaises(self.module.AcceptanceError):
                self.module.validate(self.arguments(), system, machine)
        self.work.write_text("not-a-directory") if not self.work.exists() else None
        (self.work / "foreign").write_text("foreign")
        with self.assertRaises(self.module.AcceptanceError):
            self.module.validate(self.arguments(), "Darwin", "arm64")

    def test_harness_rejects_relative_and_overlapping_roots_before_commands(self) -> None:
        arguments = self.arguments()
        arguments.runtime_store = "relative-store"
        with self.assertRaises(self.module.AcceptanceError):
            self.module.validate(arguments, "Darwin", "arm64")
        arguments = self.arguments()
        arguments.work_root = str(self.wine_root / "work")
        (self.wine_root / "work").mkdir()
        with self.assertRaises(self.module.AcceptanceError):
            self.module.validate(arguments, "Darwin", "arm64")

    def test_harness_uses_no_shell_or_path_discovery(self) -> None:
        source = HARNESS.read_text()
        self.assertNotIn("shell=True", source)
        self.assertNotIn("shutil.which", source)
        self.assertNotIn("Path.home", source)
        self.assertNotIn("urllib", source)

    def test_harness_auto_discovery_populates_a_complete_verified_selection(self) -> None:
        arguments = self.arguments()
        arguments.wine_root = None
        arguments.wine = None
        arguments.wineserver = None
        arguments.version = None
        original = self.module.discover
        self.module.discover = lambda runner: {
            "materializedRoot": str(self.wine_root),
            "wine": "bin/wine",
            "wineserver": "bin/wineserver",
            "version": "11.11",
            "source": "test-candidate",
        }
        try:
            resolved = self.module.resolve_wine(arguments, runner=lambda *_args, **_kwargs: None)
        finally:
            self.module.discover = original
        self.assertEqual(resolved.wine_root, str(self.wine_root))
        self.assertEqual(resolved.version, "11.11")
        self.assertEqual(resolved.wine_source, "test-candidate")

    def test_harness_rejects_partial_explicit_wine_selection(self) -> None:
        arguments = self.arguments()
        arguments.version = None
        with self.assertRaises(self.module.AcceptanceError):
            self.module.resolve_wine(arguments)

    def test_real_subprocess_mode_preserves_an_explicit_runtime(self) -> None:
        source = HARNESS.read_text()
        explicit_branch = source.index("if any(explicit_runtime):")
        bootstrap_branch = source.index("elif runner is subprocess.run:")
        self.assertLess(explicit_branch, bootstrap_branch)
        self.assertIn(
            "arguments = resolve_wine(arguments, runner)",
            source[explicit_branch:bootstrap_branch],
        )
        self.assertIn(
            "paths = validate(arguments, platform.system(), platform.machine())",
            source[explicit_branch:bootstrap_branch],
        )

    def test_mocked_harness_runs_the_exact_trust_chain_and_writes_redacted_summary(self) -> None:
        calls: list[list[str]] = []
        digest = "sha256:" + "a" * 64
        pack_digest = "sha256:" + "b" * 64

        def completed(argv, stdout=""):
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

        def fake_runner(argv, **kwargs):
            calls.append(list(argv))
            self.assertNotIn("shell", kwargs)
            if argv[0] == str(self.cc.resolve()):
                Path(argv[argv.index("-o") + 1]).write_bytes(b"mock-pe")
                return completed(argv)
            if argv[0] == sys.executable:
                registration = self.work / "registration"
                (registration / "bundle").mkdir(parents=True)
                (registration / "provider.json").write_text("{}")
                return completed(
                    argv,
                    json.dumps(
                        {
                            "schemaVersion": "1",
                            "packId": "wine-macos-local-preview",
                            "packDigest": pack_digest,
                            "bundlePath": str(registration / "bundle"),
                            "providerConfigPath": str(registration / "provider.json"),
                            "activated": False,
                        }
                    ),
                )
            self.assertEqual(argv[0], str(self.cli.resolve()))
            command = argv[1:]
            if command[0] == "inspect":
                return completed(
                    argv,
                    json.dumps(
                        {
                            "schemaVersion": "1",
                            "fileDigest": digest,
                            "architecture": "x86_64",
                            "subsystem": "windowsConsole",
                            "imageKind": "executable",
                        }
                    ),
                )
            if command[:2] == ["runtime", "install"]:
                return completed(argv, json.dumps({"digest": pack_digest, "packId": "wine-macos-local-preview"}))
            if command[:2] == ["runtime", "verify"]:
                return completed(argv, json.dumps({"digest": pack_digest, "packId": "wine-macos-local-preview"}))
            if command[:3] == ["provider", "macos", "probe"]:
                return completed(
                    argv,
                    json.dumps(
                        {
                            "host": {"architecture": "arm64"},
                            "runtimeProviders": [{"kind": "wine", "available": True}],
                            "translators": [{"kind": "rosetta", "available": True}],
                            "graphicsBackends": [{"kind": "wined3d", "available": True}],
                        }
                    ),
                )
            if command[:3] == ["provider", "macos", "context"]:
                return completed(
                    argv,
                    json.dumps(
                        {
                            "schemaVersion": "1",
                            "storageRoot": str(self.root / "storage-root"),
                            "supervisor": {"terminationGraceMilliseconds": 5000},
                        }
                    ),
                )
            if command[0] == "prepared-plan":
                working_directory = self.root / "storage-root/bottles/macos-headless-preview"
                return completed(
                    argv,
                    json.dumps(
                        {
                            "runtime": {"packDigest": pack_digest},
                            "translator": {"provider": "rosetta"},
                            "graphics": {"backend": "wined3d"},
                            "guestArtifact": {"digest": digest},
                            "process": {
                                "workingDirectory": str(working_directory),
                                "environment": {"WINEPREFIX": str(working_directory / "prefix")},
                            },
                        }
                    ),
                )
            if command[0] == "prepared-launch":
                events = [
                    {"sequence": 0, "kind": "started"},
                    {
                        "sequence": 1,
                        "kind": "output",
                        "output": {"stream": "stdout", "text": "COMPATFORGE_WINDOWS_CONSOLE_OK\n"},
                    },
                    {"sequence": 2, "kind": "exited", "exit": {"success": True, "code": 0}},
                ]
                return completed(argv, "".join(json.dumps(event) + "\n" for event in events))
            self.fail(f"unexpected command: {argv}")

        with mock.patch.object(self.module.platform, "system", return_value="Darwin"), mock.patch.object(
            self.module.platform, "machine", return_value="arm64"
        ):
            summary = self.module.run(self.arguments(), runner=fake_runner)
        self.assertTrue(summary["success"])
        self.assertEqual(summary["packDigest"], pack_digest)
        self.assertEqual(summary["runtimeSource"], "explicit")
        self.assertEqual(
            calls[0][1:8],
            [
                "-Os",
                "-s",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-Wl,--no-insert-timestamp",
                str(ROOT / "tests/fixtures/windows_console_smoke.c"),
            ],
        )
        self.assertEqual(calls[-2][1], "prepared-plan")
        self.assertEqual(calls[-1][1], "prepared-launch")
        serialized = json.dumps(summary)
        self.assertNotIn(str(self.root), serialized)
        self.assertTrue((self.work / "prepared-launch-plan.json").is_file())
        self.assertTrue((self.work / "runtime-events.jsonl").is_file())


class MacOsWineDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("discover_macos_wine", DISCOVER)
        assert spec is not None and spec.loader is not None
        cls.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.module
        spec.loader.exec_module(cls.module)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="compatforge-wine-discovery-")
        self.root = Path(self.temporary.name)
        (self.root / "loader").mkdir()
        (self.root / "server").mkdir()
        self.wine = self.root / "loader/wine"
        self.wineserver = self.root / "server/wineserver"
        macho = b"\xcf\xfa\xed\xfe" + (0x0100_0007).to_bytes(4, "little") + b"fixture"
        for path in (self.wine, self.wineserver):
            path.write_bytes(macho)
            path.chmod(0o700)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_candidate(self, source: str, name: str):
        root = self.root / name
        (root / "bin").mkdir(parents=True)
        macho = b"\xcf\xfa\xed\xfe" + (0x0100_0007).to_bytes(4, "little") + b"fixture"
        for relative in ("bin/wine", "bin/wineserver"):
            path = root / relative
            path.write_bytes(macho)
            path.chmod(0o700)
        if source in {"whisky-app", "whisky-library"}:
            for relative in self.module.WHISKY_GRAPHICS_COMPONENTS:
                component = root / relative
                component.parent.mkdir(parents=True, exist_ok=True)
                component.write_bytes(b"graphics-driver-fixture")
        return self.module.Candidate(source, root, "bin/wine", "bin/wineserver")

    def verify_candidate(self, candidate, runner):
        # These tests own candidate selection, architecture, and version contracts.
        # Windows cannot represent their executable-mode fixture; POSIX keeps the
        # production verifier here and in the dedicated negative contract below.
        if os.name == "nt":
            with mock.patch.object(self.module, "regular_executable", return_value=True):
                return self.module.verify_candidate(candidate, runner)
        return self.module.verify_candidate(candidate, runner)

    def test_whisky_requires_paired_x86_64_graphics_modules(self) -> None:
        candidate = self.make_candidate("whisky-library", "whisky-graphics")
        self.assertIsNotNone(self.verify_candidate(candidate, self.successful_runner))

        for relative in self.module.WHISKY_GRAPHICS_COMPONENTS:
            with self.subTest(relative=relative):
                component = candidate.root / relative
                payload = component.read_bytes()
                component.unlink()
                self.assertIsNone(
                    self.verify_candidate(candidate, self.successful_runner)
                )
                component.write_bytes(payload)

    @staticmethod
    def successful_runner(argv, **_kwargs):
        executable = Path(argv[0]).name
        stdout = (
            "wine-11.11\n"
            if executable in {"wine", "wine64", "wineloader"}
            else "Wine 11.11\n"
        )
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    def discover_all(self, candidates, runner):
        # Windows does not preserve the executable bit used by the macOS-only
        # verifier. Keep these enumeration tests focused on the closed candidate
        # classification while the existing verifier tests own that invariant.
        with mock.patch.object(self.module, "regular_executable", return_value=True):
            return self.module.discover_all(candidates, runner=runner)

    def test_runtime_id_is_a_closed_source_classification(self) -> None:
        cases = (
            ("crossover-app", "crossover"),
            ("crossover-interactive-derived", "crossover"),
            ("whisky-app", "whisky"),
            ("whisky-library", "whisky"),
            ("whisky-interactive-derived", "whisky"),
            ("mac-win-development-build", None),
            ("test", None),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                candidate = self.module.Candidate(source, self.root, "wine", "wineserver")
                self.assertEqual(self.module.runtime_id(candidate), expected)

    def test_known_candidates_prefer_closed_prepared_descriptors(self) -> None:
        home = self.root / "prepared-home"
        prepared = home / "Library/Caches/dev.compatforge/interactive-runtimes/crossover"
        (prepared / "bin").mkdir(parents=True)
        descriptor = {
            "architecture": "x86_64",
            "materializedRoot": str(prepared),
            "runtimeId": "crossover",
            "schemaVersion": "1",
            "source": "crossover-interactive-derived",
            "version": "25.1.1",
            "wine": "bin/wine",
            "wineserver": "bin/wineserver",
        }
        (prepared / "descriptor.json").write_text(
            json.dumps(descriptor), encoding="utf-8"
        )

        candidates = self.module.known_candidates(home=home)

        self.assertEqual(candidates[0].source, "crossover-interactive-derived")
        self.assertEqual(candidates[0].root, prepared)
        self.assertEqual(candidates[0].wine, "bin/wine")

    def test_known_candidates_prioritize_crossover_wineloader_before_legacy_wine(self) -> None:
        home = self.root / "home"
        crossover = [
            candidate
            for candidate in self.module.known_candidates(home=home)
            if candidate.source == "crossover-app"
        ]

        self.assertEqual(
            [
                (candidate.root, candidate.wine, candidate.wineserver)
                for candidate in crossover
            ],
            [
                (
                    Path("/Applications/CrossOver.app/Contents/SharedSupport/CrossOver"),
                    "bin/wineloader",
                    "bin/wineserver",
                ),
                (
                    Path("/Applications/CrossOver.app/Contents/SharedSupport/CrossOver"),
                    "bin/wine",
                    "bin/wineserver",
                ),
                (
                    home / "Applications/CrossOver.app/Contents/SharedSupport/CrossOver",
                    "bin/wineloader",
                    "bin/wineserver",
                ),
                (
                    home / "Applications/CrossOver.app/Contents/SharedSupport/CrossOver",
                    "bin/wine",
                    "bin/wineserver",
                ),
            ],
        )

    def test_known_crossover_layout_verifies_wineloader_and_preserves_legacy_fallback(self) -> None:
        home = self.root / "home"
        root = home / "Applications/CrossOver.app/Contents/SharedSupport/CrossOver"
        (root / "bin").mkdir(parents=True)
        macho = b"\xcf\xfa\xed\xfe" + (0x0100_0007).to_bytes(4, "little") + b"fixture"
        for relative in ("bin/wineloader", "bin/wineserver", "bin/wine"):
            path = root / relative
            path.write_bytes(macho)
            path.chmod(0o700)

        candidates = [
            candidate
            for candidate in self.module.known_candidates(home=home)
            if candidate.root == root
        ]
        self.assertEqual(
            [(candidate.wine, candidate.wineserver) for candidate in candidates],
            [("bin/wineloader", "bin/wineserver"), ("bin/wine", "bin/wineserver")],
        )
        selected = self.verify_candidate(candidates[0], self.successful_runner)
        self.assertIsNotNone(selected)
        self.assertEqual(selected["wine"], "bin/wineloader")

        (root / "bin/wineloader").unlink()
        selected = self.verify_candidate(candidates[1], self.successful_runner)
        self.assertIsNotNone(selected)
        self.assertEqual(selected["wine"], "bin/wine")

    def test_crossover_legacy_wine_script_wrapper_is_rejected(self) -> None:
        root = self.root / "crossover-script-wrapper"
        (root / "bin").mkdir(parents=True)
        wrapper = root / "bin/wine"
        wrapper.write_text("#!/bin/sh\nexec \"$@\"\n", encoding="utf-8")
        wrapper.chmod(0o700)
        wineserver = root / "bin/wineserver"
        wineserver.write_bytes(
            b"\xcf\xfa\xed\xfe" + (0x0100_0007).to_bytes(4, "little") + b"fixture"
        )
        wineserver.chmod(0o700)
        candidate = self.module.Candidate(
            "crossover-app", root, "bin/wine", "bin/wineserver"
        )

        self.assertIsNone(self.verify_candidate(candidate, self.successful_runner))

    def test_crossover_wineloader_keeps_thin_x86_64_and_root_checks(self) -> None:
        root = self.root / "crossover-invalid-architecture"
        (root / "bin").mkdir(parents=True)
        wineloader = root / "bin/wineloader"
        wineloader.write_bytes(
            b"\xcf\xfa\xed\xfe" + (0x0100_000C).to_bytes(4, "little") + b"fixture"
        )
        wineloader.chmod(0o700)
        wineserver = root / "bin/wineserver"
        wineserver.write_bytes(
            b"\xcf\xfa\xed\xfe" + (0x0100_0007).to_bytes(4, "little") + b"fixture"
        )
        wineserver.chmod(0o700)
        candidate = self.module.Candidate(
            "crossover-app", root, "bin/wineloader", "bin/wineserver"
        )
        self.assertIsNone(self.verify_candidate(candidate, self.successful_runner))

        wineloader.write_bytes(
            b"\xcf\xfa\xed\xfe" + (0x0100_0007).to_bytes(4, "little") + b"fixture"
        )
        outside = self.root / "outside-wineloader"
        outside.write_bytes(wineloader.read_bytes())
        outside.chmod(0o700)
        wineloader.unlink()
        wineloader.symlink_to(outside)
        self.assertIsNone(self.verify_candidate(candidate, self.successful_runner))

    def test_discover_all_selects_first_verified_candidate_per_required_runtime(self) -> None:
        invalid_crossover = self.make_candidate("crossover-app", "crossover-invalid-macho")
        (invalid_crossover.root / invalid_crossover.wine).write_bytes(b"not-mach-o")
        valid_crossover = self.make_candidate("crossover-app", "crossover-selected")
        duplicate_crossover = self.make_candidate("crossover-app", "crossover-duplicate")

        failed_whisky = self.make_candidate("whisky-app", "whisky-failed-version")
        development_build = self.make_candidate("mac-win-development-build", "development-build")
        valid_whisky = self.make_candidate("whisky-library", "whisky-selected")
        duplicate_whisky = self.make_candidate("whisky-app", "whisky-duplicate")
        calls: list[str] = []

        def runner(argv, **kwargs):
            calls.append(str(argv[0]))
            if "whisky-failed-version" in str(argv[0]):
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="failed")
            return self.successful_runner(argv, **kwargs)

        result = self.discover_all(
            (
                invalid_crossover,
                valid_crossover,
                duplicate_crossover,
                failed_whisky,
                development_build,
                valid_whisky,
                duplicate_whisky,
            ),
            runner=runner,
        )

        self.assertEqual([item["runtimeId"] for item in result], ["crossover", "whisky"])
        self.assertEqual(
            [item["materializedRoot"] for item in result],
            [str(valid_crossover.root.resolve()), str(valid_whisky.root.resolve())],
        )
        self.assertEqual(
            [set(item) for item in result],
            [
                {
                    "schemaVersion",
                    "source",
                    "materializedRoot",
                    "wine",
                    "wineserver",
                    "version",
                    "architecture",
                    "runtimeId",
                },
                {
                    "schemaVersion",
                    "source",
                    "materializedRoot",
                    "wine",
                    "wineserver",
                    "version",
                    "architecture",
                    "runtimeId",
                },
            ],
        )
        serialized_calls = "\n".join(calls)
        self.assertNotIn("crossover-invalid-macho", serialized_calls)
        self.assertNotIn("crossover-duplicate", serialized_calls)
        self.assertNotIn("development-build", serialized_calls)
        self.assertNotIn("whisky-duplicate", serialized_calls)

    def test_discover_all_rejects_symlink_escape_and_uses_later_verified_candidate(self) -> None:
        escaping = self.make_candidate("crossover-app", "crossover-escaping")
        outside = self.root / "outside-enumerator-wine"
        outside.write_bytes((escaping.root / escaping.wine).read_bytes())
        outside.chmod(0o700)
        (escaping.root / escaping.wine).unlink()
        (escaping.root / escaping.wine).symlink_to(outside)
        valid_crossover = self.make_candidate("crossover-app", "crossover-after-escape")
        valid_whisky = self.make_candidate("whisky-app", "whisky-for-escape")

        result = self.discover_all(
            (escaping, valid_crossover, valid_whisky), runner=self.successful_runner
        )

        self.assertEqual(
            [item["materializedRoot"] for item in result],
            [str(valid_crossover.root.resolve()), str(valid_whisky.root.resolve())],
        )

    def test_discover_all_requires_both_runtimes_and_excludes_development_builds(self) -> None:
        crossover = self.make_candidate("crossover-app", "only-crossover")
        whisky = self.make_candidate("whisky-app", "only-whisky")
        development_build = self.make_candidate("mac-win-development-build", "only-development")
        cases = (
            (crossover,),
            (whisky,),
            (crossover, development_build),
        )
        for candidates in cases:
            with self.subTest(sources=[candidate.source for candidate in candidates]):
                with self.assertRaisesRegex(
                    self.module.DiscoveryError, "^required Runtime is unavailable$"
                ):
                    self.discover_all(candidates, runner=self.successful_runner)

    def test_discovery_cli_default_output_is_byte_compatible(self) -> None:
        record = {
            "schemaVersion": "1",
            "source": "crossover-app",
            "materializedRoot": "/runtime",
            "wine": "bin/wine",
            "wineserver": "bin/wineserver",
            "version": "11.11",
            "architecture": "x86_64",
        }
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(self.module.sys, "argv", ["discover_macos_wine.py"]), mock.patch.object(
            self.module, "discover", return_value=record
        ), mock.patch.object(self.module.sys, "stdout", stdout), mock.patch.object(
            self.module.sys, "stderr", stderr
        ):
            exit_code = self.module.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            stdout.getvalue(),
            '{"architecture":"x86_64","materializedRoot":"/runtime","schemaVersion":"1","source":"crossover-app","version":"11.11","wine":"bin/wine","wineserver":"bin/wineserver"}\n',
        )
        self.assertEqual(stderr.getvalue(), "")

    def test_discovery_cli_all_output_is_closed_canonical_and_runtime_sorted(self) -> None:
        records = [
            {"runtimeId": "crossover", "schemaVersion": "1", "source": "crossover-app"},
            {"runtimeId": "whisky", "schemaVersion": "1", "source": "whisky-app"},
        ]
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(self.module.sys, "argv", ["discover_macos_wine.py", "--all"]), mock.patch.object(
            self.module, "discover_all", return_value=records
        ) as discover_all, mock.patch.object(self.module.sys, "stdout", stdout), mock.patch.object(
            self.module.sys, "stderr", stderr
        ):
            exit_code = self.module.main()

        self.assertEqual(exit_code, 0)
        discover_all.assert_called_once_with()
        self.assertEqual(
            stdout.getvalue(),
            '{"runtimes":[{"runtimeId":"crossover","schemaVersion":"1","source":"crossover-app"},{"runtimeId":"whisky","schemaVersion":"1","source":"whisky-app"}],"schemaVersion":"1"}\n',
        )
        self.assertEqual(stderr.getvalue(), "")

    def test_discovery_cli_rejects_unknown_or_combined_arguments_without_leaking_input(self) -> None:
        cases = (
            ["--unknown", str(self.root)],
            ["--all", "--unknown", str(self.root)],
            ["--all=true"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with mock.patch.object(
                    self.module.sys, "argv", ["discover_macos_wine.py", *arguments]
                ), mock.patch.object(self.module.sys, "stdout", stdout), mock.patch.object(
                    self.module.sys, "stderr", stderr
                ):
                    exit_code = self.module.main()

                self.assertEqual(exit_code, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(
                    stderr.getvalue(),
                    "compatforge-wine-discovery: invalid command-line arguments\n",
                )
                self.assertNotIn(str(self.root), stderr.getvalue())

    def test_discovery_requires_thin_x86_64_and_successful_version_execution(self) -> None:
        calls: list[list[str]] = []

        def runner(argv, **kwargs):
            calls.append(list(argv))
            self.assertEqual(kwargs["env"], {"LANG": "C", "LC_ALL": "C", "WINEDEBUG": "-all"})
            stdout = "wine-11.11\n" if Path(argv[0]).name == "wine" else "Wine 11.11\n"
            return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

        candidate = self.module.Candidate("test", self.root, "loader/wine", "server/wineserver")
        selected = self.verify_candidate(candidate, runner)
        self.assertEqual(selected["version"], "11.11")
        self.assertEqual(selected["wine"], "loader/wine")
        self.assertEqual(len(calls), 2)

        self.wine.write_bytes(b"\xcf\xfa\xed\xfe" + (0x0100_000C).to_bytes(4, "little") + b"fixture")
        self.assertIsNone(self.verify_candidate(candidate, runner))

    def test_discovery_rejects_failed_version_probe_and_escaping_entrypoint(self) -> None:
        candidate = self.module.Candidate("test", self.root, "loader/wine", "server/wineserver")

        def failed(argv, **_kwargs):
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="failed")

        self.assertIsNone(self.verify_candidate(candidate, failed))
        outside = self.root.parent / "outside-wine"
        outside.write_bytes(self.wine.read_bytes())
        outside.chmod(0o700)
        self.wine.unlink()
        self.wine.symlink_to(outside)
        self.assertIsNone(self.verify_candidate(candidate, failed))

    @unittest.skipIf(os.name == "nt", "POSIX executable-mode bits are required")
    def test_discovery_rejects_non_executable_entrypoint(self) -> None:
        self.wine.chmod(0o600)
        candidate = self.module.Candidate(
            "test", self.root, "loader/wine", "server/wineserver"
        )
        self.assertIsNone(
            self.module.verify_candidate(candidate, self.successful_runner)
        )


if __name__ == "__main__":
    unittest.main()
