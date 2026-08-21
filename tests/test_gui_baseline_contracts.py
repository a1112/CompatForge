from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import http.client
import importlib.util
import io
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
import urllib.error
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSET_TOOL = ROOT / "tools" / "download_gui_assets.py"
BASELINE_TOOL = ROOT / "tools" / "run_gui_baseline.py"
DESKTOP = ROOT / "apps" / "desktop"
TAURI = DESKTOP / "src-tauri"


def load_tool(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[path.stem] = module
    spec.loader.exec_module(module)
    return module


def project_rust(source: str, *, strip_literals: bool) -> str:
    """Project Rust source with comments removed and literals optionally masked."""

    def token_boundary(index: int) -> bool:
        return index == 0 or not (source[index - 1].isalnum() or source[index - 1] == "_")

    def raw_string_end(index: int) -> int | None:
        prefix_length = 0
        if source.startswith("br", index) and token_boundary(index):
            prefix_length = 2
        elif source.startswith("r", index) and token_boundary(index):
            prefix_length = 1
        if not prefix_length:
            return None
        cursor = index + prefix_length
        while cursor < len(source) and source[cursor] == "#":
            cursor += 1
        if cursor >= len(source) or source[cursor] != '"':
            return None
        hashes = source[index + prefix_length : cursor]
        closing = '"' + hashes
        closing_index = source.find(closing, cursor + 1)
        return len(source) if closing_index < 0 else closing_index + len(closing)

    def quoted_string_end(index: int) -> int | None:
        quote = index
        if source.startswith('b"', index) and token_boundary(index):
            quote += 1
        elif not source.startswith('"', index):
            return None
        cursor = quote + 1
        while cursor < len(source):
            if source[cursor] == "\\":
                cursor += 2
            elif source[cursor] == '"':
                return cursor + 1
            else:
                cursor += 1
        return len(source)

    def char_literal_end(index: int) -> int | None:
        quote = index
        if source.startswith("b'", index) and token_boundary(index):
            quote += 1
        elif not source.startswith("'", index):
            return None
        content = quote + 1
        if content >= len(source):
            return None
        if source[content] != "\\":
            closing = content + 1
        elif source.startswith("\\u{", content):
            brace = source.find("}", content + 3)
            if brace < 0:
                return None
            closing = brace + 1
        elif source.startswith("\\x", content):
            closing = content + 4
        else:
            closing = content + 2
        if closing < len(source) and source[closing] == "'":
            return closing + 1
        return None

    def masked(segment: str, marker: str = " ") -> str:
        return marker + "\n" * segment.count("\n")

    output: list[str] = []
    index = 0
    while index < len(source):
        if source.startswith("//", index):
            end = source.find("\n", index + 2)
            end = len(source) if end < 0 else end
            output.append(masked(source[index:end]))
            index = end
            continue
        if source.startswith("/*", index):
            depth = 1
            end = index + 2
            while end < len(source) and depth:
                if source.startswith("/*", end):
                    depth += 1
                    end += 2
                elif source.startswith("*/", end):
                    depth -= 1
                    end += 2
                else:
                    end += 1
            output.append(masked(source[index:end]))
            index = end
            continue

        literal_end = raw_string_end(index)
        marker = '""'
        if literal_end is None:
            literal_end = quoted_string_end(index)
        if literal_end is None:
            literal_end = char_literal_end(index)
            marker = "''"
        if literal_end is not None:
            segment = source[index:literal_end]
            output.append(masked(segment, marker) if strip_literals else segment)
            index = literal_end
            continue

        output.append(source[index])
        index += 1
    return "".join(output)


def rust_without_comments(source: str) -> str:
    return project_rust(source, strip_literals=False)


def rust_code_only(source: str) -> str:
    return project_rust(source, strip_literals=True)


def desktop_runtime_boundary_violations(projected_rust: str) -> set[str]:
    allowed_environment_read = 'std::env::var_os("")'
    projected_rust = projected_rust.replace(allowed_environment_read, "")
    return set(re.findall(r"\b(?:Command|PATH|env)\b", projected_rust))


class GuiBaselineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.assets = load_tool(ASSET_TOOL)
        cls.baseline = load_tool(BASELINE_TOOL)

    @staticmethod
    def descriptor_receipt() -> dict[str, object]:
        return {
            "schemaVersion": "1",
            "source": "crossover-app",
            "version": "24.0",
            "packId": "wine-macos-auto-preview",
            "packDigest": "sha256:" + "a" * 64,
        }

    @staticmethod
    def descriptor_context(
        storage: Path,
        receipt: dict[str, object],
    ) -> dict[str, object]:
        return {
            "schemaVersion": "1",
            "storageRoot": str(storage),
            "runtimeBindings": [
                {
                    "packId": receipt["packId"],
                    "packDigest": receipt["packDigest"],
                }
            ],
            "supervisor": {},
        }

    def test_rust_code_projection_removes_comment_and_string_decoys(self) -> None:
        source = """
// pub struct DesktopLaunchOptions;
/* outer /* Command env PATH */ comment */
const DECOY: &str = r#"std::env::var_os(\"FORGED\") Command"#;
struct RealCode;
"""
        projected = rust_code_only(source)
        self.assertIn("struct RealCode", projected)
        self.assertNotRegex(projected, r"\b(?:DesktopLaunchOptions|Command|env|PATH)\b")

    def test_rust_code_projection_preserves_code_after_raw_literals(self) -> None:
        raw_mutant = (
            'const DECOY: &str = r#"inner " // raw"#; '
            'std::process::Command::new("wine");'
        )
        raw_byte_mutant = (
            'const DECOY: &[u8] = br##"inner " // raw byte"##; '
            'use std::env as runtime_env;'
        )
        self.assertEqual(desktop_runtime_boundary_violations(rust_code_only(raw_mutant)), {"Command"})
        self.assertIn("env", desktop_runtime_boundary_violations(rust_code_only(raw_byte_mutant)))

        decoy_only = 'const A: &str = r#"Command env // raw"#; const B: &[u8] = br#"PATH"#;'
        self.assertEqual(desktop_runtime_boundary_violations(rust_code_only(decoy_only)), set())

    def test_rust_code_projection_handles_other_literals_and_nested_comments(self) -> None:
        source = r'''
const TEXT: &str = "Command // string";
const BYTES: &[u8] = b"env /* bytes */";
const SLASH: char = '/';
const QUOTE: char = '\'';
const BYTE: u8 = b'\n';
const FACE: char = '\u{1F600}';
/* outer Command /* nested env */ PATH */
// Command env PATH
struct RealCode;
'''
        projected = rust_code_only(source)
        self.assertIn("struct RealCode", projected)
        self.assertNotRegex(projected, r"\b(?:Command|env|PATH)\b")
        self.assertIn('"Command // string"', rust_without_comments(source))

    def test_fixed_official_asset_matrix_is_closed(self) -> None:
        self.assertEqual(
            [asset.app_id for asset in self.assets.ASSETS],
            ["7zip", "sumatrapdf", "notepad-plus-plus"],
        )
        self.assertEqual(
            [asset.sha256 for asset in self.assets.ASSETS],
            [
                "d64a0468f5b5b0b0fc5b2188450bcd655b70809d97b1c4535f2884635094377d",
                "1eee71cccd2ea6e94d5bcea54ee2f759844da3e1a0ee2f6045035b1d17b94381",
                "7c243203265ce8fdac76c839bf744ae35dcf620760eb97c2ea279af498560e45",
            ],
        )
        for asset in self.assets.ASSETS:
            self.assertTrue(asset.url.startswith("https://"))
            self.assertEqual(len(asset.sha256), 64)
            self.assertTrue(asset.window_title_tokens)

    def test_desktop_shell_is_tauri_and_qt_sources_are_removed(self) -> None:
        self.assertTrue((DESKTOP / "package-lock.json").is_file())
        self.assertTrue((TAURI / "Cargo.lock").is_file())
        self.assertFalse((DESKTOP / "CMakeLists.txt").exists())
        self.assertFalse((DESKTOP / "qml").exists())
        self.assertFalse((DESKTOP / "src" / "compatforgecontroller.cpp").exists())
        package = json.loads((DESKTOP / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["dependencies"]["@tauri-apps/api"], "2.11.1")
        self.assertEqual(package["devDependencies"]["@tauri-apps/cli"], "2.11.4")
        config = json.loads((TAURI / "tauri.conf.json").read_text(encoding="utf-8"))
        self.assertEqual(config["identifier"], "dev.compatforge.desktop")
        self.assertEqual(config["app"]["windows"][0]["titleBarStyle"], "Overlay")
        self.assertIn("script-src 'self'", config["app"]["security"]["csp"])
        capability = json.loads((TAURI / "capabilities" / "default.json").read_text(encoding="utf-8"))
        self.assertEqual(
            capability["permissions"],
            ["core:default", "core:window:allow-start-dragging", "dialog:allow-open"],
        )

    def test_tauri_uses_the_shared_application_service(self) -> None:
        rust = rust_without_comments((TAURI / "src" / "lib.rs").read_text(encoding="utf-8"))
        for symbol in (
            "create_local_context",
            "AutomationService::new",
            "ServiceRequest",
            "service_call",
            "seed_default_applications",
            "open_settings",
        ):
            self.assertIn(symbol, rust)
        self.assertNotIn("std::process::Command", rust)
        self.assertNotIn("compatforge_ffi", rust)
        self.assertNotIn("BASELINE_SPECS", rust)
        service = (ROOT / "crates" / "compatforge-service" / "src" / "jobs.rs").read_text(encoding="utf-8")
        for symbol in ("PreparedLaunch::prepare", "ProcessSupervisor::start", "ExecutableMode::BottleInPlace", "NetworkPolicy::Deny"):
            self.assertIn(symbol, service)

    def test_desktop_acceptance_runtime_keeps_private_structure_and_abi(self) -> None:
        rust_source = (TAURI / "src" / "lib.rs").read_text(encoding="utf-8")
        rust = rust_code_only(rust_source)
        main = rust_code_only((TAURI / "src" / "main.rs").read_text(encoding="utf-8"))
        cargo = tomllib.loads((TAURI / "Cargo.toml").read_text(encoding="utf-8"))

        self.assertRegex(rust, r"\bstruct\s+DesktopLaunchOptions\b")
        self.assertNotRegex(
            rust,
            r"\bpub(?:\s*\([^)]*\))?\s+struct\s+(?:DesktopLaunchOptions|RuntimeOverride)\b",
        )
        self.assertNotIn("compatforge-ffi", cargo["dependencies"])
        self.assertNotRegex(rust, r"\b(?:no_mangle|compatforge_ffi|extern)\b")

        normalized_main = re.sub(r"\s+", "", main)
        self.assertEqual(normalized_main.count("compatforge_desktop::run(std::env::args_os())"), 1)

        allowed_environment_read = 'std::env::var_os("")'
        self.assertEqual(rust.count(allowed_environment_read), 1)
        self.assertEqual(desktop_runtime_boundary_violations(rust), set())
        self.assertEqual(
            rust_without_comments(rust_source).count('std::env::var_os("COMPATFORGE_DESKTOP_SMOKE")'),
            1,
        )

        self.assertNotIn("runtimeId", rust)
        self.assertNotIn("failureClass", rust)

    def test_application_grid_and_function_switches_are_stable(self) -> None:
        frontend = (DESKTOP / "src" / "main.ts").read_text(encoding="utf-8")
        for label in (
            'label: "应用程序"',
            'label: "安装器"',
            'label: "Bottle"',
            'label: "运行记录"',
            'label: "兼容环境"',
            'label: "已安装"',
            'label: "可安装"',
            'label: "运行中"',
            'label: "最近使用"',
            'placeholder="搜索应用"',
        ):
            self.assertIn(label, frontend)
        self.assertIn('class="app-grid"', frontend)
        self.assertIn('data-action="cancel-all"', frontend)
        self.assertIn('data-action="open-settings"', frontend)
        self.assertIn('"applications.list"', frontend)
        self.assertIn('"jobs.submit"', frontend)
        self.assertIn('"jobs.poll"', frontend)
        self.assertIn('getCurrentWindow } from "@tauri-apps/api/window"', frontend)
        self.assertIn("appWindow.startDragging()", frontend)
        self.assertIn("isTitlebarDragTarget", frontend)

    def test_settings_are_a_separate_macos_style_api_client(self) -> None:
        self.assertTrue((DESKTOP / "settings.html").is_file())
        settings = (DESKTOP / "src" / "settings.ts").read_text(encoding="utf-8")
        for label in ("通用", "运行环境", "Bottle", "自动化", "诊断", "辅助功能", "外观"):
            self.assertIn(label, settings)
        for operation in ("settings.get", "settings.update", "bottles.archives.list", "bottles.restore"):
            self.assertIn(operation, settings)
        vite = (DESKTOP / "vite.config.ts").read_text(encoding="utf-8")
        self.assertIn('settings: "settings.html"', vite)

    def test_download_requires_explicit_network_opt_in(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-assets-") as temporary:
            result = subprocess.run(
                [
                    sys.executable,
                    "-S",
                    "-B",
                    str(ASSET_TOOL),
                    "fetch",
                    "7zip",
                    "--cache-root",
                    str(Path(temporary) / "cache"),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertIn("--allow-network", result.stderr)

    def test_cache_and_evidence_tools_have_no_shell_or_repository_artifacts(self) -> None:
        source = BASELINE_TOOL.read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("Path.home", source)
        self.assertNotIn("urllib", source)
        self.assertIn("bottleInPlace", source)
        self.assertIn('"unverified"', source)
        self.assertIn("WINDOW_APPEARANCE_SECONDS = 30", source)
        self.assertIn("process_group_ids", source)

    def test_explicit_runtime_identity_is_closed_and_quartet_bound(self) -> None:
        common = [
            "--compatforge-cli",
            "C:\\tools\\compatforge.exe",
            "--cache-root",
            "C:\\acceptance\\cache",
            "--runtime-store",
            "C:\\acceptance\\runtime-store",
            "--storage-root",
            "C:\\acceptance\\storage",
            "--work-root",
            "C:\\acceptance\\work",
        ]
        quartet = [
            "--wine-root",
            "C:\\Runtimes\\selected",
            "--wine",
            "bin/wine",
            "--wineserver",
            "bin/wineserver",
            "--version",
            "24.0",
        ]

        automatic = self.baseline.parser().parse_args(common)
        self.assertIsNone(self.baseline.validate_runtime_selection(automatic))
        for runtime_id in ("crossover", "whisky"):
            arguments = self.baseline.parser().parse_args(
                [*common, "--runtime-id", runtime_id, *quartet]
            )
            self.assertEqual(self.baseline.validate_runtime_selection(arguments), runtime_id)

        invalid_argv = (
            [*common, "--runtime-id", "crossover"],
            [*common, *quartet],
            [*common, "--runtime-id", "whisky", *quartet[:-2]],
        )
        for argv in invalid_argv:
            with self.subTest(argv=argv), self.assertRaises(self.baseline.AcceptanceError):
                self.baseline.validate_runtime_selection(self.baseline.parser().parse_args(argv))

        for flag in ("--wine-root", "--wine", "--wineserver", "--version"):
            with self.subTest(empty_flag=flag), self.assertRaises(self.baseline.AcceptanceError):
                arguments = self.baseline.parser().parse_args([*common, flag, ""])
                self.baseline.validate_runtime_selection(arguments)

        parser_failures = (
            [*common, "--runtime-id", "other", *quartet],
            [*common, "--runtime-id", "crossover", "--runtime-id", "whisky", *quartet],
            [*common, "--runtime-id", "crossover", *quartet, "--wine", "other/wine"],
        )
        for argv in parser_failures:
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.baseline.parser().parse_args(argv)

    def test_failure_reason_mapping_is_closed_and_table_driven(self) -> None:
        expected = {
            "platform-unsupported": "environment",
            "runtime-descriptor-invalid": "runtime",
            "core-plan-failed": "core",
            "desktop-window-unobserved": "desktop",
            "application-interaction-unverified": "application",
            "cleanup-delete-failed": "cleanup",
        }
        self.assertEqual(
            {reason: self.baseline.failure_class(reason) for reason in expected},
            expected,
        )
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.failure_class("C:\\private\\arbitrary failure")

        expected_status = {
            "platform-unsupported": "blocked",
            "tool-unavailable": "blocked",
            "network-unavailable": "blocked",
            "rosetta-unavailable": "blocked",
            "asset-fetch-failed": "failed",
            "runtime-descriptor-invalid": "blocked",
            "runtime-start-failed": "failed",
            "runtime-version-invalid": "failed",
            "core-snapshot-failed": "failed",
            "core-plan-failed": "failed",
            "core-import-failed": "failed",
            "core-inspection-failed": "failed",
            "core-launch-failed": "failed",
            "core-verification-failed": "failed",
            "core-rollback-failed": "failed",
            "desktop-launch-failed": "failed",
            "desktop-window-unobserved": "failed",
            "application-install-failed": "failed",
            "application-interaction-unverified": "unverified",
            "application-content-verification-failed": "failed",
            "cleanup-residual-processes": "failed",
            "cleanup-termination-failed": "failed",
            "cleanup-delete-failed": "failed",
        }
        self.assertEqual(
            {reason: self.baseline.failure_status(reason) for reason in expected_status},
            expected_status,
        )
        self.assertEqual(set(self.baseline.STATUS_BY_REASON_CODE), set(expected_status))
        self.assertEqual(
            set(self.baseline.STATUS_BY_REASON_CODE),
            set(self.baseline.FAILURE_CLASS_BY_REASON_CODE),
        )
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.failure_status("arbitrary-status-reason")

    def test_execution_stage_mapping_is_independent_and_closed(self) -> None:
        expected = {
            "asset-fetch": "asset-fetch-failed",
            "runtime-descriptor": "runtime-descriptor-invalid",
            "core-plan": "core-plan-failed",
            "desktop-launch": "desktop-launch-failed",
            "installer-launch": "application-install-failed",
            "cleanup-delete": "cleanup-delete-failed",
        }
        self.assertEqual(
            {stage: self.baseline.failure_reason(stage) for stage in expected},
            expected,
        )
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.failure_reason("C:\\private\\unknown-stage")

    def test_application_outcomes_have_closed_status_and_failure_class(self) -> None:
        valid = (
            ("failed", "core-plan-failed", "core"),
            ("unverified", "application-interaction-unverified", "application"),
            ("blocked", "network-unavailable", "environment"),
        )
        for status, reason_code, expected_class in valid:
            with self.subTest(status=status, reason_code=reason_code):
                evidence: dict[str, object] = {"failureClass": "runtime", "reason": "local detail"}
                self.baseline.set_application_outcome(
                    evidence,
                    status,
                    reason_code,
                    diagnostic="C:\\Users\\developer\\secret.txt",
                )
                self.assertEqual(evidence["status"], status)
                self.assertEqual(evidence["failureClass"], expected_class)
                self.assertEqual(evidence["reasonCode"], reason_code)

        mismatches = (
            ("blocked", "core-plan-failed"),
            ("unverified", "cleanup-delete-failed"),
            ("failed", "network-unavailable"),
        )
        for status, reason_code in mismatches:
            evidence = {"sentinel": "unchanged"}
            with self.subTest(status=status, reason_code=reason_code), self.assertRaises(
                self.baseline.AcceptanceError
            ):
                self.baseline.set_application_outcome(
                    evidence,
                    status,
                    reason_code,
                    diagnostic="must not append",
                )
            self.assertEqual(evidence, {"sentinel": "unchanged"})

        accepted: dict[str, object] = {
            "failureClass": "cleanup",
            "reasonCode": "cleanup-delete-failed",
            "reason": "/Users/developer/private",
        }
        self.baseline.set_application_outcome(accepted, "accepted")
        self.assertEqual(accepted, {"status": "accepted"})
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.set_application_outcome({}, "accepted", "core-plan-failed")
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.set_application_outcome({}, "unknown")

    def test_full_evidence_preserves_bounded_ordered_diagnostics_but_compact_excludes_them(self) -> None:
        evidence: dict[str, object] = {
            "schemaVersion": "1",
            "runtimeId": "crossover",
            "appId": "7zip",
            "cleanup": False,
        }
        primary = "core plan failed under /Users/developer/primary"
        cleanup = "cleanup failed under C:\\Users\\developer\\cleanup"
        self.baseline.apply_stage_outcome(evidence, "core-plan", diagnostic=primary)
        self.baseline.apply_stage_outcome(evidence, "cleanup-delete", diagnostic=cleanup)
        self.assertEqual(
            evidence["diagnostics"],
            [
                {
                    "sequence": 1,
                    "status": "failed",
                    "failureClass": "core",
                    "reasonCode": "core-plan-failed",
                    "detail": primary,
                },
                {
                    "sequence": 2,
                    "status": "failed",
                    "failureClass": "cleanup",
                    "reasonCode": "cleanup-delete-failed",
                    "detail": cleanup,
                },
            ],
        )
        self.assertEqual(evidence["failureClass"], "cleanup")
        self.assertEqual(evidence["reasonCode"], "cleanup-delete-failed")

        receipt = {
            "schemaVersion": "1",
            "runtimeId": "crossover",
            "packId": "wine-macos-auto-preview",
            "version": "24.0",
            "packDigest": "sha256:" + "a" * 64,
            "source": "explicit-override",
        }
        compact = self.baseline.compact_summary(receipt, [evidence])
        encoded = self.baseline.compact_json(compact)
        self.assertNotIn("diagnostics", encoded)
        self.assertNotIn("/Users/", encoded)
        self.assertNotIn("C:\\\\", encoded)
        self.assertEqual(compact["applications"][0]["failureClass"], "cleanup")
        self.assertEqual(compact["applications"][0]["reasonCode"], "cleanup-delete-failed")

        bounded: dict[str, object] = {}
        for index in range(20):
            self.baseline.apply_stage_outcome(
                bounded,
                "core-plan",
                diagnostic=f"bounded diagnostic {index + 1}",
            )
        self.assertEqual(len(bounded["diagnostics"]), 16)
        self.assertEqual(bounded["diagnostics"][0]["sequence"], 1)
        self.assertEqual(bounded["diagnostics"][-1]["sequence"], 20)

        self.baseline.set_application_outcome(bounded, "accepted")
        self.assertEqual(bounded, {"status": "accepted"})

        invalid_history = {
            "diagnostics": [
                {
                    "sequence": 1,
                    "status": "failed",
                    "failureClass": "core",
                    "reasonCode": "arbitrary-reason",
                    "detail": "not a closed diagnostic",
                }
            ]
        }
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.apply_stage_outcome(
                invalid_history,
                "cleanup-delete",
                diagnostic="cleanup failed",
            )
        mismatched_history = {
            "diagnostics": [
                {
                    "sequence": 1,
                    "status": "blocked",
                    "failureClass": "core",
                    "reasonCode": "core-plan-failed",
                    "detail": "closed values with the wrong relation",
                }
            ]
        }
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.apply_stage_outcome(
                mismatched_history,
                "cleanup-delete",
                diagnostic="cleanup failed",
            )

    def test_main_preserves_primary_and_cleanup_diagnostics_only_in_full_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-diagnostic-history-") as temporary:
            root = Path(temporary)
            cli = root / "compatforge"
            cli.write_bytes(b"placeholder")
            storage = root / "storage"
            work = root / "work"
            argv = [
                str(BASELINE_TOOL),
                "--compatforge-cli",
                str(cli),
                "--cache-root",
                str(root / "cache"),
                "--runtime-store",
                str(root / "runtime-store"),
                "--storage-root",
                str(storage),
                "--work-root",
                str(work),
                "--allow-network",
            ]
            primary = "core plan failed under /Users/developer/primary"
            cleanup = "cleanup failed under C:\\Users\\developer\\cleanup"

            def fake_invoke(command, *, timeout=self.baseline.MAX_COMMAND_SECONDS):
                del timeout
                if command[1:4] == ["local", "macos", "context"]:
                    receipt = self.descriptor_receipt()
                    Path(command[-1]).write_text(
                        json.dumps(self.descriptor_context(storage, receipt)),
                        encoding="utf-8",
                    )
                    return subprocess.CompletedProcess(command, 0, json.dumps(receipt), "")
                if command[1] == "inspect":
                    return subprocess.CompletedProcess(command, 0, '{"architecture":"x86_64"}', "")
                if command[1] == "prepared-plan":
                    raise self.baseline.AcceptanceError(primary)
                raise AssertionError(f"unexpected command: {command}")

            stdout = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                mock.patch.object(self.baseline.platform, "machine", return_value="arm64"),
                mock.patch.object(self.baseline.os, "access", return_value=True),
                mock.patch.object(self.baseline, "rosetta_available", return_value=True),
                mock.patch.object(self.baseline, "invoke", side_effect=fake_invoke),
                mock.patch.object(self.baseline, "fetch_asset", return_value=root / "installer.exe"),
                mock.patch.object(self.baseline.shutil, "rmtree", side_effect=OSError(cleanup)),
                contextlib.redirect_stdout(stdout),
            ):
                result = self.baseline.main()

            self.assertEqual(result, 1)
            full = json.loads((work / "7zip-evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [(item["reasonCode"], item["detail"]) for item in full["diagnostics"]],
                [("core-plan-failed", primary), ("cleanup-delete-failed", cleanup)],
            )
            compact = json.loads(stdout.getvalue())
            self.assertEqual(compact["applications"][0]["reasonCode"], "cleanup-delete-failed")
            self.assertNotIn("diagnostics", stdout.getvalue())
            self.assertNotIn("/Users/", stdout.getvalue())
            self.assertNotIn("C:\\\\", stdout.getvalue())

    def test_actual_stage_outcomes_cover_all_failure_classes(self) -> None:
        expected = {
            "preflight-tool": ("blocked", "environment", "tool-unavailable"),
            "runtime-start": ("failed", "runtime", "runtime-start-failed"),
            "core-plan": ("failed", "core", "core-plan-failed"),
            "desktop-launch": ("failed", "desktop", "desktop-launch-failed"),
            "installer-launch": ("failed", "application", "application-install-failed"),
            "cleanup-delete": ("failed", "cleanup", "cleanup-delete-failed"),
        }
        for stage, outcome in expected.items():
            with self.subTest(stage=stage):
                evidence: dict[str, object] = {}
                self.baseline.apply_stage_outcome(evidence, stage, diagnostic="local full detail")
                self.assertEqual(
                    (evidence["status"], evidence["failureClass"], evidence["reasonCode"]),
                    outcome,
                )

    def test_actual_application_observation_branches_are_classified(self) -> None:
        accepted_events = [{"kind": "exited", "exit": {"code": 0, "success": True}}]
        nonzero_events = [{"kind": "exited", "exit": {"code": 7, "success": False}}]
        termination_failed_events = [
            {"kind": "terminate-requested"},
            {"kind": "exited", "exit": {"code": 7, "success": False}},
        ]
        complete_checks = {"fileList": True, "menus": True}
        cases = (
            (
                "accepted",
                accepted_events,
                {"available": True},
                {"available": True},
                [],
                complete_checks,
                ("accepted", None, None),
            ),
            (
                "manual-unverified",
                accepted_events,
                {"available": True},
                {"available": True},
                [],
                {},
                ("unverified", "application", "application-interaction-unverified"),
            ),
            (
                "nonzero-failed",
                nonzero_events,
                {"available": True},
                {"available": True},
                [],
                complete_checks,
                ("failed", "application", "application-content-verification-failed"),
            ),
            (
                "termination-failed",
                termination_failed_events,
                {"available": True},
                {"available": True},
                [],
                complete_checks,
                ("failed", "cleanup", "cleanup-termination-failed"),
            ),
            (
                "window-failed",
                accepted_events,
                {"available": False},
                {"available": True},
                [],
                complete_checks,
                ("failed", "desktop", "desktop-window-unobserved"),
            ),
            (
                "residual-failed",
                accepted_events,
                {"available": True},
                {"available": True},
                ["residual process"],
                complete_checks,
                ("failed", "cleanup", "cleanup-residual-processes"),
            ),
        )
        for name, events, windows, shot, residual, checks, expected in cases:
            with self.subTest(name=name):
                evidence: dict[str, object] = {}
                self.baseline.evaluate_application_outcome(
                    evidence,
                    "7zip",
                    events,
                    windows,
                    shot,
                    residual,
                    checks,
                )
                self.assertEqual(
                    (
                        evidence["status"],
                        evidence.get("failureClass"),
                        evidence.get("reasonCode"),
                    ),
                    expected,
                )
        self.assertEqual(self.baseline.status(nonzero_events), "failed")

    def test_actual_installer_branches_fail_for_nonzero_or_missing_executable(self) -> None:
        accepted_events = [{"kind": "exited", "exit": {"code": 0, "success": True}}]
        nonzero_events = [{"kind": "exited", "exit": {"code": 5, "success": False}}]
        termination_failed_events = [
            {"kind": "terminate-requested"},
            {"kind": "exited", "exit": {"code": 5, "success": False}},
        ]
        with tempfile.TemporaryDirectory(prefix="compatforge-installer-outcome-") as temporary:
            installed = Path(temporary) / "installed.exe"
            cases = (
                ("nonzero", nonzero_events, installed, "application", "application-install-failed"),
                ("missing", accepted_events, installed, "application", "application-install-failed"),
                (
                    "termination",
                    termination_failed_events,
                    installed,
                    "cleanup",
                    "cleanup-termination-failed",
                ),
            )
            for name, events, executable, failure_class, reason_code in cases:
                with self.subTest(name=name):
                    evidence: dict[str, object] = {}
                    self.assertFalse(
                        self.baseline.installer_succeeded(evidence, events, executable)
                    )
                    self.assertEqual(evidence["status"], "failed")
                    self.assertEqual(evidence["failureClass"], failure_class)
                    self.assertEqual(evidence["reasonCode"], reason_code)

            installed.write_bytes(b"MZ")
            evidence = {}
            self.assertTrue(self.baseline.installer_succeeded(evidence, accepted_events, installed))
            self.assertEqual(evidence, {})

    def test_asset_preflight_blocks_only_missing_offline_asset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-asset-preflight-") as temporary:
            cache_entry = Path(temporary) / "asset.exe"
            evidence: dict[str, object] = {}
            self.assertFalse(self.baseline.asset_preflight(evidence, cache_entry, False))
            self.assertEqual(evidence["status"], "blocked")
            self.assertEqual(evidence["failureClass"], "environment")
            self.assertEqual(evidence["reasonCode"], "network-unavailable")

            cache_entry.write_bytes(b"cached")
            evidence = {}
            self.assertTrue(self.baseline.asset_preflight(evidence, cache_entry, False))
            self.assertEqual(evidence, {})

            cache_entry.unlink()
            evidence = {}
            self.assertTrue(self.baseline.asset_preflight(evidence, cache_entry, True))
            self.assertEqual(evidence, {})

    def test_invoke_and_fetch_asset_preserve_closed_failure_kinds(self) -> None:
        command_result = subprocess.CompletedProcess(
            ["compatforge", "inspect"],
            9,
            "",
            "failure under /Users/developer/runtime",
        )
        with mock.patch.object(self.baseline.subprocess, "run", return_value=command_result):
            with self.assertRaises(self.baseline.InvocationError) as caught:
                self.baseline.invoke(["/external/compatforge", "inspect"])
        self.assertEqual(caught.exception.closed_code, "command-failed")
        self.assertEqual(caught.exception.returncode, 9)
        self.assertIn("/Users/developer/runtime", caught.exception.diagnostic)

        arguments = mock.Mock()
        arguments.cache_root = Path("/external/cache")
        arguments.allow_network = True
        with mock.patch.object(
            self.baseline,
            "invoke",
            side_effect=AssertionError("fetch_asset must use typed downloader failures"),
        ):
            with mock.patch.object(
                self.assets,
                "fetch",
                side_effect=urllib.error.URLError("DNS unavailable"),
            ):
                with self.assertRaises(self.baseline.NetworkUnavailableError):
                    self.baseline.fetch_asset(arguments, "7zip")
            with mock.patch.object(
                self.assets,
                "fetch",
                side_effect=http.client.IncompleteRead(b"partial", 4096),
            ):
                with self.assertRaises(self.baseline.NetworkUnavailableError):
                    self.baseline.fetch_asset(arguments, "7zip")
            with mock.patch.object(
                self.assets,
                "fetch",
                side_effect=self.assets.AssetError("cached 7zip digest mismatch"),
            ):
                with self.assertRaises(self.baseline.AssetFetchError):
                    self.baseline.fetch_asset(arguments, "7zip")

    def test_downloader_typed_network_boundary_preserves_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-downloader-") as temporary:
            cache_root = Path(temporary)
            asset = self.assets.ASSETS[0]
            with mock.patch.object(
                self.assets,
                "fetch",
                side_effect=urllib.error.URLError("DNS unavailable for acceptance host"),
            ):
                with self.assertRaises(self.assets.NetworkUnavailable) as caught:
                    self.assets.fetch_classified(asset, cache_root, True)
            self.assertIn("DNS unavailable", caught.exception.diagnostic)
            self.assertEqual(str(caught.exception), "network unavailable")

            protocol_failures = (
                http.client.IncompleteRead(b"partial", 4096),
                http.client.RemoteDisconnected("response closed before installer body completed"),
            )
            for protocol_failure in protocol_failures:
                with self.subTest(protocol_failure=type(protocol_failure).__name__), mock.patch.object(
                    self.assets,
                    "fetch",
                    side_effect=protocol_failure,
                ):
                    with self.assertRaises(self.assets.NetworkUnavailable) as protocol:
                        self.assets.fetch_classified(asset, cache_root, True)
                self.assertTrue(protocol.exception.diagnostic)

            for detail in (
                "cached asset digest mismatch",
                "download redirect leaves official host allowlist",
            ):
                with self.subTest(detail=detail), mock.patch.object(
                    self.assets,
                    "fetch",
                    side_effect=self.assets.AssetError(detail),
                ):
                    with self.assertRaises(self.assets.AssetError) as deterministic:
                        self.assets.fetch_classified(asset, cache_root, True)
                self.assertNotIsInstance(deterministic.exception, self.assets.NetworkUnavailable)
                self.assertEqual(str(deterministic.exception), detail)

            http_error = urllib.error.HTTPError(
                asset.url,
                404,
                "installer content not found",
                None,
                None,
            )
            with mock.patch.object(self.assets, "fetch", side_effect=http_error):
                with self.assertRaises(urllib.error.HTTPError) as deterministic_http:
                    self.assets.fetch_classified(asset, cache_root, True)
            self.assertNotIsInstance(deterministic_http.exception, self.assets.NetworkUnavailable)

    def test_offline_downloader_rejects_an_isolated_mutated_cached_installer(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-mutated-cache-") as temporary:
            root = Path(temporary)
            original_cache = root / "original-cache"
            negative_cache = root / "negative-cache"
            original_cache.mkdir()
            negative_cache.mkdir()
            original = b"MZ" + b"fixed-installer-fixture"
            digest = hashlib.sha256(original).hexdigest()
            asset = dataclasses.replace(self.assets.ASSETS[0], sha256=digest)
            source = original_cache / asset.filename
            mutant = negative_cache / asset.filename
            source.write_bytes(original)
            mutant.write_bytes(original)
            mutated = bytearray(mutant.read_bytes())
            mutated[0] ^= 0xFF
            mutant.write_bytes(mutated)
            source_metadata = source.stat()

            with mock.patch.object(
                self.assets.urllib.request,
                "build_opener",
                side_effect=AssertionError("offline cache validation attempted network access"),
            ):
                self.assertEqual(
                    self.assets.fetch(asset, original_cache, False),
                    source,
                )
                with self.assertRaisesRegex(
                    self.assets.AssetError,
                    "^cached 7zip digest mismatch$",
                ):
                    self.assets.fetch(asset, negative_cache, False)

            current = source.stat()
            self.assertEqual(
                (current.st_dev, current.st_ino),
                (source_metadata.st_dev, source_metadata.st_ino),
            )
            self.assertEqual(source.read_bytes(), original)

    def test_protocol_body_failure_flows_through_fetch_asset_and_main_as_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-protocol-body-") as temporary:
            root = Path(temporary)
            cli = root / "compatforge"
            cli.write_bytes(b"placeholder")
            storage = root / "storage"
            work = root / "work"
            argv = [
                str(BASELINE_TOOL),
                "--compatforge-cli",
                str(cli),
                "--cache-root",
                str(root / "cache"),
                "--runtime-store",
                str(root / "runtime-store"),
                "--storage-root",
                str(storage),
                "--work-root",
                str(work),
                "--allow-network",
            ]

            def fake_invoke(command, *, timeout=self.baseline.MAX_COMMAND_SECONDS):
                del timeout
                if command[1:4] != ["local", "macos", "context"]:
                    raise AssertionError(f"unexpected command: {command}")
                receipt = self.descriptor_receipt()
                Path(command[-1]).write_text(
                    json.dumps(self.descriptor_context(storage, receipt)),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0, json.dumps(receipt), "")

            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                mock.patch.object(self.baseline.platform, "machine", return_value="arm64"),
                mock.patch.object(self.baseline.os, "access", return_value=True),
                mock.patch.object(self.baseline, "rosetta_available", return_value=True),
                mock.patch.object(self.baseline, "invoke", side_effect=fake_invoke),
                mock.patch.object(
                    self.assets,
                    "fetch",
                    side_effect=http.client.IncompleteRead(b"partial", 4096),
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = self.baseline.main()

            self.assertEqual(result, 1)
            compact = json.loads(stdout.getvalue())
            self.assertEqual(
                [(item["status"], item["reasonCode"]) for item in compact["applications"]],
                [("blocked", "network-unavailable")] * 3,
            )
            full = json.loads((work / "7zip-evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(full["status"], "blocked")
            self.assertEqual(full["failureClass"], "environment")
            self.assertTrue(full["diagnostics"][0]["detail"])
            self.assertNotIn(str(root), stdout.getvalue())
            self.assertEqual(stderr.getvalue(), "")

    def test_allow_network_main_blocks_network_failure_but_fails_deterministic_asset_error(self) -> None:
        cases = (
            (
                "network",
                self.baseline.NetworkUnavailableError("network unavailable under /Users/developer/network"),
                "blocked",
                "network-unavailable",
            ),
            (
                "digest",
                self.baseline.AssetFetchError("digest mismatch under C:\\Users\\developer\\asset"),
                "failed",
                "asset-fetch-failed",
            ),
        )
        for name, fetch_error, expected_status, expected_reason in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix=f"compatforge-gui-{name}-asset-"
            ) as temporary:
                root = Path(temporary)
                cli = root / "compatforge"
                cli.write_bytes(b"placeholder")
                storage = root / "storage"
                work = root / "work"
                argv = [
                    str(BASELINE_TOOL),
                    "--compatforge-cli",
                    str(cli),
                    "--cache-root",
                    str(root / "cache"),
                    "--runtime-store",
                    str(root / "runtime-store"),
                    "--storage-root",
                    str(storage),
                    "--work-root",
                    str(work),
                    "--allow-network",
                ]

                def fake_invoke(command, *, timeout=self.baseline.MAX_COMMAND_SECONDS):
                    del timeout
                    if command[1:4] != ["local", "macos", "context"]:
                        raise AssertionError(f"unexpected command: {command}")
                    context_path = Path(command[-1])
                    receipt = self.descriptor_receipt()
                    context_path.write_text(
                        json.dumps(self.descriptor_context(storage, receipt)),
                        encoding="utf-8",
                    )
                    return subprocess.CompletedProcess(command, 0, json.dumps(receipt), "")

                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                    mock.patch.object(self.baseline.platform, "machine", return_value="arm64"),
                    mock.patch.object(self.baseline.os, "access", return_value=True),
                    mock.patch.object(self.baseline, "rosetta_available", return_value=True),
                    mock.patch.object(self.baseline, "invoke", side_effect=fake_invoke),
                    mock.patch.object(self.baseline, "fetch_asset", side_effect=fetch_error),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    result = self.baseline.main()
                self.assertEqual(result, 1)
                compact = json.loads(stdout.getvalue())
                self.assertEqual(
                    [application["status"] for application in compact["applications"]],
                    [expected_status, expected_status, expected_status],
                )
                self.assertEqual(
                    [application["reasonCode"] for application in compact["applications"]],
                    [expected_reason, expected_reason, expected_reason],
                )
                self.assertNotIn("diagnostics", stdout.getvalue())
                self.assertNotIn("/Users/", stdout.getvalue())
                self.assertNotIn("C:\\\\", stdout.getvalue())
                full = json.loads((work / "7zip-evidence.json").read_text(encoding="utf-8"))
                self.assertEqual(full["status"], expected_status)
                self.assertEqual(full["reasonCode"], expected_reason)
                self.assertEqual(len(full["diagnostics"]), 1)
                self.assertEqual(stderr.getvalue(), "")

    def test_main_writes_blocked_preflight_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-preflight-") as temporary:
            root = Path(temporary)
            work = root / "work"
            argv = [
                str(BASELINE_TOOL),
                "--compatforge-cli",
                str(root / "missing-compatforge"),
                "--cache-root",
                str(root / "cache"),
                "--runtime-store",
                str(root / "runtime-store"),
                "--storage-root",
                str(root / "storage"),
                "--work-root",
                str(work),
            ]
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(self.baseline.platform, "system", return_value="Linux"),
                mock.patch.object(self.baseline.platform, "machine", return_value="x86_64"),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = self.baseline.main()
            self.assertEqual(result, 1)
            full = json.loads((work / "preflight-evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(full["status"], "blocked")
            self.assertEqual(full["failureClass"], "environment")
            self.assertEqual(full["reasonCode"], "platform-unsupported")
            self.assertIn("requires Darwin/arm64", full["reason"])
            compact = json.loads(stdout.getvalue())
            self.assertEqual(
                compact,
                {
                    "schemaVersion": "1",
                    "runtimeId": None,
                    "status": "blocked",
                    "failureClass": "environment",
                    "reasonCode": "platform-unsupported",
                },
            )
            self.assertEqual(
                compact,
                json.loads((work / "summary.json").read_text(encoding="utf-8")),
            )
            self.assertEqual(stderr.getvalue(), "")

    def test_main_writes_blocked_runtime_descriptor_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-runtime-blocked-") as temporary:
            root = Path(temporary)
            cli = root / "compatforge"
            cli.write_bytes(b"placeholder")
            work = root / "work"
            argv = [
                str(BASELINE_TOOL),
                "--compatforge-cli",
                str(cli),
                "--cache-root",
                str(root / "cache"),
                "--runtime-store",
                str(root / "runtime-store"),
                "--storage-root",
                str(root / "storage"),
                "--work-root",
                str(work),
            ]
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                mock.patch.object(self.baseline.platform, "machine", return_value="arm64"),
                mock.patch.object(self.baseline.os, "access", return_value=True),
                mock.patch.object(self.baseline, "rosetta_available", return_value=True),
                mock.patch.object(
                    self.baseline,
                    "invoke",
                    side_effect=self.baseline.AcceptanceError(
                        "Runtime descriptor unavailable under /Users/developer/runtime"
                    ),
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                result = self.baseline.main()
            self.assertEqual(result, 1)
            full = json.loads((work / "preflight-evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(full["status"], "blocked")
            self.assertEqual(full["failureClass"], "runtime")
            self.assertEqual(full["reasonCode"], "runtime-descriptor-invalid")
            self.assertIn("/Users/developer/runtime", full["reason"])
            compact = json.loads(stdout.getvalue())
            self.assertEqual(compact["status"], "blocked")
            self.assertEqual(compact["failureClass"], "runtime")
            self.assertEqual(compact["reasonCode"], "runtime-descriptor-invalid")
            self.assertNotIn("/Users/", stdout.getvalue())
            self.assertEqual(stderr.getvalue(), "")

    def test_main_closes_all_runtime_descriptor_context_failures_as_blocked_evidence(self) -> None:
        cases = (
            "missing-context",
            "invalid-json",
            "nonobject",
            "schema-mismatch",
            "missing-bindings",
            "storage-mismatch",
            "binding-mismatch",
            "receipt-runtime-mismatch",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(
                prefix=f"compatforge-gui-descriptor-{case}-"
            ) as temporary:
                root = Path(temporary)
                cli = root / "compatforge"
                cli.write_bytes(b"placeholder")
                storage = root / "storage"
                work = root / "work"
                argv = [
                    str(BASELINE_TOOL),
                    "--compatforge-cli",
                    str(cli),
                    "--cache-root",
                    str(root / "cache"),
                    "--runtime-store",
                    str(root / "runtime-store"),
                    "--storage-root",
                    str(storage),
                    "--work-root",
                    str(work),
                ]

                def fake_invoke(command, *, timeout=self.baseline.MAX_COMMAND_SECONDS):
                    del timeout
                    self.assertEqual(command[1:4], ["local", "macos", "context"])
                    receipt = self.descriptor_receipt()
                    context_path = Path(command[-1])
                    context = self.descriptor_context(storage, receipt)
                    if case == "invalid-json":
                        context_path.write_text("{", encoding="utf-8")
                    elif case == "nonobject":
                        context_path.write_text("[]", encoding="utf-8")
                    elif case == "schema-mismatch":
                        context["schemaVersion"] = "2"
                        context_path.write_text(json.dumps(context), encoding="utf-8")
                    elif case == "missing-bindings":
                        del context["runtimeBindings"]
                        context_path.write_text(json.dumps(context), encoding="utf-8")
                    elif case == "storage-mismatch":
                        context["storageRoot"] = str(root / "different-storage")
                        context_path.write_text(json.dumps(context), encoding="utf-8")
                    elif case == "binding-mismatch":
                        context["runtimeBindings"][0]["packDigest"] = "sha256:" + "b" * 64
                        context_path.write_text(json.dumps(context), encoding="utf-8")
                    elif case == "receipt-runtime-mismatch":
                        receipt["runtimeId"] = "crossover"
                        context_path.write_text(json.dumps(context), encoding="utf-8")
                    elif case != "missing-context":
                        raise AssertionError(f"unhandled descriptor case: {case}")
                    return subprocess.CompletedProcess(command, 0, json.dumps(receipt), "")

                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                    mock.patch.object(self.baseline.platform, "machine", return_value="arm64"),
                    mock.patch.object(self.baseline.os, "access", return_value=True),
                    mock.patch.object(self.baseline, "rosetta_available", return_value=True),
                    mock.patch.object(self.baseline, "invoke", side_effect=fake_invoke),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    result = self.baseline.main()

                self.assertEqual(result, 1)
                full = json.loads((work / "preflight-evidence.json").read_text(encoding="utf-8"))
                self.assertEqual(full["status"], "blocked")
                self.assertEqual(full["failureClass"], "runtime")
                self.assertEqual(full["reasonCode"], "runtime-descriptor-invalid")
                compact_text = stdout.getvalue()
                compact = json.loads(compact_text)
                self.assertEqual(compact["reasonCode"], "runtime-descriptor-invalid")
                self.assertEqual(
                    compact_text,
                    json.dumps(compact, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                )
                self.assertNotIn(str(root), compact_text)
                self.assertEqual(stderr.getvalue(), "")

    def test_main_writes_blocked_tool_and_rosetta_preflight_evidence(self) -> None:
        cases = (
            ("tool", False, True, "tool-unavailable"),
            ("rosetta", True, False, "rosetta-unavailable"),
        )
        for name, create_cli, rosetta, reason_code in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix=f"compatforge-gui-{name}-blocked-"
            ) as temporary:
                root = Path(temporary)
                cli = root / "compatforge"
                if create_cli:
                    cli.write_bytes(b"placeholder")
                work = root / "work"
                argv = [
                    str(BASELINE_TOOL),
                    "--compatforge-cli",
                    str(cli),
                    "--cache-root",
                    str(root / "cache"),
                    "--runtime-store",
                    str(root / "runtime-store"),
                    "--storage-root",
                    str(root / "storage"),
                    "--work-root",
                    str(work),
                ]
                stdout = io.StringIO()
                stderr = io.StringIO()
                with (
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                    mock.patch.object(self.baseline.platform, "machine", return_value="arm64"),
                    mock.patch.object(self.baseline.os, "access", return_value=True),
                    mock.patch.object(self.baseline, "rosetta_available", return_value=rosetta),
                    mock.patch.object(
                        self.baseline,
                        "invoke",
                        side_effect=self.baseline.AcceptanceError("must not bootstrap"),
                    ),
                    contextlib.redirect_stdout(stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    result = self.baseline.main()
                self.assertEqual(result, 1)
                full = json.loads((work / "preflight-evidence.json").read_text(encoding="utf-8"))
                self.assertEqual(full["status"], "blocked")
                self.assertEqual(full["failureClass"], "environment")
                self.assertEqual(full["reasonCode"], reason_code)
                compact = json.loads(stdout.getvalue())
                self.assertEqual(compact["reasonCode"], reason_code)
                self.assertEqual(stderr.getvalue(), "")

    def test_receipt_and_application_evidence_share_runtime_identity(self) -> None:
        for runtime_id in ("crossover", "whisky"):
            with self.subTest(runtime_id=runtime_id):
                receipt: dict[str, object] = {"schemaVersion": "1"}
                applications = [{"appId": "7zip"}, {"appId": "sumatrapdf"}]
                self.baseline.bind_runtime_identity(runtime_id, receipt, applications)
                self.assertEqual(receipt["runtimeId"], runtime_id)
                self.assertEqual(
                    [application["runtimeId"] for application in applications],
                    [runtime_id, runtime_id],
                )

        automatic_receipt: dict[str, object] = {"schemaVersion": "1"}
        automatic_applications = [{"appId": "7zip"}]
        self.baseline.bind_runtime_identity(None, automatic_receipt, automatic_applications)
        self.assertIsNone(automatic_receipt["runtimeId"])
        self.assertIsNone(automatic_applications[0]["runtimeId"])

    def test_compact_validation_is_shape_first_iterative_and_bounded(self) -> None:
        receipt = {
            "schemaVersion": "1",
            "runtimeId": "crossover",
            "packId": "local-crossover",
            "version": "24.0",
            "packDigest": "sha256:" + "a" * 64,
            "source": "crossover-app",
        }
        application = {
            "schemaVersion": "1",
            "runtimeId": "crossover",
            "appId": "7zip",
            "status": "failed",
            "failureClass": "core",
            "reasonCode": "core-plan-failed",
            "cleanup": True,
        }

        nested: object = True
        for _ in range(1200):
            nested = {"safe": nested}
        deep_known_field = {
            "schemaVersion": "1",
            "receipt": {**receipt, "activated": nested},
            "applications": [application],
        }
        with self.assertRaises(self.baseline.AcceptanceError) as shape_error:
            self.baseline.validate_compact_summary(deep_known_field)
        self.assertEqual(str(shape_error.exception), "compact receipt activated must be a boolean")

        depth_boundary: object = "leaf"
        for _ in range(self.baseline.MAX_COMPACT_DEPTH):
            depth_boundary = [depth_boundary]
        self.baseline._scan_compact_scalars(depth_boundary)
        too_deep = [depth_boundary]
        with self.assertRaises(self.baseline.AcceptanceError) as depth_error:
            self.baseline._scan_compact_scalars(too_deep)
        self.assertEqual(str(depth_error.exception), "compact summary exceeds structural bounds")

        node_boundary = [None] * (self.baseline.MAX_COMPACT_NODES - 1)
        self.baseline._scan_compact_scalars(node_boundary)
        with self.assertRaises(self.baseline.AcceptanceError) as node_error:
            self.baseline._scan_compact_scalars([*node_boundary, None])
        self.assertEqual(str(node_error.exception), "compact summary exceeds structural bounds")

        self.baseline._scan_compact_scalars("x" * self.baseline.MAX_COMPACT_TEXT_CHARS)
        with self.assertRaises(self.baseline.AcceptanceError) as text_error:
            self.baseline._scan_compact_scalars("x" * (self.baseline.MAX_COMPACT_TEXT_CHARS + 1))
        self.assertEqual(str(text_error.exception), "compact summary text exceeds its bound")

        with self.assertRaises(self.baseline.AcceptanceError) as key_type_error:
            self.baseline._scan_compact_scalars({1: True})
        self.assertEqual(str(key_type_error.exception), "compact summary text is invalid")

        deep_keys: object = {"/Users/developer/private": True}
        for _ in range(1200):
            deep_keys = {"safe": deep_keys}
        with self.assertRaises(self.baseline.AcceptanceError) as key_error:
            self.baseline._scan_compact_scalars(deep_keys)
        self.assertEqual(str(key_error.exception), "compact summary exceeds structural bounds")
        self.assertNotIn("/Users/", str(key_error.exception))

    def test_compact_summary_is_canonical_closed_and_path_free(self) -> None:
        receipt = {
            "schemaVersion": "1",
            "runtimeId": "crossover",
            "packId": "local-crossover",
            "version": "24.0",
            "packDigest": "sha256:" + "a" * 64,
            "source": "crossover-app",
            "providerConfigPath": "/Users/developer/acceptance/provider.json",
        }
        applications = [
            {
                "schemaVersion": "1",
                "runtimeId": "crossover",
                "appId": "7zip",
                "status": "failed",
                "failureClass": "desktop",
                "reasonCode": "desktop-window-unobserved",
                "reason": "window tool failed under C:\\Users\\developer\\acceptance",
                "cleanupError": "/Users/developer/acceptance/bottle is busy",
                "cleanup": True,
                "interactionChecks": {
                    "fileList": True,
                    "menus": False,
                },
                "exit": {"present": True, "code": 0, "success": True, "path": "/private/tmp/log"},
                "windows": {"available": False, "reason": "/Users/developer denied access"},
                "screenshot": {"available": False, "path": "/Users/developer/7zip.png"},
            }
        ]
        compact = self.baseline.compact_summary(receipt, applications)
        expected = {
            "schemaVersion": "1",
            "receipt": {
                "schemaVersion": "1",
                "runtimeId": "crossover",
                "packId": "local-crossover",
                "version": "24.0",
                "packDigest": "sha256:" + "a" * 64,
                "source": "crossover-app",
            },
            "applications": [
                {
                    "schemaVersion": "1",
                    "runtimeId": "crossover",
                    "appId": "7zip",
                    "status": "failed",
                    "failureClass": "desktop",
                    "reasonCode": "desktop-window-unobserved",
                    "cleanup": True,
                    "interactionChecks": {"fileList": True, "menus": False},
                    "exit": {"present": True, "code": 0, "success": True},
                    "windowAvailable": False,
                    "screenshotAvailable": False,
                }
            ],
        }
        self.assertEqual(compact, expected)
        encoded = self.baseline.compact_json(compact)
        self.assertEqual(
            encoded,
            json.dumps(expected, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )
        self.assertNotIn("C:\\\\", encoded)
        self.assertNotIn("/Users/", encoded)
        self.assertNotIn("/private/", encoded)

        poisoned_receipt = {**receipt, "source": "/Users/developer/runtime"}
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.compact_summary(poisoned_receipt, applications)

        unsafe_receipt_values = (
            {"source": "file:///Users/developer/runtime"},
            {"source": "failure under /Users/developer/runtime"},
            {"source": "failure under C:\\Users\\developer\\runtime"},
            {"source": "crossover-app\nsecret"},
            {"source": {"nested": "crossover-app"}},
            {"activated": {"nested": True}},
        )
        for mutation in unsafe_receipt_values:
            with self.subTest(mutation=mutation), self.assertRaises(self.baseline.AcceptanceError):
                self.baseline.compact_summary({**receipt, **mutation}, applications)

        unsafe_application = json.loads(json.dumps(applications))
        unsafe_application[0]["interactionChecks"]["/Users/developer/secret"] = True
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.compact_summary(receipt, unsafe_application)
        nested_application_id = json.loads(json.dumps(applications))
        nested_application_id[0]["appId"] = {"nested": "7zip"}
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.compact_summary(receipt, nested_application_id)

        status_reason_mismatches = (
            ("blocked", "core", "core-plan-failed"),
            ("unverified", "cleanup", "cleanup-delete-failed"),
            ("failed", "environment", "network-unavailable"),
        )
        for status, failure_class, reason_code in status_reason_mismatches:
            with self.subTest(boundary="full", status=status, reason_code=reason_code):
                full_mutant = json.loads(json.dumps(applications))
                full_mutant[0].update(
                    status=status,
                    failureClass=failure_class,
                    reasonCode=reason_code,
                )
                with self.assertRaises(self.baseline.AcceptanceError):
                    self.baseline.compact_summary(receipt, full_mutant)
            with self.subTest(boundary="compact", status=status, reason_code=reason_code):
                compact_mutant = json.loads(json.dumps(expected))
                compact_mutant["applications"][0].update(
                    status=status,
                    failureClass=failure_class,
                    reasonCode=reason_code,
                )
                with self.assertRaises(self.baseline.AcceptanceError):
                    self.baseline.validate_compact_summary(compact_mutant)

        polluted_history = json.loads(json.dumps(applications))
        polluted_history[0]["diagnostics"] = [
            {
                "sequence": 1,
                "status": "blocked",
                "failureClass": "core",
                "reasonCode": "core-plan-failed",
                "detail": "closed values with the wrong relation",
            }
        ]
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.compact_summary(receipt, polluted_history)

        compact_mutants = []
        nested_key = json.loads(json.dumps(expected))
        nested_key["applications"][0]["interactionChecks"]["/Users/developer/secret"] = True
        compact_mutants.append(nested_key)
        unknown_nested = json.loads(json.dumps(expected))
        unknown_nested["receipt"]["activated"] = {"/Users/developer/secret": True}
        compact_mutants.append(unknown_nested)
        embedded_windows = json.loads(json.dumps(expected))
        embedded_windows["receipt"]["source"] = "failed under C:/Users/developer/runtime"
        compact_mutants.append(embedded_windows)
        control_value = json.loads(json.dumps(expected))
        control_value["receipt"]["version"] = "24.0\u0001secret"
        compact_mutants.append(control_value)
        for mutant in compact_mutants:
            with self.subTest(mutant=mutant), self.assertRaises(self.baseline.AcceptanceError):
                self.baseline.compact_json(mutant)

    def test_each_application_evidence_is_appended_once(self) -> None:
        source = BASELINE_TOOL.read_text(encoding="utf-8")
        self.assertEqual(source.count("results.append(evidence)"), 1)

    def test_acceptance_requires_complete_structured_interaction_evidence(self) -> None:
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.interaction_evidence(None, True)
        with tempfile.TemporaryDirectory(prefix="compatforge-interactions-") as temporary:
            path = Path(temporary) / "interactions.json"
            path.write_text(
                json.dumps(
                    {
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
                ),
                encoding="utf-8",
            )
            checks = self.baseline.interaction_evidence(path, True)
            self.assertTrue(checks["notepad-plus-plus"]["rereadMatches"])

    def test_residual_process_check_uses_the_launch_process_group(self) -> None:
        with mock.patch.object(
            self.baseline,
            "process_table",
            return_value=[
                (100, 100, "/runtime/wine unrelated.exe"),
                (101, 777, "/runtime/wine target.exe"),
                (102, 102, "/runtime/wine /external/bottle/drive_c/app.exe"),
            ],
        ):
            residual = self.baseline.process_snapshot("/external/bottle", 777)
        self.assertEqual(len(residual), 2)
        self.assertTrue(any(value.startswith("101 ") for value in residual))
        self.assertTrue(any(value.startswith("102 ") for value in residual))

    def test_window_evidence_is_structured_and_title_bound(self) -> None:
        windows = self.baseline.matching_windows(
            "48498|7-Zip|1288x711\n99|Unrelated|800x600\n100|7-Zip|0x600\n",
            ("7-Zip",),
        )
        self.assertEqual(
            windows,
            [{"processId": 48498, "title": "7-Zip", "width": 1288, "height": 711}],
        )

    def test_list_output_is_json_and_does_not_download(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-assets-") as temporary:
            cache = Path(temporary) / "cache"
            result = subprocess.run(
                [
                    sys.executable,
                    "-S",
                    "-B",
                    str(ASSET_TOOL),
                    "list",
                    "--cache-root",
                    str(cache),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([item["appId"] for item in json.loads(result.stdout)], ["7zip", "sumatrapdf", "notepad-plus-plus"])
            self.assertFalse(cache.exists())


if __name__ == "__main__":
    unittest.main()
