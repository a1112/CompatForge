from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
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


def rust_without_comments(source: str) -> str:
    """Remove nested Rust comments while preserving string literals."""
    output: list[str] = []
    index = 0
    block_depth = 0
    in_line_comment = False
    in_string = False
    escaped = False
    while index < len(source):
        pair = source[index : index + 2]
        character = source[index]
        if in_line_comment:
            if character == "\n":
                in_line_comment = False
                output.append(character)
            index += 1
            continue
        if block_depth:
            if pair == "/*":
                block_depth += 1
                index += 2
            elif pair == "*/":
                block_depth -= 1
                index += 2
            else:
                if character == "\n":
                    output.append(character)
                index += 1
            continue
        if in_string:
            output.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            index += 1
            continue
        if pair == "//":
            in_line_comment = True
            index += 2
        elif pair == "/*":
            block_depth = 1
            index += 2
        else:
            output.append(character)
            if character == '"':
                in_string = True
            index += 1
    return "".join(output)


def rust_code_only(source: str) -> str:
    source = rust_without_comments(source)
    source = re.sub(r'(?s)(?:br|r)(?P<hash>#{0,16})".*?"(?P=hash)', '""', source)
    return re.sub(r'(?s)b?"(?:\\.|[^"\\])*"', '""', source)


class GuiBaselineContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.assets = load_tool(ASSET_TOOL)
        cls.baseline = load_tool(BASELINE_TOOL)

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
        rust_without_smoke = rust.replace(allowed_environment_read, "")
        self.assertNotRegex(rust_without_smoke, r"\benv\b")
        self.assertNotRegex(rust, r"\b(?:Command|PATH)\b")
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
