from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import http.client
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
import urllib.error
import zipfile
from dataclasses import replace
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSET_TOOL = ROOT / "tools" / "download_gui_assets.py"
BASELINE_TOOL = ROOT / "tools" / "run_gui_baseline.py"
ACKNOWLEDGEMENT_TOOL = ROOT / "tools" / "confirm_macos_gui_interactions.py"
INTERACTION_TOOL = ROOT / "tools" / "prepare_gui_interaction_evidence.py"
SUMMARY_TOOL = ROOT / "tools" / "summarize_gui_compatibility.py"
SOAK_TOOL = ROOT / "tools" / "run_gui_soak.py"
DESKTOP = ROOT / "apps" / "desktop"
TAURI = DESKTOP / "src-tauri"
PRIVATE_TMP = Path("/private/tmp") if Path("/private/tmp").is_dir() else None


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
        cls.acknowledgements = load_tool(ACKNOWLEDGEMENT_TOOL)
        cls.baseline = load_tool(BASELINE_TOOL)
        cls.summary_tool = load_tool(SUMMARY_TOOL)
        cls.soak_tool = load_tool(SOAK_TOOL)

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

    @staticmethod
    def interaction_plan(round_id: str = "round-1", runtime_id: str = "crossover") -> dict[str, object]:
        return {
            "schemaVersion": "1",
            "roundId": round_id,
            "runtimeId": runtime_id,
            "applications": {
                app_id: {"requiredChecks": list(checks)}
                for app_id, checks in (
                    ("7zip", ("fileList", "menus")),
                    ("sumatrapdf", ("mainWindow", "openDialog")),
                    (
                        "notepad-plus-plus",
                        (
                            "open",
                            "edit",
                            "saveUtf8Chinese",
                            "cjkTextReadable",
                            "rereadMatches",
                        ),
                    ),
                )
            },
        }

    @staticmethod
    def write_canonical_json(path: Path, value: object) -> None:
        path.write_bytes(
            (
                json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        )

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

    def test_rust_code_projection_excludes_pinned_wiring_decoys(self) -> None:
        root_check = (
            "self.work_root()?.revalidate().map_err(|_| PinnedSessionError)?;"
        )
        decoys = f'''
// {root_check}
/* {root_check} */
const TEXT: &str = "{root_check}";
const RAW: &str = r#"{root_check}"#;
const RAW_BYTES: &[u8] = br##"{root_check}"##;
const BYTES: &[u8] = b"{root_check}";
'''
        self.assertNotIn(root_check, rust_code_only(decoys))

        real_after_decoys = f'''
/* {root_check} */ {root_check}
const TEXT: &str = "{root_check}"; {root_check}
const RAW: &str = r#"{root_check}"#; {root_check}
const RAW_BYTES: &[u8] = br##"{root_check}"##; {root_check}
const BYTES: &[u8] = b"{root_check}"; {root_check}
'''
        self.assertEqual(rust_code_only(real_after_decoys).count(root_check), 5)

    def test_fixed_official_asset_matrix_is_closed(self) -> None:
        self.assertEqual(
            [asset.app_id for asset in self.assets.BASELINE_ASSETS],
            ["7zip", "sumatrapdf", "notepad-plus-plus"],
        )
        self.assertEqual(
            [asset.sha256 for asset in self.assets.BASELINE_ASSETS],
            [
                "d64a0468f5b5b0b0fc5b2188450bcd655b70809d97b1c4535f2884635094377d",
                "719f689b34f47be8ca105ce8484948474dafde0e106bab599e4a89326070c3d0",
                "7c243203265ce8fdac76c839bf744ae35dcf620760eb97c2ea279af498560e45",
            ],
        )
        for asset in self.assets.ASSETS:
            self.assertTrue(asset.url.startswith("https://"))
            self.assertEqual(len(asset.sha256), 64)
            self.assertTrue(asset.window_title_tokens)
            self.assertIn(asset.package_kind, {"installer", "portable-zip"})
        self.assertEqual([asset.app_id for asset in self.assets.EXTENDED_ASSETS], ["firefox", "krita"])
        self.assertEqual(
            [asset.app_id for asset in self.assets.CERTIFICATION_ASSETS],
            ["7zip-x86", "vlc", "winmerge", "audacity-x86", "everything-x86"],
        )
        self.assertEqual(len(self.assets.ASSETS), 10)
        self.assertEqual(
            {asset.guest_architecture for asset in self.assets.CERTIFICATION_ASSETS},
            {"i386", "x86_64"},
        )
        self.assertEqual(self.assets.asset_for("winmerge").guest_architecture, "x86_64")
        self.assertEqual(self.assets.asset_for("winmerge").package_kind, "portable-zip")
        self.assertEqual(
            self.assets.asset_for("winmerge").installed_executable,
            "WinMerge/WinMergeU.exe",
        )
        self.assertEqual(self.assets.asset_for("winmerge").window_appearance_seconds, 45)
        self.assertEqual(self.assets.asset_for("everything-x86").launch_args, ("-nodb",))
        self.assertEqual(
            {asset.category for asset in self.assets.CERTIFICATION_ASSETS},
            {"win32", "multimedia", "developer-tool", "audio", "search"},
        )
        self.assertTrue(all(asset.launch_args for asset in self.assets.EXTENDED_ASSETS))
        self.assertEqual(
            [asset.install_wait_milliseconds for asset in self.assets.EXTENDED_ASSETS],
            [20_000, 45_000],
        )
        self.assertEqual([asset.screenshot_delay_seconds for asset in self.assets.EXTENDED_ASSETS], [35, 30])
        self.assertEqual(dict(self.assets.EXTENDED_ASSETS[1].runtime_environment)["QT_OPENGL"], "desktop")
        self.assertEqual(self.assets.EXTENDED_ASSETS[1].window_appearance_seconds, 55)

    def test_sumatrapdf_uses_the_fixed_bottle_install_location(self) -> None:
        asset = self.assets.asset_for("sumatrapdf")
        self.assertEqual(
            asset.install_args,
            (),
        )
        self.assertEqual(
            asset.installed_executable,
            "CompatForge/SumatraPDF/SumatraPDF.exe",
        )
        unchanged = {
            value.app_id: (value.install_args, value.installed_executable)
            for value in self.assets.BASELINE_ASSETS
            if value.app_id != "sumatrapdf"
        }
        self.assertEqual(
            unchanged,
            {
                "7zip": (("/S",), "Program Files/7-Zip/7zFM.exe"),
                "notepad-plus-plus": (
                    ("/S",),
                    "Program Files/Notepad++/notepad++.exe",
                ),
            },
        )

    def test_every_matrix_executable_location_is_strictly_bound(self) -> None:
        for asset in self.assets.ASSETS:
            allowed = (
                asset.installed_executable,
                *asset.alternate_installed_executables,
            )
            for relative in allowed:
                with self.subTest(app=asset.app_id, relative=relative), tempfile.TemporaryDirectory(
                    prefix=f"compatforge-fixed-{asset.app_id}-"
                ) as temporary:
                    bottle = Path(temporary) / "drive_c"
                    executable = bottle.joinpath(*Path(relative).parts)
                    executable.parent.mkdir(parents=True)
                    executable.write_bytes(b"MZfixed-matrix-executable")
                    binding = self.baseline.installed_executable(asset, bottle)
                    try:
                        self.assertEqual(binding.path, executable)
                        binding.revalidate()
                    finally:
                        binding.close()

    def test_sumatrapdf_portable_materialization_is_single_use_and_digest_bound(self) -> None:
        payload = b"MZportable-sumatra-fixture"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory(
            prefix="compatforge-portable-sumatra-", dir=PRIVATE_TMP
        ) as temporary:
            root = Path(temporary)
            source = root / "SumatraPDF.exe"
            source.write_bytes(payload)
            bottle = root / "prefix" / "drive_c"
            bottle.mkdir(parents=True)

            installed = self.baseline.materialize_sumatrapdf_portable(
                source, bottle, digest
            )
            self.assertEqual(
                installed,
                bottle / "CompatForge" / "SumatraPDF" / "SumatraPDF.exe",
            )
            self.assertEqual(installed.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o700)
            with self.assertRaises(self.baseline.ExecutableIntegrityError):
                self.baseline.materialize_sumatrapdf_portable(
                    source, bottle, digest
                )
            self.assertEqual(installed.read_bytes(), payload)

            rejected_bottle = root / "rejected" / "drive_c"
            rejected_bottle.mkdir(parents=True)
            with self.assertRaises(self.baseline.ExecutableIntegrityError):
                self.baseline.materialize_sumatrapdf_portable(
                    source, rejected_bottle, "0" * 64
                )
            self.assertFalse(
                (
                    rejected_bottle
                    / "CompatForge"
                    / "SumatraPDF"
                    / "SumatraPDF.exe"
                ).exists()
            )

            linked_source = root / "linked.exe"
            linked_source.symlink_to(source)
            linked_bottle = root / "linked" / "drive_c"
            linked_bottle.mkdir(parents=True)
            with self.assertRaises(self.baseline.ExecutableIntegrityError):
                self.baseline.materialize_sumatrapdf_portable(
                    linked_source, linked_bottle, digest
                )

    def test_sumatrapdf_lookup_ignores_ambient_user_state(self) -> None:
        class ForbiddenEnvironment(dict[str, str]):
            def get(self, key: str, default: object = None) -> object:
                raise AssertionError(f"ambient environment was consulted: {key}")

        with tempfile.TemporaryDirectory(
            prefix="compatforge-fixed-sumatra-"
        ) as temporary:
            bottle = Path(temporary) / "drive_c"
            expected = bottle / "CompatForge" / "SumatraPDF" / "SumatraPDF.exe"
            expected.parent.mkdir(parents=True)
            expected.write_bytes(b"MZsumatra")
            asset = self.assets.asset_for("sumatrapdf")
            with mock.patch.object(
                self.baseline.os, "environ", ForbiddenEnvironment()
            ):
                binding = self.baseline.installed_executable(asset, bottle)
            try:
                self.assertEqual(binding.path, expected)
                binding.revalidate()
            finally:
                binding.close()

    def test_cjk_font_is_copied_once_into_the_owned_bottle(self) -> None:
        payload = b"local-system-cjk-font-fixture"
        with tempfile.TemporaryDirectory(
            prefix="compatforge-cjk-font-", dir=PRIVATE_TMP
        ) as temporary:
            root = Path(temporary)
            source = root / "system-font.ttf"
            source.write_bytes(payload)
            bottle = root / "prefix" / "drive_c"
            bottle.mkdir(parents=True)
            candidates = ((source, "CompatForgeCJK.ttf"),)
            with (
                mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                mock.patch.object(
                    self.baseline, "MACOS_CJK_FONT_CANDIDATES", candidates
                ),
            ):
                evidence = self.baseline.stage_macos_cjk_font(bottle)
                with self.assertRaises(self.baseline.CjkFontIntegrityError):
                    self.baseline.stage_macos_cjk_font(bottle)

            destination = bottle / "windows" / "Fonts" / "CompatForgeCJK.ttf"
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(
                evidence,
                {
                    "schemaVersion": "1",
                    "scope": "bottle-local",
                    "registration": "windows-fonts-directory",
                    "fileName": "CompatForgeCJK.ttf",
                    "sizeBytes": len(payload),
                    "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
                },
            )
            self.assertNotIn(str(source), json.dumps(evidence))

    def test_cjk_font_is_staged_before_the_first_wine_installer_launch(self) -> None:
        source = BASELINE_TOOL.read_text(encoding="utf-8")
        application_loop = source.index("for asset in ASSETS:")
        font_stage = source.index(
            'evidence["cjkFont"] = stage_macos_cjk_font(bottle_root)',
            application_loop,
        )
        installer_launch = source.index(
            'failure_stage = "installer-launch"',
            application_loop,
        )
        self.assertLess(font_stage, installer_launch)

    def test_cjk_font_registry_is_bottle_local_fixed_and_reaps_wineserver(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-cjk-font-registry-", dir=PRIVATE_TMP
        ) as temporary:
            root = Path(temporary)
            wine = root / "wine"
            wineserver = root / "wineserver"
            wine.write_bytes(b"wine")
            wineserver.write_bytes(b"wineserver")
            wine.chmod(0o700)
            wineserver.chmod(0o700)
            prefix = root / "prefix"
            font = prefix / "drive_c" / "windows" / "Fonts" / "CompatForgeCJK.ttf"
            font.parent.mkdir(parents=True)
            font.write_bytes(b"font")

            completed = subprocess.CompletedProcess([], 0, b"", b"")
            with (
                mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                mock.patch.object(
                    self.baseline.subprocess,
                    "run",
                    return_value=completed,
                ) as run,
                mock.patch.object(
                    self.baseline, "process_snapshot", return_value=[]
                ),
            ):
                evidence = self.baseline.register_macos_cjk_font(
                    wine, wineserver, prefix
                )

            registry_count = len(self.baseline.CJK_FONT_REGISTRY_VALUES)
            self.assertEqual(run.call_count, registry_count + 2)
            for call, registry_value in zip(
                run.call_args_list[:registry_count],
                self.baseline.CJK_FONT_REGISTRY_VALUES,
                strict=True,
            ):
                key, name, value = registry_value
                self.assertEqual(
                    call.args[0],
                    [
                        str(wine),
                        "reg",
                        "add",
                        key,
                        "/v",
                        name,
                        "/d",
                        value,
                        "/f",
                    ],
                )
                self.assertEqual(call.kwargs["env"], {"WINEPREFIX": str(prefix)})
                self.assertEqual(call.kwargs["timeout"], 10)
            self.assertEqual(
                [call.args[0] for call in run.call_args_list[registry_count:]],
                [[str(wineserver), "-k"], [str(wineserver), "-w"]],
            )
            self.assertEqual(
                evidence,
                {
                    "schemaVersion": "1",
                    "scope": "bottle-local",
                    "family": "Arial Unicode MS",
                    "registration": "wine-registry",
                    "replacementCount": registry_count - 1,
                },
            )

    def test_cjk_font_staging_rejects_linked_sources_and_destinations(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-cjk-font-links-", dir=PRIVATE_TMP
        ) as temporary:
            root = Path(temporary)
            source = root / "system-font.ttf"
            source.write_bytes(b"font")
            linked_source = root / "linked-font.ttf"
            linked_source.symlink_to(source)
            bottle = root / "prefix" / "drive_c"
            (bottle / "windows" / "Fonts").mkdir(parents=True)
            candidates = ((linked_source, "CompatForgeCJK.ttf"),)
            with (
                mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                mock.patch.object(
                    self.baseline, "MACOS_CJK_FONT_CANDIDATES", candidates
                ),
                self.assertRaises(self.baseline.CjkFontIntegrityError),
            ):
                self.baseline.stage_macos_cjk_font(bottle)

            destination = bottle / "windows" / "Fonts" / "CompatForgeCJK.ttf"
            destination.symlink_to(source)
            candidates = ((source, "CompatForgeCJK.ttf"),)
            with (
                mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                mock.patch.object(
                    self.baseline, "MACOS_CJK_FONT_CANDIDATES", candidates
                ),
                self.assertRaises(self.baseline.CjkFontIntegrityError),
            ):
                self.baseline.stage_macos_cjk_font(bottle)
            self.assertTrue(destination.is_symlink())

    def test_notepad_cjk_style_is_bottle_local_and_digest_bound(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-notepad-cjk-style-", dir=PRIVATE_TMP
        ) as temporary:
            bottle = Path(temporary) / "prefix" / "drive_c"
            style = (
                bottle
                / "Program Files"
                / "Notepad++"
                / "stylers.model.xml"
            )
            style.parent.mkdir(parents=True)
            original = (
                b'<WidgetStyle name="Default Style" fontName="Courier New" />\n'
                b'<WidgetStyle name="Global override" fontName="Courier New" />\n'
            )
            style.write_bytes(original)

            evidence = self.baseline.configure_notepad_cjk_font(bottle)
            updated = style.read_bytes()
            self.assertEqual(updated.count(b'fontName="Arial Unicode MS"'), 2)
            self.assertNotIn(b'fontName="Courier New"', updated)
            self.assertEqual(stat.S_IMODE(style.stat().st_mode), 0o600)
            self.assertEqual(evidence["scope"], "bottle-local")
            self.assertEqual(evidence["editorFont"], "Arial Unicode MS")
            self.assertEqual(
                evidence["sha256"],
                "sha256:" + hashlib.sha256(updated).hexdigest(),
            )
            with self.assertRaises(self.baseline.CjkFontIntegrityError):
                self.baseline.configure_notepad_cjk_font(bottle)

    def test_sumatrapdf_rejects_exact_known_legacy_locations(self) -> None:
        asset = self.assets.asset_for("sumatrapdf")
        legacy_locations = (
            "Program Files/SumatraPDF/SumatraPDF.exe",
            "users/Public/AppData/Local/SumatraPDF/SumatraPDF.exe",
        )
        for fixed_present in (False, True):
            for legacy_relative in legacy_locations:
                with self.subTest(
                    fixed_present=fixed_present, legacy=legacy_relative
                ), tempfile.TemporaryDirectory(
                    prefix="compatforge-legacy-sumatra-"
                ) as temporary:
                    bottle = Path(temporary) / "drive_c"
                    fixed = (
                        bottle
                        / "CompatForge"
                        / "SumatraPDF"
                        / "SumatraPDF.exe"
                    )
                    if fixed_present:
                        fixed.parent.mkdir(parents=True)
                        fixed.write_bytes(b"MZfixed")
                    legacy = bottle.joinpath(*Path(legacy_relative).parts)
                    legacy.parent.mkdir(parents=True, exist_ok=True)
                    legacy.write_bytes(b"MZlegacy")
                    with self.assertRaises(self.baseline.ExecutableIntegrityError):
                        self.baseline.installed_executable(asset, bottle)

    def test_installed_executable_binding_detects_post_validation_mutation(self) -> None:
        asset = self.assets.asset_for("sumatrapdf")
        variants = ["hardlink-added"]
        if os.name != "nt":
            variants.extend(("bottle-replaced", "parent-replaced", "file-replaced"))
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(
                prefix="compatforge-bound-sumatra-"
            ) as temporary:
                root = Path(temporary)
                bottle = root / "drive_c"
                installed = (
                    bottle / "CompatForge" / "SumatraPDF" / "SumatraPDF.exe"
                )
                installed.parent.mkdir(parents=True)
                installed.write_bytes(b"MZoriginal")
                binding = self.baseline.installed_executable(asset, bottle)
                try:
                    if variant == "hardlink-added":
                        os.link(installed, root / "second-name.exe")
                    else:
                        replaced = {
                            "bottle-replaced": bottle,
                            "parent-replaced": installed.parent,
                            "file-replaced": installed,
                        }[variant]
                        old = replaced.with_name(replaced.name + ".old")
                        replaced.rename(old)
                        if variant == "file-replaced":
                            replaced.write_bytes(b"MZforeign")
                        else:
                            replaced.mkdir()
                            relative = installed.relative_to(
                                bottle if variant == "bottle-replaced" else installed.parent
                            )
                            foreign = replaced / relative
                            foreign.parent.mkdir(parents=True, exist_ok=True)
                            foreign.write_bytes(b"MZforeign")
                    with self.assertRaises(self.baseline.ExecutableIntegrityError):
                        binding.revalidate()
                finally:
                    binding.close()

    def test_main_never_inspects_an_executable_mutated_after_binding(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-main-bound-sumatra-"
        ) as temporary:
            root = Path(temporary)
            cli = root / "compatforge"
            cli.write_bytes(b"placeholder")
            installer = root / "SumatraPDF-installer.exe"
            installer.write_bytes(b"MZinstaller")
            storage = root / "storage"
            work = root / "work"
            bottle = (
                storage
                / "bottles"
                / "gui-sumatrapdf"
                / "prefix"
                / "drive_c"
            )
            installed = (
                bottle / "CompatForge" / "SumatraPDF" / "SumatraPDF.exe"
            )
            inspected: list[Path] = []
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

            def fake_invoke(
                command: list[str], *, timeout: int = 0
            ) -> subprocess.CompletedProcess[str]:
                del timeout
                if command[1:4] == ["local", "macos", "context"]:
                    receipt = self.descriptor_receipt()
                    Path(command[-1]).write_text(
                        json.dumps(self.descriptor_context(storage, receipt)),
                        encoding="utf-8",
                    )
                    return subprocess.CompletedProcess(
                        command, 0, json.dumps(receipt), ""
                    )
                if command[1] == "inspect":
                    inspected.append(Path(command[2]))
                    return subprocess.CompletedProcess(
                        command, 0, '{"architecture":"x86_64"}', ""
                    )
                if command[1] == "prepared-plan":
                    return subprocess.CompletedProcess(command, 0, "{}", "")
                if command[1] == "prepared-launch-terminate":
                    installed.parent.mkdir(parents=True, exist_ok=True)
                    installed.write_bytes(b"MZoriginal")
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        '{"kind":"exited","exit":{"code":0,"success":true}}\n',
                        "",
                    )
                raise AssertionError(f"unexpected command: {command}")

            original_installer_succeeded = self.baseline.installer_succeeded

            def materialize_fixture(
                _source: Path,
                _bottle: Path,
                _digest: str,
            ) -> Path:
                installed.parent.mkdir(parents=True, exist_ok=True)
                installed.write_bytes(b"MZportable")
                return installed

            def mutate_after_validation(
                evidence: dict[str, object],
                events: list[dict[str, object]],
                binding: object,
                **options: object,
            ) -> bool:
                succeeded = original_installer_succeeded(
                    evidence, events, binding, **options
                )
                if succeeded:
                    os.link(installed, root / "second-name.exe")
                return succeeded

            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(
                    self.assets,
                    "ASSETS",
                    (self.assets.asset_for("sumatrapdf"),),
                ),
                mock.patch.object(
                    self.baseline.platform, "system", return_value="Darwin"
                ),
                mock.patch.object(
                    self.baseline.platform, "machine", return_value="arm64"
                ),
                mock.patch.object(self.baseline.os, "access", return_value=True),
                mock.patch.object(
                    self.baseline, "rosetta_available", return_value=True
                ),
                mock.patch.object(
                    self.baseline, "invoke", side_effect=fake_invoke
                ),
                mock.patch.object(
                    self.baseline, "fetch_asset", return_value=installer
                ),
                mock.patch.object(
                    self.baseline,
                    "materialize_sumatrapdf_portable",
                    side_effect=materialize_fixture,
                ),
                mock.patch.object(
                    self.baseline,
                    "installer_succeeded",
                    side_effect=mutate_after_validation,
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                result = self.baseline.main()

            self.assertEqual(result, 1)
            self.assertEqual(inspected, [installer])
            self.assertIn("installed GUI executable identity changed", stderr.getvalue())

    def test_failed_initial_executable_binding_closes_every_held_handle(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-failed-bind-cleanup-"
        ) as temporary:
            root = Path(temporary)
            bottle = root / "drive_c"
            installed = (
                bottle / "CompatForge" / "SumatraPDF" / "SumatraPDF.exe"
            )
            installed.parent.mkdir(parents=True)
            installed.write_bytes(b"MZsumatra")
            asset = self.assets.asset_for("sumatrapdf")
            with (
                mock.patch.object(
                    self.baseline.InstalledExecutableBinding,
                    "revalidate",
                    side_effect=self.baseline.ExecutableIntegrityError(
                        "forced initial binding drift"
                    ),
                ),
                self.assertRaises(self.baseline.ExecutableIntegrityError),
            ):
                self.baseline.installed_executable(asset, bottle)
            shutil.rmtree(bottle)
            self.assertFalse(bottle.exists())

    def test_installed_executable_rejects_path_drift_and_unsafe_entries(self) -> None:
        asset = self.assets.asset_for("sumatrapdf")
        variants = (
            "missing",
            "wrong-location",
            "escape",
            "symlink",
            "linked-parent",
            "linked-bottle",
            "hardlink-multiple",
        )
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(
                prefix="compatforge-unsafe-sumatra-"
            ) as temporary:
                root = Path(temporary)
                bottle = root / "drive_c"
                expected = bottle / "CompatForge" / "SumatraPDF" / "SumatraPDF.exe"
                expected.parent.mkdir(parents=True)
                selected_asset = asset
                if variant == "wrong-location":
                    wrong = bottle / "Program Files" / "SumatraPDF" / "SumatraPDF.exe"
                    wrong.parent.mkdir(parents=True)
                    wrong.write_bytes(b"MZwrong")
                elif variant == "escape":
                    outside = root / "outside.exe"
                    outside.write_bytes(b"MZoutside")
                    selected_asset = dataclasses.replace(
                        asset, installed_executable="../outside.exe"
                    )
                elif variant == "symlink":
                    victim = root / "victim.exe"
                    victim.write_bytes(b"MZvictim")
                    try:
                        expected.symlink_to(victim)
                    except OSError as error:
                        self.skipTest(f"symlinks are unavailable: {error}")
                elif variant == "linked-parent":
                    expected.parent.rmdir()
                    target = root / "linked-target"
                    target.mkdir()
                    (target / "SumatraPDF.exe").write_bytes(b"MZlinked-parent")
                    try:
                        expected.parent.symlink_to(target, target_is_directory=True)
                    except OSError as error:
                        self.skipTest(f"directory links are unavailable: {error}")
                elif variant == "linked-bottle":
                    shutil.rmtree(bottle)
                    target = root / "bottle-target"
                    target.joinpath("CompatForge", "SumatraPDF").mkdir(parents=True)
                    target.joinpath(
                        "CompatForge", "SumatraPDF", "SumatraPDF.exe"
                    ).write_bytes(b"MZlinked-bottle")
                    try:
                        bottle.symlink_to(target, target_is_directory=True)
                    except OSError as error:
                        self.skipTest(f"directory links are unavailable: {error}")
                elif variant == "hardlink-multiple":
                    victim = root / "victim.exe"
                    victim.write_bytes(b"MZvictim")
                    try:
                        os.link(victim, expected)
                    except OSError as error:
                        self.skipTest(f"hardlinks are unavailable: {error}")
                with self.assertRaises(self.baseline.AcceptanceError):
                    self.baseline.installed_executable(selected_asset, bottle)

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

    def test_pinned_launch_keeps_the_existing_ffi_header_and_exports_byte_stable(
        self,
    ) -> None:
        ffi_root = ROOT / "crates" / "compatforge-ffi"
        header = (ffi_root / "include" / "compatforge.h").read_bytes()
        self.assertEqual(
            hashlib.sha256(header).hexdigest(),
            "d616269ff5ddf8c3df44179854cca771cd2a85800d04cfe68c6fdb750a357fbb",
        )

        source = rust_without_comments(
            (ffi_root / "src" / "lib.rs").read_text(encoding="utf-8")
        )
        self.assertEqual(
            re.findall(
                r'#\[no_mangle\]\s*pub(?:\s+unsafe|\s+const)?\s+extern\s+"C"\s+fn\s+(cf_[a-z0-9_]+)',
                source,
            ),
            [
                "cf_api_version",
                "cf_abi_version",
                "cf_probe_capabilities",
                "cf_inspect_executable",
                "cf_capabilities_get",
                "cf_context_create",
                "cf_macos_local_context_create",
                "cf_service_create",
                "cf_service_call",
                "cf_compile_launch",
                "cf_launch_prepare",
                "cf_prepared_launch_inspection_get",
                "cf_prepared_launch_plan_get",
                "cf_prepared_launch_start",
                "cf_launch_start",
                "cf_launch_next_event",
                "cf_launch_terminate",
                "cf_last_error_json",
                "cf_string_free",
                "cf_context_release",
                "cf_service_release",
                "cf_prepared_launch_release",
                "cf_launch_release",
            ],
        )
        self.assertRegex(
            source,
            r'pub\s+const\s+extern\s+"C"\s+fn\s+cf_abi_version\(\)\s*->\s*u32\s*\{\s*1\s*\}',
        )

    def test_pinned_cli_session_is_one_closed_capture_to_receipt_boundary(self) -> None:
        source = rust_without_comments(
            (ROOT / "apps" / "cli" / "src" / "main.rs").read_text(encoding="utf-8")
        )
        cargo = tomllib.loads(
            (ROOT / "apps" / "cli" / "Cargo.toml").read_text(encoding="utf-8")
        )
        self.assertIn("compatforge-guest-artifact", cargo["dependencies"])
        ordered = (
            "session.validate_closed_inputs()",
            "session.capture_source()",
            "session.prepare_pinned()",
            "session.authorize_pinned()",
            "session.publish_evidence()",
            "session.start_pinned()",
            "session.post_spawn_revalidate()",
            "session.supervise_pinned(handle)",
            "session.finalize_session()",
        )
        positions = [source.index(token) for token in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertIn(
            '"compatforge-cli: pinned SumatraPDF launch failed\\n"', source
        )
        self.assertIn('"pinned-evidence-receipt"', source)
        self.assertNotIn("COMPATFORGE_PINNED", source)

    def test_pinned_cli_receipt_contract_is_fixed_and_path_free(self) -> None:
        source = rust_without_comments(
            (ROOT / "apps" / "cli" / "src" / "main.rs").read_text(encoding="utf-8")
        )
        for field in (
            "PinnedEvidenceReceipt",
            "PinnedEvidenceOutput",
            "byte_length",
            "record_type",
            "schema_version",
            'kind: "inspection"',
            'kind: "plan"',
        ):
            self.assertIn(field, source)
        self.assertRegex(
            source,
            r'const\s+PINNED_SUMATRAPDF_FAILURE\s*:\s*&str\s*=\s*'
            r'"pinned SumatraPDF launch failed"',
        )

    def test_pinned_macos_production_wires_every_work_root_revalidation(self) -> None:
        source = rust_code_only(
            (ROOT / "apps" / "cli" / "src" / "main.rs").read_text(encoding="utf-8")
        )
        implementation = source.index(
            'impl ClosedPinnedSession for MacOsClosedPinnedSession<\'_> {'
        )

        def method_body(name: str, next_name: str) -> str:
            start = source.index(f"    fn {name}(", implementation)
            end = source.index(f"\n    fn {next_name}(", start)
            return source[start:end]

        root_check = (
            "self.work_root()?.revalidate().map_err(|_| PinnedSessionError)?;"
        )
        publish = method_body("publish_evidence", "start_pinned")
        root_positions = [
            match.start() for match in re.finditer(re.escape(root_check), publish)
        ]
        self.assertEqual(len(root_positions), 4)
        inspection_write = publish.index(".write_canonical(&inspection_bytes)")
        plan_write = publish.index(".write_canonical(&plan_bytes)")
        self.assertLess(root_positions[0], inspection_write)
        self.assertLess(inspection_write, root_positions[1])
        self.assertLess(root_positions[1], root_positions[2])
        self.assertLess(root_positions[2], plan_write)
        self.assertLess(plan_write, root_positions[3])

        start = method_body("start_pinned", "post_spawn_revalidate")
        self.assertEqual(start.count(root_check), 1)
        self.assertEqual(start.count(".revalidate_binding("), 2)
        self.assertLess(
            start.index(root_check),
            start.index("ProcessSupervisor::start_pinned_bottle"),
        )
        self.assertLess(
            start.rindex(".revalidate_binding("),
            start.index("ProcessSupervisor::start_pinned_bottle"),
        )

        finalize = method_body("finalize_session", "evidence_receipt")
        self.assertEqual(finalize.count("self.work_root()?.revalidate()"), 1)
        self.assertIn(".map_err(|_| PinnedSessionError)", finalize)

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

    def test_portable_zip_materialization_is_bounded_and_traversal_safe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-portable-zip-") as temporary:
            root = Path(temporary)
            archive = root / "winmerge.zip"
            bottle = root / "drive_c"
            bottle.mkdir()
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("WinMerge/WinMergeU.exe", b"MZ-fixed-fixture")
                bundle.writestr("WinMerge/Languages/ChineseSimplified.po", "中文")
            inspection = self.baseline.materialize_portable_zip(
                archive,
                bottle,
                self.baseline.file_sha256(archive),
            )
            self.assertEqual(inspection["format"], "zip")
            self.assertEqual(inspection["entryCount"], 2)
            self.assertEqual((bottle / "WinMerge" / "WinMergeU.exe").read_bytes(), b"MZ-fixed-fixture")

            malicious = root / "traversal.zip"
            with zipfile.ZipFile(malicious, "w") as bundle:
                bundle.writestr("../escape.exe", b"MZ")
            with self.assertRaises(self.baseline.AcceptanceError):
                self.baseline.materialize_portable_zip(
                    malicious,
                    root / "malicious-drive-c",
                    self.baseline.file_sha256(malicious),
                )
            self.assertFalse((root / "escape.exe").exists())

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
            "desktop-font-unavailable": "blocked",
            "desktop-window-unobserved": "failed",
            "application-install-failed": "failed",
            "application-interaction-unverified": "unverified",
            "application-interaction-invalid": "failed",
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
                mock.patch.object(
                    self.baseline,
                    "materialize_sumatrapdf_portable",
                    return_value=root / "installer.exe",
                ),
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
                "termination-accepted",
                termination_failed_events,
                {"available": True},
                {"available": True},
                [],
                complete_checks,
                ("accepted", None, None),
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

    def test_application_evaluation_accepts_requested_cli_termination(self) -> None:
        events = [
            {"kind": "terminate-requested"},
            {"kind": "exited", "exit": {"code": 1, "success": False}},
        ]
        self.assertEqual(self.baseline.status(events), "failed")
        self.assertEqual(
            self.baseline.status(events, allow_requested_termination=True),
            "accepted",
        )

        sumatra: dict[str, object] = {}
        self.baseline.evaluate_application_outcome(
            sumatra,
            "sumatrapdf",
            events,
            {"available": True},
            {"available": True},
            [],
            {"mainWindow": True, "openDialog": True},
        )
        self.assertEqual(sumatra["status"], "accepted")

        seven_zip: dict[str, object] = {}
        self.baseline.evaluate_application_outcome(
            seven_zip,
            "7zip",
            events,
            {"available": True},
            {"available": True},
            [],
            {"fileList": True, "menus": True},
        )
        self.assertEqual(seven_zip["status"], "accepted")

        installer: dict[str, object] = {}
        installed = Path("/private/tmp/compatforge-missing-installer-output.exe")
        self.assertFalse(
            self.baseline.installer_succeeded(installer, events, installed)
        )
        self.assertEqual(
            installer["reasonCode"], "cleanup-termination-failed"
        )

    def test_live_ack_error_never_masks_process_window_or_cleanup_failure(self) -> None:
        accepted_events = [{"kind": "exited", "exit": {"code": 0, "success": True}}]
        failed_events = [{"kind": "exited", "exit": {"code": 9, "success": False}}]
        cases = (
            (
                "residual-before-unverified",
                accepted_events,
                {"available": True},
                {"available": True},
                ["residual"],
                self.baseline.InteractionUnverifiedError("unverified"),
                ("failed", "cleanup-residual-processes"),
            ),
            (
                "exit-before-invalid",
                failed_events,
                {"available": True},
                {"available": True},
                [],
                self.baseline.InteractionInvalidError("invalid"),
                ("failed", "application-content-verification-failed"),
            ),
            (
                "window-before-invalid",
                accepted_events,
                {"available": False},
                {"available": True},
                [],
                self.baseline.InteractionInvalidError("invalid"),
                ("failed", "desktop-window-unobserved"),
            ),
            (
                "invalid-after-clean-boundary",
                accepted_events,
                {"available": True},
                {"available": True},
                [],
                self.baseline.InteractionInvalidError("invalid"),
                ("failed", "application-interaction-invalid"),
            ),
        )
        for name, events, windows, shot, residual, error, expected in cases:
            evidence: dict[str, object] = {}
            with self.subTest(name=name):
                self.baseline.evaluate_live_interaction_outcome(
                    evidence,
                    "7zip",
                    events,
                    windows,
                    shot,
                    residual,
                    None,
                    error,
                )
                self.assertEqual(
                    (evidence["status"], evidence["reasonCode"]), expected
                )

    def test_complete_checks_cannot_override_any_interaction_error(self) -> None:
        accepted_events = [{"kind": "exited", "exit": {"code": 0, "success": True}}]
        complete_checks = {"fileList": True, "menus": True}
        cases = (
            (
                self.baseline.InteractionUnverifiedError("unverified"),
                ("unverified", "application-interaction-unverified"),
            ),
            (
                self.baseline.InteractionInvalidError("invalid"),
                ("failed", "application-interaction-invalid"),
            ),
            (
                self.baseline.AcceptanceError("unexpected acknowledgement failure"),
                ("unverified", "application-interaction-unverified"),
            ),
        )
        for error, expected in cases:
            with self.subTest(error=type(error).__name__):
                evidence: dict[str, object] = {}
                self.baseline.evaluate_live_interaction_outcome(
                    evidence,
                    "7zip",
                    accepted_events,
                    {"available": True},
                    {"available": True},
                    [],
                    dict(complete_checks),
                    error,
                )
                self.assertEqual(
                    (evidence["status"], evidence["reasonCode"]), expected
                )
                self.assertNotIn("interactionChecks", evidence)

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
        unsafe_application[0]["interactionChecks"] = {
            "fileList": True,
            "menus": True,
            "/Users/developer/secret": True,
        }
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
        nested_key["applications"][0]["interactionChecks"] = {
            "fileList": True,
            "menus": True,
            "/Users/developer/secret": True,
        }
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

    def test_compact_summary_preserves_sumatrapdf_requested_installer_termination(self) -> None:
        receipt = {
            "schemaVersion": "1",
            "runtimeId": "crossover",
            "packId": "wine-macos-auto-preview",
            "version": "24.0",
            "packDigest": "sha256:" + "a" * 64,
            "source": "explicit-override",
        }
        application = {
            "schemaVersion": "1",
            "runtimeId": "crossover",
            "appId": "sumatrapdf",
            "assetSha256": "b" * 64,
            "status": "accepted",
            "cleanup": True,
            "interactionChecks": {"mainWindow": True, "openDialog": True},
            "installerEvents": [
                {"kind": "started"},
                {"kind": "terminate-requested"},
                {"kind": "exited"},
            ],
            "installerExit": {"present": True, "code": None, "success": False},
            "exit": {"present": True, "code": 0, "success": True},
            "windows": {"available": True},
            "screenshot": {"available": True},
        }

        compact = self.baseline.compact_summary(receipt, [application])
        self.assertIs(compact["applications"][0]["installerTerminationRequested"], True)
        self.baseline.validate_compact_summary(compact)

        for label, mutation in (
            ("false", False),
            ("wrong-app", True),
            ("successful-exit", True),
        ):
            mutant = json.loads(json.dumps(compact))
            target = mutant["applications"][0]
            target["installerTerminationRequested"] = mutation
            if label == "wrong-app":
                target["appId"] = "7zip"
                target["interactionChecks"] = {"fileList": True, "menus": True}
            elif label == "successful-exit":
                target["installerExit"] = {"present": True, "code": 0, "success": True}
            with self.subTest(label=label), self.assertRaisesRegex(
                self.baseline.AcceptanceError,
                "installer termination relation",
            ):
                self.baseline.validate_compact_summary(mutant)

    def test_each_application_evidence_is_appended_once(self) -> None:
        source = BASELINE_TOOL.read_text(encoding="utf-8")
        self.assertEqual(source.count("results.append(evidence)"), 1)

    def test_interactive_cli_requires_the_new_closed_acknowledgement_boundary(self) -> None:
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
            "--runtime-id",
            "crossover",
            "--wine-root",
            "C:\\Runtimes\\selected",
            "--wine",
            "bin/wine",
            "--wineserver",
            "bin/wineserver",
            "--version",
            "24.0",
        ]
        interactive = [
            *common,
            "--accept-interactive",
            "--interaction-plan",
            "C:\\acceptance\\plans\\round-1-crossover.json",
            "--acknowledgement-root",
            "C:\\acceptance\\acknowledgements",
            "--round-id",
            "round-1",
        ]
        arguments = self.baseline.parser().parse_args(interactive)
        self.baseline.validate_interaction_selection(arguments, "crossover")
        self.assertEqual(arguments.round_id, "round-1")

        for omitted in ("--interaction-plan", "--acknowledgement-root", "--round-id"):
            mutant = interactive.copy()
            index = mutant.index(omitted)
            del mutant[index : index + 2]
            with self.subTest(omitted=omitted), self.assertRaises(self.baseline.AcceptanceError):
                parsed = self.baseline.parser().parse_args(mutant)
                self.baseline.validate_interaction_selection(parsed, "crossover")

        with self.assertRaises(self.baseline.AcceptanceError):
            parsed = self.baseline.parser().parse_args(
                [*common, "--accept-interactive", "--interaction-evidence", "C:\\old.json"]
            )
            self.baseline.validate_interaction_selection(parsed, "crossover")

    def test_interaction_plan_is_closed_canonical_and_cannot_prefill_truth_claims(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-interaction-plan-") as temporary:
            root = Path(temporary)
            path = root / "round-1-crossover.json"
            plan = self.interaction_plan()
            self.write_canonical_json(path, plan)
            self.assertEqual(
                self.baseline.read_interaction_plan(path, "round-1", "crossover"),
                plan["applications"],
            )

            mutants = []
            prefilled = json.loads(json.dumps(plan))
            prefilled["applications"]["7zip"] = {"fileList": True, "menus": True}
            mutants.append(prefilled)
            unknown = json.loads(json.dumps(plan))
            unknown["accepted"] = True
            mutants.append(unknown)
            wrong_round = json.loads(json.dumps(plan))
            wrong_round["roundId"] = "round-2"
            mutants.append(wrong_round)
            wrong_runtime = json.loads(json.dumps(plan))
            wrong_runtime["runtimeId"] = "whisky"
            mutants.append(wrong_runtime)
            for index, mutant in enumerate(mutants):
                with self.subTest(index=index):
                    self.write_canonical_json(path, mutant)
                    with self.assertRaises(self.baseline.InteractionInvalidError):
                        self.baseline.read_interaction_plan(path, "round-1", "crossover")

            path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
            with self.assertRaises(self.baseline.InteractionInvalidError):
                self.baseline.read_interaction_plan(path, "round-1", "crossover")

    def test_challenge_is_post_window_and_deterministic_callback_never_reads_stdin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-ack-") as temporary:
            root = Path(temporary)
            plan_path = root / "plans" / "round-1-crossover.json"
            acknowledgement_root = root / "acknowledgements"
            plan_path.parent.mkdir()
            (acknowledgement_root / "challenges").mkdir(parents=True)
            (acknowledgement_root / "receipts").mkdir()
            self.write_canonical_json(plan_path, self.interaction_plan())
            session = self.baseline.open_interaction_session(
                plan_path, acknowledgement_root, "round-1", "crossover"
            )
            callback_calls: list[str] = []

            def acknowledge(challenge: dict[str, object], challenge_path: Path, receipt_path: Path) -> bool:
                callback_calls.append(challenge["appId"])
                self.assertTrue(challenge_path.is_file())
                self.assertFalse(receipt_path.exists())
                self.acknowledgements.write_acknowledgement(
                    receipt_path,
                    self.acknowledgements.make_acknowledgement(challenge),
                )
                return True

            try:
                self.assertEqual(
                    session.acknowledge_application(
                        app_id="7zip",
                        runtime_version="24.0",
                        pack_digest="sha256:" + "a" * 64,
                        asset_digest="sha256:" + "b" * 64,
                        window_observed=False,
                        nonce_source=lambda _size: "c" * 64,
                        wait_for_acknowledgement=acknowledge,
                    ),
                    {},
                )
                self.assertEqual(callback_calls, [])
                self.assertEqual(list((acknowledgement_root / "challenges").iterdir()), [])
                checks = session.acknowledge_application(
                    app_id="7zip",
                    runtime_version="24.0",
                    pack_digest="sha256:" + "a" * 64,
                    asset_digest="sha256:" + "b" * 64,
                    window_observed=True,
                    nonce_source=lambda _size: "c" * 64,
                    wait_for_acknowledgement=acknowledge,
                )
            finally:
                session.close()
            self.assertEqual(checks, {"fileList": True, "menus": True})
            self.assertEqual(callback_calls, ["7zip"])
            self.assertEqual(
                (acknowledgement_root / "challenges" / "round-1--crossover--7zip.json")
                .read_bytes(),
                b"!",
            )
            self.assertEqual(
                (acknowledgement_root / "receipts" / "round-1--crossover--7zip.json")
                .read_bytes(),
                b"!",
            )

    def test_observed_launch_calls_ack_hook_after_window_while_process_is_alive(self) -> None:
        order: list[str] = []
        observed_processes: list[object] = []

        class Output:
            def __init__(self) -> None:
                self.first = True

            def readline(self) -> str:
                if self.first:
                    self.first = False
                    return '{"kind":"started","processId":321}\n'
                return ""

            def read(self) -> str:
                return '{"kind":"exited","exit":{"code":0,"success":true}}\n'

        class Errors:
            @staticmethod
            def read() -> str:
                return ""

        class Process:
            def __init__(self) -> None:
                self.stdout = Output()
                self.stderr = Errors()
                self.returncode = 0
                self.polls = 0

            def poll(self) -> int | None:
                self.polls += 1
                return None if self.polls <= 2 else 0

            def wait(self, timeout: int) -> int:
                del timeout
                return 0

            def kill(self) -> None:
                self.returncode = -9

        process = Process()

        class Selector:
            def register(self, _stream: object, _events: object) -> None:
                return None

            def select(self, timeout: float) -> list[tuple[object, object]]:
                del timeout
                return [(type("Key", (), {"fileobj": process.stdout})(), None)]

            def unregister(self, _stream: object) -> None:
                return None

            def close(self) -> None:
                return None

        def observe(_process_group_id: int, _tokens: tuple[str, ...]) -> dict[str, object]:
            order.append("window")
            return {"available": True, "windows": [{"title": "7-Zip"}]}

        def capture(_path: Path, _window_id: int | None = None) -> dict[str, object]:
            order.append("screenshot")
            return {"available": True}

        hook_budgets: list[float] = []

        def acknowledge(live_process: object, remaining_budget: float) -> None:
            observed_processes.append(live_process)
            hook_budgets.append(remaining_budget)
            self.assertGreater(remaining_budget, 0)
            self.assertLessEqual(remaining_budget, 5)
            self.assertLessEqual(
                remaining_budget,
                self.baseline.INTERACTIVE_RUNTIME_MILLISECONDS / 1000,
            )

            def write_receipt(
                challenge: dict[str, object],
                challenge_path: Path,
                receipt_path: Path,
            ) -> bool:
                order.append("acknowledgement")
                self.assertIsNone(live_process.poll())
                self.assertTrue(challenge_path.is_file())
                self.acknowledgements.write_acknowledgement(
                    receipt_path,
                    self.acknowledgements.make_acknowledgement(challenge),
                )
                return True

            checks = session.acknowledge_application(
                app_id="7zip",
                runtime_version="24.0",
                pack_digest="sha256:" + "a" * 64,
                asset_digest="sha256:" + "b" * 64,
                window_observed=True,
                nonce_source=lambda _size: "c" * 64,
                wait_for_acknowledgement=write_receipt,
            )
            self.assertEqual(checks, {"fileList": True, "menus": True})

        with (
            tempfile.TemporaryDirectory(prefix="compatforge-live-window-") as temporary,
            mock.patch.object(self.baseline.subprocess, "Popen", return_value=process),
            mock.patch.object(
                self.baseline.selectors, "DefaultSelector", return_value=Selector()
            ),
            mock.patch.object(self.baseline, "observer", side_effect=observe),
            mock.patch.object(self.baseline, "screenshot", side_effect=capture),
        ):
            root = Path(temporary)
            plan_path = root / "plans" / "plan.json"
            acknowledgement_root = root / "ack"
            plan_path.parent.mkdir()
            (acknowledgement_root / "challenges").mkdir(parents=True)
            (acknowledgement_root / "receipts").mkdir()
            self.write_canonical_json(plan_path, self.interaction_plan())
            session = self.baseline.open_interaction_session(
                plan_path, acknowledgement_root, "round-1", "crossover"
            )
            try:
                events, windows, shot, _process_id = self.baseline.observed_launch(
                    ["/absolute/compatforge", "prepared-launch-terminate"],
                    root / "window.png",
                    ("7-Zip",),
                    on_window_observed=acknowledge,
                    timeout=5,
                )
            finally:
                session.close()
        self.assertEqual(order, ["window", "acknowledgement", "screenshot"])
        self.assertEqual(self.baseline.status(events), "accepted")
        self.assertTrue(windows["available"])
        self.assertTrue(shot["available"])
        self.assertEqual(len(hook_budgets), 1)
        self.assertIsNotNone(observed_processes[0].poll())

    def test_pinned_receipt_and_anonymous_outputs_are_fd_bound(self) -> None:
        inspection = {"architecture": "x86_64", "schemaVersion": "1"}
        plan = {"process": {"arguments": []}, "schemaVersion": "1"}
        payloads = [
            self.baseline.canonical_json_bytes(inspection),
            self.baseline.canonical_json_bytes(plan),
        ]
        receipt = {
            "outputs": [
                {
                    "byteLength": len(payload),
                    "kind": kind,
                    "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
                }
                for kind, payload in zip(("inspection", "plan"), payloads, strict=True)
            ],
            "recordType": "pinned-evidence-receipt",
            "schemaVersion": 1,
        }
        outputs = self.baseline.parse_pinned_receipt(receipt)

        with tempfile.TemporaryDirectory(
            prefix="compatforge-pinned-runner-", dir=PRIVATE_TMP
        ) as temporary:
            directory = os.open(
                temporary,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            bindings = []
            try:
                for payload in payloads:
                    binding = self.baseline.create_anonymous_pinned_output(directory)
                    bindings.append(binding)
                    self.assertEqual(os.fstat(binding.descriptor).st_nlink, 0)
                    os.write(binding.descriptor, payload)
                self.assertEqual(
                    self.baseline.read_pinned_evidence(bindings[0], outputs[0]),
                    inspection,
                )
                self.assertEqual(
                    self.baseline.read_pinned_evidence(bindings[1], outputs[1]),
                    plan,
                )
                self.assertEqual(list(Path(temporary).iterdir()), [])
            finally:
                for binding in reversed(bindings):
                    os.close(binding.descriptor)
                os.close(directory)

    def test_pinned_evidence_root_is_isolated_from_screenshot_metadata_changes(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-pinned-root-", dir=PRIVATE_TMP
        ) as temporary:
            work_root = Path(temporary)
            pinned_root, identity = self.baseline.create_pinned_evidence_work_root(
                work_root
            )
            before = pinned_root.stat()
            (work_root / "sumatrapdf.png").write_bytes(b"screenshot")
            after = pinned_root.stat()
            self.assertEqual(
                (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns),
                (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns),
            )
            self.baseline.remove_pinned_evidence_work_root(pinned_root, identity)
            self.assertFalse(pinned_root.exists())
            self.assertTrue((work_root / "sumatrapdf.png").is_file())

    def test_observed_pinned_launch_forwards_exact_fds_and_terminal_receipt(self) -> None:
        receipt = {
            "outputs": [
                {"byteLength": 1, "kind": "inspection", "sha256": "sha256:" + "a" * 64},
                {"byteLength": 1, "kind": "plan", "sha256": "sha256:" + "b" * 64},
            ],
            "recordType": "pinned-evidence-receipt",
            "schemaVersion": 1,
        }
        transcript = "\n".join(
            (
                '{"kind":"started","processId":321}',
                '{"kind":"exited","exit":{"code":0,"success":true}}',
                self.baseline.canonical_json_bytes(receipt).decode("utf-8"),
            )
        ) + "\n"

        class Output:
            @staticmethod
            def read() -> str:
                return transcript

        class Errors:
            @staticmethod
            def read() -> str:
                return ""

        class Process:
            stdout = Output()
            stderr = Errors()
            returncode = 0

            @staticmethod
            def poll() -> int:
                return 0

            @staticmethod
            def wait(timeout: int) -> int:
                del timeout
                return 0

            @staticmethod
            def kill() -> None:
                return None

        class Selector:
            @staticmethod
            def register(_stream: object, _events: object) -> None:
                return None

            @staticmethod
            def unregister(_stream: object) -> None:
                return None

            @staticmethod
            def close() -> None:
                return None

        records: list[dict[str, object]] = []
        with (
            tempfile.TemporaryDirectory(
                prefix="compatforge-pinned-observed-", dir=PRIVATE_TMP
            ) as temporary,
            mock.patch.object(
                self.baseline.subprocess, "Popen", return_value=Process()
            ) as popen,
            mock.patch.object(
                self.baseline.selectors, "DefaultSelector", return_value=Selector()
            ),
        ):
            events, _windows, _shot, process_id = self.baseline.observed_launch(
                ["/absolute/compatforge", "prepared-pinned-sumatrapdf-launch-terminate"],
                Path(temporary) / "window.png",
                ("SumatraPDF",),
                pass_fds=(7, 8, 9),
                terminal_records=records,
                require_empty_stderr=True,
            )
        self.assertEqual([event["kind"] for event in events], ["started", "exited"])
        self.assertEqual(process_id, 321)
        self.assertEqual(records, [receipt])
        self.assertEqual(popen.call_args.kwargs["pass_fds"], (7, 8, 9))
        self.assertIs(popen.call_args.kwargs["close_fds"], True)

    def test_observed_launch_cleans_child_and_selector_when_live_hook_raises(self) -> None:
        cases = (
            (
                "protocol",
                lambda: self.baseline.InteractionInvalidError("invalid receipt"),
                self.baseline.InteractionInvalidError,
            ),
            ("keyboard-interrupt", KeyboardInterrupt, KeyboardInterrupt),
        )
        for name, make_error, expected_error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="compatforge-live-hook-cleanup-"
            ) as temporary:
                cleanup_calls: list[str] = []

                class Output:
                    def readline(self) -> str:
                        return '{"kind":"started","processId":321}\n'

                    def read(self) -> str:
                        return ""

                class Errors:
                    def read(self) -> str:
                        return ""

                class Process:
                    def __init__(self) -> None:
                        self.stdout = Output()
                        self.stderr = Errors()
                        self.returncode: int | None = None
                        self.killed = False

                    def poll(self) -> int | None:
                        return self.returncode

                    def terminate(self) -> None:
                        cleanup_calls.append("terminate")

                    def wait(self, timeout: int) -> int:
                        self.assert_timeout(timeout)
                        cleanup_calls.append("wait")
                        if not self.killed:
                            raise subprocess.TimeoutExpired("compatforge", timeout)
                        self.returncode = -9
                        return -9

                    @staticmethod
                    def assert_timeout(timeout: int) -> None:
                        if timeout != 10:
                            raise AssertionError(f"unexpected timeout: {timeout}")

                    def kill(self) -> None:
                        cleanup_calls.append("kill")
                        self.killed = True

                process = Process()

                class Selector:
                    def __init__(self) -> None:
                        self.closed = False
                        self.unregistered = False

                    def register(self, _stream: object, _events: object) -> None:
                        return None

                    def select(self, timeout: float) -> list[tuple[object, object]]:
                        del timeout
                        return [(type("Key", (), {"fileobj": process.stdout})(), None)]

                    def unregister(self, _stream: object) -> None:
                        self.unregistered = True

                    def close(self) -> None:
                        self.closed = True

                selector = Selector()

                def raise_from_hook(_process: object, _budget: float) -> None:
                    raise make_error()

                with (
                    mock.patch.object(self.baseline.subprocess, "Popen", return_value=process),
                    mock.patch.object(
                        self.baseline.selectors,
                        "DefaultSelector",
                        return_value=selector,
                    ),
                    mock.patch.object(
                        self.baseline,
                        "observer",
                        return_value={"available": True},
                    ),
                    self.assertRaises(expected_error),
                ):
                    self.baseline.observed_launch(
                        ["/absolute/compatforge", "prepared-launch-terminate"],
                        Path(temporary) / "window.png",
                        ("7-Zip",),
                        on_window_observed=raise_from_hook,
                        timeout=5,
                    )
                self.assertEqual(
                    cleanup_calls, ["terminate", "wait", "kill", "wait"]
                )
                self.assertTrue(process.killed)
                self.assertTrue(selector.unregistered)
                self.assertTrue(selector.closed)

    def test_observed_launch_cleanup_failure_is_fatal_over_hook_error(self) -> None:
        cleanup_calls: list[str] = []

        class Output:
            def readline(self) -> str:
                return '{"kind":"started","processId":321}\n'

        class Errors:
            pass

        class Process:
            def __init__(self) -> None:
                self.stdout = Output()
                self.stderr = Errors()
                self.returncode: int | None = None

            def poll(self) -> int | None:
                return None

            def terminate(self) -> None:
                cleanup_calls.append("terminate")

            def wait(self, timeout: int) -> int:
                cleanup_calls.append("wait")
                raise subprocess.TimeoutExpired("compatforge", timeout)

            def kill(self) -> None:
                cleanup_calls.append("kill")

        process = Process()

        class Selector:
            def register(self, _stream: object, _events: object) -> None:
                return None

            def select(self, timeout: float) -> list[tuple[object, object]]:
                del timeout
                return [(type("Key", (), {"fileobj": process.stdout})(), None)]

            def unregister(self, _stream: object) -> None:
                return None

            def close(self) -> None:
                return None

        def invalid_hook(_process: object, _budget: float) -> None:
            raise self.baseline.InteractionInvalidError("invalid receipt")

        with (
            mock.patch.object(self.baseline.subprocess, "Popen", return_value=process),
            mock.patch.object(
                self.baseline.selectors, "DefaultSelector", return_value=Selector()
            ),
            mock.patch.object(
                self.baseline, "observer", return_value={"available": True}
            ),
            self.assertRaises(self.baseline.InteractionCleanupError) as captured,
        ):
            self.baseline.observed_launch(
                ["/absolute/compatforge", "prepared-launch-terminate"],
                Path("/absolute/window.png"),
                ("7-Zip",),
                on_window_observed=invalid_hook,
                timeout=5,
            )
        self.assertEqual(cleanup_calls, ["terminate", "wait", "kill", "wait"])
        self.assertIsInstance(
            captured.exception.__cause__, self.baseline.InteractionInvalidError
        )

    def test_hook_cannot_cross_absolute_deadline_then_exit_successfully(self) -> None:
        now = [0.0]
        hook_budgets: list[float] = []
        screenshot_calls: list[str] = []

        class Output:
            def __init__(self) -> None:
                self.emitted = False

            def readline(self) -> str:
                if self.emitted:
                    return ""
                self.emitted = True
                return '{"kind":"started","processId":321}\n'

            def read(self) -> str:
                return '{"kind":"exited","exit":{"code":0,"success":true}}\n'

        class Errors:
            def read(self) -> str:
                return ""

        class Process:
            def __init__(self) -> None:
                self.stdout = Output()
                self.stderr = Errors()
                self.returncode: int | None = None
                self.terminated = False
                self.killed = False

            def poll(self) -> int | None:
                return self.returncode

            def terminate(self) -> None:
                self.terminated = True

            def kill(self) -> None:
                self.killed = True

            def wait(self, timeout: int) -> int:
                del timeout
                return self.returncode or 0

        process = Process()

        class Selector:
            def __init__(self) -> None:
                self.unregistered = False
                self.closed = False

            def register(self, _stream: object, _events: object) -> None:
                return None

            def select(self, timeout: float) -> list[tuple[object, object]]:
                del timeout
                return [(type("Key", (), {"fileobj": process.stdout})(), None)]

            def unregister(self, _stream: object) -> None:
                self.unregistered = True

            def close(self) -> None:
                self.closed = True

        selector = Selector()

        def acknowledge(_process: object, remaining_budget: float) -> None:
            hook_budgets.append(remaining_budget)
            now[0] = 2.0
            process.returncode = 0

        def capture(_path: Path, _window_id: int | None = None) -> dict[str, object]:
            screenshot_calls.append("screenshot")
            return {"available": True}

        with (
            mock.patch.object(self.baseline.subprocess, "Popen", return_value=process),
            mock.patch.object(
                self.baseline.selectors, "DefaultSelector", return_value=selector
            ),
            mock.patch.object(self.baseline.time, "monotonic", side_effect=lambda: now[0]),
            mock.patch.object(self.baseline.time, "sleep", return_value=None),
            mock.patch.object(
                self.baseline, "observer", return_value={"available": True}
            ),
            mock.patch.object(self.baseline, "screenshot", side_effect=capture),
            self.assertRaisesRegex(
                self.baseline.AcceptanceError,
                "bounded observation timeout",
            ),
        ):
            self.baseline.observed_launch(
                ["/absolute/compatforge", "prepared-launch-terminate"],
                Path("/absolute/window.png"),
                ("7-Zip",),
                on_window_observed=acknowledge,
                timeout=1,
            )
        self.assertEqual(hook_budgets, [1.0])
        self.assertEqual(screenshot_calls, [])
        self.assertTrue(selector.unregistered)
        self.assertTrue(selector.closed)
        self.assertFalse(process.terminated)
        self.assertFalse(process.killed)

    def test_ack_wait_polls_liveness_before_every_read_or_sleep(self) -> None:
        cases = (
            ("initially-dead", (False,), (False,), (), 0.0),
            ("dies-during-wait", (True, False), (True, False), (0.25,), 0.25),
        )
        for name, liveness, expected_calls, expected_sleeps, expected_elapsed in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="compatforge-gui-ack-liveness-"
            ) as temporary:
                root = Path(temporary)
                plan_path = root / "plans" / "plan.json"
                acknowledgement_root = root / "ack"
                plan_path.parent.mkdir()
                (acknowledgement_root / "challenges").mkdir(parents=True)
                (acknowledgement_root / "receipts").mkdir()
                self.write_canonical_json(plan_path, self.interaction_plan())
                session = self.baseline.open_interaction_session(
                    plan_path, acknowledgement_root, "round-1", "crossover"
                )
                now = [0.0]
                alive_values = iter(liveness)
                alive_calls: list[bool] = []
                sleeps: list[float] = []

                def application_alive() -> bool:
                    alive = next(alive_values)
                    alive_calls.append(alive)
                    return alive

                def advance(seconds: float) -> None:
                    sleeps.append(seconds)
                    now[0] += seconds

                try:
                    with self.assertRaises(self.baseline.InteractionUnverifiedError):
                        session.acknowledge_application(
                            app_id="7zip",
                            runtime_version="24.0",
                            pack_digest="sha256:" + "a" * 64,
                            asset_digest="sha256:" + "b" * 64,
                            window_observed=True,
                            nonce_source=lambda _size: "c" * 64,
                            monotonic=lambda: now[0],
                            sleeper=advance,
                            application_alive=application_alive,
                        )
                finally:
                    session.close()
                self.assertEqual(tuple(alive_calls), expected_calls)
                self.assertEqual(tuple(sleeps), expected_sleeps)
                self.assertEqual(now[0], expected_elapsed)
                self.assertLess(now[0], 1.0)

    def test_ack_budget_cannot_outlive_interactive_application(self) -> None:
        self.assertLessEqual(
            self.baseline.ACKNOWLEDGEMENT_WAIT_SECONDS,
            self.baseline.INTERACTIVE_RUNTIME_MILLISECONDS / 1000,
        )
        self.assertGreaterEqual(
            self.baseline.INTERACTIVE_RUNTIME_MILLISECONDS / 1000,
            2 * self.baseline.ACKNOWLEDGEMENT_WAIT_SECONDS,
        )

    def test_receipt_at_the_deadline_is_late_and_cannot_be_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-ack-deadline-") as temporary:
            root = Path(temporary)
            plan_path = root / "plans" / "plan.json"
            acknowledgement_root = root / "ack"
            plan_path.parent.mkdir()
            (acknowledgement_root / "challenges").mkdir(parents=True)
            (acknowledgement_root / "receipts").mkdir()
            self.write_canonical_json(plan_path, self.interaction_plan())
            session = self.baseline.open_interaction_session(
                plan_path, acknowledgement_root, "round-1", "crossover"
            )
            now = [0.0]

            def late_receipt(
                challenge: dict[str, object], _challenge: Path, receipt: Path
            ) -> bool:
                self.acknowledgements.write_acknowledgement(
                    receipt, self.acknowledgements.make_acknowledgement(challenge)
                )
                now[0] = 0.1
                return True

            try:
                with self.assertRaises(self.baseline.InteractionUnverifiedError):
                    session.acknowledge_application(
                        app_id="7zip",
                        runtime_version="24.0",
                        pack_digest="sha256:" + "a" * 64,
                        asset_digest="sha256:" + "b" * 64,
                        window_observed=True,
                        nonce_source=lambda _size: "c" * 64,
                        monotonic=lambda: now[0],
                        sleeper=lambda seconds: now.__setitem__(0, now[0] + seconds),
                        deadline_seconds=0.1,
                        wait_for_acknowledgement=late_receipt,
                    )
            finally:
                session.close()

    def test_receipt_crossing_deadline_during_read_cannot_be_accepted(self) -> None:
        cases = ((0.099, True), (0.1, False), (0.101, False))
        for final_time, accepted in cases:
            with self.subTest(final_time=final_time), tempfile.TemporaryDirectory(
                prefix="compatforge-gui-ack-final-deadline-"
            ) as temporary:
                root = Path(temporary)
                plan_path = root / "plans" / "plan.json"
                acknowledgement_root = root / "ack"
                plan_path.parent.mkdir()
                (acknowledgement_root / "challenges").mkdir(parents=True)
                (acknowledgement_root / "receipts").mkdir()
                self.write_canonical_json(plan_path, self.interaction_plan())
                session = self.baseline.open_interaction_session(
                    plan_path, acknowledgement_root, "round-1", "crossover"
                )
                now = [0.0]
                original_read = self.acknowledgements.read_acknowledgement

                def write_receipt(
                    challenge: dict[str, object], _challenge: Path, receipt: Path
                ) -> bool:
                    self.acknowledgements.write_acknowledgement(
                        receipt,
                        self.acknowledgements.make_acknowledgement(challenge),
                    )
                    now[0] = 0.099
                    return True

                def read_while_clock_advances(
                    path: Path, binding: object
                ) -> dict[str, object]:
                    acknowledgement = original_read(path, binding)
                    now[0] = final_time
                    return acknowledgement

                try:
                    invocation = lambda: session.acknowledge_application(
                        app_id="7zip",
                        runtime_version="24.0",
                        pack_digest="sha256:" + "a" * 64,
                        asset_digest="sha256:" + "b" * 64,
                        window_observed=True,
                        nonce_source=lambda _size: "c" * 64,
                        monotonic=lambda: now[0],
                        sleeper=lambda seconds: now.__setitem__(
                            0, now[0] + seconds
                        ),
                        deadline_seconds=0.1,
                        wait_for_acknowledgement=write_receipt,
                    )
                    with mock.patch.object(
                        self.acknowledgements,
                        "read_acknowledgement",
                        side_effect=read_while_clock_advances,
                    ):
                        if accepted:
                            self.assertEqual(
                                invocation(), {"fileList": True, "menus": True}
                            )
                        else:
                            with self.assertRaises(
                                self.baseline.InteractionUnverifiedError
                            ):
                                invocation()
                    name = "round-1--crossover--7zip.json"
                    self.assertEqual(
                        (acknowledgement_root / "challenges" / name)
                        .read_bytes(),
                        b"!",
                    )
                    self.assertEqual(
                        (acknowledgement_root / "receipts" / name)
                        .read_bytes(),
                        b"!",
                    )
                finally:
                    session.close()

    def test_process_exit_during_acknowledgement_cannot_accept_valid_receipt(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-gui-ack-process-exit-"
        ) as temporary:
            root = Path(temporary)
            plan_path = root / "plans" / "plan.json"
            acknowledgement_root = root / "ack"
            plan_path.parent.mkdir()
            (acknowledgement_root / "challenges").mkdir(parents=True)
            (acknowledgement_root / "receipts").mkdir()
            self.write_canonical_json(plan_path, self.interaction_plan())
            session = self.baseline.open_interaction_session(
                plan_path, acknowledgement_root, "round-1", "crossover"
            )
            process_liveness = iter((True, True, False))
            liveness_checks: list[bool] = []

            def write_receipt_before_exit(
                challenge: dict[str, object], _challenge: Path, receipt: Path
            ) -> bool:
                self.acknowledgements.write_acknowledgement(
                    receipt, self.acknowledgements.make_acknowledgement(challenge)
                )
                return True

            def application_alive() -> bool:
                alive = next(process_liveness)
                liveness_checks.append(alive)
                return alive

            try:
                with self.assertRaises(self.baseline.InteractionUnverifiedError):
                    session.acknowledge_application(
                        app_id="7zip",
                        runtime_version="24.0",
                        pack_digest="sha256:" + "a" * 64,
                        asset_digest="sha256:" + "b" * 64,
                        window_observed=True,
                        nonce_source=lambda _size: "c" * 64,
                        application_alive=application_alive,
                        wait_for_acknowledgement=write_receipt_before_exit,
                    )
            finally:
                session.close()
            self.assertEqual(liveness_checks, [True, True, False])
            challenge = (
                acknowledgement_root
                / "challenges"
                / "round-1--crossover--7zip.json"
            )
            receipt = (
                acknowledgement_root
                / "receipts"
                / "round-1--crossover--7zip.json"
            )
            self.assertEqual(challenge.read_bytes(), b"!")
            self.assertEqual(receipt.read_bytes(), b"!")

    def test_accepted_compact_application_requires_literal_complete_checks(self) -> None:
        receipt = {
            "schemaVersion": "1",
            "runtimeId": "crossover",
            "packId": "local-crossover",
            "version": "24.0",
            "packDigest": "sha256:" + "a" * 64,
            "source": "crossover-app",
        }
        accepted_without_checks = {
            "schemaVersion": "1",
            "runtimeId": "crossover",
            "appId": "7zip",
            "assetSha256": "b" * 64,
            "status": "accepted",
            "cleanup": True,
        }
        compact_without_checks = {
            "schemaVersion": "1",
            "receipt": dict(receipt),
            "applications": [dict(accepted_without_checks)],
        }
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.compact_summary(receipt, [accepted_without_checks])
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.validate_compact_summary(compact_without_checks)

        literal_checks = {"fileList": True, "menus": True}
        accepted = {**accepted_without_checks, "interactionChecks": literal_checks}
        compact = self.baseline.compact_summary(receipt, [accepted])
        self.assertEqual(compact["applications"][0]["interactionChecks"], literal_checks)
        self.baseline.validate_compact_summary(compact)

    def test_unverified_or_invalid_interaction_outcome_cannot_claim_checks(self) -> None:
        receipt = {
            "schemaVersion": "1",
            "runtimeId": "crossover",
            "packId": "local-crossover",
            "version": "24.0",
            "packDigest": "sha256:" + "a" * 64,
            "source": "crossover-app",
        }
        for status, reason_code in (
            ("unverified", "application-interaction-unverified"),
            ("failed", "application-interaction-invalid"),
        ):
            application = {
                "schemaVersion": "1",
                "runtimeId": "crossover",
                "appId": "7zip",
                "status": status,
                "failureClass": "application",
                "reasonCode": reason_code,
                "cleanup": True,
                "interactionChecks": {"fileList": True, "menus": True},
            }
            compact = {
                "schemaVersion": "1",
                "receipt": dict(receipt),
                "applications": [dict(application)],
            }
            with self.subTest(status=status, boundary="full"), self.assertRaises(
                self.baseline.AcceptanceError
            ):
                self.baseline.compact_summary(receipt, [application])
            with self.subTest(status=status, boundary="compact"), self.assertRaises(
                self.baseline.AcceptanceError
            ):
                self.baseline.validate_compact_summary(compact)

    def test_nonwindow_path_revalidates_bound_roots_before_returning(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-ack-nonwindow-") as temporary:
            root = Path(temporary)
            plan_path = root / "plans" / "plan.json"
            acknowledgement_root = root / "ack"
            plan_path.parent.mkdir()
            (acknowledgement_root / "challenges").mkdir(parents=True)
            (acknowledgement_root / "receipts").mkdir()
            self.write_canonical_json(plan_path, self.interaction_plan())
            session = self.baseline.open_interaction_session(
                plan_path, acknowledgement_root, "round-1", "crossover"
            )
            try:
                with mock.patch.object(
                    self.baseline.InteractionSession,
                    "_revalidate",
                    side_effect=self.baseline.InteractionIntegrityError(
                        "application interaction root identity changed"
                    ),
                ) as revalidate, self.assertRaises(
                    self.baseline.InteractionIntegrityError
                ):
                    session.acknowledge_application(
                        app_id="7zip",
                        runtime_version="24.0",
                        pack_digest="sha256:" + "a" * 64,
                        asset_digest="sha256:" + "b" * 64,
                        window_observed=False,
                    )
                self.assertEqual(revalidate.call_count, 1)
            finally:
                session.close()

    def test_main_treats_root_drift_on_application_path_as_integrity_fatal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-main-drift-") as temporary:
            root = Path(temporary)
            cli = root / "compatforge"
            cli.write_bytes(b"placeholder")
            work = root / "work"
            plan = root / "plans" / "plan.json"
            acknowledgements = root / "acknowledgements"
            plan.parent.mkdir()
            acknowledgements.mkdir()
            calls: list[str] = []

            class DriftingSession:
                def revalidate(self) -> None:
                    calls.append(f"revalidate-{len(calls) + 1}")
                    if len(calls) == 1:
                        raise self_error

                def close(self) -> None:
                    calls.append("close")

            self_error = self.baseline.InteractionIntegrityError(
                "application interaction root identity changed"
            )

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
                "--runtime-id",
                "crossover",
                "--wine-root",
                str(root / "runtime"),
                "--wine",
                "bin/wine",
                "--wineserver",
                "bin/wineserver",
                "--version",
                "24.0",
                "--accept-interactive",
                "--interaction-plan",
                str(plan),
                "--acknowledgement-root",
                str(acknowledgements),
                "--round-id",
                "round-1",
            ]

            def fake_invoke(command: list[str], *, timeout: int = 0) -> subprocess.CompletedProcess[str]:
                del timeout
                self.assertEqual(command[1:4], ["local", "macos", "context"])
                receipt = self.descriptor_receipt()
                Path(command[-1]).write_text(
                    json.dumps(self.descriptor_context(root / "storage", receipt)),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0, json.dumps(receipt), "")

            stderr = io.StringIO()
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                mock.patch.object(self.baseline.platform, "machine", return_value="arm64"),
                mock.patch.object(self.baseline.os, "access", return_value=True),
                mock.patch.object(self.baseline, "rosetta_available", return_value=True),
                mock.patch.object(self.baseline, "invoke", side_effect=fake_invoke),
                mock.patch.object(
                    self.baseline,
                    "open_interaction_session",
                    return_value=DriftingSession(),
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                result = self.baseline.main()

            self.assertEqual(result, 1)
            self.assertEqual(calls, ["revalidate-1", "revalidate-2", "close"])
            self.assertIn("application interaction root identity changed", stderr.getvalue())

    def test_main_revalidates_after_window_failure_and_before_last_summary(self) -> None:
        for raise_at in (3, 13):
            with self.subTest(raise_at=raise_at), tempfile.TemporaryDirectory(
                prefix="compatforge-gui-window-drift-"
            ) as temporary:
                root = Path(temporary)
                cli = root / "compatforge"
                cli.write_bytes(b"placeholder")
                installer = root / "installer.exe"
                installer.write_bytes(b"MZ")
                installed = root / "installed.exe"
                installed.write_bytes(b"MZ")
                work = root / "work"
                plan = root / "plans" / "plan.json"
                acknowledgements = root / "acknowledgements"
                plan.parent.mkdir()
                acknowledgements.mkdir()
                calls: list[object] = []

                class DriftingSession:
                    def revalidate(self) -> None:
                        number = len([value for value in calls if isinstance(value, int)]) + 1
                        calls.append(number)
                        if number == raise_at:
                            raise self_error

                    def close(self) -> None:
                        calls.append("close")

                self_error = self.baseline.InteractionIntegrityError(
                    "application interaction root identity changed"
                )
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
                    "--runtime-id",
                    "crossover",
                    "--wine-root",
                    str(root / "runtime"),
                    "--wine",
                    "bin/wine",
                    "--wineserver",
                    "bin/wineserver",
                    "--version",
                    "24.0",
                    "--accept-interactive",
                    "--interaction-plan",
                    str(plan),
                    "--acknowledgement-root",
                    str(acknowledgements),
                    "--round-id",
                    "round-1",
                    "--allow-network",
                ]

                def fake_invoke(
                    command: list[str], *, timeout: int = 0
                ) -> subprocess.CompletedProcess[str]:
                    del timeout
                    if command[1:4] == ["local", "macos", "context"]:
                        receipt = self.descriptor_receipt()
                        Path(command[-1]).write_text(
                            json.dumps(self.descriptor_context(root / "storage", receipt)),
                            encoding="utf-8",
                        )
                        return subprocess.CompletedProcess(
                            command, 0, json.dumps(receipt), ""
                        )
                    if command[1] == "inspect":
                        return subprocess.CompletedProcess(
                            command, 0, '{"architecture":"x86_64"}', ""
                        )
                    if command[1] == "prepared-plan":
                        return subprocess.CompletedProcess(command, 0, "{}", "")
                    if command[1] == "prepared-launch-terminate":
                        return subprocess.CompletedProcess(
                            command,
                            0,
                            '{"kind":"exited","exit":{"code":0,"success":true}}\n',
                            "",
                        )
                    raise AssertionError(f"unexpected command: {command}")

                def window_failure(
                    _argv: list[str],
                    _screenshot_path: Path,
                    _title_tokens: tuple[str, ...],
                    **_options: object,
                ) -> tuple[list[dict[str, object]], dict[str, object], dict[str, object], int]:
                    return (
                        [{"kind": "exited", "exit": {"code": 0, "success": True}}],
                        {"available": False},
                        {"available": True},
                        321,
                    )

                stderr = io.StringIO()
                with (
                    mock.patch.object(sys, "argv", argv),
                    mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
                    mock.patch.object(self.baseline.platform, "machine", return_value="arm64"),
                    mock.patch.object(self.baseline.os, "access", return_value=True),
                    mock.patch.object(self.baseline, "rosetta_available", return_value=True),
                    mock.patch.object(self.baseline, "invoke", side_effect=fake_invoke),
                    mock.patch.object(self.baseline, "fetch_asset", return_value=installer),
                    mock.patch.object(
                        self.baseline, "stage_macos_cjk_font", return_value={}
                    ),
                    mock.patch.object(
                        self.baseline, "register_macos_cjk_font", return_value={}
                    ),
                    mock.patch.object(
                        self.baseline, "configure_notepad_cjk_font", return_value={}
                    ),
                    mock.patch.object(
                        self.baseline,
                        "materialize_sumatrapdf_portable",
                        return_value=installed,
                    ),
                    mock.patch.object(
                        self.baseline, "installed_executable", return_value=installed
                    ),
                    mock.patch.object(
                        self.baseline, "observed_launch", side_effect=window_failure
                    ),
                    mock.patch.object(self.baseline, "process_snapshot", return_value=[]),
                    mock.patch.object(
                        self.baseline,
                        "open_interaction_session",
                        return_value=DriftingSession(),
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(stderr),
                ):
                    result = self.baseline.main()

                self.assertEqual(result, 1)
                expected_numbers = list(range(1, 5 if raise_at == 3 else 14))
                self.assertEqual(calls, [*expected_numbers, "close"])
                self.assertIn(
                    "application interaction root identity changed", stderr.getvalue()
                )

    def test_acknowledgement_binds_every_identity_digest_nonce_and_check(self) -> None:
        mutations = (
            ("roundId", "round-2"),
            ("runtimeId", "whisky"),
            ("runtimeVersion", "25.0"),
            ("packDigest", "sha256:" + "d" * 64),
            ("assetDigest", "sha256:" + "e" * 64),
            ("nonce", "f" * 64),
            ("challengeDigest", "sha256:" + "0" * 64),
        )
        variants: list[tuple[str, object]] = list(mutations) + [("appId", "sumatrapdf"), ("checkSet", None)]
        for field, replacement in variants:
            with self.subTest(field=field), tempfile.TemporaryDirectory(
                prefix="compatforge-gui-ack-binding-"
            ) as temporary:
                root = Path(temporary)
                plan_path = root / "plans" / "plan.json"
                acknowledgement_root = root / "ack"
                plan_path.parent.mkdir()
                (acknowledgement_root / "challenges").mkdir(parents=True)
                (acknowledgement_root / "receipts").mkdir()
                self.write_canonical_json(plan_path, self.interaction_plan())
                session = self.baseline.open_interaction_session(
                    plan_path, acknowledgement_root, "round-1", "crossover"
                )

                def wrong_receipt(
                    challenge: dict[str, object], _challenge_path: Path, receipt_path: Path
                ) -> bool:
                    acknowledgement = self.acknowledgements.make_acknowledgement(challenge)
                    if field == "appId":
                        acknowledgement["appId"] = replacement
                        acknowledgement["requiredChecks"] = list(
                            self.acknowledgements.REQUIRED_CHECKS[replacement]
                        )
                        acknowledgement["interactionChecks"] = {
                            check: True for check in acknowledgement["requiredChecks"]
                        }
                    elif field == "checkSet":
                        acknowledgement["interactionChecks"].pop("menus")
                    else:
                        acknowledgement[field] = replacement
                    receipt_path.write_bytes(
                        json.dumps(
                            acknowledgement,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode("utf-8")
                        + b"\n"
                    )
                    return True

                try:
                    with self.assertRaises(self.baseline.InteractionInvalidError):
                        session.acknowledge_application(
                            app_id="7zip",
                            runtime_version="24.0",
                            pack_digest="sha256:" + "a" * 64,
                            asset_digest="sha256:" + "b" * 64,
                            window_observed=True,
                            nonce_source=lambda _size: "c" * 64,
                            wait_for_acknowledgement=wrong_receipt,
                        )
                finally:
                    session.close()

    def test_prefilled_replayed_unsafe_negative_and_timeout_receipts_fail_closed(self) -> None:
        for variant in (
            "prefilled",
            "hardlink",
            "substituted-challenge",
            "substituted-challenge-timeout",
            "replay-round",
            "replay-application",
            "callback-integer",
            "negative",
            "timeout",
        ):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory(
                prefix="compatforge-gui-ack-failure-"
            ) as temporary:
                root = Path(temporary)
                plan_path = root / "plans" / "plan.json"
                acknowledgement_root = root / "ack"
                challenges = acknowledgement_root / "challenges"
                receipts = acknowledgement_root / "receipts"
                plan_path.parent.mkdir()
                challenges.mkdir(parents=True)
                receipts.mkdir()
                self.write_canonical_json(plan_path, self.interaction_plan())
                name = "round-1--crossover--7zip.json"
                if variant == "prefilled":
                    receipts.joinpath(name).write_bytes(b"{}\n")
                session = self.baseline.open_interaction_session(
                    plan_path, acknowledgement_root, "round-1", "crossover"
                )
                now = [0.0]

                def wait(
                    challenge: dict[str, object], challenge_path: Path, receipt_path: Path
                ) -> bool:
                    if variant == "negative":
                        return False
                    if variant == "callback-integer":
                        return 1  # type: ignore[return-value]
                    if variant == "hardlink":
                        victim = root / "victim.json"
                        victim.write_bytes(
                            self.acknowledgements.encode_acknowledgement(
                                self.acknowledgements.make_acknowledgement(challenge)
                            )
                        )
                        os.link(victim, receipt_path)
                    elif variant in (
                        "substituted-challenge",
                        "substituted-challenge-timeout",
                    ):
                        challenge_path.unlink()
                        self.acknowledgements.write_challenge(
                            challenge_path,
                            self.acknowledgements.make_challenge(
                                round_id="round-1",
                                runtime_id="crossover",
                                runtime_version="24.0",
                                app_id="7zip",
                                pack_digest="sha256:" + "a" * 64,
                                asset_digest="sha256:" + "b" * 64,
                                nonce_source=lambda _size: "d" * 64,
                            ),
                        )
                        if variant == "substituted-challenge":
                            self.acknowledgements.write_acknowledgement(
                                receipt_path,
                                self.acknowledgements.make_acknowledgement(challenge),
                            )
                    elif variant in ("replay-round", "replay-application"):
                        replay_app = (
                            "sumatrapdf" if variant == "replay-application" else "7zip"
                        )
                        replay = self.acknowledgements.make_challenge(
                            round_id=(
                                "round-2" if variant == "replay-round" else "round-1"
                            ),
                            runtime_id="crossover",
                            runtime_version="24.0",
                            app_id=replay_app,
                            pack_digest="sha256:" + "a" * 64,
                            asset_digest="sha256:" + "b" * 64,
                            nonce_source=lambda _size: "d" * 64,
                        )
                        self.acknowledgements.write_acknowledgement(
                            receipt_path,
                            self.acknowledgements.make_acknowledgement(replay),
                        )
                    return True

                def sleep(seconds: float) -> None:
                    now[0] += seconds

                expected = (
                    self.baseline.InteractionUnverifiedError
                    if variant in ("negative", "timeout")
                    else self.baseline.InteractionInvalidError
                )
                try:
                    with self.assertRaises(expected):
                        session.acknowledge_application(
                            app_id="7zip",
                            runtime_version="24.0",
                            pack_digest="sha256:" + "a" * 64,
                            asset_digest="sha256:" + "b" * 64,
                            window_observed=True,
                            nonce_source=lambda _size: "c" * 64,
                            monotonic=lambda: now[0],
                            sleeper=sleep,
                            deadline_seconds=0.1,
                            wait_for_acknowledgement=None if variant == "timeout" else wait,
                        )
                finally:
                    session.close()

    def test_interaction_integrity_and_cleanup_failures_are_fatal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-gui-ack-fatal-") as temporary:
            root = Path(temporary)
            plan_path = root / "plans" / "plan.json"
            acknowledgement_root = root / "ack"
            plan_path.parent.mkdir()
            (acknowledgement_root / "challenges").mkdir(parents=True)
            (acknowledgement_root / "receipts").mkdir()
            self.write_canonical_json(plan_path, self.interaction_plan())
            session = self.baseline.open_interaction_session(
                plan_path, acknowledgement_root, "round-1", "crossover"
            )
            try:
                with mock.patch.object(
                    self.acknowledgements,
                    "_revalidate_directory",
                    side_effect=self.acknowledgements.AcknowledgementError(
                        "acknowledgement root identity changed"
                    ),
                ), self.assertRaises(self.baseline.InteractionIntegrityError):
                    session.acknowledge_application(
                        app_id="7zip",
                        runtime_version="24.0",
                        pack_digest="sha256:" + "a" * 64,
                        asset_digest="sha256:" + "b" * 64,
                        window_observed=True,
                    )
            finally:
                session.close()

        with tempfile.TemporaryDirectory(prefix="compatforge-gui-ack-cleanup-") as temporary:
            root = Path(temporary)
            plan_path = root / "plans" / "plan.json"
            acknowledgement_root = root / "ack"
            plan_path.parent.mkdir()
            (acknowledgement_root / "challenges").mkdir(parents=True)
            (acknowledgement_root / "receipts").mkdir()
            self.write_canonical_json(plan_path, self.interaction_plan())
            session = self.baseline.open_interaction_session(
                plan_path, acknowledgement_root, "round-1", "crossover"
            )

            def acknowledge(challenge: dict[str, object], _challenge: Path, receipt: Path) -> bool:
                self.acknowledgements.write_acknowledgement(
                    receipt, self.acknowledgements.make_acknowledgement(challenge)
                )
                return True

            try:
                with mock.patch.object(
                    self.acknowledgements,
                    "_invalidate_relative_if_owned",
                    side_effect=OSError("denied"),
                ), self.assertRaises(self.baseline.InteractionCleanupError):
                    session.acknowledge_application(
                        app_id="7zip",
                        runtime_version="24.0",
                        pack_digest="sha256:" + "a" * 64,
                        asset_digest="sha256:" + "b" * 64,
                        window_observed=True,
                        nonce_source=lambda _size: "c" * 64,
                        wait_for_acknowledgement=acknowledge,
                    )
            finally:
                session.close()
    def test_acceptance_requires_complete_structured_interaction_evidence(self) -> None:
        with self.assertRaises(self.baseline.AcceptanceError):
            self.baseline.interaction_evidence(None, True)
        with tempfile.TemporaryDirectory(prefix="compatforge-interactions-") as temporary:
            path = Path(temporary) / "interactions.json"
            path.write_text(
                json.dumps(
                    {
                        "schemaVersion": "2",
                        "attestation": {
                            "mode": "human",
                            "observer": "Compatibility Lab",
                            "observedAt": "2026-08-18T10:00:00+08:00",
                        },
                        "applications": {
                            "7zip": {"fileList": True, "menus": True, "cjkTextReadable": True},
                            "sumatrapdf": {"mainWindow": True, "openDialog": True, "cjkTextReadable": True},
                            "notepad-plus-plus": {
                                "open": True,
                                "edit": True,
                                "saveUtf8Chinese": True,
                                "rereadMatches": True,
                                "cjkTextReadable": True,
                            },
                        },
                    }
                ),
                encoding="utf-8",
            )
            checks = self.baseline.interaction_evidence(path, True)
            self.assertTrue(checks["notepad-plus-plus"]["rereadMatches"])
            checks, attestation = self.baseline.load_interaction_evidence(path, True)
            self.assertTrue(checks["7zip"]["menus"])
            self.assertEqual(
                attestation,
                {
                    "mode": "human",
                    "observer": "Compatibility Lab",
                    "observedAt": "2026-08-18T10:00:00+08:00",
                },
            )

    def test_interaction_evidence_rejects_legacy_or_automated_attestations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-interactions-") as temporary:
            path = Path(temporary) / "interactions.json"
            for value in (
                {"schemaVersion": "1", "applications": {}},
                {
                    "schemaVersion": "2",
                    "attestation": {
                        "mode": "automation",
                        "observer": "runner",
                        "observedAt": "2026-08-18T10:00:00Z",
                    },
                    "applications": {},
                },
            ):
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(self.baseline.AcceptanceError):
                    self.baseline.interaction_evidence(path, True, {"7zip"})

    def test_interaction_evidence_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-interactions-") as temporary:
            target = Path(temporary) / "target.json"
            target.write_text("{}", encoding="utf-8")
            link = Path(temporary) / "link.json"
            link.symlink_to(target)
            with self.assertRaises(self.baseline.AcceptanceError):
                self.baseline.interaction_evidence(link, True, {"7zip"})

    def test_interaction_worksheet_is_external_closed_and_fails_safe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-interaction-template-") as temporary:
            output = Path(temporary) / "worksheet.json"
            result = subprocess.run(
                [
                    sys.executable,
                    "-S",
                    "-B",
                    str(INTERACTION_TOOL),
                    "--output",
                    str(output),
                    "--observer",
                    "Compatibility Lab",
                    "--app",
                    "vlc",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            worksheet = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(set(worksheet), {"schemaVersion", "attestation", "applications"})
            self.assertEqual(worksheet["attestation"]["observedAt"], "")
            self.assertTrue(all(value is False for value in worksheet["applications"]["vlc"].values()))
            with self.assertRaises(self.baseline.AcceptanceError):
                self.baseline.interaction_evidence(output, True, {"vlc"})

    def test_visual_observation_classifies_infrastructure_separately(self) -> None:
        self.assertEqual(
            self.baseline.observation_diagnostic(
                {
                    "available": False,
                    "reason": "desktop session is locked",
                    "failureClassification": "test-infrastructure",
                },
                {"available": False},
            )["failureClassification"],
            "test-infrastructure",
        )
        self.assertEqual(
            self.baseline.observation_diagnostic(
                {"available": False, "reason": "target window was not observed"},
                {"available": False},
            )["failureClassification"],
            "runtime-regression",
        )

    def test_launch_runtime_covers_visual_evidence_budget(self) -> None:
        self.assertEqual(self.baseline.launch_runtime_milliseconds(30, 0, False), 35_000)
        self.assertEqual(self.baseline.launch_runtime_milliseconds(45, 0, False), 50_000)
        self.assertEqual(self.baseline.launch_runtime_milliseconds(30, 55, False), 60_000)
        self.assertEqual(self.baseline.launch_runtime_milliseconds(30, 0, True), 60_000)

    def test_recipe_digest_binds_visual_evidence_budget(self) -> None:
        asset = self.assets.asset_for("winmerge")
        changed = replace(asset, window_appearance_seconds=30)
        self.assertNotEqual(
            self.baseline.matrix_entry_digest(asset),
            self.baseline.matrix_entry_digest(changed),
        )

    def test_compatibility_result_binds_matrix_and_failure_classification(self) -> None:
        asset = self.assets.asset_for("vlc")
        evidence = {
            "status": "unverified",
            "cleanup": True,
            "failureClassification": "test-infrastructure",
            "windows": {"available": False, "reason": "desktop session is locked"},
            "screenshot": {"available": False},
            "exit": {"present": True},
            "interactionChecks": {},
            "residualProcesses": [],
            "installerInspection": {"architecture": "x86_64"},
        }
        result = self.baseline.compatibility_result(
            asset,
            evidence,
            {"packDigest": "sha256:" + "a" * 64},
            "2026-08-18T10:00:00Z",
            "2026-08-18T10:01:00Z",
        )
        self.assertEqual(result["outcome"], "blocked")
        self.assertEqual(result["failureClassification"], "test-infrastructure")
        self.assertEqual(result["installerDigest"], "sha256:" + asset.sha256)
        self.assertRegex(result["recipeDigest"], r"^sha256:[0-9a-f]{64}$")

    def test_compatibility_schema_requires_reproducibility_keys_and_closed_failures(self) -> None:
        schema = json.loads((ROOT / "schemas" / "compatibility-result.schema.json").read_text(encoding="utf-8"))
        self.assertTrue(
            {"recipeDigest", "installerDigest", "testSuiteVersion"}.issubset(schema["required"])
        )
        self.assertEqual(
            set(schema["properties"]["failureClassification"]["enum"]),
            self.summary_tool.FAILURE_CLASSIFICATIONS,
        )

    def test_summary_separates_policy_and_infrastructure_blocks(self) -> None:
        assets = [self.assets.asset_for("7zip"), self.assets.asset_for("vlc")]
        results = []
        for asset, classification in zip(assets, ("policy-blocked", "test-infrastructure"), strict=True):
            results.append(
                self.baseline.compatibility_result(
                    asset,
                    {
                        "status": "unverified",
                        "cleanup": True,
                        "failureClassification": classification,
                        "windows": {"available": classification == "policy-blocked"},
                        "screenshot": {"available": classification == "policy-blocked"},
                        "exit": {"present": True},
                        "interactionChecks": {},
                        "residualProcesses": [],
                        "installerInspection": {"architecture": "x86_64"},
                    },
                    {"packDigest": "sha256:" + "b" * 64},
                    "2026-08-18T10:00:00Z",
                    "2026-08-18T10:01:00Z",
                )
            )
        report = self.summary_tool.aggregate(
            {
                "schemaVersion": "1",
                "testSuiteVersion": self.baseline.TEST_SUITE_VERSION,
                "compatibilityResults": results,
            }
        )
        self.assertEqual(report["releaseGate"], "blocked")
        self.assertEqual(report["policyBlocked"], 1)
        self.assertEqual(report["infrastructureBlocked"], 1)

    def test_summary_fails_closed_for_skips_and_matrix_digest_drift(self) -> None:
        asset = self.assets.asset_for("7zip")
        result = self.baseline.compatibility_result(
            asset,
            {
                "status": "accepted",
                "cleanup": True,
                "windows": {"available": True},
                "screenshot": {"available": True, "path": "/external/7zip.png"},
                "exit": {"present": True},
                "interactionChecks": {
                    "fileList": True,
                    "menus": True,
                    "cjkTextReadable": True,
                },
                "residualProcesses": [],
                "installerInspection": {"architecture": "x86_64"},
            },
            {"packDigest": "sha256:" + "c" * 64},
            "2026-08-18T10:00:00Z",
            "2026-08-18T10:01:00Z",
        )
        result["outcome"] = "skipped"
        report = self.summary_tool.aggregate(
            {
                "schemaVersion": "1",
                "testSuiteVersion": self.baseline.TEST_SUITE_VERSION,
                "compatibilityResults": [result],
            }
        )
        self.assertEqual(report["releaseGate"], "blocked")
        result["recipeDigest"] = "sha256:" + "0" * 64
        with self.assertRaises(self.baseline.AcceptanceError):
            self.summary_tool.aggregate(
                {
                    "schemaVersion": "1",
                    "testSuiteVersion": self.baseline.TEST_SUITE_VERSION,
                    "compatibilityResults": [result],
                }
            )

    def soak_runtime_selection(self, root: Path) -> dict[str, str]:
        return {
            "runtimeId": "crossover",
            "wineRoot": str(root / "CrossOver Runtime"),
            "wine": "Contents/SharedSupport/CrossOver/bin/wine",
            "wineserver": "Contents/SharedSupport/CrossOver/bin/wineserver",
            "version": "11.0-8726-g2e2f5fca349",
        }

    def test_soak_runtime_selection_is_required_closed_and_unique(self) -> None:
        common = [
            "--compatforge-cli",
            "C:\\tools\\compatforge.exe",
            "--cache-root",
            "C:\\acceptance\\cache",
            "--output-root",
            "C:\\acceptance\\soak",
        ]
        with tempfile.TemporaryDirectory(prefix="compatforge-soak-runtime-") as temporary:
            runtime = self.soak_runtime_selection(Path(temporary))
            identity = [
                "--runtime-id",
                runtime["runtimeId"],
                "--wine-root",
                runtime["wineRoot"],
                "--wine",
                runtime["wine"],
                "--wineserver",
                runtime["wineserver"],
                "--version",
                runtime["version"],
            ]

            parser_failures = (
                common,
                [*common, identity[0], "other", *identity[2:]],
                [*common, *identity, "--version", runtime["version"]],
            )
            for argv in parser_failures:
                with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        self.soak_tool.parser().parse_args(argv)

            arguments = self.soak_tool.parser().parse_args([*common, *identity])
            self.assertEqual(self.soak_tool.runtime_selection(arguments), runtime)

            missing_quartet_field = argparse.Namespace(
                runtime_id=runtime["runtimeId"],
                wine_root=runtime["wineRoot"],
                wine=runtime["wine"],
                wineserver=None,
                version=runtime["version"],
            )
            with self.assertRaises(self.baseline.AcceptanceError):
                self.soak_tool.runtime_selection(missing_quartet_field)

            missing_runtime_id = argparse.Namespace(
                runtime_id=None,
                wine_root=runtime["wineRoot"],
                wine=runtime["wine"],
                wineserver=runtime["wineserver"],
                version=runtime["version"],
            )
            with self.assertRaises(self.baseline.AcceptanceError):
                self.soak_tool.runtime_selection(missing_runtime_id)

            invalid_wine_roots = (
                str(Path("relative") / "CrossOver Runtime"),
                str(Path(temporary) / "CrossOver Runtime" / ".." / "Selected Runtime"),
                str(ROOT / "runtime"),
            )
            for invalid in invalid_wine_roots:
                mutant = argparse.Namespace(
                    runtime_id=runtime["runtimeId"],
                    wine_root=invalid,
                    wine=runtime["wine"],
                    wineserver=runtime["wineserver"],
                    version=runtime["version"],
                )
                with self.subTest(wine_root=invalid):
                    with self.assertRaises(self.baseline.AcceptanceError):
                        self.soak_tool.runtime_selection(mutant)

            for field in ("wine", "wineserver"):
                for invalid in (
                    "",
                    ".",
                    str(Path(temporary) / field),
                    f"../bin/{field}",
                    f"bin/./{field}",
                    f"bin/../{field}",
                    f"bin//{field}",
                    f"\\bin\\{field}",
                    f"bin\\{field}",
                    f"C:bin/{field}",
                ):
                    mutant = argparse.Namespace(
                        runtime_id=runtime["runtimeId"],
                        wine_root=runtime["wineRoot"],
                        wine=runtime["wine"],
                        wineserver=runtime["wineserver"],
                        version=runtime["version"],
                    )
                    setattr(mutant, field, invalid)
                    with self.subTest(field=field, invalid=invalid):
                        with self.assertRaises(self.baseline.AcceptanceError):
                            self.soak_tool.runtime_selection(mutant)

    def test_soak_distinguishes_verified_lifecycle_from_acceptance_and_infrastructure(self) -> None:
        asset = self.assets.asset_for("everything-x86")

        def result(classification: str, visible: bool) -> dict[str, object]:
            return self.baseline.compatibility_result(
                asset,
                {
                    "status": "unverified",
                    "cleanup": True,
                    "failureClassification": classification,
                    "windows": {"available": visible},
                    "screenshot": {
                        "available": visible,
                        **({"path": "/external/everything.png"} if visible else {}),
                    },
                    "exit": {"present": True},
                    "interactionChecks": {},
                    "residualProcesses": [],
                    "installerInspection": {"format": "pe32"},
                },
                {"packDigest": "sha256:" + "d" * 64},
                "2026-08-18T10:00:00Z",
                "2026-08-18T10:01:00Z",
            )

        verified = self.soak_tool.classify_summary(
            {
                "schemaVersion": "1",
                "testSuiteVersion": self.baseline.TEST_SUITE_VERSION,
                "compatibilityResults": [result("policy-blocked", True)],
            },
            {"everything-x86"},
        )
        self.assertEqual(verified["status"], "verified")
        self.assertFalse(verified["hardFailure"])
        self.assertEqual(verified["applications"][0]["outcome"], "blocked")

        duplicate_check = result("policy-blocked", True)
        duplicate_check["checks"].append(duplicate_check["checks"][0])
        with self.assertRaises(self.baseline.AcceptanceError):
            self.soak_tool.classify_summary(
                {
                    "schemaVersion": "1",
                    "testSuiteVersion": self.baseline.TEST_SUITE_VERSION,
                    "compatibilityResults": [duplicate_check],
                },
                {"everything-x86"},
            )

        unavailable = self.soak_tool.classify_summary(
            {
                "schemaVersion": "1",
                "testSuiteVersion": self.baseline.TEST_SUITE_VERSION,
                "compatibilityResults": [result("test-infrastructure", False)],
            },
            {"everything-x86"},
        )
        self.assertEqual(unavailable["status"], "unverified")
        self.assertFalse(unavailable["hardFailure"])

    def test_soak_resume_configuration_is_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-soak-resume-") as temporary:
            root = Path(temporary)
            path = root / "configuration.json"
            selected = {"winmerge", "everything-x86"}
            runtime = self.soak_runtime_selection(root)
            self.soak_tool.write_configuration(path, selected, 60, runtime)
            configuration = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                set(configuration),
                {
                    "schemaVersion",
                    "testSuiteVersion",
                    "applications",
                    "assets",
                    "cycles",
                    "runtimeSelection",
                },
            )
            self.assertEqual(
                configuration["assets"],
                sorted(
                    (
                        {"appId": asset.app_id, "sha256": f"sha256:{asset.sha256}"}
                        for asset in self.assets.CERTIFICATION_ASSETS
                        if asset.app_id in selected
                    ),
                    key=lambda value: value["appId"],
                ),
            )
            self.assertEqual(configuration["runtimeSelection"], runtime)
            self.soak_tool.validate_configuration(path, selected, 60, runtime)

            digest_mutant = json.loads(json.dumps(configuration))
            digest_mutant["assets"][0]["sha256"] = "sha256:" + "0" * 64
            version_mutant = dict(configuration)
            version_mutant["testSuiteVersion"] = "drifted"
            for field, mutant in (
                ("assets.sha256", digest_mutant),
                ("testSuiteVersion", version_mutant),
            ):
                self.write_canonical_json(path, mutant)
                with self.subTest(field=field), self.assertRaises(self.baseline.AcceptanceError):
                    self.soak_tool.validate_configuration(path, selected, 60, runtime)
            self.write_canonical_json(path, configuration)

            runtime_mutations = {
                "runtimeId": "whisky",
                "wineRoot": str(root / "Whisky Runtime"),
                "wine": "bin/wine",
                "wineserver": "bin/wineserver",
                "version": "24.0",
            }
            for field, replacement in runtime_mutations.items():
                mutant = dict(runtime)
                mutant[field] = replacement
                with self.subTest(field=field), self.assertRaises(self.baseline.AcceptanceError):
                    self.soak_tool.validate_configuration(path, selected, 60, mutant)

            with self.assertRaises(self.baseline.AcceptanceError):
                self.soak_tool.validate_configuration(path, {"winmerge"}, 60, runtime)
            with self.assertRaises(self.baseline.AcceptanceError):
                self.soak_tool.validate_configuration(path, selected, 61, runtime)
            self.assertEqual(
                self.soak_tool.cycle_application_ids(
                    {
                        "applications": [
                            {"recipeId": "winmerge"},
                            {"recipeId": "everything-x86"},
                        ]
                    }
                ),
                selected,
            )

    def test_soak_resume_configuration_rejects_json_numeric_aliases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-soak-cycle-type-") as temporary:
            root = Path(temporary)
            path = root / "configuration.json"
            selected = {"winmerge", "everything-x86"}
            runtime = self.soak_runtime_selection(root)
            self.soak_tool.write_configuration(path, selected, 60, runtime)
            configuration = json.loads(path.read_text(encoding="utf-8"))

            for persisted_cycles, requested_cycles in ((60.0, 60), (True, 1)):
                mutant = dict(configuration)
                mutant["cycles"] = persisted_cycles
                self.write_canonical_json(path, mutant)
                with self.subTest(cycles=persisted_cycles):
                    with self.assertRaises(self.baseline.AcceptanceError):
                        self.soak_tool.validate_configuration(
                            path,
                            selected,
                            requested_cycles,
                            runtime,
                        )

    def test_soak_report_records_fail_fast_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-soak-report-") as temporary:
            path = Path(temporary) / "summary.json"
            report = self.soak_tool.write_report(
                path,
                [
                    {
                        "status": "unverified",
                        "hardFailure": False,
                        "infrastructureBlocked": True,
                    }
                ],
                60,
                "cycle 1 completed with status unverified",
            )
            self.assertTrue(report["stoppedEarly"])
            self.assertEqual(report["releaseGate"], "blocked")
        self.assertEqual(report["stopReason"], "cycle 1 completed with status unverified")

    def test_residual_process_check_uses_the_launch_process_group(self) -> None:
        with (
            mock.patch.object(
                self.baseline,
                "process_table",
                return_value=[
                    (100, 100, "/runtime/wine unrelated.exe"),
                    (101, 777, "/runtime/wine target.exe"),
                    (102, 102, "/runtime/wine /external/bottle/drive_c/app.exe"),
                    (103, 103, "C:\\windows\\system32\\services.exe"),
                ],
            ),
            mock.patch.object(self.baseline, "prefix_process_ids", return_value={103}),
        ):
            residual = self.baseline.process_snapshot(Path("/external/bottle/drive_c"), 777)
        self.assertEqual(len(residual), 3)
        self.assertTrue(any(value.startswith("101 ") for value in residual))
        self.assertTrue(any(value.startswith("102 ") for value in residual))
        self.assertTrue(any(value.startswith("103 ") for value in residual))

    def test_cleanup_uses_digest_bound_wineserver_and_exact_prefix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-cleanup-") as temporary:
            root = Path(temporary)
            storage = root / "storage"
            bottle = storage / "bottles" / "probe-fixture"
            drive_c = bottle / "prefix" / "drive_c"
            drive_c.mkdir(parents=True)
            wineserver = root / "wineserver"
            wineserver.write_bytes(b"fixed-wineserver-fixture")
            wineserver.chmod(0o700)
            context = {
                "runtimeBindings": [
                    {
                        "wineserverExecutable": str(wineserver),
                        "environment": {
                            "COMPATFORGE_WINESERVER_EXECUTABLE_SHA256": (
                                "sha256:" + self.baseline.file_sha256(wineserver)
                            ),
                            "WINEDEBUG": "-all",
                        },
                    }
                ]
            }
            completed = subprocess.CompletedProcess([str(wineserver), "-k"], 0, "", "")
            with (
                mock.patch.object(self.baseline.subprocess, "run", return_value=completed) as run,
                mock.patch.object(self.baseline, "prefix_process_ids", return_value=set()),
                mock.patch.object(self.baseline, "process_table", return_value=[]),
                mock.patch.object(self.baseline.time, "sleep"),
            ):
                result = self.baseline.cleanup_bottle(context, storage, "probe-fixture")
            self.assertTrue(result["success"])
            self.assertFalse(bottle.exists())
            self.assertEqual(run.call_args.args[0], [str(wineserver), "-k"])
            self.assertEqual(run.call_args.kwargs["env"]["WINEPREFIX"], str(bottle / "prefix"))

    def test_cleanup_rejects_wineserver_digest_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-cleanup-") as temporary:
            root = Path(temporary)
            storage = root / "storage"
            (storage / "bottles" / "probe-fixture").mkdir(parents=True)
            wineserver = root / "wineserver"
            wineserver.write_bytes(b"changed")
            wineserver.chmod(0o700)
            result = self.baseline.cleanup_bottle(
                {
                    "runtimeBindings": [
                        {
                            "wineserverExecutable": str(wineserver),
                            "environment": {
                                "COMPATFORGE_WINESERVER_EXECUTABLE_SHA256": "sha256:" + "0" * 64,
                            },
                        }
                    ]
                },
                storage,
                "probe-fixture",
            )
            self.assertFalse(result["success"])
            self.assertTrue((storage / "bottles" / "probe-fixture").exists())

    def test_desktop_session_requires_console_and_awake_display(self) -> None:
        def completed(stdout: str, returncode: int = 0) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(["fixture"], returncode, stdout, "")

        console = '"kCGSSessionOnConsoleKey"=Yes'
        awake = "Assertion status system-wide:\n   UserIsActive                 1\n"
        with (
            mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
            mock.patch.object(
                self.baseline.subprocess,
                "run",
                side_effect=[completed(console), completed(awake)],
            ),
        ):
            self.assertEqual(self.baseline.desktop_session_state()["state"], "interactive")

        asleep = "Assertion status system-wide:\n   UserIsActive                 0\n"
        with (
            mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
            mock.patch.object(
                self.baseline.subprocess,
                "run",
                side_effect=[completed(console), completed(asleep)],
            ),
        ):
            value = self.baseline.desktop_session_state()
        self.assertEqual(value["state"], "display-inactive")
        self.assertEqual(value["failureClassification"], "test-infrastructure")

        locked = (
            '"IOConsoleLocked" = No\n'
            '"IOConsoleUsers" = ({"kCGSSessionOnConsoleKey"=Yes,'
            '"CGSSessionScreenIsLocked"=Yes})\n'
        )
        with (
            mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
            mock.patch.object(
                self.baseline.subprocess,
                "run",
                side_effect=[completed(locked), completed(awake)],
            ),
        ):
            value = self.baseline.desktop_session_state()
        self.assertEqual(value["state"], "locked")
        self.assertFalse(value["observable"])

    def test_bottle_wineserver_cleanup_is_prefix_scoped_and_waits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-wineserver-cleanup-") as temporary:
            root = Path(temporary)
            wineserver = root / "wineserver"
            prefix = root / "prefix"
            wineserver.write_bytes(b"runtime")
            wineserver.chmod(0o700)
            prefix.mkdir()
            completed = subprocess.CompletedProcess([], 0, b"", b"")
            with mock.patch.object(
                self.baseline.subprocess,
                "run",
                side_effect=[completed, completed],
            ) as run:
                self.baseline.stop_bottle_wineserver(wineserver, prefix)

        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [[str(wineserver), "-k"], [str(wineserver), "-w"]],
        )
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["env"]["WINEPREFIX"], str(prefix))
            self.assertEqual(call.kwargs["timeout"], 10)

    def test_bottle_wineserver_cleanup_rejects_failure_and_aliases(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-wineserver-invalid-") as temporary:
            root = Path(temporary)
            wineserver = root / "wineserver"
            alias = root / "wineserver-alias"
            prefix = root / "prefix"
            wineserver.write_bytes(b"runtime")
            wineserver.chmod(0o700)
            alias.symlink_to(wineserver)
            prefix.mkdir()
            with self.assertRaises(self.baseline.AcceptanceError):
                self.baseline.stop_bottle_wineserver(alias, prefix)
            failed = subprocess.CompletedProcess([], 1, b"", b"failed")
            with mock.patch.object(
                self.baseline.subprocess,
                "run",
                return_value=failed,
            ), self.assertRaises(self.baseline.AcceptanceError):
                self.baseline.stop_bottle_wineserver(wineserver, prefix)

    def test_window_evidence_is_structured_and_title_bound(self) -> None:
        windows = self.baseline.matching_windows(
            (
                "48498|7-Zip|1288x711\n"
                "wine64-preloader|48499|7-Zip Child|900x700\n"
                "99|Unrelated|800x600\n"
                "100|7-Zip|0x600\n"
            ),
            ("7-Zip",),
        )
        self.assertEqual(
            windows,
            [
                {"processId": 48498, "title": "7-Zip", "width": 1288, "height": 711},
                {"processId": 48499, "title": "7-Zip Child", "width": 900, "height": 700},
            ],
        )

        native = self.baseline.matching_core_graphics_windows(
            [
                {
                    "kCGWindowOwnerPID": 57496,
                    "kCGWindowName": "SumatraPDF",
                    "kCGWindowBounds": {"Width": 771.0, "Height": 1003.0},
                    "kCGWindowLayer": 0,
                    "kCGWindowNumber": 1541,
                },
                {
                    "kCGWindowOwnerPID": 99,
                    "kCGWindowName": "SumatraPDF",
                    "kCGWindowBounds": {"Width": 800, "Height": 600},
                    "kCGWindowLayer": 0,
                    "kCGWindowNumber": 1542,
                },
            ],
            [57496],
            ("SumatraPDF",),
        )
        self.assertEqual(
            native,
            [
                {
                    "processId": 57496,
                    "title": "SumatraPDF",
                    "width": 771,
                    "height": 1003,
                    "windowId": 1541,
                }
            ],
        )

        prepared_window = {
            "kCGWindowOwnerPID": 60003,
            "kCGWindowOwnerName": "CompatForgeWhiskyAcceptance",
            "kCGWindowName": "SumatraPDF",
            "kCGWindowBounds": {"Width": 774, "Height": 1013},
            "kCGWindowLayer": 0,
            "kCGWindowNumber": 1544,
        }
        prepared = self.baseline.matching_prepared_core_graphics_windows(
            [prepared_window], ("SumatraPDF",)
        )
        self.assertEqual(prepared[0]["processId"], 60003)
        self.assertEqual(
            self.baseline.matching_prepared_core_graphics_windows(
                [
                    prepared_window,
                    {**prepared_window, "kCGWindowOwnerPID": 60004},
                ],
                ("SumatraPDF",),
            ),
            [],
        )

        with (
            mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
            mock.patch.object(
                self.baseline,
                "desktop_session_state",
                return_value={"observable": True, "state": "interactive"},
            ),
            mock.patch.object(
                self.baseline, "process_group_ids", return_value=[57496]
            ),
            mock.patch.object(
                self.baseline,
                "core_graphics_window_list",
                return_value=[
                    {
                        "kCGWindowOwnerPID": 57496,
                        "kCGWindowName": "SumatraPDF",
                        "kCGWindowBounds": {"Width": 771, "Height": 1003},
                        "kCGWindowLayer": 0,
                        "kCGWindowNumber": 1541,
                    }
                ],
            ),
        ):
            observed = self.baseline.observer(57496, ("SumatraPDF",))
        self.assertTrue(observed["available"])
        self.assertEqual(observed["windows"], native)

        detached_executable = Path("/external/bottle/drive_c/7-Zip/7zFM.exe")
        with (
            mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
            mock.patch.object(
                self.baseline,
                "desktop_session_state",
                return_value={"observable": True, "state": "interactive"},
            ),
            mock.patch.object(
                self.baseline, "process_group_ids", return_value=[57496]
            ),
            mock.patch.object(
                self.baseline,
                "process_table",
                return_value=[
                    (60001, 60001, f"/runtime/wine64-preloader {detached_executable}"),
                    (60002, 60002, "/runtime/wine64-preloader unrelated.exe"),
                ],
            ),
            mock.patch.object(
                self.baseline,
                "core_graphics_window_list",
                return_value=[
                    {
                        "kCGWindowOwnerPID": 60001,
                        "kCGWindowName": "7-Zip",
                        "kCGWindowBounds": {"Width": 1288, "Height": 711},
                        "kCGWindowLayer": 0,
                        "kCGWindowNumber": 1543,
                    }
                ],
            ),
        ):
            detached = self.baseline.observer(
                57496,
                ("7-Zip",),
                detached_executable,
            )
        self.assertTrue(detached["available"])
        self.assertEqual(detached["processIds"], [57496, 60001])
        self.assertEqual(detached["windows"][0]["processId"], 60001)

        with (
            mock.patch.object(self.baseline.platform, "system", return_value="Darwin"),
            mock.patch.object(
                self.baseline,
                "desktop_session_state",
                return_value={"observable": True, "state": "interactive"},
            ),
            mock.patch.object(
                self.baseline, "process_group_ids", return_value=[57496]
            ),
            mock.patch.object(
                self.baseline,
                "core_graphics_window_list",
                return_value=[prepared_window],
            ),
        ):
            prepared_detached = self.baseline.observer(
                57496,
                ("SumatraPDF",),
                Path("/external/bottle/drive_c/CompatForge/SumatraPDF/SumatraPDF.exe"),
            )
        self.assertTrue(prepared_detached["available"])
        self.assertEqual(prepared_detached["processIds"], [57496, 60003])

        with tempfile.TemporaryDirectory(
            prefix="compatforge-window-screenshot-", dir=PRIVATE_TMP
        ) as temporary:
            target = Path(temporary) / "window.png"
            target.write_bytes(b"png")
            with mock.patch.object(
                self.baseline.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, b"", b""),
            ) as run:
                captured = self.baseline.screenshot(target, 1541)
            self.assertTrue(captured["available"])
            self.assertEqual(
                run.call_args.args[0],
                ["/usr/sbin/screencapture", "-x", "-l1541", str(target)],
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
            self.assertEqual(
                [item["appId"] for item in json.loads(result.stdout)],
                [
                    "7zip",
                    "sumatrapdf",
                    "notepad-plus-plus",
                    "firefox",
                    "krita",
                    "7zip-x86",
                    "vlc",
                    "winmerge",
                    "audacity-x86",
                    "everything-x86",
                ],
            )
            self.assertFalse(cache.exists())


if __name__ == "__main__":
    unittest.main()
