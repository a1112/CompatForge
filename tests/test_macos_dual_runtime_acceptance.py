from __future__ import annotations

import importlib.util
import copy
import hashlib
import os
import re
import shlex
import shutil
import sys
import tempfile
import unittest
import argparse
import json
import subprocess
import threading
import time
from types import SimpleNamespace
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE_TOOL = ROOT / "tools" / "run_macos_dual_runtime_acceptance.py"
GUI_BASELINE_TOOL = ROOT / "tools" / "run_gui_baseline.py"
VALIDATOR = ROOT / "scripts" / "validate_repository.py"
GUI_ASSET_TOOL = ROOT / "tools" / "download_gui_assets.py"
ACCEPTANCE_GUIDE = ROOT / "docs" / "guides" / "macos-local-dual-runtime-acceptance.md"
ACCEPTANCE_INTERACTIONS = ROOT / "examples" / "macos-dual-runtime-interactions.json"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
DESKTOP_SMOKE = ROOT / "apps" / "desktop" / "tests" / "smoke.py"

EXPECTED_MATRIX = {
    "crossover": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
    "whisky": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
}
EXPECTED_REVIEWED_PATHS = (
    "README.md",
    "docs/testing.md",
    "docs/guides/macos-local-dual-runtime-acceptance.md",
    "examples/macos-dual-runtime-interactions.json",
    "tests/test_macos_dual_runtime_acceptance.py",
    "tools/run_macos_dual_runtime_acceptance.py",
)
EXPECTED_REQUIRED_INTERACTIONS = {
    "7zip": ("fileList", "menus"),
    "sumatrapdf": ("mainWindow", "openDialog"),
    "notepad-plus-plus": ("open", "edit", "saveUtf8Chinese", "rereadMatches"),
}

CI_CHECKOUT = "uses:actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
CI_SETUP_PYTHON = (
    "uses:actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
)
CI_RUST_TOOLCHAIN = "uses:dtolnay/rust-toolchain@stable"
EXPECTED_CI_TOP_LEVEL = {
    "name": "CI",
    "on": "",
    "permissions": "",
    "jobs": "",
}
EXPECTED_CI_JOBS = {
    "contracts": ("ubuntu-latest", {}),
    "macos-dual-runtime-contracts": (
        "${{ matrix.os }}",
        {"os": ("windows-latest", "macos-latest")},
    ),
    "rust": (
        "${{ matrix.os }}",
        {"os": ("ubuntu-latest", "macos-latest", "windows-latest")},
    ),
    "desktop": ("macos-latest", {}),
}
EXPECTED_CI_STEP_WITH = {
    ("contracts", 1): (("python-version", "3.12"),),
    ("macos-dual-runtime-contracts", 1): (("python-version", "3.12"),),
    ("rust", 2): (("components", "clippy,rustfmt"),),
    ("desktop", 1): (
        ("cache", "npm"),
        ("cache-dependency-path", "apps/desktop/package-lock.json"),
        ("node-version", "24"),
    ),
    ("desktop", 2): (("components", "clippy,rustfmt"),),
}
EXPECTED_CI_STEP_SURFACES = {
    "contracts": (
        ("", CI_CHECKOUT, "", ""),
        ("", CI_SETUP_PYTHON, "", ""),
        (
            "Validate repository contracts",
            "run:python -B scripts/validate_repository.py",
            "",
            "",
        ),
        (
            "Test macOS headless preview contracts",
            "run:python -S -B -m unittest tests.test_macos_headless_preview -v",
            "",
            "",
        ),
        (
            "Test desktop GUI baseline contracts",
            "run:python -S -B -m unittest tests.test_gui_baseline_contracts -v",
            "",
            "",
        ),
        (
            "Test Bottle migration contracts and independent goldens",
            "run:python -S -B -m unittest "
            "tests.test_bottle_migration_contracts.BottleMigrationRepositoryTests "
            "tests.test_bottle_migration_contracts.BottleMigrationGoldenTests",
            "",
            "",
        ),
        (
            "Check portable Mac-Win assets",
            "run:python -B tools/convert_macwin_assets.py --check",
            "",
            "",
        ),
        (
            "Compile public C header",
            "run:cc -std=c11 -Wall -Wextra -Werror -x c -fsyntax-only -include "
            "crates/compatforge-ffi/include/compatforge.h /dev/null",
            "",
            "",
        ),
        (
            "Compile public C++ header",
            "run:c++ -std=c++17 -Wall -Wextra -Werror -x c++ -fsyntax-only "
            "-include crates/compatforge-ffi/include/compatforge.h /dev/null",
            "",
            "",
        ),
    ),
    "macos-dual-runtime-contracts": (
        ("", CI_CHECKOUT, "", ""),
        ("", CI_SETUP_PYTHON, "", ""),
        (
            "Test dual-Runtime macOS acceptance contracts",
            "run:python -S -B -m unittest "
            "tests.test_macos_dual_runtime_acceptance -v",
            "",
            "",
        ),
    ),
    "rust": (
        ("", CI_CHECKOUT, "", ""),
        (
            "Check portable Mac-Win assets",
            "run:python -B tools/convert_macwin_assets.py --check",
            "",
            "",
        ),
        ("", CI_RUST_TOOLCHAIN, "", ""),
        ("Check formatting", "run:cargo fmt --all --check", "", ""),
        (
            "Check workspace",
            "run:cargo check --workspace --all-targets --locked",
            "",
            "",
        ),
        (
            "Build C ABI library",
            "run:cargo build -p compatforge-ffi --locked",
            "",
            "",
        ),
        (
            "Run ForgeOS dynamic C ABI fixture",
            "run|sha256:99d0dd5c67e23589d805a78895139115018ae60246be6eb49d93b2eedbc4844b",
            "runner.os == 'Linux'",
            "",
        ),
        (
            "Run ForgeOS PE inspection C ABI fixture",
            "run|sha256:be7872699b22dd5039a5933445ceaf2132787d31a914bdc1f83458950d19fba5",
            "runner.os == 'Linux'",
            "",
        ),
        (
            "Run ForgeOS PreparedLaunch C ABI fixture",
            "run|sha256:4c59d2bef8c963c82ad6bb354a1fb9e51563e0bdd1f18cb63419f2c3798d5a42",
            "runner.os == 'Linux'",
            "",
        ),
        (
            "Run ForgeOS application service C ABI fixture",
            "run|sha256:14a252e1715dd539449591b4e3e05e196b8d9c88242ee6a7e1a13a18a0f21b23",
            "runner.os == 'Linux'",
            "",
        ),
        ("Run tests", "run:cargo test --workspace --locked", "", ""),
        (
            "Install Runtime Pack fixture v1",
            "run:cargo run -p compatforge-cli --locked -- runtime install "
            "target/runtime-store tests/fixtures/runtime-packs/basic-v1 manifest.json",
            "",
            "",
        ),
        (
            "Install Runtime Pack fixture v2",
            "run:cargo run -p compatforge-cli --locked -- runtime install "
            "target/runtime-store tests/fixtures/runtime-packs/basic-v2 manifest.json",
            "",
            "",
        ),
        (
            "Verify Runtime Pack fixture v2",
            "run:cargo run -p compatforge-cli --locked -- runtime verify "
            "target/runtime-store "
            "sha256:b7e18e933c0a51f6f1ec387862793e5d22cc2edb7e23c114449ea98357d717af",
            "",
            "",
        ),
        (
            "Roll back Runtime Pack fixture",
            "run:cargo run -p compatforge-cli --locked -- runtime rollback "
            "target/runtime-store fixture-runtime",
            "",
            "",
        ),
        (
            "Run Bottle migration fixture sequence",
            "run|sha256:69c7dbad0a3aecdbf0efe5fbe51fa14913b93a59ba601081ede582fc2484ffc3",
            "runner.os != 'macOS'",
            "bash",
        ),
        (
            "Check strict Bottle migration boundary on macOS",
            "run:cargo test -p compatforge-bottle snapshot --locked",
            "runner.os == 'macOS'",
            "",
        ),
        (
            "Compile example launch plan",
            "run:cargo run -p compatforge-cli --locked -- plan "
            "examples/context-config.linux-arm64.json examples/launch-request.json",
            "",
            "",
        ),
        (
            "Probe host capabilities",
            "run:cargo run -p compatforge-cli --locked -- probe",
            "",
            "",
        ),
        (
            "Verify and inspect PE fixture",
            "run|sha256:a3e34d9dfd5c25f1b50239b25ec39f5fe9c2b574f1b8467dfb756546cbfbed67",
            "",
            "",
        ),
        (
            "Build macOS x86_64 Provider fixture",
            "run|sha256:aada52d4b8c4c4c27af93c40442a2f991d7e0718114169d51f936d661390e022",
            "runner.os == 'macOS'",
            "",
        ),
        (
            "Install macOS Provider Runtime Pack fixture",
            "run:cargo run -p compatforge-cli --locked -- runtime install "
            "target/macos-provider-fixture/store "
            "target/macos-provider-fixture/bundle manifest.json",
            "runner.os == 'macOS'",
            "",
        ),
        (
            "Probe and compile macOS Provider context",
            "run|sha256:f901d4361c8a5b6d4de3145912c5eadd3857ac44b6c0c5ccfaac8a15811ab832",
            "runner.os == 'macOS'",
            "",
        ),
        (
            "Launch and terminate through macOS Provider",
            "run|sha256:2137ceecf302b62d9530a57fca96ad0998f46c4a258bb04d34c05ad4eda52a41",
            "runner.os == 'macOS'",
            "",
        ),
        (
            "Run Clippy",
            "run:cargo clippy --workspace --all-targets --locked -- -D warnings",
            "",
            "",
        ),
    ),
    "desktop": (
        ("", CI_CHECKOUT, "", ""),
        (
            "",
            "uses:actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020",
            "",
            "",
        ),
        ("", CI_RUST_TOOLCHAIN, "", ""),
        (
            "Install locked desktop dependencies",
            "run:npm ci --prefix apps/desktop",
            "",
            "",
        ),
        (
            "Check and build TypeScript frontend",
            "run:npm run build --prefix apps/desktop",
            "",
            "",
        ),
        (
            "Check Tauri Rust formatting",
            "run:cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml -- --check",
            "",
            "",
        ),
        (
            "Test Tauri Rust commands and state",
            "run:cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --locked",
            "",
            "",
        ),
        (
            "Lint Tauri Rust commands",
            "run:cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml "
            "--all-targets --locked -- -D warnings",
            "",
            "",
        ),
        (
            "Build CompatForge.app",
            "run:npm run tauri --prefix apps/desktop -- build --bundles app",
            "",
            "",
        ),
        (
            "Run packaged Tauri smoke",
            "run:python -B apps/desktop/tests/smoke.py "
            "apps/desktop/src-tauri/target/release/bundle/macos/"
            "CompatForge.app/Contents/MacOS/CompatForge",
            "",
            "",
        ),
    ),
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
gui_baseline = load_module("run_gui_baseline_for_dual_runtime", GUI_BASELINE_TOOL)
validator = load_module("validate_repository_for_macos_acceptance", VALIDATOR)
gui_assets = load_module("download_gui_assets_for_dual_runtime_docs", GUI_ASSET_TOOL)
desktop_smoke = load_module("desktop_smoke_for_dual_runtime_ci", DESKTOP_SMOKE)


def _workflow_block_scalar_style(value: str) -> bool:
    return re.fullmatch(r"[|>](?:[1-9][+-]?|[+-][1-9]?)?", value) is not None


def _workflow_comment_free_lines(source: str) -> list[tuple[int, str]]:
    def active_content(value: str) -> str:
        quote = ""
        escaped = False
        for index, character in enumerate(value):
            if quote == '"':
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = ""
            elif quote == "'":
                if character == quote:
                    quote = ""
            elif character in ("'", '"'):
                quote = character
            elif character == "#" and (index == 0 or value[index - 1].isspace()):
                return value[:index].rstrip()
        return value.rstrip()

    lines: list[tuple[int, str]] = []
    block_parent_indent: int | None = None
    pending_block_blanks = 0
    for raw_line in source.splitlines():
        prefix = raw_line[: len(raw_line) - len(raw_line.lstrip())]
        if "\t" in prefix:
            raise AssertionError("workflow indentation must use spaces")
        indent = len(prefix)
        stripped = raw_line.lstrip(" ")
        if block_parent_indent is not None:
            if not stripped:
                pending_block_blanks += 1
                continue
            if indent > block_parent_indent:
                lines.extend(
                    (block_parent_indent + 1, "")
                    for _index in range(pending_block_blanks)
                )
                pending_block_blanks = 0
                lines.append((indent, stripped))
                continue
            pending_block_blanks = 0
            block_parent_indent = None
        content = active_content(stripped)
        if content:
            lines.append((indent, content))
            candidate = content[2:].strip() if content.startswith("- ") else content
            if ":" in candidate:
                key, value = _workflow_pair(candidate)
                if key == "run" and _workflow_block_scalar_style(value):
                    block_parent_indent = indent
    if block_parent_indent is not None:
        lines.extend(
            (block_parent_indent + 1, "")
            for _index in range(pending_block_blanks)
        )
    return lines


def _workflow_pair(content: str) -> tuple[str, str]:
    if ":" not in content:
        raise AssertionError(f"workflow mapping entry is invalid: {content}")
    key, value = content.split(":", 1)
    key = key.strip()
    if not key:
        raise AssertionError("workflow mapping key is empty")
    return key, value.strip()


class _WorkflowScalar(str):
    kind: str
    quote: str

    def __new__(
        cls, value: str, *, kind: str, quote: str = ""
    ) -> _WorkflowScalar:
        scalar = super().__new__(cls, value)
        scalar.kind = kind
        scalar.quote = quote
        return scalar


def _workflow_scalar(value: str) -> _WorkflowScalar:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return _WorkflowScalar(value[1:-1], kind="string", quote=value[0])
    lowered = value.lower()
    if not value or lowered == "null" or value == "~":
        kind = "null"
    elif lowered in ("true", "false"):
        kind = "bool"
    elif re.fullmatch(
        r"[+-]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]*)?(?:[eE][+-]?[0-9_]+)?",
        value,
    ):
        kind = "number"
    else:
        kind = "string"
    return _WorkflowScalar(value, kind=kind)


def _normalize_workflow_surface(value: str, *, preserve_edges: bool = False) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    normalized = re.sub(r"\\\n[ \t]*", "", normalized)
    return normalized if preserve_edges else normalized.strip()


def _workflow_step_signature(
    step: dict[str, object],
) -> tuple[str, str, str, str, tuple[tuple[str, str], ...]]:
    fields = step["fields"]
    active_fields = [field for field in ("uses", "run") if field in fields]
    if len(active_fields) != 1:
        raise AssertionError("workflow step must have exactly one active uses or run field")
    active_field = active_fields[0]
    run_style = step["run-style"] if active_field == "run" else ""
    active_value = _normalize_workflow_surface(
        fields[active_field], preserve_edges=bool(run_style)
    )
    surface_kind = f"run{run_style}" if active_field == "run" else "uses"
    if active_field == "run" and "\n" in active_value:
        digest = hashlib.sha256(active_value.encode("utf-8")).hexdigest()
        surface = f"{surface_kind}sha256:{digest}"
    else:
        surface = f"{surface_kind}:{active_value}"
    return (
        _normalize_workflow_surface(fields.get("name", "")),
        surface,
        _normalize_workflow_surface(fields.get("if", "")),
        _normalize_workflow_surface(fields.get("shell", "")),
        tuple(sorted(step["with"].items())),
    )


def _workflow_inline_list(value: str) -> tuple[_WorkflowScalar, ...]:
    if not value.startswith("[") or not value.endswith("]"):
        raise AssertionError(f"workflow value must be an inline list: {value}")
    body = value[1:-1].strip()
    if not body:
        return ()
    return tuple(_workflow_scalar(item.strip()) for item in body.split(","))


def _workflow_headers(
    lines: list[tuple[int, str]], indent: int
) -> list[tuple[int, str, str]]:
    headers: list[tuple[int, str, str]] = []
    names: set[str] = set()
    for index, (line_indent, content) in enumerate(lines):
        if line_indent != indent or content.startswith("- "):
            continue
        key, value = _workflow_pair(content)
        if key in names:
            raise AssertionError(f"duplicate workflow mapping key: {key}")
        names.add(key)
        headers.append((index, key, value))
    return headers


def _workflow_step(lines: list[tuple[int, str]]) -> dict[str, object]:
    if not lines or lines[0][0] != 6 or not lines[0][1].startswith("- "):
        raise AssertionError("workflow step boundary is invalid")
    fields: dict[str, str] = {}
    with_fields: dict[str, str] = {}
    direct_keys: set[str] = set()
    run_style = ""

    def record_key(key: str) -> None:
        if key in direct_keys:
            raise AssertionError(f"duplicate workflow step field: {key}")
        direct_keys.add(key)

    def set_field(key: str, value: str) -> None:
        if key in fields:
            raise AssertionError(f"duplicate workflow step field: {key}")
        fields[key] = _workflow_scalar(value)

    first_key, first_value = _workflow_pair(lines[0][1][2:].strip())
    record_key(first_key)
    set_field(first_key, first_value)
    index = 1
    while index < len(lines):
        indent, content = lines[index]
        if indent != 8 or content.startswith("- "):
            index += 1
            continue
        key, value = _workflow_pair(content)
        record_key(key)
        if key == "with":
            if value:
                raise AssertionError("workflow step with mapping must be expanded")
            index += 1
            while index < len(lines) and lines[index][0] > 8:
                child_indent, child_content = lines[index]
                if child_indent == 10 and not child_content.startswith("- "):
                    child_key, child_value = _workflow_pair(child_content)
                    if child_key in with_fields:
                        raise AssertionError(
                            f"duplicate workflow step input: {child_key}"
                        )
                    with_fields[child_key] = _workflow_scalar(child_value)
                index += 1
            continue
        if key == "run" and _workflow_block_scalar_style(value):
            run_style = value
            index += 1
            command_lines: list[str] = []
            while index < len(lines) and lines[index][0] > 8:
                command_lines.append(lines[index][1])
                index += 1
            set_field(key, "\n".join(command_lines))
            continue
        set_field(key, value)
        index += 1
    return {
        "fields": fields,
        "keys": tuple(sorted(direct_keys)),
        "run-style": run_style,
        "with": with_fields,
    }


def _workflow_job(lines: list[tuple[int, str]]) -> dict[str, object]:
    direct_fields: dict[str, str] = {}
    for indent, content in lines:
        if indent == 4 and not content.startswith("- "):
            key, value = _workflow_pair(content)
            if key in direct_fields:
                raise AssertionError(f"duplicate workflow job field: {key}")
            direct_fields[key] = _workflow_scalar(value)

    matrix: dict[str, object] = {}
    strategy_fields: dict[str, str] = {}
    strategy_index = next(
        (
            index
            for index, (indent, content) in enumerate(lines)
            if indent == 4 and _workflow_pair(content)[0] == "strategy"
        ),
        None,
    )
    if strategy_index is not None:
        strategy_end = next(
            (
                index
                for index in range(strategy_index + 1, len(lines))
                if lines[index][0] <= 4
            ),
            len(lines),
        )
        for indent, content in lines[strategy_index + 1 : strategy_end]:
            if indent == 6 and not content.startswith("- "):
                key, value = _workflow_pair(content)
                if key in strategy_fields:
                    raise AssertionError(f"duplicate workflow strategy field: {key}")
                strategy_fields[key] = _workflow_scalar(value)
        matrix_index = next(
            (
                index
                for index in range(strategy_index + 1, strategy_end)
                if lines[index][0] == 6
                and _workflow_pair(lines[index][1])[0] == "matrix"
            ),
            None,
        )
        if matrix_index is not None:
            matrix_end = next(
                (
                    index
                    for index in range(matrix_index + 1, strategy_end)
                    if lines[index][0] <= 6
                ),
                strategy_end,
            )
            for indent, content in lines[matrix_index + 1 : matrix_end]:
                if indent == 8 and not content.startswith("- "):
                    key, value = _workflow_pair(content)
                    if key in matrix:
                        raise AssertionError(f"duplicate workflow matrix field: {key}")
                    matrix[key] = (
                        _workflow_inline_list(value)
                        if key == "os"
                        else _workflow_scalar(value)
                    )

    steps: list[dict[str, object]] = []
    steps_index = next(
        (
            index
            for index, (indent, content) in enumerate(lines)
            if indent == 4 and _workflow_pair(content)[0] == "steps"
        ),
        None,
    )
    if steps_index is not None:
        steps_end = next(
            (
                index
                for index in range(steps_index + 1, len(lines))
                if lines[index][0] <= 4
            ),
            len(lines),
        )
        starts = [
            index
            for index in range(steps_index + 1, steps_end)
            if lines[index][0] == 6 and lines[index][1].startswith("- ")
        ]
        for position, start in enumerate(starts):
            end = starts[position + 1] if position + 1 < len(starts) else steps_end
            steps.append(_workflow_step(lines[start:end]))
    return {
        "fields": direct_fields,
        "matrix": matrix,
        "steps": steps,
        "strategy": strategy_fields,
    }


def _workflow_oracle(source: str) -> dict[str, object]:
    lines = _workflow_comment_free_lines(source)
    top_headers = _workflow_headers(lines, 0)
    top = {key: (index, value) for index, key, value in top_headers}
    if not {"on", "permissions", "jobs"}.issubset(top):
        raise AssertionError(
            "workflow must define top-level on, permissions, and jobs mappings"
        )

    def top_block(name: str) -> list[tuple[int, str]]:
        start = top[name][0]
        end = next(
            (index for index, _key, _value in top_headers if index > start),
            len(lines),
        )
        return lines[start + 1 : end]

    top_values = {key: _workflow_scalar(value) for _index, key, value in top_headers}
    permissions: dict[str, str] = {}
    for indent, content in top_block("permissions"):
        if indent == 2 and not content.startswith("- "):
            key, value = _workflow_pair(content)
            if key in permissions:
                raise AssertionError(f"duplicate workflow permission: {key}")
            permissions[key] = _workflow_scalar(value)

    trigger_lines = top_block("on")
    trigger_headers = _workflow_headers(trigger_lines, 2)
    triggers: dict[str, dict[str, object]] = {}
    for position, (start, name, value) in enumerate(trigger_headers):
        if value:
            raise AssertionError(f"workflow trigger must be a mapping: {name}")
        end = (
            trigger_headers[position + 1][0]
            if position + 1 < len(trigger_headers)
            else len(trigger_lines)
        )
        fields: dict[str, object] = {}
        for indent, content in trigger_lines[start + 1 : end]:
            if indent == 4 and not content.startswith("- "):
                key, field_value = _workflow_pair(content)
                if key in fields:
                    raise AssertionError(f"duplicate workflow trigger field: {key}")
                fields[key] = (
                    _workflow_inline_list(field_value)
                    if key == "branches"
                    else _workflow_scalar(field_value)
                )
        triggers[name] = fields

    job_lines = top_block("jobs")
    job_headers = _workflow_headers(job_lines, 2)
    jobs: dict[str, dict[str, object]] = {}
    for position, (start, name, value) in enumerate(job_headers):
        if value:
            raise AssertionError(f"workflow job must be a mapping: {name}")
        end = (
            job_headers[position + 1][0]
            if position + 1 < len(job_headers)
            else len(job_lines)
        )
        jobs[name] = _workflow_job(job_lines[start + 1 : end])
    return {
        "top": top_values,
        "permissions": permissions,
        "triggers": triggers,
        "jobs": jobs,
        "lines": lines,
    }


class MacOsDualRuntimeCiContractTests(unittest.TestCase):
    @staticmethod
    def _workflow() -> str:
        return CI_WORKFLOW.read_text(encoding="utf-8")

    @staticmethod
    def _comment_command(workflow: str, command: str) -> str:
        active = f"        run: {command}"
        commented = f"        # run: {command}"
        if active not in workflow:
            raise AssertionError(f"active workflow command is missing: {command}")
        return workflow.replace(active, commented, 1)

    @staticmethod
    def _append_contract_step(workflow: str, field: str, value: str) -> str:
        marker = "\n  macos-dual-runtime-contracts:\n"
        if marker not in workflow:
            raise AssertionError("dual-Runtime job marker is missing")
        step = f"      - name: Mutant step\n        {field}: {value}\n"
        return workflow.replace(marker, f"\n{step}{marker}", 1)

    @staticmethod
    def _replace_after(workflow: str, marker: str, old: str, new: str) -> str:
        start = workflow.find(marker)
        if start < 0:
            raise AssertionError(f"workflow marker is missing: {marker}")
        target = workflow.find(old, start + len(marker))
        if target < 0:
            raise AssertionError(f"workflow target is missing after {marker}: {old}")
        return workflow[:target] + new + workflow[target + len(old) :]

    def _assert_workflow_contract(self, source: str) -> None:
        document = _workflow_oracle(source)
        triggers = document["triggers"]
        jobs = document["jobs"]

        def assert_gate(fields: dict[str, _WorkflowScalar], label: str) -> None:
            self.assertNotIn("if", fields, label)
            self.assertNotIn("continue-on-error", fields, label)

        def assert_scalar(
            value: object,
            kind: str,
            label: str,
            *,
            quotes: tuple[str, ...] | None = None,
        ) -> None:
            self.assertIsInstance(value, _WorkflowScalar, label)
            self.assertEqual(value.kind, kind, label)
            if kind != "string":
                self.assertEqual(value.quote, "", label)
            if quotes is not None:
                self.assertIn(value.quote, quotes, label)

        self.assertEqual(document["top"], EXPECTED_CI_TOP_LEVEL)
        self.assertEqual(document["permissions"], {"contents": "read"})
        for key, scalar in document["top"].items():
            assert_scalar(scalar, "string" if key == "name" else "null", key)
        assert_scalar(document["permissions"]["contents"], "string", "permissions")
        self.assertEqual(set(triggers), {"push", "pull_request"})
        self.assertEqual(triggers["push"], {"branches": ("main",)})
        self.assertEqual(triggers["pull_request"], {})
        for branch in triggers["push"]["branches"]:
            assert_scalar(branch, "string", "push branch")
        self.assertEqual(tuple(jobs), tuple(EXPECTED_CI_JOBS))
        for job_name, (runner, matrix) in EXPECTED_CI_JOBS.items():
            job = jobs[job_name]
            expected_fields = {"runs-on": runner, "steps": ""}
            expected_strategy: dict[str, str] = {}
            if matrix:
                expected_fields["strategy"] = ""
                expected_strategy = {"fail-fast": "false", "matrix": ""}
            self.assertEqual(job["fields"], expected_fields, job_name)
            self.assertEqual(job["strategy"], expected_strategy, job_name)
            self.assertEqual(job["matrix"], matrix, job_name)
            assert_scalar(job["fields"]["runs-on"], "string", job_name)
            assert_scalar(job["fields"]["steps"], "null", job_name)
            if matrix:
                assert_scalar(job["fields"]["strategy"], "null", job_name)
                assert_scalar(
                    job["strategy"]["fail-fast"], "bool", f"{job_name} fail-fast"
                )
                assert_scalar(
                    job["strategy"]["matrix"], "null", f"{job_name} matrix"
                )
                for runner_name in job["matrix"]["os"]:
                    assert_scalar(runner_name, "string", f"{job_name} matrix os")
            for control in ("needs", "if", "continue-on-error"):
                self.assertNotIn(control, job["fields"], job_name)
            actual_steps = tuple(
                _workflow_step_signature(step) for step in job["steps"]
            )
            expected_steps = tuple(
                (
                    *surface,
                    EXPECTED_CI_STEP_WITH.get((job_name, index), ()),
                )
                for index, surface in enumerate(EXPECTED_CI_STEP_SURFACES[job_name])
            )
            self.assertEqual(
                actual_steps,
                expected_steps,
                job_name,
            )
            self.assertEqual(actual_steps[0][1], CI_CHECKOUT, job_name)
            self.assertEqual(job["steps"][0]["with"], {}, job_name)
            for index, step in enumerate(job["steps"]):
                name, surface, condition, shell = EXPECTED_CI_STEP_SURFACES[
                    job_name
                ][index]
                expected_keys = {"uses"} if surface.startswith("uses:") else {
                    "name",
                    "run",
                }
                if EXPECTED_CI_STEP_WITH.get((job_name, index)):
                    expected_keys.add("with")
                if condition:
                    expected_keys.add("if")
                if shell:
                    expected_keys.add("shell")
                self.assertEqual(step["keys"], tuple(sorted(expected_keys)), name)
                for field_name, scalar in step["fields"].items():
                    assert_scalar(scalar, "string", f"{job_name} {field_name}")
                for input_name, scalar in step["with"].items():
                    assert_scalar(scalar, "string", f"{job_name} {input_name}")
                    if input_name in ("python-version", "node-version"):
                        assert_scalar(
                            scalar,
                            "string",
                            f"{job_name} {input_name}",
                            quotes=("'", '"'),
                        )
                for control in ("working-directory", "env", "continue-on-error"):
                    self.assertNotIn(control, step["fields"], job_name)

        dual = jobs.get("macos-dual-runtime-contracts")
        self.assertIsNotNone(dual)
        self.assertEqual(dual["fields"].get("runs-on"), "${{ matrix.os }}")
        assert_gate(dual["fields"], "dual-Runtime job")
        self.assertEqual(
            dual["matrix"].get("os"), ("windows-latest", "macos-latest")
        )
        self.assertNotIn("exclude", dual["matrix"])

        dual_steps = dual["steps"]
        python_steps = [
            step
            for step in dual_steps
            if step["fields"].get("uses", "").startswith("actions/setup-python@")
        ]
        self.assertEqual(len(python_steps), 1)
        self.assertEqual(python_steps[0]["with"].get("python-version"), "3.12")
        assert_gate(python_steps[0]["fields"], "Python setup")

        dual_command = (
            "python -S -B -m unittest tests.test_macos_dual_runtime_acceptance -v"
        )
        dual_runs = [
            step
            for step in dual_steps
            if step["fields"].get("run") == dual_command
        ]
        self.assertEqual(len(dual_runs), 1)
        assert_gate(dual_runs[0]["fields"], dual_command)

        def command_occurrences(command: str) -> list[tuple[dict, dict]]:
            return [
                (job, step)
                for job in jobs.values()
                for step in job["steps"]
                if step["fields"].get("run") == command
            ]

        for command in (
            "python -B scripts/validate_repository.py",
            "python -S -B -m unittest tests.test_macos_headless_preview -v",
            "python -S -B -m unittest tests.test_gui_baseline_contracts -v",
        ):
            occurrences = command_occurrences(command)
            self.assertEqual(len(occurrences), 1, command)
            job, step = occurrences[0]
            assert_gate(job["fields"], command)
            assert_gate(step["fields"], command)

        desktop = jobs.get("desktop")
        self.assertIsNotNone(desktop)
        self.assertEqual(desktop["fields"].get("runs-on"), "macos-latest")
        assert_gate(desktop["fields"], "desktop job")
        desktop_steps = desktop["steps"]
        node_steps = [
            step
            for step in desktop_steps
            if step["fields"].get("uses", "").startswith("actions/setup-node@")
        ]
        self.assertEqual(len(node_steps), 1)
        self.assertEqual(node_steps[0]["with"].get("node-version"), "24")
        assert_gate(node_steps[0]["fields"], "Node setup")

        smoke_command = (
            "python -B apps/desktop/tests/smoke.py "
            "apps/desktop/src-tauri/target/release/bundle/macos/"
            "CompatForge.app/Contents/MacOS/CompatForge"
        )
        desktop_commands = (
            "npm ci --prefix apps/desktop",
            "npm run build --prefix apps/desktop",
            "cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml --locked",
            "cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets --locked -- -D warnings",
            "npm run tauri --prefix apps/desktop -- build --bundles app",
            smoke_command,
        )
        for command in desktop_commands:
            matching = [
                step
                for step in desktop_steps
                if step["fields"].get("run") == command
            ]
            self.assertEqual(len(matching), 1, command)
            assert_gate(matching[0]["fields"], command)
        self.assertEqual(
            shlex.split(smoke_command),
            [
                "python",
                "-B",
                "apps/desktop/tests/smoke.py",
                "apps/desktop/src-tauri/target/release/bundle/macos/"
                "CompatForge.app/Contents/MacOS/CompatForge",
            ],
        )

        active_lines = "\n".join(content for _indent, content in document["lines"])
        folded_lines = active_lines.casefold()
        for token in ("secrets.", "secrets[", "secrets:", "self-hosted"):
            self.assertNotIn(token, folded_lines)

    def _assert_smoke_main_contract(self, module: object) -> None:
        source_environment = {
            "PATH": "/usr/bin",
            "HOME": "/tmp/home",
            "COMPATFORGE_RUNTIME_ROOT": "/private/runtime",
            "WINEPREFIX": "/private/bottle",
            "CX_BOTTLE": "private-bottle",
            "CROSSOVER_ROOT": "/private/crossover",
            "WHISKY_BOTTLE": "/private/whisky",
        }
        expected_environment = module.smoke_environment(source_environment)
        self.assertEqual(
            expected_environment,
            {
                "PATH": "/usr/bin",
                "HOME": "/tmp/home",
                "COMPATFORGE_DESKTOP_SMOKE": "1",
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "CompatForge"
            executable.write_bytes(b"packaged-app")
            completed = subprocess.CompletedProcess(
                [str(executable)],
                0,
                "COMPATFORGE_TAURI_SMOKE_READY\n",
                "",
            )
            with (
                mock.patch.dict(module.os.environ, source_environment, clear=True),
                mock.patch.object(
                    module,
                    "smoke_environment",
                    return_value=expected_environment,
                ) as build_environment,
                mock.patch.object(
                    module.subprocess, "run", return_value=completed
                ) as run,
                mock.patch.object(
                    module.sys, "argv", ["smoke.py", str(executable)]
                ),
            ):
                self.assertEqual(module.main(), 0)
        build_environment.assert_called_once_with()
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], [str(executable)])
        self.assertIs(run.call_args.kwargs["env"], expected_environment)
        self.assertEqual(completed.stdout, "COMPATFORGE_TAURI_SMOKE_READY\n")

    def test_default_ci_has_the_complete_active_contract(self) -> None:
        self._assert_workflow_contract(self._workflow())

    def test_workflow_surface_normalization_closes_crlf_continuations(self) -> None:
        self.assertEqual(
            _normalize_workflow_surface("  cu\\\r\n    rl https://example.invalid  "),
            "curl https://example.invalid",
        )

    def test_desktop_smoke_scrubs_runtime_environment(self) -> None:
        source = {
            "PATH": "/usr/bin",
            "HOME": "/tmp/home",
            "COMPATFORGE_RUNTIME_ROOT": "/private/runtime",
            "COMPATFORGE_DESKTOP_SMOKE": "stale",
            "WINEPREFIX": "/private/bottle",
            "WINESERVER": "/private/runtime/bin/wineserver",
            "CX_BOTTLE": "private-bottle",
            "CROSSOVER_ROOT": "/private/crossover",
            "WHISKY_BOTTLE": "/private/whisky",
        }
        environment = desktop_smoke.smoke_environment(source)
        self.assertEqual(
            environment,
            {
                "PATH": "/usr/bin",
                "HOME": "/tmp/home",
                "COMPATFORGE_DESKTOP_SMOKE": "1",
            },
        )

    def test_desktop_smoke_launches_only_the_packaged_executable(self) -> None:
        self._assert_smoke_main_contract(desktop_smoke)

    def test_structured_workflow_oracle_rejects_review_mutants(self) -> None:
        workflow = self._workflow()
        required_commands = (
            "python -S -B -m unittest tests.test_macos_dual_runtime_acceptance -v",
            "python -B scripts/validate_repository.py",
            "cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets --locked -- -D warnings",
            "python -B apps/desktop/tests/smoke.py apps/desktop/src-tauri/target/release/bundle/macos/CompatForge.app/Contents/MacOS/CompatForge",
        )
        mutants = {
            f"comment-{index}": self._comment_command(workflow, command)
            for index, command in enumerate(required_commands)
        }
        mutants.update(
            {
                "delete-pull-request": workflow.replace("  pull_request:\n", "", 1),
                "exclude-windows": workflow.replace(
                    "        os: [windows-latest, macos-latest]\n",
                    "        os: [windows-latest, macos-latest]\n"
                    "        exclude:\n"
                    "          - os: windows-latest\n",
                    1,
                ),
                "rename-desktop-comment-shell": workflow.replace(
                    "\n  desktop:\n", "\n  desktop-real:\n", 1
                )
                + "\n# jobs:\n#   desktop:\n#     runs-on: macos-latest\n",
                "continue-on-error-dual": workflow.replace(
                    "        run: python -S -B -m unittest "
                    "tests.test_macos_dual_runtime_acceptance -v\n",
                    "        run: python -S -B -m unittest "
                    "tests.test_macos_dual_runtime_acceptance -v\n"
                    "        continue-on-error: true\n",
                    1,
                ),
            }
        )
        for label, mutant in mutants.items():
            with self.subTest(label=label), self.assertRaises(AssertionError):
                self._assert_workflow_contract(mutant)

    def test_closed_workflow_oracle_rejects_second_review_mutants(self) -> None:
        workflow = self._workflow()
        dual_marker = "\n  macos-dual-runtime-contracts:\n"
        checkout = (
            "      - uses: actions/checkout@"
            "11bd71901bbe5b1630ceea73d27597364c9af683\n"
        )
        dual_command = (
            "        run: python -S -B -m unittest "
            "tests.test_macos_dual_runtime_acceptance -v\n"
        )
        needs_disabled = workflow.replace(
            dual_marker,
            "\n  disabled-contracts:\n"
            "    if: false\n"
            "    runs-on: ubuntu-latest\n"
            "\n  macos-dual-runtime-contracts:\n"
            "    needs: disabled-contracts\n",
            1,
        )
        split_curl = workflow.replace(
            dual_marker,
            "\n      - name: Split network mutant\n"
            "        run: |\n"
            "          cu\\\n"
            "          rl https://example.invalid/runtime\n"
            + dual_marker,
            1,
        )
        mutants = {
            "pull-request-closed": workflow.replace(
                "  pull_request:\n", "  pull_request:\n    types: [closed]\n", 1
            ),
            "push-paths-ignore-all": workflow.replace(
                "    branches: [main]\n",
                "    branches: [main]\n    paths-ignore: ['**']\n",
                1,
            ),
            "dual-needs-disabled-job": needs_disabled,
            "remove-dual-checkout": self._replace_after(
                workflow, dual_marker, checkout, ""
            ),
            "dual-working-directory": self._replace_after(
                workflow,
                dual_marker,
                dual_command,
                dual_command + "        working-directory: /tmp\n",
            ),
            "wine-msi": self._append_contract_step(
                workflow, "run", "wine Runtime.msi"
            ),
            "wine-setup": self._append_contract_step(
                workflow, "run", "wine setup.exe /S"
            ),
            "split-curl": split_curl,
            "block-shell-comment": workflow.replace(
                "        run: |\n"
                "          cc -std=c11 -Wall -Wextra -Werror \\\n",
                "        run: |\n"
                "          # active shell input\n"
                "          cc -std=c11 -Wall -Wextra -Werror \\\n",
                1,
            ),
        }
        for label, mutant in mutants.items():
            with self.subTest(label=label), self.assertRaises(AssertionError):
                self._assert_workflow_contract(mutant)

    def test_closed_workflow_oracle_rejects_final_review_mutants(self) -> None:
        workflow = self._workflow()
        dual_marker = "\n  macos-dual-runtime-contracts:\n"
        mutants = {
            "folded-run-scalar": workflow.replace(
                "        run: |\n", "        run: >\n", 1
            ),
            "continuation-trailing-space": workflow.replace(
                "          cc -std=c11 -Wall -Wextra -Werror \\\n",
                "          cc -std=c11 -Wall -Wextra -Werror \\ \n",
                1,
            ),
            "top-env": workflow.replace(
                "\njobs:\n", "\nenv:\n  WINE: injected\n\njobs:\n", 1
            ),
            "job-env": workflow.replace(
                dual_marker,
                dual_marker + "    env:\n      WINE: injected\n",
                1,
            ),
            "job-default-cwd": workflow.replace(
                dual_marker,
                dual_marker
                + "    defaults:\n"
                + "      run:\n"
                + "        working-directory: /tmp\n",
                1,
            ),
            "job-container": workflow.replace(
                dual_marker,
                dual_marker + "    container: wine:latest\n",
                1,
            ),
            "setup-node-cache": workflow.replace(
                "          cache: npm\n", "          cache: invalid\n", 1
            ),
            "setup-python-inputs": workflow.replace(
                '          python-version: "3.12"\n',
                '          python-version: "3.12"\n'
                "          cache: invalid\n"
                "          architecture: x86\n",
                1,
            ),
            "rust-components": workflow.replace(
                "          components: clippy,rustfmt\n",
                "          components: invalid\n",
                1,
            ),
        }
        for label, mutant in mutants.items():
            with self.subTest(label=label), self.assertRaises(AssertionError):
                self._assert_workflow_contract(mutant)

    def test_closed_workflow_oracle_accepts_equivalent_quoted_scalars(self) -> None:
        workflow = self._workflow()
        quoted = (
            workflow.replace("name: CI\n", 'name: "CI"\n', 1)
            .replace('python-version: "3.12"', "python-version: '3.12'")
            .replace('node-version: "24"', "node-version: '24'")
            .replace("cache: npm", 'cache: "npm"')
            .replace("contents: read", 'contents: "read"')
        )
        self._assert_workflow_contract(quoted)

    def test_closed_workflow_oracle_rejects_quoted_strategy_boole(self) -> None:
        workflow = self._workflow()
        for quote in ('"', "'"):
            mutant = workflow.replace(
                "      fail-fast: false\n",
                f"      fail-fast: {quote}false{quote}\n",
                1,
            )
            with self.subTest(quote=quote), self.assertRaises(AssertionError):
                self._assert_workflow_contract(mutant)

    def test_closed_workflow_oracle_accepts_bool_and_quoted_versions(self) -> None:
        workflow = self._workflow().replace(
            '          python-version: "3.12"\n',
            "          python-version: '3.12'\n",
            1,
        )
        self._assert_workflow_contract(workflow)

    def test_closed_workflow_oracle_rejects_typed_scalar_mutants(self) -> None:
        workflow = self._workflow()
        mutants = {
            "numeric-python-version": workflow.replace(
                '          python-version: "3.12"\n',
                "          python-version: 3.12\n",
                1,
            ),
            "numeric-node-version": workflow.replace(
                '          node-version: "24"\n',
                "          node-version: 24\n",
                1,
            ),
            "quoted-null-steps": workflow.replace(
                "    steps:\n", '    steps: ""\n', 1
            ),
        }
        for label, mutant in mutants.items():
            with self.subTest(label=label), self.assertRaises(AssertionError):
                self._assert_workflow_contract(mutant)

    def test_closed_workflow_oracle_rejects_indented_blank_in_run_block(
        self,
    ) -> None:
        workflow = self._workflow()
        mutant = workflow.replace(
            "          cc -std=c11 -Wall -Wextra -Werror \\\n",
            "          cc -std=c11 -Wall -Wextra -Werror \\\n"
            "          \n",
            1,
        )
        with self.assertRaises(AssertionError):
            self._assert_workflow_contract(mutant)

    def test_closed_workflow_oracle_rejects_unindented_blank_in_run_block(
        self,
    ) -> None:
        workflow = self._workflow()
        mutant = workflow.replace(
            "          cc -std=c11 -Wall -Wextra -Werror \\\n"
            "            -I crates/compatforge-ffi/include \\\n",
            "          cc -std=c11 -Wall -Wextra -Werror \\\n"
            "\n"
            "            -I crates/compatforge-ffi/include \\\n",
            1,
        )
        with self.assertRaises(AssertionError):
            self._assert_workflow_contract(mutant)

    def test_closed_workflow_oracle_accepts_existing_blocks_and_crlf(self) -> None:
        workflow = self._workflow()
        self._assert_workflow_contract(workflow)
        self._assert_workflow_contract(workflow.replace("\n", "\r\n"))

    def test_closed_workflow_oracle_ignores_blanks_after_run_block(self) -> None:
        workflow = self._workflow()
        adjacent = workflow.replace(
            "            examples/context-config.linux-arm64.json\n"
            "\n"
            "      - name: Run ForgeOS PE inspection C ABI fixture\n",
            "            examples/context-config.linux-arm64.json\n"
            "\n"
            "\n"
            "      - name: Run ForgeOS PE inspection C ABI fixture\n",
            1,
        )
        self._assert_workflow_contract(adjacent)

    def test_structured_workflow_oracle_rejects_active_forbidden_surfaces(self) -> None:
        workflow = self._workflow()
        commands = (
            "curl https://example.invalid/runtime",
            "wget https://example.invalid/runtime",
            "Invoke-WebRequest https://example.invalid/runtime",
            'python -c "import urllib.request"',
            "python tools/download_gui_assets.py fetch 7zip --allow-network",
            "python tools/download_commercial_runtime.py",
            "python tools/run_macos_dual_runtime_acceptance.py --accept-interactive",
            "crossover --version",
            "whisky --version",
            "python capture_screenshot.py",
            "screencapture /tmp/runtime.png",
            "sudo installer -pkg Runtime.pkg -target /",
            "hdiutil attach Runtime.dmg",
            "echo ${{ secrets.RUNTIME_TOKEN }}",
        )
        for command in commands:
            mutant = self._append_contract_step(workflow, "run", command)
            with self.subTest(command=command), self.assertRaises(AssertionError):
                self._assert_workflow_contract(mutant)

        prohibited_use = self._append_contract_step(
            workflow, "uses", "crossover/download-runtime@v1"
        )
        with self.assertRaises(AssertionError):
            self._assert_workflow_contract(prohibited_use)

        self_hosted = workflow.replace(
            "    runs-on: ${{ matrix.os }}\n", "    runs-on: self-hosted\n", 1
        )
        with self.assertRaises(AssertionError):
            self._assert_workflow_contract(self_hosted)

    def test_structured_workflow_oracle_ignores_comments(self) -> None:
        workflow = self._workflow().replace(
            '          python-version: "3.12"\n',
            '          python-version: "3.12" # pinned interpreter\n',
            1,
        ) + (
            "\n# curl https://example.invalid/runtime\n"
            "# sudo installer -pkg Runtime.pkg -target /\n"
            "# uses: crossover/download-runtime@v1\n"
            "# runs-on: self-hosted\n"
            "# run: echo ${{ secrets.RUNTIME_TOKEN }}\n"
        )
        self._assert_workflow_contract(workflow)

    def test_desktop_smoke_main_bypass_mutant_is_rejected(self) -> None:
        source = DESKTOP_SMOKE.read_text(encoding="utf-8")
        original = "    environment = smoke_environment()\n"
        self.assertIn(original, source)
        mutant = source.replace(original, "    environment = os.environ.copy()\n", 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "smoke_mutant.py"
            path.write_text(mutant, encoding="utf-8")
            module = load_module("desktop_smoke_bypass_mutant", path)
            with self.assertRaises(AssertionError):
                self._assert_smoke_main_contract(module)


class MacOsDualRuntimeAcceptanceContractTests(unittest.TestCase):
    @staticmethod
    def _copy_reviewed_surface(repository_root: Path) -> None:
        for relative in EXPECTED_REVIEWED_PATHS:
            target = repository_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, target)

    @staticmethod
    def _rewrite_json(path: Path, mutate: callable) -> None:
        document = json.loads(path.read_text(encoding="utf-8"))
        mutate(document)
        path.write_bytes(
            (
                json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2)
                + "\n"
            ).encode("utf-8")
        )

    def test_operator_guide_exists_and_binds_the_exact_local_flow(self) -> None:
        self.assertTrue(ACCEPTANCE_GUIDE.is_file())
        guide = ACCEPTANCE_GUIDE.read_text(encoding="utf-8")
        for required in (
            "Python 3.11+",
            "Apple Silicon",
            "Rosetta",
            "CrossOver",
            "Whisky",
            "x86_64-w64-mingw32-gcc",
            "Rust",
            "Node.js",
            "16",
            "developer-local",
            "python3 -S -B tools/discover_macos_wine.py --all",
            "python3 -S -B tools/run_macos_dual_runtime_acceptance.py",
        ):
            self.assertIn(required, guide)

    def test_interaction_template_exists_and_has_four_independent_records(self) -> None:
        self.assertTrue(ACCEPTANCE_INTERACTIONS.is_file())
        document = json.loads(ACCEPTANCE_INTERACTIONS.read_text(encoding="utf-8"))
        self.assertEqual(set(document), {"schemaVersion", "records"})
        self.assertEqual(document["schemaVersion"], "1")
        self.assertEqual(
            [(record["roundId"], record["runtimeId"]) for record in document["records"]],
            [
                ("round-1", "crossover"),
                ("round-1", "whisky"),
                ("round-2", "crossover"),
                ("round-2", "whisky"),
            ],
        )
        for record in document["records"]:
            evidence = record["document"]
            self.assertEqual(evidence["schemaVersion"], "1")
            self.assertEqual(
                {name: set(checks) for name, checks in evidence["applications"].items()},
                {
                    name: set(checks)
                    for name, checks in EXPECTED_REQUIRED_INTERACTIONS.items()
                },
            )
            self.assertTrue(
                all(
                    checked is True
                    for checks in evidence["applications"].values()
                    for checked in checks.values()
                )
            )

    def test_documented_command_literals_match_the_current_closed_parsers(self) -> None:
        def arguments(lines: tuple[str, ...]) -> list[str]:
            command = " ".join(
                line[:-2] if line.endswith(" \\") else line for line in lines
            )
            return shlex.split(command)[4:]

        self.assertEqual(
            validator.MACOS_ACCEPTANCE_DISCOVERY_COMMAND,
            ("python3 -S -B tools/discover_macos_wine.py --all",),
        )
        standard = acceptance.parse_arguments(
            arguments(validator.MACOS_ACCEPTANCE_ORCHESTRATOR_COMMAND)
        )
        self.assertFalse(standard.allow_network)
        self.assertFalse(standard.negative_checks)
        self.assertEqual(standard.runtime_store_root, "/absolute/external/runtime-store")

        guide = validator._macos_acceptance_markdown(
            validator.MACOS_ACCEPTANCE_GUIDE
        )
        blocks, _prose = validator._macos_acceptance_guide_fences(guide)
        network_lines = tuple(
            line for block in blocks for line in block if "--allow-network" in line
        )
        self.assertEqual(
            network_lines,
            validator.MACOS_ACCEPTANCE_ASSET_FETCH_COMMANDS,
        )

        negative = acceptance.parse_arguments(
            arguments(validator.MACOS_ACCEPTANCE_NEGATIVE_COMMAND)
        )
        self.assertTrue(negative.negative_checks)
        self.assertFalse(negative.allow_network)
        self.assertEqual(
            negative.console_guest,
            "/absolute/external/inputs/windows-console-smoke.exe",
        )

        for command, app_id in zip(
            validator.MACOS_ACCEPTANCE_ASSET_FETCH_COMMANDS,
            ("7zip", "sumatrapdf", "notepad-plus-plus"),
        ):
            parsed = gui_assets.parser().parse_args(shlex.split(command)[4:])
            self.assertEqual(parsed.command, "fetch")
            self.assertEqual(parsed.app, app_id)
            self.assertEqual(parsed.cache_root, "/absolute/external/cache")
            self.assertTrue(parsed.allow_network)

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
        self.assertEqual(validator.validate_macos_acceptance_docs(), [])

    def test_repository_validator_rejects_independent_document_mutants(self) -> None:
        def delete(relative: str):
            return lambda root: (root / relative).unlink()

        def mutate_example(change: callable):
            return lambda root: self._rewrite_json(
                root / "examples/macos-dual-runtime-interactions.json", change
            )

        def replace(relative: str, old: str, new: str):
            def mutation(root: Path) -> None:
                path = root / relative
                source = path.read_text(encoding="utf-8")
                self.assertIn(old, source)
                path.write_bytes(source.replace(old, new, 1).encode("utf-8"))

            return mutation

        def navigation_fence_spoof(root: Path) -> None:
            path = root / "README.md"
            marker = (
                "[Apple Silicon 双 Runtime 本地验收指南]"
                "(docs/guides/macos-local-dual-runtime-acceptance.md)"
            )
            source = path.read_text(encoding="utf-8")
            self.assertIn(marker, source)
            path.write_bytes(
                (
                    source.replace(marker, "[已移除的导航](docs/platform-support.md)", 1)
                    + f"\n```text\n{marker}\n```\n"
                ).encode("utf-8")
            )

        def append_guide(text: str):
            def mutation(root: Path) -> None:
                path = root / "docs/guides/macos-local-dual-runtime-acceptance.md"
                source = path.read_text(encoding="utf-8")
                path.write_bytes((source + "\n" + text + "\n").encode("utf-8"))

            return mutation

        cases = (
            ("missing-guide", delete("docs/guides/macos-local-dual-runtime-acceptance.md")),
            ("missing-example", delete("examples/macos-dual-runtime-interactions.json")),
            ("schema-drift", mutate_example(lambda value: value.update(schemaVersion="2"))),
            (
                "application-drift",
                mutate_example(
                    lambda value: value["records"][0]["document"]["applications"].pop("7zip")
                ),
            ),
            ("round-drift", mutate_example(lambda value: value["records"][0].update(roundId="round-0"))),
            ("runtime-drift", mutate_example(lambda value: value["records"][0].update(runtimeId="other"))),
            (
                "path-leak",
                mutate_example(
                    lambda value: value["records"][0].update(
                        evidencePath="/Users/operator/private.json"
                    )
                ),
            ),
            ("extra-key", mutate_example(lambda value: value.update(comment="looks valid"))),
            (
                "command-flag-drift",
                replace(
                    "docs/guides/macos-local-dual-runtime-acceptance.md",
                    "--runtime-store-root /absolute/external/runtime-store",
                    "--runtime-store /absolute/external/runtime-store",
                ),
            ),
            (
                "command-flag-reordered",
                replace(
                    "docs/guides/macos-local-dual-runtime-acceptance.md",
                    "  --cache-root /absolute/external/cache \\\n  --runtime-store-root /absolute/external/runtime-store \\",
                    "  --runtime-store-root /absolute/external/runtime-store \\\n  --cache-root /absolute/external/cache \\",
                ),
            ),
            (
                "public-beta-claim",
                replace(
                    "docs/guides/macos-local-dual-runtime-acceptance.md",
                    "它不是 public beta",
                    "它是 public beta",
                ),
            ),
            (
                "ci-real-runtime-claim",
                replace(
                    "docs/testing.md",
                    "默认 CI 不下载或运行 CrossOver、Whisky、安装器或真实 Windows 应用。",
                    "默认 CI 下载并运行 CrossOver、Whisky、安装器和真实 Windows 应用。",
                ),
            ),
            (
                "comment-spoof",
                replace(
                    "docs/guides/macos-local-dual-runtime-acceptance.md",
                    "python3 -S -B tools/discover_macos_wine.py --all",
                    "<!-- python3 -S -B tools/discover_macos_wine.py --all -->",
                ),
            ),
            (
                "readme-marker",
                replace(
                    "README.md",
                    "[Apple Silicon 双 Runtime 本地验收指南]",
                    "[已移除的双 Runtime 文档]",
                ),
            ),
            ("navigation-fence-spoof", navigation_fence_spoof),
            (
                "extra-bash-command",
                append_guide(
                    "```bash\npython3 -S -B tools/discover_macos_wine.py --all --verbose\n```"
                ),
            ),
            (
                "duplicate-text-command",
                append_guide(
                    "```text\npython3 -S -B tools/discover_macos_wine.py --all\n```"
                ),
            ),
            (
                "alternate-sh-network-command",
                append_guide("```sh\ncurl https://example.invalid/runtime\n```"),
            ),
            (
                "blank-language-command",
                append_guide(
                    "```\npython3 -S -B tools/discover_macos_wine.py --all --hidden\n```"
                ),
            ),
            (
                "standalone-network-flag",
                append_guide("```console\n--allow-network\n```"),
            ),
            (
                "indented-command",
                append_guide(
                    "    python3 -S -B tools/discover_macos_wine.py --all --hidden"
                ),
            ),
            (
                "inline-curl-command",
                append_guide("Run `curl https://example.invalid/runtime`."),
            ),
            (
                "long-inline-curl-command",
                append_guide("Run ``curl https://example.invalid/runtime`` now."),
            ),
            (
                "blockquote-curl-command",
                append_guide("> curl https://example.invalid/runtime"),
            ),
            (
                "list-wget-command",
                append_guide("- wget https://example.invalid/runtime"),
            ),
            (
                "numbered-python-fetch-command",
                append_guide(
                    "1. python3 -S -B tools/download_gui_assets.py fetch 7zip "
                    "--cache-root /tmp/cache --allow-network"
                ),
            ),
            (
                "inline-network-flag",
                append_guide("Add `--allow-network` to continue."),
            ),
            (
                "inline-network-url",
                append_guide("Run `https://example.invalid/runtime` now."),
            ),
            (
                "task-list-absolute-curl",
                append_guide(
                    "- [ ] /usr/bin/curl https://example.invalid/runtime"
                ),
            ),
            (
                "multiline-code-span-curl",
                append_guide(
                    "Please run ``\n/usr/bin/curl https://example.invalid/runtime\n`` now."
                ),
            ),
            (
                "html-code-curl",
                append_guide(
                    "Please run <code>/usr/bin/curl "
                    "https://example.invalid/runtime</code>."
                ),
            ),
            (
                "please-run-absolute-wget",
                append_guide(
                    "Please run /usr/local/bin/wget https://example.invalid/runtime."
                ),
            ),
            (
                "html-asset-downloader",
                append_guide(
                    "Use <code>tools/download_gui_assets.py fetch 7zip</code>."
                ),
            ),
            ("public-release-ready", append_guide("CompatForge is PUBLIC release-ready.")),
            ("released-claim", append_guide("CompatForge has been released.")),
            ("public-beta-ready", append_guide("This stage is public   beta ready!")),
            ("signed-claim", append_guide("The application is signed.")),
            ("signed-prefix-claim", append_guide("A signed application is available.")),
            (
                "signed-after-comma",
                append_guide("The application, now signed, is available."),
            ),
            ("notarized-claim", append_guide("The build is NOTARIZED.")),
            ("notarized-suffix-claim", append_guide("Build notarized successfully.")),
            ("valid-code-signature", append_guide("A valid code signature is present.")),
            ("notarization-succeeded", append_guide("Notarization succeeded.")),
            (
                "signature-verification-passed",
                append_guide("The artifact signature passed verification."),
            ),
            ("generic-signing-complete", append_guide("Release signing completed.")),
            ("notarizing-succeeded", append_guide("Notarizing succeeded.")),
            (
                "notarized-after-comma",
                append_guide("The build, now notarized, passed validation."),
            ),
            ("dmg-claim", append_guide("A DMG is ready for distribution.")),
            ("dmg-any-mention", append_guide("DMG packaging support is present.")),
            ("generated-dmg-claim", append_guide("Generated DMG for distribution.")),
            (
                "dmg-generated-after-comma",
                append_guide("The DMG, generated locally, is available."),
            ),
            (
                "negative-beta-contrasts-with-signed",
                append_guide(
                    "This is not a public beta although the application is signed."
                ),
            ),
            (
                "negative-signing-contrasts-with-generated-dmg",
                append_guide(
                    "The application is not signed while it generated a DMG."
                ),
            ),
            (
                "cross-repository-authorization",
                append_guide(
                    "Authorized to modify ForgeOS, ForgeTools, and Mac-Win."
                ),
            ),
            (
                "reverse-cross-repository-authorization",
                append_guide("Modifications to ForgeTools are authorized."),
            ),
            ("repository-authorized", append_guide("ForgeOS authorized.")),
            ("repository-may-alter", append_guide("Maintainers may alter ForgeOS.")),
            ("repository-may-rewrite", append_guide("Maintainers may rewrite ForgeOS.")),
            (
                "available-to-public",
                append_guide("The build is available to the public."),
            ),
            ("chinese-public-release", append_guide("本阶段进入公测并公开发布。")),
            ("chinese-external-release", append_guide("本阶段已经对外发布。")),
            ("chinese-signed-notarized", append_guide("应用已签名并完成公证。")),
            ("chinese-signature-valid", append_guide("应用签名有效。")),
            ("chinese-notarization-valid", append_guide("构建公证有效。")),
            ("chinese-signing-complete", append_guide("构建签署完成。")),
            ("chinese-signature-after-comma", append_guide("应用，现已签名。")),
            ("chinese-notarization-after-comma", append_guide("构建，现已公证。")),
            ("chinese-dmg", append_guide("下一步将生成 DMG。")),
            ("chinese-dmg-any-mention", append_guide("本阶段包含 DMG。")),
            ("chinese-dmg-generated", append_guide("DMG 已生成。")),
            ("chinese-dmg-after-comma", append_guide("DMG，已生成。")),
            ("chinese-cross-repository", append_guide("允许修改 ForgeOS。")),
            ("chinese-repository-change", append_guide("可以改动 ForgeTools。")),
            ("chinese-repository-edit", append_guide("允许更改 Mac-Win。")),
            ("chinese-repository-adjust", append_guide("允许调整 ForgeTools。")),
            ("chinese-repository-authorized", append_guide("ForgeOS 获授权。")),
        )
        for label, mutate in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory(
                prefix=f"compatforge-macos-doc-mutant-{label}-"
            ) as temporary:
                repository_root = Path(temporary) / "repository"
                self._copy_reviewed_surface(repository_root)
                mutate(repository_root)
                with mock.patch.object(validator, "ROOT", repository_root):
                    self.assertTrue(validator.validate_macos_acceptance_docs())

    def test_repository_validator_accepts_explicit_negative_nonclaims(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-macos-doc-negative-nonclaims-"
        ) as temporary:
            repository_root = Path(temporary) / "repository"
            self._copy_reviewed_surface(repository_root)
            guide = repository_root / "docs/guides/macos-local-dual-runtime-acceptance.md"
            source = guide.read_text(encoding="utf-8")
            source += (
                "\n这不是公测、不公开发布，未签名、未完成公证、未 notarized，不生成 DMG，"
                "也不授权修改 ForgeOS、ForgeTools 或 Mac-Win。\n"
                "This is not public beta ready or public release ready; "
                "the application is not signed or "
                "notarized, does not create a DMG, and does not authorize modifications "
                "to ForgeOS, ForgeTools, or Mac-Win.\n"
                "This stage is not ready for release; neither the application nor the "
                "build is signed or notarized; it will not generate a DMG and ForgeOS "
                "will not be authorized.\n"
                "本阶段绝非公测或公开发布，绝不会签名或公证，不会生成 DMG，"
                "严禁修改 ForgeOS、ForgeTools 或 Mac-Win。\n"
                "PUBLIC BETA is not ready. Public release is forbidden.\n"
                "中文公测绝不允许，公开发布不会发生。\n"
            )
            guide.write_bytes(source.encode("utf-8"))
            with mock.patch.object(validator, "ROOT", repository_root):
                self.assertEqual(validator.validate_macos_acceptance_docs(), [])

    def test_repository_validator_applies_symmetric_topic_claim_grammar(self) -> None:
        self.assertEqual(
            tuple(
                topic
                for topic, _patterns in getattr(
                    validator, "MACOS_ACCEPTANCE_TOPIC_TRIGGERS", ()
                )
            ),
            ("public", "signing", "dmg", "repositories"),
        )
        accepted = (
            ("public-en-prefix", "This stage is not a public beta."),
            ("public-zh-prefix", "本阶段绝非公测。"),
            ("public-en-suffix", "Public release is forbidden."),
            ("public-zh-suffix", "公开发布不会发生。"),
            (
                "public-en-not-ready-family",
                "This stage is NOT   ready for PUBLIC beta or public release.",
            ),
            (
                "public-en-neither-family",
                "This stage is neither a PUBLIC beta nor a public release.",
            ),
            (
                "public-en-not-intended",
                "This stage is not intended as a public beta.",
            ),
            (
                "public-en-no-plans",
                "There are no plans for a public release.",
            ),
            ("public-en-no-plans-exact", "No plans public release."),
            ("public-zh-not-intended", "本阶段不打算进入公测。"),
            ("public-zh-no-plans", "本阶段无计划公开发布。"),
            ("public-en-never", "This stage is never a public release."),
            ("public-zh-not-planned", "本阶段不计划对外发布。"),
            ("irrelevant-released-file", "File handles are released after cleanup."),
            (
                "irrelevant-released-build-resource",
                "Build resources are released after cleanup.",
            ),
            (
                "public-en-publicly-released-negative",
                "The build was not publicly released.",
            ),
            (
                "public-en-available-publicly-negative",
                "The stage is not available publicly.",
            ),
            ("signing-en-prefix", "The application will not be signed."),
            ("signing-zh-prefix", "应用不会签名。"),
            ("signing-en-suffix", "Application signing is prohibited."),
            ("signing-zh-suffix", "应用签名被禁止。"),
            ("signing-en-out-of-scope", "Code signing is out of scope."),
            ("signing-en-out-of-scope-exact", "Signing out of scope."),
            ("signing-zh-out-of-scope", "代码签名不在本阶段范围内。"),
            ("signing-en-beyond-scope", "Artifact signature is beyond scope."),
            ("signing-en-excluded", "Notarization is excluded."),
            ("signing-en-remains-excluded", "Code signing remains excluded."),
            ("signing-zh-beyond-scope", "构建签署在范围外。"),
            ("dmg-en-prefix", "This stage will not generate a DMG."),
            ("dmg-zh-prefix", "本阶段不会生成 DMG。"),
            ("dmg-en-suffix", "DMG generation will not happen."),
            ("dmg-zh-suffix", "DMG 生成不会发生。"),
            ("dmg-en-forbidden", "DMG generation is forbidden."),
            ("dmg-zh-forbidden", "DMG 生成被禁止。"),
            ("dmg-en-out-of-scope", "DMG generation is out of scope."),
            ("dmg-en-out-of-scope-exact", "DMG generation out of scope."),
            ("dmg-zh-out-of-scope", "DMG 生成不在范围内。"),
            ("dmg-en-beyond-scope", "DMG is beyond scope."),
            ("dmg-en-excluded", "DMG is excluded."),
            ("dmg-zh-excluded", "DMG 已排除。"),
            ("repositories-en-prefix", "This stage will not modify ForgeOS."),
            ("repositories-zh-prefix", "本阶段不会修改 ForgeTools。"),
            ("repositories-en-suffix", "Mac-Win modification is forbidden."),
            ("repositories-zh-suffix", "ForgeOS 修改被禁止。"),
            (
                "public-en-stays-outside-scope",
                "Public release stays outside scope.",
            ),
            (
                "public-en-outside-the-scope",
                "Public release stays outside the scope.",
            ),
            (
                "public-en-outside-the-current-scope",
                "Public release stays outside the current scope.",
            ),
            (
                "signing-en-beyond-this-scope",
                "Code signing remains beyond this scope.",
            ),
            (
                "repositories-en-remains-forbidden",
                "ForgeOS changes remain forbidden.",
            ),
            (
                "unrelated-authorization-en",
                "The operator is authorized to fetch the three fixed assets.",
            ),
            ("unrelated-authorization-zh", "操作者获授权获取三个固定资产。"),
            ("unrelated-edit-complete-zh", "该文件已编辑了。"),
            (
                "public-comma-colon-negative-state",
                "Not public beta, public release: forbidden.",
            ),
            (
                "ordinary-markdown-link",
                "See [network policy](https://example.invalid/policy).",
            ),
            ("ordinary-markdown-autolink", "See <https://example.invalid/policy>."),
            (
                "ordinary-markdown-reference",
                "See policy [p].\n\n[p]: https://example.invalid/policy",
            ),
        )
        rejected = (
            ("public-en-positive", "This stage is a public beta."),
            ("public-zh-positive", "本阶段进入公测。"),
            ("public-en-publicly-available", "The build is publicly available."),
            (
                "public-en-publicly-released-object",
                "Maintainers publicly released the build.",
            ),
            (
                "public-en-available-publicly",
                "The app is available publicly.",
            ),
            ("public-zh-facing-public", "本阶段面向公众发布。"),
            ("signing-en-positive", "Application signing is complete."),
            ("signing-zh-positive", "应用签名有效。"),
            ("dmg-en-positive", "DMG generation is complete."),
            ("dmg-zh-positive", "DMG 已生成。"),
            (
                "repositories-en-positive",
                "ForgeOS modification is authorized.",
            ),
            ("repositories-en-update", "Maintainers may update ForgeTools."),
            ("repositories-zh-positive", "ForgeTools 修改已获授权。"),
            ("repositories-zh-edit", "允许编辑 Mac-Win。"),
            ("repositories-zh-edit-complete", "已编辑了 Mac-Win。"),
            ("repositories-zh-ascii-comma", "ForgeOS, 已获授权。"),
            ("repositories-zh-fullwidth-comma", "ForgeOS，已获授权。"),
            (
                "public-mixed",
                "Public beta is forbidden, but this stage is a public release.",
            ),
            (
                "public-not-ready-family-mixed",
                "This stage is not ready for public beta or public release, "
                "but the application is signed.",
            ),
            (
                "public-neither-family-mixed",
                "This stage is neither a public beta nor a public release, "
                "while the build is notarized.",
            ),
            (
                "public-no-plans-mixed",
                "There are no plans for public release, but maintainers may alter ForgeOS.",
            ),
            (
                "signing-mixed",
                "Application signing is prohibited, but the build is notarized.",
            ),
            (
                "signing-out-of-scope-mixed",
                "Signing is out of scope, but notarization succeeded.",
            ),
            (
                "negative-signing-comma-generated-dmg",
                "The application is not signed, generated DMG is available.",
            ),
            (
                "negative-signing-sentence-generated-dmg",
                "The application is not signed. Generated DMG is available.",
            ),
            (
                "negative-signing-colon-public-release",
                "Not signed: public release begins.",
            ),
            (
                "negative-public-comma-positive-public-release",
                "Not public beta, public release begins.",
            ),
            (
                "negative-public-comma-colon-positive-state",
                "Not public beta, public release: ready.",
            ),
            (
                "dmg-mixed",
                "DMG generation is forbidden, but this stage generated a DMG.",
            ),
            (
                "repositories-mixed",
                "ForgeOS modification is forbidden, but ForgeTools changes are authorized.",
            ),
        )

        for should_accept, cases in ((True, accepted), (False, rejected)):
            for label, fragment in cases:
                with self.subTest(label=label), tempfile.TemporaryDirectory(
                    prefix=f"compatforge-macos-topic-grammar-{label}-"
                ) as temporary:
                    repository_root = Path(temporary) / "repository"
                    self._copy_reviewed_surface(repository_root)
                    guide = (
                        repository_root
                        / "docs/guides/macos-local-dual-runtime-acceptance.md"
                    )
                    source = guide.read_text(encoding="utf-8")
                    guide.write_bytes(f"{source}\n{fragment}\n".encode("utf-8"))
                    with mock.patch.object(validator, "ROOT", repository_root):
                        errors = validator.validate_macos_acceptance_docs()
                    if should_accept:
                        self.assertEqual(errors, [])
                    else:
                        self.assertTrue(errors)

    def test_repository_validator_rejects_duplicate_example_keys(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-macos-doc-duplicate-"
        ) as temporary:
            repository_root = Path(temporary) / "repository"
            self._copy_reviewed_surface(repository_root)
            example = repository_root / "examples/macos-dual-runtime-interactions.json"
            source = example.read_text(encoding="utf-8")
            example.write_bytes(
                source.replace(
                    '{\n  "records":', '{\n  "schemaVersion": "1",\n  "records":', 1
                ).encode("utf-8")
            )
            with mock.patch.object(validator, "ROOT", repository_root):
                self.assertTrue(validator.validate_macos_acceptance_docs())

    def test_repository_validator_rejects_an_ancestor_link(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="compatforge-macos-acceptance-validator-"
        ) as temporary:
            temporary_root = Path(temporary)
            repository_root = temporary_root / "repository"
            external_tools = temporary_root / "external-tools"
            self._copy_reviewed_surface(repository_root)
            external_tools.mkdir()
            (repository_root / "tools" / "run_macos_dual_runtime_acceptance.py").unlink()
            (repository_root / "tools").rmdir()
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


class MacOsDualRuntimeProjectionTests(unittest.TestCase):
    @staticmethod
    def _round_fixture(round_id: str, dynamic_marker: str) -> dict[str, object]:
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
        runtimes: list[dict[str, object]] = []
        for runtime_id, runtime_version in (("crossover", "24.0"), ("whisky", "2.3")):
            applications: list[dict[str, object]] = [
                {
                    "schemaVersion": "1",
                    "runtimeId": runtime_id,
                    "appId": "console",
                    "status": "accepted",
                    "packDigest": "sha256:" + "a" * 64,
                    "guestDigest": "sha256:" + "b" * 64,
                    "eventKinds": ["started", "stdout", "exited"],
                    "exitCode": 0,
                    "requestId": f"console-request-{dynamic_marker}",
                    "pid": 1100 if dynamic_marker == "one" else 2200,
                    "startedAt": f"2026-08-21T00:00:0{1 if dynamic_marker == 'one' else 2}Z",
                    "durationMs": 11 if dynamic_marker == "one" else 29,
                    "workRoot": f"/Users/{dynamic_marker}/console",
                    "runtimeEvents": [
                        {
                            "kind": "started",
                            "requestId": f"event-request-{dynamic_marker}",
                            "pid": 3100 if dynamic_marker == "one" else 4200,
                            "timestampNs": 101 if dynamic_marker == "one" else 909,
                            "durationNs": 7 if dynamic_marker == "one" else 13,
                            "root": f"/Users/{dynamic_marker}/events",
                        }
                    ],
                }
            ]
            for app_id in ("7zip", "sumatrapdf", "notepad-plus-plus"):
                applications.append(
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
                        "requestId": f"{app_id}-request-{dynamic_marker}",
                        "pid": 5100 if dynamic_marker == "one" else 6200,
                        "startedAt": f"2026-08-21T00:01:0{1 if dynamic_marker == 'one' else 2}Z",
                        "durationMs": 17 if dynamic_marker == "one" else 31,
                        "workRoot": f"/Users/{dynamic_marker}/{app_id}",
                        "screenshotPath": f"/Users/{dynamic_marker}/{app_id}.png",
                        "runtimeEvents": [],
                    }
                )
            runtimes.append(
                {
                    "runtimeId": runtime_id,
                    "runtimeVersion": runtime_version,
                    "packDigest": "sha256:" + "c" * 64,
                    "applications": applications,
                    "desktop": {"status": "accepted", "exitCode": 0},
                    "requestId": f"runtime-request-{dynamic_marker}",
                    "processIds": [7100] if dynamic_marker == "one" else [8200],
                    "startedAt": f"2026-08-21T00:02:0{1 if dynamic_marker == 'one' else 2}Z",
                    "durationMs": 23 if dynamic_marker == "one" else 37,
                    "runtimeRoot": f"/Applications/{dynamic_marker}/{runtime_id}",
                    "runtimeEvents": [],
                }
            )
        return {
            "roundId": round_id,
            "runtimes": runtimes,
            "requestId": f"round-request-{dynamic_marker}",
            "startedAt": f"2026-08-21T00:03:0{1 if dynamic_marker == 'one' else 2}Z",
            "durationMs": 41 if dynamic_marker == "one" else 53,
            "workRoot": f"/Users/{dynamic_marker}/round",
            "runtimeEvents": [],
        }

    def test_dynamic_only_evidence_has_byte_equal_allowlist_projection(self) -> None:
        first = self._round_fixture("round-1", "one")
        second = self._round_fixture("round-2", "two")

        first_projection = acceptance.project_round_evidence(first)
        second_projection = acceptance.project_round_evidence(second)

        self.assertEqual(first_projection, second_projection)
        self.assertEqual(
            acceptance.canonical_projection_bytes(first_projection),
            acceptance.canonical_projection_bytes(second_projection),
        )
        self.assertTrue(acceptance.compare_round_evidence(first, second))
        encoded = acceptance.canonical_projection_bytes(first_projection).decode("utf-8")
        for secret in ("request", "/Users/", "/Applications/", ".png", "timestampNs", "pid"):
            self.assertNotIn(secret, encoded)
        self.assertEqual(
            [runtime["runtimeId"] for runtime in first_projection["runtimes"]],
            ["crossover", "whisky"],
        )
        self.assertEqual(
            [app["appId"] for app in first_projection["runtimes"][0]["applications"]],
            ["console", "7zip", "sumatrapdf", "notepad-plus-plus"],
        )

    def test_stable_security_and_behavior_mutations_never_compare_equal(self) -> None:
        baseline = self._round_fixture("round-1", "one")
        cases: list[tuple[str, callable]] = [
            ("runtime-id", lambda value: value["runtimes"][0].update(runtimeId="whisky")),
            ("runtime-version", lambda value: value["runtimes"][0].update(runtimeVersion="25.0")),
            ("pack-digest", lambda value: value["runtimes"][0].update(packDigest="sha256:" + "e" * 64)),
            ("missing-app", lambda value: value["runtimes"][0]["applications"].pop()),
            ("extra-app", lambda value: value["runtimes"][0]["applications"].append(copy.deepcopy(value["runtimes"][0]["applications"][1]))),
            ("app-identity", lambda value: value["runtimes"][0]["applications"][1].update(appId="sumatrapdf")),
            ("asset-digest", lambda value: value["runtimes"][0]["applications"][1].update(assetSha256="e" * 64)),
            ("status", lambda value: value["runtimes"][0]["applications"][1].update(status="failed")),
            ("interaction", lambda value: value["runtimes"][0]["applications"][1]["interactionChecks"].update(menus=False)),
            ("exit", lambda value: value["runtimes"][0]["applications"][1]["exit"].update(code=9, success=False)),
            ("window", lambda value: value["runtimes"][0]["applications"][1].update(windowAvailable=False)),
            ("cleanup", lambda value: value["runtimes"][0]["applications"][1].update(cleanup=False)),
        ]
        for label, mutate in cases:
            with self.subTest(label=label):
                mutant = copy.deepcopy(baseline)
                mutate(mutant)
                self.assertFalse(acceptance.compare_round_evidence(baseline, mutant))

        failure_one = copy.deepcopy(baseline)
        failure_two = copy.deepcopy(baseline)
        for fixture, reason in (
            (failure_one, "application-install-failed"),
            (failure_two, "application-content-verification-failed"),
        ):
            fixture["runtimes"][0]["applications"][1] = {
                "schemaVersion": "1",
                "runtimeId": "crossover",
                "appId": "7zip",
                "status": "failed",
                "failureClass": "application",
                "reasonCode": reason,
            }
        self.assertFalse(acceptance.compare_round_evidence(failure_one, failure_two))

    def test_projection_sorts_fixed_identities_but_rejects_unknown_duplicate_and_bounds(self) -> None:
        unordered = self._round_fixture("round-1", "one")
        unordered["runtimes"].reverse()
        for runtime in unordered["runtimes"]:
            runtime["applications"].reverse()
        projection = acceptance.project_round_evidence(unordered)
        self.assertEqual(
            [runtime["runtimeId"] for runtime in projection["runtimes"]],
            ["crossover", "whisky"],
        )
        self.assertEqual(
            [app["appId"] for app in projection["runtimes"][0]["applications"]],
            ["console", "7zip", "sumatrapdf", "notepad-plus-plus"],
        )

        invalid_documents: list[dict[str, object]] = []
        unknown = self._round_fixture("round-1", "one")
        unknown["absoluteSecret"] = "/Users/private"
        invalid_documents.append(unknown)
        duplicate = self._round_fixture("round-1", "one")
        duplicate["runtimes"][1]["runtimeId"] = "crossover"
        invalid_documents.append(duplicate)
        malformed_dynamic = self._round_fixture("round-1", "one")
        malformed_dynamic["runtimes"][0]["processIds"] = [True]
        invalid_documents.append(malformed_dynamic)
        too_long = self._round_fixture("round-1", "one")
        too_long["requestId"] = "x" * (acceptance.MAX_TEXT_CHARS + 1)
        invalid_documents.append(too_long)
        too_deep = self._round_fixture("round-1", "one")
        too_deep["runtimeEvents"] = [[[[[[[[[[[[[["closed"]]]]]]]]]]]]]]
        invalid_documents.append(too_deep)
        for document in invalid_documents:
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.project_round_evidence(document)

        polluted_projection = copy.deepcopy(projection)
        polluted_projection["absoluteSecret"] = "/Users/private"
        with self.assertRaises(acceptance.AcceptanceError):
            acceptance.canonical_projection_bytes(polluted_projection)


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
            self._macho_tool_at(runtime_root / "bin" / "wine")
            self._macho_tool_at(runtime_root / "bin" / "wineserver")
            self.runtime_roots[runtime_id] = runtime_root

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _tool_at(self, path: Path) -> Path:
        path.write_text("fixture\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def _macho_tool_at(self, path: Path) -> Path:
        path.write_bytes(
            b"\xcf\xfa\xed\xfe" + (0x0100_0007).to_bytes(4, "little") + b"fixture\n"
        )
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

    def _negative_fixture(self):
        self.work.mkdir(exist_ok=True)
        guest = self.external / "console-guest.exe"
        guest.write_bytes(b"MZ" + b"guest-fixture")
        sentinel = self.external / "negative-sentinel"
        sentinel.write_bytes(b"outside-sentinel")
        installer_bytes = b"MZ" + b"installer-fixture"
        asset = SimpleNamespace(
            app_id="7zip",
            filename="fixture-installer.exe",
            sha256=hashlib.sha256(installer_bytes).hexdigest(),
        )
        (self.cache / asset.filename).write_bytes(installer_bytes)
        return guest, sentinel, asset

    def test_negative_checks_reject_four_isolated_mutants_without_touching_sources(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        originals = {
            path: (path.stat(), path.read_bytes())
            for path in (
                guest,
                sentinel,
                self.cache / asset.filename,
                *(root / "bin" / name for root in self.runtime_roots.values() for name in ("wine", "wineserver")),
            )
        }
        validation_calls: list[Path] = []
        inspection_calls: list[list[str]] = []
        fetch_calls: list[tuple[Path, bool]] = []

        def runtime_validator(path: Path) -> set[str]:
            validation_calls.append(path)
            self.assertEqual(list(path.parent.iterdir()), [path])
            return {"x86_64"} if path.read_bytes().startswith(b"\xcf\xfa\xed\xfe") else set()

        def guest_runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            inspection_calls.append(list(argv))
            inspected = Path(argv[-1])
            self.assertEqual(list(inspected.parent.iterdir()), [inspected])
            self.assertFalse(inspected.read_bytes().startswith(b"MZ"))
            return subprocess.CompletedProcess(
                argv, 1, "", "compatforge-cli: invalid DOS header\n"
            )

        class AssetError(Exception):
            pass

        def asset_fetcher(_asset, cache_root: Path, allow_network: bool) -> Path:
            fetch_calls.append((cache_root, allow_network))
            candidate = cache_root / asset.filename
            self.assertEqual(list(cache_root.iterdir()), [candidate])
            if hashlib.sha256(candidate.read_bytes()).hexdigest() != asset.sha256:
                raise AssetError("cached 7zip digest mismatch")
            return candidate

        summary = acceptance.run_negative_checks(
            paths,
            descriptors,
            console_guest=guest,
            sentinel=sentinel,
            runtime_validator=runtime_validator,
            guest_runner=guest_runner,
            asset=asset,
            asset_fetcher=asset_fetcher,
            asset_error=AssetError,
        )

        self.assertEqual(
            summary,
            {
                "schemaVersion": "1",
                "status": "accepted",
                "cases": [
                    {
                        "runtimeId": runtime_id,
                        "caseId": case_id,
                        "status": "accepted",
                        "failureClass": failure_class,
                        "reasonCode": reason_code,
                    }
                    for runtime_id, case_id, failure_class, reason_code in (
                        ("crossover", "wine-bytes-changed", "runtime", "runtime-architecture-invalid"),
                        ("whisky", "wineserver-bytes-changed", "runtime", "runtime-architecture-invalid"),
                        ("crossover", "console-guest-bytes-changed", "core", "core-inspection-refused"),
                        ("whisky", "cached-installer-bytes-changed", "environment", "cached-asset-digest-mismatch"),
                    )
                ],
            },
        )
        self.assertEqual(len(validation_calls), 2)
        self.assertEqual(len(inspection_calls), 1)
        self.assertEqual(inspection_calls[0][1], "inspect")
        self.assertEqual(fetch_calls, [(self.work / "negative" / "whisky" / "cached-installer-bytes-changed", False)])
        for path, (metadata, content) in originals.items():
            current = path.stat()
            self.assertEqual((current.st_dev, current.st_ino), (metadata.st_dev, metadata.st_ino))
            self.assertEqual(path.read_bytes(), content)
        self.assertFalse(any(path.is_file() for path in (self.work / "negative").rglob("*")))
        self.assertNotIn(str(self.external), json.dumps(summary))

    def test_negative_mode_runs_only_discovery_and_guest_validation_processes(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        arguments = self._arguments(
            "--negative-checks",
            "--console-guest",
            str(guest),
            "--negative-sentinel",
            str(sentinel),
        )
        calls: list[list[str]] = []

        def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            calls.append(list(argv))
            if argv[-1] == "--all":
                return subprocess.CompletedProcess(argv, 0, json.dumps(self._discovery()), "")
            if len(argv) == 3 and argv[1] == "inspect":
                return subprocess.CompletedProcess(
                    argv, 1, "", "compatforge-cli: invalid DOS header\n"
                )
            raise AssertionError("negative mode attempted a non-validation process")

        class AssetError(Exception):
            pass

        def fetcher(_asset, cache_root: Path, allow_network: bool) -> Path:
            self.assertFalse(allow_network)
            candidate = cache_root / asset.filename
            if hashlib.sha256(candidate.read_bytes()).hexdigest() != asset.sha256:
                raise AssetError("cached 7zip digest mismatch")
            return candidate

        with (
            mock.patch.object(
                acceptance,
                "_default_runtime_validator",
                side_effect=lambda path: {"x86_64"}
                if path.read_bytes().startswith(b"\xcf\xfa\xed\xfe")
                else set(),
            ),
            mock.patch.object(
                acceptance,
                "_default_asset_boundary",
                return_value=(asset, fetcher, AssetError),
            ),
        ):
            summary = acceptance.orchestrate(
                arguments,
                runner=runner,
                launcher=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    AssertionError("negative mode launched the desktop")
                ),
                host_system="Darwin",
                host_machine="arm64",
                printer=lambda _line: None,
            )

        self.assertEqual(summary["status"], "accepted")
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][-1], "--all")
        self.assertEqual(calls[1][1], "inspect")
        negative_summary = json.loads(
            (self.work / "negative-summary.json").read_text(encoding="utf-8")
        )
        self.assertEqual(negative_summary, summary)

    def test_negative_boundary_failures_are_closed_and_do_not_skip_later_cases(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        runtime_calls = 0
        guest_calls = 0
        asset_calls = 0

        def runtime_accepts(_path: Path) -> set[str]:
            nonlocal runtime_calls
            runtime_calls += 1
            return {"x86_64"}

        def guest_accepts(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            nonlocal guest_calls
            guest_calls += 1
            return subprocess.CompletedProcess(argv, 0, "{}", "")

        class AssetError(Exception):
            pass

        def asset_accepts(_asset, cache_root: Path, allow_network: bool) -> Path:
            nonlocal asset_calls
            asset_calls += 1
            self.assertFalse(allow_network)
            return cache_root / asset.filename

        summary = acceptance.run_negative_checks(
            paths,
            descriptors,
            console_guest=guest,
            sentinel=sentinel,
            runtime_validator=runtime_accepts,
            guest_runner=guest_accepts,
            asset=asset,
            asset_fetcher=asset_accepts,
            asset_error=AssetError,
        )

        self.assertEqual(summary["status"], "failed")
        self.assertEqual([case["status"] for case in summary["cases"]], ["failed"] * 4)
        self.assertEqual(
            {case["reasonCode"] for case in summary["cases"]},
            {"negative-boundary-unexpectedly-accepted"},
        )
        self.assertEqual((runtime_calls, guest_calls, asset_calls), (2, 1, 1))

    def test_default_runtime_negative_boundary_uses_the_discovery_header_validator(self) -> None:
        candidate = self.external / "isolated-runtime-entrypoint"
        self._macho_tool_at(candidate)
        self.assertEqual(acceptance._default_runtime_validator(candidate), {"x86_64"})
        mutated = bytearray(candidate.read_bytes())
        mutated[0] ^= 0xFF
        candidate.write_bytes(mutated)
        self.assertEqual(acceptance._default_runtime_validator(candidate), set())

    def test_runtime_negative_refusal_accepts_only_the_exact_empty_verified_set(self) -> None:
        candidate = self.external / "runtime-mutant"
        candidate.write_bytes(b"mutant")
        self.assertIsNone(
            acceptance._runtime_negative_boundary(candidate, lambda _path: set())
        )
        for result in ({"arm64"}, {"unknown"}, {"arm64", "x86_64"}):
            with self.subTest(result=result):
                self.assertEqual(
                    acceptance._runtime_negative_boundary(
                        candidate, lambda _path, value=result: value
                    ),
                    "negative-boundary-error-invalid",
                )

    def test_guest_negative_refusal_requires_the_exact_cli_diagnostic(self) -> None:
        candidate = self.external / "guest-mutant.exe"
        candidate.write_bytes(b"not-a-PE")

        def result(returncode: int, stdout: str, stderr: str):
            return lambda argv, **_kwargs: subprocess.CompletedProcess(
                argv, returncode, stdout, stderr
            )

        self.assertIsNone(
            acceptance._guest_negative_boundary(
                candidate,
                self.cli,
                result(1, "", "compatforge-cli: invalid DOS header\n"),
            )
        )
        for returncode, stdout, stderr in (
            (1, "", "unrelated failure\n"),
            (1, "unexpected output", "compatforge-cli: invalid DOS header\n"),
            (2, "", "compatforge-cli: invalid DOS header\n"),
            (1, "", "compatforge-cli: invalid PE signature\n"),
        ):
            with self.subTest(returncode=returncode, stdout=stdout, stderr=stderr):
                self.assertEqual(
                    acceptance._guest_negative_boundary(
                        candidate,
                        self.cli,
                        result(returncode, stdout, stderr),
                    ),
                    "negative-boundary-error-invalid",
                )

    def test_real_cli_rejects_the_isolated_mutated_pe_with_the_exact_diagnostic(self) -> None:
        configured = os.environ.get("COMPATFORGE_TEST_CLI")
        if not configured:
            self.skipTest("set COMPATFORGE_TEST_CLI to a built compatforge-cli")
        cli = Path(configured).resolve(strict=True)
        source = ROOT / "tests" / "fixtures" / "hello-x86_64.exe"
        mutant = self.external / "real-cli-mutant.exe"
        shutil.copyfile(source, mutant)
        payload = bytearray(mutant.read_bytes())
        payload[0] ^= 0xFF
        mutant.write_bytes(payload)

        actual = subprocess.run(
            [str(cli), "inspect", str(mutant)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=acceptance.DISCOVERY_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            (actual.returncode, actual.stdout, actual.stderr),
            (1, "", "compatforge-cli: invalid DOS header\n"),
        )
        self.assertIsNone(
            acceptance._guest_negative_boundary(mutant, cli, subprocess.run)
        )

    def test_wrong_negative_boundary_errors_are_closed_and_sequentially_isolated(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        runtime_calls = 0

        def invalid_runtime_boundary(_path: Path):
            nonlocal runtime_calls
            runtime_calls += 1
            if runtime_calls == 1:
                raise ValueError("wrong Runtime error")
            return ["not-a-closed-set"]

        def invalid_guest_boundary(
            _argv: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            raise OSError("wrong inspection error")

        class AssetError(Exception):
            pass

        class WrongAssetError(AssetError):
            pass

        def invalid_asset_boundary(_asset, _root: Path, _allow_network: bool) -> Path:
            raise WrongAssetError("cached 7zip digest mismatch")

        summary = acceptance.run_negative_checks(
            paths,
            descriptors,
            console_guest=guest,
            sentinel=sentinel,
            runtime_validator=invalid_runtime_boundary,
            guest_runner=invalid_guest_boundary,
            asset=asset,
            asset_fetcher=invalid_asset_boundary,
            asset_error=AssetError,
        )

        self.assertEqual(summary["status"], "failed")
        self.assertEqual(len(summary["cases"]), 4)
        self.assertEqual(
            {case["reasonCode"] for case in summary["cases"]},
            {"negative-boundary-error-invalid"},
        )

    def test_negative_sources_reject_symlinks_and_hardlinks_before_copying(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        guest_target = self.external / "guest-target.exe"
        guest_target.write_bytes(guest.read_bytes())
        guest.unlink()
        try:
            os.symlink(guest_target, guest)
        except OSError as error:
            self.skipTest(f"file symlinks are unavailable: {error}")
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        with self.assertRaisesRegex(acceptance.AcceptanceError, "unsafe path component"):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                asset=asset,
                asset_fetcher=lambda *_args: None,
                asset_error=RuntimeError,
            )
        self.assertEqual(list(self.work.iterdir()), [])
        self.assertEqual(guest_target.read_bytes(), b"MZ" + b"guest-fixture")

        guest.unlink()
        guest.write_bytes(b"MZ" + b"guest-fixture")
        hardlink = self.external / "guest-hardlink.exe"
        try:
            os.link(guest, hardlink)
        except OSError as error:
            self.skipTest(f"hardlinks are unavailable: {error}")
        with self.assertRaisesRegex(acceptance.AcceptanceError, "private bounded"):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                asset=asset,
                asset_fetcher=lambda *_args: None,
                asset_error=RuntimeError,
            )
        self.assertEqual(hardlink.read_bytes(), b"MZ" + b"guest-fixture")

    def test_negative_cleanup_refuses_case_directory_substitution(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        victim = self.external / "case-directory-victim"
        victim.mkdir()
        (victim / "sentinel").write_bytes(b"foreign-directory")

        def substitute_case(path: Path) -> set[str]:
            original_case = path.parent
            original_case.rename(original_case.with_name(original_case.name + "-owned"))
            try:
                os.symlink(victim, original_case, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks are unavailable: {error}")
            return set()

        with self.assertRaisesRegex(acceptance.CleanupError, "case root identity changed"):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                runtime_validator=substitute_case,
                guest_runner=lambda *_args, **_kwargs: None,
                asset=asset,
                asset_fetcher=lambda *_args: None,
                asset_error=RuntimeError,
            )
        self.assertEqual((victim / "sentinel").read_bytes(), b"foreign-directory")
        self.assertFalse((victim / "payload.bin").exists())

    def test_negative_cleanup_binds_negative_root_ancestor_identity(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        replacement_payload = b""

        def replace_negative_root(path: Path) -> set[str]:
            nonlocal replacement_payload
            replacement_payload = path.read_bytes()
            negative_root = path.parents[2]
            negative_root.rename(negative_root.with_name("negative-owned"))
            replacement = negative_root / "crossover" / "wine-bytes-changed"
            replacement.mkdir(parents=True)
            (replacement / "payload.bin").write_bytes(replacement_payload)
            return set()

        with self.assertRaisesRegex(
            acceptance.CleanupError, "negative root identity changed"
        ):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                runtime_validator=replace_negative_root,
                guest_runner=lambda *_args, **_kwargs: None,
                asset=asset,
                asset_fetcher=lambda *_args: None,
                asset_error=RuntimeError,
            )
        self.assertEqual(
            (
                self.work
                / "negative"
                / "crossover"
                / "wine-bytes-changed"
                / "payload.bin"
            ).read_bytes(),
            replacement_payload,
        )

    def test_negative_cleanup_binds_runtime_root_ancestor_identity(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        replacement_payload = b""

        def replace_runtime_root(path: Path) -> set[str]:
            nonlocal replacement_payload
            replacement_payload = path.read_bytes()
            runtime_root = path.parents[1]
            runtime_root.rename(runtime_root.with_name("crossover-owned"))
            replacement = runtime_root / "wine-bytes-changed"
            replacement.mkdir(parents=True)
            (replacement / "payload.bin").write_bytes(replacement_payload)
            return set()

        with self.assertRaisesRegex(
            acceptance.CleanupError, "negative Runtime root identity changed"
        ):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                runtime_validator=replace_runtime_root,
                guest_runner=lambda *_args, **_kwargs: None,
                asset=asset,
                asset_fetcher=lambda *_args: None,
                asset_error=RuntimeError,
            )
        self.assertEqual(
            (
                self.work
                / "negative"
                / "crossover"
                / "wine-bytes-changed"
                / "payload.bin"
            ).read_bytes(),
            replacement_payload,
        )

    def test_negative_cleanup_rejects_symlink_replacement_at_every_owned_directory(self) -> None:
        levels = (
            ("work-root", "work-root identity changed"),
            ("negative", "negative root identity changed"),
            ("runtime", "negative Runtime root identity changed"),
            ("case", "negative case root identity changed"),
        )
        for level, diagnostic in levels:
            with self.subTest(level=level), tempfile.TemporaryDirectory(
                prefix=f"compatforge-negative-chain-{level}-"
            ) as temporary:
                root = Path(temporary)
                work = root / "work"
                work.mkdir()
                work_node = acceptance._owned_directory(
                    work, "work-root", create=False
                )
                negative = acceptance._owned_directory(
                    work / "negative",
                    "negative root",
                    create=True,
                    parent=work_node,
                )
                runtime = acceptance._owned_directory(
                    negative.path / "crossover",
                    "negative Runtime root",
                    create=True,
                    parent=negative,
                )
                case = acceptance._owned_directory(
                    runtime.path / "wine-bytes-changed",
                    "negative case root",
                    create=True,
                    parent=runtime,
                )
                payload = acceptance._create_private_copy(case, b"mutant")
                selected = {
                    "work-root": work_node,
                    "negative": negative,
                    "runtime": runtime,
                    "case": case,
                }[level]
                moved = selected.path.with_name(selected.path.name + "-owned")
                selected.path.rename(moved)
                victim = root / f"{level}-foreign-victim"
                victim.mkdir()
                (victim / "sentinel").write_bytes(b"foreign-directory")
                try:
                    os.symlink(victim, selected.path, target_is_directory=True)
                except OSError as error:
                    self.skipTest(f"directory symlinks are unavailable: {error}")

                with self.assertRaisesRegex(acceptance.CleanupError, diagnostic):
                    acceptance._cleanup_owned_case(case, payload)
                self.assertEqual(
                    (victim / "sentinel").read_bytes(), b"foreign-directory"
                )
                self.assertFalse((victim / "payload.bin").exists())
                selected.path.unlink()

    def test_negative_cleanup_refuses_hardlink_file_substitution(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        victim = self.external / "cleanup-hardlink-victim"
        victim.write_bytes(b"foreign-file")

        def substitute_copy(path: Path) -> set[str]:
            path.unlink()
            try:
                os.link(victim, path)
            except OSError as error:
                self.skipTest(f"hardlinks are unavailable: {error}")
            return set()

        with self.assertRaisesRegex(acceptance.CleanupError, "copy identity changed"):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                runtime_validator=substitute_copy,
                guest_runner=lambda *_args, **_kwargs: None,
                asset=asset,
                asset_fetcher=lambda *_args: None,
                asset_error=RuntimeError,
            )
        self.assertEqual(victim.read_bytes(), b"foreign-file")

    def test_negative_check_detects_original_source_swap_during_validation(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        replacement = self.external / "replacement-guest.exe"
        replacement.write_bytes(guest.read_bytes())

        def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            guest.unlink()
            replacement.rename(guest)
            return subprocess.CompletedProcess(argv, 1, "", "invalid PE")

        class AssetError(Exception):
            pass

        def fetcher(_asset, cache_root: Path, _allow_network: bool) -> Path:
            candidate = cache_root / asset.filename
            if hashlib.sha256(candidate.read_bytes()).hexdigest() != asset.sha256:
                raise AssetError("cached 7zip digest mismatch")
            return candidate

        with self.assertRaisesRegex(acceptance.IntegrityError, "identity or digest changed"):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                runtime_validator=lambda _path: set(),
                guest_runner=runner,
                asset=asset,
                asset_fetcher=fetcher,
                asset_error=AssetError,
            )

    def test_negative_check_detects_external_sentinel_mutation(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )

        def mutate_sentinel(_path: Path) -> set[str]:
            sentinel.write_bytes(b"attacker-mutated-sentinel")
            return set()

        with self.assertRaisesRegex(acceptance.IntegrityError, "identity or digest changed"):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                runtime_validator=mutate_sentinel,
                guest_runner=lambda *_args, **_kwargs: None,
                asset=asset,
                asset_fetcher=lambda *_args: None,
                asset_error=RuntimeError,
            )

    def test_negative_case_cleanup_covers_mutation_and_preboundary_revalidation_failures(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        original_mutate = acceptance._mutate_owned_copy

        def mutate_then_fail(owned) -> None:
            original_mutate(owned)
            raise acceptance.AcceptanceError("injected mutation failure")

        with (
            mock.patch.object(
                acceptance, "_mutate_owned_copy", side_effect=mutate_then_fail
            ),
            self.assertRaisesRegex(
                acceptance.AcceptanceError, "injected mutation failure"
            ),
        ):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                runtime_validator=lambda _path: set(),
                guest_runner=lambda *_args, **_kwargs: None,
                asset=asset,
                asset_fetcher=lambda *_args: None,
                asset_error=RuntimeError,
            )
        failed_case = (
            self.work / "negative" / "crossover" / "wine-bytes-changed"
        )
        self.assertFalse(failed_case.exists())
        self.assertFalse(any(path.is_file() for path in self.work.rglob("*")))

    def test_negative_case_cleanup_covers_source_change_before_boundary(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        source = self.runtime_roots["crossover"] / "bin" / "wine"
        original_mutate = acceptance._mutate_owned_copy

        def mutate_then_change_source(owned) -> None:
            original_mutate(owned)
            changed = bytearray(source.read_bytes())
            changed[-1] ^= 0xFF
            source.write_bytes(changed)

        with (
            mock.patch.object(
                acceptance,
                "_mutate_owned_copy",
                side_effect=mutate_then_change_source,
            ),
            self.assertRaisesRegex(
                acceptance.IntegrityError, "identity or digest changed"
            ),
        ):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                runtime_validator=lambda _path: set(),
                guest_runner=lambda *_args, **_kwargs: None,
                asset=asset,
                asset_fetcher=lambda *_args: None,
                asset_error=RuntimeError,
            )
        self.assertFalse(
            (
                self.work
                / "negative"
                / "crossover"
                / "wine-bytes-changed"
            ).exists()
        )
        self.assertFalse(any(path.is_file() for path in self.work.rglob("*")))

    def test_partial_private_copy_failure_cleans_only_its_trusted_residue(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )

        def partial_write_then_fail(descriptor: int, payload: bytes) -> None:
            self.assertGreater(len(payload), 0)
            os.write(descriptor, payload[:1])
            raise OSError("injected partial copy failure")

        with (
            mock.patch.object(
                acceptance, "_write_all", side_effect=partial_write_then_fail
            ),
            self.assertRaisesRegex(
                acceptance.AcceptanceError,
                "negative copy could not be created safely",
            ),
        ):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                runtime_validator=lambda _path: set(),
                guest_runner=lambda *_args, **_kwargs: None,
                asset=asset,
                asset_fetcher=lambda *_args: None,
                asset_error=RuntimeError,
            )
        failed_case = (
            self.work / "negative" / "crossover" / "wine-bytes-changed"
        )
        self.assertFalse(failed_case.exists())
        self.assertFalse(any(path.is_file() for path in self.work.rglob("*")))

    @unittest.skipUnless(os.name == "posix", "open-file replacement requires POSIX")
    def test_partial_private_copy_failure_does_not_delete_a_foreign_replacement(self) -> None:
        guest, sentinel, asset = self._negative_fixture()
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        descriptors = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )
        payload_path = (
            self.work
            / "negative"
            / "crossover"
            / "wine-bytes-changed"
            / "payload.bin"
        )
        foreign_bytes = b"foreign replacement must survive"

        def replace_partial_copy_then_fail(descriptor: int, _payload: bytes) -> None:
            os.write(descriptor, b"x")
            payload_path.unlink()
            payload_path.write_bytes(foreign_bytes)
            raise OSError("injected replacement failure")

        with (
            mock.patch.object(
                acceptance,
                "_write_all",
                side_effect=replace_partial_copy_then_fail,
            ),
            self.assertRaises(acceptance.CleanupError),
        ):
            acceptance.run_negative_checks(
                paths,
                descriptors,
                console_guest=guest,
                sentinel=sentinel,
                runtime_validator=lambda _path: set(),
                guest_runner=lambda *_args, **_kwargs: None,
                asset=asset,
                asset_fetcher=lambda *_args: None,
                asset_error=RuntimeError,
            )
        self.assertEqual(payload_path.read_bytes(), foreign_bytes)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "mkfifo"),
        "FIFO open-bound regression requires POSIX",
    )
    def test_bounded_source_rejects_fifo_without_waiting_for_a_writer(self) -> None:
        fifo = self.external / "source-fifo"
        os.mkfifo(fifo)
        probe = """
import importlib.util
import pathlib
import sys
spec = importlib.util.spec_from_file_location("fifo_acceptance", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
try:
    module._read_bound_source(pathlib.Path(sys.argv[2]), "FIFO source")
except module.AcceptanceError:
    raise SystemExit(0)
raise SystemExit(1)
"""
        result = subprocess.run(
            [sys.executable, "-S", "-B", "-c", probe, str(ACCEPTANCE_TOOL), str(fifo)],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=2,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bounded_source_rejects_nonregular_entry_before_open(self) -> None:
        directory = self.external / "source-directory"
        directory.mkdir()
        with mock.patch.object(
            acceptance.os,
            "open",
            side_effect=AssertionError("nonregular source reached open"),
        ):
            with self.assertRaisesRegex(
                acceptance.AcceptanceError, "private bounded regular file"
            ):
                acceptance._read_bound_source(directory, "directory source")

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

    def test_negative_mode_is_explicit_closed_and_always_offline(self) -> None:
        guest, sentinel, _asset = self._negative_fixture()
        negative = self._arguments(
            "--negative-checks",
            "--console-guest",
            str(guest),
            "--negative-sentinel",
            str(sentinel),
        )
        self.assertTrue(negative.negative_checks)
        self.assertEqual(negative.console_guest, str(guest))
        self.assertEqual(negative.negative_sentinel, str(sentinel))
        for extra in (
            ("--negative-checks",),
            ("--negative-checks", "--console-guest", str(guest)),
            ("--console-guest", str(guest), "--negative-sentinel", str(sentinel)),
            (
                "--negative-checks",
                "--console-guest",
                str(guest),
                "--negative-sentinel",
                str(sentinel),
                "--allow-network",
            ),
        ):
            with self.subTest(extra=extra), self.assertRaises(acceptance.AcceptanceError):
                self._arguments(*extra)

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
        projections = [
            json.loads(
                (self.work / round_id / "round-projection.json").read_text(
                    encoding="utf-8"
                )
            )
            for round_id in ("round-1", "round-2")
        ]
        self.assertEqual(projections[0], projections[1])
        self.assertEqual(
            json.loads((self.work / "comparison.json").read_text(encoding="utf-8")),
            {"schemaVersion": "1", "roundsEqual": True, "status": "accepted"},
        )
        self.assertEqual(summary["status"], "accepted")
        for artifact in (
            self.work / "round-1" / "round-projection.json",
            self.work / "round-2" / "round-projection.json",
            self.work / "comparison.json",
        ):
            encoded_artifact = artifact.read_text(encoding="utf-8")
            self.assertNotIn(str(self.external), encoded_artifact)
            self.assertNotIn("requestId", encoded_artifact)
        self.assertEqual(
            source_snapshots,
            {path: path.read_bytes() for path in source_snapshots},
        )

    def test_round_mismatch_is_stage_failed_and_writes_unequal_closed_projections(self) -> None:
        def runner(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            if argv[-1] == "--all":
                payload = self._discovery()
            elif Path(argv[3]).name == "run_macos_headless_preview.py":
                pack_id = argv[argv.index("--pack-id") + 1]
                runtime_id = "crossover" if "crossover" in pack_id else "whisky"
                payload = self._console_summary(runtime_id)
            else:
                runtime_id = argv[argv.index("--runtime-id") + 1]
                payload = self._gui_summary(runtime_id)
                work_root = argv[argv.index("--work-root") + 1]
                if "round-2" in work_root and runtime_id == "whisky":
                    payload["applications"][2]["assetSha256"] = "e" * 64
            return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

        summary = acceptance.orchestrate(
            self._arguments(),
            runner=runner,
            launcher=lambda *_args, **_kwargs: FinishedDesktopProcess(),
            waiter=lambda _process, _timeout: 0,
            host_system="Darwin",
            host_machine="arm64",
            printer=lambda _line: None,
        )

        self.assertEqual(summary["status"], "failed")
        self.assertTrue(acceptance.aggregate_is_accepted(summary["rounds"]))
        self.assertEqual(
            json.loads((self.work / "comparison.json").read_text(encoding="utf-8")),
            {"schemaVersion": "1", "roundsEqual": False, "status": "failed"},
        )
        self.assertNotEqual(
            (self.work / "round-1" / "round-projection.json").read_bytes(),
            (self.work / "round-2" / "round-projection.json").read_bytes(),
        )

    def test_projection_and_comparison_outputs_reject_existing_links_without_overwrite(self) -> None:
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        acceptance._prepare_layout(paths)
        victim_one = self.external / "projection-link-victim"
        victim_two = self.external / "projection-hardlink-victim"
        victim_one.write_text("unchanged-one", encoding="utf-8")
        victim_two.write_text("unchanged-two", encoding="utf-8")
        try:
            os.symlink(victim_one, self.work / "round-1" / "round-projection.json")
        except OSError as error:
            self.skipTest(f"file symlinks are unavailable: {error}")
        try:
            os.link(victim_two, self.work / "round-2" / "round-projection.json")
        except OSError as error:
            self.skipTest(f"hardlinks are unavailable: {error}")
        (self.work / "comparison.json").write_text("foreign", encoding="utf-8")

        for target in (
            ("round-1", "round-projection.json"),
            ("round-2", "round-projection.json"),
            ("comparison.json",),
        ):
            with self.subTest(target=target), self.assertRaisesRegex(
                acceptance.AcceptanceError, "unsafe"
            ):
                acceptance._safe_create_output(paths, target, "{}", "closed output")
        self.assertEqual(victim_one.read_text(encoding="utf-8"), "unchanged-one")
        self.assertEqual(victim_two.read_text(encoding="utf-8"), "unchanged-two")
        self.assertEqual(
            (self.work / "comparison.json").read_text(encoding="utf-8"), "foreign"
        )

    def test_private_output_identity_binds_device_inode_kind_and_single_link(self) -> None:
        first = self.external / "identity-first"
        second = self.external / "identity-second"
        first.write_text("first", encoding="utf-8")
        second.write_text("second", encoding="utf-8")
        self.assertTrue(
            acceptance._same_private_output_identity(first.stat(), first.stat())
        )
        self.assertFalse(
            acceptance._same_private_output_identity(first.stat(), second.stat())
        )
        linked = self.external / "identity-linked"
        try:
            os.link(first, linked)
        except OSError as error:
            self.skipTest(f"hardlinks are unavailable: {error}")
        self.assertFalse(
            acceptance._same_private_output_identity(first.stat(), linked.stat())
        )

    @unittest.skipUnless(
        os.name == "posix", "output directory-entry race requires POSIX"
    )
    def test_post_write_entry_races_are_fatal_without_touching_replacements(self) -> None:
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        acceptance._prepare_layout(paths)
        original_write_all = acceptance._write_all

        for replacement in ("missing", "regular", "symlink", "hardlink"):
            with self.subTest(replacement=replacement):
                target = self.work / f"comparison-{replacement}.json"
                moved = self.work / f"comparison-{replacement}-moved.json"
                victim = self.external / f"comparison-{replacement}-victim"
                victim.write_text(f"unchanged-{replacement}", encoding="utf-8")

                def racing_write(file_descriptor: int, payload: bytes) -> None:
                    target.rename(moved)
                    if replacement == "regular":
                        target.write_text("attacker-regular", encoding="utf-8")
                    elif replacement == "symlink":
                        os.symlink(victim, target)
                    elif replacement == "hardlink":
                        os.link(victim, target)
                    original_write_all(file_descriptor, payload)

                with (
                    mock.patch.object(acceptance, "_write_all", side_effect=racing_write),
                    self.assertRaisesRegex(
                        acceptance.AcceptanceError, "output identity changed"
                    ),
                ):
                    acceptance._safe_create_output(
                        paths,
                        (target.name,),
                        '{"closed":true}',
                        "comparison output",
                    )
                self.assertTrue(moved.is_file())
                self.assertEqual(
                    moved.read_text(encoding="utf-8"), '{"closed":true}\n'
                )
                self.assertEqual(
                    victim.read_text(encoding="utf-8"), f"unchanged-{replacement}"
                )
                if replacement == "missing":
                    self.assertFalse(target.exists())
                elif replacement == "regular":
                    self.assertEqual(target.read_text(encoding="utf-8"), "attacker-regular")

    def test_round_projection_revalidates_its_bound_directory_before_writing(self) -> None:
        paths = acceptance.preflight(
            self._arguments(), host_system="Darwin", host_machine="arm64"
        )
        acceptance._prepare_layout(paths)
        original = self.work / "round-1-original"
        victim = self.external / "round-projection-directory-victim"
        victim.mkdir()
        (victim / "sentinel").write_text("unchanged", encoding="utf-8")
        (self.work / "round-1").rename(original)
        try:
            os.symlink(victim, self.work / "round-1", target_is_directory=True)
        except OSError as error:
            self.skipTest(f"directory symlinks are unavailable: {error}")

        with self.assertRaisesRegex(
            acceptance.AcceptanceError, "(?:identity changed|unsafe)"
        ):
            acceptance._safe_create_output(
                paths,
                ("round-1", "round-projection.json"),
                "{}",
                "round projection output",
            )
        self.assertEqual((victim / "sentinel").read_text(encoding="utf-8"), "unchanged")
        self.assertFalse((victim / "round-projection.json").exists())

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

            activated = self._gui_summary(runtime_id)
            activated["receipt"]["activated"] = True
            with self.subTest(runtime_id=runtime_id, case="activated-optional-true"):
                acceptance._project_gui(activated, descriptor)

    def test_real_provider_receipt_shape_projects_through_gui_compact_summary(self) -> None:
        runtime_id = "crossover"
        provider_receipt: dict[str, object] = {
            "schemaVersion": "1",
            "source": "explicit-override",
            "version": "24.0",
            "architecture": "x86_64",
            "packId": "wine-macos-auto-preview",
            "packDigest": "sha256:" + "c" * 64,
            "capabilities": [
                "guest-i386",
                "guest-x86_64",
                "new-wow64",
                "windows-gui",
            ],
        }
        full_applications = self._gui_summary(runtime_id)["applications"]
        for application in full_applications:
            application["windows"] = {
                "available": application.pop("windowAvailable")
            }
            application["screenshot"] = {
                "available": application.pop("screenshotAvailable")
            }
        gui_baseline.bind_runtime_identity(
            runtime_id, provider_receipt, full_applications
        )
        compact = gui_baseline.compact_summary(provider_receipt, full_applications)
        self.assertEqual(
            set(compact["receipt"]),
            {"schemaVersion", "runtimeId", "packId", "version", "packDigest", "source"},
        )
        descriptor = acceptance.parse_discovery(
            json.dumps(self._discovery()), self._arguments()
        )[0]
        receipt, applications = acceptance._project_gui(compact, descriptor)
        self.assertEqual(receipt["runtimeVersion"], "24.0")
        self.assertTrue(
            all(application["status"] == "accepted" for application in applications)
        )

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
