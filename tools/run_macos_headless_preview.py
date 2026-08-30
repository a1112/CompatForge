#!/usr/bin/env python3
"""Run the Apple Silicon local Wine Console PE preview acceptance."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Callable, Sequence

from discover_macos_wine import DiscoveryError, discover

ROOT = Path(__file__).resolve().parents[1]
REGISTER = ROOT / "tools" / "register_macos_local_wine.py"
PROBE_SOURCE = ROOT / "tests" / "fixtures" / "windows_console_smoke.c"
SUCCESS_MARKER = "COMPATFORGE_WINDOWS_CONSOLE_OK"
COMMAND_TIMEOUT_SECONDS = 120


class AcceptanceError(Exception):
    pass


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--compatforge-cli", required=True)
    value.add_argument("--cc", required=True)
    value.add_argument("--wine-root")
    value.add_argument("--wine")
    value.add_argument("--wineserver")
    value.add_argument("--runtime-store", required=True)
    value.add_argument("--storage-root", required=True)
    value.add_argument("--work-root", required=True)
    value.add_argument("--pack-id", default="wine-macos-auto-preview")
    value.add_argument("--version")
    return value


def absolute(value: str, field: str, *, must_exist: bool) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise AcceptanceError(f"{field} must be absolute")
    try:
        return path.resolve(strict=must_exist)
    except OSError as error:
        raise AcceptanceError(f"invalid {field}") from error


def portable(value: str, field: str) -> PurePosixPath:
    if not value or value.startswith("/") or "\\" in value or ":" in value:
        raise AcceptanceError(f"invalid {field}")
    path = PurePosixPath(value)
    if any(part in ("", ".", "..") for part in path.parts):
        raise AcceptanceError(f"invalid {field}")
    return path


def overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def executable(path: Path, field: str) -> None:
    if path.is_symlink() or not path.is_file() or os.access(path, os.X_OK) is False:
        raise AcceptanceError(f"invalid {field}")


def validate(
    arguments: argparse.Namespace,
    host_system: str,
    host_machine: str,
    *,
    require_runtime: bool = True,
) -> dict[str, object]:
    if host_system != "Darwin" or host_machine != "arm64":
        raise AcceptanceError("host must be Darwin/arm64")
    cli = absolute(arguments.compatforge_cli, "compatforge-cli", must_exist=True)
    cc = absolute(arguments.cc, "cc", must_exist=True)
    wine_root = absolute(arguments.wine_root, "wine-root", must_exist=True) if require_runtime else None
    runtime_store = absolute(arguments.runtime_store, "runtime-store", must_exist=False)
    storage_root = absolute(arguments.storage_root, "storage-root", must_exist=False)
    work_root = absolute(arguments.work_root, "work-root", must_exist=True)
    wine_relative = portable(arguments.wine, "wine") if require_runtime else None
    wineserver_relative = portable(arguments.wineserver, "wineserver") if require_runtime else None
    executable(cli, "compatforge-cli")
    executable(cc, "cc")
    if require_runtime and (not isinstance(wine_root, Path) or not wine_root.is_dir()):
        raise AcceptanceError("wine-root must be a directory")
    if not work_root.is_dir() or any(work_root.iterdir()):
        raise AcceptanceError("empty work-root must be a directory")
    if require_runtime:
        assert isinstance(wine_root, Path)
        assert wine_relative is not None and wineserver_relative is not None
        wine = wine_root.joinpath(*wine_relative.parts)
        wineserver = wine_root.joinpath(*wineserver_relative.parts)
        executable(wine, "wine")
        executable(wineserver, "wineserver")
    protected = [ROOT.resolve(), runtime_store, storage_root]
    if isinstance(wine_root, Path):
        protected.append(wine_root)
    if any(overlaps(work_root, path) for path in protected):
        raise AcceptanceError("work-root overlaps a protected root")
    if overlaps(runtime_store, storage_root) or any(
        overlaps(store, path)
        for store in (runtime_store, storage_root)
        for path in ([ROOT.resolve(), wine_root] if isinstance(wine_root, Path) else [ROOT.resolve()])
    ):
        raise AcceptanceError("store roots overlap")
    if require_runtime and (not arguments.pack_id or not arguments.version):
        raise AcceptanceError("pack-id and version are required")
    return {
        "cli": cli,
        "cc": cc,
        "wineRoot": wine_root,
        "wine": wine_relative,
        "wineserver": wineserver_relative,
        "runtimeStore": runtime_store,
        "storageRoot": storage_root,
        "workRoot": work_root,
    }


def resolve_wine(arguments: argparse.Namespace, runner: Runner = subprocess.run) -> argparse.Namespace:
    explicit = [arguments.wine_root, arguments.wine, arguments.wineserver, arguments.version]
    if any(explicit) and not all(explicit):
        raise AcceptanceError("wine-root, wine, wineserver and version must be provided together")
    if all(explicit):
        arguments.wine_source = "explicit"
        return arguments
    try:
        selected = discover(runner=runner)
    except DiscoveryError as error:
        raise AcceptanceError(str(error)) from error
    arguments.wine_root = selected["materializedRoot"]
    arguments.wine = selected["wine"]
    arguments.wineserver = selected["wineserver"]
    arguments.version = selected["version"]
    arguments.wine_source = selected["source"]
    return arguments


Runner = Callable[..., subprocess.CompletedProcess[str]]


def invoke(arguments: Sequence[str], runner: Runner = subprocess.run) -> subprocess.CompletedProcess[str]:
    result = runner(
        list(arguments),
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise AcceptanceError(f"command failed: {Path(arguments[0]).name}")
    return result


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def parse_json(result: subprocess.CompletedProcess[str], field: str) -> dict[str, object]:
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AcceptanceError(f"invalid {field} JSON") from error
    if not isinstance(value, dict):
        raise AcceptanceError(f"invalid {field} object")
    return value


def run(arguments: argparse.Namespace, runner: Runner = subprocess.run) -> dict[str, object]:
    explicit_runtime = (
        arguments.wine_root,
        arguments.wine,
        arguments.wineserver,
        arguments.version,
    )
    if any(explicit_runtime):
        arguments = resolve_wine(arguments, runner)
        use_rust_bootstrap = False
        paths = validate(arguments, platform.system(), platform.machine())
    elif runner is subprocess.run:
        use_rust_bootstrap = True
        paths = validate(arguments, platform.system(), platform.machine(), require_runtime=False)
    else:
        use_rust_bootstrap = False
        arguments = resolve_wine(arguments, runner)
        paths = validate(arguments, platform.system(), platform.machine())
    cli = str(paths["cli"])
    work_root = paths["workRoot"]
    assert isinstance(work_root, Path)
    probe = work_root / "windows-console-smoke.exe"
    invoke(
        [
            str(paths["cc"]),
            "-Os",
            "-s",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wl,--no-insert-timestamp",
            str(PROBE_SOURCE),
            "-o",
            str(probe),
        ],
        runner,
    )
    if not probe.is_file() or probe.parent != work_root:
        raise AcceptanceError("compiler did not create the owned probe")

    inspection = parse_json(invoke([cli, "inspect", str(probe)], runner), "inspection")
    if (
        inspection.get("architecture") != "x86_64"
        or inspection.get("subsystem") != "windowsConsole"
        or inspection.get("imageKind") != "executable"
    ):
        raise AcceptanceError("probe is not an x86_64 Windows Console executable")
    write_json(work_root / "inspection.json", inspection)

    context_path = work_root / "context.json"
    if use_rust_bootstrap:
        bootstrap_request_path = work_root / "bootstrap-request.json"
        write_json(
            bootstrap_request_path,
            {
                "schemaVersion": "1",
                "runtimeStoreRoot": str(paths["runtimeStore"]),
                "storageRoot": str(paths["storageRoot"]),
            },
        )
        receipt = parse_json(
            invoke([cli, "local", "macos", "context", str(bootstrap_request_path), str(context_path)], runner),
            "bootstrap receipt",
        )
        pack_digest = receipt.get("packDigest")
        pack_id = receipt.get("packId")
        pack_version = receipt.get("version")
        runtime_source = receipt.get("source")
        if not all(isinstance(value, str) and value for value in (pack_digest, pack_id, pack_version, runtime_source)):
            raise AcceptanceError("bootstrap receipt omitted Runtime identity")
        context = parse_json(
            subprocess.CompletedProcess(
                [str(context_path)], 0, context_path.read_text(encoding="utf-8"), ""
            ),
            "context",
        )
        capabilities = {
            "runtimeProviders": [{"kind": "wine", "available": True}],
            "translators": [{"kind": "rosetta", "available": True}],
            "graphicsBackends": [{"kind": "wined3d", "available": True}],
        }
        arguments.pack_id = pack_id
        arguments.version = pack_version
        arguments.wine_source = runtime_source
        write_json(work_root / "bootstrap-receipt.json", receipt)
    else:
        registration_root = work_root / "registration"
        registration = parse_json(
            invoke(
                [
                    sys.executable,
                    "-S",
                    "-B",
                    str(REGISTER),
                    "--output-root",
                    str(registration_root),
                    "--runtime-store-root",
                    str(paths["runtimeStore"]),
                    "--materialized-root",
                    str(paths["wineRoot"]),
                    "--wine",
                    str(paths["wine"]),
                    "--wineserver",
                    str(paths["wineserver"]),
                    "--pack-id",
                    arguments.pack_id,
                    "--version",
                    arguments.version,
                ],
                runner,
            ),
            "registration",
        )
        pack_digest = registration.get("packDigest")
        if not isinstance(pack_digest, str):
            raise AcceptanceError("registration omitted pack digest")

        install = parse_json(
            invoke(
                [cli, "runtime", "install", str(paths["runtimeStore"]), str(registration_root / "bundle"), "manifest.json"],
                runner,
            ),
            "install receipt",
        )
        verify = parse_json(
            invoke([cli, "runtime", "verify", str(paths["runtimeStore"]), pack_digest], runner),
            "verify receipt",
        )
        if install.get("digest") != pack_digest or verify.get("digest") != pack_digest:
            raise AcceptanceError("Runtime receipt digest mismatch")
        write_json(work_root / "runtime-install.json", install)
        write_json(work_root / "runtime-verify.json", verify)

        provider_path = registration_root / "provider.json"
        capabilities = parse_json(invoke([cli, "provider", "macos", "probe", str(provider_path)], runner), "capabilities")
        context = parse_json(
            invoke([cli, "provider", "macos", "context", str(provider_path), str(paths["storageRoot"])], runner),
            "context",
        )
    supervisor = context.get("supervisor")
    if not isinstance(supervisor, dict):
        raise AcceptanceError("context omitted supervisor policy")
    supervisor["maximumRuntimeMilliseconds"] = 60_000
    write_json(work_root / "capabilities.json", capabilities)
    write_json(context_path, context)

    file_digest = inspection.get("fileDigest")
    if not isinstance(file_digest, str) or not file_digest.startswith("sha256:"):
        raise AcceptanceError("inspection omitted guest digest")
    request = {
        "schemaVersion": "1",
        "requestId": "018fe3cb-9d12-7b52-b334-1cce0e857fc9",
        "bottleId": "macos-headless-preview",
        "executable": {"path": str(probe), "architecture": "x86_64", "sha256": file_digest[7:]},
        "arguments": [],
        "environment": {},
        "constraints": {
            "allowVirtualMachine": False,
            "allowRemote": False,
            "requiresKernelDriver": False,
            "requiresDirectX12": False,
            "networkPolicy": "deny",
            "requiredCapabilities": [],
        },
    }
    request_path = work_root / "launch-request.json"
    write_json(request_path, request)
    plan = parse_json(invoke([cli, "prepared-plan", str(context_path), str(probe), str(request_path)], runner), "plan")
    write_json(work_root / "prepared-launch-plan.json", plan)
    event_result = invoke([cli, "prepared-launch", str(context_path), str(probe), str(request_path)], runner)
    try:
        events = [json.loads(line) for line in event_result.stdout.splitlines() if line]
    except json.JSONDecodeError as error:
        raise AcceptanceError("invalid RuntimeEvent JSONL") from error
    if not events or not all(isinstance(event, dict) for event in events):
        raise AcceptanceError("empty RuntimeEvent stream")
    (work_root / "runtime-events.jsonl").write_text(
        "".join(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n" for event in events),
        encoding="utf-8",
    )

    runtime_available = any(
        provider.get("kind") == "wine" and provider.get("available") is True
        for provider in capabilities.get("runtimeProviders", [])
    )
    rosetta_available = any(
        provider.get("kind") == "rosetta" and provider.get("available") is True
        for provider in capabilities.get("translators", [])
    )
    wined3d_available = any(
        provider.get("kind") == "wined3d" and provider.get("available") is True
        for provider in capabilities.get("graphicsBackends", [])
    )
    sequences = [event.get("sequence") for event in events]
    kinds = [event.get("kind") for event in events]
    output_lines = [
        line
        for event in events
        if event.get("kind") == "output" and event.get("output", {}).get("stream") == "stdout"
        for line in event.get("output", {}).get("text", "").splitlines()
    ]
    exit_event = next((event for event in reversed(events) if event.get("kind") == "exited"), None)
    guest = plan.get("guestArtifact", {})
    if not (
        runtime_available
        and rosetta_available
        and wined3d_available
        and plan.get("runtime", {}).get("packDigest") == pack_digest
        and guest.get("digest") == file_digest
        and plan.get("translator", {}).get("provider") == "rosetta"
        and plan.get("graphics", {}).get("backend") == "wined3d"
        and all(isinstance(sequence, int) for sequence in sequences)
        and all(left < right for left, right in zip(sequences, sequences[1:]))
        and kinds[0] == "started"
        and output_lines.count(SUCCESS_MARKER) == 1
        and exit_event is not None
        and exit_event.get("exit", {}).get("success") is True
        and exit_event.get("exit", {}).get("code") == 0
    ):
        raise AcceptanceError("preview evidence did not satisfy the acceptance contract")

    summary = {
        "schemaVersion": "1",
        "packId": arguments.pack_id,
        "packVersion": arguments.version,
        "packDigest": pack_digest,
        "guestDigest": file_digest,
        "hostArchitecture": "arm64",
        "runtime": "wine",
        "runtimeSource": arguments.wine_source,
        "translator": "rosetta",
        "graphics": "wined3d",
        "eventKinds": kinds,
        "exitCode": 0,
        "success": True,
    }
    write_json(work_root / "summary.json", summary)
    return summary


def main() -> int:
    try:
        summary = run(parser().parse_args())
    except (AcceptanceError, OSError, subprocess.TimeoutExpired) as error:
        print(f"compatforge-preview: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
