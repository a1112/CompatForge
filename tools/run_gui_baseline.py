#!/usr/bin/env python3
"""Opt-in macOS GUI acceptance for the fixed CompatForge baseline apps.

This script intentionally uses only ``accepted``, ``failed``, ``unverified``
or ``blocked`` per application. A visible process or a blank window is never
promoted to an acceptance claim. Downloads, screenshots and evidence live in
caller-owned external directories and are excluded from the repository.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import selectors
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path, PurePosixPath, PureWindowsPath

ROOT = Path(__file__).resolve().parents[1]
DOWNLOAD = ROOT / "tools" / "download_gui_assets.py"
MAX_COMMAND_SECONDS = 180
WINDOW_APPEARANCE_SECONDS = 30
INTERACTIVE_RUNTIME_MILLISECONDS = 60_000

REQUIRED_INTERACTIONS = {
    "7zip": ("fileList", "menus"),
    "sumatrapdf": ("mainWindow", "openDialog"),
    "notepad-plus-plus": ("open", "edit", "saveUtf8Chinese", "rereadMatches"),
}

RUNTIME_IDS = ("crossover", "whisky")
STATUSES = ("accepted", "failed", "unverified", "blocked")
FAILURE_CLASSES = ("environment", "runtime", "core", "desktop", "application", "cleanup")
FAILURE_CLASS_BY_REASON_CODE = {
    "platform-unsupported": "environment",
    "tool-unavailable": "environment",
    "network-unavailable": "environment",
    "asset-fetch-failed": "environment",
    "runtime-descriptor-invalid": "runtime",
    "runtime-start-failed": "runtime",
    "runtime-version-invalid": "runtime",
    "core-snapshot-failed": "core",
    "core-plan-failed": "core",
    "core-import-failed": "core",
    "core-inspection-failed": "core",
    "core-launch-failed": "core",
    "core-verification-failed": "core",
    "core-rollback-failed": "core",
    "desktop-launch-failed": "desktop",
    "desktop-window-unobserved": "desktop",
    "application-install-failed": "application",
    "application-interaction-unverified": "application",
    "application-content-unverified": "application",
    "cleanup-residual-processes": "cleanup",
    "cleanup-delete-failed": "cleanup",
}
FAILURE_REASON_BY_STAGE = {
    "preflight-platform": "platform-unsupported",
    "preflight-tool": "tool-unavailable",
    "preflight-network": "network-unavailable",
    "asset-fetch": "asset-fetch-failed",
    "runtime-descriptor": "runtime-descriptor-invalid",
    "runtime-start": "runtime-start-failed",
    "runtime-version": "runtime-version-invalid",
    "core-snapshot": "core-snapshot-failed",
    "core-plan": "core-plan-failed",
    "core-import": "core-import-failed",
    "core-inspection": "core-inspection-failed",
    "core-launch": "core-launch-failed",
    "core-verification": "core-verification-failed",
    "core-rollback": "core-rollback-failed",
    "desktop-launch": "desktop-launch-failed",
    "desktop-window": "desktop-window-unobserved",
    "installer-launch": "application-install-failed",
    "application-interaction": "application-interaction-unverified",
    "application-content": "application-content-unverified",
    "cleanup-residual": "cleanup-residual-processes",
    "cleanup-delete": "cleanup-delete-failed",
}


class AcceptanceError(Exception):
    pass


class UniqueValueAction(argparse.Action):
    """Reject repeated identity arguments instead of accepting the last value."""

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string or self.dest} may be provided only once")
        setattr(namespace, self.dest, values)


def absolute(value: str, field: str, *, external: bool = False) -> Path:
    path = Path(value)
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts):
        raise AcceptanceError(f"{field} must be an absolute non-traversing path")
    if external and (path == ROOT or ROOT in path.parents):
        raise AcceptanceError(f"{field} must be outside the repository")
    return path


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    value.add_argument("--compatforge-cli", required=True)
    value.add_argument("--cache-root", required=True)
    value.add_argument("--runtime-store", required=True)
    value.add_argument("--storage-root", required=True)
    value.add_argument("--work-root", required=True)
    value.add_argument("--allow-network", action="store_true")
    value.add_argument("--runtime-id", choices=RUNTIME_IDS, action=UniqueValueAction)
    value.add_argument("--wine-root", action=UniqueValueAction)
    value.add_argument("--wine", action=UniqueValueAction)
    value.add_argument("--wineserver", action=UniqueValueAction)
    value.add_argument("--version", action=UniqueValueAction)
    value.add_argument(
        "--accept-interactive",
        action="store_true",
        help="promote non-empty window/screenshot evidence after manual GUI behavior checks",
    )
    value.add_argument(
        "--interaction-evidence",
        help="absolute JSON record of the required per-application manual checks",
    )
    return value


def validate_runtime_selection(arguments: argparse.Namespace) -> str | None:
    explicit = [arguments.wine_root, arguments.wine, arguments.wineserver, arguments.version]
    if any(explicit) and not all(explicit):
        raise AcceptanceError("wine-root, wine, wineserver and version must be provided together")
    if all(explicit) and arguments.runtime_id is None:
        raise AcceptanceError("--runtime-id is required with an explicit Runtime quartet")
    if arguments.runtime_id is not None and not all(explicit):
        raise AcceptanceError("--runtime-id requires an explicit Runtime quartet")
    return arguments.runtime_id


def failure_class(reason_code: str) -> str:
    try:
        return FAILURE_CLASS_BY_REASON_CODE[reason_code]
    except KeyError as error:
        raise AcceptanceError("failure reason code is not recognized") from error


def failure_reason(stage: str) -> str:
    try:
        return FAILURE_REASON_BY_STAGE[stage]
    except KeyError as error:
        raise AcceptanceError("failure stage is not recognized") from error


def set_application_outcome(
    evidence: dict[str, object],
    status_value: str,
    reason_code: str | None = None,
    *,
    diagnostic: str | None = None,
) -> None:
    if status_value not in STATUSES:
        raise AcceptanceError("application status is not recognized")
    evidence["status"] = status_value
    if status_value == "accepted":
        evidence.pop("failureClass", None)
        evidence.pop("reasonCode", None)
        evidence.pop("reason", None)
        return
    if reason_code is None:
        raise AcceptanceError("non-accepted application status requires a reason code")
    evidence["reasonCode"] = reason_code
    evidence["failureClass"] = failure_class(reason_code)
    if diagnostic is not None:
        evidence["reason"] = diagnostic


def bind_runtime_identity(
    runtime_id: str | None,
    receipt: dict[str, object],
    applications: list[dict[str, object]],
) -> None:
    if runtime_id is not None and runtime_id not in RUNTIME_IDS:
        raise AcceptanceError("Runtime identity is not recognized")
    receipt["runtimeId"] = runtime_id
    for application in applications:
        application["runtimeId"] = runtime_id


def _compact_exit(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    return {
        "present": value.get("present") is True,
        "code": value.get("code") if isinstance(value.get("code"), int) else None,
        "success": value.get("success") is True,
    }


def _reject_absolute_paths(value: object) -> None:
    if isinstance(value, str):
        if PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute():
            raise AcceptanceError("compact summary contains an absolute path")
        return
    if isinstance(value, dict):
        for nested in value.values():
            _reject_absolute_paths(nested)
        return
    if isinstance(value, list):
        for nested in value:
            _reject_absolute_paths(nested)


def compact_summary(
    receipt: dict[str, object],
    applications: list[dict[str, object]],
) -> dict[str, object]:
    runtime_id = receipt.get("runtimeId")
    if runtime_id is not None and runtime_id not in RUNTIME_IDS:
        raise AcceptanceError("receipt Runtime identity is not recognized")
    compact_receipt = {
        key: receipt[key]
        for key in ("schemaVersion", "runtimeId", "packId", "version", "packDigest", "source", "activated")
        if key in receipt
    }
    compact_applications: list[dict[str, object]] = []
    for application in applications:
        if application.get("runtimeId") != runtime_id:
            raise AcceptanceError("receipt and application Runtime identities differ")
        status_value = application.get("status")
        if status_value not in STATUSES:
            raise AcceptanceError("application status is not recognized")
        projected = {
            key: application[key]
            for key in ("schemaVersion", "runtimeId", "appId", "assetSha256", "status", "cleanup")
            if key in application
        }
        if status_value == "accepted":
            if "failureClass" in application or "reasonCode" in application:
                raise AcceptanceError("accepted application includes failure metadata")
        else:
            reason_code = application.get("reasonCode")
            class_value = application.get("failureClass")
            if not isinstance(reason_code, str) or class_value != failure_class(reason_code):
                raise AcceptanceError("application failure metadata is invalid")
            projected["failureClass"] = class_value
            projected["reasonCode"] = reason_code
        interactions = application.get("interactionChecks")
        required_interactions = REQUIRED_INTERACTIONS.get(application.get("appId"))
        if isinstance(interactions, dict) and required_interactions is not None:
            projected["interactionChecks"] = {
                name: interactions.get(name) is True for name in required_interactions
            }
        for source_key, target_key in (("installerExit", "installerExit"), ("exit", "exit")):
            compact_exit = _compact_exit(application.get(source_key))
            if compact_exit is not None:
                projected[target_key] = compact_exit
        windows = application.get("windows")
        if isinstance(windows, dict):
            projected["windowAvailable"] = windows.get("available") is True
        screenshot_value = application.get("screenshot")
        if isinstance(screenshot_value, dict):
            projected["screenshotAvailable"] = screenshot_value.get("available") is True
        compact_applications.append(projected)
    summary = {"schemaVersion": "1", "receipt": compact_receipt, "applications": compact_applications}
    _reject_absolute_paths(summary)
    return summary


def compact_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def invoke(argv: list[str], *, timeout: int = MAX_COMMAND_SECONDS) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise AcceptanceError(f"command failed: {Path(argv[0]).name} {' '.join(argv[1:3])}")
    return result


def json_object(result: subprocess.CompletedProcess[str], label: str) -> dict[str, object]:
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AcceptanceError(f"{label} did not return JSON") from error
    if not isinstance(value, dict):
        raise AcceptanceError(f"{label} did not return an object")
    return value


def run_events(result: subprocess.CompletedProcess[str], label: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for line in result.stdout.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise AcceptanceError(f"{label} emitted invalid RuntimeEvent JSON") from error
        if not isinstance(value, dict):
            raise AcceptanceError(f"{label} emitted a non-object RuntimeEvent")
        events.append(value)
    if not events:
        raise AcceptanceError(f"{label} emitted no RuntimeEvent")
    return events


def exit_observation(events: list[dict[str, object]]) -> dict[str, object]:
    """Return the terminal exit evidence in a stable, compact projection."""
    event = next((value for value in reversed(events) if value.get("kind") == "exited"), None)
    if event is None:
        return {"present": False}
    exit_value = event.get("exit")
    if not isinstance(exit_value, dict):
        return {"present": False}
    return {
        "present": True,
        "code": exit_value.get("code"),
        "success": exit_value.get("success") is True,
    }


def process_table() -> list[tuple[int, int, str]]:
    """Return a bounded macOS process table projection without shelling out."""
    if platform.system() != "Darwin":
        return []
    try:
        result = subprocess.run(
            ["/bin/ps", "-axo", "pid=,pgid=,command="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    rows: list[tuple[int, int, str]] = []
    for line in result.stdout.splitlines():
        parts = line.strip().split(maxsplit=2)
        if len(parts) != 3:
            continue
        try:
            rows.append((int(parts[0]), int(parts[1]), parts[2]))
        except ValueError:
            continue
    return rows


def process_snapshot(marker: str, process_group_id: int | None = None) -> list[str]:
    """List residual commands tied to either the Bottle path or launch group."""
    current = os.getpid()
    rows = process_table()
    if not rows:
        return ["process observation unavailable"]
    return [
        f"{pid} {command}"
        for pid, pgid, command in rows
        if pid != current and (marker in command or (process_group_id is not None and pgid == process_group_id))
    ]


def process_group_ids(process_group_id: int) -> list[int]:
    return [pid for pid, pgid, _command in process_table() if pgid == process_group_id]


def matching_windows(output: str, title_tokens: tuple[str, ...]) -> list[dict[str, object]]:
    matching: list[dict[str, object]] = []
    for line in output.splitlines():
        parts = line.strip().split("|", 2)
        if len(parts) != 3 or not any(token.casefold() in parts[1].casefold() for token in title_tokens):
            continue
        dimensions = parts[2].split("x", 1)
        try:
            process_id = int(parts[0])
            width = int(dimensions[0])
            height = int(dimensions[1])
        except (ValueError, IndexError):
            continue
        if width <= 0 or height <= 0:
            continue
        matching.append({"processId": process_id, "title": parts[1], "width": width, "height": height})
    return matching


def parse_event_line(line: str, label: str) -> dict[str, object]:
    try:
        value = json.loads(line)
    except json.JSONDecodeError as error:
        raise AcceptanceError(f"{label} emitted invalid RuntimeEvent JSON") from error
    if not isinstance(value, dict):
        raise AcceptanceError(f"{label} emitted a non-object RuntimeEvent")
    return value


def observed_launch(
    argv: list[str],
    screenshot_path: Path,
    title_tokens: tuple[str, ...],
    *,
    timeout: int = MAX_COMMAND_SECONDS,
) -> tuple[list[dict[str, object]], dict[str, object], dict[str, object], int | None]:
    """Keep the Core launch process alive while collecting visual evidence."""
    process = subprocess.Popen(
        argv,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
    )
    if process.stdout is None or process.stderr is None:
        process.kill()
        raise AcceptanceError("GUI launch pipes were not created")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    started = time.monotonic()
    windows: dict[str, object] = {"available": False, "reason": "observation pending"}
    shot: dict[str, object] = {"available": False, "path": str(screenshot_path)}
    events: list[dict[str, object]] = []
    root_process_id: int | None = None
    next_observation = started
    while process.poll() is None:
        elapsed = time.monotonic() - started
        for key, _mask in selector.select(timeout=0.1):
            line = key.fileobj.readline()
            if not line:
                continue
            event = parse_event_line(line, "GUI launch")
            events.append(event)
            if event.get("kind") == "started" and isinstance(event.get("processId"), int):
                root_process_id = event["processId"]
        now = time.monotonic()
        if (
            root_process_id is not None
            and not windows.get("available")
            and elapsed <= WINDOW_APPEARANCE_SECONDS
            and now >= next_observation
        ):
            windows = observer(root_process_id, title_tokens)
            if windows.get("available") is True:
                shot = screenshot(screenshot_path)
            next_observation = now + 0.5
        if elapsed >= timeout:
            process.kill()
            process.wait(timeout=10)
            raise AcceptanceError("GUI launch exceeded the bounded observation timeout")
        time.sleep(0.1)
    selector.unregister(process.stdout)
    selector.close()
    for line in process.stdout.read().splitlines():
        if line.strip():
            events.append(parse_event_line(line, "GUI launch"))
    stderr = process.stderr.read()
    process.wait(timeout=10)
    if process.returncode != 0:
        detail = stderr.strip().splitlines()[-1] if stderr.strip() else "no stderr"
        raise AcceptanceError(f"GUI launch failed: {detail}")
    if not events:
        raise AcceptanceError("GUI launch emitted no RuntimeEvent")
    return events, windows, shot, root_process_id


def status(events: list[dict[str, object]]) -> str:
    exit_event = next((event for event in reversed(events) if event.get("kind") == "exited"), None)
    if exit_event is None:
        return "failed"
    exit_value = exit_event.get("exit")
    if isinstance(exit_value, dict) and exit_value.get("success") is True:
        return "accepted"
    if any(event.get("kind") == "terminate-requested" for event in events):
        return "accepted"
    if not isinstance(exit_value, dict):
        return "failed"
    return "failed"


def observer(process_group_id: int, title_tokens: tuple[str, ...]) -> dict[str, object]:
    if platform.system() != "Darwin":
        return {"available": False, "reason": "window observation requires macOS"}
    target_ids = process_group_ids(process_group_id)
    if not target_ids:
        return {"available": False, "reason": "launch process group is no longer visible", "processGroupId": process_group_id}
    ids = ",".join(str(value) for value in target_ids)
    script = (
        'tell application "System Events"\n'
        "set resultText to {}\n"
        f"set targetIds to {{{ids}}}\n"
        "repeat with p in (every process whose background only is false)\n"
        "if targetIds contains (unix id of p) then\n"
        "repeat with w in (every window of p)\n"
        "set t to title of w\n"
        "set windowSize to size of w\n"
        "if t is not missing value and t is not \"\" then set end of resultText to ((unix id of p as text) & \"|\" & t & \"|\" & (item 1 of windowSize as text) & \"x\" & (item 2 of windowSize as text))\n"
        "end repeat\n"
        "end if\n"
        "end repeat\n"
        "set AppleScript's text item delimiters to linefeed\n"
        "return resultText as text\n"
        "end tell"
    )
    try:
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", script],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "reason": "osascript unavailable"}
    if result.returncode != 0:
        return {"available": False, "reason": "Accessibility permission unavailable"}
    matching = matching_windows(result.stdout, title_tokens)
    if matching:
        return {
            "available": True,
            "processGroupId": process_group_id,
            "processIds": target_ids,
            "expectedTitleTokens": list(title_tokens),
            "windows": matching[:32],
        }
    fallback_script = (
        "tell application \"System Events\"\\n"
        "set resultText to {}\\n"
        "repeat with p in (every application process whose background only is false)\\n"
        "repeat with w in (every window of p)\\n"
        "set t to title of w\\n"
        "set windowSize to size of w\\n"
        "if t is not missing value and t is not \"\" then\\n"
        "set end of resultText to ((name of p as text) & \"|\" & (unix id of p as text) & \"|\" & t & \"|\" & (item 1 of windowSize as text) & \"x\" & (item 2 of windowSize as text))\\n"
        "end if\\n"
        "end repeat\\n"
        "end repeat\\n"
        "set AppleScript's text item delimiters to linefeed\\n"
        "return resultText as text\\n"
        "end tell"
    )
    fallback = subprocess.run(
        ["/usr/bin/osascript", "-e", fallback_script],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if fallback.returncode == 0:
        matching_all = matching_windows(fallback.stdout, title_tokens)
        if matching_all:
            return {
                "available": True,
                "processGroupId": process_group_id,
                "processIds": target_ids,
                "expectedTitleTokens": list(title_tokens),
                "windows": matching_all[:32],
            }
    return {
        "available": False,
        "reason": "launch process group is no longer visible",
        "processGroupId": process_group_id,
    }


def screenshot(path: Path) -> dict[str, object]:
    try:
        result = subprocess.run(
            ["/usr/sbin/screencapture", "-x", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "reason": "screencapture unavailable"}
    return {"available": result.returncode == 0 and path.is_file() and path.stat().st_size > 0, "path": str(path)}


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def interaction_evidence(path: Path | None, accept_interactive: bool) -> dict[str, dict[str, bool]]:
    if not accept_interactive:
        if path is not None:
            raise AcceptanceError("--interaction-evidence requires --accept-interactive")
        return {}
    if path is None:
        raise AcceptanceError("--accept-interactive requires --interaction-evidence")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AcceptanceError("interaction evidence is not readable JSON") from error
    if not isinstance(value, dict) or value.get("schemaVersion") != "1":
        raise AcceptanceError("interaction evidence must use schemaVersion 1")
    applications = value.get("applications")
    if not isinstance(applications, dict):
        raise AcceptanceError("interaction evidence omitted applications")
    result: dict[str, dict[str, bool]] = {}
    for app_id, required in REQUIRED_INTERACTIONS.items():
        checks = applications.get(app_id)
        if not isinstance(checks, dict) or any(checks.get(name) is not True for name in required):
            raise AcceptanceError(f"interaction evidence is incomplete for {app_id}")
        result[app_id] = {name: True for name in required}
    return result


def installed_executable(asset, bottle_root: Path) -> Path:  # type: ignore[no-untyped-def]
    """Resolve only fixed, application-specific install locations."""
    primary = bottle_root / Path(asset.installed_executable)
    candidates = [primary]
    if asset.app_id == "sumatrapdf":
        candidates.append(
            bottle_root
            / "users"
            / os.environ.get("USER", "Public")
            / "AppData"
            / "Local"
            / "SumatraPDF"
            / "SumatraPDF.exe"
        )
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return primary


def request_architecture(value: str) -> str:
    # PE inspection uses the human-readable x86 label; the public schema
    # intentionally uses the stable i386 enum.
    return "i386" if value == "x86" else value


def fetch_asset(arguments: argparse.Namespace, app_id: str) -> Path:
    result = invoke(
        [
            sys.executable,
            "-S",
            "-B",
            str(DOWNLOAD),
            "fetch",
            app_id,
            "--cache-root",
            str(arguments.cache_root),
            *(["--allow-network"] if arguments.allow_network else []),
        ],
        timeout=240,
    )
    value = json_object(result, f"{app_id} asset fetch")
    path = value.get("path")
    if not isinstance(path, str):
        raise AcceptanceError(f"{app_id} asset fetch omitted path")
    return absolute(path, f"{app_id} asset")


def main() -> int:
    try:
        arguments = parser().parse_args()
        if platform.system() != "Darwin" or platform.machine() != "arm64":
            raise AcceptanceError("GUI baseline requires Darwin/arm64")
        runtime_id = validate_runtime_selection(arguments)
        arguments.compatforge_cli = absolute(arguments.compatforge_cli, "compatforge-cli")
        arguments.cache_root = absolute(arguments.cache_root, "cache-root", external=True)
        arguments.runtime_store = absolute(arguments.runtime_store, "runtime-store", external=True)
        arguments.storage_root = absolute(arguments.storage_root, "storage-root", external=True)
        arguments.work_root = absolute(arguments.work_root, "work-root", external=True)
        arguments.work_root.mkdir(parents=True, exist_ok=True)
        if any(arguments.work_root.iterdir()):
            raise AcceptanceError("work-root must be empty")
        explicit = [arguments.wine_root, arguments.wine, arguments.wineserver, arguments.version]
        evidence_path = (
            absolute(arguments.interaction_evidence, "interaction-evidence", external=True)
            if arguments.interaction_evidence
            else None
        )
        manual_checks = interaction_evidence(evidence_path, arguments.accept_interactive)

        request = {
            "schemaVersion": "1",
            "runtimeStoreRoot": str(arguments.runtime_store),
            "storageRoot": str(arguments.storage_root),
        }
        if all(explicit):
            request.update(
                {
                    "materializedRoot": str(absolute(arguments.wine_root, "wine-root")),
                    "wine": arguments.wine,
                    "wineserver": arguments.wineserver,
                    "version": arguments.version,
                }
            )
        request_path = arguments.work_root / "bootstrap-request.json"
        context_path = arguments.work_root / "context.json"
        write_json(request_path, request)
        receipt = json_object(
            invoke([str(arguments.compatforge_cli), "local", "macos", "context", str(request_path), str(context_path)]),
            "bootstrap receipt",
        )
        bind_runtime_identity(runtime_id, receipt, [])
        context = json.loads(context_path.read_text(encoding="utf-8"))
        if not isinstance(context, dict):
            raise AcceptanceError("bootstrap context is not an object")
        canonical_storage = context.get("storageRoot")
        if not isinstance(canonical_storage, str) or not Path(canonical_storage).is_absolute():
            raise AcceptanceError("bootstrap context omitted an absolute storage root")
        # Rust bootstrap canonicalizes macOS aliases such as /tmp ->
        # /private/tmp. Reuse that authoritative root for Bottle paths so
        # string-boundary validation and the filesystem observe the same path.
        arguments.storage_root = Path(canonical_storage)
        supervisor = context.setdefault("supervisor", {})
        if isinstance(supervisor, dict):
            supervisor["maximumRuntimeMilliseconds"] = 120_000
        write_json(context_path, context)
        write_json(arguments.work_root / "bootstrap-receipt.json", receipt)

        from download_gui_assets import ASSETS, asset_for  # type: ignore[import-not-found]

        results: list[dict[str, object]] = []
        for asset in ASSETS:
            bottle_id = f"gui-{asset.app_id}"
            bottle_root = arguments.storage_root / "bottles" / bottle_id / "prefix" / "drive_c"
            bottle_root.mkdir(parents=True, exist_ok=True)
            evidence: dict[str, object] = {
                "schemaVersion": "1",
                "runtimeId": runtime_id,
                "appId": asset.app_id,
                "bottleId": bottle_id,
                "cleanup": False,
            }
            set_application_outcome(
                evidence,
                "unverified",
                failure_reason("application-interaction"),
                diagnostic="application acceptance was not completed",
            )
            failure_reason_code = failure_reason("asset-fetch")
            try:
                installer = fetch_asset(arguments, asset.app_id)
                failure_reason_code = failure_reason("core-inspection")
                installer_inspection = json_object(
                    invoke([str(arguments.compatforge_cli), "inspect", str(installer)]),
                    f"{asset.app_id} installer inspection",
                )
                installer_architecture = installer_inspection.get("architecture")
                if not isinstance(installer_architecture, str):
                    raise AcceptanceError(f"{asset.app_id} installer inspection omitted architecture")
                evidence["installerInspection"] = installer_inspection
                inspection_request = {
                    "schemaVersion": "1",
                    "requestId": str(uuid.uuid4()),
                    "bottleId": bottle_id,
                    "executable": {
                        "path": str(installer),
                        "architecture": request_architecture(installer_architecture),
                        "mode": "immutableArtifact",
                    },
                    "arguments": list(asset.install_args),
                    "constraints": {
                        "allowVirtualMachine": False,
                        "allowRemote": False,
                        "networkPolicy": "deny",
                    },
                }
                installer_request_path = arguments.work_root / f"{asset.app_id}-installer-request.json"
                write_json(installer_request_path, inspection_request)
                failure_reason_code = failure_reason("core-plan")
                plan = json_object(
                    invoke(
                        [
                            str(arguments.compatforge_cli),
                            "prepared-plan",
                            str(context_path),
                            str(installer),
                            str(installer_request_path),
                        ]
                    ),
                    f"{asset.app_id} installer plan",
                )
                evidence["installerPlan"] = plan
                failure_reason_code = failure_reason("installer-launch")
                installer_events = run_events(
                    invoke(
                        [
                            str(arguments.compatforge_cli),
                            "prepared-launch-terminate",
                            str(context_path),
                            str(installer),
                            str(installer_request_path),
                            "8000",
                        ]
                    ),
                    f"{asset.app_id} installer",
                )
                evidence["installerEvents"] = installer_events
                evidence["installerExit"] = exit_observation(installer_events)
                installed = installed_executable(asset, bottle_root)
                if not installed.is_file() or installed.is_symlink():
                    set_application_outcome(
                        evidence,
                        "unverified",
                        failure_reason("installer-launch"),
                        diagnostic="installer exited but expected GUI executable was not found",
                    )
                    continue
                launch_request = {
                    "schemaVersion": "1",
                    "requestId": str(uuid.uuid4()),
                    "bottleId": bottle_id,
                    "executable": {
                        "path": str(installed),
                        "architecture": "x86_64",
                        "mode": "bottleInPlace",
                    },
                    "constraints": {
                        "allowVirtualMachine": False,
                        "allowRemote": False,
                        "networkPolicy": "deny",
                    },
                }
                launch_request_path = arguments.work_root / f"{asset.app_id}-launch-request.json"
                failure_reason_code = failure_reason("core-inspection")
                gui_inspection = json_object(
                    invoke([str(arguments.compatforge_cli), "inspect", str(installed)]),
                    f"{asset.app_id} GUI inspection",
                )
                gui_architecture = gui_inspection.get("architecture")
                if not isinstance(gui_architecture, str):
                    raise AcceptanceError(f"{asset.app_id} GUI inspection omitted architecture")
                launch_request["executable"]["architecture"] = request_architecture(gui_architecture)  # type: ignore[index]
                write_json(launch_request_path, launch_request)
                evidence["inspection"] = gui_inspection
                failure_reason_code = failure_reason("core-plan")
                evidence["plan"] = json_object(
                    invoke(
                        [
                            str(arguments.compatforge_cli),
                            "prepared-plan",
                            str(context_path),
                            str(installed),
                            str(launch_request_path),
                        ]
                    ),
                    f"{asset.app_id} GUI plan",
                )
                failure_reason_code = failure_reason("desktop-launch")
                events, windows, shot, process_group_id = observed_launch(
                    [
                        str(arguments.compatforge_cli),
                        "prepared-launch-terminate",
                        str(context_path),
                        str(installed),
                        str(launch_request_path),
                        str(INTERACTIVE_RUNTIME_MILLISECONDS if arguments.accept_interactive else 30_000),
                    ],
                    arguments.work_root / f"{asset.app_id}.png",
                    asset.window_title_tokens,
                )
                evidence["events"] = events
                evidence["exit"] = exit_observation(events)
                evidence["windows"] = windows
                evidence["screenshot"] = shot
                evidence["interactionChecks"] = manual_checks.get(asset.app_id, {})
                evidence["residualProcesses"] = process_snapshot(str(bottle_root), process_group_id)
                basic = status(events) == "accepted" and evidence["windows"].get("available") is True and evidence[
                    "screenshot"
                ].get("available") is True and not evidence["residualProcesses"]
                interactions_complete = all(
                    evidence["interactionChecks"].get(name) is True
                    for name in REQUIRED_INTERACTIONS[asset.app_id]
                )
                if basic and interactions_complete:
                    set_application_outcome(evidence, "accepted")
                elif evidence["residualProcesses"]:
                    set_application_outcome(
                        evidence,
                        "unverified",
                        failure_reason("cleanup-residual"),
                        diagnostic="launch left residual processes",
                    )
                elif (
                    evidence["windows"].get("available") is not True
                    or evidence["screenshot"].get("available") is not True
                ):
                    set_application_outcome(
                        evidence,
                        "unverified",
                        failure_reason("desktop-window"),
                        diagnostic="target window or screenshot evidence is incomplete",
                    )
                elif status(events) != "accepted":
                    set_application_outcome(
                        evidence,
                        "unverified",
                        failure_reason("application-content"),
                        diagnostic="application exit evidence is incomplete",
                    )
                elif not interactions_complete:
                    set_application_outcome(
                        evidence,
                        "unverified",
                        failure_reason("application-interaction"),
                        diagnostic="required per-application interaction evidence was not supplied",
                    )
            except (AcceptanceError, OSError, subprocess.TimeoutExpired) as error:
                set_application_outcome(
                    evidence,
                    "failed",
                    failure_reason_code,
                    diagnostic=str(error),
                )
            finally:
                try:
                    if bottle_root.exists() or bottle_root.is_symlink():
                        if bottle_root.is_symlink():
                            raise AcceptanceError("Bottle root became a symlink")
                        shutil.rmtree(arguments.storage_root / "bottles" / bottle_id)
                    evidence["cleanup"] = True
                except (OSError, AcceptanceError) as error:
                    evidence["cleanup"] = False
                    evidence["cleanupError"] = str(error)
                if evidence["cleanup"] is not True:
                    set_application_outcome(
                        evidence,
                        "failed",
                        failure_reason("cleanup-delete"),
                        diagnostic="Bottle cleanup failed",
                    )
                write_json(arguments.work_root / f"{asset.app_id}-evidence.json", evidence)
                results.append(evidence)

        bind_runtime_identity(runtime_id, receipt, results)
        summary = compact_summary(receipt, results)
        write_json(arguments.work_root / "summary.json", summary)
        print(compact_json(summary))
        return 0 if all(value["status"] == "accepted" for value in results) else 1
    except (AcceptanceError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError, ImportError) as error:
        print(f"compatforge-gui-baseline: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
