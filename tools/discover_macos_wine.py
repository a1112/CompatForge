#!/usr/bin/env python3
"""Discover and execute-verify a usable local x86_64 Wine on Apple Silicon."""

from __future__ import annotations

import json
import platform
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

ROOT = Path(__file__).resolve().parents[1]
PROBE_TIMEOUT_SECONDS = 10
MAX_MACHO_HEADER_BYTES = 64 * 1024
WHISKY_GRAPHICS_COMPONENTS = (
    "lib/wine/x86_64-windows/winemac.drv",
    "lib/wine/x86_64-unix/winemac.drv.so",
)


class DiscoveryError(Exception):
    pass


@dataclass(frozen=True)
class Candidate:
    source: str
    root: Path
    wine: str
    wineserver: str


Runner = Callable[..., subprocess.CompletedProcess[str]]


def runtime_id(candidate: Candidate) -> str | None:
    if candidate.source in ("crossover-app", "crossover-interactive-derived"):
        return "crossover"
    if candidate.source in ("whisky-app", "whisky-library", "whisky-interactive-derived"):
        return "whisky"
    return None


def prepared_candidate(root: Path, identifier: str) -> Candidate | None:
    descriptor_path = root / "descriptor.json"
    try:
        if descriptor_path.stat().st_size > 64 * 1024:
            return None
        descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
        expected_source = f"{identifier}-interactive-derived"
        if (
            not isinstance(descriptor, dict)
            or descriptor.get("schemaVersion") != "1"
            or descriptor.get("runtimeId") != identifier
            or descriptor.get("source") != expected_source
            or Path(descriptor.get("materializedRoot", "")).resolve(strict=True)
            != root.resolve(strict=True)
            or not isinstance(descriptor.get("wine"), str)
            or not isinstance(descriptor.get("wineserver"), str)
        ):
            return None
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError):
        return None
    return Candidate(expected_source, root, descriptor["wine"], descriptor["wineserver"])


def known_candidates(home: Path | None = None) -> list[Candidate]:
    home = home or Path.home()
    candidates: list[Candidate] = []

    prepared_root = home / "Library" / "Caches" / "dev.compatforge" / "interactive-runtimes"
    for identifier in ("crossover", "whisky"):
        candidate = prepared_candidate(prepared_root / identifier, identifier)
        if candidate is not None:
            candidates.append(candidate)

    for app in (
        Path("/Applications/CrossOver.app"),
        home / "Applications" / "CrossOver.app",
    ):
        root = app / "Contents" / "SharedSupport" / "CrossOver"
        candidates.extend(
            [
                Candidate(
                    "crossover-app",
                    root,
                    "bin/wineloader",
                    "bin/wineserver",
                ),
                Candidate(
                    "crossover-app",
                    root,
                    "bin/wine",
                    "bin/wineserver",
                ),
            ]
        )
    for app in (
        Path("/Applications/Whisky.app"),
        home / "Applications" / "Whisky.app",
    ):
        candidates.extend(
            [
                Candidate(
                    "whisky-app",
                    app / "Contents" / "Resources" / "Libraries" / "Wine",
                    "bin/wine64",
                    "bin/wineserver",
                ),
                Candidate(
                    "whisky-app",
                    app / "Contents" / "Resources" / "Wine",
                    "bin/wine64",
                    "bin/wineserver",
                ),
            ]
        )
    whisky_library = (
        home
        / "Library"
        / "Application Support"
        / "com.isaacmarovitz.Whisky"
        / "Libraries"
        / "Wine"
    )
    candidates.extend(
        [
            Candidate("whisky-library", whisky_library, "bin/wine64", "bin/wineserver"),
            Candidate("whisky-library", whisky_library, "bin/wine", "bin/wineserver"),
        ]
    )

    developer_refs = ROOT.parent / "Mac-Win" / "refs"
    if developer_refs.is_dir():
        preferred = [
            developer_refs / "Whisky-x86_64-build",
            developer_refs / "Whisky-x86_64-game-build",
            developer_refs / "Whisky-wow64-game-build",
        ]
        remaining = sorted(developer_refs.glob("Whisky-*-build"), key=lambda path: path.name)
        for build in [*preferred, *remaining]:
            candidates.append(
                Candidate(
                    "mac-win-development-build",
                    build,
                    "loader/wine",
                    "server/wineserver",
                )
            )

    unique: dict[tuple[str, str, str], Candidate] = {}
    for candidate in candidates:
        key = (str(candidate.root), candidate.wine, candidate.wineserver)
        unique.setdefault(key, candidate)
    return list(unique.values())


def macho_architectures(path: Path) -> set[str]:
    with path.open("rb") as source:
        data = source.read(MAX_MACHO_HEADER_BYTES)
    if len(data) < 8:
        return set()
    magic = data[:4]
    if magic == b"\xcf\xfa\xed\xfe":
        cpu = int.from_bytes(data[4:8], "little")
        return {architecture for architecture in [cpu_architecture(cpu)] if architecture}
    if magic == b"\xfe\xed\xfa\xcf":
        cpu = int.from_bytes(data[4:8], "big")
        return {architecture for architecture in [cpu_architecture(cpu)] if architecture}
    if magic not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        return set()
    count = int.from_bytes(data[4:8], "big")
    if count == 0 or count > 32:
        return set()
    stride = 32 if magic == b"\xca\xfe\xba\xbf" else 20
    architectures: set[str] = set()
    for index in range(count):
        offset = 8 + index * stride
        if offset + 4 > len(data):
            return set()
        architecture = cpu_architecture(int.from_bytes(data[offset : offset + 4], "big"))
        if architecture:
            architectures.add(architecture)
    return architectures


def cpu_architecture(cpu_type: int) -> str | None:
    return {0x0100_0007: "x86_64", 0x0100_000C: "arm64"}.get(cpu_type)


def regular_executable(path: Path) -> bool:
    try:
        metadata = path.stat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o111 != 0


def whisky_graphics_complete(root: Path) -> bool:
    """Require the paired 64-bit PE and Unix macOS graphics modules."""

    for graphics_root in (root, root / "runtime"):
        complete = True
        for relative in WHISKY_GRAPHICS_COMPONENTS:
            component = graphics_root / relative
            try:
                resolved = component.resolve(strict=True)
                metadata = resolved.stat()
            except OSError:
                complete = False
                break
            if root not in resolved.parents or not stat.S_ISREG(metadata.st_mode) or metadata.st_size == 0:
                complete = False
                break
        if complete:
            return True
    return False


def run_version(executable: Path, root: Path, runner: Runner) -> subprocess.CompletedProcess[str]:
    return runner(
        [str(executable), "--version"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=PROBE_TIMEOUT_SECONDS,
        env={"LANG": "C", "LC_ALL": "C", "WINEDEBUG": "-all"},
    )


def verify_candidate(candidate: Candidate, runner: Runner = subprocess.run) -> dict[str, str] | None:
    try:
        root = candidate.root.resolve(strict=True)
        wine = (root / candidate.wine).resolve(strict=True)
        wineserver = (root / candidate.wineserver).resolve(strict=True)
    except OSError:
        return None
    if not root.is_dir() or root not in wine.parents or root not in wineserver.parents:
        return None
    if not regular_executable(wine) or not regular_executable(wineserver):
        return None
    if macho_architectures(wine) != {"x86_64"} or macho_architectures(wineserver) != {"x86_64"}:
        return None
    if candidate.source in (
        "whisky-app",
        "whisky-library",
        "whisky-interactive-derived",
    ) and not whisky_graphics_complete(root):
        return None
    try:
        wine_version = run_version(wine, root, runner)
        wineserver_version = run_version(wineserver, root, runner)
    except (OSError, subprocess.TimeoutExpired):
        return None
    version_line = wine_version.stdout.strip().splitlines()
    if wine_version.returncode != 0 or not version_line or not version_line[0].startswith("wine-"):
        return None
    if wineserver_version.returncode != 0:
        return None
    version = version_line[0].removeprefix("wine-").strip()
    if not version:
        return None
    return {
        "schemaVersion": "1",
        "source": candidate.source,
        "materializedRoot": str(root),
        "wine": wine.relative_to(root).as_posix(),
        "wineserver": wineserver.relative_to(root).as_posix(),
        "version": version,
        "architecture": "x86_64",
    }


def discover(candidates: Iterable[Candidate] | None = None, runner: Runner = subprocess.run) -> dict[str, str]:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise DiscoveryError("automatic Wine discovery requires Darwin/arm64")
    selected_candidates = known_candidates() if candidates is None else candidates
    for candidate in selected_candidates:
        verified = verify_candidate(candidate, runner)
        if verified is not None:
            return verified
    raise DiscoveryError("no executable-verified x86_64 Wine candidate was found")


def discover_all(
    candidates: Iterable[Candidate] | None = None, runner: Runner = subprocess.run
) -> list[dict[str, str]]:
    selected_candidates = known_candidates() if candidates is None else candidates
    selected: dict[str, dict[str, str]] = {}
    for candidate in selected_candidates:
        identifier = runtime_id(candidate)
        if identifier is None or identifier in selected:
            continue
        verified = verify_candidate(candidate, runner)
        if verified is not None:
            selected[identifier] = {**verified, "runtimeId": identifier}
    if set(selected) != {"crossover", "whisky"}:
        raise DiscoveryError("required Runtime is unavailable")
    return [selected[identifier] for identifier in ("crossover", "whisky")]


def main() -> int:
    arguments = sys.argv[1:]
    if arguments not in ([], ["--all"]):
        print("compatforge-wine-discovery: invalid command-line arguments", file=sys.stderr)
        return 2
    try:
        if arguments == ["--all"]:
            result: dict[str, object] = {
                "runtimes": discover_all(),
                "schemaVersion": "1",
            }
        else:
            result = discover()
    except DiscoveryError as error:
        print(f"compatforge-wine-discovery: {error}", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
