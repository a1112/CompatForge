#!/usr/bin/env python3
"""Launch the packaged Tauri app without Runtime discovery and require a clean exit."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path


RUNTIME_ENVIRONMENT_PREFIXES = (
    "COMPATFORGE_",
    "WINE",
    "CX_",
    "CROSSOVER_",
    "WHISKY_",
)


def smoke_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ if source is None else source)
    for name in tuple(environment):
        if name.startswith(RUNTIME_ENVIRONMENT_PREFIXES):
            del environment[name]
    environment["COMPATFORGE_DESKTOP_SMOKE"] = "1"
    return environment


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: smoke.py <CompatForge executable>", file=sys.stderr)
        return 2
    executable = Path(sys.argv[1])
    if not executable.is_file():
        print(f"application executable is missing: {executable}", file=sys.stderr)
        return 2
    environment = smoke_environment()
    try:
        result = subprocess.run(
            [str(executable)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print("CompatForge Tauri smoke did not exit within 20 seconds", file=sys.stderr)
        return 1
    if result.returncode != 0:
        print(result.stdout, file=sys.stderr, end="")
        print(result.stderr, file=sys.stderr, end="")
        print(f"CompatForge Tauri smoke exited with {result.returncode}", file=sys.stderr)
        return 1
    if "COMPATFORGE_TAURI_SMOKE_READY" not in result.stdout:
        print("CompatForge Tauri smoke readiness marker is missing", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
