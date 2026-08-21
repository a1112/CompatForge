#!/usr/bin/env python3
"""Developer-local dual-Runtime macOS acceptance contract."""

from __future__ import annotations

import sys


RUNTIME_MATRIX = {
    "crossover": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
    "whisky": ("console", "7zip", "sumatrapdf", "notepad-plus-plus"),
}
ROUNDS = ("round-1", "round-2")


class AcceptanceError(Exception):
    """Report a closed developer-local acceptance failure."""


def require_python(version: tuple[int, int, int]) -> None:
    """Reject interpreters below the repository's supported Python floor."""

    if version < (3, 11, 0):
        raise AcceptanceError("Python 3.11 or newer is required")


def main() -> int:
    try:
        require_python(sys.version_info[:3])
    except AcceptanceError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
