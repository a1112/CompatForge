#!/usr/bin/env python3
"""Create a closed, unsigned human-interaction evidence worksheet.

The generated worksheet deliberately contains ``false`` checks and an empty
timestamp. A human observer must perform each application interaction, set the
corresponding checks to ``true`` and supply ``observedAt`` before
``run_gui_baseline.py --accept-interactive`` will accept it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from download_gui_assets import ASSETS
from run_gui_baseline import AcceptanceError, REQUIRED_INTERACTIONS, absolute


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--output", required=True)
    value.add_argument("--observer", required=True)
    value.add_argument("--app", action="append", dest="applications")
    return value


def main() -> int:
    try:
        arguments = parser().parse_args()
        output = absolute(arguments.output, "output", external=True)
        observer = arguments.observer.strip()
        if not observer or len(observer.encode("utf-8")) > 256:
            raise AcceptanceError("observer must contain 1..256 UTF-8 bytes")
        known = {asset.app_id for asset in ASSETS}
        selected = set(arguments.applications or known)
        unknown = selected - known
        if unknown:
            raise AcceptanceError(f"unknown GUI application: {sorted(unknown)[0]}")
        if output.exists():
            raise AcceptanceError("output already exists")
        output.parent.mkdir(parents=True, exist_ok=True)
        value = {
            "schemaVersion": "2",
            "attestation": {
                "mode": "human",
                "observer": observer,
                "observedAt": "",
            },
            "applications": {
                app_id: {name: False for name in REQUIRED_INTERACTIONS[app_id]}
                for app_id in sorted(selected)
            },
        }
        output.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"schemaVersion": "1", "path": str(output), "applications": sorted(selected)}))
        return 0
    except (AcceptanceError, OSError) as error:
        print(f"compatforge-gui-interactions: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
