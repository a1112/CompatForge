#!/usr/bin/env python3
"""Validate the closed, non-executing Phase 2.3 MSI install request."""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from pathlib import Path

from validate_capability_probe import ContractError, digest, exact_keys, identifier, load_document, portable_component

PROPERTY = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


def validate_install_request(value: dict[str, object]) -> dict[str, object]:
    exact_keys(value, {"schemaVersion", "requestId", "bottleId", "package", "handler", "constraints"}, {"recipeId"})
    if value["schemaVersion"] != "1":
        raise ContractError("install request schemaVersion is unsupported")
    try:
        request_id = uuid.UUID(str(value["requestId"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise ContractError("requestId is not a UUID") from error
    if str(request_id) != value["requestId"]:
        raise ContractError("requestId is not canonical")
    identifier(value["bottleId"], "bottleId")
    if "recipeId" in value:
        identifier(value["recipeId"], "recipeId")

    package = value["package"]
    if not isinstance(package, dict):
        raise ContractError("package must be an object")
    exact_keys(package, {"path", "fileName", "sha256", "sizeBytes", "mediaType"})
    package_path = package["path"]
    if (
        not isinstance(package_path, str)
        or len(package_path.encode("utf-8")) > 4096
        or not Path(package_path).is_absolute()
        or ".." in Path(package_path).parts
    ):
        raise ContractError("package.path must be absolute and non-traversing")
    file_name = portable_component(package["fileName"], "package.fileName")
    if not file_name.casefold().endswith(".msi"):
        raise ContractError("package.fileName must use the .msi extension")
    if Path(package_path).name != file_name:
        raise ContractError("package.fileName does not match package.path")
    digest(package["sha256"], "package.sha256")
    if not isinstance(package["sizeBytes"], int) or not 1 <= package["sizeBytes"] <= 1024 * 1024 * 1024:
        raise ContractError("package size is outside the fixed bound")
    if package["mediaType"] != "application/x-msi":
        raise ContractError("package mediaType is unsupported")

    handler = value["handler"]
    if not isinstance(handler, dict):
        raise ContractError("handler must be an object")
    exact_keys(handler, {"kind", "action", "ui", "reboot", "properties"})
    if handler["kind"] != "msiexec" or handler["action"] != "install":
        raise ContractError("handler is outside the closed msiexec install operation")
    if handler["ui"] not in {"none", "basic"} or handler["reboot"] != "suppress":
        raise ContractError("handler UI/reboot policy is unsupported")
    properties = handler["properties"]
    if not isinstance(properties, dict) or len(properties) > 64:
        raise ContractError("handler properties exceed the fixed bound")
    for key, item in properties.items():
        if PROPERTY.fullmatch(key) is None:
            raise ContractError("handler property name is not canonical")
        if not isinstance(item, str) or len(item.encode("utf-8")) > 4096:
            raise ContractError("handler property value exceeds the fixed bound")

    constraints = value["constraints"]
    if not isinstance(constraints, dict):
        raise ContractError("constraints must be an object")
    exact_keys(
        constraints,
        {"allowVirtualMachine", "allowRemote", "networkPolicy", "maximumRuntimeMilliseconds"},
    )
    if constraints["allowVirtualMachine"] is not False or constraints["allowRemote"] is not False:
        raise ContractError("Prepared Install must remain local and non-virtualized")
    if constraints["networkPolicy"] not in {"deny", "installer-only"}:
        raise ContractError("install network policy is unsupported")
    maximum = constraints["maximumRuntimeMilliseconds"]
    if not isinstance(maximum, int) or not 1000 <= maximum <= 3_600_000:
        raise ContractError("install maximum runtime is outside the fixed bound")
    return value


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("request")
    return value


def main() -> int:
    try:
        request = validate_install_request(load_document(Path(parser().parse_args().request)))
        print(
            json.dumps(
                {
                    "schemaVersion": "1",
                    "requestId": request["requestId"],
                    "bottleId": request["bottleId"],
                    "handler": "msiexec",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (ContractError, OSError) as error:
        print(f"compatforge-install-request: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
