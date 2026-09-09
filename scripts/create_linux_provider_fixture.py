#!/usr/bin/env python3
"""Create external synthetic Linux Provider evidence from two explicit ELF files.

The helpers implement only --version. This fixture does not validate Wine or
Windows Guest execution. Runtime Pack evidence covers its two entrypoints only.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys


REPOSITORY = Path(__file__).resolve().parents[1]
PACK_ID = "wine-linux-ci"
BOOTSTRAP_PACK_ID = "wine-linux-x86-64-local-preview"
VERSION = "11.0"
MAX_ELF_BYTES = 64 * 1024 * 1024
MARKER = b"COMPATFORGE_LINUX_PROVIDER_FIXTURE_V1\n"


def explicit_path(path: Path) -> Path:
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("paths must be explicit absolute paths without parent traversal")
    if any(char in str(path) for char in ("\x00", "\r", "\n")):
        raise ValueError("invalid path characters")
    for component in (path, *path.parents):
        if component.is_symlink() or getattr(component, "is_junction", lambda: False)():
            raise ValueError("symlink and junction paths are not fixture inputs")
    return path.resolve(strict=False)


def read_elf(path: Path, expected_type: int) -> bytes:
    inspected = path.lstat()
    if not stat.S_ISREG(inspected.st_mode) or not 64 <= inspected.st_size <= MAX_ELF_BYTES:
        raise ValueError("fixture input must be a bounded regular ELF file")
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(os.open(path, flags), "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or not 64 <= before.st_size <= MAX_ELF_BYTES or
                (inspected.st_dev, inspected.st_ino) != (before.st_dev, before.st_ino)):
            raise ValueError("fixture input must be a bounded regular ELF file")
        data = source.read(MAX_ELF_BYTES + 1)
        after = os.fstat(source.fileno())
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or len(data) != before.st_size:
        raise ValueError("fixture input changed while reading")
    if (data[:7] != b"\x7fELF\x02\x01\x01" or
            struct.unpack_from("<HHI", data, 16) != (expected_type, 62, 1) or
            struct.unpack_from("<H", data, 52)[0] != 64):
        raise ValueError("expected Linux x86_64 ELF64 ET_EXEC Wine and ET_DYN Wineserver")
    return data


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def manifest_for(pack_id: str, wine: bytes, wineserver: bytes) -> dict:
    # Preserve Rust UnsignedRuntimePackManifest/RuntimeComponent field order;
    # component names and capability lists are already in canonical sorted order.
    unsigned = {
        "schemaVersion": "1", "id": pack_id, "version": VERSION, "channel": "preview",
        "host": {"os": "linux", "architecture": "x86_64"},
        "components": [
            {"name": role + "-entrypoint", "version": VERSION, "license": "LGPL-2.1-or-later",
             "artifact": "components/" + role + "-entrypoint.bin", "digest": digest(data),
             "entrypoints": {role: "bin/" + role}}
            for role, data in (("wine", wine), ("wineserver", wineserver))
        ],
        "capabilities": ["guest-x86_64"],
    }
    return dict(unsigned, digest=digest(json.dumps(unsigned, ensure_ascii=False, separators=(",", ":")).encode()))


def write_new(path: Path, data: bytes, mode: int = 0o600) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, mode), "wb") as destination:
        destination.write(data)
        destination.flush()
        os.fsync(destination.fileno())


def write_json(path: Path, document: dict) -> None:
    write_new(path, (json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode())


def create_fixture(root: Path, wine_path: Path, wineserver_path: Path) -> None:
    root, wine_path, wineserver_path = map(explicit_path, (root, wine_path, wineserver_path))
    if root == REPOSITORY or REPOSITORY in root.parents:
        raise ValueError("generated fixtures must remain outside the repository")
    if root == wine_path or root in wine_path.parents or root == wineserver_path or root in wineserver_path.parents:
        raise ValueError("fixture inputs must be outside the generated output root")
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise FileExistsError("fixture output root must be absent or empty")
    if not root.parent.is_dir():
        raise ValueError("explicit output parent must already exist")
    wine, wineserver = read_elf(wine_path, 2), read_elf(wineserver_path, 3)
    manifest = manifest_for(PACK_ID, wine, wineserver)
    bootstrap_manifest = manifest_for(BOOTSTRAP_PACK_ID, wine, wineserver)
    materialized = root / "materialized"
    provider = {
        "schemaVersion": "1", "runtimeStoreRoot": str(root / "store"),
        "wineRuntime": {
            "providerId": PACK_ID, "packId": PACK_ID, "packDigest": manifest["digest"],
            "version": VERSION, "architecture": "x86_64", "materializedRoot": str(materialized),
            "wine": {"path": "bin/wine", "digest": digest(wine)},
            "wineserver": {"path": "bin/wineserver", "digest": digest(wineserver)},
            "capabilities": ["guest-x86_64"], "wined3dCapabilities": ["opengl"],
        },
    }
    bootstrap = {
        "schemaVersion": "1", "runtimeStoreRoot": str(root / "bootstrap-store"),
        "storageRoot": str(root / "bootstrap-storage"), "materializedRoot": str(materialized),
        "wine": "bin/wine", "wineserver": "bin/wineserver", "version": VERSION,
    }
    expected = {
        "schemaVersion": "1", "packId": PACK_ID, "packDigest": manifest["digest"],
        "wineDigest": digest(wine), "wineserverDigest": digest(wineserver),
        "bootstrapPackId": BOOTSTRAP_PACK_ID, "bootstrapPackDigest": bootstrap_manifest["digest"],
    }
    if not root.exists():
        root.mkdir(mode=0o700)
    for directory in (materialized, materialized / "bin", root / "bundle", root / "bundle/components"):
        directory.mkdir(mode=0o700)
    for role, data in (("wine", wine), ("wineserver", wineserver)):
        write_new(materialized / "bin" / role, data, mode=0o700)
        write_new(root / "bundle/components" / (role + "-entrypoint.bin"), data)
    write_new(materialized / "compatforge-linux-provider-fixture.marker", MARKER)
    for path, document in (("bundle/manifest.json", manifest), ("provider.json", provider),
                           ("bootstrap.json", bootstrap), ("expected-digests.json", expected)):
        write_json(root / path, document)


def main(arguments: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    if len(arguments) != 3:
        print("usage: create_linux_provider_fixture.py <absolute-output-root> <absolute-wine-elf> <absolute-wineserver-elf>",
              file=sys.stderr)
        return 2
    try:
        create_fixture(*(Path(argument) for argument in arguments))
    except (ValueError, OSError) as error:
        print("Linux synthetic fixture refused: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
