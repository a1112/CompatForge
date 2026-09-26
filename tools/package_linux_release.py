#!/usr/bin/env python3
"""Build and verify the closed Linux x86_64 CompatForge release bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zlib


MEMBERS = (
    "manifest.json",
    "bin/compatforge-cli",
    "lib/libcompatforge_ffi.so",
)
ARTIFACTS = MEMBERS[1:]
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024
MAX_UNCOMPRESSED_BYTES = 2 * MAX_ARTIFACT_BYTES + MAX_MANIFEST_BYTES + 16 * 1024


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(source: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(source), *args],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _git_bytes(source: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(source), *args])


def _source_version(source: Path) -> str:
    cargo = (source / "Cargo.toml").read_text(encoding="utf-8")
    section = re.search(r"(?ms)^\[workspace\.package\]\s*\n(.*?)(?=^\[|\Z)", cargo)
    if section is None:
        raise ValueError("workspace package version is missing")
    match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', section.group(1), re.M)
    if match is None or VERSION.fullmatch(match.group(1)) is None:
        raise ValueError("workspace package version is invalid")
    return match.group(1)


def _elf_x86_64(data: bytes, label: str) -> None:
    if (
        len(data) < 120
        or data[:4] != b"\x7fELF"
        or data[4:6] != b"\x02\x01"
        or int.from_bytes(data[16:18], "little") not in (2, 3)
        or int.from_bytes(data[18:20], "little") != 62
    ):
        raise ValueError(f"{label} must be an ELF x86_64 binary")
    offset = int.from_bytes(data[32:40], "little")
    entry_size = int.from_bytes(data[54:56], "little")
    count = int.from_bytes(data[56:58], "little")
    if entry_size != 56 or not 1 <= count <= 128 or offset < 64 or offset + entry_size * count > len(data):
        raise ValueError(f"{label} ELF program headers are invalid")
    loadable = False
    for index in range(count):
        start = offset + index * entry_size
        if int.from_bytes(data[start:start + 4], "little") != 1:
            continue
        file_offset = int.from_bytes(data[start + 8:start + 16], "little")
        file_size = int.from_bytes(data[start + 32:start + 40], "little")
        memory_size = int.from_bytes(data[start + 40:start + 48], "little")
        loadable |= file_size > 0 and memory_size >= file_size and file_offset + file_size <= len(data)
    if not loadable:
        raise ValueError(f"{label} ELF has no valid loadable segment")


def _artifact(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular file")
    size = path.stat().st_size
    if not 64 <= size <= MAX_ARTIFACT_BYTES:
        raise ValueError(f"{label} size is outside the release bound")
    data = path.read_bytes()
    _elf_x86_64(data, label)
    return data


def _canonical(document: dict) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _manifest(data: bytes) -> dict:
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("release manifest exceeds its size bound")
    try:
        manifest = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("release manifest is malformed") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schemaVersion", "version", "architecture", "sourceCommit", "cargoLockSha256", "artifacts"
    }:
        raise ValueError("release manifest fields are invalid")
    if data != _canonical(manifest):
        raise ValueError("release manifest is not canonical")
    if type(manifest["schemaVersion"]) is not int or manifest["schemaVersion"] != 1 or manifest["architecture"] != "linux-x86_64":
        raise ValueError("release manifest platform or schema is invalid")
    if not isinstance(manifest["version"], str) or not VERSION.fullmatch(manifest["version"]):
        raise ValueError("release manifest version is invalid")
    if not isinstance(manifest["sourceCommit"], str) or not COMMIT.fullmatch(manifest["sourceCommit"]):
        raise ValueError("release manifest source commit is invalid")
    if not isinstance(manifest["cargoLockSha256"], str) or not SHA256.fullmatch(manifest["cargoLockSha256"]):
        raise ValueError("release manifest Cargo.lock digest is invalid")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != set(ARTIFACTS):
        raise ValueError("release manifest artifacts are invalid")
    for name in ARTIFACTS:
        entry = artifacts[name]
        if not isinstance(entry, dict) or set(entry) != {"sha256", "sizeBytes"}:
            raise ValueError(f"release manifest artifact {name} fields are invalid")
        if not isinstance(entry["sha256"], str) or not SHA256.fullmatch(entry["sha256"]):
            raise ValueError(f"release manifest artifact {name} digest is invalid")
        if type(entry["sizeBytes"]) is not int or not 64 <= entry["sizeBytes"] <= MAX_ARTIFACT_BYTES:
            raise ValueError(f"release manifest artifact {name} size is invalid")
    return manifest


def build_bundle(source: Path, cli: Path, library: Path, output: Path) -> dict:
    """Package already built release binaries from one clean source commit."""
    source = Path(source).resolve()
    if _git(source, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("release source checkout must be clean")
    tracked = _git_bytes(source, "ls-files", "-v", "-z").split(b"\0")
    if any(entry and not entry.startswith(b"H ") for entry in tracked):
        raise ValueError("release source checkout has hidden index flags and is not clean")
    for name in ("Cargo.toml", "Cargo.lock"):
        if (source / name).read_bytes() != _git_bytes(source, "show", f"HEAD:{name}"):
            raise ValueError(f"release source {name} differs from the clean commit")
    commit = _git(source, "rev-parse", "HEAD")
    if not COMMIT.fullmatch(commit):
        raise ValueError("release source commit is invalid")
    cargo_lock = (source / "Cargo.lock").read_bytes()
    if not cargo_lock:
        raise ValueError("Cargo.lock is empty")
    contents = {
        ARTIFACTS[0]: _artifact(Path(cli), "CLI"),
        ARTIFACTS[1]: _artifact(Path(library), "FFI library"),
    }
    manifest = {
        "schemaVersion": 1,
        "version": _source_version(source),
        "architecture": "linux-x86_64",
        "sourceCommit": commit,
        "cargoLockSha256": _digest(cargo_lock),
        "artifacts": {
            name: {"sha256": _digest(contents[name]), "sizeBytes": len(contents[name])}
            for name in ARTIFACTS
        },
    }
    contents[MEMBERS[0]] = _canonical(manifest)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0, compresslevel=9) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    for name in MEMBERS:
                        body = contents[name]
                        item = tarfile.TarInfo(name)
                        item.mode = 0o644 if name == "manifest.json" else 0o755
                        item.size = len(body)
                        item.mtime = 0
                        archive.addfile(item, io.BytesIO(body))
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    verify_bundle(output, _digest(output.read_bytes()), commit)
    return manifest


def _closed_ustar_members(blob: bytes) -> dict[str, bytes]:
    """Bound gzip expansion and inspect raw USTAR headers, including controls."""
    try:
        decoder = zlib.decompressobj(31)
        raw = decoder.decompress(blob, MAX_UNCOMPRESSED_BYTES + 1)
    except zlib.error as error:
        raise ValueError("release bundle compression is malformed") from error
    if (len(raw) > MAX_UNCOMPRESSED_BYTES or not decoder.eof
            or decoder.unused_data or decoder.unconsumed_tail):
        raise ValueError("release bundle compressed stream exceeds the bound or has trailing data")
    contents: dict[str, bytes] = {}
    position = 0
    while position + 512 <= len(raw):
        header = raw[position:position + 512]
        if header == bytes(512):
            if position + 1024 > len(raw) or any(raw[position:]):
                raise ValueError("release bundle terminator is malformed")
            if set(contents) != set(MEMBERS):
                raise ValueError("release bundle member list is incomplete")
            return contents
        if header[257:265] != b"ustar\x0000" or header[156:157] not in (b"0", b"\0"):
            raise ValueError("release bundle has an unsupported member header")
        try:
            name = header[:100].split(b"\0", 1)[0].decode("ascii")
            size_field = header[124:136].strip(b" \0")
            check_field = header[148:156].strip(b" \0")
            if not re.fullmatch(rb"[0-7]+", size_field) or not re.fullmatch(rb"[0-7]+", check_field):
                raise ValueError("release bundle member header has invalid octal fields")
            size = int(size_field, 8)
            checksum = int(check_field, 8)
        except UnicodeDecodeError as error:
            raise ValueError("release bundle member name is invalid") from error
        actual_checksum = sum(header[:148]) + 8 * 32 + sum(header[156:])
        if checksum != actual_checksum:
            raise ValueError("release bundle member header checksum differs")
        if name not in MEMBERS or name in contents:
            raise ValueError("release bundle has an extra or duplicate member")
        limit = MAX_MANIFEST_BYTES if name == "manifest.json" else MAX_ARTIFACT_BYTES
        if not 1 <= size <= limit:
            raise ValueError("release bundle member size is invalid")
        start = position + 512
        end = start + size
        next_position = start + ((size + 511) // 512) * 512
        if next_position > len(raw) or any(raw[end:next_position]):
            raise ValueError("release bundle member data or padding is malformed")
        contents[name] = raw[start:end]
        position = next_position
    raise ValueError("release bundle has no valid USTAR terminator")


def verify_bundle(bundle: Path, expected_sha256: str, expected_source_commit: str) -> tuple[dict, dict[str, bytes]]:
    """Check an externally pinned archive and every embedded byte before use."""
    if not SHA256.fullmatch(expected_sha256):
        raise ValueError("expected bundle digest is invalid")
    if not COMMIT.fullmatch(expected_source_commit):
        raise ValueError("expected source commit is invalid")
    bundle = Path(bundle)
    if bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("release bundle must be a bounded regular file")
    blob = bundle.read_bytes()
    if _digest(blob) != expected_sha256:
        raise ValueError("release bundle digest mismatch")
    contents = _closed_ustar_members(blob)
    manifest = _manifest(contents["manifest.json"])
    if manifest["sourceCommit"] != expected_source_commit:
        raise ValueError("release bundle source commit mismatch")
    for name in ARTIFACTS:
        body = contents[name]
        _elf_x86_64(body, f"release artifact {name}")
        record = manifest["artifacts"][name]
        if record["sizeBytes"] != len(body) or record["sha256"] != _digest(body):
            raise ValueError(f"release artifact {name} digest or size mismatch")
    return manifest, contents


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--cli", type=Path, required=True)
    build.add_argument("--library", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--sha256", required=True)
    verify.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    try:
        if args.command == "build":
            manifest = build_bundle(args.source_root, args.cli, args.library, args.output)
            result = {"bundleSha256": _digest(args.output.read_bytes()), "manifest": manifest}
        else:
            manifest, _ = verify_bundle(args.bundle, args.sha256, args.source_commit)
            result = {"bundleSha256": args.sha256, "manifest": manifest}
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"CompatForge release bundle rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
