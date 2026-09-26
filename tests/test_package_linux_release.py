"""Contract tests for the Linux release bundle consumed by ForgeOS."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/package_linux_release.py"


def load_package_module():
    spec = importlib.util.spec_from_file_location("package_linux_release", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def elf_x86_64(payload: bytes) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4] = 2
    header[5] = 1
    header[16:18] = (3).to_bytes(2, "little")
    header[18:20] = (62).to_bytes(2, "little")
    return bytes(header) + payload


def tar_bytes(members: dict[str, bytes], *, symlink: str | None = None) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, body in members.items():
                entry = tarfile.TarInfo(name)
                if name == symlink:
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = "../../escape"
                else:
                    entry.size = len(body)
                archive.addfile(entry, None if name == symlink else io.BytesIO(body))
    return buffer.getvalue()


class LinuxReleasePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="compatforge-release-")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.source = base / "source"
        self.source.mkdir()
        (self.source / "Cargo.toml").write_text(
            '[workspace.package]\nversion = "0.12.0"\n', encoding="utf-8"
        )
        (self.source / "Cargo.lock").write_bytes(b"locked dependency graph\n")
        subprocess.run(["git", "init", "-q", str(self.source)], check=True)
        subprocess.run(["git", "-C", str(self.source), "config", "core.autocrlf", "false"], check=True)
        subprocess.run(["git", "-C", str(self.source), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.source), "-c", "user.name=Test", "-c",
             "user.email=test@example.invalid", "commit", "-qm", "fixture"], check=True,
        )
        self.commit = subprocess.check_output(
            ["git", "-C", str(self.source), "rev-parse", "HEAD"], text=True
        ).strip()
        self.cli = base / "compatforge-cli"
        self.library = base / "libcompatforge_ffi.so"
        self.cli.write_bytes(elf_x86_64(b"CLI"))
        self.library.write_bytes(elf_x86_64(b"LIB"))
        self.bundle = base / "compatforge-linux-x86_64-v0.12.0.tar.gz"

    def build(self) -> None:
        load_package_module().build_bundle(
            self.source, self.cli, self.library, self.bundle
        )

    def verify(self):
        digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
        return load_package_module().verify_bundle(
            self.bundle, expected_sha256=digest, expected_source_commit=self.commit
        )

    def members(self) -> dict[str, bytes]:
        with tarfile.open(self.bundle, "r:gz") as archive:
            return {item.name: archive.extractfile(item).read() for item in archive}

    def test_build_is_deterministic_and_binds_source_and_binaries(self) -> None:
        self.build()
        first = self.bundle.read_bytes()
        manifest, members = self.verify()
        self.assertEqual(
            set(members),
            {"manifest.json", "bin/compatforge-cli", "lib/libcompatforge_ffi.so"},
        )
        self.assertEqual(manifest["sourceCommit"], self.commit)
        self.assertEqual(manifest["version"], "0.12.0")
        self.assertEqual(manifest["architecture"], "linux-x86_64")
        self.assertEqual(manifest["cargoLockSha256"], hashlib.sha256(b"locked dependency graph\n").hexdigest())
        self.assertEqual(manifest["artifacts"]["bin/compatforge-cli"]["sha256"], hashlib.sha256(self.cli.read_bytes()).hexdigest())
        self.build()
        self.assertEqual(self.bundle.read_bytes(), first)

    def test_dirty_source_is_rejected(self) -> None:
        (self.source / "uncommitted.txt").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "clean"):
            self.build()

    def test_wrong_architecture_is_rejected(self) -> None:
        self.cli.write_bytes(b"not an ELF".ljust(64, b"x"))
        with self.assertRaisesRegex(ValueError, "ELF"):
            self.build()

    def test_bundle_digest_and_commit_are_external_trust_inputs(self) -> None:
        self.build()
        module = load_package_module()
        with self.assertRaisesRegex(ValueError, "digest"):
            module.verify_bundle(self.bundle, "a" * 64, self.commit)
        with self.assertRaisesRegex(ValueError, "commit"):
            module.verify_bundle(
                self.bundle, hashlib.sha256(self.bundle.read_bytes()).hexdigest(), "b" * 40
            )

    def test_extra_member_and_symlink_are_rejected(self) -> None:
        self.build()
        original = self.members()
        for changed, linked in (
            ({**original, "../outside": b"bad"}, None),
            ({**original, "unexpected": b"bad"}, None),
            (original, "bin/compatforge-cli"),
        ):
            with self.subTest(linked=linked):
                self.bundle.write_bytes(tar_bytes(changed, symlink=linked))
                with self.assertRaises(ValueError):
                    self.verify()

    def test_duplicate_member_is_rejected(self) -> None:
        self.build()
        original = self.members()
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name in (*original, "bin/compatforge-cli"):
                    body = original[name]
                    entry = tarfile.TarInfo(name)
                    entry.size = len(body)
                    archive.addfile(entry, io.BytesIO(body))
        self.bundle.write_bytes(buffer.getvalue())
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.verify()

    def test_embedded_binary_and_manifest_mutation_are_rejected(self) -> None:
        self.build()
        original = self.members()
        mutated = dict(original)
        mutated["bin/compatforge-cli"] += b"x"
        self.bundle.write_bytes(tar_bytes(mutated))
        with self.assertRaisesRegex(ValueError, "artifact"):
            self.verify()
        mutated = dict(original)
        document = json.loads(mutated["manifest.json"])
        document["unexpected"] = True
        mutated["manifest.json"] = json.dumps(document).encode()
        self.bundle.write_bytes(tar_bytes(mutated))
        with self.assertRaisesRegex(ValueError, "manifest"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
