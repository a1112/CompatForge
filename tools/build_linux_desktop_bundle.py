#!/usr/bin/env python3
"""Build a deterministic, closed local CompatForge Linux desktop bundle."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_BINARY = 512 * 1024 * 1024


def require(condition, message):
    if not condition: raise ValueError(message)


def read(path, maximum):
    path = Path(path).absolute()
    require(not any(part.is_symlink() for part in (path, *path.parents)), "bundle input contains symlink")
    require(path.is_file() and path.stat().st_nlink == 1 and path.stat().st_size <= maximum, "invalid bundle input")
    with path.open("rb") as stream: raw = stream.read(maximum + 1)
    require(len(raw) <= maximum, "bundle input grew beyond bound")
    return raw


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def build(cli, library, source_commit, output):
    output = Path(output).absolute()
    require(not any(part.is_symlink() for part in (output, *output.parents)) and not output.exists(), "bundle output exists or links")
    require(type(source_commit) is str and re.fullmatch("[a-f0-9]{40}", source_commit), "source commit must be exact")
    binaries = [read(cli, MAX_BINARY), read(library, MAX_BINARY)]
    require(all(len(raw) >= 64 and raw[:6] == b"\x7fELF\x02\x01" and raw[18:20] == b"\x3e\x00" for raw in binaries), "expected Linux x86_64 ELF binaries")
    template = json.loads(read(ROOT / "packaging/linux/desktop-runtime.json", 16384))
    template["cliSha256"] = sha(binaries[0])
    worker = read(ROOT / "packaging/linux/compatforge-debug-worker.py", 256 * 1024).replace(b"\r\n", b"\n")
    template["debuggerRuntime"]["worker"]["sha256"] = "sha256:" + sha(worker)
    provenance = {"schemaVersion": 1, "sourceCommit": source_commit, "cargoLockSha256": sha(read(ROOT / "Cargo.lock", 4 * 1024 * 1024)),
                  "distribution": "local-candidate-only", "components": [
                      {"name": "CompatForge", "license": "NOASSERTION", "source": "https://github.com/a1112/CompatForge", "note": "Repository has no project license declaration; no public redistribution is asserted."},
                      {"name": "Wine", "version": "11.14-2", "license": "LGPL-2.1-or-later", "source": "https://gitlab.winehq.org/wine/wine/-/tree/wine-11.14"},
                      {"name": "Noto CJK", "version": "20240730-1", "license": "OFL-1.1", "source": "https://github.com/notofonts/noto-cjk"},
                      {"name": "Python", "license": "PSF-2.0", "source": "https://www.python.org/"},
                      {"name": "GDB", "version": "17.2", "license": "GPL-3.0-or-later", "source": "https://sourceware.org/gdb/"}]}
    payloads = {
        "usr/bin/compatforge-cli": (binaries[0], 0o755),
        "usr/libexec/forge/compatforge-cli": (binaries[0], 0o755),
        "usr/lib/compatforge/libcompatforge.so": (binaries[1], 0o755),
        "usr/lib/compatforge/compatforge-debug-worker.py": (worker, 0o755),
        "usr/libexec/compatforge/user-init": (read(ROOT / "tools/linux_user_init.py", 128 * 1024).replace(b"\r\n", b"\n"), 0o755),
        "usr/lib/systemd/user/compatforge.service": (read(ROOT / "packaging/linux/compatforge.service", 16384).replace(b"\r\n", b"\n"), 0o644),
        "usr/share/compatforge/linux-desktop.json": (canonical(template), 0o644),
        "usr/share/compatforge/desktop-provenance.json": (canonical(provenance), 0o644),
        "usr/share/compatforge/linux-applications.json": (read(ROOT / "packaging/linux/applications.json", 16384).replace(b"\r\n", b"\n"), 0o644),
    }
    receipt = {"schemaVersion": 2, "kind": "compatforge-linux-desktop", "target": "x86_64-linux-gnu", "sourceCommit": source_commit,
               "cargoLockSha256": provenance["cargoLockSha256"], "files": {name: {"sha256": sha(data), "size": len(data), "mode": mode} for name, (data, mode) in payloads.items()}}
    output.mkdir(mode=0o755)
    for name, (raw, mode) in payloads.items():
        path = output / name; path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        path.chmod(mode)
    (output / "bundle.json").write_bytes(canonical(receipt))
    (output / "bundle.json").chmod(0o644)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "library", "output"): parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    build(args.cli, args.library, args.source_commit, args.output)
    print(json.dumps({"bundleSha256": sha((args.output / "bundle.json").read_bytes())}))


if __name__ == "__main__":
    try: main()
    except (ValueError, OSError) as error:
        print("compatforge.bundle.rejected: " + str(error), file=sys.stderr); sys.exit(1)
