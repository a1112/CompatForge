"""Prepare an isolated direct-worker fixture config in the disposable guest."""

import hashlib
import json
from pathlib import Path
import sys

source, directory = map(Path, sys.argv[1:])
target = directory / "worker-config.json"
assert not target.exists()
config = json.loads(source.read_bytes())
program = directory / "windows_debug_probe-v2.exe"
code = directory / "windows_debug_probe.c"
assert program.is_file() and code.is_file()
config["program"] = str(program)
config["backendSources"] = [str(code)]
config["sourceSubstitution"]["installed"] = str(directory)
config["sha256"]["program"] = hashlib.sha256(program.read_bytes()).hexdigest()
target.write_text(json.dumps(config, indent=2) + "\n")
