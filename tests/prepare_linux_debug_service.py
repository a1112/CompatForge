#!/usr/bin/env python3
"""Create an isolated source-mapped debug service config from the installed pin."""

import json
import os
from pathlib import Path
import sys

source, output = map(Path, sys.argv[1:])
assert output.is_absolute() and not output.exists()
service = json.loads(source.read_bytes())
debugger = service["debuggerRuntime"]
assert debugger["sourceMap"] == {} and "sourceSubstitution" not in debugger
root = "/home/forge/forge-debug-probe"
public = root + "/public/windows_debug_probe.c"
backend = root + "/windows_debug_probe.c"
assert Path(public).is_file() and Path(backend).is_file()
assert Path(public).read_bytes() == Path(backend).read_bytes()
debugger["sourceMap"] = {public: backend}
debugger["sourceSubstitution"] = {"compiled": "/srv/forge-apps-build/sources", "installed": root}
descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "wb") as stream:
    stream.write((json.dumps(service, sort_keys=True, separators=(",", ":")) + "\n").encode())
