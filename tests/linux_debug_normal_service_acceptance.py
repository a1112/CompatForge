#!/usr/bin/env python3
"""Check the installed debugger under the ordinary user service after test cleanup."""

import argparse
import json
from pathlib import Path
import subprocess

from linux_debug_service_acceptance import APP, call, require, sha


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "refusing to replace ordinary service receipt")
    before = json.loads(args.before.read_bytes())
    require(subprocess.run(["systemctl", "--user", "is-active", "compatforge.service"],
                           capture_output=True, check=True).stdout.strip() == b"active", "ordinary service inactive")
    config_path = Path.home() / ".config/compatforge/service.json"
    service = json.loads(config_path.read_bytes())
    require(service["debuggerRuntime"]["sourceMap"] == {}, "ordinary service config was modified")
    cli = "/usr/bin/compatforge-cli"
    require(sha(cli) == before["cliSha256"], "CLI differs from tested image")
    require(sha(service["debuggerRuntime"]["worker"]["path"]) == before["workerSha256"],
            "worker differs from tested image")
    selected = call(cli, "applications.generations", {"id": APP})["selectedGeneration"]
    require(selected == before["selectedGeneration"], "selected generation changed")
    launch = {"schemaVersion": "1", "command": "launch",
              "target": {"applicationId": APP, "generationId": selected, "launcherId": "main"}}
    handle = call(cli, "debug.session", launch)
    call(cli, "debug.session", {"schemaVersion": "1", "command": "disconnect", "handle": handle})
    sessions = Path(service["serviceRoot"]) / "debug-sessions"
    require(not sessions.exists() or not list(sessions.iterdir()), "owned session directory remains")
    require(b":25000 " not in subprocess.run(["/usr/bin/ss", "-ltn"], capture_output=True, check=True).stdout,
            "private WineDbg listener escaped namespace")
    result = {"schemaVersion": 1, "selectedGeneration": selected, "cliSha256": sha(cli),
              "workerSha256": before["workerSha256"], "serviceConfigSha256": sha(config_path),
              "ordinaryServiceActive": True, "launchDisconnectSucceeded": True,
              "sessionDirectoryEmpty": True, "privateListenerAbsent": True}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
