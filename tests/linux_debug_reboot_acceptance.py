#!/usr/bin/env python3
"""Verify the managed debugger and selected generation after a normal VM reboot."""

import argparse
import json
from pathlib import Path
import subprocess

from linux_debug_service_acceptance import APP, ROOT, call, require, sha


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--before", type=Path, required=True)
    parser.add_argument("--boot-id-before", required=True)
    parser.add_argument("--service-sha-before", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), "refusing to replace reboot receipt")
    before = json.loads(args.before.read_bytes())
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    require(boot_id != args.boot_id_before, "VM did not reboot")
    service_config = Path.home() / ".config/compatforge/service.json"
    require(sha(service_config) == args.service_sha_before, "ordinary service config changed")
    active = subprocess.run(["systemctl", "--user", "is-active", "compatforge.service"],
                            capture_output=True, check=True).stdout.strip() == b"active"
    require(active, "ordinary service is inactive")
    cli = "/usr/bin/compatforge-cli"
    require(sha(cli) == before["cliSha256"], "installed CLI differs after reboot")
    service = json.loads(service_config.read_bytes())
    require(sha(service["debuggerRuntime"]["worker"]["path"]) == before["workerSha256"],
            "installed worker differs after reboot")
    require(sha(service["debuggerRuntime"]["gdb"]["path"]) == before["gdbSha256"],
            "installed GDB differs after reboot")
    selected = call(cli, "applications.generations", {"id": APP})["selectedGeneration"]
    require(selected == before["selectedGeneration"], "selected managed generation changed")
    launch = {"schemaVersion": "1", "command": "launch",
              "target": {"applicationId": APP, "generationId": selected, "launcherId": "main"}}
    handle = call(cli, "debug.session", launch)
    call(cli, "debug.session", {"schemaVersion": "1", "command": "disconnect", "handle": handle})
    session_root = Path(service["serviceRoot"]) / "debug-sessions"
    require(not session_root.exists() or not list(session_root.iterdir()), "debug session files remain")
    require(b":25000 " not in subprocess.run(["/usr/bin/ss", "-ltn"], capture_output=True, check=True).stdout,
            "debugger listener escaped private namespace")
    receipt = {"schemaVersion": 1, "bootIdBefore": args.boot_id_before, "bootIdAfter": boot_id,
               "selectedGeneration": selected, "serviceConfigSha256": sha(service_config),
               "cliSha256": sha(cli), "workerSha256": before["workerSha256"],
               "gdbSha256": before["gdbSha256"], "ordinaryServiceActive": True,
               "debugLaunchDisconnectAfterReboot": True, "sessionDirectoryEmpty": True,
               "privateListenerAbsent": True, "fixtureSha256": sha(ROOT / "windows_debug_probe.exe")}
    require(receipt["fixtureSha256"] == before["fixtureSha256"], "test fixture changed")
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
