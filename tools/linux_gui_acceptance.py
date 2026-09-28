#!/usr/bin/env python3
"""Repeatable real Linux service transactions and observed-file reboot checks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

CLI = "/usr/bin/compatforge-cli"
APP_IDS = ("7zip", "notepad-plus-plus", "sumatrapdf")
MAX_REPLY = 16 * 1024 * 1024
ASSETS = Path(__file__).resolve().parents[1] / "packaging/linux/applications.json"


def require(condition, message):
    if not condition: raise ValueError(message)


def file_sha(path):
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink() and path.is_file(), "expected absolute regular file")
    require(path.stat().st_size <= 512 * 1024 * 1024, "acceptance file exceeds limit")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""): digest.update(block)
    return digest.hexdigest()


def verify_assets(directory):
    descriptor = json.loads(ASSETS.read_bytes())
    require(descriptor["schemaVersion"] == 1 and tuple(item["id"] for item in descriptor["applications"]) == APP_IDS,
            "acceptance asset descriptor differs")
    result = {}
    for item in descriptor["applications"]:
        path = Path(directory).absolute() / item["file"]
        require(file_sha(path) == item["sha256"], "installer digest mismatch: " + item["id"])
        result[item["id"]] = path
    return result


class Client:
    def __init__(self, output):
        self.output = Path(output).absolute()
        require(not self.output.exists(), "acceptance output already exists")
        self.output.mkdir(mode=0o700)
        self.sequence = 0

    def run(self, arguments):
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            result = subprocess.run([CLI, *arguments], stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    timeout=75, check=False)
            require(stdout.tell() <= MAX_REPLY and stderr.tell() <= 65536, "client output exceeds bounds")
            stdout.seek(0); stderr.seek(0)
            raw = stdout.read(MAX_REPLY + 1); errors = stderr.read(65537)
        self.sequence += 1
        event = {"sequence": self.sequence, "command": arguments, "exitCode": result.returncode,
                 "stdout": raw.decode("utf-8", errors="replace"), "stderr": errors.decode("utf-8", errors="replace")}
        with (self.output / "client.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n"); stream.flush(); os.fsync(stream.fileno())
        require(result.returncode == 0, "CompatForge client rejected request; see client.jsonl")
        return json.loads(raw)

    def call(self, operation, payload):
        request = {"schemaVersion": "1", "requestId": "acceptance-" + str(self.sequence), "operation": operation, "payload": payload}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", dir=self.output, delete=False, encoding="utf-8") as stream:
            json.dump(request, stream); path = Path(stream.name)
        try:
            response = self.run(["service-call", str(path)])
            require(response.get("operation") == operation and response.get("schemaVersion") == "1", "response identity differs")
            return response["result"]
        finally: path.unlink()

    def selected(self):
        return {app: self.call("applications.generations", {"id": app}).get("selectedGeneration") for app in APP_IDS}

    def wait(self, job, expected, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            poll = self.call("jobs.poll", {"id": job["id"], "timeoutMilliseconds": 200})
            result = poll["job"]
            if result["status"] in ("succeeded", "cancelled", "failed") and poll["streamEnded"] is True:
                require(result["status"] == expected, "job terminal state differs: " + result["status"])
                return result
            time.sleep(0.2)
        raise ValueError("acceptance job did not reach a terminal state")

    def receipt(self, name, value):
        value.update(schemaVersion=1, cliSha256=file_sha(Path(CLI)), runnerSha256=file_sha(Path(__file__).resolve()))
        with (self.output / name).open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())


def session_environment():
    result = {name: os.environ[name] for name in ("DISPLAY", "XAUTHORITY") if name in os.environ}
    require("DISPLAY" in result and re.fullmatch(r":[0-9]+(?:\.[0-9]+)?", result["DISPLAY"]), "run inside the real local graphical session")
    if "XAUTHORITY" in result: require(Path(result["XAUTHORITY"]).is_absolute(), "XAUTHORITY must be absolute")
    return result


def submit_install(client, app, path):
    return client.call("jobs.submit", {"schemaVersion": "1", "applicationId": app, "kind": "install",
                                      "executablePath": str(path), "environmentOverrides": session_environment()})


def exercise(client, assets):
    """Real installation/cancellation/update/rollback/uninstall without synthetic Save claims."""
    paths = verify_assets(assets)
    for app in APP_IDS: client.wait(submit_install(client, app, paths[app]), "succeeded")
    first = client.selected()
    require(all(first.values()), "installed applications have no selected generation")
    export = client.run(["desktop-export"])
    require({entry["applicationId"] for entry in export["entries"]} >= set(APP_IDS), "launcher export missing application")
    cancelled = submit_install(client, "7zip", paths["7zip"])
    client.call("jobs.cancel", {"id": cancelled["id"]}); client.wait(cancelled, "cancelled")
    require(client.selected() == first, "cancelled installation changed selection")
    client.wait(submit_install(client, "7zip", paths["7zip"]), "succeeded")
    second = client.selected()["7zip"]
    require(second != first["7zip"], "update did not create a separate generation")
    client.call("applications.rollback", {"applicationId": "7zip", "generationId": first["7zip"]})
    client.call("applications.uninstall", {"id": "7zip"})
    require(client.selected()["7zip"] is None, "uninstall did not deactivate")
    client.call("applications.rollback", {"applicationId": "7zip", "generationId": first["7zip"]})
    require(client.selected() == first, "rollback did not restore original selection")
    client.receipt("transactions.json", {"result": "passed", "scope": "real-service-transactions",
                                        "selectedGenerations": first, "updatedGeneration": second,
                                        "guiSaveAndWindowObservation": "required-separately", "reboot": "pending"})


def snapshot(client, files):
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    require(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot_id), "invalid kernel boot identity")
    require(1 <= len(files) <= 32 and len(set(files)) == len(files), "provide 1..32 distinct observed application files")
    return {"bootId": boot_id, "selectedGenerations": client.selected(),
            "files": {str(Path(path).absolute()): file_sha(Path(path).absolute()) for path in files},
            "fileOrigin": "external-GUI-observation-required; runner never writes application files"}

def compare_reboot(before, after):
    require(before["bootId"] != after["bootId"], "kernel boot identity has not changed")
    require(before["selectedGenerations"] == after["selectedGenerations"], "selected application generations changed")
    require(bool(before["files"]) and before["files"] == after["files"], "observed application files changed")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("exercise"); install.add_argument("--assets", type=Path, required=True)
    launch = commands.add_parser("launch"); launch.add_argument("--app", choices=APP_IDS, required=True); launch.add_argument("files", nargs="*", type=Path)
    cancel = commands.add_parser("cancel"); cancel.add_argument("--job", required=True)
    commands.add_parser("status")
    before = commands.add_parser("before-reboot"); before.add_argument("files", nargs="+", type=Path)
    after = commands.add_parser("after-reboot"); after.add_argument("--before", type=Path, required=True)
    args = parser.parse_args()
    require(sys.platform == "linux" and os.getuid() != 0 and os.getuid() == os.geteuid(), "run as ordinary Linux desktop user")
    os.umask(0o077)
    client = Client(args.output)
    if args.command == "exercise": exercise(client, args.assets)
    elif args.command == "launch":
        response = client.run(["desktop-launch", args.app, "main", "--", *[str(path.absolute()) for path in args.files]])
        client.receipt("launch.json", {"applicationId": args.app, "job": response["result"], "windowObservation": "required-separately"})
    elif args.command == "cancel":
        client.call("jobs.cancel", {"id": args.job}); client.wait({"id": args.job}, "cancelled")
        client.receipt("cancel.json", {"jobId": args.job, "result": "cancelled-and-joined"})
    elif args.command == "status":
        client.receipt("status.json", {"selectedGenerations": client.selected(), "jobs": client.call("jobs.list", {})})
    elif args.command == "before-reboot": client.receipt("before-reboot.json", snapshot(client, args.files))
    else:
        require(args.before.is_file() and args.before.stat().st_size <= 65536, "missing or oversized reboot receipt")
        before = json.loads(args.before.read_bytes()); after = snapshot(client, list(before["files"]))
        compare_reboot(before, after); after["result"] = "new-kernel-boot-and-file-persistence-verified"
        client.receipt("after-reboot.json", after)


if __name__ == "__main__":
    try: main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("linux-gui-acceptance.failed: " + str(error), file=sys.stderr); sys.exit(1)
