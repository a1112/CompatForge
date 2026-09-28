#!/usr/bin/env python3
"""Isolated ForgeOS guest acceptance for managed WineDbg via the real CLI/daemon.

Requires a test-only service.json with a reviewed sourceMap and sourceSubstitution,
and the three pinned C fixture files under /home/forge/forge-debug-probe.
"""

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import time

APP = "forge-debug-probe"
ROOT = Path("/home/forge/forge-debug-probe")
EXE_SHA = "ea376c6a96392c9d369cdd392fcace3d53572e16552c4907e3a6fac7829d2f19"
INSTALLER_SHA = "fda570c4e7a0041d95cd33b2d5c2b74b31782cbc3a12aa059c233cde93c3f55b"
MAX = 64 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        digest = hashlib.sha256()
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def call(cli, operation, payload, *, allow_failure=False):
    request = {"schemaVersion": "1", "requestId": f"debug-acceptance-{time.monotonic_ns()}",
               "operation": operation, "payload": payload}
    with tempfile.NamedTemporaryFile("w", suffix=".json", dir=ROOT, delete=False) as file:
        json.dump(request, file)
        path = Path(file.name)
    try:
        result = subprocess.run([cli, "service-call", str(path)], capture_output=True,
                                stdin=subprocess.DEVNULL, timeout=75)
    finally:
        path.unlink()
    require(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 65536,
            "service reply exceeded bound")
    if result.returncode:
        if allow_failure:
            return None
        raise RuntimeError(f"{operation} rejected: {result.stderr.decode(errors='replace')[:1000]}")
    reply = json.loads(result.stdout)
    require(reply["operation"] == operation and reply["schemaVersion"] == "1", "service reply identity differs")
    return reply["result"]


class DapClient:
    def __init__(self, process):
        self.process = process
        self.selector = selectors.DefaultSelector()
        self.selector.register(process.stdout, selectors.EVENT_READ)
        self.pending = bytearray()
        self.responses = {}
        self.events = deque()
        self.seq = 0
        self.last_output_seq = 0
        self.transcript = []

    def send(self, command, arguments=None):
        self.seq += 1
        message = {"seq": self.seq, "type": "request", "command": command, "arguments": arguments or {}}
        raw = json.dumps(message, separators=(",", ":")).encode()
        require(len(raw) <= MAX, "oversized DAP request")
        self.process.stdin.write(f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
        self.process.stdin.flush()
        return self.seq

    def pump(self, deadline):
        while True:
            marker = self.pending.find(b"\r\n\r\n")
            if marker >= 0:
                header = bytes(self.pending[:marker])
                require(header.startswith(b"Content-Length: ") and b"\r\n" not in header and len(header) <= 128,
                        "malformed DAP response header")
                length = int(header.removeprefix(b"Content-Length: "))
                require(0 < length <= MAX, "oversized DAP response")
                if len(self.pending) >= marker + 4 + length:
                    raw = bytes(self.pending[marker + 4:marker + 4 + length])
                    del self.pending[:marker + 4 + length]
                    message = json.loads(raw)
                    sequence = message.get("seq")
                    require(type(sequence) is int and sequence == self.last_output_seq + 1,
                            "public DAP output sequence is not monotonic")
                    self.last_output_seq = sequence
                    if message.get("type") == "request":
                        raise RuntimeError("backend reverse request escaped private gateway")
                    # Keep only protocol type, command, status and stop reason.
                    # Source paths, process IDs and variable contents stay out.
                    record = {"type": message.get("type")}
                    if message.get("type") == "response":
                        record.update(command=message.get("command"), success=message.get("success"))
                    elif message.get("type") == "event":
                        record.update(event=message.get("event"))
                        if message.get("event") == "stopped":
                            record["reason"] = message.get("body", {}).get("reason")
                    require(len(self.transcript) < 128, "DAP transcript exceeded bound")
                    self.transcript.append(record)
                    if message.get("type") == "response":
                        self.responses[message["request_seq"]] = message
                    elif message.get("type") == "event":
                        self.events.append(message)
                    else:
                        raise RuntimeError("unknown DAP response type")
                    return
            require(len(self.pending) <= MAX + 128, "DAP response stream exceeded bound")
            remaining = deadline - time.monotonic()
            require(remaining > 0 and self.selector.select(remaining), "DAP response timeout")
            chunk = os.read(self.process.stdout.fileno(), 8192)
            require(chunk, "debug adapter closed unexpectedly")
            self.pending.extend(chunk)

    def reply(self, seq, timeout=30, *, success=True):
        deadline = time.monotonic() + timeout
        while seq not in self.responses:
            self.pump(deadline)
        result = self.responses.pop(seq)
        require(result.get("success") is success, f"DAP reply failed: {result}")
        return result

    def event(self, name, reason=None, timeout=30):
        deadline = time.monotonic() + timeout
        while True:
            for message in list(self.events):
                if message.get("event") == name and (reason is None or message.get("body", {}).get("reason") == reason):
                    self.events.remove(message)
                    return message
            self.pump(deadline)


def install(cli):
    installer = ROOT / "debug-installer.exe"
    executable = ROOT / "windows_debug_probe.exe"
    require(sha(installer) == INSTALLER_SHA and sha(executable) == EXE_SHA, "fixture digest mismatch")
    definition = {"schemaVersion": "1", "id": APP, "name": "Forge Debug Probe", "version": "1.0",
                  "publisher": "ForgeOS Acceptance", "category": "Development", "bottleId": APP,
                  "installer": {"fileName": installer.name, "sha256": INSTALLER_SHA},
                  "launchers": [{"id": "main", "name": "Forge Debug Probe",
                                 "executable": "Program Files/Forge Debug Probe/probe.exe"}]}
    call(cli, "applications.upsert", {"application": definition})
    environment = {"DISPLAY": os.environ["DISPLAY"]}
    if "XAUTHORITY" in os.environ:
        environment["XAUTHORITY"] = os.environ["XAUTHORITY"]
    job = call(cli, "jobs.submit", {"schemaVersion": "1", "applicationId": APP, "kind": "install",
                                    "executablePath": str(installer), "environmentOverrides": environment})
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        poll = call(cli, "jobs.poll", {"id": job["id"], "timeoutMilliseconds": 200})
        if poll["job"]["status"] in ("succeeded", "failed", "cancelled") and poll["streamEnded"]:
            require(poll["job"]["status"] == "succeeded", f"managed install failed: {poll['job']}")
            break
    else:
        raise RuntimeError("managed install timed out")
    selected = call(cli, "applications.generations", {"id": APP})["selectedGeneration"]
    require(isinstance(selected, str) and selected.startswith("gen-job-"), "no selected debug generation")
    return selected


def debug(cli, selected):
    public_source = ROOT / "public/windows_debug_probe.c"
    require(public_source.is_file() and public_source.read_bytes() == (ROOT / "windows_debug_probe.c").read_bytes(),
            "public source copy differs")
    launch = {"schemaVersion": "1", "command": "launch",
              "target": {"applicationId": APP, "generationId": selected, "launcherId": "main"}}
    with tempfile.NamedTemporaryFile("w", suffix=".json", dir=ROOT, delete=False) as file:
        json.dump(launch, file)
        path = Path(file.name)
    process = subprocess.Popen([cli, "debug-adapter", str(path)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=os.environ.copy())
    client = DapClient(process)
    try:
        init = client.reply(client.send("initialize", {"adapterID": "gdb", "clientID": "compatforge"}))
        require(init["body"]["supportsConfigurationDoneRequest"] is True, "DAP capability missing")
        require(not init["body"].get("supportsEvaluateForHovers", False), "unsafe evaluate advertised")
        client.reply(client.send("evaluate", {"expression": "shell touch /tmp/unsafe", "context": "repl"}), success=False)
        attach = client.send("launch", {"type": "compatforge", "request": "launch",
                                        "name": "Managed Windows C app"})
        client.event("initialized")
        points = client.reply(client.send("setBreakpoints", {"source": {"path": str(public_source),
                                                                            "name": "windows_debug_probe.c"},
                                                              "breakpoints": [{"line": 17}]}))
        # WineDbg has not loaded the program image yet. GDB reports a pending
        # breakpoint here and resolves it when the initial continue runs.
        point = points["body"]["breakpoints"][0]
        require(point.get("id") and point.get("reason") in (None, "pending"),
                f"source breakpoint was rejected: {points}")
        if "source" in point:
            require(point["source"]["path"] == str(public_source), "breakpoint source was not reverse mapped")
        client.reply(client.send("configurationDone"))
        client.reply(attach)
        client.reply(client.send("continue", {"threadId": 1}))
        stopped = client.event("stopped", "breakpoint")
        thread = stopped["body"]["threadId"]
        stack = client.reply(client.send("stackTrace", {"threadId": thread, "levels": 8}))
        names = [frame["name"] for frame in stack["body"]["stackFrames"]]
        require(names[0] == "main", f"main breakpoint stack mismatch: {names}")
        require(stack["body"]["stackFrames"][0]["source"]["path"] == str(public_source),
                "stack source was not reverse mapped")
        client.reply(client.send("stepIn", {"threadId": thread}))
        client.event("stopped", "step")
        stack = client.reply(client.send("stackTrace", {"threadId": thread, "levels": 8}))
        require(stack["body"]["stackFrames"][0]["name"] == "outer", "stepIn did not enter outer")
        client.reply(client.send("stepIn", {"threadId": thread}))
        client.event("stopped", "step")
        stack = client.reply(client.send("stackTrace", {"threadId": thread, "levels": 8}))
        names = [frame["name"] for frame in stack["body"]["stackFrames"]]
        require(names[:3] == ["inner", "outer", "main"], f"nested stack mismatch: {names}")
        require(stack["body"]["stackFrames"][0]["source"]["path"] == str(public_source),
                "nested source was not reverse mapped")
        client.reply(client.send("next", {"threadId": thread}))
        client.event("stopped", "step")
        stack = client.reply(client.send("stackTrace", {"threadId": thread, "levels": 8}))
        frame = stack["body"]["stackFrames"][0]
        require(frame["line"] == 8, "source step line mismatch")
        scopes = client.reply(client.send("scopes", {"frameId": frame["id"]}))
        reference = next(scope["variablesReference"] for scope in scopes["body"]["scopes"] if scope["name"] == "Locals")
        variables = client.reply(client.send("variables", {"variablesReference": reference}))
        value = {item["name"]: item["value"] for item in variables["body"]["variables"]}["local_value"]
        require(value == "17", "local variable differs")
        client.reply(client.send("stepOut", {"threadId": thread}))
        client.event("stopped", "step")
        stack = client.reply(client.send("stackTrace", {"threadId": thread, "levels": 8}))
        require(stack["body"]["stackFrames"][0]["name"] == "outer", "stepOut did not return to outer")
        client.reply(client.send("stepOut", {"threadId": thread}))
        client.event("stopped", "step")
        stack = client.reply(client.send("stackTrace", {"threadId": thread, "levels": 8}))
        require(stack["body"]["stackFrames"][0]["name"] == "main", "stepOut did not return to main")
        client.reply(client.send("continue", {"threadId": thread}))
        client.reply(client.send("pause", {"threadId": thread}))
        paused = client.event("stopped", timeout=10)
        require(paused["body"]["reason"] == "pause", f"pause produced {paused['body']['reason']}")
        client.reply(client.send("continue", {"threadId": thread}))
        client.event("stopped", "signal")
        client.reply(client.send("disconnect"))
        process.stdin.close()
        require(process.wait(timeout=10) == 0, "debug adapter did not cleanly exit")
        return {"breakpointVerified": True, "initialBreakpointPending": not point.get("verified", False),
                "stack": names[:3], "stepInVerified": True, "stepOutVerified": True,
                "pauseVerified": True, "sourceReverseMapped": True, "dapOutputSequenceMonotonic": True,
                "stepLine": frame["line"],
                "localValue": value, "exceptionStopReason": "signal", "disconnectSucceeded": True,
                "unsafeEvaluateRejected": True, "sanitizedDapTranscript": client.transcript}
    finally:
        path.unlink()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", default="/usr/bin/compatforge-cli")
    parser.add_argument("--service-config", default="/home/forge/.config/compatforge/service.json")
    parser.add_argument("--output", required=True)
    parser.add_argument("--existing-generation")
    args = parser.parse_args()
    output = Path(args.output)
    require(not output.exists(), "refusing to replace acceptance receipt")
    selected = (call(args.cli, "applications.generations", {"id": APP})["selectedGeneration"]
                if args.existing_generation == "auto" else args.existing_generation or install(args.cli))
    observation = debug(args.cli, selected)
    service = json.loads(Path(args.service_config).read_text())
    session_root = Path(service["serviceRoot"]) / "debug-sessions"
    require(not session_root.exists() or not list(session_root.iterdir()), "debug session files remain")
    require(b":25000 " not in subprocess.run(["/usr/bin/ss", "-ltn"], capture_output=True, check=True).stdout,
            "WineDbg listener escaped private network namespace")
    receipt = {"schemaVersion": 1, "selectedGeneration": selected, "cliSha256": sha(args.cli),
               "installerSha256": INSTALLER_SHA, "fixtureSha256": EXE_SHA,
               "sourceSha256": sha(ROOT / "windows_debug_probe.c"),
               "serviceConfigSha256": sha(args.service_config),
               "workerSha256": sha(service["debuggerRuntime"]["worker"]["path"]),
               "gdbSha256": sha(service["debuggerRuntime"]["gdb"]["path"]),
               "observation": observation, "privateListenerAbsent": True, "sessionDirectoryEmpty": True}
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
