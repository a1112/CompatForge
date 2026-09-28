"""End-to-end acceptance for the packaged private DAP worker in a test guest."""

from __future__ import annotations

import argparse
from collections import deque
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time


def owned_prefix_pids(prefix: str) -> list[int]:
    needle = f"WINEPREFIX={prefix}".encode()
    result = []
    for item in Path("/proc").iterdir():
        if item.name.isdigit():
            try:
                if needle in (item / "environ").read_bytes().split(b"\0"):
                    result.append(int(item.name))
            except OSError:
                pass
    return result


def assert_private_cleanup(prefix: str) -> None:
    for _ in range(50):
        if not owned_prefix_pids(prefix):
            break
        time.sleep(0.1)
    if owned_prefix_pids(prefix):
        raise RuntimeError("debugger prefix process escaped private worker")
    if b":25000 " in subprocess.run(["/usr/bin/ss", "-ltn"], capture_output=True, check=True).stdout:
        raise RuntimeError("private WineDbg listener escaped namespace")


class PlannedCrash(Exception):
    pass


class WorkerClient:
    def __init__(self, child: subprocess.Popen[bytes]):
        self.child = child
        self.bytes = bytearray()
        self.selector = selectors.DefaultSelector()
        self.selector.register(child.stdout, selectors.EVENT_READ)
        self.messages: deque[dict] = deque()
        self.responses: dict[int, dict] = {}
        self.events: deque[dict] = deque()
        self.seq = 0
        self.control_seq = 0

    def control(self, value: dict, timeout: float = 15) -> dict:
        self.control_seq += 1
        value = {**value, "requestId": self.control_seq}
        assert self.child.stdin is not None
        self.child.stdin.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")
        self.child.stdin.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if b"\n" in self.bytes:
                raw, _, rest = self.bytes.partition(b"\n")
                self.bytes = bytearray(rest)
                result = json.loads(raw)
                if result.get("requestId") != self.control_seq:
                    raise RuntimeError("worker reply identity differs")
                self.messages.extend(result.get("messages", []))
                return result
            if not self.selector.select(max(0, deadline - time.monotonic())):
                break
            assert self.child.stdout is not None
            block = os.read(self.child.stdout.fileno(), 8192)
            if not block or len(self.bytes) + len(block) > 65_536:
                raise RuntimeError("worker exited or exceeded output bound")
            self.bytes.extend(block)
        raise TimeoutError("worker control timeout")

    def send(self, command: str, arguments: dict | None = None) -> int:
        self.seq += 1
        self.control({"op": "send", "message": {"seq": self.seq, "type": "request", "command": command,
                                               "arguments": arguments or {}}})
        return self.seq

    def next_message(self, timeout: float = 15) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.messages:
                return self.messages.popleft()
            self.control({"op": "poll"}, min(1, deadline - time.monotonic()))
        raise TimeoutError("DAP event timeout")

    def reply(self, seq: int) -> dict:
        if seq in self.responses:
            result = self.responses.pop(seq)
        else:
            deadline = time.monotonic() + 15
            while True:
                message = self.next_message(max(0, deadline - time.monotonic()))
                if message.get("type") == "response":
                    if message.get("request_seq") == seq:
                        result = message
                        break
                    self.responses[message["request_seq"]] = message
                elif message.get("type") == "event":
                    self.events.append(message)
        assert result.get("success") is True, result
        return result

    def event(self, name: str, reason: str | None = None) -> dict:
        deadline = time.monotonic() + 15
        while True:
            message = self.events.popleft() if self.events else self.next_message(max(0, deadline - time.monotonic()))
            if message.get("type") == "response":
                self.responses[message["request_seq"]] = message
            elif message.get("type") == "event" and message.get("event") == name:
                if reason is None or message.get("body", {}).get("reason") == reason:
                    return message


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--worker", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--crash", action="store_true")
    parser.add_argument("--terminate", action="store_true")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    if Path(args.output).exists():
        raise RuntimeError("refusing to overwrite receipt")
    child = subprocess.Popen(["/usr/bin/unshare", "-Urnpf", "--mount-proc", "--kill-child",
                              "/usr/bin/python3", args.worker], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True,
                             env={"HOME": os.environ["HOME"], "USER": os.environ["USER"],
                                  "LOGNAME": os.environ["USER"], "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                                  "XDG_RUNTIME_DIR": os.environ["XDG_RUNTIME_DIR"]})
    client = WorkerClient(child)
    try:
        assert client.control(config, 30) == {"requestId": 1, "ready": True}
        if args.crash:
            child.kill()
            raise PlannedCrash
        if args.terminate:
            os.killpg(child.pid, signal.SIGTERM)
            raise PlannedCrash
        init = client.reply(client.send("initialize", {"adapterID": "gdb", "clientID": "compatforge",
                                                       "linesStartAt1": True, "columnsStartAt1": True}))
        assert init["body"]["supportsConfigurationDoneRequest"] is True
        attach = client.send("attach", {"program": config["program"], "target": "127.0.0.1:25000"})
        client.event("initialized")
        client.reply(client.send("setBreakpoints", {"source": {"path": config["backendSources"][0]},
                                                    "breakpoints": [{"line": 7}]}))
        client.reply(client.send("configurationDone"))
        client.reply(attach)
        client.reply(client.send("continue", {"threadId": 1}))
        stopped = client.event("stopped", "breakpoint")
        thread = stopped["body"]["threadId"]
        stack = client.reply(client.send("stackTrace", {"threadId": thread, "startFrame": 0, "levels": 8}))
        names = [item["name"] for item in stack["body"]["stackFrames"]]
        assert names[:3] == ["inner", "outer", "main"]
        client.reply(client.send("next", {"threadId": thread}))
        client.event("stopped", "step")
        stack = client.reply(client.send("stackTrace", {"threadId": thread, "startFrame": 0, "levels": 8}))
        frame = stack["body"]["stackFrames"][0]
        assert frame["line"] == 8
        scopes = client.reply(client.send("scopes", {"frameId": frame["id"]}))
        reference = next(scope["variablesReference"] for scope in scopes["body"]["scopes"] if scope["name"] == "Locals")
        variables = client.reply(client.send("variables", {"variablesReference": reference}))
        assert {item["name"]: item["value"] for item in variables["body"]["variables"]}["local_value"] == "17"
        client.reply(client.send("continue", {"threadId": thread}))
        client.event("stopped", "signal")
        client.reply(client.send("disconnect", {"terminateDebuggee": False}))
        assert client.control({"op": "shutdown"}) == {"requestId": client.control_seq, "stopped": True}
    except PlannedCrash:
        pass
    finally:
        if child.stdin:
            child.stdin.close()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)
        if child.returncode and child.stderr:
            print(child.stderr.read(1024).decode(errors="replace"), file=__import__("sys").stderr)
    assert_private_cleanup(config["prefix"])
    if args.crash or args.terminate:
        receipt = {"workerParentKilled": args.crash, "workerTerminated": args.terminate, "ownedPrefixProcessesAfterCrash": 0,
                   "rootNamespaceListenerAbsent": True}
        Path(args.output).write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt))
        return
    if child.returncode != 0:
        raise RuntimeError("worker did not cleanly exit")
    receipt = {"privateWorkerCompleted": True, "breakpointVerified": True, "stack": names[:3],
               "stepLocalValue": "17", "exceptionStopReason": "signal", "cleanDisconnect": True}
    Path(args.output).write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
