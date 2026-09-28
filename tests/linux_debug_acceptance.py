"""Real WineDbg/GDB DAP probe for an isolated, dedicated Linux test prefix.

This is a developer acceptance runner, not the public debug API. It enters a
new user/network namespace, verifies fixed tool and fixture hashes, and emits
only a sanitized observation record. Run it against a copy of a ready Bottle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

MAX_DAP_BODY = 64 * 1024
PORT = 25000


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def require_digest(path: Path, expected: str) -> None:
    if not path.is_file() or path.is_symlink() or digest(path) != expected:
        raise RuntimeError(f"pinned file is absent or changed: {path.name}")


class DapConnection:
    def __init__(self, child: subprocess.Popen[bytes]) -> None:
        self.child = child
        self.selector = selectors.DefaultSelector()
        assert child.stdout is not None
        self.selector.register(child.stdout, selectors.EVENT_READ)
        self.buffer = b""
        self.seq = 0
        self.responses: dict[int, dict] = {}
        self.events: list[dict] = []

    def send(self, command: str, arguments: dict | None = None) -> int:
        self.seq += 1
        body = json.dumps({"seq": self.seq, "type": "request", "command": command,
                           "arguments": arguments or {}}, separators=(",", ":")).encode()
        if len(body) > MAX_DAP_BODY:
            raise RuntimeError("oversized DAP request")
        assert self.child.stdin is not None
        self.child.stdin.write(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        self.child.stdin.flush()
        return self.seq

    def receive(self, timeout: float = 15) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if b"\r\n\r\n" in self.buffer:
                header, rest = self.buffer.split(b"\r\n\r\n", 1)
                if not header.startswith(b"Content-Length: ") or b"\r\n" in header:
                    raise RuntimeError("unexpected DAP header")
                size = int(header.removeprefix(b"Content-Length: "))
                if not 1 <= size <= MAX_DAP_BODY:
                    raise RuntimeError("oversized DAP response")
                if len(rest) >= size:
                    body, self.buffer = rest[:size], rest[size:]
                    value = json.loads(body)
                    if not isinstance(value, dict):
                        raise RuntimeError("DAP response is not an object")
                    return value
            if len(self.buffer) > MAX_DAP_BODY + 128:
                raise RuntimeError("oversized DAP stream")
            ready = self.selector.select(max(0, deadline - time.monotonic()))
            if not ready:
                break
            assert self.child.stdout is not None
            chunk = os.read(self.child.stdout.fileno(), 8192)
            if not chunk:
                raise RuntimeError("GDB closed DAP before completing the probe")
            self.buffer += chunk
        raise TimeoutError("DAP response timeout")

    def reply(self, seq: int, timeout: float = 15) -> dict:
        if seq in self.responses:
            result = self.responses.pop(seq)
        else:
            deadline = time.monotonic() + timeout
            while True:
                message = self.receive(deadline - time.monotonic())
                if message.get("type") == "response":
                    if message.get("request_seq") == seq:
                        result = message
                        break
                    self.responses[message["request_seq"]] = message
                elif message.get("type") == "event":
                    self.events.append(message)
        if result.get("success") is not True:
            raise RuntimeError(f"DAP {result.get('command')} failed: {result.get('message')}")
        return result

    def event(self, name: str, reason: str | None = None, timeout: float = 15) -> dict:
        deadline = time.monotonic() + timeout
        while True:
            message = self.events.pop(0) if self.events else self.receive(deadline - time.monotonic())
            if message.get("type") == "response":
                self.responses[message["request_seq"]] = message
            elif message.get("type") == "event" and message.get("event") == name:
                if reason is None or message.get("body", {}).get("reason") == reason:
                    return message


def owned_prefix_pids(prefix: Path) -> list[int]:
    match = f"WINEPREFIX={prefix}".encode()
    pids = []
    for item in Path("/proc").iterdir():
        if not item.name.isdigit() or int(item.name) == os.getpid():
            continue
        try:
            if match in (item / "environ").read_bytes().split(b"\0"):
                pids.append(int(item.name))
        except OSError:
            continue
    return pids


def stop_group(child: subprocess.Popen[bytes] | None) -> None:
    if child is None or child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait(timeout=3)


def inside(args: argparse.Namespace) -> dict:
    if os.readlink("/proc/self/ns/net") == args.parent_netns:
        raise RuntimeError("private network namespace was not created")
    subprocess.run(["/usr/bin/ip", "link", "set", "lo", "up"], check=True)
    prefix = Path(args.prefix)
    if prefix.is_symlink() or not prefix.is_dir() or "forge-debug-probe" not in str(prefix):
        raise RuntimeError("acceptance requires a dedicated copied test prefix")
    if prefix.stat().st_uid != os.getuid():
        # In a user namespace the current user is mapped to uid 0.
        if os.getuid() != 0 or prefix.stat().st_uid != 1000:
            raise RuntimeError("test prefix is not owned by the test user")
    require_digest(Path(args.gdb), args.gdb_sha256)
    require_digest(Path(args.wine).resolve(), args.wine_sha256)
    require_digest(Path(args.winedbg_module), args.winedbg_sha256)
    require_digest(Path(args.fixture_exe), args.fixture_sha256)
    require_digest(Path(args.fixture_source), args.source_sha256)
    gdb_root = Path(args.gdb_root)
    env = os.environ.copy()
    env.update({"LD_LIBRARY_PATH": str(gdb_root / "usr/lib"),
                "GUILE_LOAD_PATH": str(gdb_root / "usr/share/guile/3.0"),
                "GUILE_LOAD_COMPILED_PATH": str(gdb_root / "usr/lib/guile/3.0/ccache")})
    wine_env = os.environ.copy()
    wine_env.update({"WINEPREFIX": str(prefix), "WINEDEBUG": "-all",
                     "WINEDLLOVERRIDES": "mscoree,mshtml=", "DISPLAY": args.display,
                     "XAUTHORITY": args.xauthority})
    wine_log = Path(args.output).with_suffix(".winedbg.log")
    wine_child = None
    gdb_child = None
    observations: dict[str, object] = {}
    try:
        with wine_log.open("wb") as log:
            wine_child = subprocess.Popen([args.wine, "--gdb", "--no-start", "--port", str(PORT), args.fixture_exe],
                                          stdout=log, stderr=subprocess.STDOUT, env=wine_env,
                                          cwd=Path(args.fixture_exe).parent, start_new_session=True)
        for _ in range(80):
            sockets = subprocess.run(["/usr/bin/ss", "-ltn"], capture_output=True, check=True).stdout
            if f":{PORT} ".encode() in sockets:
                break
            if wine_child.poll() is not None:
                raise RuntimeError("WineDbg exited before listening")
            time.sleep(0.25)
        else:
            raise RuntimeError("WineDbg did not open its private listener")
        gdb_child = subprocess.Popen([args.gdb, f"--data-directory={gdb_root}/usr/share/gdb", "-q", "-nx",
                                      "--interpreter=dap", "-iex",
                                      f"set substitute-path {args.compiled_source_dir} {Path(args.fixture_source).parent}"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     cwd=Path(args.fixture_exe).parent, env=env, start_new_session=True)
        dap = DapConnection(gdb_child)
        init = dap.reply(dap.send("initialize", {"adapterID": "gdb", "clientID": "forge-acceptance",
                                                 "linesStartAt1": True, "columnsStartAt1": True}))
        assert init["body"]["supportsConfigurationDoneRequest"] is True
        attach_seq = dap.send("attach", {"program": args.fixture_exe, "target": f"127.0.0.1:{PORT}"})
        dap.event("initialized")
        point = dap.reply(dap.send("setBreakpoints", {"source": {"path": args.fixture_source},
                                                       "breakpoints": [{"line": 7}]}))
        assert len(point["body"]["breakpoints"]) == 1
        dap.reply(dap.send("configurationDone"))
        dap.reply(attach_seq)
        dap.reply(dap.send("continue", {"threadId": 1}))
        stopped = dap.event("stopped", "breakpoint")
        thread_id = stopped["body"]["threadId"]
        stack = dap.reply(dap.send("stackTrace", {"threadId": thread_id, "startFrame": 0, "levels": 8}))
        names = [frame["name"] for frame in stack["body"]["stackFrames"]]
        assert names[:3] == ["inner", "outer", "main"]
        dap.reply(dap.send("next", {"threadId": thread_id}))
        dap.event("stopped", "step")
        stack = dap.reply(dap.send("stackTrace", {"threadId": thread_id, "startFrame": 0, "levels": 8}))
        frame = stack["body"]["stackFrames"][0]
        assert frame["line"] == 8
        scopes = dap.reply(dap.send("scopes", {"frameId": frame["id"]}))
        locals_ref = next(scope["variablesReference"] for scope in scopes["body"]["scopes"] if scope["name"] == "Locals")
        variables = dap.reply(dap.send("variables", {"variablesReference": locals_ref}))
        assert {variable["name"]: variable["value"] for variable in variables["body"]["variables"]}["local_value"] == "17"
        dap.reply(dap.send("continue", {"threadId": thread_id}))
        signal_stop = dap.event("stopped", "signal")
        assert signal_stop["body"]["threadId"] == thread_id
        stack = dap.reply(dap.send("stackTrace", {"threadId": thread_id, "startFrame": 0, "levels": 8}))
        assert any(frame.get("name") == "main" and frame.get("line") == 20 for frame in stack["body"]["stackFrames"])
        dap.reply(dap.send("disconnect", {"terminateDebuggee": False}))
        observations = {"breakpointVerified": True, "stack": names[:3], "stepLine": 8,
                        "localValue": "17", "sehRaisedAtLine": 20, "dapStopReason": "signal",
                        "disconnectSucceeded": True}
    finally:
        stop_group(gdb_child)
        stop_group(wine_child)
        # Wine descendants can daemonize. This dedicated copied prefix must
        # drain; a successful DAP reply alone is not cleanup evidence.
        for _ in range(50):
            if not owned_prefix_pids(prefix):
                break
            time.sleep(0.1)
        remaining = owned_prefix_pids(prefix)
        if remaining:
            for pid in remaining:
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            raise RuntimeError("owned Wine process tree did not drain after disconnect")
    observations.update({"privateNetworkNamespace": True, "ownedPrefixProcessesAfterDisconnect": 0,
                         "wineLoaderSha256": args.wine_sha256, "winedbgModuleSha256": args.winedbg_sha256,
                         "gdbSha256": args.gdb_sha256, "fixtureSha256": args.fixture_sha256,
                         "sourceSha256": args.source_sha256})
    Path(args.output).write_text(json.dumps(observations, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return observations


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--parent-netns", default="")
    for key in ("gdb", "gdb-root", "gdb-sha256", "wine", "wine-sha256", "winedbg-module",
                "winedbg-sha256", "prefix", "fixture-exe", "fixture-sha256", "fixture-source",
                "source-sha256", "compiled-source-dir", "display", "xauthority", "output"):
        parser.add_argument("--" + key, required=True)
    args = parser.parse_args()
    if args.inside:
        print(json.dumps(inside(args), ensure_ascii=False), flush=True)
    else:
        if Path(args.output).exists():
            raise RuntimeError("refusing to replace an existing acceptance receipt")
        command = ["/usr/bin/unshare", "-Urn", sys.executable, __file__, "--inside",
                   "--parent-netns", os.readlink("/proc/self/ns/net")]
        for key, value in vars(args).items():
            if key not in ("inside", "parent_netns"):
                command.extend(["--" + key.replace("_", "-"), value])
        subprocess.run(command, check=True, timeout=90)


if __name__ == "__main__":
    main()
