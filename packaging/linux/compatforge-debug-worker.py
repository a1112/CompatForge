"""Private WineDbg/GDB DAP worker. Run only as PID 1 in a fresh user/net/PID namespace.

The service supplies one pinned managed launch over stdin, then bounded JSON
lines with safe DAP messages. The worker has no listening IPC endpoint. WineDbg's
TCP stub exists only on loopback inside the private network namespace.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
from collections import deque

MAX = 64 * 1024
PORT = 25000
SAFE_DAP_COMMANDS = frozenset({"initialize", "attach", "setBreakpoints", "configurationDone", "threads",
                               "continue", "pause", "next", "stepIn", "stepOut", "stackTrace", "scopes",
                               "variables", "terminate", "disconnect"})


class OversizedDapResponse(Exception):
    def __init__(self, message: dict) -> None:
        self.message = message


def request_id(value: dict, expected: int) -> int:
    actual = value.get("requestId")
    if type(actual) is not int or actual != expected or actual > 2**63 - 1:
        raise ValueError("worker request identity differs")
    return actual


def response_fits(messages: list[dict]) -> bool:
    # Leave room for the control requestId and JSON wrapper emitted below.
    raw = json.dumps({"messages": messages}, separators=(",", ":"), ensure_ascii=False).encode()
    return len(raw) <= MAX - 256


def oversized_metadata(message: dict) -> dict:
    # A malformed backend field must not overflow the control envelope used
    # to report an oversized DAP body. Rust converts unknown responses to a
    # bounded stderr output event rather than exposing their contents.
    kind = "response" if message.get("type") == "response" else "event"
    command = message.get("command")
    sequence = message.get("request_seq")
    return {"type": kind,
            "command": command if kind == "response" and type(command) is str and command in SAFE_DAP_COMMANDS else None,
            "request_seq": sequence if type(sequence) is int and 0 < sequence <= 2**63 - 1 else None}


class WorkerTerminated(Exception):
    pass


def terminate_on_signal(_signum: int, _frame: object) -> None:
    # PID 1 ignores SIGTERM by default. Raising here enters run()'s cleanup.
    raise WorkerTerminated()


def line() -> dict | None:
    raw = sys.stdin.buffer.readline(MAX + 1)
    if not raw:
        return None
    if len(raw) > MAX or not raw.endswith(b"\n"):
        raise ValueError("bounded control line required")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("control value must be an object")
    return value


def emit(value: dict) -> None:
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    if len(raw) > MAX:
        raise ValueError("bounded control response required")
    sys.stdout.buffer.write(raw + b"\n")
    sys.stdout.buffer.flush()


def verify(path: str, expected: str) -> Path:
    item = Path(path)
    if not item.is_absolute() or not item.is_file() or len(expected) != 64:
        raise ValueError("pinned debugger file is unavailable")
    digest = hashlib.sha256()
    with item.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != expected:
        raise ValueError("pinned debugger file changed")
    return item


def owned_prefix_pids(prefix: str) -> list[int]:
    needle = f"WINEPREFIX={prefix}".encode()
    result = []
    for item in Path("/proc").iterdir():
        if not item.name.isdigit() or int(item.name) == os.getpid():
            continue
        try:
            if needle in (item / "environ").read_bytes().split(b"\0"):
                result.append(int(item.name))
        except OSError:
            continue
    return result


def reap_orphans() -> None:
    # The worker is PID 1 in its private namespace, so daemonized Wine
    # descendants become its children after their immediate parent exits.
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def stop(child: subprocess.Popen[bytes] | None) -> None:
    if child is None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait(timeout=2)


class DapPipe:
    def __init__(self, child: subprocess.Popen[bytes]) -> None:
        self.child = child
        self.bytes = bytearray()
        self.deferred: deque[dict] = deque()
        self.selector = selectors.DefaultSelector()
        assert child.stdout is not None
        self.selector.register(child.stdout, selectors.EVENT_READ)

    def send(self, value: dict) -> None:
        data = json.dumps(value, separators=(",", ":")).encode()
        if len(data) > MAX:
            raise ValueError("DAP message too long")
        assert self.child.stdin is not None
        self.child.stdin.write(f"Content-Length: {len(data)}\r\n\r\n".encode() + data)
        self.child.stdin.flush()

    def drain(self, timeout: float) -> list[dict]:
        messages: list[dict] = []
        while self.deferred:
            value = self.deferred.popleft()
            if not response_fits(messages + [value]):
                if not messages:
                    raise OversizedDapResponse(value)
                self.deferred.appendleft(value)
                return messages
            messages.append(value)
        deadline = time.monotonic() + timeout
        while True:
            while b"\r\n\r\n" in self.bytes:
                header, rest = bytes(self.bytes).split(b"\r\n\r\n", 1)
                if not header.startswith(b"Content-Length: ") or b"\r\n" in header or len(header) > 128:
                    raise ValueError("invalid DAP header")
                length = int(header.removeprefix(b"Content-Length: "))
                if not 1 <= length <= MAX:
                    raise ValueError("invalid DAP length")
                if len(rest) < length:
                    break
                value = json.loads(rest[:length])
                if not isinstance(value, dict):
                    raise ValueError("invalid DAP value")
                self.bytes = bytearray(rest[length:])
                if not response_fits(messages + [value]):
                    if not messages:
                        raise OversizedDapResponse(value)
                    self.deferred.append(value)
                    return messages
                messages.append(value)
            if len(self.bytes) > MAX + 128 or time.monotonic() >= deadline:
                return messages
            if not self.selector.select(max(0, deadline - time.monotonic())):
                return messages
            assert self.child.stdout is not None
            chunk = os.read(self.child.stdout.fileno(), 8192)
            if not chunk:
                if self.child.poll() is not None:
                    if messages:
                        return messages
                    raise RuntimeError("debugger exited")
                return messages
            self.bytes.extend(chunk)


def safe_forward(message: dict, config: dict) -> None:
    command = message.get("command")
    args = message.get("arguments")
    if message.get("type") != "request" or command not in SAFE_DAP_COMMANDS or not isinstance(args, dict):
        raise ValueError("unsupported DAP request")
    if command == "attach" and (args != {"program": config["program"], "target": f"127.0.0.1:{PORT}"}):
        raise ValueError("unbound debugger target")
    if command == "setBreakpoints" and args.get("source", {}).get("path") not in config["backendSources"]:
        raise ValueError("unbound debugger source")
    if command == "disconnect" and args != {"terminateDebuggee": False}:
        raise ValueError("unsupported disconnect option")


def run(config: dict) -> None:
    request_id(config, 1)
    if os.getpid() != 1 or os.getuid() != 0:
        raise RuntimeError("worker requires private PID and mapped user namespace")
    if not isinstance(config.get("backendSources"), list) or len(config["backendSources"]) > 128:
        raise ValueError("invalid source map")
    prefix = config.get("prefix", "")
    if not isinstance(prefix, str) or not Path(prefix).is_absolute() or Path(prefix).is_symlink() or not Path(prefix).is_dir():
        raise ValueError("invalid dedicated prefix")
    if config.get("schemaVersion") != 1 or config.get("port") != PORT:
        raise ValueError("invalid worker contract")
    for name in ("program", "wine", "winedbgModule", "gdb"):
        verify(config[name], config["sha256"][name])
    if not Path(config["gdbRoot"]).is_dir():
        raise ValueError("GDB runtime root is absent")
    source_substitution = config.get("sourceSubstitution")
    if source_substitution is not None:
        if not isinstance(source_substitution, dict) or set(source_substitution) != {"compiled", "installed"}:
            raise ValueError("invalid source substitution")
        for value in source_substitution.values():
            if not isinstance(value, str) or not value.startswith("/") or any(char in value for char in "\n\r;\""):
                raise ValueError("unsafe source substitution")
    subprocess.run(["/usr/bin/ip", "link", "set", "lo", "up"], check=True, timeout=3)
    wine_env = os.environ.copy()
    wine_env.update({"WINEPREFIX": prefix, "WINEDEBUG": "-all", "WINEDLLOVERRIDES": "mscoree,mshtml=",
                     "DISPLAY": config["display"], "XAUTHORITY": config["xauthority"]})
    gdb_root = Path(config["gdbRoot"])
    gdb_env = os.environ.copy()
    gdb_env.update({"LD_LIBRARY_PATH": str(gdb_root / "usr/lib"),
                    "GUILE_LOAD_PATH": str(gdb_root / "usr/share/guile/3.0"),
                    "GUILE_LOAD_COMPILED_PATH": str(gdb_root / "usr/lib/guile/3.0/ccache")})
    wine = None
    gdb = None
    try:
        wine = subprocess.Popen([config["wine"], "--gdb", "--no-start", "--port", str(PORT), config["program"]],
                                cwd=Path(config["program"]).parent, env=wine_env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        for _ in range(80):
            sockets = subprocess.run(["/usr/bin/ss", "-ltn"], capture_output=True, check=True, timeout=2).stdout
            if f":{PORT} ".encode() in sockets:
                break
            if wine.poll() is not None:
                raise RuntimeError("WineDbg exited before opening private stub")
            time.sleep(0.25)
        else:
            raise TimeoutError("WineDbg private stub timeout")
        gdb_argv = [config["gdb"], f"--data-directory={gdb_root}/usr/share/gdb", "-q", "-nx", "--interpreter=dap"]
        if source_substitution is not None:
            gdb_argv += ["-iex", f"set substitute-path {source_substitution['compiled']} {source_substitution['installed']}"]
        gdb = subprocess.Popen(gdb_argv, cwd=Path(config["program"]).parent, env=gdb_env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True)
        dap = DapPipe(gdb)
        emit({"requestId": 1, "ready": True})
        next_request_id = 2
        while (call := line()) is not None:
            current_id = request_id(call, next_request_id)
            next_request_id += 1
            op = call.get("op")
            if op == "shutdown":
                emit({"requestId": current_id, "stopped": True})
                return
            if op == "send":
                message = call.get("message")
                if not isinstance(message, dict):
                    raise ValueError("DAP request required")
                safe_forward(message, config)
                dap.send(message)
            elif op != "poll":
                raise ValueError("unknown worker operation")
            try:
                messages = dap.drain(0.05 if op == "send" else 0.2)
            except OversizedDapResponse as error:
                emit({"requestId": current_id, "oversized": oversized_metadata(error.message)})
                continue
            emit({"requestId": current_id, "messages": messages})
    finally:
        stop(gdb)
        stop(wine)
        for _ in range(20):
            reap_orphans()
            if not owned_prefix_pids(prefix):
                break
            time.sleep(0.1)
        remaining = owned_prefix_pids(prefix)
        if remaining:
            for pid in remaining:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            for _ in range(30):
                reap_orphans()
                if not owned_prefix_pids(prefix):
                    break
                time.sleep(0.1)
            if owned_prefix_pids(prefix):
                raise RuntimeError("owned prefix process tree did not drain")


if __name__ == "__main__":
    try:
        signal.signal(signal.SIGTERM, terminate_on_signal)
        first = line()
        if first is None:
            raise ValueError("missing worker configuration")
        run(first)
    except Exception as error:
        # Never print an untrusted debugger path or process output to the caller.
        print(f"debug worker failed: {type(error).__name__}", file=sys.stderr, flush=True)
        sys.exit(1)
