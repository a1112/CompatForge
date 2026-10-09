"""Python adapter for forge-provider-contract v1; no service/runtime side effects."""
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

MAX_CONTRACT_BYTES = 64 * 1024
PROBE_TIMEOUT = 2.0
FIELDS = {"schemaVersion", "contractVersion", "providerId", "providerVersion", "sourceCommit",
          "target", "serviceName", "commands", "schemas", "capabilities", "operations"}
TOKEN = re.compile(r"[a-z0-9_.-]+\Z")
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\Z")


class ContractError(ValueError):
    def __init__(self, code, message):
        self.code = code
        self.message = message
        super().__init__(f"forge.provider.{code}: {message}")

    @property
    def public_code(self):
        """R-SDK interop v1 adapter; preserves this independent domain code."""
        return {"provider-unavailable": "CAPABILITY_UNAVAILABLE",
                "capability-missing": "CAPABILITY_UNAVAILABLE",
                "schema-mismatch": "SCHEMA_INVALID",
                "unsupported-version": "UNSUPPORTED_VERSION",
                "source-mismatch": "BINDING_MISMATCH"}[self.code]


def reject(code, message):
    raise ContractError(code, message)


def unique(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            reject("schema-mismatch", "duplicate provider contract field")
        value[name] = item
    return value


def token(value, maximum):
    return type(value) is str and len(value) <= maximum and TOKEN.fullmatch(value) is not None


def validate(value, *, report=False):
    if type(value) is not dict or set(value) != FIELDS | ({"sourceDirty"} if report else set()):
        reject("schema-mismatch", "provider contract has missing or unknown fields")
    if (value["schemaVersion"] != "1" or type(value["schemaVersion"]) is not str
            or any(type(value[name]) is not str or not VERSION.fullmatch(value[name])
                   for name in ("contractVersion", "providerVersion"))
            or not token(value["providerId"], 64) or not token(value["target"], 80)
            or not (value["serviceName"] == "" or token(value["serviceName"], 80))
            or type(value["sourceCommit"]) is not str or not re.fullmatch(r"[0-9a-f]{40}", value["sourceCommit"])
            or report and type(value["sourceDirty"]) is not bool):
        reject("schema-mismatch", "invalid provider identity or schemaVersion; expected provider contract v1")
    for name in ("commands", "schemas"):
        items = value[name]
        if (type(items) is not dict or len(items) > 64
                or any(not token(key, 64) or type(major) is not str
                       or not re.fullmatch(r"[1-9][0-9]{0,3}", major) for key, major in items.items())):
            reject("schema-mismatch", "invalid bounded command/schema version map")
    for name in ("capabilities", "operations"):
        items = value[name]
        if (type(items) is not list or len(items) > 64 or any(not token(item, 80) for item in items)
                or items != sorted(set(items))):
            reject("schema-mismatch", "capabilities/operations must be bounded, sorted and unique")
    return value


def decode(raw, *, report=False):
    if len(raw) > MAX_CONTRACT_BYTES:
        reject("schema-mismatch", "provider contract exceeds 64 KiB")
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: reject("schema-mismatch", "non-finite JSON value"))
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, ContractError):
            raise
        reject("schema-mismatch", "provider contract is malformed or has wrong types")
    return validate(value, report=report)


def load_lock(path):
    try:
        with Path(path).open("rb") as stream:
            return decode(stream.read(MAX_CONTRACT_BYTES + 1))
    except OSError:
        reject("provider-unavailable", "versioned provider composition lock is unavailable")


def negotiate(info, required):
    validate(info, report=True)
    validate(required)
    if info["contractVersion"] != required["contractVersion"] or info["providerVersion"] != required["providerVersion"]:
        reject("unsupported-version", "contract/provider version differs from composition lock")
    if info["sourceDirty"] or info["sourceCommit"] != required["sourceCommit"]:
        reject("source-mismatch", f"expected clean provider source {required['sourceCommit']}")
    if any(info[name] != required[name] for name in ("providerId", "target", "serviceName")):
        reject("capability-missing", "provider, target or service differs from composition lock")
    for name, major in required["commands"].items():
        if info["commands"].get(name) != major:
            reject("capability-missing", f"required CLI {name} v{major} is unavailable")
    for name, major in required["schemas"].items():
        if info["schemas"].get(name) != major:
            reject("schema-mismatch", f"required schema {name} v{major} is unavailable or incompatible")
    for field in ("capabilities", "operations"):
        for name in required[field]:
            if name not in info[field]:
                reject("capability-missing", f"required capability/operation {name} is unavailable")


def query_info(client):
    """Bound stdout during reading, before allocating/decoding; kill on timeout."""
    try:
        process = subprocess.Popen([str(client), "provider-info"], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
    except OSError:
        reject("provider-unavailable", "CompatForge CLI or provider-info command is unavailable")
    output = bytearray()
    deadline = time.monotonic() + PROBE_TIMEOUT
    try:
        with selectors.SelectSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    reject("provider-unavailable", "CompatForge provider-info timed out")
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                if len(output) + len(chunk) > MAX_CONTRACT_BYTES:
                    reject("schema-mismatch", "provider contract exceeds 64 KiB")
                output.extend(chunk)
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            reject("provider-unavailable", "CompatForge provider-info is missing or failed; expected versioned CLI")
        info = decode(output, report=True)
        return info
    except subprocess.TimeoutExpired:
        reject("provider-unavailable", "CompatForge provider-info timed out")
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def probe(client, required):
    info = query_info(client)
    negotiate(info, required)
    return info
