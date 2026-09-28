#!/usr/bin/env python3
"""Provision the ordinary-user CompatForge desktop service."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

CLI = "/usr/bin/compatforge-cli"
TEMPLATE = "/usr/share/compatforge/linux-desktop.json"
FONT = "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc"
MAX_JSON = 4 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return type(value) is str and re.fullmatch("[a-f0-9]{64}", value)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def no_links(path):
    require(path.is_absolute() and path == Path(os.path.abspath(path)), "noncanonical path")
    for part in (path, *path.parents):
        require(not part.is_symlink(), "symbolic link in initialization path")


def read_regular(path, owner=None, maximum=MAX_JSON):
    path = Path(path)
    no_links(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= maximum,
                "expected bounded singly linked regular file")
        if owner is not None and os.name == "posix":
            require(metadata.st_uid == owner and metadata.st_mode & 0o022 == 0,
                    "unsafe file owner or write permissions")
        raw = stream.read(maximum + 1)
        require(len(raw) == metadata.st_size, "file changed while reading")
        return raw


def read_json(path, owner=None):
    return json.loads(read_regular(path, owner), object_pairs_hook=unique_pairs)


def private_directory(path):
    no_links(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.stat()
    require(stat.S_ISDIR(metadata.st_mode), "expected directory")
    if os.name == "posix":
        require(metadata.st_uid == os.getuid() and metadata.st_mode & 0o077 == 0,
                "CompatForge private directory must be owned by this user and mode 0700")


def sync_directory(path):
    if os.name == "posix":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)


def write_new(path, value):
    raw = canonical(value)
    with path.open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def validate_template(value):
    require(type(value) is dict and set(value) == {"schemaVersion", "cliSha256", "runtimePackDigest", "runtime", "bottleFont"},
            "unknown desktop template fields")
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and digest(value["cliSha256"]) and type(value["runtimePackDigest"]) is str
            and value["runtimePackDigest"].startswith("sha256:") and digest(value["runtimePackDigest"][7:]),
            "invalid desktop template identity")
    runtime = value["runtime"]
    require(type(runtime) is dict and set(runtime) == {"materializedRoot", "wine", "wineserver", "version", "wineSha256", "wineserverSha256"}
            and runtime["materializedRoot"] == "/usr" and runtime["wine"] == "bin/wine"
            and runtime["wineserver"] == "bin/wineserver" and type(runtime["version"]) is str
            and re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", runtime["version"])
            and digest(runtime["wineSha256"]) and digest(runtime["wineserverSha256"]),
            "unsupported or unpinned desktop runtime")
    font = value["bottleFont"]
    require(type(font) is dict and set(font) == {"path", "digest", "family"}
            and font["path"] == FONT and font["family"] == "Noto Sans CJK SC"
            and type(font["digest"]) is str and font["digest"].startswith("sha256:")
            and digest(font["digest"][7:]), "unsupported or unpinned desktop font")
    return value


def verify_system(template):
    for path, pin in [(CLI, template["cliSha256"]), ("/usr/bin/wine", template["runtime"]["wineSha256"]),
                      ("/usr/bin/wineserver", template["runtime"]["wineserverSha256"]),
                      (FONT, template["bottleFont"]["digest"][7:])]:
        for ancestor in Path(path).parents:
            metadata = ancestor.stat()
            require(metadata.st_uid == 0 and metadata.st_mode & 0o022 == 0, "system asset ancestor is writable")
        require(sha(read_regular(path, 0, 512 * 1024 * 1024)) == pin,
                "system asset changed; install a matching verified CompatForge image: " + path)


def command(argv):
    # Only fixed product commands, never metadata-derived shell text. Temporary
    # regular output files bound memory before parsing and retain subprocess timeout.
    import tempfile
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=errors,
                                timeout=90, check=False, env={"PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"})
        require(result.returncode == 0, "CompatForge bootstrap command failed; run journalctl --user -u compatforge")
        require(output.tell() <= MAX_JSON, "CompatForge bootstrap response too large")
        output.seek(0)
        return json.loads(output.read(MAX_JSON + 1), object_pairs_hook=unique_pairs)


def initialize(home, template, run=command):
    """Caller holds the initialization lock; no live daemon may own this config."""
    validate_template(template)
    home = Path(home).absolute()
    no_links(home)
    parent = home / ".config"
    no_links(parent)
    parent.mkdir(mode=0o700, exist_ok=True)
    if os.name == "posix":
        require(parent.stat().st_uid == os.getuid() and parent.stat().st_mode & 0o022 == 0,
                "configuration parent is writable by another user")
    config = parent / "compatforge"
    template_pin = sha(canonical(template))
    configuration_pin = sha(canonical({key: value for key, value in template.items() if key != "cliSha256"}))
    owner = os.getuid() if os.name == "posix" else None
    if config.exists() or config.is_symlink():
        private_directory(config)
        receipt = read_json(config / "init-v1.json", owner)
        require(type(receipt) is dict and set(receipt) == {"schemaVersion", "templateSha256", "configurationSha256", "contextSha256", "serviceSha256"}
                and type(receipt["schemaVersion"]) is int and receipt["schemaVersion"] == 1
                and receipt["configurationSha256"] == configuration_pin,
                "existing context differs from image template; preserve it and migrate explicitly")
        for name, key in [("context.json", "contextSha256"), ("service.json", "serviceSha256")]:
            require(sha(read_regular(config / name, owner)) == receipt[key], "existing context was modified; refusing overwrite")
        if receipt["templateSha256"] != template_pin:
            receipt["templateSha256"] = template_pin
            # A CLI-only update has no configuration semantic change. Preserve
            # context/service and registry bytes, atomically refresh just the pin.
            temporary = config / ".init-v1.next"
            if os.path.lexists(temporary):
                read_regular(temporary, owner)
                temporary.unlink()
            write_new(temporary, receipt)
            os.replace(temporary, config / "init-v1.json")
            sync_directory(config)
        return {"initialized": True, "reused": True}
    stage = parent / ".compatforge-init-v1"
    private_directory(stage)
    intent = {"schemaVersion": 1, "home": str(home), "configurationSha256": configuration_pin}
    marker = stage / "intent-v1.json"
    if any(stage.iterdir()):
        require(marker.is_file(), "preexisting staging is not owned by this initializer; preserving files")
        require(read_json(marker, owner) == intent, "interrupted initialization belongs to a different configuration")
    else:
        write_new(marker, intent)
        sync_directory(stage)
    permitted = {"context.json", "service.json", "bootstrap.json", "seed.json", "init-v1.json", "intent-v1.json"}
    # Interrupted preparation can only contain these bounded private artifacts.
    for path in stage.iterdir():
        require(path.name in permitted, "unrecognized interrupted initialization file; preserving directory")
        read_regular(path, owner)
    for path in stage.iterdir():
        if path != marker: path.unlink()
    root = home / ".local/share/compatforge"
    private_directory(root)
    for name in ("runtime-store", "storage", "service"): private_directory(root / name)
    runtime = template["runtime"]
    request = {key: runtime[key] for key in ("materializedRoot", "wine", "wineserver", "version")}
    request.update(schemaVersion="1", runtimeStoreRoot=str(root / "runtime-store"), storageRoot=str(root / "storage"), bottleFont=template["bottleFont"])
    write_new(stage / "bootstrap.json", request)
    receipt = run([CLI, "local", "linux", "context", str(stage / "bootstrap.json"), str(stage / "context.json")])
    require(receipt.get("packDigest") == template["runtimePackDigest"], "bootstrapped runtime differs from image pin")
    write_new(stage / "service.json", {"schemaVersion": "1", "serviceRoot": str(root / "service")})
    write_new(stage / "seed.json", {"schemaVersion": "1", "requestId": "first-login", "operation": "applications.seed-defaults", "payload": {}})
    response = run([CLI, "api", str(stage / "context.json"), str(stage / "service.json"), str(stage / "seed.json")])
    require(response.get("operation") == "applications.seed-defaults" and response.get("result") == {"seeded": True}, "application registry initialization failed")
    write_new(stage / "init-v1.json", {"schemaVersion": 1, "templateSha256": template_pin,
                                     "configurationSha256": configuration_pin,
                                     "contextSha256": sha(read_regular(stage / "context.json", owner)),
                                     "serviceSha256": sha(read_regular(stage / "service.json", owner))})
    (stage / "bootstrap.json").unlink()
    (stage / "seed.json").unlink()
    sync_directory(stage)
    require(not config.exists(), "configuration appeared during initialization")
    stage.rename(config)
    sync_directory(parent)
    return {"initialized": True, "reused": False}


def main():
    require(sys.platform == "linux" and len(sys.argv) == 1, "user-init takes no arguments and requires Linux")
    import fcntl
    import pwd
    require(os.getuid() != 0 and os.getuid() == os.geteuid(), "run as the ordinary desktop user")
    os.umask(0o077)
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    no_links(home)
    require(home.stat().st_uid == os.getuid() and home.stat().st_mode & 0o022 == 0, "unsafe account home")
    parent = home / ".config"
    no_links(parent)
    parent.mkdir(mode=0o700, exist_ok=True)
    lock = parent / ".compatforge-init.lock"
    no_links(lock)
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_uid == os.getuid()
                and metadata.st_mode & 0o077 == 0, "unsafe initialization lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        template = validate_template(read_json(TEMPLATE, 0))
        verify_system(template)
        print(json.dumps(initialize(home, template), sort_keys=True))
    finally: os.close(descriptor)


if __name__ == "__main__":
    try: main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("compatforge.init.rejected: " + str(error), file=sys.stderr)
        sys.exit(1)

