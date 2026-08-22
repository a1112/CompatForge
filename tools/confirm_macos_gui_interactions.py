#!/usr/bin/env python3
"""Confirm observed macOS GUI interactions in a separate terminal."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

if os.name == "nt":
    from ctypes import wintypes


ROOT = Path(__file__).resolve().parents[1]

ROUND_IDS = ("round-1", "round-2")
RUNTIME_IDS = ("crossover", "whisky")
APPLICATION_IDS = ("7zip", "sumatrapdf", "notepad-plus-plus")
REQUIRED_CHECKS = {
    "7zip": ("fileList", "menus"),
    "sumatrapdf": ("mainWindow", "openDialog"),
    "notepad-plus-plus": ("open", "edit", "saveUtf8Chinese", "rereadMatches"),
}
CHALLENGE_NAMES = tuple(
    f"{round_id}--{runtime_id}--{app_id}.json"
    for round_id in ROUND_IDS
    for runtime_id in RUNTIME_IDS
    for app_id in APPLICATION_IDS
)

CHALLENGE_KEYS = frozenset(
    {
        "schemaVersion",
        "roundId",
        "runtimeId",
        "runtimeVersion",
        "appId",
        "packDigest",
        "assetDigest",
        "requiredChecks",
        "nonce",
    }
)
ACKNOWLEDGEMENT_KEYS = CHALLENGE_KEYS | {
    "challengeDigest",
    "interactionChecks",
}
IDENTITY_KEYS = (
    "schemaVersion",
    "roundId",
    "runtimeId",
    "runtimeVersion",
    "appId",
    "packDigest",
    "assetDigest",
    "requiredChecks",
    "nonce",
)

MAX_DOCUMENT_BYTES = 4096
MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 128
MAX_TEXT_CHARS = 128
READ_DEADLINE_SECONDS = 5.0
READ_CHUNK_BYTES = 4096
MIN_POLL_SECONDS = 0.01
MAX_POLL_SECONDS = 1.0
DEFAULT_POLL_SECONDS = 0.25
DEFAULT_WATCH_SECONDS = 6 * 60 * 60
MAX_WATCH_SECONDS = 24 * 60 * 60

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{64}\Z")
_RUNTIME_VERSION = re.compile(r"[0-9][0-9A-Za-z._+\-]{0,63}\Z")

try:
    _O_CLOEXEC = os.O_CLOEXEC
except AttributeError:
    _O_CLOEXEC = 0
try:
    _O_NOFOLLOW = os.O_NOFOLLOW
except AttributeError:
    _O_NOFOLLOW = 0
try:
    _O_BINARY = os.O_BINARY
except AttributeError:
    _O_BINARY = 0
try:
    _O_NONBLOCK = os.O_NONBLOCK
except AttributeError:
    _O_NONBLOCK = 0
try:
    _O_NOINHERIT = os.O_NOINHERIT
except AttributeError:
    _O_NOINHERIT = 0
try:
    _O_DIRECTORY = os.O_DIRECTORY
except AttributeError:
    _O_DIRECTORY = 0

if os.name == "nt":
    _FILE_READ_ATTRIBUTES = 0x0080
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
    _FILE_ID_INFO_CLASS = 18
    _MOVEFILE_WRITE_THROUGH = 0x00000008
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class _FileAttributeTagInfo(ctypes.Structure):
        _fields_ = (
            ("file_attributes", wintypes.DWORD),
            ("reparse_tag", wintypes.DWORD),
        )

    class _FileId128(ctypes.Structure):
        _fields_ = (("identifier", ctypes.c_ubyte * 16),)

    class _FileIdInfo(ctypes.Structure):
        _fields_ = (
            ("volume_serial_number", ctypes.c_ulonglong),
            ("file_id", _FileId128),
        )

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _CREATE_FILE = _KERNEL32.CreateFileW
    _CREATE_FILE.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _CREATE_FILE.restype = wintypes.HANDLE
    _GET_FILE_INFORMATION = _KERNEL32.GetFileInformationByHandleEx
    _GET_FILE_INFORMATION.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    _GET_FILE_INFORMATION.restype = wintypes.BOOL
    _CLOSE_HANDLE = _KERNEL32.CloseHandle
    _CLOSE_HANDLE.argtypes = (wintypes.HANDLE,)
    _CLOSE_HANDLE.restype = wintypes.BOOL
    _MOVE_FILE = _KERNEL32.MoveFileExW
    _MOVE_FILE.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    _MOVE_FILE.restype = wintypes.BOOL


class AcknowledgementError(ValueError):
    """A fixed, non-reflective acknowledgement protocol failure."""


@dataclass(frozen=True, slots=True)
class DirectoryBinding:
    path: Path
    chain: tuple[tuple[Path, tuple[int, int, int]], ...]
    identity: tuple[int, int, int]
    handle: object


def _fail(message: str) -> None:
    raise AcknowledgementError(message)


def _is_reparse(metadata: os.stat_result) -> bool:
    try:
        attributes = metadata.st_file_attributes
    except AttributeError:
        attributes = 0
    try:
        reparse_tag = metadata.st_reparse_tag
    except AttributeError:
        reparse_tag = 0
    return bool(attributes & 0x400) or bool(reparse_tag)


def _node_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        *_node_identity(metadata),
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _prescan_depth(text: str, label: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                _fail(f"{label} JSON exceeds its structural bound")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                _fail(f"{label} JSON is invalid")


def _closed_object(label: str) -> Callable[[list[tuple[str, object]]], dict[str, object]]:
    def close(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, nested in pairs:
            if type(key) is not str or not key or key in value:
                _fail(f"{label} JSON contains a duplicate or invalid key")
            value[key] = nested
        return value

    return close


def _reject_number(_value: str) -> object:
    raise ValueError("numbers are not part of the protocol")


def _bounded_structure(value: object, label: str) -> None:
    pending: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            _fail(f"{label} JSON exceeds its structural bound")
        if type(current) is str:
            if len(current) > MAX_TEXT_CHARS or any(
                ord(character) < 32 or ord(character) == 127 for character in current
            ):
                _fail(f"{label} document is invalid")
            try:
                current.encode("utf-8", errors="strict")
            except UnicodeEncodeError:
                _fail(f"{label} document is invalid")
        elif type(current) is list:
            pending.extend((nested, depth + 1) for nested in current)
        elif type(current) is dict:
            pending.extend((key, depth + 1) for key in current)
            pending.extend((nested, depth + 1) for nested in current.values())
        elif type(current) is not bool and current is not None:
            _fail(f"{label} document is invalid")


def _parse_json(raw: object, label: str) -> object:
    if type(raw) is not bytes:
        _fail(f"{label} JSON is invalid")
    if not raw or len(raw) > MAX_DOCUMENT_BYTES:
        _fail(f"{label} JSON exceeds its size bound")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail(f"{label} JSON is invalid")
    _prescan_depth(text, label)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_closed_object(label),
            parse_constant=_reject_number,
            parse_float=_reject_number,
            parse_int=_reject_number,
        )
    except AcknowledgementError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        _fail(f"{label} JSON is invalid")
    _bounded_structure(value, label)
    return value


def _canonical_bytes(value: object, label: str) -> bytes:
    try:
        encoded = (
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _fail(f"{label} document is invalid")
    if len(encoded) > MAX_DOCUMENT_BYTES:
        _fail(f"{label} JSON exceeds its size bound")
    return encoded


def _validate_challenge(value: object) -> dict[str, object]:
    label = "challenge"
    if type(value) is not dict or set(value) != CHALLENGE_KEYS:
        _fail(f"{label} document is invalid")
    challenge = value
    app_id = challenge["appId"]
    if (
        challenge["schemaVersion"] != "1"
        or type(challenge["schemaVersion"]) is not str
        or type(challenge["roundId"]) is not str
        or challenge["roundId"] not in ROUND_IDS
        or type(challenge["runtimeId"]) is not str
        or challenge["runtimeId"] not in RUNTIME_IDS
        or type(challenge["runtimeVersion"]) is not str
        or _RUNTIME_VERSION.fullmatch(challenge["runtimeVersion"]) is None
        or type(app_id) is not str
        or app_id not in APPLICATION_IDS
        or type(challenge["packDigest"]) is not str
        or _DIGEST.fullmatch(challenge["packDigest"]) is None
        or type(challenge["assetDigest"]) is not str
        or _DIGEST.fullmatch(challenge["assetDigest"]) is None
        or type(challenge["requiredChecks"]) is not list
        or challenge["requiredChecks"] != list(REQUIRED_CHECKS[app_id])
        or type(challenge["nonce"]) is not str
        or _NONCE.fullmatch(challenge["nonce"]) is None
    ):
        _fail(f"{label} document is invalid")
    _bounded_structure(challenge, label)
    return challenge


def _validate_acknowledgement(value: object) -> dict[str, object]:
    label = "acknowledgement"
    if type(value) is not dict or set(value) != ACKNOWLEDGEMENT_KEYS:
        _fail(f"{label} document is invalid")
    acknowledgement = value
    _validate_challenge({key: acknowledgement[key] for key in IDENTITY_KEYS})
    checks = acknowledgement["interactionChecks"]
    required = acknowledgement["requiredChecks"]
    if (
        type(acknowledgement["challengeDigest"]) is not str
        or _DIGEST.fullmatch(acknowledgement["challengeDigest"]) is None
        or type(checks) is not dict
        or tuple(sorted(checks)) != tuple(sorted(required))
        or any(type(value) is not bool or value is not True for value in checks.values())
    ):
        _fail(f"{label} document is invalid")
    _bounded_structure(acknowledgement, label)
    return acknowledgement


def encode_challenge(challenge: object) -> bytes:
    """Validate and encode one canonical challenge."""

    return _canonical_bytes(_validate_challenge(challenge), "challenge")


def parse_challenge(raw: object) -> dict[str, object]:
    """Parse exactly one canonical challenge."""

    challenge = _validate_challenge(_parse_json(raw, "challenge"))
    if raw != _canonical_bytes(challenge, "challenge"):
        _fail("challenge bytes are non-canonical")
    return challenge


def challenge_digest(challenge: object) -> str:
    """Return the digest of the validated canonical challenge bytes."""

    return "sha256:" + hashlib.sha256(encode_challenge(challenge)).hexdigest()


def encode_acknowledgement(acknowledgement: object) -> bytes:
    """Validate and encode one canonical acknowledgement."""

    return _canonical_bytes(
        _validate_acknowledgement(acknowledgement), "acknowledgement"
    )


def parse_acknowledgement(raw: object) -> dict[str, object]:
    """Parse exactly one canonical acknowledgement."""

    acknowledgement = _validate_acknowledgement(
        _parse_json(raw, "acknowledgement")
    )
    if raw != _canonical_bytes(acknowledgement, "acknowledgement"):
        _fail("acknowledgement bytes are non-canonical")
    return acknowledgement


def make_challenge(
    *,
    round_id: str,
    runtime_id: str,
    runtime_version: str,
    app_id: str,
    pack_digest: str,
    asset_digest: str,
    nonce_source: Callable[[int], str] = secrets.token_hex,
) -> dict[str, object]:
    """Build a challenge using only explicit identity and injected entropy."""

    try:
        nonce = nonce_source(32)
    except Exception as error:
        raise AcknowledgementError("challenge nonce generation failed") from error
    challenge: dict[str, object] = {
        "schemaVersion": "1",
        "roundId": round_id,
        "runtimeId": runtime_id,
        "runtimeVersion": runtime_version,
        "appId": app_id,
        "packDigest": pack_digest,
        "assetDigest": asset_digest,
        "requiredChecks": list(REQUIRED_CHECKS.get(app_id, ())),
        "nonce": nonce,
    }
    return dict(_validate_challenge(challenge))


def make_acknowledgement(challenge: object) -> dict[str, object]:
    """Create literal-true acknowledgement content for a validated challenge."""

    validated = _validate_challenge(challenge)
    acknowledgement: dict[str, object] = {
        **validated,
        "challengeDigest": challenge_digest(validated),
        "interactionChecks": {
            check: True for check in validated["requiredChecks"]
        },
    }
    return dict(_validate_acknowledgement(acknowledgement))


def validate_acknowledgement(
    challenge: object,
    acknowledgement: object,
) -> dict[str, bool]:
    """Bind an acknowledgement to every field of one challenge."""

    validated_challenge = _validate_challenge(challenge)
    validated_acknowledgement = _validate_acknowledgement(acknowledgement)
    if (
        any(
            validated_acknowledgement[key] != validated_challenge[key]
            for key in IDENTITY_KEYS
        )
        or validated_acknowledgement["challengeDigest"]
        != challenge_digest(validated_challenge)
    ):
        _fail("acknowledgement does not match challenge")
    return dict(validated_acknowledgement["interactionChecks"])


def _path_chain(
    path: Path,
    label: str,
    *,
    include_leaf: bool,
) -> tuple[tuple[Path, tuple[int, int, int]], ...]:
    if not isinstance(path, Path) or not path.is_absolute() or any(
        part in ("", ".", "..") for part in path.parts[1:]
    ):
        _fail(f"{label} path is invalid")
    target = path if include_leaf else path.parent
    chain: list[tuple[Path, tuple[int, int, int]]] = []
    for component in reversed((target, *target.parents)):
        try:
            metadata = component.lstat()
        except OSError:
            _fail(f"{label} file is unsafe")
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            _fail(f"{label} file is unsafe")
        if component != path and not stat.S_ISDIR(metadata.st_mode):
            _fail(f"{label} file is unsafe")
        chain.append((component, _node_identity(metadata)))
    return tuple(chain)


def _revalidate_chain(
    chain: tuple[tuple[Path, tuple[int, int, int]], ...], label: str
) -> None:
    for component, expected in chain:
        try:
            metadata = component.lstat()
        except OSError:
            _fail(f"{label} file identity changed")
        if (
            stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or _node_identity(metadata) != expected
        ):
            _fail(f"{label} file identity changed")


def _relative_stat(binding: DirectoryBinding, name: str) -> os.stat_result:
    if Path(name).name != name or not name:
        raise OSError("invalid relative leaf")
    if os.name == "nt":
        return (binding.path / name).lstat()
    return os.stat(name, dir_fd=binding.handle, follow_symlinks=False)


def _relative_open(
    binding: DirectoryBinding,
    name: str,
    flags: int,
    mode: int = 0o600,
) -> int:
    if Path(name).name != name or not name:
        raise OSError("invalid relative leaf")
    if os.name == "nt":
        return os.open(binding.path / name, flags, mode)
    return os.open(name, flags, mode, dir_fd=binding.handle)


def _relative_unlink(binding: DirectoryBinding, name: str) -> None:
    if os.name == "nt":
        (binding.path / name).unlink()
    else:
        os.unlink(name, dir_fd=binding.handle)


def _read_file(
    path: Path,
    label: str,
    directory: DirectoryBinding | None = None,
) -> bytes:
    owned_directory = directory is None
    binding = directory or _bind_directory(path.parent, f"{label} parent")
    descriptor: int | None = None
    try:
        if path.parent != binding.path:
            _fail(f"{label} file is unsafe")
        _revalidate_directory(binding, f"{label} parent")
        try:
            entry = _relative_stat(binding, path.name)
        except OSError:
            _fail(f"{label} file is unsafe")
        if (
            not stat.S_ISREG(entry.st_mode)
            or stat.S_ISLNK(entry.st_mode)
            or _is_reparse(entry)
            or entry.st_nlink != 1
            or entry.st_size <= 0
            or entry.st_size > MAX_DOCUMENT_BYTES
        ):
            _fail(f"{label} file is unsafe")
        flags = (
            os.O_RDONLY
            | _O_CLOEXEC
            | _O_NOFOLLOW
            | _O_BINARY
            | _O_NONBLOCK
        )
        descriptor = _relative_open(binding, path.name, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _file_identity(opened) != _file_identity(entry)
        ):
            _fail(f"{label} file is unsafe")
        deadline = time.monotonic() + READ_DEADLINE_SECONDS
        chunks: list[bytes] = []
        total = 0
        while total < opened.st_size:
            if time.monotonic() >= deadline:
                _fail(f"{label} file read timed out")
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, opened.st_size - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        final = os.fstat(descriptor)
        try:
            after = _relative_stat(binding, path.name)
        except OSError:
            _fail(f"{label} file identity changed")
        _revalidate_directory(binding, f"{label} parent")
        if (
            total != opened.st_size
            or _file_identity(final) != _file_identity(opened)
            or _file_identity(after) != _file_identity(opened)
            or final.st_nlink != 1
            or after.st_nlink != 1
        ):
            _fail(f"{label} file identity changed")
        return b"".join(chunks)
    except AcknowledgementError:
        raise
    except OSError as error:
        raise AcknowledgementError(f"{label} file is unsafe") from error
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if owned_directory:
            _close_directory(binding)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _remove_relative_if_owned(
    binding: DirectoryBinding,
    name: str,
    identity: tuple[int, int, int],
) -> None:
    try:
        current = _relative_stat(binding, name)
    except OSError:
        return
    if (
        stat.S_ISREG(current.st_mode)
        and not stat.S_ISLNK(current.st_mode)
        and not _is_reparse(current)
        and _node_identity(current) == identity
    ):
        try:
            _relative_unlink(binding, name)
        except OSError:
            pass


def _atomic_publish(
    binding: DirectoryBinding,
    staged_name: str,
    final_name: str,
) -> None:
    if os.name == "nt":
        if not _MOVE_FILE(
            str(binding.path / staged_name),
            str(binding.path / final_name),
            _MOVEFILE_WRITE_THROUGH,
        ):
            error = ctypes.get_last_error()
            if error in (80, 183):
                raise FileExistsError(error, "destination exists")
            raise OSError(error, "conditional move failed")
        return
    library = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        try:
            rename = library.renameat2
        except AttributeError:
            rename = None
        flag = 0x1
    elif sys.platform == "darwin":
        try:
            rename = library.renameatx_np
        except AttributeError:
            rename = None
        flag = 0x00000004
    else:
        rename = None
        flag = 0
    if rename is None:
        raise OSError("atomic no-replace publication is unsupported")
    rename.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    rename.restype = ctypes.c_int
    if rename(
        binding.handle,
        os.fsencode(staged_name),
        binding.handle,
        os.fsencode(final_name),
        flag,
    ) != 0:
        error = ctypes.get_errno()
        if error == 17:
            raise FileExistsError(error, "destination exists")
        raise OSError(error, "conditional rename failed")


def _sync_directory(binding: DirectoryBinding) -> None:
    if os.name != "nt":
        os.fsync(binding.handle)


def _write_new_file(
    path: Path,
    payload: bytes,
    label: str,
    directory: DirectoryBinding | None = None,
) -> None:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or Path(path.name).name != path.name
        or not path.name
        or len(path.name) > 128
    ):
        _fail(f"{label} path is invalid")
    owned_directory = directory is None
    binding = directory or _bind_directory(path.parent, f"{label} parent")
    if path.parent != binding.path:
        if owned_directory:
            _close_directory(binding)
        _fail(f"{label} path is invalid")
    try:
        staged_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    except Exception as error:
        if owned_directory:
            _close_directory(binding)
        raise AcknowledgementError(f"{label} staging failed") from error
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= _O_CLOEXEC | _O_NOFOLLOW
    flags |= _O_BINARY | _O_NOINHERIT
    descriptor: int | None = None
    identity: tuple[int, int, int] | None = None
    published = False
    failure: tuple[BaseException, BaseException | None] | None = None
    try:
        _revalidate_directory(binding, f"{label} parent")
        try:
            _relative_stat(binding, path.name)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise AcknowledgementError(f"{label} file is unsafe") from error
        else:
            raise FileExistsError
        descriptor = _relative_open(binding, staged_name, flags, 0o600)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            _fail(f"{label} file is unsafe")
        identity = _node_identity(opened)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        current = os.fstat(descriptor)
        if (
            _node_identity(current) != identity
            or current.st_nlink != 1
            or current.st_size != len(payload)
        ):
            _fail(f"{label} file identity changed")
        os.close(descriptor)
        descriptor = None
        staged = _relative_stat(binding, staged_name)
        _revalidate_directory(binding, f"{label} parent")
        if (
            _node_identity(staged) != identity
            or staged.st_nlink != 1
            or staged.st_size != len(payload)
        ):
            _fail(f"{label} file identity changed")
        _atomic_publish(binding, staged_name, path.name)
        published = True
        _sync_directory(binding)
        final = _relative_stat(binding, path.name)
        _revalidate_directory(binding, f"{label} parent")
        if (
            _node_identity(final) != identity
            or final.st_nlink != 1
            or final.st_size != len(payload)
            or _read_file(path, label, binding) != payload
        ):
            _fail(f"{label} file identity changed")
    except FileExistsError as error:
        failure = (AcknowledgementError(f"{label} file already exists"), error)
    except KeyboardInterrupt as error:
        failure = (AcknowledgementError("operator cancelled acknowledgement"), error)
    except AcknowledgementError as error:
        failure = (error, None)
    except OSError as error:
        failure = (
            AcknowledgementError(f"{label} file could not be created safely"),
            error,
        )
    except BaseException as error:
        failure = (error, None)
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if failure is not None and identity is not None:
            _remove_relative_if_owned(binding, staged_name, identity)
            if published:
                _remove_relative_if_owned(binding, path.name, identity)
        if owned_directory:
            _close_directory(binding)
    if failure is not None:
        error, cause = failure
        if cause is not None:
            raise error from cause
        raise error


def read_challenge(
    path: Path,
    directory: DirectoryBinding | None = None,
) -> dict[str, object]:
    return parse_challenge(_read_file(path, "challenge", directory))


def read_acknowledgement(
    path: Path,
    directory: DirectoryBinding | None = None,
) -> dict[str, object]:
    return parse_acknowledgement(_read_file(path, "acknowledgement", directory))


def write_challenge(
    path: Path,
    challenge: object,
    directory: DirectoryBinding | None = None,
) -> None:
    _write_new_file(path, encode_challenge(challenge), "challenge", directory)


def write_acknowledgement(
    path: Path,
    acknowledgement: object,
    directory: DirectoryBinding | None = None,
) -> None:
    _write_new_file(
        path,
        encode_acknowledgement(acknowledgement),
        "acknowledgement",
        directory,
    )


def _uses_windows_native_namespace(value: object) -> bool:
    if os.name != "nt" or type(value) is not str or len(value) < 4:
        return False
    separators = "\\/"
    return (
        value[0] in separators
        and value[1] in separators
        and value[2] in "?."
        and value[3] in separators
    ) or (
        value[0] in separators
        and value[1] == "?"
        and value[2] == "?"
        and value[3] in separators
    )


def _external_path(value: str, label: str) -> Path:
    if _uses_windows_native_namespace(value):
        raise argparse.ArgumentTypeError(
            f"{label} uses a forbidden Windows namespace"
        )
    path = Path(value)
    if not path.is_absolute() or any(part in ("", ".", "..") for part in path.parts[1:]):
        raise argparse.ArgumentTypeError(
            f"{label} must be an absolute non-traversing external path"
        )
    if path == ROOT or path in ROOT.parents or ROOT in path.parents:
        raise argparse.ArgumentTypeError(f"{label} must be outside the repository")
    return path


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _is_external_root(path: Path) -> bool:
    raw = str(path)
    return (
        not _uses_windows_native_namespace(raw)
        and path.is_absolute()
        and not any(part in ("", ".", "..") for part in path.parts[1:])
        and path != ROOT
        and path not in ROOT.parents
        and ROOT not in path.parents
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    value.add_argument(
        "--interaction-plan-root",
        required=True,
        type=lambda raw: _external_path(raw, "interaction-plan-root"),
    )
    value.add_argument(
        "--acknowledgement-root",
        required=True,
        type=lambda raw: _external_path(raw, "acknowledgement-root"),
    )
    return value


def parse_arguments(arguments: list[str]) -> argparse.Namespace:
    value = parser()
    for option in ("--interaction-plan-root", "--acknowledgement-root"):
        occurrences = sum(
            argument == option or argument.startswith(option + "=")
            for argument in arguments
        )
        if occurrences > 1:
            value.error(f"{option} may be provided only once")
    parsed = value.parse_args(arguments)
    if _overlaps(parsed.interaction_plan_root, parsed.acknowledgement_root):
        value.error("interaction and acknowledgement roots must not overlap")
    bindings: (
        tuple[DirectoryBinding, DirectoryBinding, DirectoryBinding] | None
    ) = None
    try:
        bindings = _bind_watch_roots(
            parsed.interaction_plan_root,
            parsed.acknowledgement_root,
        )
    except AcknowledgementError as error:
        value.error(str(error))
    finally:
        if bindings is not None:
            for binding in reversed(bindings):
                _close_directory(binding)
    return parsed


def _bind_directory(path: Path, label: str) -> DirectoryBinding:
    if not path.is_absolute() or any(part in ("", ".", "..") for part in path.parts[1:]):
        _fail(f"{label} is unsafe")
    chain: list[tuple[Path, tuple[int, int, int]]] = []
    for component in reversed((path, *path.parents)):
        try:
            metadata = component.lstat()
        except OSError:
            _fail(f"{label} is unsafe")
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
        ):
            _fail(f"{label} is unsafe")
        chain.append((component, _node_identity(metadata)))
    identity = chain[-1][1]
    handle: object | None = None
    try:
        if os.name == "nt":
            handle = _CREATE_FILE(
                str(path),
                _FILE_READ_ATTRIBUTES,
                _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                None,
                _OPEN_EXISTING,
                _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
            if handle == _INVALID_HANDLE_VALUE:
                _fail(f"{label} is unsafe")
            attributes = _FileAttributeTagInfo()
            file_id = _FileIdInfo()
            if (
                not _GET_FILE_INFORMATION(
                    handle,
                    _FILE_ATTRIBUTE_TAG_INFO_CLASS,
                    ctypes.byref(attributes),
                    ctypes.sizeof(attributes),
                )
                or attributes.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
                or not _GET_FILE_INFORMATION(
                    handle,
                    _FILE_ID_INFO_CLASS,
                    ctypes.byref(file_id),
                    ctypes.sizeof(file_id),
                )
                or (
                    file_id.volume_serial_number,
                    int.from_bytes(bytes(file_id.file_id.identifier), "little"),
                )
                != identity[:2]
            ):
                _fail(f"{label} is unsafe")
        else:
            handle = os.open(
                path,
                os.O_RDONLY
                | _O_DIRECTORY
                | _O_NOFOLLOW
                | _O_CLOEXEC,
            )
            opened = os.fstat(handle)
            if not stat.S_ISDIR(opened.st_mode) or _node_identity(opened) != identity:
                _fail(f"{label} is unsafe")
        binding = DirectoryBinding(path, tuple(chain), identity, handle)
        _revalidate_directory(binding, label)
        return binding
    except AcknowledgementError:
        if handle is not None:
            if os.name == "nt" and handle != _INVALID_HANDLE_VALUE:
                _CLOSE_HANDLE(handle)
            elif os.name != "nt":
                os.close(handle)
        raise
    except OSError as error:
        if handle is not None:
            if os.name == "nt":
                _CLOSE_HANDLE(handle)
            else:
                os.close(handle)
        raise AcknowledgementError(f"{label} is unsafe") from error


def _close_directory(binding: DirectoryBinding) -> None:
    try:
        if os.name == "nt":
            _CLOSE_HANDLE(binding.handle)
        else:
            os.close(binding.handle)
    except OSError:
        pass


def _directory_bindings_overlap(
    left: DirectoryBinding,
    right: DirectoryBinding,
) -> bool:
    left_chain = {identity for _path, identity in left.chain}
    right_chain = {identity for _path, identity in right.chain}
    return left.identity in right_chain or right.identity in left_chain


def _bind_watch_roots(
    interaction_plan_root: Path,
    acknowledgement_root: Path,
) -> tuple[DirectoryBinding, DirectoryBinding, DirectoryBinding]:
    held: list[DirectoryBinding] = []
    try:
        repository = _bind_directory(ROOT, "repository root")
        held.append(repository)
        plan = _bind_directory(interaction_plan_root, "interaction plan root")
        held.append(plan)
        acknowledgements = _bind_directory(
            acknowledgement_root, "acknowledgement root"
        )
        held.append(acknowledgements)
        if _directory_bindings_overlap(repository, plan) or _directory_bindings_overlap(
            repository, acknowledgements
        ):
            _fail("watch root configuration is invalid")
        if _directory_bindings_overlap(plan, acknowledgements):
            _fail("watch roots overlap")
        return repository, plan, acknowledgements
    except BaseException:
        for binding in reversed(held):
            _close_directory(binding)
        raise


def _revalidate_directory(binding: DirectoryBinding, label: str) -> None:
    for component, expected in binding.chain:
        try:
            metadata = component.lstat()
        except OSError:
            _fail(f"{label} identity changed")
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
            or _node_identity(metadata) != expected
        ):
            _fail(f"{label} identity changed")
    if os.name == "nt":
        attributes = _FileAttributeTagInfo()
        file_id = _FileIdInfo()
        if (
            not _GET_FILE_INFORMATION(
                binding.handle,
                _FILE_ATTRIBUTE_TAG_INFO_CLASS,
                ctypes.byref(attributes),
                ctypes.sizeof(attributes),
            )
            or attributes.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
            or not _GET_FILE_INFORMATION(
                binding.handle,
                _FILE_ID_INFO_CLASS,
                ctypes.byref(file_id),
                ctypes.sizeof(file_id),
            )
            or (
                file_id.volume_serial_number,
                int.from_bytes(bytes(file_id.file_id.identifier), "little"),
            )
            != binding.identity[:2]
        ):
            _fail(f"{label} identity changed")
    else:
        try:
            opened = os.fstat(binding.handle)
        except OSError:
            _fail(f"{label} identity changed")
        if not stat.S_ISDIR(opened.st_mode) or _node_identity(opened) != binding.identity:
            _fail(f"{label} identity changed")


def _revalidate_watch_roots(bindings: tuple[tuple[DirectoryBinding, str], ...]) -> None:
    for binding, label in bindings:
        _revalidate_directory(binding, label)


def _assert_receipt_absent(path: Path, receipts: DirectoryBinding) -> None:
    _revalidate_directory(receipts, "receipts root")
    try:
        _relative_stat(receipts, path.name)
    except FileNotFoundError:
        return
    except OSError:
        _fail("acknowledgement file already exists")
    _fail("acknowledgement file already exists")


def _challenge_identity(
    path: Path,
    challenges: DirectoryBinding,
) -> tuple[int, int, int, int, int]:
    try:
        metadata = _relative_stat(challenges, path.name)
    except OSError:
        _fail("challenge file identity changed")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or metadata.st_nlink != 1
    ):
        _fail("challenge file is unsafe")
    return _file_identity(metadata)


def _wait_for_challenge(
    path: Path,
    challenges: DirectoryBinding,
    bindings: tuple[tuple[DirectoryBinding, str], ...],
    *,
    monotonic: Callable[[], float],
    sleeper: Callable[[float], None],
    deadline: float,
    poll_interval: float,
) -> tuple[dict[str, object], tuple[int, int, int, int, int]]:
    while True:
        _revalidate_watch_roots(bindings)
        try:
            _relative_stat(challenges, path.name)
        except FileNotFoundError:
            now = monotonic()
            if now >= deadline:
                _fail("challenge wait timed out")
            sleeper(min(poll_interval, deadline - now))
            continue
        except OSError:
            _fail("challenge file is unsafe")
        challenge = read_challenge(path, challenges)
        return challenge, _challenge_identity(path, challenges)


def _confirm_check(
    challenge: dict[str, object],
    check: str,
    input_fn: Callable[[str], str],
) -> bool:
    prompt = (
        f"{challenge['roundId']} {challenge['runtimeId']} {challenge['appId']}: "
        f"confirm {check} [yes/no]: "
    )
    try:
        response = input_fn(prompt)
    except (EOFError, KeyboardInterrupt) as error:
        raise AcknowledgementError("operator cancelled acknowledgement") from error
    if type(response) is not str:
        _fail("operator response is invalid")
    normalized = response.strip().lower()
    if normalized in ("no", "n"):
        return False
    if normalized in ("cancel", "c"):
        _fail("operator cancelled acknowledgement")
    if normalized not in ("yes", "y"):
        _fail("operator response is invalid")
    return True


def watch(
    interaction_plan_root: Path,
    acknowledgement_root: Path,
    *,
    input_fn: Callable[[str], str] = input,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    poll_interval: float = DEFAULT_POLL_SECONDS,
    deadline_seconds: float = DEFAULT_WATCH_SECONDS,
) -> int:
    """Watch and acknowledge the fixed twelve GUI challenges in order."""

    if (
        type(poll_interval) not in (int, float)
        or isinstance(poll_interval, bool)
        or not MIN_POLL_SECONDS <= poll_interval <= MAX_POLL_SECONDS
        or type(deadline_seconds) not in (int, float)
        or isinstance(deadline_seconds, bool)
        or not poll_interval <= deadline_seconds <= MAX_WATCH_SECONDS
    ):
        _fail("watch timing configuration is invalid")
    if not callable(input_fn) or not callable(monotonic) or not callable(sleeper):
        _fail("watch callback configuration is invalid")
    if not isinstance(interaction_plan_root, Path) or not isinstance(
        acknowledgement_root, Path
    ) or not _is_external_root(interaction_plan_root) or not _is_external_root(
        acknowledgement_root
    ):
        _fail("watch root configuration is invalid")
    if _overlaps(interaction_plan_root, acknowledgement_root):
        _fail("watch roots overlap")

    challenges_root = acknowledgement_root / "challenges"
    receipts_root = acknowledgement_root / "receipts"
    held: list[DirectoryBinding] = []
    try:
        repository_binding, plan_binding, acknowledgement_binding = _bind_watch_roots(
            interaction_plan_root,
            acknowledgement_root,
        )
        held.extend((repository_binding, plan_binding, acknowledgement_binding))
        challenge_binding = _bind_directory(challenges_root, "challenges root")
        held.append(challenge_binding)
        receipt_binding = _bind_directory(receipts_root, "receipts root")
        held.append(receipt_binding)
        bindings = (
            (repository_binding, "repository root"),
            (plan_binding, "interaction plan root"),
            (acknowledgement_binding, "acknowledgement root"),
            (challenge_binding, "challenges root"),
            (receipt_binding, "receipts root"),
        )
        deadline = monotonic() + deadline_seconds

        completed = 0
        rejected = 0
        for round_id in ROUND_IDS:
            for runtime_id in RUNTIME_IDS:
                for app_id in APPLICATION_IDS:
                    name = f"{round_id}--{runtime_id}--{app_id}.json"
                    challenge_path = challenges_root / name
                    receipt_path = receipts_root / name
                    _assert_receipt_absent(receipt_path, receipt_binding)
                    challenge, identity = _wait_for_challenge(
                        challenge_path,
                        challenge_binding,
                        bindings,
                        monotonic=monotonic,
                        sleeper=sleeper,
                        deadline=deadline,
                        poll_interval=float(poll_interval),
                    )
                    if (
                        challenge["roundId"] != round_id
                        or challenge["runtimeId"] != runtime_id
                        or challenge["appId"] != app_id
                    ):
                        _fail("challenge identity is invalid")
                    acknowledged = all(
                        _confirm_check(challenge, check, input_fn)
                        for check in challenge["requiredChecks"]
                    )
                    if not acknowledged:
                        rejected += 1
                        continue
                    _revalidate_watch_roots(bindings)
                    if (
                        _challenge_identity(challenge_path, challenge_binding)
                        != identity
                    ):
                        _fail("challenge file identity changed")
                    if read_challenge(challenge_path, challenge_binding) != challenge:
                        _fail("challenge file identity changed")
                    _assert_receipt_absent(receipt_path, receipt_binding)
                    write_acknowledgement(
                        receipt_path,
                        make_acknowledgement(challenge),
                        receipt_binding,
                    )
                    _revalidate_watch_roots(bindings)
                    completed += 1
        if rejected:
            _fail("one or more interactions were not acknowledged")
        return completed
    finally:
        for binding in reversed(held):
            _close_directory(binding)


def main(arguments: list[str] | None = None) -> int:
    parsed = parse_arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        completed = watch(
            parsed.interaction_plan_root,
            parsed.acknowledgement_root,
        )
    except AcknowledgementError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(f"acknowledged {completed} macOS GUI interactions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
