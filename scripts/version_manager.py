#!/usr/bin/env python3
"""Local, explicit-source version maintenance. Python 3.11+; no third-party code."""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import tomllib
from typing import Any


class VersionError(ValueError):
    """A safe refusal. Nothing has been intentionally changed."""


SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z")
PYTHON_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:(a|b|rc)(0|[1-9][0-9]*))?\Z")
APPLE_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")
FORMATS = {"semver", "pep440", "apple", "opaque"}


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int
    pre: tuple[str, ...] = ()
    build: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str, fmt: str = "semver") -> "Version":
        if not isinstance(value, str):
            raise VersionError("Version values must be strings")
        if fmt == "opaque":
            if not value or len(value) > 128 or value != value.strip() or any(ord(x) < 32 for x in value):
                raise VersionError("Invalid opaque version literal")
            return LiteralVersion(value)
        if fmt == "semver":
            match = SEMVER.fullmatch(value)
            if not match:
                raise VersionError(f"Unsupported SemVer: {value!r}")
            a, b, c, pre, build = match.groups()
            pieces = tuple(pre.split(".")) if pre else ()
            if any(x.isdigit() and len(x) > 1 and x.startswith("0") for x in pieces):
                raise VersionError(f"Leading zero in prerelease: {value!r}")
            return cls(int(a), int(b), int(c), pieces, tuple(build.split(".")) if build else ())
        if fmt == "pep440":
            match = PYTHON_VERSION.fullmatch(value)
            if not match:
                raise VersionError(f"Only three-component PEP 440 releases and a/b/rc prereleases are supported: {value!r}")
            a, b, c, stage, n = match.groups()
            return cls(int(a), int(b), int(c), ({"a": "alpha", "b": "beta", "rc": "rc"}[stage], n) if stage else ())
        if fmt == "apple":
            match = APPLE_VERSION.fullmatch(value)
            if not match:
                raise VersionError(f"Unsupported Apple marketing version (three numeric components only): {value!r}")
            return cls(*(int(x) for x in match.groups()))
        raise VersionError(f"Unknown version format: {fmt}")

    def render(self, fmt: str = "semver") -> str:
        value = f"{self.major}.{self.minor}.{self.patch}"
        if fmt == "semver":
            return value + ("-" + ".".join(self.pre) if self.pre else "") + ("+" + ".".join(self.build) if self.build else "")
        if fmt == "pep440":
            if self.build or (self.pre and not (len(self.pre) == 2 and self.pre[0] in {"alpha", "beta", "rc"} and self.pre[1].isdigit())):
                raise VersionError("Version has no supported explicit PEP 440 representation")
            if self.pre:
                value += {"alpha": "a", "beta": "b", "rc": "rc"}[self.pre[0]] + self.pre[1]
            return value
        if fmt == "apple":
            if self.pre or self.build or not APPLE_VERSION.fullmatch(value):
                raise VersionError("Apple marketing versions cannot contain prerelease/build metadata ")
            return value
        raise VersionError(f"Unknown version format: {fmt}")

    def precedence_key(self):
        return (self.major, self.minor, self.patch, not bool(self.pre), tuple((0, int(x)) if x.isdigit() else (1, x) for x in self.pre))

    def bump(self, part: str, preid: str | None = None) -> "Version":
        a, b, c = self.major, self.minor, self.patch
        if preid is not None and not re.fullmatch(r"[A-Za-z-][0-9A-Za-z-]*", preid):
            raise VersionError("--preid must be one nonnumeric SemVer identifier")
        if preid and part != "prerelease":
            raise VersionError("--preid is only valid with bump prerelease")
        if part == "major":
            return Version(a if self.pre and b == c == 0 else a + 1, 0, 0)
        if part == "minor":
            return Version(a, b if self.pre and c == 0 else b + 1, 0)
        if part == "patch":
            return Version(a, b, c if self.pre else c + 1)
        if part != "prerelease":
            raise VersionError(f"Unknown bump part: {part}")
        if not self.pre:
            if not preid:
                raise VersionError("Starting a prerelease requires --preid, for example --preid rc")
            return Version(a, b, c + 1, (preid, "0"))
        if preid and self.pre[0] != preid:
            return Version(a, b, c, (preid, "0"))
        pieces = list(self.pre)
        for i in range(len(pieces) - 1, -1, -1):
            if pieces[i].isdigit():
                pieces[i] = str(int(pieces[i]) + 1)
                break
        else:
            pieces.append("0")
        return Version(a, b, c, tuple(pieces))


@dataclass(frozen=True)
class LiteralVersion:
    value: str

    def render(self, fmt="opaque"):
        if fmt != "opaque":
            raise VersionError("Opaque literals cannot be converted between version formats")
        return self.value


def strict_json(text: str) -> Any:
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise VersionError(f"Duplicate JSON key: {key!r}")
            out[key] = value
        return out
    def constant(value):
        raise VersionError(f"Nonstandard JSON constant: {value}")
    try:
        return json.loads(text.removeprefix("\ufeff"), object_pairs_hook=pairs, parse_constant=constant)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise VersionError(f"Invalid JSON: {exc}") from exc


def allowed_keys(obj: Any, required: set[str], optional: set[str], what: str):
    if not isinstance(obj, dict) or not required <= obj.keys() or obj.keys() - required - optional:
        raise VersionError(f"Invalid {what}; required keys {sorted(required)}, optional keys {sorted(optional)}")


def relative_path(root: Path, name: str) -> Path:
    if not isinstance(name, str) or not name or "\\" in name or ":" in name or any(ord(x) < 32 for x in name):
        raise VersionError(f"Invalid repository-relative path: {name!r}")
    pure = PurePosixPath(name)
    if pure.is_absolute() or name != pure.as_posix() or any(x.casefold() in {".", "..", ".git", "node_modules", ".venv", "venv", "vendor", "target", "dist"} for x in pure.parts):
        raise VersionError(f"Unsafe or generated/dependency path: {name!r}")
    path = root
    for part in pure.parts:
        path = path / part
        if path.is_symlink():
            raise VersionError(f"Symlink paths are unsupported: {name}")
    if not path.is_file():
        raise VersionError(f"Missing or nonregular configured file: {name}")
    if not stat.S_ISREG(path.stat().st_mode):
        raise VersionError(f"Nonregular configured file: {name}")
    return path


def pointer_parts(pointer: str) -> tuple[str, ...]:
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
        raise VersionError("JSON pointer must be empty or start with /")
    if re.search(r"~(?![01])", pointer):
        raise VersionError("Invalid JSON pointer escape")
    return tuple(x.replace("~1", "/").replace("~0", "~") for x in pointer[1:].split("/")) if pointer else ()


def json_spans(text: str) -> dict[tuple[str, ...], tuple[int, int, Any]]:
    """Parse validated JSON and retain exact string-token spans; never reserialize it."""
    strict_json(text)
    decoder = json.JSONDecoder()
    spans = {}
    def whitespace(i):
        while i < len(text) and text[i].isspace():
            i += 1
        return i
    def walk(i, path):
        i = whitespace(i)
        if text[i] == "{":
            i = whitespace(i + 1)
            if text[i] == "}":
                return i + 1
            while True:
                key, end = decoder.raw_decode(text, i)
                i = whitespace(end) + 1  # colon is guaranteed by strict_json
                i = whitespace(walk(i, path + (key,)))
                if text[i] == "}":
                    return i + 1
                i = whitespace(i + 1)
        elif text[i] == "[":
            i = whitespace(i + 1)
            if text[i] == "]":
                return i + 1
            index = 0
            while True:
                i = whitespace(walk(i, path + (str(index),)))
                if text[i] == "]":
                    return i + 1
                i = whitespace(i + 1)
                index += 1
        else:
            value, end = decoder.raw_decode(text, i)
            spans[path] = (i, end, value)
            return end
    try:
        walk(1 if text.startswith("\ufeff") else 0, ())
    except (IndexError, RecursionError) as exc:
        raise VersionError("Unsupported JSON nesting") from exc
    return spans


def toml_lines(text: str):
    """Yield offsets of statement-leading lines, excluding multiline-string contents."""
    state = None
    offset = 0
    for line in text.splitlines(keepends=True):
        if state is None:
            yield offset, line
        i = 0
        while i < len(line):
            if state in {"'''", '\"\"\"'}:
                if line.startswith(state, i):
                    i += 3
                    state = None
                elif state == '\"\"\"' and line[i] == "\\":
                    i += 2
                else:
                    i += 1
            elif state in {"'", '"'}:
                if state == '"' and line[i] == "\\":
                    i += 2
                elif line[i] == state:
                    state = None
                    i += 1
                else:
                    i += 1
            elif line[i] == "#":
                break
            elif line[i] in {"'", '"'}:
                state = line[i] * 3 if line.startswith(line[i] * 3, i) else line[i]
                i += len(state)
            else:
                i += 1
        offset += len(line)


def source_span(text: str, source: dict) -> tuple[int, int, str, str]:
    """Return the exactly bound token span, current value and serialization type."""
    adapter = source["adapter"]
    if adapter == "json":
        span = json_spans(text).get(pointer_parts(source["pointer"]))
        if not span or not isinstance(span[2], str):
            raise VersionError(f"JSON pointer does not bind one existing string: {source['pointer']}")
        return *span, "json"
    if adapter == "text":
        match = re.fullmatch(r"([^\r\n]+)(?:\r?\n)?", text)
        if not match:
            raise VersionError("Plain version file must have one nonempty line")
        return match.start(1), match.end(1), match[1], "raw"
    if adapter == "toml":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise VersionError(f"Invalid TOML: {exc}") from exc
        try:
            for key in source["table"]:
                data = data[key]
            value = data[source["key"]]
        except (KeyError, TypeError):
            raise VersionError("Missing literal TOML table/key") from None
        if not isinstance(value, str):
            raise VersionError("TOML source is inherited/dynamic/non-string; a literal is required")
        current = ()
        matches = []
        for offset, line in toml_lines(text):
            stripped = line.lstrip()
            if stripped.startswith("["):
                header = re.fullmatch(r"\s*\[\s*([A-Za-z0-9_-]+(?:\s*\.\s*[A-Za-z0-9_-]+)*)\s*\]\s*(?:#[^\r\n]*)?\r?\n?", line)
                current = tuple(re.split(r"\s*\.\s*", header[1])) if header else None
            if current == tuple(source["table"]):
                pattern = r"\s*" + re.escape(source["key"]) + r"\s*=\s*(['\"])([^'\"\r\n\\]*)\1\s*(?:#[^\r\n]*)?\r?\n?"
                match = re.fullmatch(pattern, line)
                if match:
                    matches.append((offset + match.start(2), offset + match.end(2), match[2], "raw"))
        if len(matches) != 1 or matches[0][2] != value:
            raise VersionError("TOML binding is not one unambiguous single-line literal; quoted/dotted keys, inline tables and multiline values need a dedicated adapter")
        return matches[0]
    if adapter == "python":
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            raise VersionError(f"Invalid Python source: {exc}") from exc
        name = source["name"]
        writes = [node for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, (ast.Store, ast.Del))]
        shadows = [node for node in ast.walk(tree) if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name) or (isinstance(node, ast.alias) and (node.asname or node.name.split(".")[0]) == name)]
        assignments = []
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name:
                assignments.append(node.value)
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
                assignments.append(node.value)
        if len(writes) != 1 or shadows or len(assignments) != 1 or not isinstance(assignments[0], ast.Constant) or not isinstance(assignments[0].value, str):
            raise VersionError("Python version must be one unambiguous top-level simple string assignment")
        node = assignments[0]
        segment = ast.get_source_segment(text, node)
        match = re.fullmatch(r"(['\"])([^'\"\r\n\\]*)\1", segment or "")
        if not match:
            raise VersionError("Python source requires one simple single-line quoted literal")
        lines = text.splitlines(keepends=True)
        start = sum(len(x) for x in lines[:node.lineno - 1]) + len(lines[node.lineno - 1].encode("utf-8")[:node.col_offset].decode("utf-8"))
        return start + 1, start + len(segment) - 1, node.value, "raw"
    if adapter == "cargo-lock":
        try:
            data = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise VersionError(f"Invalid Cargo.lock TOML: {exc}") from exc
        candidates = [x for x in data.get("package", []) if isinstance(x, dict) and x.get("name") == source["package"]]
        local = [x for x in candidates if "source" not in x and "checksum" not in x]
        if len(local) != 1:
            raise VersionError("Cargo.lock binding requires exactly one local package with matching name and no source/checksum")
        for package in data.get("package", []):
            for dependency in package.get("dependencies", []):
                if isinstance(dependency, str) and dependency.split()[:1] == [source["package"]] and len(dependency.split()) > 1:
                    raise VersionError("Cargo.lock has a version-qualified dependency reference to this package; use Cargo to update the lockfile safely")
        starts = [(offset, line) for offset, line in toml_lines(text) if re.fullmatch(r"\s*\[\[package\]\]\s*(?:#[^\r\n]*)?\r?\n?", line)]
        spans = []
        for index, (start, _) in enumerate(starts):
            end = starts[index + 1][0] if index + 1 < len(starts) else len(text)
            block = text[start:end]
            try:
                package = tomllib.loads(block)["package"][0]
            except (tomllib.TOMLDecodeError, KeyError, IndexError, TypeError) as exc:
                raise VersionError("Unsupported Cargo.lock package block structure") from exc
            if package.get("name") == source["package"] and "source" not in package and "checksum" not in package:
                # Reuse strict literal TOML binding after replacing only this block's header.
                header_end = block.index("\n") + 1 if "\n" in block else len(block)
                body = block[header_end:]
                left, right, value, encoding = source_span(body, {"adapter": "toml", "table": [], "key": "version"})
                spans.append((start + header_end + left, start + header_end + right, value, encoding))
        if len(spans) != 1 or spans[0][2] != local[0].get("version"):
            raise VersionError("Cargo.lock target is ambiguous or not a literal version")
        return spans[0]
    if adapter == "line":
        syntax = source["syntax"]
        if syntax == "swift":
            if any(marker in text for marker in ('/*', '*/', '"""', '#/', '/#')):
                raise VersionError("Swift line adapter conservatively refuses block comments, multiline strings and extended regex literals; use a dedicated version file or native tool")
            comment_marker = "//"
        else:
            if re.search(r"\[=*\[|\]=*\]", text):
                raise VersionError("CMake line adapter conservatively refuses bracket comments/strings; use a dedicated version file or native tool")
            comment_marker = "#"
        for line in text.splitlines():
            quoted = False
            index = 0
            while index < len(line):
                if line[index] == "\\":
                    index += 2
                    continue
                if not quoted and line.startswith(comment_marker, index):
                    break
                if line[index] == '"':
                    quoted = not quoted
                index += 1
            if quoted:
                raise VersionError("Line adapter refuses multiline quoted strings")
        prefix, suffix = source["prefix"], source["suffix"]
        matches = []
        offset = 0
        for line in text.splitlines(keepends=True):
            body = line.rstrip("\r\n")
            if body.startswith(prefix) and body.endswith(suffix) and len(body) >= len(prefix) + len(suffix):
                end = len(body) - len(suffix) if suffix else len(body)
                matches.append((offset + len(prefix), offset + end, body[len(prefix):end], "raw"))
            offset += len(line)
        if len(matches) != 1:
            raise VersionError(f"Exact line binding expected 1 occurrence; found {len(matches)}")
        return matches[0]
    raise VersionError(f"Unsupported adapter: {adapter}")


def validate_source(source: dict):
    allowed_keys(source, {"path", "adapter"}, {"format", "pointer", "table", "key", "prefix", "suffix", "expected_occurrences", "syntax", "package", "name"}, "source")
    if not isinstance(source["path"], str) or not isinstance(source["adapter"], str):
        raise VersionError("Source path and adapter must be strings")
    fmt = source.get("format", "semver")
    if not isinstance(fmt, str) or fmt not in FORMATS:
        raise VersionError(f"Unsupported format: {fmt}")
    adapter = source["adapter"]
    extras = set(source) - {"path", "adapter", "format"}
    required = {"json": {"pointer"}, "toml": {"table", "key"}, "text": set(), "python": {"name"}, "cargo-lock": {"package"}, "line": {"prefix", "suffix", "expected_occurrences", "syntax"}}
    if adapter not in required or extras != required[adapter]:
        raise VersionError(f"Invalid fields for adapter {adapter!r}; expected {sorted(required.get(adapter, []))}")
    if adapter == "python":
        if not isinstance(source["name"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", source["name"]):
            raise VersionError("Python binding requires one exact identifier")
    if adapter == "cargo-lock":
        if not isinstance(source["package"], str) or not re.fullmatch(r"[A-Za-z0-9_-]+", source["package"]):
            raise VersionError("Cargo.lock package must be an exact package name")
        if Path(source["path"]).name != "Cargo.lock":
            raise VersionError("cargo-lock adapter only supports Cargo.lock files")
    if adapter == "json":
        parts = pointer_parts(source["pointer"])
        if any(part in {"dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "resolutions", "overrides"} or "node_modules" in part.split("/") for part in parts):
            raise VersionError("Dependency/registry JSON fields may not be version sources")
    if adapter == "toml":
        if not isinstance(source["table"], list) or not all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_-]+", x) for x in source["table"]):
            raise VersionError("TOML table must be a list of bare key segments")
        if any(x in {"dependencies", "dev-dependencies", "build-dependencies", "patch", "replace"} for x in source["table"]):
            raise VersionError("Dependency TOML tables may not be version sources")
        if not isinstance(source["key"], str) or not re.fullmatch(r"[A-Za-z0-9_-]+", source["key"]):
            raise VersionError("TOML key must be a bare key")
    if adapter == "line":
        prefix, suffix = source["prefix"], source["suffix"]
        if not isinstance(prefix, str) or not isinstance(suffix, str) or not prefix or any(x in prefix + suffix for x in "\n\r"):
            raise VersionError("Line binding requires a nonempty single-line prefix and a single-line suffix")
        if type(source["expected_occurrences"]) is not int or source["expected_occurrences"] != 1:
            raise VersionError("Only exactly one expected line occurrence is supported")
        binding = prefix + "__VERSION__" + suffix
        patterns = {
            "swift": r'\s*(?:(?:public|private|fileprivate|internal|package)\s+)?(?:(?:static|class)\s+)?let\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*:\s*String)?\s*=\s*"__VERSION__"\s*(?://[^\r\n]*)?',
            "cmake-project": r'\s*project\(\s*[A-Za-z_][A-Za-z0-9_-]*\s+VERSION\s+(?:"__VERSION__"|__VERSION__)(?:\s+LANGUAGES\s+[A-Za-z_]+(?:\s+[A-Za-z_]+)*)?\s*\)\s*(?:#[^\r\n]*)?',
            "cmake-set": r'\s*set\(\s*[A-Za-z_][A-Za-z0-9_]*\s+(?:"__VERSION__"|__VERSION__)\s*\)\s*(?:#[^\r\n]*)?',
        }
        syntax = source["syntax"]
        if syntax not in patterns or not re.fullmatch(patterns[syntax], binding):
            raise VersionError("Line bindings only support an exact simple Swift let or CMake set/project literal; arbitrary expressions are refused")


@dataclass
class Snapshot:
    path: Path
    raw: bytes
    text: str
    mode: int


@dataclass
class Binding:
    unit: str
    source: dict
    start: int
    end: int
    value: str
    encoding: str
    version: Version


class Manager:
    def __init__(self, root: Path, config: str = "versioning.json"):
        original_root = Path(os.path.abspath(root))
        if any(part.casefold() == ".git" for part in original_root.parts):
            raise VersionError("Repository root may not be inside .git")
        for candidate in [original_root, *original_root.parents]:
            if candidate.is_symlink():
                raise VersionError("Repository root must not traverse symlinks; use its verified real path")
        self.root = original_root.resolve(strict=True)
        self._validated_plan = None
        self.config_name = config
        self.snapshots: dict[str, Snapshot] = {}
        config_text = self.read(config).text
        self.config = strict_json(config_text)
        allowed_keys(self.config, {"schema_version", "units"}, {"notes", "unmanaged"}, "configuration")
        if type(self.config["schema_version"]) is not int or self.config["schema_version"] != 1:
            raise VersionError("Unsupported schema_version; expected integer 1")
        units = self.config["units"]
        unmanaged = self.config.get("unmanaged", [])
        if not isinstance(unmanaged, list):
            raise VersionError("unmanaged must be an array")
        for entry in unmanaged:
            allowed_keys(entry, {"name", "reason"}, {"paths"}, "unmanaged entry")
            if not all(isinstance(entry[x], str) and entry[x].strip() for x in ("name", "reason")):
                raise VersionError("Unmanaged entries require a nonempty name and reason")
            if "paths" in entry and (not isinstance(entry["paths"], list) or not all(isinstance(x, str) for x in entry["paths"])):
                raise VersionError("Unmanaged paths must be an array of descriptive strings")
        if not isinstance(units, dict) or not units and not unmanaged:
            raise VersionError("units must be an object; empty units require explicit unmanaged entries")
        seen = set()
        occupied = {}
        for name, unit in units.items():
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
                raise VersionError(f"Invalid unit name: {name!r}")
            allowed_keys(unit, {"canonical"}, {"mirrors", "notes", "read_only", "assertions"}, "release unit")
            if type(unit.get("read_only", False)) is not bool:
                raise VersionError("read_only must be boolean")
            assertions = unit.get("assertions", [])
            if not isinstance(assertions, list):
                raise VersionError("assertions must be an array")
            for assertion in assertions:
                allowed_keys(assertion, {"path", "adapter", "equals"}, {"pointer", "table", "key"}, "assertion")
                a = assertion["adapter"]
                expected = {"path", "adapter", "equals", *({"pointer"} if a == "json" else {"table", "key"})}
                if a not in {"json", "toml"} or set(assertion) != expected:
                    raise VersionError("Assertions require a JSON pointer or TOML table/key")
                if a == "json":
                    pointer_parts(assertion["pointer"])
                elif not isinstance(assertion["table"], list) or not all(isinstance(x, str) for x in assertion["table"]) or not isinstance(assertion["key"], str):
                    raise VersionError("TOML assertion table/key must be strings")
                relative_path(self.root, assertion["path"])
            mirrors = unit.get("mirrors", [])
            if not isinstance(mirrors, list):
                raise VersionError("mirrors must be an array")
            for source in [unit["canonical"], *mirrors]:
                validate_source(source)
                if source.get("format") == "opaque" and not unit.get("read_only", False):
                    raise VersionError("Opaque versions require read_only:true on their release unit")
                if source["path"] == config:
                    raise VersionError("Configuration may not be a version source")
                # Validate path policy even for unselected units, without reading their content.
                relative_path(self.root, source["path"])
                identity = json.dumps({k: v for k, v in source.items() if k != "format"}, sort_keys=True)
                if identity in seen:
                    raise VersionError("Duplicate source binding across or within release units")
                seen.add(identity)
                start, end, _, _ = source_span(self.read(source["path"]).text, source)
                for left, right, owner in occupied.get(source["path"], []):
                    if start < right and end > left:
                        raise VersionError(f"Source collision in {source['path']} between {owner} and {name}")
                occupied.setdefault(source["path"], []).append((start, end, name))

    def read(self, name: str) -> Snapshot:
        if name not in self.snapshots:
            path = relative_path(self.root, name)
            raw = path.read_bytes()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise VersionError(f"Configured file is not UTF-8 text: {name}") from exc
            self.snapshots[name] = Snapshot(path, raw, text, stat.S_IMODE(path.stat().st_mode))
        return self.snapshots[name]

    def select(self, name: str | None = None, single: bool = False) -> list[str]:
        units = self.config["units"]
        if name:
            if name not in units:
                raise VersionError(f"Unknown release unit: {name}")
            return [name]
        if single and len(units) != 1:
            raise VersionError("Choose --unit explicitly; release units are independent")
        return list(units)

    def check_assertions(self, unit: dict, texts: dict[str, str] | None = None):
        for assertion in unit.get("assertions", []):
            path = assertion["path"]
            text = texts[path] if texts and path in texts else self.read(path).text
            try:
                if assertion["adapter"] == "json":
                    value = strict_json(text)
                    for part in pointer_parts(assertion["pointer"]):
                        value = value[int(part)] if isinstance(value, list) else value[part]
                else:
                    value = tomllib.loads(text)
                    for part in assertion["table"]:
                        value = value[part]
                    value = value[assertion["key"]]
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                raise VersionError(f"Missing or invalid assertion binding: {path}") from exc
            if type(value) is not type(assertion["equals"]) or value != assertion["equals"]:
                raise VersionError(f"Assertion failed: {path}; expected {assertion['equals']!r}, found {value!r}")

    def inspect(self, names: list[str], texts: dict[str, str] | None = None) -> list[Binding]:
        bindings = []
        occupied = {}
        for name in names:
            unit = self.config["units"][name]
            self.check_assertions(unit, texts)
            canonical = None
            for source in [unit["canonical"], *unit.get("mirrors", [])]:
                path = source["path"]
                text = texts[path] if texts is not None and path in texts else self.read(path).text
                try:
                    start, end, value, encoding = source_span(text, source)
                    version = Version.parse(value, source.get("format", "semver"))
                    if source.get("syntax") == "cmake-project" and isinstance(version, Version) and (version.pre or version.build):
                        raise VersionError("CMake project VERSION only accepts numeric release components")
                except VersionError as exc:
                    raise VersionError(f"{name}: {path}: {exc}") from exc
                if canonical is None:
                    canonical = version
                elif version != canonical:
                    raise VersionError(f"{name}: version mismatch in {path}: {value!r}; canonical is {canonical.render()!r}")
                for left, right in occupied.get(path, []):
                    if start < right and end > left:
                        raise VersionError(f"Overlapping source bindings in {path}")
                occupied.setdefault(path, []).append((start, end))
                bindings.append(Binding(name, source, start, end, value, encoding, version))
        return bindings

    def plan(self, name: str | None, *, part: str | None = None, value: str | None = None, preid: str | None = None, expect: str | None = None, allow_downgrade: bool = False, allow_stable: bool = False):
        names = self.select(name, single=True)
        if self.config["units"][names[0]].get("read_only", False):
            raise VersionError("This release unit is read-only; use its documented native release process")
        bindings = self.inspect(names)
        current = bindings[0].version
        canonical_format = bindings[0].source.get("format", "semver")
        if expect is not None and bindings[0].value != expect:
            raise VersionError(f"Stale --expect: expected {expect!r}, found {bindings[0].value!r}")
        if (part is None) == (value is None):
            raise VersionError("Choose exactly one bump or set operation")
        target = current.bump(part, preid) if part else Version.parse(value, canonical_format)
        if current.pre and not target.pre and not allow_stable:
            raise VersionError("Removing prerelease status requires explicit --allow-stable")
        if target.precedence_key() < current.precedence_key() and not allow_downgrade:
            raise VersionError("Version downgrade refused; an intentional set downgrade requires --allow-downgrade")
        edits = {}
        for binding in bindings:
            new_value = target.render(binding.source.get("format", "semver"))
            if new_value == binding.value:
                continue
            rendered = json.dumps(new_value, ensure_ascii=False) if binding.encoding == "json" else new_value
            edits.setdefault(binding.source["path"], []).append((binding.start, binding.end, rendered))
        proposed = {}
        for path, spans in edits.items():
            text = self.read(path).text
            for start, end, rendered in sorted(spans, reverse=True):
                text = text[:start] + rendered + text[end:]
            proposed[path] = text
        checked = self.inspect(names, proposed)
        if any(binding.version != target for binding in checked):
            raise VersionError("Proposed update failed exact target verification")
        self._validated_plan = dict(proposed)
        return {"unit": names[0], "current": bindings[0].value, "target": target.render(canonical_format), "files": sorted(proposed)}, proposed

    def verify_unchanged(self):
        for name, snapshot in self.snapshots.items():
            path = relative_path(self.root, name)
            if path.read_bytes() != snapshot.raw or stat.S_IMODE(path.stat().st_mode) != snapshot.mode:
                raise VersionError(f"File changed after validation: {name}; rerun from current files")

    def apply(self, proposed: dict[str, str]):
        if self._validated_plan is None or proposed != self._validated_plan:
            raise VersionError("Apply accepts only the unchanged, validated plan produced by this manager")
        if not proposed:
            return
        self.verify_unchanged()
        lock = self.root / ".versioning.lock"
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            raise VersionError(".versioning.lock already exists; another update or interrupted update requires inspection") from None
        os.close(fd)
        staged, backups, replaced = {}, {}, []
        retain_backups = False
        def stage(path, raw, mode, suffix):
            fd, temporary = tempfile.mkstemp(prefix=".versioning-", suffix=suffix, dir=path.parent)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fchmod(stream.fileno(), mode)
                    os.fsync(stream.fileno())
                return Path(temporary)
            except BaseException:
                Path(temporary).unlink(missing_ok=True)
                raise
        try:
            self.verify_unchanged()
            for name, text in proposed.items():
                snapshot = self.snapshots[name]
                staged[name] = stage(snapshot.path, text.encode("utf-8"), snapshot.mode, ".tmp")
                backups[name] = stage(snapshot.path, snapshot.raw, snapshot.mode, ".bak")
            self.verify_unchanged()
            for name in proposed:
                snapshot = self.snapshots[name]
                if relative_path(self.root, name).read_bytes() != snapshot.raw:
                    raise VersionError(f"Concurrent modification detected: {name}")
                os.replace(staged[name], snapshot.path)
                replaced.append(name)
        except BaseException as exc:
            failures = []
            for name in reversed(replaced):
                snapshot = self.snapshots[name]
                try:
                    if relative_path(self.root, name).read_bytes() != proposed[name].encode("utf-8"):
                        raise VersionError("File was modified by another writer during rollback")
                    os.replace(backups[name], snapshot.path)
                except BaseException as rollback_error:
                    failures.append(f"{name}: {rollback_error}; backup: {backups[name].name}")
            if failures:
                retain_backups = True
                raise VersionError("Update interrupted; manual recovery required: " + "; ".join(failures)) from exc
            raise
        finally:
            for temporary in staged.values():
                temporary.unlink(missing_ok=True)
            if not retain_backups:
                for backup in backups.values():
                    backup.unlink(missing_ok=True)
                lock.unlink(missing_ok=True)


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root (default: working directory)")
    parser.add_argument("--config", default="versioning.json", help="repository-relative config path")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("show", "check", "bump", "set"):
        child = sub.add_parser(command)
        child.add_argument("--unit")
        if command in {"bump", "set"}:
            child.add_argument("--apply", action="store_true", help="write the fully validated plan; otherwise preview only")
            child.add_argument("--allow-stable", action="store_true", help="explicitly permit removing prerelease status")
            child.add_argument("--expect", help="refuse if the canonical literal differs from this value")
            if command == "bump":
                child.add_argument("part", choices=("major", "minor", "patch", "prerelease"))
                child.add_argument("--preid")
            else:
                child.add_argument("version")
                child.add_argument("--allow-downgrade", action="store_true", help="allow an explicit set to lower version precedence")
    args = parser.parse_args(argv)
    try:
        manager = Manager(Path(args.root), args.config)
        if args.command in {"show", "check"}:
            bindings = manager.inspect(manager.select(args.unit))
            units = {}
            for binding in bindings:
                units.setdefault(binding.unit, {"version": binding.value, "sources": []})["sources"].append(binding.source)
            print(json.dumps({"status": "ok", "units": units, "unmanaged": manager.config.get("unmanaged", [])}, indent=2))
        else:
            if args.apply and args.expect is None:
                raise VersionError("--apply requires --expect CURRENT_VERSION to bind the intended starting version")
            options = {"part": args.part, "preid": args.preid} if args.command == "bump" else {"value": args.version, "allow_downgrade": args.allow_downgrade}
            summary, proposed = manager.plan(args.unit, expect=args.expect, allow_stable=args.allow_stable, **options)
            if args.apply:
                manager.apply(proposed)
            summary["mode"] = "apply" if args.apply else "dry-run"
            summary["changed"] = bool(proposed)
            print(json.dumps(summary, indent=2))
        return 0
    except (VersionError, OSError, TypeError) as exc:
        print(f"version-manager: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(cli())
