from __future__ import annotations

import json
import importlib.util
import re
import sys
import os
import tempfile
import time
import hashlib
import copy
from unittest import mock
from dataclasses import replace
from types import SimpleNamespace
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_SCHEMA = ROOT / "schemas" / "linux-provider.schema.json"
BOOTSTRAP_SCHEMA = ROOT / "schemas" / "linux-bootstrap-request.schema.json"


def runner_module():
    name = "compatforge_linux_console_runner"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            name, ROOT / "tools" / "run_linux_console_preview.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def runner_args():
    base = ROOT.parent / "runner-fixtures"
    return [
        "--cli", str(base / "cli"),
        "--compiler", str(base / "compiler"),
        "--runtime-store-root", str(base / "runtime"),
        "--storage-root", str(base / "storage"),
        "--materialized-root", str(base / "wine"),
        "--evidence-root", str(base / "evidence"),
        "--wine", "bin/wine64", "--wineserver", "bin/wineserver",
        "--version", "10.0-preview",
    ]


class FakePlatform:
    def __init__(self, os_name="Linux", machine="x86_64", uid=1000):
        self.os = os_name
        self.arch = machine
        self.uid = uid

    def os_name(self):
        return self.os

    def machine(self):
        return self.arch

    def current_uid(self):
        return self.uid


class FakeFileSystem:
    def __init__(self, inputs):
        self.repository_root = ROOT
        self.nodes = {}
        self.aliases = {}
        self.created = []
        self.commands = []
        for path in (ROOT, inputs.materialized_root, inputs.cli.parent):
            self.put(path, "directory")
        for path in (inputs.cli, inputs.compiler,
                     inputs.materialized_root / inputs.wine_relative,
                     inputs.materialized_root / inputs.wineserver_relative):
            self.put(path, "file", mode=0o700)

    def put(self, path, kind, mode=0o700, uid=1000, symlink=False):
        self.nodes[path] = SimpleNamespace(exists=True, kind=kind, mode=mode,
                                          uid=uid, symlink=symlink,
                                          identity=(1, len(self.nodes) + 1))

    def inspect(self, path):
        return self.nodes.get(path, SimpleNamespace(exists=False))

    def nearest_existing_ancestor(self, path):
        runner = runner_module()
        for source, destination in self.aliases.items():
            if path == source or source in path.parents:
                return runner.PhysicalAncestor(source, destination, (1, 1),
                                                tuple(path.relative_to(source).parts))
        parent = path
        missing = []
        while not self.inspect(parent).exists:
            missing.insert(0, parent.name)
            parent = parent.parent
        return runner.PhysicalAncestor(parent, parent, self.inspect(parent).identity,
                                       tuple(missing))

    def mkdir_exclusive(self, path):
        if self.inspect(path).exists:
            raise FileExistsError(path)
        self.put(path, "directory")
        self.created.append((path, 0o700))
        return self.inspect(path).identity

    def remove_owned_empty_directory(self, path, identity):
        if self.inspect(path).identity == identity:
            self.nodes.pop(path)

    def record(self, argv, environment):
        self.commands.append((argv, environment))


def document(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def accepts_string(definition: dict[str, object], value: object) -> bool:
    if definition.get("type") != "string" or not isinstance(value, str):
        return False
    minimum = definition.get("minLength")
    maximum = definition.get("maxLength")
    pattern = definition.get("pattern")
    if isinstance(minimum, int) and len(value) < minimum:
        return False
    if isinstance(maximum, int) and len(value) > maximum:
        return False
    return not isinstance(pattern, str) or re.fullmatch(pattern, value) is not None


def accepts_const(definition: dict[str, object], value: object) -> bool:
    return "const" in definition and definition["const"] == value


class LinuxProviderSchemaTests(unittest.TestCase):
    def test_schema_identity_and_object_shapes_are_frozen(self) -> None:
        provider = document(PROVIDER_SCHEMA)
        bootstrap = document(BOOTSTRAP_SCHEMA)

        expected_identities = (
            (
                provider,
                "https://compatforge.dev/schemas/linux-provider.schema.json",
            ),
            (
                bootstrap,
                "https://compatforge.dev/schemas/linux-bootstrap-request.schema.json",
            ),
        )
        for schema, expected_id in expected_identities:
            self.assertEqual(
                schema.get("$schema"),
                "https://json-schema.org/draft/2020-12/schema",
            )
            self.assertEqual(schema.get("$id"), expected_id)
            self.assertEqual(schema.get("type"), "object")
            self.assertEqual(
                schema["properties"]["schemaVersion"], {"const": "1"}
            )

        self.assertEqual(
            provider["properties"]["wineRuntime"].get("type"), "object"
        )
        self.assertEqual(provider["$defs"]["entrypoint"].get("type"), "object")

    def test_provider_schema_is_closed_and_x86_64_only(self) -> None:
        self.assertTrue(PROVIDER_SCHEMA.is_file(), "Linux Provider schema is missing")
        schema = document(PROVIDER_SCHEMA)
        runtime = schema["properties"]["wineRuntime"]
        self.assertFalse(schema["additionalProperties"])
        self.assertFalse(runtime["additionalProperties"])
        root_fields = {"schemaVersion", "runtimeStoreRoot", "wineRuntime"}
        self.assertEqual(set(schema["required"]), root_fields)
        self.assertEqual(set(schema["properties"]), root_fields)
        self.assertEqual(
            schema["properties"]["runtimeStoreRoot"]["$ref"],
            "#/$defs/absoluteLinuxPath",
        )
        self.assertEqual(runtime["properties"]["architecture"], {"const": "x86_64"})
        self.assertEqual(
            runtime["properties"]["capabilities"],
            {"const": ["guest-x86_64"]},
        )
        self.assertEqual(
            runtime["properties"]["wined3dCapabilities"],
            {"const": ["opengl"]},
        )
        self.assertEqual(
            set(runtime["required"]),
            {
                "providerId",
                "packId",
                "packDigest",
                "version",
                "architecture",
                "materializedRoot",
                "wine",
                "wineserver",
                "capabilities",
                "wined3dCapabilities",
            },
        )
        self.assertEqual(set(runtime["properties"]), set(runtime["required"]))
        self.assertNotIn("d3dmetal", runtime["properties"])
        self.assertEqual(
            runtime["properties"]["materializedRoot"]["$ref"],
            "#/$defs/absoluteLinuxPath",
        )
        for identifier_name in ("providerId", "packId"):
            self.assertEqual(
                runtime["properties"][identifier_name]["$ref"], "#/$defs/id"
            )
        self.assertEqual(
            runtime["properties"]["packDigest"]["$ref"], "#/$defs/digest"
        )
        self.assertEqual(
            runtime["properties"]["version"]["$ref"], "#/$defs/version"
        )
        for entrypoint_name in ("wine", "wineserver"):
            entrypoint_ref = runtime["properties"][entrypoint_name]["$ref"]
            self.assertEqual(entrypoint_ref, "#/$defs/entrypoint")
        entrypoint = schema["$defs"]["entrypoint"]
        self.assertFalse(entrypoint["additionalProperties"])
        self.assertEqual(set(entrypoint["required"]), {"path", "digest"})
        self.assertEqual(set(entrypoint["properties"]), {"path", "digest"})
        self.assertEqual(
            entrypoint["properties"]["path"]["$ref"], "#/$defs/relativePath"
        )
        self.assertEqual(
            entrypoint["properties"]["digest"]["$ref"], "#/$defs/digest"
        )

    def test_bootstrap_schema_requires_the_explicit_runtime_quartet(self) -> None:
        self.assertTrue(BOOTSTRAP_SCHEMA.is_file(), "Linux bootstrap schema is missing")
        schema = document(BOOTSTRAP_SCHEMA)
        self.assertFalse(schema["additionalProperties"])
        fields = {
            "schemaVersion",
            "runtimeStoreRoot",
            "storageRoot",
            "materializedRoot",
            "wine",
            "wineserver",
            "version",
        }
        self.assertEqual(set(schema["required"]), fields)
        self.assertEqual(set(schema["properties"]), fields)
        for path_name in ("runtimeStoreRoot", "storageRoot", "materializedRoot"):
            self.assertEqual(
                schema["properties"][path_name]["$ref"],
                "#/$defs/absoluteLinuxPath",
            )
        for entrypoint_name in ("wine", "wineserver"):
            self.assertEqual(
                schema["properties"][entrypoint_name]["$ref"],
                "#/$defs/relativePath",
            )

    def test_linux_path_patterns_accept_and_reject_examples(self) -> None:
        for schema in (document(PROVIDER_SCHEMA), document(BOOTSTRAP_SCHEMA)):
            absolute = schema["$defs"]["absoluteLinuxPath"]
            relative = schema["$defs"]["relativePath"]
            for value in ("/opt/wine", "/" + "a" * 4095):
                self.assertTrue(accepts_string(absolute, value), value)
            for value in ("bin/wine64", "a" * 1024):
                self.assertTrue(accepts_string(relative, value), value)
            for value in (
                "/",
                "/opt//wine",
                "/./wine",
                "/opt/../wine",
                "/opt/",
                "C:\\wine",
                "/bad\npath",
                "/bad\rpath",
                "/bad\0path",
                "/" + "a" * 4096,
            ):
                self.assertFalse(accepts_string(absolute, value), value)
            for value in (
                "/bin/wine",
                "../wine",
                "bin//wine",
                "bin\\wine",
                "C:wine",
                "bad\npath",
                "bad\rpath",
                "bad\0path",
                "a" * 1025,
            ):
                self.assertFalse(accepts_string(relative, value), value)

    def test_path_patterns_use_ecma_safe_all_character_scans(self) -> None:
        schemas = (document(PROVIDER_SCHEMA), document(BOOTSTRAP_SCHEMA))
        patterns_by_kind: dict[str, list[str]] = {
            "absoluteLinuxPath": [],
            "relativePath": [],
        }

        for schema in schemas:
            for definition_name, expected_scan_count in (
                ("absoluteLinuxPath", 4),
                ("relativePath", 3),
            ):
                pattern = schema["$defs"][definition_name]["pattern"]
                patterns_by_kind[definition_name].append(pattern)
                self.assertNotIn(".*", pattern, definition_name)
                self.assertEqual(
                    pattern.count(r"[\s\S]*"),
                    expected_scan_count,
                    definition_name,
                )

            absolute = schema["$defs"]["absoluteLinuxPath"]
            relative = schema["$defs"]["relativePath"]
            for separator in ("\u2028", "\u2029"):
                self.assertTrue(
                    accepts_string(absolute, f"/safe{separator}name"), separator
                )
                self.assertTrue(
                    accepts_string(relative, f"safe{separator}name"), separator
                )
                for suffix in (
                    "/../escape",
                    "\\escape",
                    "\0escape",
                    "\rescape",
                    "\nescape",
                ):
                    self.assertFalse(
                        accepts_string(absolute, f"/safe{separator}{suffix}"),
                        repr(separator + suffix),
                    )
                    self.assertFalse(
                        accepts_string(relative, f"safe{separator}{suffix}"),
                        repr(separator + suffix),
                    )

        for definition_name, patterns in patterns_by_kind.items():
            self.assertEqual(patterns[0], patterns[1], definition_name)

    def test_identifier_version_and_digest_constraints(self) -> None:
        provider = document(PROVIDER_SCHEMA)
        bootstrap = document(BOOTSTRAP_SCHEMA)
        identifier = provider["$defs"]["id"]
        digest = provider["$defs"]["digest"]
        versions = (
            provider["$defs"]["version"],
            bootstrap["properties"]["version"],
        )

        for value in ("w1", "winehq-staging", "a" * 128):
            self.assertTrue(accepts_string(identifier, value), value)
        for value in ("a", "a" * 129, "-wine", "Wine", "wine/runtime", "wine\nx"):
            self.assertFalse(accepts_string(identifier, value), value)

        for version in versions:
            for value in ("1", "9.0", "10.0-rc1+linux", "1" + "a" * 127):
                self.assertTrue(accepts_string(version, value), value)
            for value in ("", "v1", "1 bad", "1/2", "1" * 129, "1\n2"):
                self.assertFalse(accepts_string(version, value), value)

        canonical = "sha256:" + "0123456789abcdef" * 4
        self.assertTrue(accepts_string(digest, canonical))
        for value in (
            "sha256:" + "A" * 64,
            "sha512:" + "a" * 64,
            "sha256:" + "a" * 63,
            "sha256:" + "a" * 65,
            "sha256:" + "a" * 63 + "\n",
        ):
            self.assertFalse(accepts_string(digest, value), value)

    def test_linux_capability_arrays_are_exact(self) -> None:
        runtime = document(PROVIDER_SCHEMA)["properties"]["wineRuntime"]
        capabilities = runtime["properties"]["capabilities"]
        graphics = runtime["properties"]["wined3dCapabilities"]

        self.assertTrue(accepts_const(capabilities, ["guest-x86_64"]))
        self.assertFalse(accepts_const(capabilities, []))
        self.assertFalse(
            accepts_const(capabilities, ["guest-x86_64", "guest-i386"])
        )
        self.assertFalse(accepts_const(capabilities, ["win64"]))

        self.assertTrue(accepts_const(graphics, ["opengl"]))
        self.assertFalse(accepts_const(graphics, []))
        self.assertFalse(accepts_const(graphics, ["opengl", "metal"]))
        self.assertFalse(accepts_const(graphics, ["metal"]))


class LinuxConsoleRunnerPreflightTests(unittest.TestCase):
    def test_root_owned_readonly_tools_are_allowed_and_direct_version_is_validated(self):
        runner = runner_module()
        inputs = runner.parse_closed_args(runner_args())
        fs = FakeFileSystem(inputs)
        for path in (inputs.cli, inputs.compiler, inputs.materialized_root,
                     inputs.materialized_root / inputs.wine_relative,
                     inputs.materialized_root / inputs.wineserver_relative):
            fs.put(path, fs.inspect(path).kind, 0o755, uid=0)
        try:
            checked = runner.preflight(inputs, FakePlatform(), fs)
        except ValueError as error:
            self.fail(f"trusted root-owned tool rejected: {error}")
        self.assertIsNotNone(checked)
        self.assert_preflight_rejects(replace(inputs, declared_version="vbad"), fs)

    def test_exclusive_roots_created_only_after_full_preflight(self):
        runner = runner_module()
        inputs = runner.parse_closed_args(runner_args())
        fs = FakeFileSystem(inputs)
        checked = runner.preflight(inputs, FakePlatform(), fs)
        self.assertEqual(fs.created, [])
        created = runner.create_exclusive_roots(checked, fs)
        self.assertIsNotNone(created)
        self.assertEqual(fs.created, [(p, 0o700) for p in checked.roots])
        self.assertEqual(fs.commands, [])

    def test_creation_refuses_changed_ancestor_and_rolls_back_owned_roots(self):
        runner = runner_module()
        inputs = runner.parse_closed_args(runner_args())
        fs = FakeFileSystem(inputs)
        checked = runner.preflight(inputs, FakePlatform(), fs)
        fs.aliases[inputs.storage_root] = ROOT / "changed"
        with self.assertRaises(ValueError):
            runner.create_exclusive_roots(checked, fs)
        self.assertEqual(fs.created, [])

    def test_physical_aliases_between_all_root_pairs_are_rejected(self):
        runner = runner_module()
        inputs = runner.parse_closed_args(runner_args())
        paths = (ROOT, inputs.runtime_store_root, inputs.storage_root,
                 inputs.materialized_root, inputs.evidence_root)
        for index, left in enumerate(paths):
            for right in paths[index + 1:]:
                for suffix in ((), ("child",)):
                    fs = FakeFileSystem(inputs)
                    fs.aliases[right] = left.joinpath(*suffix)
                    with self.subTest(left=left, right=right, suffix=suffix):
                        self.assert_preflight_rejects(inputs, fs)

    def test_parser_does_not_silently_normalize_path_components(self):
        runner = runner_module()
        base = runner_args()[1].replace("\\", "/")
        for value in (base + "/", base + "/./child", base + "//child", base + "/../child"):
            args = runner_args()
            args[1] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                runner.parse_closed_args(args)

    def test_every_root_pair_lexical_equal_ancestor_descendant_is_rejected(self):
        runner = runner_module()
        original = runner.parse_closed_args(runner_args())
        fields = ("repository_root", "runtime_store_root", "storage_root",
                  "materialized_root", "evidence_root")
        for index, left in enumerate(fields):
            for right in fields[index + 1:]:
                for relation in ("equal", "ancestor", "descendant"):
                    inputs = original
                    fs = FakeFileSystem(inputs)
                    base = getattr(fs if left == "repository_root" else inputs, left)
                    other = base if relation == "equal" else (
                        base.parent if relation == "ancestor" else base / "child")
                    inputs = replace(inputs, **{right: other})
                    if right == "materialized_root":
                        fs.put(other, "directory")
                        fs.put(other / inputs.wine_relative, "file")
                        fs.put(other / inputs.wineserver_relative, "file")
                    with self.subTest(left=left, right=right, relation=relation):
                        self.assert_preflight_rejects(inputs, fs)

    def assert_preflight_rejects(self, inputs, filesystem, platform=None):
        with self.assertRaises(ValueError):
            runner_module().preflight(inputs, platform or FakePlatform(), filesystem)
        self.assertEqual(filesystem.created, [])
        self.assertEqual(filesystem.commands, [])

    def test_host_and_executable_preflight_before_any_side_effect(self):
        runner = runner_module()
        inputs = runner.parse_closed_args(runner_args())
        for platform in (FakePlatform("Windows"), FakePlatform("Darwin"),
                         FakePlatform(machine="aarch64")):
            self.assert_preflight_rejects(inputs, FakeFileSystem(inputs), platform)
        for field in ("cli", "compiler"):
            for kind, mode, uid, symlink in (("missing", 0o700, 1000, False),
                    ("directory", 0o700, 1000, False), ("file", 0o600, 1000, False),
                    ("file", 0o777, 1000, False), ("file", 0o700, 2000, False),
                    ("file", 0o700, 1000, True)):
                fs = FakeFileSystem(inputs)
                path = getattr(inputs, field)
                if kind == "missing":
                    fs.nodes.pop(path)
                else:
                    fs.put(path, kind, mode, uid, symlink)
                with self.subTest(field=field, kind=kind, mode=mode, uid=uid, symlink=symlink):
                    self.assert_preflight_rejects(inputs, fs)

    def test_materialized_entrypoints_and_all_new_roots_are_checked(self):
        runner = runner_module()
        inputs = runner.parse_closed_args(runner_args())
        for path in (inputs.materialized_root,
                     inputs.materialized_root / inputs.wine_relative,
                     inputs.materialized_root / inputs.wineserver_relative):
            fs = FakeFileSystem(inputs)
            fs.nodes.pop(path)
            self.assert_preflight_rejects(inputs, fs)
        fs = FakeFileSystem(inputs)
        fs.put(inputs.materialized_root, "file")
        self.assert_preflight_rejects(inputs, fs)
        for field in ("runtime_store_root", "storage_root", "evidence_root"):
            fs = FakeFileSystem(inputs)
            fs.put(getattr(inputs, field), "directory")
            self.assert_preflight_rejects(inputs, fs)
        fs = FakeFileSystem(inputs)
        fs.put(inputs.storage_root / "bottles" / "linux-console-preview" / "prefix", "directory")
        self.assert_preflight_rejects(inputs, fs)

    def test_closed_parser_requires_every_flag_exactly_once(self):
        runner = runner_module()
        args = runner_args()
        for invalid in ([], args[:-2], args + args[:2], args + ["extra"],
                        args + ["--unknown", "x"], ["--cli=x"] + args[2:]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                runner.parse_closed_args(invalid)
        parsed = runner.parse_closed_args(args)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.cli, Path(args[1]))
        self.assertEqual(str(parsed.wine_relative), "bin/wine64")

    def test_parser_rejects_unsafe_path_spelling_and_version(self):
        runner = runner_module()
        for flag, values in (
            ("--cli", ["relative", "", "a\0b"]),
            ("--wine", ["/wine", "../wine", "a/../wine", "a//wine", "./wine", "a\\wine", "C:wine", "wine/", ""]),
            ("--wineserver", ["/server", "../server"]),
            ("--version", ["", "v10", "1 bad", "1\n2", "1" * 129]),
        ):
            for value in values:
                args = runner_args()
                args[args.index(flag) + 1] = value
                with self.subTest(flag=flag, value=value), self.assertRaises(ValueError):
                    runner.parse_closed_args(args)

    def test_runner_module_exists(self) -> None:
        self.assertTrue(
            (ROOT / "tools" / "run_linux_console_preview.py").is_file(),
            "Linux Console preview runner is missing",
        )


class EvidencePrimitiveTests(unittest.TestCase):
    def test_compound_write_or_sync_and_close_failure_removes_identified_partial(self):
        for operation in ("write", "fsync"):
            with self.subTest(operation=operation):
                name = "request.json" if operation == "write" else "inspection.json"
                store = self.runner.EvidenceStore(self.root)
                real_close = os.close
                def close_then_fail(descriptor):
                    real_close(descriptor)
                    raise OSError("secondary close failure")
                with mock.patch.object(self.runner.os, operation, side_effect=OSError("primary failure")), \
                        mock.patch.object(self.runner.os, "close", side_effect=close_then_fail):
                    with self.assertRaises(OSError):
                        store.write_json(name, {})
                store.rollback_setup()
                self.assertFalse((self.root / name).exists())

    def test_fsynced_marker_close_failure_runs_finalizer_and_preserves_evidence(self):
        store = self.runner.EvidenceStore(self.root)
        store.write_json("private-context.json", {})
        calls = []
        real_close = os.close
        real_fsync = os.fsync
        synced = set()
        failed = []
        def record_sync(descriptor):
            real_fsync(descriptor)
            synced.add(descriptor)
        def close_after_sync(descriptor):
            real_close(descriptor)
            if descriptor in synced and not failed:
                failed.append(True)
                raise OSError("close after durable marker")
        with mock.patch.object(self.runner.os, "fsync", side_effect=record_sync), \
                mock.patch.object(self.runner.os, "close", side_effect=close_after_sync):
            with self.assertRaises(OSError):
                store.run_product(self.root / "private-context.json", self.root.parent / "prefix",
                                  "sha256:" + "a" * 64, lambda: calls.append("product"),
                                  lambda failure: calls.append(("finalizer", failure)))
        self.assertEqual(calls, [("finalizer", True)])
        self.assertTrue(store.started)
        self.assertTrue((self.root / "run-start.json").is_file())
        self.assertTrue((self.root / "private-context.json").is_file())
        self.assertEqual(store.read_json("failure.json"), {"schemaVersion": "1", "reason": "execution"})
        self.assertFalse((self.root / "public-summary.json").exists())

    def test_symlink_json_read_is_rejected_before_open(self):
        store = self.runner.EvidenceStore(self.root)
        with mock.patch.object(Path, "is_symlink", return_value=True), \
                mock.patch.object(self.runner.os, "open") as opened:
            with self.assertRaises(ValueError):
                store.read_json("private-context.json")
        opened.assert_not_called()

    def test_fstat_failure_closes_descriptor_without_claiming_unknown_file_ownership(self):
        store = self.runner.EvidenceStore(self.root)
        opened_descriptors = []
        real_open = os.open
        def capture(*args):
            descriptor = real_open(*args)
            opened_descriptors.append(descriptor)
            def close_if_open():
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            self.addCleanup(close_if_open)
            return descriptor
        with mock.patch.object(self.runner.os, "open", side_effect=capture), \
                mock.patch.object(self.runner.os, "fstat", side_effect=OSError("metadata")):
            with self.assertRaises(OSError):
                store.write_json("private-context.json", {})
        with self.assertRaises(OSError):
            os.fstat(opened_descriptors[0])

    def test_pre_marker_rollback_removes_owned_empty_roots_but_preserves_caller_data(self):
        runner = self.runner
        fs = runner.NativeFileSystem()
        fresh = self.root.parent / "fresh"
        identity = fs.mkdir_exclusive(fresh)
        roots = runner.CreatedRoots((fresh,), ((fresh, identity),))
        store = runner.EvidenceStore(fresh, created_roots=roots, filesystem=fs)
        store.write_json("private-context.json", {})
        store.rollback_setup()
        self.assertFalse(fresh.exists())
        self.assertTrue(self.root.exists())

    def test_nonzero_product_status_is_failure_even_if_callback_returns_normally(self):
        store = self.runner.EvidenceStore(self.root)
        store.write_json("private-context.json", {})
        finalized = []
        def product():
            return self.runner.CommandResult(7, b"", b"", 101, 101)
        with self.assertRaises(self.runner.CommandFailure):
            store.run_product(self.root / "private-context.json", self.root.parent / "prefix",
                              "sha256:" + "a" * 64, product, finalized.append)
        self.assertEqual(finalized, [True])

    def setUp(self):
        self.runner = runner_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / "evidence"
        self.root.mkdir(mode=0o700)

    def test_exclusive_private_artifact_is_fsynced_and_not_overwritten(self):
        store = self.runner.EvidenceStore(self.root)
        with mock.patch.object(self.runner.os, "open", wraps=os.open) as opened, \
                mock.patch.object(self.runner.os, "fsync", wraps=os.fsync) as synced:
            store.write_json("private-context.json", {"fixed": True})
            self.assertTrue((self.root / "private-context.json").is_file())
            self.assertTrue(synced.called)
            flags = opened.call_args.args[1]
            self.assertTrue(flags & os.O_EXCL)
            self.assertEqual(opened.call_args.args[2], 0o600)
        with self.assertRaises(FileExistsError):
            store.write_json("private-context.json", {})
        self.assertEqual(store.read_json("private-context.json"), {"fixed": True})

    def test_closed_names_and_bounded_json_reads(self):
        store = self.runner.EvidenceStore(self.root)
        for name in ("../private-context.json", "other.json", "public-summary.json"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                store.write_json(name, {})
        store.write_json("private-context.json", {"a": "x" * 20})
        with self.assertRaises(ValueError):
            store.read_json("private-context.json", limit=10)

    def test_write_and_sync_failure_remove_only_own_partial_file(self):
        for operation in ("write", "fsync"):
            with self.subTest(operation=operation):
                store = self.runner.EvidenceStore(self.root)
                with mock.patch.object(self.runner.os, operation, side_effect=OSError("injected")):
                    with self.assertRaises(OSError):
                        store.write_json("private-context.json", {})
                self.assertFalse((self.root / "private-context.json").exists())

    def test_fsynced_marker_precedes_product_and_finalizer_runs_on_success(self):
        store = self.runner.EvidenceStore(self.root)
        store.write_json("private-context.json", {})
        calls = []
        def product():
            self.assertTrue((self.root / "run-start.json").is_file())
            calls.append("product")
            return 42
        result = store.run_product(self.root / "private-context.json", self.root.parent / "prefix",
                                   "sha256:" + "a" * 64, product,
                                   lambda failed: calls.append(("finalizer", failed)))
        self.assertEqual(result, 42)
        self.assertEqual(calls, ["product", ("finalizer", False)])

    def test_post_marker_failure_preserves_one_private_failure_and_no_summary(self):
        store = self.runner.EvidenceStore(self.root)
        store.write_json("private-context.json", {})
        finalized = []
        def fail():
            raise RuntimeError("secret /absolute/path")
        with self.assertRaises(RuntimeError):
            store.run_product(self.root / "private-context.json", self.root.parent / "prefix",
                              "sha256:" + "a" * 64, fail, finalized.append)
        self.assertEqual(finalized, [True])
        record = store.read_json("failure.json")
        self.assertEqual(record, {"schemaVersion": "1", "reason": "execution"})
        self.assertEqual(len(list(self.root.glob("failure*"))), 1)
        self.assertFalse((self.root / "public-summary.json").exists())

    def test_marker_sync_failure_rolls_back_before_product(self):
        store = self.runner.EvidenceStore(self.root)
        store.write_json("private-context.json", {})
        calls = []
        with mock.patch.object(self.runner.os, "fsync", side_effect=OSError("injected")):
            with self.assertRaises(OSError):
                store.run_product(self.root / "private-context.json", self.root.parent / "prefix",
                                  "sha256:" + "a" * 64, lambda: calls.append("product"), calls.append)
        self.assertEqual(calls, [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_finalizer_failure_is_sticky_and_records_private_failure(self):
        store = self.runner.EvidenceStore(self.root)
        store.write_json("private-context.json", {})
        def fail_finalizer(failed):
            raise RuntimeError("cleanup")
        with self.assertRaises(RuntimeError):
            store.run_product(self.root / "private-context.json", self.root.parent / "prefix",
                              "sha256:" + "a" * 64, lambda: 0, fail_finalizer)
        self.assertEqual(store.read_json("failure.json")["reason"], "cleanup")


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        self.now += 0.001
        return self.now

    def pause(self, duration):
        self.now += duration


class FakeCommandAdapter:
    def __init__(self, chunks=(), failure=None):
        self.chunks = list(chunks) + [("stdout", b""), ("stderr", b"")]
        self.failure = failure
        self.actions = []
        self.started = []

    def start(self, spec):
        self.started.append(spec)
        return SimpleNamespace(pid=101, process_group_id=101)

    def readiness(self, running, timeout):
        if self.failure == "timeout":
            return []
        return [self.chunks[0][0]] if self.chunks else []

    def apply(self, action, running):
        self.actions.append(action.kind)
        if self.failure == action.kind:
            raise OSError("injected " + action.kind)
        if action.kind == "read":
            stream, chunk = self.chunks.pop(0)
            if len(chunk) > action.size:
                self.chunks.insert(0, (stream, chunk[action.size:]))
            return chunk[:action.size]
        if action.kind == "reap":
            return 0
        if action.kind == "group":
            return self.failure == "group-live"

    def exited(self, running):
        return not self.chunks

    def close(self, running):
        self.actions.append("close")


class BoundedCommandStateMachineTests(unittest.TestCase):
    def test_broken_readiness_does_not_abort_delayed_outer_cleanup(self):
        runner = runner_module()
        for delayed_stage in ("reap", "group"):
            with self.subTest(stage=delayed_stage):
                adapter = FakeCommandAdapter()
                adapter.readiness = mock.Mock(side_effect=OSError("persistent readiness failure"))
                original_apply = adapter.apply
                attempts = []
                def delayed_cleanup(action, running):
                    if action.kind == delayed_stage:
                        attempts.append(action.kind)
                        if len(attempts) == 1:
                            return None if delayed_stage == "reap" else True
                    return original_apply(action, running)
                adapter.apply = delayed_cleanup
                clock = FakeClock()
                spec = SimpleNamespace(argv=(str(Path(sys.executable).resolve()),), environment={},
                                       cwd=ROOT, output_limit_bytes=8, deadline=1.0)
                with self.assertRaises(runner.CommandFailure) as caught:
                    runner.run_bounded(spec, adapter, None, clock)
                self.assertEqual(caught.exception.reason, "read")
                self.assertEqual(caught.exception.outer_cleanup_status.state, "Complete")
                self.assertEqual(len(attempts), 2)
                self.assertEqual(adapter.readiness.call_count, 1)
                self.assertLess(clock.now, spec.deadline)

    def test_simultaneously_ready_streams_read_at_most_combined_cap_plus_one(self):
        runner = runner_module()
        adapter = FakeCommandAdapter([("stdout", b"12345678"), ("stderr", b"x" * 100)])
        adapter.readiness = lambda running, timeout: ["stdout", "stderr"]
        read_sizes = []
        read_bytes = []
        apply = adapter.apply
        def record_read(action, running):
            result = apply(action, running)
            if action.kind == "read":
                read_sizes.append(action.size)
                read_bytes.append(result)
            return result
        adapter.apply = record_read
        spec = SimpleNamespace(argv=(str(Path(sys.executable).resolve()),), environment={},
                               cwd=ROOT, output_limit_bytes=8, deadline=1.0)
        with self.assertRaises(runner.CommandFailure) as caught:
            runner.run_bounded(spec, adapter, None, FakeClock())
        self.assertEqual(caught.exception.reason, "output-limit")
        self.assertEqual(read_sizes, [9, 1])
        self.assertEqual(sum(map(len, read_bytes)), 9)
        self.assertEqual(caught.exception.partial_stdout, b"12345678")
        self.assertEqual(caught.exception.partial_stderr, b"")

    def test_spurious_readiness_is_not_eof_or_read_failure(self):
        runner = runner_module()
        adapter = FakeCommandAdapter([("stdout", b"ok")])
        apply = adapter.apply
        seen = []
        def would_block_once(action, running):
            if action.kind == "read" and not seen:
                seen.append(True)
                return None
            return apply(action, running)
        adapter.apply = would_block_once
        spec = SimpleNamespace(argv=(str(Path(sys.executable).resolve()),), environment={},
                               cwd=ROOT, output_limit_bytes=8, deadline=1.0)
        try:
            result = runner.run_bounded(spec, adapter, None, FakeClock())
        except runner.CommandFailure as error:
            self.fail(f"would-block readiness was treated as {error.reason}")
        self.assertEqual(result.stdout, b"ok")

    def test_cleanup_does_not_signal_after_reap_and_respects_absolute_deadline(self):
        runner = runner_module()
        adapter = FakeCommandAdapter(failure="group-live")
        clock = FakeClock()
        spec = SimpleNamespace(argv=(str(Path(sys.executable).resolve()),), environment={},
                               cwd=ROOT, output_limit_bytes=8, deadline=1.0)
        with self.assertRaises(runner.CommandFailure) as caught:
            runner.run_bounded(spec, adapter, None, clock)
        self.assertEqual(caught.exception.outer_cleanup_status.state, "TimedOut")
        self.assertLess(clock.now, 1.01)
        self.assertLess(adapter.actions.index("kill"), adapter.actions.index("reap"))
        self.assertEqual(adapter.actions.count("kill"), 1)

    def test_readiness_failure_still_kills_and_reaps_outer_group(self):
        runner = runner_module()
        adapter = FakeCommandAdapter()
        adapter.readiness = mock.Mock(side_effect=OSError("readiness"))
        spec = SimpleNamespace(argv=(str(Path(sys.executable).resolve()),), environment={},
                               cwd=ROOT, output_limit_bytes=8, deadline=1.0)
        with self.assertRaises(Exception) as caught:
            runner.run_bounded(spec, adapter, None, FakeClock())
        self.assertEqual(getattr(caught.exception, "reason", None), "read")
        self.assertIn("kill", adapter.actions)
        self.assertIn("reap", adapter.actions)

    def test_invalid_command_spec_does_not_spawn(self):
        runner = runner_module()
        valid = dict(argv=(str(Path(sys.executable).resolve()),), environment={},
                     cwd=ROOT, output_limit_bytes=8, deadline=1.0)
        for field, value in (("argv", ("python",)), ("argv", ()),
                             ("environment", None), ("cwd", Path("relative")),
                             ("output_limit_bytes", 1024 * 1024 + 1),
                             ("deadline", float("inf")), ("deadline", -1.0)):
            adapter = FakeCommandAdapter()
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                runner.run_bounded(SimpleNamespace(**(valid | {field: value})), adapter, None, FakeClock())
            self.assertEqual(adapter.started, [])

    def command(self, chunks=(), failure=None, observer=None, cap=8):
        runner = runner_module()
        spec = SimpleNamespace(argv=(str(Path(sys.executable).resolve()), "-c", "pass"),
                               environment={}, cwd=ROOT, output_limit_bytes=cap, deadline=1.0)
        adapter = FakeCommandAdapter(chunks, failure)
        result = runner.run_bounded(spec, adapter, observer, FakeClock())
        return result, adapter

    def test_normal_eof_exit_and_exact_cap(self):
        for chunks in ([], [("stdout", b"12345678")], [("stdout", b"1234"), ("stderr", b"5678")]):
            with self.subTest(chunks=chunks):
                result, adapter = self.command(chunks)
                self.assertIsNotNone(result)
                self.assertEqual(result.return_code, 0)
                self.assertEqual(result.stdout, b"".join(c for s, c in chunks if s == "stdout"))
                self.assertEqual(result.stderr, b"".join(c for s, c in chunks if s == "stderr"))
                self.assertIn("reap", adapter.actions)
                self.assertIn("group", adapter.actions)

    def test_overflow_no_newline_and_combined_budget_preserve_bounded_partial_bytes(self):
        for chunks in ([("stdout", b"x" * 9)], [("stdout", b"x" * 10000)],
                       [("stdout", b"1234"), ("stderr", b"56789")]):
            with self.subTest(chunks=chunks), self.assertRaises(Exception) as caught:
                self.command(chunks)
            error = getattr(caught, "exception", None)
            self.assertIsNotNone(error)
            self.assertEqual(getattr(error, "reason", None), "output-limit")
            self.assertEqual(len(error.partial_stdout) + len(error.partial_stderr), 8)
            self.assertEqual(error.outer_cleanup_status.state, "Complete")
            self.assertEqual(error.outer_pid, 101)
            self.assertEqual(error.outer_process_group_id, 101)
            self.assertFalse(hasattr(error, "inner_cleanup_status"))

    def test_timeout_observer_and_read_failure_are_distinct_and_cleanup_outer_only(self):
        class FailingObserver:
            def on_chunk(self, stream, chunk):
                raise ValueError("private-observer-details")
        for fault, observer, reason in (("timeout", None, "timeout"),
                                        ("read", None, "read"),
                                        (None, FailingObserver(), "observer")):
            with self.subTest(fault=fault, reason=reason), self.assertRaises(Exception) as caught:
                self.command([("stdout", b"partial")], fault, observer)
            error = getattr(caught, "exception", None)
            self.assertIsNotNone(error)
            self.assertEqual(getattr(error, "reason", None), reason)
            self.assertEqual(error.outer_cleanup_status.state, "Complete")
            if observer:
                self.assertEqual(error.partial_stdout, b"partial")

    def test_outer_kill_reap_and_group_failures_are_permanently_unsuccessful(self):
        for fault, state, stage in (("kill", "Failed", "kill"),
                                    ("reap", "Failed", "reap"),
                                    ("group", "Failed", "group"),
                                    ("group-live", "TimedOut", "group")):
            with self.subTest(fault=fault), self.assertRaises(Exception) as caught:
                self.command([("stdout", b"123456789")], fault)
            error = getattr(caught, "exception", None)
            self.assertIsNotNone(error)
            self.assertEqual(getattr(error, "reason", None), "output-limit")
            self.assertEqual(error.outer_cleanup_status.state, state)
            self.assertEqual(error.outer_cleanup_status.stage, stage)


@unittest.skipUnless(sys.platform == "linux", "requires native Linux selectors and process groups")
class LinuxBoundedCommandIntegrationTests(unittest.TestCase):
    def command(self, source, cap=1024, duration=3.0):
        runner = runner_module()
        return runner.run_bounded(
            runner.CommandSpec((str(Path(sys.executable).resolve()), "-S", "-c", source),
                               {}, ROOT, cap, time.monotonic() + duration),
            runner.LinuxCommandAdapter(), None, time.monotonic)

    def test_native_success_nonzero_and_empty_environment(self):
        result = self.command("import os; print(os.environ.get('HOME','absent')); raise SystemExit(7)")
        self.assertEqual(result.stdout, b"absent\n")
        self.assertEqual(result.return_code, 7)

    def test_native_exact_cap_and_nonnewline_overflow(self):
        self.assertEqual(self.command("import os; os.write(1,b'x'*8)", 8).stdout, b"x" * 8)
        with self.assertRaises(runner_module().CommandFailure) as caught:
            self.command("import os; os.write(1,b'x'*100000)", 8)
        self.assertEqual(caught.exception.reason, "output-limit")
        self.assertEqual(caught.exception.outer_cleanup_status.state, "Complete")

    def test_native_timeout_and_descendant_held_pipe_are_bounded(self):
        for source in ("import time; time.sleep(30)",
                       "import os,time; child=os.fork(); time.sleep(30) if child==0 else None"):
            start = time.monotonic()
            with self.assertRaises(runner_module().CommandFailure) as caught:
                self.command(source, duration=1.5)
            self.assertEqual(caught.exception.reason, "timeout")
            self.assertLess(time.monotonic() - start, 2.0)


@unittest.skipUnless(sys.platform == "linux", "requires Linux permissions and symlinks")
class LinuxPhysicalPreflightIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.runner = runner_module()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.materialized = self.base / "wine"
        self.materialized.mkdir(mode=0o700)
        for name in ("wine64", "wineserver", "cli", "compiler"):
            path = self.materialized / name
            path.write_bytes(b"controlled non-executing preflight fixture")
            path.chmod(0o700)
        self.inputs = self.runner.RunnerInputs(
            self.materialized / "cli", self.materialized / "compiler",
            self.base / "runtime", self.base / "storage", self.materialized,
            self.base / "evidence", self.runner.PurePosixPath("wine64"),
            self.runner.PurePosixPath("wineserver"), "10.0")

    def test_physical_alias_and_nearest_existing_ancestor(self):
        fs = self.runner.NativeFileSystem()
        alias = self.base / "alias"
        alias.symlink_to(self.materialized, target_is_directory=True)
        result = fs.nearest_existing_ancestor(alias / "missing" / "child")
        self.assertEqual(result.destination, self.materialized / "missing" / "child")
        inputs = replace(self.inputs, evidence_root=alias / "missing" / "child")
        with self.assertRaises(ValueError):
            self.runner.preflight(inputs, self.runner.NativePlatform(), fs)
        self.assertFalse(self.inputs.runtime_store_root.exists())

    def test_executable_mode_and_exclusive_root_modes(self):
        fs = self.runner.NativeFileSystem()
        self.inputs.cli.chmod(0o600)
        with self.assertRaises(ValueError):
            self.runner.preflight(self.inputs, self.runner.NativePlatform(), fs)
        self.inputs.cli.chmod(0o700)
        checked = self.runner.preflight(self.inputs, self.runner.NativePlatform(), fs)
        created = self.runner.create_exclusive_roots(checked, fs)
        for root in created.roots:
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(root.stat().st_uid, os.getuid())

    def test_private_evidence_mode_symlink_and_fifo_refusal(self):
        self.inputs.evidence_root.mkdir(mode=0o700)
        store = self.runner.EvidenceStore(self.inputs.evidence_root)
        store.write_json("private-context.json", {})
        target = self.inputs.evidence_root / "private-context.json"
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        link = self.inputs.evidence_root / "request.json"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            store.write_json("request.json", {})
        with self.assertRaises(ValueError):
            store.read_json("request.json")
        fifo = self.inputs.evidence_root / "inspection.json"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            store.read_json("inspection.json")
        self.inputs.evidence_root.chmod(0o755)
        with self.assertRaises(ValueError):
            self.runner.EvidenceStore(self.inputs.evidence_root)


class PreviewHarness:
    """Only the process boundary is synthetic; parsing, files and policy are real."""
    def __init__(self, case, fault=None):
        self.r = runner_module()
        self.fault = fault
        temporary = tempfile.TemporaryDirectory()
        case.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        materialized = self.base / "wine"
        materialized.mkdir()
        for name in ("cli", "compiler", "wine64", "wineserver"):
            (materialized / name).write_bytes(name.encode())
        self.inputs = self.r.RunnerInputs(materialized / "cli", materialized / "compiler",
            self.base / "runtime", self.base / "storage", materialized,
            self.base / "evidence", self.r.PurePosixPath("wine64"),
            self.r.PurePosixPath("wineserver"), "10.0")
        self.paths = self.r.EvidencePaths(self.inputs.evidence_root)
        self.clock = FakeClock()
        self.calls = []
        self.io = []
        self.signals = []
        self.platform = FakePlatform()
        self.host_display_detected = True
        self.observed = False
        self.pid = 321
        self.identity = self.r.Verified(self.pid, 1000, 1234, self.prefix)
        harness = self
        class Files(self.r.NativeFileSystem):
            def inspect(self, path):
                result = super().inspect(path)
                return replace(result, mode=0o700, uid=1000) if result.exists else result
            def record_io(self, operation, path):
                harness.io.append((operation, path))
        self.fs = Files()
        self.expected = ["PROC_OBSERVER_SELF_TEST", "COMPILE_GUEST", "INSPECT_GUEST",
            "BOOTSTRAP_CONTEXT", "PREPARED_PLAN_PRE", "PREPARED_LAUNCH",
            "PREPARED_PLAN_POST", "WINESERVER_VERSION", "WINESERVER_WAIT"]

    @property
    def prefix(self):
        return self.inputs.storage_root / "bottles" / "linux-console-preview" / "prefix"

    def digest(self, path):
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def receipt(self):
        return {"schemaVersion": "1", "source": "explicit-override", "version": "10.0",
                "architecture": "x86_64", "packId": "wine-linux-x86-64-local-preview",
                "packDigest": "sha256:" + "a" * 64, "capabilities": ["guest-x86_64"]}

    def context(self):
        receipt = self.receipt()
        return {"schemaVersion": "1", "storageRoot": str(self.inputs.storage_root),
            "capabilities": {"schemaVersion": "1", "host": {"os": "linux", "osVersion": "controlled", "architecture": "x86_64"},
                "runtimeProviders": [{"id": "wine-linux-x86-64-preview", "kind": "wine", "version": "10.0", "available": True, "capabilities": ["guest-x86_64"]}],
                "translators": [{"id": "native-host", "kind": "native", "version": "host", "available": True, "capabilities": ["x86_64-on-x86_64"]}],
                "graphicsBackends": [{"id": "linux-wined3d", "kind": "wined3d", "version": "10.0", "available": True, "capabilities": ["opengl"]}]},
            "runtimeBindings": [{"providerId": "wine-linux-x86-64-preview",
                "packId": receipt["packId"], "packDigest": receipt["packDigest"],
                "executable": str(self.inputs.materialized_root / "wine64"),
                "wineserverExecutable": str(self.inputs.materialized_root / "wineserver"),
                "environment": {"COMPATFORGE_RUNTIME_PACK": receipt["packId"],
                    "COMPATFORGE_RUNTIME_PACK_DIGEST": receipt["packDigest"],
                    "COMPATFORGE_RUNTIME_EXECUTABLE_SHA256": self.digest(self.inputs.materialized_root / "wine64"),
                    "COMPATFORGE_WINESERVER_EXECUTABLE_SHA256": self.digest(self.inputs.materialized_root / "wineserver"),
                    "WINEDEBUG": "-all", "WINESERVER": str(self.inputs.materialized_root / "wineserver"),
                    "WINEARCH": "win64", "WINEDLLOVERRIDES": "mscoree,mshtml="}}],
            "sandboxProfile": "desktop", "supervisor": {"terminationGraceMilliseconds": 1000}}

    def plan(self):
        receipt = self.receipt()
        digest = self.digest(self.paths.guest)
        stored = self.inputs.storage_root / "guest-artifacts" / "objects" / "sha256" / digest[7:]
        return {"schemaVersion": "1", "requestId": self.r.REQUEST_ID,
            "runtime": {"provider": "wine", "packId": receipt["packId"], "packDigest": receipt["packDigest"]},
            "translator": {"provider": "native"}, "graphics": {"backend": "wined3d"},
            "process": {"executable": str(self.inputs.materialized_root / "wine64"),
                "arguments": [str(stored)], "environment": self.context()["runtimeBindings"][0]["environment"] | {"WINEPREFIX": str(self.prefix)},
                "workingDirectory": str(self.prefix)},
            "guestArtifact": {"digest": digest, "sizeBytes": self.paths.guest.stat().st_size,
                "storedPath": str(stored), "originalName": self.paths.guest.name,
                "architecture": "x86_64", "imageKind": "executable", "subsystem": "windowsConsole", "inspectionSchemaVersion": "1"},
            "sandbox": {"profile": "desktop", "network": "deny", "allowDevices": []},
            "lifecycle": {"maximumRuntimeMilliseconds": 60000, "terminationGraceMilliseconds": 1000,
                "wineserver": {"executable": str(self.inputs.materialized_root / "wineserver"), "prefix": str(self.prefix)}}}

    def events(self):
        values = [{"kind": "started", "processId": self.pid},
            {"kind": "output", "output": {"stream": "stdout", "text": "COMPATFORGE_WINDOWS_CONSOLE_OK\n"}},
            {"kind": "wine-server-stop-requested"},
            {"kind": "exited", "exit": {"code": 0, "success": True}}]
        if self.fault == "missing-marker": values[1]["output"]["text"] = ""
        if self.fault == "duplicate-marker": values[1]["output"]["text"] *= 2
        if self.fault == "stderr-marker": values[1]["output"]["stream"] = "stderr"
        if self.fault == "nonzero-exit": values[-1]["exit"] = {"code": 7, "success": False}
        if self.fault == "failure-event": values[2] = {"kind": "failed", "message": "private /secret"}
        if self.fault == "missing-ack": values.pop(2)
        if self.fault == "second-started": values.insert(1, {"kind": "started", "processId": self.pid})
        if self.fault == "event-after-exit": values.append({"kind": "output", "output": {"stream": "stdout", "text": "late"}})
        for index, value in enumerate(values):
            value.update(schemaVersion="1", requestId=self.r.REQUEST_ID, sequence=index, elapsedMilliseconds=index)
        if self.fault == "gapped-events": values[-1]["sequence"] += 1
        return b"".join(json.dumps(value).encode() + b"\n" for value in values)

    def run(self, kind, spec, observer=None):
        name = kind.name
        self.calls.append((name, spec))
        # A success fixture rejects any unexpected command immediately.
        if self.fault is None:
            assert name == self.expected[len(self.calls) - 1], (name, self.calls)
        assert Path(spec.argv[0]).is_absolute()
        assert spec.cwd.is_absolute()
        assert not any(key in spec.environment for key in ("PATH", "HOME", "DISPLAY", "XDG_DATA_HOME"))
        assert spec.deadline <= 300.01
        output = b""
        code = 0
        if name == "PROC_OBSERVER_SELF_TEST":
            observer.on_chunk("stdout", b"322\n")
            if self.fault == "self-test": raise ValueError("helper not visible")
        elif name == "COMPILE_GUEST":
            self.paths.guest.write_bytes(b"controlled synthetic PE bytes")
            if self.fault == "compiler": code = 1
            if self.fault == "compiler-warning": return self.r.CommandResult(0, b"", b"warning", 900, 900)
            if self.fault == "missing-pe": self.paths.guest.unlink()
        elif name == "INSPECT_GUEST":
            value = {"schemaVersion": "1", "fileDigest": self.digest(self.paths.guest),
                "fileSizeBytes": self.paths.guest.stat().st_size, "format": "pe32Plus", "architecture": "x86_64",
                "machineCode": 0x8664, "imageKind": "executable", "subsystem": "windowsConsole",
                "subsystemCode": 3, "entryPointRva": 4096, "sections": [], "importLibraries": []}
            if self.fault == "inspection": value["architecture"] = "x86"
            output = json.dumps(value).encode()
        elif name == "BOOTSTRAP_CONTEXT":
            value = self.context()
            if self.fault == "bootstrap": value["runtimeBindings"][0]["packDigest"] = "sha256:" + "b" * 64
            self.paths.bootstrap_context.write_text(json.dumps(value), encoding="utf-8")
            output = json.dumps(self.receipt()).encode()
        elif name in ("PREPARED_PLAN_PRE", "PREPARED_PLAN_POST"):
            value = self.plan()
            if self.fault == "pre-plan" and name.endswith("PRE"): value["translator"]["provider"] = "qemu"
            if self.fault == "plan-mismatch" and name.endswith("POST"): value["decisionTrace"] = ["changed"]
            if self.fault == "reserve" and name.endswith("PRE"): self.clock.now = 256
            if self.fault == "pre-input" and name.endswith("PRE"): self.paths.execution_context.write_text("{}")
            output = json.dumps(value).encode()
        elif name == "PREPARED_LAUNCH":
            assert (self.paths.root / "run-start.json").is_file()
            assert spec.deadline <= 255.01
            if self.fault == "abort-before-started":
                raise self.r.CommandFailure("read", b"", b"", 900, 900, self.r.OuterCleanupStatus("Complete", "none"))
            output = b"bad-json\n" if self.fault == "malformed-events" else self.events()
            for start in range(0, len(output), 13): observer.on_chunk("stdout", output[start:start + 13])
            if self.fault in ("abort-after-started", "outer-cleanup", "overflow", "deadline"):
                if self.fault == "deadline": self.clock.now = 256
                raise self.r.CommandFailure("output-limit" if self.fault == "overflow" else "timeout", output, b"", 900, 900,
                    self.r.OuterCleanupStatus("Failed", "group") if self.fault == "outer-cleanup" else self.r.OuterCleanupStatus("Complete", "none"))
            if self.fault == "post-input": self.paths.launch_request.write_text("{}")
            if self.fault == "server-drift": (self.inputs.materialized_root / "wineserver").write_bytes(b"replaced")
            if self.fault == "cli-ack": code = 1
        elif name == "WINESERVER_VERSION": return self.r.CommandResult(0, b"", b"Wine 10.0\n", 900, 900)
        elif name == "WINESERVER_WAIT":
            if self.fault == "wait-failure": code = 1
            if self.fault == "wait-timeout": raise self.r.CommandFailure("timeout", b"", b"", 900, 900, self.r.OuterCleanupStatus("Complete", "none"))
        elif name != "WINESERVER_KILL": raise AssertionError(name)
        return self.r.CommandResult(code, output, b"", 900, 900)

    def observe(self, pid, prefix):
        if prefix != self.prefix: return self.r.Verified(pid, 1000, 1234, prefix)
        if self.fault in ("quick-exit", "zombie"): return self.r.ExitedBeforeSnapshot(pid)
        if self.fault == "hidden-proc": raise PermissionError("hidden /proc")
        if self.observed and self.fault == "disappeared-leader": return self.r.ExitedBeforeSnapshot(pid)
        if self.observed and self.fault == "changed-start": return replace(self.identity, start_time_ticks=9999)
        if self.fault == "prefix-mismatch": return replace(self.identity, canonical_prefix=prefix.parent)
        self.observed = True
        return self.identity

    def exact_prefix_processes(self, prefix):
        if prefix != self.prefix: return []
        if self.fault == "hidden-scan": raise PermissionError("hidden /proc")
        return [self.pid] if self.fault == "live-prefix" else []

    def group_exists(self, pid):
        if pid != self.pid: return False
        return self.fault in ("live-group", "quick-live-group")

    def signal_verified_group(self, identity, signum):
        if identity.canonical_prefix == self.prefix:
            self.signals.append((identity, signum))

    def execute(self):
        return self.r.execute_preview(self.inputs, self.paths, self, self, self.fs, self.clock)


class LinuxConsoleRunnerExecutionTests(unittest.TestCase):
    def test_launch_failure_preserves_transcript_and_bounded_diagnostics(self):
        for fault in ("cli-ack", "overflow", "abort-after-started", "malformed-events"):
            with self.subTest(fault=fault):
                h = self.harness(fault)
                self.assertFalse(h.execute().success)
                self.assertTrue(h.paths.events.exists())
                self.assertGreater(h.paths.events.stat().st_size, 0)
                diagnostics = h.paths.root / "command-diagnostics.json"
                self.assertTrue(diagnostics.exists())
                self.assertLessEqual(diagnostics.stat().st_size, h.r.JSON_LIMIT)
                self.assertIn("PREPARED_LAUNCH", diagnostics.read_text())
                self.assertEqual(len(list(h.paths.root.glob("failure*"))), 1)
                self.assertFalse(h.paths.public_summary.exists())

    def test_late_failure_always_escalates_to_abnormal_finalizer(self):
        for fault in ("late-hash", "late-summary"):
            with self.subTest(fault=fault):
                h = self.harness(fault)
                run = h.run
                def late_mutation(kind, spec, observer=None):
                    result = run(kind, spec, observer)
                    if kind.name == "WINESERVER_WAIT" and fault == "late-hash": h.inputs.cli.write_bytes(b"changed")
                    return result
                h.run = late_mutation
                original_write = h.r.EvidenceStore._write_payload
                def fail_summary(store, name, payload, **kwargs):
                    if name == "public-summary.json" and fault == "late-summary":
                        with mock.patch.object(h.r.os, "fsync", side_effect=OSError("injected")):
                            return original_write(store, name, payload, **kwargs)
                    return original_write(store, name, payload, **kwargs)
                with mock.patch.object(h.r.EvidenceStore, "_write_payload", new=fail_summary):
                    self.assertFalse(h.execute().success)
                self.assertEqual([name for name, _ in h.calls][-3:], ["WINESERVER_VERSION", "WINESERVER_KILL", "WINESERVER_WAIT"])
                self.assertFalse(h.paths.public_summary.exists())

    def test_console_marker_is_one_complete_lf_or_crlf_line(self):
        for line in ("COMPATFORGE_WINDOWS_CONSOLE_OK\n", "COMPATFORGE_WINDOWS_CONSOLE_OK\r\n",
                     "diagnostic\nCOMPATFORGE_WINDOWS_CONSOLE_OK\r\n"):
            with self.subTest(line=line):
                h = self.harness("line-ending")
                original_events = h.events
                h.events = lambda: original_events().replace(b"COMPATFORGE_WINDOWS_CONSOLE_OK\\n", json.dumps(line)[1:-1].encode())
                self.assertTrue(h.execute().success)
        for line in ("beforeCOMPATFORGE_WINDOWS_CONSOLE_OK\n", "COMPATFORGE_WINDOWS_CONSOLE_OKafter\n", "COMPATFORGE_WINDOWS_CONSOLE_OK", "COMPATFORGE_WINDOWS_CONSOLE_OK\r"):
            with self.subTest(line=line):
                h = self.harness("incomplete-marker")
                original_events = h.events
                h.events = lambda: original_events().replace(b"COMPATFORGE_WINDOWS_CONSOLE_OK\\n", json.dumps(line)[1:-1].encode())
                self.assertFalse(h.execute().success)

    def test_guest_is_private_before_compiler_and_identity_checked_after(self):
        h = self.harness("guest-private")
        run = h.run
        seen = []
        def check_placeholder(kind, spec, observer=None):
            if kind.name == "COMPILE_GUEST":
                self.assertTrue(h.paths.guest.is_file(), "compiler output must be precreated exclusively")
                self.assertEqual(h.paths.guest.read_bytes(), b"")
                self.assertEqual(spec.creation_umask, 0o177)
                seen.append(h.paths.guest.stat().st_ino)
            return run(kind, spec, observer)
        h.run = check_placeholder
        self.assertTrue(h.execute().success)
        self.assertEqual(len(seen), 1)
        self.assertIn(("private-mode", h.paths.guest), h.io)

    def test_diagnostic_write_failure_does_not_suppress_failure_record(self):
        h = self.harness("cli-ack")
        write = h.r.EvidenceStore.write_json
        def fail_diagnostics(store, name, value):
            if name == "command-diagnostics.json": raise OSError("diagnostic disk failure")
            return write(store, name, value)
        with mock.patch.object(h.r.EvidenceStore, "write_json", new=fail_diagnostics):
            self.assertFalse(h.execute().success)
        self.assertTrue(h.paths.private_failure.exists())
        self.assertFalse(h.paths.public_summary.exists())

    def test_post_plan_outer_cleanup_failure_remains_distinct(self):
        h = self.harness("post-plan-outer")
        run = h.run
        def fail_post_plan(kind, spec, observer=None):
            if kind.name == "PREPARED_PLAN_POST":
                h.calls.append((kind.name, spec))
                raise h.r.CommandFailure("read", b"", b"", 901, 901, h.r.OuterCleanupStatus("Failed", "reap"))
            return run(kind, spec, observer)
        h.run = fail_post_plan
        result = h.execute()
        self.assertFalse(result.success)
        self.assertFalse(result.finalizer.outer_cleanup)
        self.assertTrue(result.finalizer.wineserver_cleanup)

    def test_server_command_outer_failure_is_not_inner_cleanup(self):
        h = self.harness("server-outer")
        run = h.run
        def fail_wait(kind, spec, observer=None):
            if kind.name == "WINESERVER_WAIT":
                h.calls.append((kind.name, spec))
                raise h.r.CommandFailure("read", b"", b"", 902, 902, h.r.OuterCleanupStatus("Failed", "reap"))
            return run(kind, spec, observer)
        h.run = fail_wait
        result = h.execute()
        self.assertFalse(result.success)
        self.assertFalse(result.finalizer.outer_cleanup)
        self.assertTrue(result.finalizer.inner_group_cleanup)

    def test_private_json_duplicate_nonfinite_and_oversize_fail_closed(self):
        for payload in ('{"schemaVersion":"1","schemaVersion":"1"}', '{"value":NaN}', '[]', 'x' * (1024 * 1024 + 1)):
            with self.subTest(payload=payload[:40]):
                h = self.harness("bad-context")
                run = h.run
                def invalid_context(kind, spec, observer=None):
                    result = run(kind, spec, observer)
                    if kind.name == "BOOTSTRAP_CONTEXT": h.paths.bootstrap_context.write_text(payload)
                    return result
                h.run = invalid_context
                self.assertFalse(h.execute().success)
                self.assertFalse((h.paths.root / "run-start.json").exists())

    def test_version_stream_shape_is_exact_and_failure_never_publishes(self):
        for stdout, stderr in ((b"Wine 10.0\n", b""), (b"", b"Wine 10.0 \n"), (b"", b"Wine 11.0\n")):
            with self.subTest(stdout=stdout, stderr=stderr):
                h = self.harness("version-shape")
                run = h.run
                def invalid_version(kind, spec, observer=None):
                    result = run(kind, spec, observer)
                    return replace(result, stdout=stdout, stderr=stderr) if kind.name == "WINESERVER_VERSION" else result
                h.run = invalid_version
                self.assertFalse(h.execute().success)
                self.assertFalse(h.paths.public_summary.exists())

    def test_public_summary_validator_rejects_private_and_unknown_values(self):
        r = runner_module()
        self.assertTrue(callable(getattr(r, "validate_public_summary", None)), "closed public summary validator missing")
        h = self.harness()
        self.assertTrue(h.execute().success)
        summary = json.loads(h.paths.public_summary.read_text())
        r.validate_public_summary(summary)
        for field, value in (("extra", "/secret"), ("runtimeVersion", str(h.paths.guest)),
                ("runtimeEventKinds", [{"path": "/secret"}]), ("guestDigest", "failure.json"),
                ("runtimePackId", r.REQUEST_ID), ("planCorrelation", "saved-plan-executed")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                r.validate_public_summary(summary | {field: value})

    def test_verified_abnormal_group_gets_bounded_term_then_kill(self):
        h = self.harness("abort-after-started")
        live = [True]
        h.group_exists = lambda pid: pid == h.pid and live[0]
        def signal_group(identity, signum):
            if identity.canonical_prefix == h.prefix:
                h.signals.append((identity, signum))
                if signum == 9: live[0] = False
        h.signal_verified_group = signal_group
        self.assertFalse(h.execute().success)
        self.assertEqual([signum for _, signum in h.signals], [15, 9])
        self.assertGreaterEqual(h.clock.now, 0.5)

    def test_proc_running_state_change_does_not_change_identity(self):
        r = runner_module()
        processes = r.NativeProcView()
        processes.platform = FakePlatform()
        prefix = ROOT.parent / "fixed-prefix"
        with mock.patch.object(processes, "_stat", side_effect=[(1000, b"S", 321, 1234), (1000, b"R", 321, 1234)]), \
                mock.patch.object(processes, "_read", return_value=os.fsencode("WINEPREFIX=" + str(prefix)) + b"\0"):
            try:
                observed = processes.observe(321, prefix)
            except OSError:
                self.fail("normal scheduling-state change was rejected as identity drift")
        self.assertEqual(observed, r.Verified(321, 1000, 1234, prefix))

    def test_unavailable_or_drifted_capabilities_fail_before_marker(self):
        for provider, field, value in (("runtimeProviders", "available", False),
                ("runtimeProviders", "capabilities", ["arbitrary"]), ("translators", "kind", "qemu"),
                ("graphicsBackends", "version", "11.0")):
            with self.subTest(provider=provider, field=field):
                h = self.harness("capabilities")
                context = h.context
                def drift():
                    value_context = context()
                    value_context["capabilities"][provider][0][field] = value
                    return value_context
                h.context = drift
                self.assertFalse(h.execute().success)
                self.assertFalse((h.paths.root / "run-start.json").exists())

    def test_premarker_failed_command_output_is_removed(self):
        for fault in ("compiler", "compiler-warning", "bootstrap"):
            with self.subTest(fault=fault):
                h = self.failure(fault, False)
                self.assertFalse(h.paths.guest.exists())
                self.assertFalse(h.paths.bootstrap_context.exists())

    def test_abnormal_server_drift_prevents_all_signalling(self):
        h = self.harness("server-drift")
        run = h.run
        def fail_after_mutation(kind, spec, observer=None):
            result = run(kind, spec, observer)
            if kind.name == "PREPARED_LAUNCH":
                raise h.r.CommandFailure("read", result.stdout, b"", 900, 900, h.r.OuterCleanupStatus("Complete", "none"))
            return result
        h.run = fail_after_mutation
        h.group_exists = lambda pid: pid == h.pid
        self.assertFalse(h.execute().success)
        self.assertEqual(h.signals, [])
        self.assertFalse(any(name.startswith("WINESERVER_") for name, _ in h.calls))

    def test_server_is_rehashed_before_every_invocation(self):
        for after in ("WINESERVER_VERSION", "WINESERVER_KILL"):
            with self.subTest(after=after):
                h = self.harness("abort-before-started")
                run = h.run
                def replace_server(kind, spec, observer=None):
                    result = run(kind, spec, observer)
                    if kind.name == after:
                        (h.inputs.materialized_root / "wineserver").write_bytes(b"replacement")
                    return result
                h.run = replace_server
                self.assertFalse(h.execute().success)
                self.assertNotIn("WINESERVER_WAIT", [name for name, _ in h.calls])

    def test_marker_durable_close_failure_still_finalizes(self):
        h = self.harness("marker-close")
        close = h.r.os.close
        failed = False
        def fail_marker_close(descriptor):
            nonlocal failed
            close(descriptor)
            if (h.paths.root / "run-start.json").exists() and not failed:
                failed = True
                raise OSError("injected close")
        with mock.patch.object(h.r.os, "close", side_effect=fail_marker_close):
            result = h.execute()
        self.assertFalse(result.success)
        self.assertEqual([name for name, _ in h.calls][-3:], ["WINESERVER_VERSION", "WINESERVER_KILL", "WINESERVER_WAIT"])
        self.assertTrue(h.paths.private_failure.exists())

    def test_final_input_rehash_and_summary_write_failures_cannot_publish(self):
        for fault in ("final-cli-drift", "summary-sync"):
            with self.subTest(fault=fault):
                h = self.harness(fault)
                run = h.run
                def mutate_after_wait(kind, spec, observer=None):
                    result = run(kind, spec, observer)
                    if kind.name == "WINESERVER_WAIT" and fault == "final-cli-drift":
                        h.inputs.cli.write_bytes(b"changed")
                    return result
                h.run = mutate_after_wait
                original_write = h.r.EvidenceStore._write_payload
                def fail_summary(store, name, payload, **kwargs):
                    if name == "public-summary.json":
                        with mock.patch.object(h.r.os, "fsync", side_effect=OSError("disk failure")):
                            return original_write(store, name, payload, **kwargs)
                    return original_write(store, name, payload, **kwargs)
                with mock.patch.object(h.r.EvidenceStore, "_write_payload", new=fail_summary) if fault == "summary-sync" else mock.patch.object(h.r.EvidenceStore, "_write_payload", new=original_write):
                    self.assertFalse(h.execute().success)
                self.assertFalse(h.paths.public_summary.exists())
                self.assertTrue(h.paths.private_failure.exists())

    def harness(self, fault=None):
        self.assertTrue(callable(getattr(runner_module(), "execute_preview", None)),
                        "Task13 execute_preview orchestration is missing")
        return PreviewHarness(self, fault)

    def failure(self, fault, started):
        h = self.harness(fault)
        result = h.execute()
        self.assertFalse(result.success, fault)
        self.assertIn(result.category, {"contract", "integrity", "unsupported-host", "test-infrastructure", "execution", "cleanup"})
        self.assertFalse(h.paths.public_summary.exists(), fault)
        names = [name for name, _ in h.calls]
        if started:
            self.assertTrue((h.paths.root / "run-start.json").exists(), fault)
            self.assertEqual(len(list(h.paths.root.glob("failure*"))), 1, fault)
            failure = json.loads(h.paths.private_failure.read_text())
            self.assertNotIn(str(h.base), json.dumps(failure))
            if fault != "server-drift":
                self.assertIn("WINESERVER_VERSION", names, fault)
                self.assertIn("WINESERVER_WAIT", names, fault)
        else:
            self.assertNotIn("WINESERVER_VERSION", names, fault)
            self.assertFalse((h.paths.root / "run-start.json").exists(), fault)
        return h

    def test_success_runs_exact_nine_commands_and_publishes_last(self):
        h = self.harness()
        result = h.execute()
        self.assertTrue(result.success)
        self.assertEqual([name for name, _ in h.calls], h.expected)
        summary = json.loads(h.paths.public_summary.read_text())
        self.assertEqual(len(summary), 20)
        self.assertEqual(summary["planCorrelation"], "pre-post-canonical-match")
        self.assertFalse(summary["displayForwarded"])
        self.assertFalse(summary["networkIsolationValidated"])
        self.assertEqual(h.io[-1], ("write", h.paths.public_summary))
        bootstrap = json.loads(h.paths.bootstrap_context.read_text())
        execution = json.loads(h.paths.execution_context.read_text())
        bootstrap["supervisor"]["maximumRuntimeMilliseconds"] = 60000
        self.assertEqual(bootstrap, execution)
        request = json.loads(h.paths.launch_request.read_text())
        self.assertEqual(request["arguments"], [])
        self.assertEqual(request["environment"], {})
        self.assertEqual(request["constraints"]["networkPolicy"], "deny")
        self.assertEqual(h.calls[1][1].argv[1:-3], ("-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", "-Wl,--subsystem,console,--no-insert-timestamp"))

    def test_compiler_or_inspection_failure_is_closed(self):
        for fault in ("self-test", "compiler", "compiler-warning", "missing-pe", "inspection", "bootstrap", "pre-plan", "reserve"):
            with self.subTest(fault=fault): self.failure(fault, False)

    def test_immutable_input_or_plan_drift_is_closed(self):
        self.failure("pre-input", False)
        for fault in ("post-input", "plan-mismatch", "server-drift"):
            with self.subTest(fault=fault): self.failure(fault, True)

    def test_malformed_or_adverse_events_are_closed(self):
        for fault in ("malformed-events", "gapped-events", "missing-marker", "duplicate-marker", "stderr-marker", "nonzero-exit", "failure-event", "missing-ack", "second-started", "event-after-exit", "cli-ack"):
            with self.subTest(fault=fault): self.failure(fault, True)

    def test_cleanup_failure_is_closed(self):
        for fault in ("wait-failure", "wait-timeout", "hidden-proc", "hidden-scan", "live-prefix", "live-group", "prefix-mismatch", "outer-cleanup"):
            with self.subTest(fault=fault): self.failure(fault, True)

    def test_deadline_or_output_failure_runs_failure_finalizer(self):
        for fault in ("overflow", "deadline", "abort-before-started", "abort-after-started"):
            with self.subTest(fault=fault):
                h = self.failure(fault, True)
                names = [name for name, _ in h.calls]
                self.assertEqual(names[-3:], ["WINESERVER_VERSION", "WINESERVER_KILL", "WINESERVER_WAIT"])
                self.assertTrue(all(identity.pid != 900 for identity, _ in h.signals))

    def test_quick_exit_requires_all_independent_cleanup_proofs(self):
        for fault in ("quick-exit", "zombie", "disappeared-leader"):
            with self.subTest(fault=fault):
                h = self.harness(fault)
                self.assertTrue(h.execute().success)
                self.assertEqual(h.signals, [])
        h = self.harness("quick-live-group")
        h.observe = lambda pid, prefix: h.r.ExitedBeforeSnapshot(pid)
        self.assertFalse(h.execute().success)
        self.assertEqual(h.signals, [])

    def test_changed_identity_is_never_signalled(self):
        h = self.harness("changed-start")
        run = h.run
        def abort(kind, spec, observer=None):
            result = run(kind, spec, observer)
            if kind.name == "PREPARED_LAUNCH":
                raise h.r.CommandFailure("read", result.stdout, b"", 900, 900, h.r.OuterCleanupStatus("Complete", "none"))
            return result
        h.run = abort
        self.assertFalse(h.execute().success)
        self.assertEqual(h.signals, [])


@unittest.skipUnless(sys.platform == "linux", "requires native Linux /proc visibility and process groups")
class LinuxPreviewProcIntegrationTests(unittest.TestCase):
    def test_native_child_umask_and_compiler_output_private_postcondition(self):
        r = runner_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.chmod(0o700)
            store = r.EvidenceStore(root)
            guest = store._write_payload("console-preview.exe", b"")
            self.assertEqual(guest.stat().st_mode & 0o777, 0o600)
            # Exercise the child-only mask even when a tool replaces its output.
            source = "import os,sys; p=sys.argv[1]; os.unlink(p); f=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o777); os.write(f,b'controlled'); os.close(f)"
            r.NativePreviewCommands().run(r.ClosedCommandKind.COMPILE_GUEST,
                r.CommandSpec((str(Path(sys.executable).resolve()), "-I", "-S", "-c", source, str(guest)),
                    {}, root, 1024, time.monotonic() + 3, 0o177))
            self.assertEqual(guest.stat().st_mode & 0o777, 0o600)
            fs = r.NativeFileSystem()
            fs.verify_private_file(guest, fs.inspect(guest).identity)
            guest.chmod(0o700)
            with self.assertRaises(ValueError):
                fs.verify_private_file(guest, fs.inspect(guest).identity)
            self.assertEqual(guest.stat().st_mode & 0o777, 0o700)

    def test_native_observer_self_test_stops_reaps_and_proves_disappearance(self):
        r = runner_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            prefix = root / "exact-prefix"
            clock = time.monotonic
            processes = r.NativeProcView(clock, clock() + 5)
            observer = r.ProcSelfTestObserver(processes, prefix)
            result = r.NativePreviewCommands(clock).run(r.ClosedCommandKind.PROC_OBSERVER_SELF_TEST,
                r.CommandSpec((str(Path(sys.executable).resolve()), "-I", "-S", "-c",
                    "import os,time; print(os.getpid(),flush=True); time.sleep(30)"),
                    {"WINEPREFIX": str(prefix)}, root, 1024, clock() + 3), observer)
            self.assertEqual(result.return_code, -15)
            self.assertIsNotNone(observer.identity)
            self.assertFalse(processes.group_exists(observer.identity.pid))
            self.assertEqual(processes.exact_prefix_processes(prefix), [])
            self.assertIsInstance(processes.observe(observer.identity.pid, prefix), r.ExitedBeforeSnapshot)

    def test_native_exact_environment_entry_does_not_match_similar_prefix(self):
        r = runner_module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            prefix = root / "prefix"
            processes = r.NativeProcView(time.monotonic, time.monotonic() + 5)
            observations = []
            class Observer:
                def on_chunk(self, stream, chunk):
                    if stream == "stdout" and b"\n" in chunk:
                        pid = int(chunk)
                        observations.append(pid)
                        selftest.assertIn(pid, processes.exact_prefix_processes(prefix))
                        selftest.assertNotIn(pid, processes.exact_prefix_processes(root / "pref"))
                        with selftest.assertRaises(OSError):
                            processes.observe(pid, root / "pref")
                        processes.signal_verified_group(processes.observe(pid, prefix), 15)
            selftest = self
            r.NativePreviewCommands().run(r.ClosedCommandKind.PROC_OBSERVER_SELF_TEST,
                r.CommandSpec((str(Path(sys.executable).resolve()), "-I", "-S", "-c",
                    "import os,time; print(os.getpid(),flush=True); time.sleep(30)"),
                    {"WINEPREFIX": str(prefix)}, root, 1024, time.monotonic() + 3), Observer())
            self.assertEqual(len(observations), 1)

    def test_native_unreadable_live_environment_is_not_skipped(self):
        r = runner_module()
        processes = r.NativeProcView()
        stat_record = (os.getuid(), b"S", 123, 1234)
        with mock.patch.object(processes, "_stat", return_value=stat_record), \
                mock.patch.object(processes, "_read", side_effect=PermissionError("hidepid")):
            with self.assertRaises(PermissionError):
                processes.observe(123, Path("/fixed-prefix"))


if __name__ == "__main__":
    unittest.main()
