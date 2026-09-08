from __future__ import annotations

import json
import importlib.util
import re
import sys
import os
import tempfile
import time
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


if __name__ == "__main__":
    unittest.main()
