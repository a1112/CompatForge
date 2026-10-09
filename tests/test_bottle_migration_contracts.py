import ast
import copy
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_NAMES = (
    "bottle-snapshot.schema.json",
    "bottle-runtime-map.schema.json",
    "bottle-migration-plan.schema.json",
    "bottle-active-ref.schema.json",
)
DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)
MAX_SNAPSHOT_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_DOCUMENT_SCALAR_CHARACTERS = 4096
MAX_DOCUMENT_COLLECTION_ITEMS = 100000
MAX_DOCUMENT_NODES = 1000000
MAX_DOCUMENT_DEPTH = 128
MAX_JSON_SAFE_INTEGER = (1 << 53) - 1
MAX_JSON_NUMBER_TEXT_CHARACTERS = 64
DOCUMENT_STRUCTURE_ERROR = "Bottle migration document exceeds structural limits"
DOCUMENT_MODEL_ERROR = "Bottle migration document is not exact JSON"
DOCUMENT_NUMBER_ERROR = "Bottle migration document contains an unsafe number"
DOCUMENT_GRAPH_ERROR = "Bottle migration document is not a JSON tree"
DOCUMENT_UNICODE_ERRORS = {
    "bottle-snapshot.schema.json": "snapshot manifest contains invalid Unicode",
    "bottle-runtime-map.schema.json": "runtime map contains invalid Unicode",
    "bottle-migration-plan.schema.json": "migration plan contains invalid Unicode",
    "bottle-active-ref.schema.json": "active reference contains invalid Unicode",
}
WINDOWS_SUPERSCRIPT_DEVICE_PATHS = (
    "COM¹",
    "COM².txt",
    "COM³",
    "LPT¹",
    "LPT².txt",
    "LPT³.log",
    "com¹",
    "cOm².TxT",
    "lPt³.LoG",
    "COM¹ .txt",
    "lpt²   .log",
)


class BottleMigrationSchemaTests(unittest.TestCase):
    def test_schemas_are_canonical_draft_2020_12_documents(self) -> None:
        identifiers = []
        for name in SCHEMA_NAMES:
            path = ROOT / "schemas" / name
            raw = path.read_bytes()
            schema = json.loads(raw)
            identifiers.append(schema["$id"])
            self.assertEqual(
                schema["$schema"],
                "https://json-schema.org/draft/2020-12/schema",
            )
            self.assertEqual(
                schema["$id"], f"https://compatforge.dev/schemas/{name}"
            )
            self.assertEqual(schema["properties"]["schemaVersion"], {"const": "1"})
            self.assertEqual(
                raw,
                (
                    json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True)
                    + "\n"
                ).encode("utf-8"),
            )
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_every_object_is_closed_and_every_value_is_bounded(self) -> None:
        for name, schema in self._schemas().items():
            for location, node in self._walk(schema):
                with self.subTest(schema=name, location=location):
                    if node.get("type") == "object":
                        self.assertIs(node.get("additionalProperties"), False)
                        self.assertIsInstance(node.get("properties"), dict)
                    elif node.get("type") == "array":
                        self.assertIn("maxItems", node)
                    elif node.get("type") == "string" and not any(
                        key in node for key in ("const", "enum", "$ref")
                    ):
                        self.assertIn("maxLength", node)
                    elif node.get("type") == "integer":
                        self.assertIn("minimum", node)
                        self.assertIn("maximum", node)

    def test_top_level_fields_and_entry_branches_are_exact(self) -> None:
        schemas = self._schemas()
        expected = {
            "bottle-snapshot.schema.json": {
                "schemaVersion",
                "legacyFormat",
                "bottleId",
                "entries",
                "entryCount",
                "totalFileBytes",
            },
            "bottle-runtime-map.schema.json": {"schemaVersion", "mappings"},
            "bottle-migration-plan.schema.json": {
                "schemaVersion",
                "snapshotDigest",
                "legacyFormat",
                "legacyEngineId",
                "bottle",
                "bottleDigest",
                "runtimePack",
                "launchers",
                "diagnostics",
                "planDigest",
            },
            "bottle-active-ref.schema.json": {
                "schemaVersion",
                "bottleId",
                "activePlanDigest",
                "history",
            },
        }
        for name, fields in expected.items():
            schema = schemas[name]
            self.assertEqual(set(schema["properties"]), fields)
            self.assertEqual(set(schema["required"]), fields)

        snapshot = schemas["bottle-snapshot.schema.json"]
        self.assertEqual(
            snapshot["properties"]["entries"]["items"]["oneOf"],
            [
                {"$ref": "#/$defs/fileEntry"},
                {"$ref": "#/$defs/directoryEntry"},
                {"$ref": "#/$defs/linkEntry"},
            ],
        )
        self.assertEqual(snapshot["properties"]["entries"]["maxItems"], 100_000)
        self.assertEqual(
            schemas["bottle-active-ref.schema.json"]["properties"]["history"][
                "maxItems"
            ],
            32,
        )

    def test_safe_identifier_digest_and_path_contracts(self) -> None:
        for name, schema in self._schemas().items():
            for value in ("bottle-1", "runtime.preview", "engine_9"):
                self._assert_valid(value, schema["$defs"]["id"], schema)
            for value in ("A", "Upper", "two/slash", "two:colon", "two\n"):
                with self.assertRaises(AssertionError, msg=(name, value)):
                    self._assert_valid(value, schema["$defs"]["id"], schema)

            self._assert_valid(DIGEST_A, schema["$defs"]["digest"], schema)
            for value in ("sha256:" + ("A" * 64), "sha256:abcd", "a" * 64):
                with self.assertRaises(AssertionError, msg=(name, value[:16])):
                    self._assert_valid(value, schema["$defs"]["digest"], schema)

            if "relativePath" in schema["$defs"]:
                path_contract = schema["$defs"]["relativePath"]
                for value in (
                    "manifest.json",
                    "drive_c/Public/example.txt",
                    "drive_c/应用/example.exe",
                    "café/file",
                ):
                    self._assert_valid(value, path_contract, schema)
                for value in (
                    "",
                    ".",
                    "..",
                    "/absolute",
                    "C:/drive",
                    "a\\b",
                    "a/../b",
                    "a//b",
                    "CON",
                    "folder/NUL.txt",
                    "folder/name.",
                    "folder/name ",
                ):
                    with self.assertRaises(AssertionError, msg=(name, value)):
                        self._assert_valid(value, path_contract, schema)
                self._assert_valid("/".join(["a"] * 128), path_contract, schema)
                with self.assertRaises(AssertionError, msg=(name, "depth")):
                    self._assert_valid("/".join(["a"] * 129), path_contract, schema)

            if "legacyEngineId" in schema["$defs"]:
                engine_id = schema["$defs"]["legacyEngineId"]
                self._assert_valid("WS11WineCX64Bit23.7.1-1", engine_id, schema)
                for value in ("", "engine/slash", "engine\\slash", "engine\n"):
                    with self.assertRaises(AssertionError, msg=(name, value)):
                        self._assert_valid(value, engine_id, schema)

    def test_portable_paths_use_utf8_byte_component_and_total_bounds(self) -> None:
        ascii_total_max = "/".join(
            (["a" * 255] * 15) + ["b" * 127, "c" * 128]
        )
        ascii_total_over = ascii_total_max + "c"
        multibyte_component_max = ("é" * 127) + "a"
        multibyte_component_over = "é" * 128
        multibyte_total_max = "/".join(
            ([multibyte_component_max] * 15)
            + [("é" * 63) + "a", "é" * 64]
        )
        multibyte_total_over = multibyte_total_max + "a"

        self.assertEqual(len(ascii_total_max.encode("utf-8")), 4096)
        self.assertEqual(len(ascii_total_over.encode("utf-8")), 4097)
        self.assertEqual(len(multibyte_component_max.encode("utf-8")), 255)
        self.assertEqual(len(multibyte_component_over.encode("utf-8")), 256)
        self.assertEqual(len(multibyte_total_max.encode("utf-8")), 4096)
        self.assertEqual(len(multibyte_total_over.encode("utf-8")), 4097)

        for name in (
            "bottle-snapshot.schema.json",
            "bottle-migration-plan.schema.json",
        ):
            schema = self._schema(name)
            contract = schema["$defs"]["relativePath"]
            for value in (
                "a" * 255,
                ascii_total_max,
                multibyte_component_max,
                multibyte_total_max,
            ):
                with self.subTest(
                    schema=name,
                    case="max",
                    bytes=len(value.encode("utf-8")),
                ):
                    self._assert_valid(value, contract, schema)
            for value in (
                "a" * 256,
                ascii_total_over,
                multibyte_component_over,
                multibyte_total_over,
            ):
                with self.subTest(
                    schema=name,
                    case="over",
                    bytes=len(value.encode("utf-8")),
                ), self.assertRaises(AssertionError):
                    self._assert_valid(value, contract, schema)

    def test_portable_paths_require_nfc_unicode_scalars(self) -> None:
        invalid_paths = (
            "cafe\u0301/file",
            "folder/\ud800/file",
            "folder/\u0085/file",
        )
        for name in (
            "bottle-snapshot.schema.json",
            "bottle-migration-plan.schema.json",
        ):
            schema = self._schema(name)
            contract = schema["$defs"]["relativePath"]
            self._assert_valid("café/应用.exe", contract, schema)
            for value in invalid_paths:
                with self.subTest(schema=name, value=repr(value)), self.assertRaises(
                    AssertionError
                ):
                    self._assert_valid(value, contract, schema)

    def test_portable_path_surrogates_have_a_fixed_unchained_error(self) -> None:
        for surrogate_kind, surrogate in (
            ("high", "\ud800"),
            ("low", "\udfff"),
        ):
            with self.subTest(surrogate=surrogate_kind):
                with self.assertRaises(AssertionError) as caught:
                    self._assert_portable_path(f"secret-{surrogate}")
                error = caught.exception
                self.assertIs(type(error), AssertionError)
                self.assertEqual(str(error), "path is not valid Unicode")
                self.assertNotIn("secret", str(error))
                self.assertIsNone(error.__cause__)
                self.assertTrue(error.__suppress_context__)

    def test_schema_patterns_reject_windows_superscript_device_aliases(self) -> None:
        for name in (
            "bottle-snapshot.schema.json",
            "bottle-migration-plan.schema.json",
        ):
            pattern = self._schema(name)["$defs"]["relativePath"]["pattern"]
            for value in WINDOWS_SUPERSCRIPT_DEVICE_PATHS:
                with self.subTest(schema=name, value=value):
                    self.assertIsNone(re.search(pattern, value))

    def test_oracle_rejects_windows_superscript_device_aliases(self) -> None:
        for value in WINDOWS_SUPERSCRIPT_DEVICE_PATHS:
            with self.subTest(value=value), self.assertRaises(AssertionError):
                self._assert_portable_path(value)

    def test_snapshot_paths_reject_casefold_collisions(self) -> None:
        name = "bottle-snapshot.schema.json"
        collision = copy.deepcopy(self._instances()[name])
        collision["entries"] = [
            {"path": "Drive", "kind": "directory"},
            {"path": "drive", "kind": "directory"},
        ]
        collision["entryCount"] = 2
        collision["totalFileBytes"] = 0
        with self.assertRaises(AssertionError):
            self._assert_document_valid(name, collision, self._schema(name))

    def test_complete_instances_and_closed_type_mutants(self) -> None:
        for name, instance in self._instances().items():
            schema = self._schema(name)
            with self.subTest(schema=name, case="valid"):
                self._assert_document_valid(name, instance, schema)

            extra = copy.deepcopy(instance)
            extra["unexpected"] = True
            with self.subTest(schema=name, case="extra"), self.assertRaises(
                AssertionError
            ):
                self._assert_document_valid(name, extra, schema)

        plan_name = "bottle-migration-plan.schema.json"
        plan_schema = self._schema(plan_name)
        integer_boolean = copy.deepcopy(self._instances()[plan_name])
        integer_boolean["launchers"][0]["showInHome"] = 1
        with self.assertRaises(AssertionError):
            self._assert_document_valid(plan_name, integer_boolean, plan_schema)

        nested_extra = copy.deepcopy(self._instances()[plan_name])
        nested_extra["launchers"][0]["unexpected"] = False
        with self.assertRaises(AssertionError):
            self._assert_document_valid(plan_name, nested_extra, plan_schema)

    def test_snapshot_entry_fields_are_disjoint_and_links_stay_inside(self) -> None:
        name = "bottle-snapshot.schema.json"
        schema = self._schema(name)
        valid = self._instances()[name]

        missing_file_fields = copy.deepcopy(valid)
        del missing_file_fields["entries"][1]["digest"]
        del missing_file_fields["entries"][1]["size"]
        directory_with_file_fields = copy.deepcopy(valid)
        directory_with_file_fields["entries"][0].update(
            {"digest": DIGEST_A, "size": 0}
        )
        absolute_link = copy.deepcopy(valid)
        absolute_link["entries"][2]["target"] = "/outside"
        escaping_link = copy.deepcopy(valid)
        escaping_link["entries"][2]["target"] = "../outside"

        for label, mutant in (
            ("file-fields", missing_file_fields),
            ("directory-file-fields", directory_with_file_fields),
            ("absolute-link", absolute_link),
            ("escaping-link", escaping_link),
        ):
            with self.subTest(case=label), self.assertRaises(AssertionError):
                self._assert_document_valid(name, mutant, schema)

    def test_snapshot_manifest_canonical_utf8_size_has_exact_64_mib_bound(self) -> None:
        name = "bottle-snapshot.schema.json"
        value = self._instances()[name]
        schema = self._schema(name)
        one_mib = "x" * (1024 * 1024)

        def controlled_chunks(canonical_size: int):
            payload_size = canonical_size - 1  # The canonical trailing LF.
            full_chunks, remainder = divmod(payload_size, len(one_mib))
            yield from (one_mib for _ in range(full_chunks))
            if remainder:
                yield "x" * remainder

        with mock.patch.object(
            type(self),
            "_canonical_json_chunks",
            return_value=controlled_chunks(MAX_SNAPSHOT_MANIFEST_BYTES),
            create=True,
        ):
            self._assert_document_valid(name, value, schema)

        with mock.patch.object(
            type(self),
            "_canonical_json_chunks",
            return_value=controlled_chunks(MAX_SNAPSHOT_MANIFEST_BYTES + 1),
            create=True,
        ), mock.patch.object(
            json,
            "dumps",
            side_effect=AssertionError("canonical output was materialized"),
        ), self.assertRaisesRegex(
            AssertionError,
            f"^snapshot manifest exceeds {MAX_SNAPSHOT_MANIFEST_BYTES} UTF-8 bytes$",
        ):
            self._assert_document_valid(name, value, schema)

    def test_snapshot_manifest_size_uses_canonical_pretty_lf_bytes(self) -> None:
        value = self._instances()["bottle-snapshot.schema.json"]
        value["entries"][0]["path"] = "drive_c/应用"
        expected = (
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        actual = "".join(self._canonical_json_chunks(value)).encode("utf-8") + b"\n"
        self.assertEqual(actual, expected)

    def test_structural_preflight_rejects_a_long_scalar_before_utf8_or_json(self) -> None:
        instances = self._instances()
        long_scalar_name = "bottle-snapshot.schema.json"
        long_scalar = instances[long_scalar_name]
        long_scalar["bottleId"] = "x" * (MAX_DOCUMENT_SCALAR_CHARACTERS + 1)
        long_key_name = "bottle-active-ref.schema.json"
        long_key = instances[long_key_name]
        long_key["x" * (MAX_DOCUMENT_SCALAR_CHARACTERS + 1)] = None

        for label, name, value in (
            ("value", long_scalar_name, long_scalar),
            ("key", long_key_name, long_key),
        ):
            with self.subTest(case=label), mock.patch.object(
                type(self),
                "_utf8_chunk_size",
                side_effect=AssertionError("UTF-8 encoding was attempted"),
            ), mock.patch.object(
                type(self),
                "_canonical_json_chunks",
                side_effect=AssertionError("JSONEncoder was constructed"),
            ), self.assertRaisesRegex(
                AssertionError,
                f"^{re.escape(DOCUMENT_STRUCTURE_ERROR)}$",
            ):
                self._assert_document_valid(name, value, self._schema(name))

    def test_structural_preflight_bounds_collections_nodes_and_depth(self) -> None:
        instances = self._instances()

        runtime_name = "bottle-runtime-map.schema.json"
        oversized_collection = copy.deepcopy(instances[runtime_name])
        oversized_collection["mappings"] = [None] * (
            MAX_DOCUMENT_COLLECTION_ITEMS + 1
        )

        active_name = "bottle-active-ref.schema.json"
        oversized_graph = copy.deepcopy(instances[active_name])
        wide_nested: object = None
        for _ in range(11):
            wide_nested = ([None] * (MAX_DOCUMENT_COLLECTION_ITEMS - 1)) + [
                wide_nested
            ]
        oversized_graph["nodes"] = wide_nested

        excessive_depth = copy.deepcopy(instances[active_name])
        nested: object = None
        for _ in range(MAX_DOCUMENT_DEPTH + 1):
            nested = [nested]
        excessive_depth["nested"] = nested

        for label, name, value in (
            ("collection", runtime_name, oversized_collection),
            ("nodes", active_name, oversized_graph),
            ("depth", active_name, excessive_depth),
        ):
            with self.subTest(case=label), mock.patch.object(
                type(self),
                "_utf8_chunk_size",
                side_effect=AssertionError("UTF-8 encoding was attempted"),
            ), self.assertRaisesRegex(
                AssertionError,
                f"^{re.escape(DOCUMENT_STRUCTURE_ERROR)}$",
            ):
                self._assert_document_valid(name, value, self._schema(name))

    def test_preflight_rejects_json_subclasses_without_calling_their_hooks(self) -> None:
        class LyingString(str):
            def __len__(self):
                raise AssertionError("lying string length was called")

            def encode(self, *args, **kwargs):
                raise AssertionError("lying string encode was called")

        class LyingList(list):
            def __len__(self):
                raise AssertionError("lying list length was called")

        class IteratorBombList(list):
            def __iter__(self):
                raise AssertionError("lying list iterator was called")

        class LyingDict(dict):
            def __len__(self):
                raise AssertionError("lying dict length was called")

        class IteratorBombDict(dict):
            def items(self):
                raise AssertionError("lying dict iterator was called")

        name = "bottle-active-ref.schema.json"
        cases = []

        string_value = self._instances()[name]
        string_value["activePlanDigest"] = LyingString(DIGEST_A)
        cases.append(("string-value", string_value))

        string_key = self._instances()[name]
        string_key[LyingString("secret-key")] = None
        cases.append(("string-key", string_key))

        list_value = self._instances()[name]
        list_value["history"] = LyingList([])
        cases.append(("list", list_value))

        iterator_list = self._instances()[name]
        iterator_list["history"] = IteratorBombList([])
        cases.append(("list-iterator", iterator_list))

        dict_value = LyingDict(self._instances()[name])
        cases.append(("dict", dict_value))

        iterator_dict = IteratorBombDict(self._instances()[name])
        cases.append(("dict-iterator", iterator_dict))

        for label, value in cases:
            with self.subTest(case=label):
                with self.assertRaises(AssertionError) as caught:
                    self._assert_document_valid(name, value, self._schema(name))
                error = caught.exception
                self.assertIs(type(error), AssertionError)
                self.assertEqual(str(error), DOCUMENT_MODEL_ERROR)
                self.assertNotIn("lying", str(error))
                self.assertIsNone(error.__cause__)
                self.assertTrue(error.__suppress_context__)

    def test_preflight_rejects_non_json_values_before_encoder_or_regex(self) -> None:
        name = "bottle-active-ref.schema.json"
        for label, hostile in (
            ("object", object()),
            ("bytes", b"secret"),
            ("tuple", ("secret",)),
            ("set", {"secret"}),
        ):
            value = self._instances()[name]
            value["hostile"] = hostile
            with self.subTest(case=label), mock.patch.object(
                re,
                "search",
                side_effect=AssertionError("regular expression was called"),
            ), mock.patch.object(
                type(self),
                "_canonical_json_chunks",
                side_effect=AssertionError("JSONEncoder was called"),
            ):
                with self.assertRaises(AssertionError) as caught:
                    self._assert_document_valid(name, value, self._schema(name))
                error = caught.exception
                self.assertIs(type(error), AssertionError)
                self.assertEqual(str(error), DOCUMENT_MODEL_ERROR)
                self.assertNotIn("secret", str(error))
                self.assertIsNone(error.__cause__)
                self.assertTrue(error.__suppress_context__)

    def test_preflight_bounds_exact_json_numbers_before_heavy_operations(self) -> None:
        name = "bottle-snapshot.schema.json"
        schema = self._schema(name)
        for label, hostile in (
            ("nan", float("nan")),
            ("positive-infinity", float("inf")),
            ("negative-infinity", float("-inf")),
            ("huge-integer", 1 << 1000000),
        ):
            value = self._instances()[name]
            value["entryCount"] = hostile
            with self.subTest(case=label), mock.patch.object(
                re,
                "search",
                side_effect=AssertionError("regular expression was called"),
            ), mock.patch.object(
                type(self),
                "_canonical_json_chunks",
                side_effect=AssertionError("JSONEncoder was called"),
            ):
                with self.assertRaises(AssertionError) as caught:
                    self._assert_document_valid(name, value, schema)
                error = caught.exception
                self.assertIs(type(error), AssertionError)
                self.assertEqual(str(error), DOCUMENT_NUMBER_ERROR)
                self.assertIsNone(error.__cause__)
                self.assertTrue(error.__suppress_context__)

        self._assert_document_preflight(name, {"number": 1.5})
        self._assert_document_preflight(name, {"number": MAX_JSON_SAFE_INTEGER})
        self.assertFalse(self._matches_type(True, "integer"))
        self.assertFalse(self._matches_type(1, "boolean"))

    def test_preflight_rejects_cycles_and_shared_containers(self) -> None:
        name = "bottle-active-ref.schema.json"

        cycle = []
        cycle.append(cycle)
        cyclic_document = self._instances()[name]
        cyclic_document["cycle"] = cycle

        shared = []
        shared_document = self._instances()[name]
        shared_document["left"] = shared
        shared_document["right"] = shared

        for label, value in (
            ("cycle", cyclic_document),
            ("shared", shared_document),
        ):
            with self.subTest(case=label):
                with self.assertRaises(AssertionError) as caught:
                    self._assert_document_valid(name, value, self._schema(name))
                error = caught.exception
                self.assertIs(type(error), AssertionError)
                self.assertEqual(str(error), DOCUMENT_GRAPH_ERROR)
                self.assertIsNone(error.__cause__)
                self.assertTrue(error.__suppress_context__)

    def test_preflight_checks_scheduled_budget_before_descending_width(self) -> None:
        name = "bottle-active-ref.schema.json"
        nested: object = "must-not-be-inspected"
        for _ in range(11):
            nested = ([None] * (MAX_DOCUMENT_COLLECTION_ITEMS - 1)) + [nested]
        value = self._instances()[name]
        value["nested"] = nested

        def reject_leaf_after_overflow(text: str) -> bool:
            if text == "must-not-be-inspected":
                raise AssertionError("a scalar was inspected after budget overflow")
            return False

        with mock.patch.object(
            type(self),
            "_contains_surrogate",
            side_effect=reject_leaf_after_overflow,
        ), self.assertRaisesRegex(
            AssertionError,
            f"^{re.escape(DOCUMENT_STRUCTURE_ERROR)}$",
        ):
            self._assert_document_valid(name, value, self._schema(name))

    def test_snapshot_encoder_chunks_are_utf8_counted_in_fixed_slices(self) -> None:
        class EncodeBomb(str):
            def encode(self, *args, **kwargs):
                raise AssertionError("the complete encoder chunk was encoded")

        observed_sizes = []

        def bounded_utf8_size(chunk: str) -> int:
            observed_sizes.append(len(chunk))
            if len(chunk) > 256:
                raise AssertionError("an oversized UTF-8 chunk was encoded")
            return len(str(chunk).encode("utf-8"))

        with mock.patch.object(
            type(self),
            "_canonical_json_chunks",
            return_value=[EncodeBomb("é" * 1024)],
        ), mock.patch.object(
            type(self),
            "_utf8_chunk_size",
            side_effect=bounded_utf8_size,
        ):
            self._assert_snapshot_manifest_size({})

        self.assertEqual(observed_sizes, [256, 256, 256, 256])

    def test_portable_path_length_precedes_utf8_encoding(self) -> None:
        class EncodeBomb(str):
            def encode(self, *args, **kwargs):
                raise AssertionError("portable path encoding was attempted")

        value = EncodeBomb("x" * (MAX_DOCUMENT_SCALAR_CHARACTERS + 1))
        with self.assertRaisesRegex(
            AssertionError,
            "^path exceeds the UTF-8 byte limit$",
        ):
            self._assert_portable_path(value)

    def test_rfc3339_length_precedes_regular_expression_matching(self) -> None:
        value = "x" * (MAX_DOCUMENT_SCALAR_CHARACTERS + 1)
        with mock.patch.object(
            re,
            "fullmatch",
            side_effect=AssertionError("regular expression matching was attempted"),
        ), self.assertRaisesRegex(
            AssertionError,
            "^RFC 3339 timestamp is invalid$",
        ):
            self._assert_rfc3339(value)

    def test_schema_items_are_validated_before_unique_canonicalization(self) -> None:
        name = "bottle-migration-plan.schema.json"
        schema = self._schema(name)
        value = [{"invented": True}]

        with mock.patch.object(
            json,
            "dumps",
            side_effect=AssertionError("unique item JSON was materialized"),
        ), self.assertRaisesRegex(AssertionError, "^enum mismatch$"):
            self._assert_valid(value, schema["properties"]["diagnostics"], schema)

    def test_snapshot_document_surrogates_use_fixed_non_reflecting_error(self) -> None:
        name = "bottle-snapshot.schema.json"
        schema = self._schema(name)
        string_fields = (
            ("schema-version", ("schemaVersion",)),
            ("legacy-format", ("legacyFormat",)),
            ("bottle-id", ("bottleId",)),
            ("entry-path", ("entries", 0, "path")),
            ("entry-kind", ("entries", 0, "kind")),
            ("file-digest", ("entries", 1, "digest")),
            ("link-target", ("entries", 2, "target")),
        )
        for surrogate_kind, surrogate in (
            ("high", "\ud800"),
            ("low", "\udfff"),
        ):
            for field, pointer in string_fields:
                value = copy.deepcopy(self._instances()[name])
                target = value
                for component in pointer[:-1]:
                    target = target[component]
                target[pointer[-1]] = f"secret-{surrogate}"

                with self.subTest(surrogate=surrogate_kind, field=field):
                    with self.assertRaises(AssertionError) as caught:
                        self._assert_document_valid(name, value, schema)
                    error = caught.exception
                    self.assertIs(type(error), AssertionError)
                    self.assertEqual(
                        str(error),
                        "snapshot manifest contains invalid Unicode",
                    )
                    self.assertNotIn("secret", str(error))
                    self.assertIsNone(error.__cause__)
                    self.assertTrue(error.__suppress_context__)

    def test_all_document_string_values_and_keys_reject_lone_surrogates(self) -> None:
        def locations(value: object, pointer=()):
            if isinstance(value, str):
                yield "value", pointer
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    yield from locations(item, (*pointer, index))
            elif isinstance(value, dict):
                yield "key", pointer
                for key, item in value.items():
                    yield from locations(item, (*pointer, key))

        for name, original in self._instances().items():
            schema = self._schema(name)
            for location_kind, pointer in locations(original):
                for surrogate_kind, surrogate in (
                    ("high", "\ud800"),
                    ("low", "\udfff"),
                ):
                    value = copy.deepcopy(original)
                    target = value
                    for component in pointer[:-1]:
                        target = target[component]
                    hostile = f"secret-{surrogate}"
                    if location_kind == "value":
                        target[pointer[-1]] = hostile
                    else:
                        for component in pointer[-1:]:
                            target = target[component]
                        target[hostile] = None

                    with self.subTest(
                        schema=name,
                        location=location_kind,
                        pointer=repr(pointer),
                        surrogate=surrogate_kind,
                    ):
                        with self.assertRaises(AssertionError) as caught:
                            self._assert_document_valid(name, value, schema)
                        error = caught.exception
                        self.assertIs(type(error), AssertionError)
                        self.assertEqual(str(error), DOCUMENT_UNICODE_ERRORS[name])
                        self.assertNotIn("secret", str(error))
                        self.assertIsNone(error.__cause__)
                        self.assertTrue(error.__suppress_context__)

    def test_records_are_sorted_and_unique(self) -> None:
        instances = self._instances()
        cases = []

        snapshot = copy.deepcopy(instances["bottle-snapshot.schema.json"])
        snapshot["entries"] = list(reversed(snapshot["entries"]))
        cases.append(("bottle-snapshot.schema.json", snapshot))

        runtime_map = copy.deepcopy(instances["bottle-runtime-map.schema.json"])
        duplicate_mapping = copy.deepcopy(runtime_map["mappings"][0])
        duplicate_mapping["runtimePackDigest"] = DIGEST_B
        runtime_map["mappings"].append(duplicate_mapping)
        cases.append(("bottle-runtime-map.schema.json", runtime_map))

        plan = copy.deepcopy(instances["bottle-migration-plan.schema.json"])
        duplicate_environment = copy.deepcopy(plan["launchers"][0]["environment"][0])
        duplicate_environment["value"] = "different"
        plan["launchers"][0]["environment"].append(duplicate_environment)
        cases.append(("bottle-migration-plan.schema.json", plan))

        for name, mutant in cases:
            with self.subTest(schema=name), self.assertRaises(AssertionError):
                self._assert_document_valid(name, mutant, self._schema(name))

    def test_history_bound_and_plan_runtime_binding_are_semantic(self) -> None:
        instances = self._instances()

        active_name = "bottle-active-ref.schema.json"
        active = copy.deepcopy(instances[active_name])
        active["history"] = [f"sha256:{index:064x}" for index in range(33)]
        with self.assertRaises(AssertionError):
            self._assert_document_valid(active_name, active, self._schema(active_name))

        plan_name = "bottle-migration-plan.schema.json"
        for field in ("id", "digest"):
            plan = copy.deepcopy(instances[plan_name])
            plan["runtimePack"][field] = (
                "different-runtime" if field == "id" else DIGEST_B
            )
            with self.subTest(field=field), self.assertRaises(AssertionError):
                self._assert_document_valid(plan_name, plan, self._schema(plan_name))

    def test_active_plan_digest_is_disjoint_from_prior_history(self) -> None:
        name = "bottle-active-ref.schema.json"
        active = copy.deepcopy(self._instances()[name])
        active["history"].append(active["activePlanDigest"])
        with self.assertRaisesRegex(
            AssertionError,
            "^active plan digest must not appear in history$",
        ):
            self._assert_document_valid(name, active, self._schema(name))

    def test_rfc3339_schema_admits_domain_leap_second_syntax(self) -> None:
        schema = self._schema("bottle-migration-plan.schema.json")
        pattern = schema["$defs"]["rfc3339"]["pattern"]
        for timestamp in (
            "2016-12-31T23:59:60Z",
            "2017-01-01T00:59:60+01:00",
        ):
            with self.subTest(timestamp=timestamp):
                self.assertIsNotNone(re.search(pattern, timestamp))

    def test_rfc3339_oracle_accepts_domain_valid_boundaries(self) -> None:
        schema = self._schema("bottle-migration-plan.schema.json")
        contract = schema["$defs"]["rfc3339"]
        for timestamp in (
            "2000-02-29T23:59:59Z",
            "2024-02-29t12:34:56.123z",
            "2026-08-08T00:00:00.1234567890Z",
            "2026-08-08T00:00:00+23:59",
            "2016-12-31T23:59:60Z",
            "2017-01-01T00:59:60+01:00",
        ):
            with self.subTest(timestamp=timestamp):
                self._assert_valid(timestamp, contract, schema)

    def test_rfc3339_oracle_rejects_invalid_dates_and_leap_positions(self) -> None:
        schema = self._schema("bottle-migration-plan.schema.json")
        contract = schema["$defs"]["rfc3339"]
        for timestamp in (
            "2026-02-30T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-08-08T00:00:00+24:00",
            "2026-08-08T00:00:60Z",
            "2016-12-30T23:59:60Z",
            "2016-12-31T23:58:60Z",
            "2016-12-31T23:59:60+01:00",
            "2017-01-01T01:00:60+01:00",
        ):
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(
                AssertionError, "^RFC 3339 timestamp is invalid$"
            ):
                self._assert_valid(timestamp, contract, schema)

    def test_launcher_bottle_id_must_match_embedded_bottle(self) -> None:
        name = "bottle-migration-plan.schema.json"
        plan = copy.deepcopy(self._instances()[name])
        plan["launchers"][0]["bottleId"] = "bottle-2"
        with self.assertRaises(AssertionError):
            self._assert_document_valid(name, plan, self._schema(name))

    def test_migration_plan_recipe_collection_is_fixed_empty(self) -> None:
        schema = self._schema("bottle-migration-plan.schema.json")
        recipes = schema["$defs"]["bottle"]["properties"]["recipes"]
        self.assertEqual(recipes["maxItems"], 0)
        self.assertIn("recipeReference", schema["$defs"])

    def test_oracle_rejects_invented_migration_plan_recipe(self) -> None:
        name = "bottle-migration-plan.schema.json"
        plan = copy.deepcopy(self._instances()[name])
        plan["bottle"]["recipes"] = [
            {
                "id": "invented-recipe",
                "version": "1",
                "digest": DIGEST_A,
            }
        ]
        with self.assertRaisesRegex(AssertionError, "^array too long$"):
            self._assert_document_valid(name, plan, self._schema(name))

    def test_oracle_uses_only_the_python_standard_library(self) -> None:
        tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            node.module.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        )
        self.assertNotIn("jsonschema", imported)

    def _schemas(self) -> dict[str, dict[str, object]]:
        return {name: self._schema(name) for name in SCHEMA_NAMES}

    def _schema(self, name: str) -> dict[str, object]:
        return json.loads((ROOT / "schemas" / name).read_bytes())

    @staticmethod
    def _canonical_json_chunks(value: object):
        return json.JSONEncoder(
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).iterencode(value)

    @staticmethod
    def _utf8_chunk_size(value: str) -> int:
        return len(value.encode("utf-8", errors="strict"))

    @classmethod
    def _utf8_text_size(cls, value: str) -> int:
        return sum(
            cls._utf8_chunk_size(value[start : start + 256])
            for start in range(0, len(value), 256)
        )

    @staticmethod
    def _contains_surrogate(value: str) -> bool:
        return any(0xD800 <= ord(character) <= 0xDFFF for character in value)

    @classmethod
    def _iter_document_strings(cls, value: object):
        value_type = type(value)
        if value_type is str:
            yield value
        elif value_type is dict:
            for key, item in value.items():
                yield key
                yield from cls._iter_document_strings(item)
        elif value_type is list:
            for index in range(len(value)):
                yield from cls._iter_document_strings(value[index])

    @classmethod
    def _assert_document_preflight(cls, name: str, value: object) -> None:
        allowed_types = {dict, list, str, int, float, bool, type(None)}
        value_type = type(value)
        if value_type not in allowed_types:
            raise AssertionError(DOCUMENT_MODEL_ERROR) from None

        scheduled_nodes = 1
        seen_containers = set()
        if value_type in (dict, list):
            seen_containers.add(id(value))

        def visit(current: object, depth: int) -> None:
            nonlocal scheduled_nodes
            current_type = type(current)
            if current_type is str:
                if len(current) > MAX_DOCUMENT_SCALAR_CHARACTERS:
                    raise AssertionError(DOCUMENT_STRUCTURE_ERROR) from None
                if cls._contains_surrogate(current):
                    raise AssertionError(DOCUMENT_UNICODE_ERRORS[name]) from None
            elif current_type is int:
                if current.bit_length() > 53 or not (
                    -MAX_JSON_SAFE_INTEGER <= current <= MAX_JSON_SAFE_INTEGER
                ):
                    raise AssertionError(DOCUMENT_NUMBER_ERROR) from None
            elif current_type is float:
                if (
                    not math.isfinite(current)
                    or abs(current) > MAX_JSON_SAFE_INTEGER
                    or len(repr(current)) > MAX_JSON_NUMBER_TEXT_CHARACTERS
                ):
                    raise AssertionError(DOCUMENT_NUMBER_ERROR) from None
            elif current_type is dict:
                if len(current) > MAX_DOCUMENT_COLLECTION_ITEMS:
                    raise AssertionError(DOCUMENT_STRUCTURE_ERROR) from None
                for key, item in current.items():
                    if type(key) is not str:
                        raise AssertionError(DOCUMENT_MODEL_ERROR) from None
                    if len(key) > MAX_DOCUMENT_SCALAR_CHARACTERS:
                        raise AssertionError(DOCUMENT_STRUCTURE_ERROR) from None
                    if cls._contains_surrogate(key):
                        raise AssertionError(DOCUMENT_UNICODE_ERRORS[name]) from None
                    schedule_and_visit(item, depth + 1)
            elif current_type is list:
                if len(current) > MAX_DOCUMENT_COLLECTION_ITEMS:
                    raise AssertionError(DOCUMENT_STRUCTURE_ERROR) from None
                for index in range(len(current)):
                    schedule_and_visit(current[index], depth + 1)

        def schedule_and_visit(child: object, depth: int) -> None:
            nonlocal scheduled_nodes
            child_type = type(child)
            if child_type not in allowed_types:
                raise AssertionError(DOCUMENT_MODEL_ERROR) from None
            if depth > MAX_DOCUMENT_DEPTH or scheduled_nodes >= MAX_DOCUMENT_NODES:
                raise AssertionError(DOCUMENT_STRUCTURE_ERROR) from None
            if child_type in (dict, list):
                identity = id(child)
                if identity in seen_containers:
                    raise AssertionError(DOCUMENT_GRAPH_ERROR) from None
                seen_containers.add(identity)
            scheduled_nodes += 1
            visit(child, depth)

        visit(value, 0)

        try:
            for text in cls._iter_document_strings(value):
                cls._utf8_text_size(text)
        except UnicodeEncodeError:
            raise AssertionError(DOCUMENT_UNICODE_ERRORS[name]) from None

    @classmethod
    def _assert_snapshot_manifest_size(cls, value: object) -> None:
        canonical_size = 1  # The canonical trailing LF.
        try:
            for chunk in cls._canonical_json_chunks(value):
                canonical_size += cls._utf8_text_size(chunk)
                if canonical_size > MAX_SNAPSHOT_MANIFEST_BYTES:
                    raise AssertionError(
                        "snapshot manifest exceeds "
                        f"{MAX_SNAPSHOT_MANIFEST_BYTES} UTF-8 bytes"
                    )
        except UnicodeEncodeError:
            raise AssertionError(
                "snapshot manifest contains invalid Unicode"
            ) from None

    @classmethod
    def _walk(cls, value: object, location: str = "$"):
        if type(value) is dict:
            yield location, value
            for key, item in value.items():
                yield from cls._walk(item, f"{location}/{key}")
        elif type(value) is list:
            for index, item in enumerate(value):
                yield from cls._walk(item, f"{location}/{index}")

    @classmethod
    def _assert_document_valid(
        cls, name: str, value: object, schema: dict[str, object]
    ) -> None:
        cls._assert_document_preflight(name, value)
        if name == "bottle-snapshot.schema.json":
            cls._assert_snapshot_manifest_size(value)
        cls._assert_valid(value, schema, schema)
        if name == "bottle-snapshot.schema.json":
            entries = value["entries"]
            cls._assert_sorted_unique(entries, "path")
            cls._assert_casefold_unique(entry["path"] for entry in entries)
            if value["entryCount"] != len(entries):
                raise AssertionError("snapshot entry count mismatch")
            file_bytes = sum(
                entry["size"] for entry in entries if entry["kind"] == "file"
            )
            if value["totalFileBytes"] != file_bytes:
                raise AssertionError("snapshot byte count mismatch")
        elif name == "bottle-runtime-map.schema.json":
            cls._assert_sorted_unique(value["mappings"], "legacyEngineId")
        elif name == "bottle-migration-plan.schema.json":
            if value["runtimePack"] != value["bottle"]["runtimePack"]:
                raise AssertionError("plan Runtime binding mismatch")
            cls._assert_sorted_unique(value["launchers"], "id")
            cls._assert_sorted_unique(value["bottle"].get("recipes", []), "id")
            for launcher in value["launchers"]:
                if launcher["bottleId"] != value["bottle"]["id"]:
                    raise AssertionError("launcher Bottle binding mismatch")
                cls._assert_sorted_unique(launcher["environment"], "name")
        elif name == "bottle-active-ref.schema.json":
            if value["activePlanDigest"] in value["history"]:
                raise AssertionError(
                    "active plan digest must not appear in history"
                )

    @staticmethod
    def _assert_sorted_unique(records: list[object], key: str) -> None:
        values = [record[key] for record in records]
        if values != sorted(values) or len(values) != len(set(values)):
            raise AssertionError(f"records are not sorted and unique by {key}")

    @staticmethod
    def _assert_casefold_unique(paths) -> None:
        folded = [unicodedata.normalize("NFC", path.casefold()) for path in paths]
        if len(folded) != len(set(folded)):
            raise AssertionError("paths collide after Unicode case folding")

    @classmethod
    def _assert_portable_path(cls, value: str) -> None:
        if len(value) > MAX_DOCUMENT_SCALAR_CHARACTERS:
            raise AssertionError("path exceeds the UTF-8 byte limit")
        try:
            encoded_size = cls._utf8_text_size(value)
        except UnicodeEncodeError:
            raise AssertionError("path is not valid Unicode") from None
        if encoded_size > 4096:
            raise AssertionError("path exceeds the UTF-8 byte limit")
        if unicodedata.normalize("NFC", value) != value:
            raise AssertionError("path is not NFC")

        components = value.split("/")
        if not 1 <= len(components) <= 128:
            raise AssertionError("path depth is invalid")
        serial_suffixes = tuple(str(index) for index in range(1, 10)) + (
            "¹",
            "²",
            "³",
        )
        reserved = {
            "con",
            "prn",
            "aux",
            "nul",
            "conin$",
            "conout$",
            *(f"com{suffix}" for suffix in serial_suffixes),
            *(f"lpt{suffix}" for suffix in serial_suffixes),
        }
        forbidden = set('<>:"\\|?*')
        for component in components:
            if not component or component in (".", ".."):
                raise AssertionError("path component is ambiguous")
            if cls._utf8_text_size(component) > 255:
                raise AssertionError("path component exceeds the UTF-8 byte limit")
            if component.endswith((".", " ")):
                raise AssertionError("path component has an ambiguous suffix")
            if any(
                character in forbidden
                or unicodedata.category(character).startswith("C")
                for character in component
            ):
                raise AssertionError("path component contains an unsafe scalar")
            device_stem = component.split(".", 1)[0].rstrip(" ").casefold()
            if device_stem in reserved:
                raise AssertionError("path component is a reserved device name")

    @staticmethod
    def _assert_rfc3339(value: str) -> None:
        if not 20 <= len(value) <= MAX_DOCUMENT_SCALAR_CHARACTERS:
            raise AssertionError("RFC 3339 timestamp is invalid")
        match = re.fullmatch(
            r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})"
            r"[Tt](?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
            r"(?:\.[0-9]+)?(?P<timezone>[Zz]|[+-][0-9]{2}:[0-9]{2})",
            value,
        )
        if match is None:
            raise AssertionError("RFC 3339 timestamp is invalid")

        year, month, day, hour, minute, second = (
            int(match[name])
            for name in ("year", "month", "day", "hour", "minute", "second")
        )
        leap_year = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        days_in_month = {
            1: 31,
            2: 29 if leap_year else 28,
            3: 31,
            4: 30,
            5: 31,
            6: 30,
            7: 31,
            8: 31,
            9: 30,
            10: 31,
            11: 30,
            12: 31,
        }.get(month)
        if (
            days_in_month is None
            or not 1 <= day <= days_in_month
            or hour > 23
            or minute > 59
            or second > 60
        ):
            raise AssertionError("RFC 3339 timestamp is invalid")

        timezone = match["timezone"]
        timezone_offset = 0
        if timezone not in ("Z", "z"):
            offset_hour = int(timezone[1:3])
            offset_minute = int(timezone[4:6])
            if offset_hour > 23 or offset_minute > 59:
                raise AssertionError("RFC 3339 timestamp is invalid")
            timezone_offset = offset_hour * 60 + offset_minute
            if timezone[0] == "-":
                timezone_offset = -timezone_offset

        if second < 60:
            return
        utc_day_delta, utc_minute = divmod(
            hour * 60 + minute - timezone_offset, 24 * 60
        )
        if utc_minute != 23 * 60 + 59 or (
            utc_day_delta,
            month,
            day,
        ) not in {
            (0, 6, 30),
            (0, 12, 31),
            (-1, 7, 1),
            (-1, 1, 1),
        }:
            raise AssertionError("RFC 3339 timestamp is invalid")

    @classmethod
    def _assert_valid(
        cls,
        value: object,
        schema: dict[str, object],
        root: dict[str, object],
    ) -> None:
        reference = schema.get("$ref")
        if reference is not None:
            if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
                raise AssertionError("only local schema references are supported")
            target = root["$defs"][reference.removeprefix("#/$defs/")]
            cls._assert_valid(value, target, root)
            return

        one_of = schema.get("oneOf")
        if one_of is not None:
            matches = sum(cls._matches(value, branch, root) for branch in one_of)
            if matches != 1:
                raise AssertionError("oneOf must match exactly one branch")
            return

        if "const" in schema and not cls._json_equal(value, schema["const"]):
            raise AssertionError("const mismatch")
        if "enum" in schema and not any(
            cls._json_equal(value, member) for member in schema["enum"]
        ):
            raise AssertionError("enum mismatch")

        declared_type = schema.get("type")
        if declared_type is not None and not cls._matches_type(value, declared_type):
            raise AssertionError("type mismatch")

        if schema is root.get("$defs", {}).get("relativePath"):
            cls._assert_portable_path(value)
        if schema is root.get("$defs", {}).get("rfc3339"):
            cls._assert_rfc3339(value)

        if type(value) is str:
            if schema.get("format") == "uuid" and re.fullmatch(
                r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
                value,
            ) is None:
                raise AssertionError("UUID format mismatch")
            if len(value) < schema.get("minLength", 0):
                raise AssertionError("string too short")
            if len(value) > schema.get("maxLength", len(value)):
                raise AssertionError("string too long")
            if "pattern" in schema and re.search(schema["pattern"], value) is None:
                raise AssertionError("pattern mismatch")
        elif type(value) is int:
            if value < schema.get("minimum", value):
                raise AssertionError("integer too small")
            if value > schema.get("maximum", value):
                raise AssertionError("integer too large")
        elif type(value) is list:
            if len(value) < schema.get("minItems", 0):
                raise AssertionError("array too short")
            if len(value) > schema.get("maxItems", len(value)):
                raise AssertionError("array too long")
            if isinstance(schema.get("items"), dict):
                for item in value:
                    cls._assert_valid(item, schema["items"], root)
            if schema.get("uniqueItems"):
                rendered = [json.dumps(item, sort_keys=True) for item in value]
                if len(rendered) != len(set(rendered)):
                    raise AssertionError("array items are not unique")
        elif type(value) is dict:
            required = schema.get("required", [])
            if any(key not in value for key in required):
                raise AssertionError("required property missing")
            properties = schema.get("properties", {})
            for key, item in value.items():
                if key not in properties:
                    if schema.get("additionalProperties") is False:
                        raise AssertionError("additional property forbidden")
                    continue
                cls._assert_valid(item, properties[key], root)

    @classmethod
    def _matches(
        cls, value: object, schema: dict[str, object], root: dict[str, object]
    ) -> bool:
        try:
            cls._assert_valid(value, schema, root)
        except AssertionError:
            return False
        return True

    @staticmethod
    def _matches_type(value: object, declared: object) -> bool:
        return {
            "object": type(value) is dict,
            "array": type(value) is list,
            "string": type(value) is str,
            "integer": type(value) is int,
            "boolean": type(value) is bool,
            "null": value is None,
        }.get(declared, False)

    @staticmethod
    def _json_equal(left: object, right: object) -> bool:
        if type(left) is not type(right):
            return False
        return left == right

    @staticmethod
    def _instances() -> dict[str, dict[str, object]]:
        bottle = {
            "schemaVersion": "1",
            "id": "bottle-1",
            "name": "Example Bottle",
            "guest": {"windowsVersion": "win10", "architecture": "x86_64"},
            "runtimePack": {"id": "runtime-preview", "digest": DIGEST_A},
            "recipes": [],
            "storage": {"layoutVersion": 1, "state": "ready"},
            "createdAt": "2026-08-08T00:00:00Z",
            "updatedAt": "2026-08-08T00:00:01Z",
        }
        return {
            "bottle-snapshot.schema.json": {
                "schemaVersion": "1",
                "legacyFormat": "macwin-bottle-v1",
                "bottleId": "bottle-1",
                "entries": [
                    {"path": "drive_c/Public", "kind": "directory"},
                    {
                        "path": "drive_c/Public/example.txt",
                        "kind": "file",
                        "size": 15,
                        "digest": DIGEST_A,
                    },
                    {
                        "path": "example-link",
                        "kind": "link",
                        "target": "drive_c/Public/example.txt",
                    },
                    {
                        "path": "manifest.json",
                        "kind": "file",
                        "size": 100,
                        "digest": DIGEST_B,
                    },
                ],
                "entryCount": 4,
                "totalFileBytes": 115,
            },
            "bottle-runtime-map.schema.json": {
                "schemaVersion": "1",
                "mappings": [
                    {
                        "legacyEngineId": "wine-9",
                        "runtimePackId": "runtime-preview",
                        "runtimePackDigest": DIGEST_A,
                    }
                ],
            },
            "bottle-migration-plan.schema.json": {
                "schemaVersion": "1",
                "snapshotDigest": DIGEST_B,
                "legacyFormat": "macwin-bottle-v1",
                "legacyEngineId": "wine-9",
                "bottle": bottle,
                "bottleDigest": DIGEST_B,
                "runtimePack": {"id": "runtime-preview", "digest": DIGEST_A},
                "launchers": [
                    {
                        "id": "launcher-1",
                        "appId": "app-1",
                        "bottleId": "bottle-1",
                        "displayName": "Example",
                        "executable": "drive_c/Example/example.exe",
                        "arguments": ["--safe"],
                        "iconPath": "icons/example.png",
                        "environment": [{"name": "LANG", "value": "en_US.UTF-8"}],
                        "showInHome": True,
                    }
                ],
                "diagnostics": [],
                "planDigest": DIGEST_A,
            },
            "bottle-active-ref.schema.json": {
                "schemaVersion": "1",
                "bottleId": "bottle-1",
                "activePlanDigest": DIGEST_A,
                "history": [DIGEST_B],
            },
        }


class BottleMigrationGoldenTests(unittest.TestCase):
    """Independent parity checks for the representative Bottle fixtures.

    These checks intentionally derive their expected values from the closed
    legacy JSON rather than asking Rust to serialize an expected object.  The
    Rust planning test consumes the same checked-in bytes, while this oracle
    independently seals the source projection and every golden digest.
    """

    FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "bottle-migration"
    CASES = ("win64", "win32")
    GOLDEN_DIGESTS = {
        "win64-legacy-planning.json": "sha256:664ed33a9a5743a5d9367c9ac628309fb958e95764630d50c197b126c86bd8b2",
        "win64-migration-plan.json": "sha256:4be176308c112323f01fe6b21e440d06b2ae828c4d8c2cefb93cc053402a57b4",
        "win64-launch-plan.json": "sha256:e9477955494b6469397a5b1651355b5fd876d7b0814f720243aeee55307373ec",
        "win32-legacy-planning.json": "sha256:4db891c9b1524fc7cab947e7cb331d42a9a4067e2b53c849e8c8ef600b4fefe7",
        "win32-migration-plan.json": "sha256:1a7c47bb3491431c9750288e67d85acf8a3d92e854b9afe8646d8a81e044d321",
        "win32-launch-plan.json": "sha256:041c16b7aa1040395e685db817c2360b57208d8c5d502bec843ee7944845335d",
    }
    RUNTIME_PACK_ID = "fixture-runtime"
    RUNTIME_PACK_DIGEST = (
        "sha256:b7e18e933c0a51f6f1ec387862793e5d22cc2edb7e23c114449ea98357d717af"
    )
    RUNTIME_MAP_DIGEST = "sha256:c0fedd9cfa46eee8c0f341c744dc82fead8c05b950b9a25bf13454324c664251"
    RUNTIME_MAP_BYTES = 237
    LAUNCH_REQUEST_IDS = {
        "bottle-win64": "018fe3cb-9d12-7b52-b334-1cce0e857fc9",
        "bottle-win32": "018fe3cb-9d12-7b52-b334-1cce0e857fca",
    }
    FIXTURE_FILE_EVIDENCE = {
        "win64/drive_c/Public/example.txt": (
            21,
            "sha256:bf3e5fba8bf05ea8ac96e264263ac896c31d7d6b4158d32b1aecf3b6d334864e",
        ),
        "win64/manifest.json": (
            1131,
            "sha256:354a64db465bd24939190cab5d3f994ca8a810975ca25c38d1d83ac28ce2e708",
        ),
        "win32/drive_c/Public/example.txt": (
            21,
            "sha256:bfbf39f393a9f6377038a9a9c84d55712c0ab684bdad24037ec5485cf5cb7303",
        ),
        "win32/manifest.json": (
            537,
            "sha256:80fd43df02519025556ecf8ba6c679fbcaa61c83e79b2ed090ed91c0528f30f0",
        ),
    }

    def test_fixture_bytes_and_snapshot_counts_are_literal(self) -> None:
        for relative, (size, digest) in self.FIXTURE_FILE_EVIDENCE.items():
            with self.subTest(fixture=relative):
                raw = (self.FIXTURE_ROOT / relative).read_bytes()
                self.assertEqual(len(raw), size)
                self.assertEqual(self._digest(raw), digest)
        self.assertEqual(
            self._snapshot_projection(self._load_json(Path("win64") / "manifest.json")),
            {
                "digest": "sha256:672021ed04ed3e53eff0df940e214bb580bb1690506440867666cd8370288c35",
                "entryCount": 4,
                "totalFileBytes": 1152,
            },
        )
        self.assertEqual(
            self._snapshot_projection(self._load_json(Path("win32") / "manifest.json")),
            {
                "digest": "sha256:7a2661322918a821a597d0ccfd1736e8c9f490d6bf41e4f1778c74a121e37523",
                "entryCount": 4,
                "totalFileBytes": 558,
            },
        )

    def test_representative_fixtures_and_goldens_have_independent_parity(self) -> None:
        for case in self.CASES:
            with self.subTest(case=case):
                manifest = self._load_json(Path(case) / "manifest.json")
                runtime_map = self._load_json(Path("runtime-map.json"))
                self._assert_runtime_map(runtime_map)
                expected = self._legacy_projection(manifest, runtime_map)
                legacy = self._load_golden(f"{case}-legacy-planning.json")
                self.assertEqual(legacy, expected)

                plan = self._load_golden(f"{case}-migration-plan.json")
                self._assert_migration_plan(manifest, runtime_map, plan)

                launch = self._load_golden(f"{case}-launch-plan.json")
                self._assert_launch_plan(manifest, runtime_map, launch)

    def test_literal_golden_digests_are_sealed(self) -> None:
        for name, expected_digest in self.GOLDEN_DIGESTS.items():
            with self.subTest(golden=name):
                self.assertRegex(expected_digest, r"^sha256:[0-9a-f]{64}$")
                raw = (self.FIXTURE_ROOT / "goldens" / name).read_bytes()
                self.assertEqual(raw, self._pretty_json_bytes(json.loads(raw)))
                self.assertEqual(self._digest(raw), expected_digest)

    def test_runtime_map_is_literal_and_self_consistent_forgery_is_rejected(self) -> None:
        raw = (self.FIXTURE_ROOT / "runtime-map.json").read_bytes()
        runtime_map = self._load_json(Path("runtime-map.json"))
        self.assertEqual(len(raw), self.RUNTIME_MAP_BYTES)
        self.assertEqual(self._digest(raw), self.RUNTIME_MAP_DIGEST)
        forged = copy.deepcopy(runtime_map)
        forged["mappings"].append(
            {
                "legacyEngineId": "wine-10",
                "runtimePackId": self.RUNTIME_PACK_ID,
                "runtimePackDigest": self.RUNTIME_PACK_DIGEST,
            }
        )
        with self.assertRaises(AssertionError):
            self._assert_runtime_map(forged)

    def test_independent_oracle_rejects_self_consistent_forgery(self) -> None:
        manifest = self._load_json(Path("win64") / "manifest.json")
        runtime_map = self._load_json(Path("runtime-map.json"))
        plan = self._load_golden("win64-migration-plan.json")
        for mutate in (
            self._mutate_launcher,
            self._mutate_runtime_digest,
            self._mutate_environment,
            self._mutate_bottle_storage,
            self._mutate_bottle_recipes,
        ):
            with self.subTest(mutator=mutate.__name__):
                forged = copy.deepcopy(plan)
                mutate(forged)
                forged["planDigest"] = self._unsigned_plan_digest(forged)
                with self.assertRaises(AssertionError):
                    self._assert_migration_plan(manifest, runtime_map, forged)

    def test_independent_oracle_rejects_launch_projection_forgery(self) -> None:
        manifest = self._load_json(Path("win64") / "manifest.json")
        runtime_map = self._load_json(Path("runtime-map.json"))
        plan = self._load_golden("win64-migration-plan.json")
        launch = self._load_golden("win64-launch-plan.json")
        mutators = (
            self._mutate_launch_environment,
            self._mutate_launch_executable,
            self._mutate_launch_request_id,
            self._mutate_launch_translator,
            self._mutate_launch_graphics,
            self._mutate_launch_lifecycle,
            self._mutate_launch_trace,
        )
        self._assert_migration_plan(manifest, runtime_map, plan)
        for mutate in mutators:
            with self.subTest(mutator=mutate.__name__):
                forged = copy.deepcopy(launch)
                mutate(forged)
                with self.assertRaises(AssertionError):
                    self._assert_launch_plan(manifest, runtime_map, forged)

    def test_launch_oracle_rejects_synchronized_runtime_binding_forge(self) -> None:
        manifest = self._load_json(Path("win64") / "manifest.json")
        runtime_map = self._load_json(Path("runtime-map.json"))
        plan = self._load_golden("win64-migration-plan.json")
        launch = self._load_golden("win64-launch-plan.json")
        forged_plan = copy.deepcopy(plan)
        forged_runtime = {
            "id": "forged-runtime",
            "digest": "sha256:" + "a" * 64,
        }
        forged_plan["runtimePack"] = forged_runtime
        forged_plan["bottle"]["runtimePack"] = forged_runtime
        forged_launch = copy.deepcopy(launch)
        forged_launch["runtime"] = {
            "provider": "wine",
            "packId": forged_runtime["id"],
            "packDigest": forged_runtime["digest"],
        }
        with self.assertRaises(AssertionError):
            self._assert_launch_plan(manifest, runtime_map, forged_launch)

    def test_launch_schema_rejects_malformed_request_id_format(self) -> None:
        launch = self._load_golden("win64-launch-plan.json")
        launch["requestId"] = "not-a-uuid"
        with self.assertRaises(AssertionError):
            self._assert_valid(launch, self._launch_schema())

    def _load_json(self, relative: Path) -> dict[str, object]:
        raw = (self.FIXTURE_ROOT / relative).read_bytes()
        self.assertEqual(raw, self._pretty_json_bytes(json.loads(raw)))
        return json.loads(raw)

    def _load_golden(self, name: str) -> dict[str, object]:
        return self._load_json(Path("goldens") / name)

    def _assert_runtime_map(self, runtime_map: dict[str, object]) -> None:
        self._assert_valid(runtime_map, self._schema("bottle-runtime-map.schema.json"))
        self.assertEqual(
            runtime_map,
            {
                "schemaVersion": "1",
                "mappings": [
                    {
                        "legacyEngineId": "wine-9",
                        "runtimePackId": self.RUNTIME_PACK_ID,
                        "runtimePackDigest": self.RUNTIME_PACK_DIGEST,
                    }
                ],
            },
        )

    @staticmethod
    def _pretty_json_bytes(value: object) -> bytes:
        return (
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n"
        ).encode("utf-8")

    @staticmethod
    def _canonical_bytes(value: object) -> bytes:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @classmethod
    def _digest(cls, value: bytes) -> str:
        import hashlib

        return "sha256:" + hashlib.sha256(value).hexdigest()

    @classmethod
    def _legacy_projection(
        cls, manifest: dict[str, object], runtime_map: dict[str, object]
    ) -> dict[str, object]:
        if set(manifest) != {
            "id",
            "name",
            "windowsVersion",
            "arch",
            "engineId",
            "envOverrides",
            "installedApps",
            "createdAt",
            "updatedAt",
        }:
            raise AssertionError("legacy fixture fields are not closed")
        mapping = next(
            item
            for item in runtime_map["mappings"]
            if item["legacyEngineId"] == manifest["engineId"]
        )
        if mapping["runtimePackId"] != cls.RUNTIME_PACK_ID:
            raise AssertionError("legacy fixture Runtime Pack ID drifted")
        if mapping["runtimePackDigest"] != cls.RUNTIME_PACK_DIGEST:
            raise AssertionError("legacy fixture Runtime Pack digest drifted")
        bottle_environment = manifest["envOverrides"]
        launchers = []
        for launcher in sorted(manifest["installedApps"], key=lambda item: item["id"]):
            environment = dict(bottle_environment)
            environment.update(launcher["envOverrides"])
            launchers.append(
                {
                    "id": launcher["id"],
                    "appId": launcher["appId"],
                    "bottleId": launcher["bottleId"],
                    "displayName": launcher["displayName"],
                    "executable": launcher["exePath"],
                    "arguments": launcher["args"],
                    **(
                        {"iconPath": launcher["iconPath"]}
                        if launcher.get("iconPath") is not None
                        else {}
                    ),
                    "environment": [
                        {"name": name, "value": value}
                        for name, value in sorted(environment.items())
                    ],
                    "showInHome": launcher["showInHome"],
                }
            )
        return {
            "bottleId": manifest["id"],
            "name": manifest["name"],
            "windowsVersion": manifest["windowsVersion"],
            "architecture": {"win32": "i386", "win64": "x86_64"}[manifest["arch"]],
            "legacyEngineId": manifest["engineId"],
            "runtimePack": {
                "id": mapping["runtimePackId"],
                "digest": mapping["runtimePackDigest"],
            },
            "launchers": launchers,
        }

    def _assert_migration_plan(
        self,
        manifest: dict[str, object],
        runtime_map: dict[str, object],
        plan: dict[str, object],
    ) -> None:
        self._assert_valid(plan, self._schema("bottle-migration-plan.schema.json"))
        self.assertEqual(plan, self._expected_migration_plan(manifest, runtime_map))

    def _expected_migration_plan(
        self,
        manifest: dict[str, object],
        runtime_map: dict[str, object],
    ) -> dict[str, object]:
        expected_legacy = self._legacy_projection(manifest, runtime_map)
        runtime_pack = expected_legacy["runtimePack"]
        bottle = {
            "schemaVersion": "1",
            "id": manifest["id"],
            "name": manifest["name"],
            "guest": {
                "windowsVersion": manifest["windowsVersion"],
                "architecture": expected_legacy["architecture"],
            },
            "runtimePack": runtime_pack,
            "storage": {"layoutVersion": 1, "state": "ready"},
            "createdAt": manifest["createdAt"],
            "updatedAt": manifest["updatedAt"],
        }
        snapshot = self._snapshot_projection(manifest)
        expected = {
            "schemaVersion": "1",
            "snapshotDigest": snapshot["digest"],
            "legacyFormat": "macwin-bottle-v1",
            "legacyEngineId": manifest["engineId"],
            "bottle": bottle,
            "bottleDigest": self._digest(self._canonical_bytes(bottle)),
            "runtimePack": runtime_pack,
            "launchers": expected_legacy["launchers"],
            "diagnostics": [],
            "planDigest": "",
        }
        expected["planDigest"] = self._unsigned_plan_digest(expected)
        return expected

    def _assert_launch_plan(
        self,
        manifest: dict[str, object],
        runtime_map: dict[str, object],
        launch: dict[str, object],
    ) -> None:
        self._assert_valid(launch, self._launch_schema())
        self.assertEqual(launch, self._expected_launch_plan(manifest, runtime_map))

    def _expected_launch_plan(
        self,
        manifest: dict[str, object],
        runtime_map: dict[str, object],
    ) -> dict[str, object]:
        launcher = sorted(manifest["installedApps"], key=lambda item: item["id"])[0]
        environment = dict(manifest["envOverrides"])
        environment.update(launcher["envOverrides"])
        runtime_pack = self._legacy_projection(manifest, runtime_map)["runtimePack"]
        return {
            "schemaVersion": "1",
            "requestId": self.LAUNCH_REQUEST_IDS[manifest["id"]],
            "runtime": {
                "provider": "wine",
                "packId": runtime_pack["id"],
                "packDigest": runtime_pack["digest"],
            },
            "translator": {"provider": "native", "version": "fixture-preview"},
            "graphics": {
                "backend": "wined3d",
                "version": "fixture-preview",
                "options": {},
            },
            "process": {
                "executable": "/compatforge/runtime/bin/wine",
                "arguments": [launcher["exePath"], *launcher["args"]],
                "environment": environment,
                "workingDirectory": f"/compatforge/bottles/{manifest['id']}/prefix",
            },
            "sandbox": {
                "profile": "strict",
                "network": "deny",
                "allowDevices": [],
            },
            "lifecycle": {
                "terminationGraceMilliseconds": 3000,
                "maximumRuntimeMilliseconds": 600000,
            },
            "decisionTrace": [
                "legacy Bottle launcher mapped to verified preview Runtime Pack",
                "environment merge uses launcher override precedence",
            ],
        }

    @staticmethod
    def _mutate_launch_environment(launch: dict[str, object]) -> None:
        launch["process"]["environment"]["SHARED"] = "forged"

    @staticmethod
    def _mutate_launch_executable(launch: dict[str, object]) -> None:
        launch["process"]["executable"] = "/forged/wine"

    @staticmethod
    def _mutate_launch_request_id(launch: dict[str, object]) -> None:
        launch["requestId"] = "not-a-uuid"

    @staticmethod
    def _mutate_launch_translator(launch: dict[str, object]) -> None:
        launch["translator"]["version"] = "forged"

    @staticmethod
    def _mutate_launch_graphics(launch: dict[str, object]) -> None:
        launch["graphics"]["backend"] = "dxvk"

    @staticmethod
    def _mutate_launch_lifecycle(launch: dict[str, object]) -> None:
        launch["lifecycle"]["terminationGraceMilliseconds"] = 4000

    @staticmethod
    def _mutate_launch_trace(launch: dict[str, object]) -> None:
        launch["decisionTrace"].append("forged")

    def _snapshot_projection(self, manifest: dict[str, object]) -> dict[str, object]:
        case = "win64" if manifest["arch"] == "win64" else "win32"
        root = self.FIXTURE_ROOT / case
        entries = []
        total = 0
        for path in sorted(
            candidate.relative_to(root).as_posix()
            for candidate in root.rglob("*")
            if candidate.is_file() or candidate.is_dir()
        ):
            candidate = root / path
            if candidate.is_dir():
                entries.append({"kind": "directory", "path": path})
                continue
            data = candidate.read_bytes()
            entries.append(
                {
                    "digest": self._digest(data),
                    "kind": "file",
                    "path": path,
                    "size": len(data),
                }
            )
            total += len(data)
        snapshot = {
            "bottleId": manifest["id"],
            "entries": entries,
            "entryCount": len(entries),
            "legacyFormat": "macwin-bottle-v1",
            "schemaVersion": "1",
            "totalFileBytes": total,
        }
        # Snapshot seals use the streaming renderer's fixed member order.
        return {
            "digest": self._digest(self._snapshot_compact_bytes(snapshot)),
            "entryCount": len(entries),
            "totalFileBytes": total,
        }

    @staticmethod
    def _snapshot_compact_bytes(snapshot: dict[str, object]) -> bytes:
        # json.dumps preserves insertion order, matching snapshot.rs.
        return json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    def _unsigned_plan_digest(self, plan: dict[str, object]) -> str:
        unsigned = copy.deepcopy(plan)
        unsigned.pop("planDigest", None)
        return self._digest(self._canonical_bytes(unsigned))

    @staticmethod
    def _schema(name: str) -> dict[str, object]:
        return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))

    @staticmethod
    def _launch_schema() -> dict[str, object]:
        return json.loads((ROOT / "schemas" / "launch-plan.schema.json").read_text(encoding="utf-8"))

    @staticmethod
    def _assert_valid(value: object, schema: dict[str, object]) -> None:
        # Reuse the already independent, standard-library schema implementation.
        BottleMigrationSchemaTests._assert_valid(value, schema, schema)

    @staticmethod
    def _mutate_launcher(plan: dict[str, object]) -> None:
        plan["launchers"][0]["displayName"] = "forged"

    @staticmethod
    def _mutate_runtime_digest(plan: dict[str, object]) -> None:
        plan["runtimePack"]["digest"] = "sha256:" + "a" * 64
        plan["bottle"]["runtimePack"]["digest"] = plan["runtimePack"]["digest"]

    @staticmethod
    def _mutate_environment(plan: dict[str, object]) -> None:
        plan["launchers"][0]["environment"][0]["value"] = "forged"

    def _mutate_bottle_storage(self, plan: dict[str, object]) -> None:
        plan["bottle"]["storage"]["layoutVersion"] = 2
        plan["bottleDigest"] = self._digest(self._canonical_bytes(plan["bottle"]))

    def _mutate_bottle_recipes(self, plan: dict[str, object]) -> None:
        plan["bottle"]["recipes"] = []
        plan["bottleDigest"] = self._digest(self._canonical_bytes(plan["bottle"]))


class BottleMigrationCliTests(unittest.TestCase):
    """Black-box checks for the bounded Bottle command group."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._target_dir = Path(tempfile.mkdtemp(prefix="compatforge-cli-target-"))
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(cls._target_dir)
        completed = subprocess.run(
            ["cargo", "build", "-p", "compatforge-cli", "--locked", "--offline"],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        if completed.returncode != 0:
            shutil.rmtree(cls._target_dir, ignore_errors=True)
            raise unittest.SkipTest(
                "compatforge-cli build unavailable: "
                + completed.stderr[-400:]
            )
        executable = "compatforge-cli.exe" if sys.platform == "win32" else "compatforge-cli"
        cls._binary = cls._target_dir / "debug" / executable
        cls._fixture_root = ROOT / "tests" / "fixtures" / "bottle-migration"

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls._target_dir, ignore_errors=True)

    @classmethod
    def _run(cls, *arguments: str, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
        merged = os.environ.copy()
        merged["CARGO_TARGET_DIR"] = str(cls._target_dir)
        if environment:
            merged.update(environment)
        return subprocess.run(
            [str(cls._binary), *arguments],
            cwd=ROOT,
            env=merged,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_help_lists_exactly_the_five_bounded_stages(self) -> None:
        completed = self._run("bottle")
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, b"")
        help_text = completed.stdout.decode("utf-8")
        expected = (
            "compatforge-cli bottle snapshot <store-root> <legacy-bottle-root>",
            "compatforge-cli bottle plan <store-root> <snapshot-digest> <runtime-store-root> <runtime-map.json>",
            "compatforge-cli bottle import <store-root> <snapshot-digest> <runtime-store-root> <runtime-map.json>",
            "compatforge-cli bottle verify <store-root> <bottle-id>",
            "compatforge-cli bottle rollback <store-root> <bottle-id>",
        )
        self.assertEqual(tuple(line for line in expected if line in help_text), expected)

    def test_unknown_or_incomplete_commands_do_not_touch_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-cli-unknown-") as temporary:
            missing = Path(temporary) / "must-not-be-created"
            completed = self._run("bottle", "plan", str(missing))
            self.assertEqual(completed.returncode, 0)
            self.assertEqual(completed.stderr, b"")
            self.assertFalse(missing.exists())

    def test_failure_is_closed_json_exit_one_and_has_empty_stdout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="compatforge-cli-failure-") as temporary:
            absolute_source = str(Path(temporary) / "absent-source")
            completed = self._run("bottle", "snapshot", absolute_source, absolute_source)
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, b"")
            diagnostic = json.loads(completed.stderr)
            self.assertEqual(set(diagnostic), {"code", "message"})
            self.assertIn(
                diagnostic["code"],
                {
                    "unsupported-platform",
                    "source-changed",
                    "unsafe-entry",
                    "invalid-manifest",
                    "runtime-unmapped",
                    "runtime-mismatch",
                    "snapshot-corrupt",
                    "target-collision",
                    "transaction-failed",
                    "rollback-unavailable",
                    "rollback-corrupt",
                },
            )
            self.assertNotIn(absolute_source, completed.stderr.decode("utf-8"))

    def test_snapshot_receipt_is_canonical_bounded_and_repeatable(self) -> None:
        if sys.platform == "darwin":
            self.skipTest("strict macOS mode rejects snapshot creation")
        with tempfile.TemporaryDirectory(prefix="compatforge-cli-snapshot-") as temporary:
            store = Path(temporary) / "store"
            source = self._fixture_root / "win64"
            first = self._run("bottle", "snapshot", str(store), str(source))
            second = self._run("bottle", "snapshot", str(store), str(source))
            self.assertEqual(first.returncode, 0)
            self.assertEqual(second.returncode, 0)
            self.assertEqual(first.stderr, b"")
            self.assertEqual(first.stdout, second.stdout)
            self.assertLessEqual(len(first.stdout), 1024 * 1024)
            receipt = json.loads(first.stdout)
            self.assertEqual(
                list(receipt),
                ["bottleId", "entryCount", "snapshotDigest", "totalFileBytes"],
            )

    def test_snapshot_accepts_a_relative_store_root_with_missing_parent_components(self) -> None:
        if sys.platform == "darwin":
            self.skipTest("strict macOS mode rejects snapshot creation")
        target_root = ROOT / "target"
        target_preexisting = target_root.exists()
        relative_store = Path("target") / f"compatforge-cli-relative-{os.getpid()}-{id(self)}"
        try:
            completed = self._run(
                "bottle",
                "snapshot",
                str(relative_store),
                str(self._fixture_root / "win64"),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
            self.assertEqual(completed.stderr, b"")
            self.assertEqual(
                list(json.loads(completed.stdout)),
                ["bottleId", "entryCount", "snapshotDigest", "totalFileBytes"],
            )
        finally:
            shutil.rmtree(ROOT / relative_store, ignore_errors=True)
            if not target_preexisting and target_root.exists() and not any(target_root.iterdir()):
                target_root.rmdir()

    def test_all_five_subcommands_have_bounded_dispatch(self) -> None:
        commands = (
            ("snapshot", "store", "source"),
            ("plan", "store", "digest", "runtime", "map.json"),
            ("import", "store", "digest", "runtime", "map.json"),
            ("verify", "store", "bottle-1"),
            ("rollback", "store", "bottle-1"),
        )
        for command in commands:
            completed = self._run("bottle", *command)
            self.assertEqual(completed.returncode, 1, command)
            self.assertEqual(completed.stdout, b"", command)
            diagnostic = json.loads(completed.stderr)
            self.assertEqual(set(diagnostic), {"code", "message"}, command)


class BottleMigrationRepositoryTests(unittest.TestCase):
    """Repository-level trust-root and evidence checks for Bottle migration.

    The repository validator is intentionally loaded as a plain Python module
    rather than importing any Rust code.  The temporary-tree tests mutate one
    authenticated input at a time, preserving otherwise valid JSON and
    checking that a self-consistent forgery is still rejected.
    """

    FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "bottle-migration"
    SCHEMA_DIGESTS = {
        "bottle-active-ref.schema.json": "sha256:511fda223f2bde6a271e668ea4faf87835aebeb9a0fb5ab11bab921d7de6d7cb",
        "bottle-migration-plan.schema.json": "sha256:ad2c2eba6031ce04155f4d4b13386318006a23ce6e35885c8808e1ce3c72b562",
        "bottle-runtime-map.schema.json": "sha256:42ce6b2d4bff934e6ed5936aa5f260c17a88ca2c05c671ab01cb4abd8734804c",
        "bottle-snapshot.schema.json": "sha256:6b97f84b1c6740e25e12392e9aa430c2f4d6fb09d7e85c82ffffd2fb1ba8aa97",
    }
    FIXTURE_FILES = {
        "goldens/win32-launch-plan.json": "sha256:041c16b7aa1040395e685db817c2360b57208d8c5d502bec843ee7944845335d",
        "goldens/win32-legacy-planning.json": "sha256:4db891c9b1524fc7cab947e7cb331d42a9a4067e2b53c849e8c8ef600b4fefe7",
        "goldens/win32-migration-plan.json": "sha256:1a7c47bb3491431c9750288e67d85acf8a3d92e854b9afe8646d8a81e044d321",
        "goldens/win64-launch-plan.json": "sha256:e9477955494b6469397a5b1651355b5fd876d7b0814f720243aeee55307373ec",
        "goldens/win64-legacy-planning.json": "sha256:664ed33a9a5743a5d9367c9ac628309fb958e95764630d50c197b126c86bd8b2",
        "goldens/win64-migration-plan.json": "sha256:4be176308c112323f01fe6b21e440d06b2ae828c4d8c2cefb93cc053402a57b4",
        "runtime-map.json": "sha256:c0fedd9cfa46eee8c0f341c744dc82fead8c05b950b9a25bf13454324c664251",
        "win32/drive_c/Public/example.txt": "sha256:bfbf39f393a9f6377038a9a9c84d55712c0ab684bdad24037ec5485cf5cb7303",
        "win32/manifest.json": "sha256:80fd43df02519025556ecf8ba6c679fbcaa61c83e79b2ed090ed91c0528f30f0",
        "win64/drive_c/Public/example.txt": "sha256:bf3e5fba8bf05ea8ac96e264263ac896c31d7d6b4158d32b1aecf3b6d334864e",
        "win64/manifest.json": "sha256:354a64db465bd24939190cab5d3f994ca8a810975ca25c38d1d83ac28ce2e708",
    }
    REQUIRED_FIXTURE_DIRECTORIES = {
        "goldens",
        "win32",
        "win32/drive_c",
        "win32/drive_c/Public",
        "win64",
        "win64/drive_c",
        "win64/drive_c/Public",
    }
    REQUIRED_DOC_SNIPPETS = {
        "docs/testing.md": (
            "compatforge-cli bottle snapshot",
            "compatforge-cli bottle plan",
            "compatforge-cli bottle import",
            "compatforge-cli bottle verify",
            "compatforge-cli bottle rollback",
            "b7e18e933c0a51f6f1ec387862793e5d22cc2edb7e23c114449ea98357d717af",
        ),
        "docs/architecture/component-model.md": (
            "compatforge-bottle",
            "content-addressed",
            "verify-before-switch",
        ),
        "docs/migration/work-breakdown.md": (
            "Bottle Bridge",
            "snapshot",
            "rollback",
        ),
        "docs/implementation/phase-1-bottle-migration.md": (
            "Source is read-only",
            "Runtime Pack",
            "golden",
            "rollback",
        ),
    }
    REQUIRED_CI_SNIPPETS = (
        "tests.test_bottle_migration_contracts",
        "compatforge-bottle",
        "bottle snapshot",
        "bottle plan",
        "bottle import",
        "bottle verify",
        "bottle rollback",
        "b7e18e933c0a51f6f1ec387862793e5d22cc2edb7e23c114449ea98357d717af",
    )

    @classmethod
    def _validator(cls):
        import importlib.util

        path = ROOT / "scripts" / "validate_repository.py"
        spec = importlib.util.spec_from_file_location(
            "compatforge_repository_validator", path
        )
        if spec is None or spec.loader is None:
            raise AssertionError("repository validator cannot be imported")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @classmethod
    def _copy_validation_tree(cls, temporary: Path) -> Path:
        root = temporary / "repo"
        (root / "schemas").mkdir(parents=True)
        (root / "tests" / "fixtures").mkdir(parents=True)
        shutil.copytree(ROOT / "schemas", root / "schemas", dirs_exist_ok=True)
        shutil.copytree(
            cls.FIXTURE_ROOT,
            root / "tests" / "fixtures" / "bottle-migration",
        )
        for relative in (
            "Cargo.toml",
            ".github/workflows/ci.yml",
            "docs/testing.md",
            "docs/migration/work-breakdown.md",
            "docs/architecture/component-model.md",
            "docs/implementation/phase-1-bottle-migration.md",
        ):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        return root

    def test_validator_authenticates_bottle_migration_evidence(self) -> None:
        validator = self._validator()
        self.assertEqual(validator.validate_bottle_migration_repository(), [])
        self.assertEqual(
            validator.BOTTLE_MIGRATION_SCHEMA_SHA256,
            self.SCHEMA_DIGESTS,
        )
        self.assertEqual(
            validator.BOTTLE_MIGRATION_FILE_SHA256,
            self.FIXTURE_FILES,
        )

    def test_validator_binds_workspace_and_ci_commands(self) -> None:
        validator = self._validator()
        self.assertEqual(validator.validate_bottle_migration_repository(), [])
        cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        self.assertIn('"apps/cli"', cargo)
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        for snippet in self.REQUIRED_CI_SNIPPETS:
            self.assertIn(snippet, workflow)
        for relative, snippets in self.REQUIRED_DOC_SNIPPETS.items():
            content = (ROOT / relative).read_text(encoding="utf-8")
            for snippet in snippets:
                self.assertIn(snippet, content)

    def test_validator_rejects_schema_golden_and_fixture_forgery(self) -> None:
        validator = self._validator()
        mutations = ("schema", "golden", "fixture", "extra")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                prefix="compatforge-bottle-validator-"
            ) as temporary:
                root = self._copy_validation_tree(Path(temporary))
                if mutation == "schema":
                    path = root / "schemas" / "bottle-snapshot.schema.json"
                    value = json.loads(path.read_text(encoding="utf-8"))
                    value["$id"] = "https://compatforge.dev/schemas/forged"
                    path.write_bytes(
                        (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
                    )
                elif mutation == "golden":
                    path = root / "tests" / "fixtures" / "bottle-migration" / "goldens" / "win64-migration-plan.json"
                    value = json.loads(path.read_text(encoding="utf-8"))
                    value["bottle"]["name"] = "forged"
                    path.write_bytes(
                        (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
                    )
                elif mutation == "fixture":
                    path = root / "tests" / "fixtures" / "bottle-migration" / "win64" / "manifest.json"
                    value = json.loads(path.read_text(encoding="utf-8"))
                    value["name"] = "forged"
                    path.write_bytes(
                        (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
                    )
                else:
                    (root / "tests" / "fixtures" / "bottle-migration" / "unexpected.txt").write_bytes(b"forged\n")
                self.assertTrue(validator.validate_bottle_migration_repository(root))

    def test_validator_revalidates_after_source_changes_and_rejects_unsafe_tree(self) -> None:
        validator = self._validator()
        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-validator-") as temporary:
            root = self._copy_validation_tree(Path(temporary))
            self.assertEqual(validator.validate_bottle_migration_repository(root), [])
            source = root / "tests" / "fixtures" / "bottle-migration" / "win32" / "drive_c" / "Public" / "example.txt"
            source.write_bytes(source.read_bytes() + b"mutated")
            self.assertTrue(validator.validate_bottle_migration_repository(root))

    def test_validator_revalidates_every_trust_root_leaf_after_document_reads(self) -> None:
        validator = self._validator()
        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-validator-") as temporary:
            root = self._copy_validation_tree(Path(temporary))
            original = validator._bottle_read_regular
            target = (
                root
                / "tests"
                / "fixtures"
                / "bottle-migration"
                / "goldens"
                / "win64-legacy-planning.json"
            )
            mutated = False

            def read_and_mutate(path, maximum=2 * 1024 * 1024):
                nonlocal mutated
                result = original(path, maximum)
                if not mutated and Path(path).name == "testing.md":
                    target.write_bytes(target.read_bytes() + b" ")
                    mutated = True
                return result

            with mock.patch.object(validator, "_bottle_read_regular", side_effect=read_and_mutate):
                self.assertTrue(validator.validate_bottle_migration_repository(root))
            self.assertTrue(mutated)

    def test_validator_rejects_schema_namespace_extras_and_schema_root_links(self) -> None:
        validator = self._validator()
        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-validator-") as temporary:
            root = self._copy_validation_tree(Path(temporary))
            (root / "schemas" / "evil.txt").write_bytes(b"forged")
            self.assertTrue(validator.validate_bottle_migration_repository(root))
        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-validator-") as temporary:
            root = self._copy_validation_tree(Path(temporary))
            shutil.copy2(
                root / "schemas" / "bottle.schema.json",
                root / "schemas" / "forged.schema.json",
            )
            self.assertTrue(validator.validate_bottle_migration_repository(root))
        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-validator-") as temporary:
            root = self._copy_validation_tree(Path(temporary))
            schema_copy = root / "schemas-copy"
            root.joinpath("schemas").rename(schema_copy)
            try:
                os.symlink(schema_copy, root / "schemas", target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"directory symlinks unavailable: {error}")
            self.assertTrue(validator.validate_bottle_migration_repository(root))

    def test_validator_requires_structural_workspace_docs_and_ci_evidence(self) -> None:
        validator = self._validator()
        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-validator-") as temporary:
            root = self._copy_validation_tree(Path(temporary))
            workflow = root / ".github" / "workflows" / "ci.yml"
            workflow.write_text(
                "# " + " ".join(validator.BOTTLE_MIGRATION_CI_SNIPPETS) + "\n",
                encoding="utf-8",
            )
            self.assertTrue(validator.validate_bottle_migration_repository(root))

        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-validator-") as temporary:
            root = self._copy_validation_tree(Path(temporary))
            cargo = root / "Cargo.toml"
            cargo.write_text(
                cargo.read_text(encoding="utf-8").replace(
                    '  "crates/compatforge-bottle",\n',
                    '  # "crates/compatforge-bottle",\n',
                ),
                encoding="utf-8",
            )
            self.assertTrue(validator.validate_bottle_migration_repository(root))

        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-validator-") as temporary:
            root = self._copy_validation_tree(Path(temporary))
            documentation = root / "docs" / "testing.md"
            content = documentation.read_text(encoding="utf-8")
            content = re.sub(
                r"^compatforge-cli bottle .*$",
                lambda match: f"<!-- {match.group(0)} -->",
                content,
                flags=re.MULTILINE,
            )
            documentation.write_text(content, encoding="utf-8")
            self.assertTrue(validator.validate_bottle_migration_repository(root))

    def test_validator_requires_exact_ci_digest_assertions(self) -> None:
        validator = self._validator()
        runtime_verify = (
            "run: cargo run -p compatforge-cli --locked -- runtime verify "
            "target/runtime-store "
            f"{validator.BOTTLE_MIGRATION_RUNTIME_PACK_DIGEST}"
        )
        snapshot_assertion = (
            "          test \"$(python -c 'import json,sys; "
            "print(json.load(sys.stdin)[\"snapshotDigest\"])' "
            "<<<\"$snapshot_receipt\")\" = \\\n"
            f"            \"{validator.BOTTLE_MIGRATION_SNAPSHOT_DIGESTS['win64']}\""
        )
        plan_assertion = (
            "          test \"$(python -c 'import json,sys; "
            "print(json.load(sys.stdin)[\"planDigest\"])' "
            "<<<\"$plan_receipt\")\" = \\\n"
            f"            \"{validator.BOTTLE_MIGRATION_PLAN_DIGESTS['win64']}\""
        )
        mutations = {
            "runtime-echo": (
                runtime_verify,
                f"run: echo {validator.BOTTLE_MIGRATION_RUNTIME_PACK_DIGEST}",
            ),
            "snapshot-echo": (
                snapshot_assertion,
                f"          echo {validator.BOTTLE_MIGRATION_SNAPSHOT_DIGESTS['win64']}",
            ),
            "plan-echo": (
                plan_assertion,
                f"          echo {validator.BOTTLE_MIGRATION_PLAN_DIGESTS['win64']}",
            ),
        }
        for name, (expected, replacement) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="compatforge-bottle-validator-"
            ) as temporary:
                root = self._copy_validation_tree(Path(temporary))
                workflow = root / ".github" / "workflows" / "ci.yml"
                content = workflow.read_text(encoding="utf-8")
                self.assertIn(expected, content)
                workflow.write_text(
                    content.replace(expected, replacement, 1),
                    encoding="utf-8",
                )
                self.assertTrue(validator.validate_bottle_migration_repository(root))

        runtime_install = (
            "run: cargo run -p compatforge-cli --locked -- runtime install "
            "target/runtime-store tests/fixtures/runtime-packs/basic-v1 manifest.json"
        )
        with self.subTest(name="runtime-verify-wrong-step"), tempfile.TemporaryDirectory(
            prefix="compatforge-bottle-validator-"
        ) as temporary:
            root = self._copy_validation_tree(Path(temporary))
            workflow = root / ".github" / "workflows" / "ci.yml"
            content = workflow.read_text(encoding="utf-8")
            self.assertIn(runtime_install, content)
            self.assertIn(runtime_verify, content)
            placeholder = "run: __compatforge_runtime_step_placeholder__"
            content = content.replace(runtime_install, placeholder, 1)
            content = content.replace(runtime_verify, runtime_install, 1)
            content = content.replace(placeholder, runtime_verify, 1)
            workflow.write_text(content, encoding="utf-8")
            self.assertTrue(validator.validate_bottle_migration_repository(root))

        receipt_mutations = {
            "snapshot-wrong-assignment": (
                "          snapshot_receipt=\"$(cargo run",
                "          wrong_receipt=\"$(cargo run",
            ),
            "plan-wrong-assignment": (
                "          plan_receipt=\"$(cargo run",
                "          wrong_receipt=\"$(cargo run",
            ),
            "snapshot-assertion-before-assignment": (
                snapshot_assertion,
                "          snapshot_receipt=\"$(cargo run",
            ),
            "plan-assertion-before-assignment": (
                plan_assertion,
                "          plan_receipt=\"$(cargo run",
            ),
        }
        for name, (expected, replacement) in receipt_mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="compatforge-bottle-validator-"
            ) as temporary:
                root = self._copy_validation_tree(Path(temporary))
                workflow = root / ".github" / "workflows" / "ci.yml"
                content = workflow.read_text(encoding="utf-8")
                self.assertIn(expected, content)
                if name.endswith("before-assignment"):
                    content = content.replace(expected, "", 1)
                    content = content.replace(
                        replacement,
                        f"{expected}\n{replacement}",
                        1,
                    )
                else:
                    content = content.replace(expected, replacement, 1)
                workflow.write_text(content, encoding="utf-8")
                self.assertTrue(validator.validate_bottle_migration_repository(root))

        command_argument_mutations = {
            "snapshot-forged-store": (
                "          snapshot_receipt=\"$(cargo run -p compatforge-cli --locked -- bottle snapshot \\\n"
                "            target/bottle-store tests/fixtures/bottle-migration/win64",
                "          snapshot_receipt=\"$(cargo run -p compatforge-cli --locked -- bottle snapshot \\\n"
                "            target/forged-store tests/fixtures/bottle-migration/win64",
            ),
            "snapshot-wrong-fixture": (
                "            target/bottle-store tests/fixtures/bottle-migration/win64",
                "            target/bottle-store tests/fixtures/bottle-migration/win32",
            ),
            "plan-forged-runtime-map": (
                "            target/runtime-store tests/fixtures/bottle-migration/runtime-map.json",
                "            target/runtime-store tests/fixtures/bottle-migration/forged-map.json",
            ),
        }
        for name, (expected, replacement) in command_argument_mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                prefix="compatforge-bottle-validator-"
            ) as temporary:
                root = self._copy_validation_tree(Path(temporary))
                workflow = root / ".github" / "workflows" / "ci.yml"
                content = workflow.read_text(encoding="utf-8")
                self.assertIn(expected, content)
                workflow.write_text(
                    content.replace(expected, replacement, 1),
                    encoding="utf-8",
                )
                self.assertTrue(validator.validate_bottle_migration_repository(root))

        with self.subTest(name="duplicate-bottle-fixture-step"), tempfile.TemporaryDirectory(
            prefix="compatforge-bottle-validator-"
        ) as temporary:
            root = self._copy_validation_tree(Path(temporary))
            workflow = root / ".github" / "workflows" / "ci.yml"
            content = workflow.read_text(encoding="utf-8")
            start = content.index("      - name: Run Bottle migration fixture sequence\n")
            end = content.index("      - name: Check strict Bottle migration boundary on macOS\n", start)
            fixture_step = content[start:end]
            workflow.write_text(
                content[:end] + fixture_step + content[end:],
                encoding="utf-8",
            )
            self.assertTrue(validator.validate_bottle_migration_repository(root))

    def test_validator_bounds_schema_directory_enumeration_before_sorting(self) -> None:
        validator = self._validator()

        class FakeScanner:
            def __init__(self, entries):
                self.entries = iter(entries)

            def __enter__(self):
                return self.entries

            def __exit__(self, *unused):
                return False

        class FakeEntry:
            def __init__(self, name):
                self.name = name

        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-validator-") as temporary:
            schema_root = Path(temporary) / "schemas"
            schema_root.mkdir()
            entries = [
                FakeEntry(f"forged-{index}.schema.json")
                for index in range(validator.BOTTLE_MIGRATION_MAX_DIRECTORY_ENTRIES + 1)
            ]
            with mock.patch.object(validator.os, "scandir", return_value=FakeScanner(entries)):
                with self.assertRaisesRegex(ValueError, "too many entries"):
                    validator._bottle_schema_names(schema_root)

    def test_validator_bounds_aggregate_trust_root_bytes(self) -> None:
        validator = self._validator()
        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-validator-") as temporary:
            root = self._copy_validation_tree(Path(temporary))
            with mock.patch.object(validator, "BOTTLE_MIGRATION_TRUST_ROOT_MAX_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "trust root exceeds the byte bound"):
                    validator._bottle_capture_trust_root(root)


class BottleMigrationSideEffectTests(unittest.TestCase):
    """Controlled capability mutants for the Bottle runtime boundary.

    These tests deliberately add one forbidden capability to a temporary copy
    of the Bottle implementation.  The repository validator must inspect the
    implementation boundary itself, rather than relying on a reviewer to
    notice a newly introduced network, process, locator, or neighboring-tree
    access.
    """

    @staticmethod
    def _validator():
        import importlib.util

        path = ROOT / "scripts" / "validate_repository.py"
        spec = importlib.util.spec_from_file_location(
            "compatforge_repository_side_effect_validator", path
        )
        if spec is None or spec.loader is None:
            raise AssertionError("repository validator cannot be imported")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _copy_runtime_sources(root: Path) -> None:
        for relative in (
            "platform.rs",
            "snapshot.rs",
            "store.rs",
        ):
            destination = root / "crates" / "compatforge-bottle" / "src" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(
                ROOT / "crates" / "compatforge-bottle" / "src" / relative,
                destination,
            )

    def test_forbidden_capability_mutants_reach_the_validator_guard(self) -> None:
        validator = self._validator()
        repository = BottleMigrationRepositoryTests
        mutants = {
            "network": (
                "platform.rs",
                'std::net::TcpStream::connect("127.0.0.1:9");',
            ),
            "network-alias": (
                "platform.rs",
                'use std::net as n; fn controlled_network_alias() { n::TcpStream::connect("127.0.0.1:9"); }',
            ),
            "network-braced-alias": (
                "platform.rs",
                'use std::{net as n}; fn controlled_network_braced_alias() { n::TcpStream::connect("127.0.0.1:9"); }',
            ),
            "network-spaced-alias": (
                "platform.rs",
                'use std :: net as n; fn controlled_network_spaced_alias() { n::TcpStream::connect("127.0.0.1:9"); }',
            ),
            "network-leading-colon-alias": (
                "platform.rs",
                'use ::std::net as n; fn controlled_network_leading_colon_alias() { n::TcpStream::connect("127.0.0.1:9"); }',
            ),
            "unix-network": (
                "platform.rs",
                'std::os::unix::net::UnixStream::connect("/tmp/forbidden");',
            ),
            "unix-network-alias": (
                "platform.rs",
                'use std::os::unix::net as n; fn controlled_unix_network_alias() { n::UnixStream::connect("/tmp/forbidden"); }',
            ),
            "process": (
                "snapshot.rs",
                "std::process::Command::new(\"sh\");",
            ),
            "process-alias": (
                "snapshot.rs",
                'use std::process as p; fn controlled_process_alias() { p::Command::new("sh"); }',
            ),
            "process-braced-alias": (
                "snapshot.rs",
                'use std::{process::Command as C}; fn controlled_process_braced_alias() { C::new("sh"); }',
            ),
            "process-braced-module-alias": (
                "snapshot.rs",
                'use std::{process as p}; fn controlled_process_braced_module_alias() { p::Command::new("sh"); }',
            ),
            "process-spaced-alias": (
                "snapshot.rs",
                'use std :: process as p; fn controlled_process_spaced_alias() { p::Command::new("sh"); }',
            ),
            "process-newline-alias": (
                "snapshot.rs",
                'use std\n::process as p; fn controlled_process_newline_alias() { p::Command::new("sh"); }',
            ),
            "process-comment-alias": (
                "snapshot.rs",
                'use std/*module*/::process as p; fn controlled_process_comment_alias() { p::Command::new("sh"); }',
            ),
            "process-comment-braced-alias": (
                "snapshot.rs",
                'use std /*module*/ { process as p}; fn controlled_process_comment_braced_alias() { p::Command::new("sh"); }',
            ),
            "process-comment-newline-alias": (
                "snapshot.rs",
                'use std\n/*module*/::process as p; fn controlled_process_comment_newline_alias() { p::Command::new("sh"); }',
            ),
            "process-root-alias": (
                "snapshot.rs",
                'use std as s; fn controlled_process_root_alias() { s::process::Command::new("sh"); }',
            ),
            "process-root-extern-alias": (
                "snapshot.rs",
                'extern crate std as s; fn controlled_process_root_extern_alias() { s::process::Command::new("sh"); }',
            ),
            "process-leading-colon-alias": (
                "snapshot.rs",
                'use ::std::process as p; fn controlled_process_leading_colon_alias() { p::Command::new("sh"); }',
            ),
            "process-leading-colon-root-alias": (
                "snapshot.rs",
                'use ::std as s; fn controlled_process_leading_colon_root_alias() { s::process::Command::new("sh"); }',
            ),
            "process-grouped-root-import-alias": (
                "snapshot.rs",
                'use { /*root*/ std\n as s }; fn controlled_process_grouped_root_import_alias() { s::process::Command::new("sh"); }',
            ),
            "process-leading-grouped-root-import-alias": (
                "snapshot.rs",
                'use ::{std as s}; fn controlled_process_leading_grouped_root_import_alias() { s::process::Command::new("sh"); }',
            ),
            "process-spaced-leading-grouped-root-import-alias": (
                "snapshot.rs",
                'use :: { /*root*/ std\n as s }; fn controlled_process_spaced_leading_grouped_root_import_alias() { s::process::Command::new("sh"); }',
            ),
            "process-pub-leading-grouped-root-import-alias": (
                "snapshot.rs",
                'pub use ::{std as s}; fn controlled_process_pub_leading_grouped_root_import_alias() { s::process::Command::new("sh"); }',
            ),
            "process-leading-root-glob-alias": (
                "snapshot.rs",
                'use ::std::*; fn controlled_process_leading_root_glob_alias() { process::Command::new("sh"); }',
            ),
            "process-root-glob-alias": (
                "snapshot.rs",
                'use std::*; fn controlled_process_root_glob_alias() { process::Command::new("sh"); }',
            ),
            "process-leading-root-grouped-glob-alias": (
                "snapshot.rs",
                'use ::std::{*}; fn controlled_process_leading_root_grouped_glob_alias() { process::Command::new("sh"); }',
            ),
            "process-root-grouped-glob-alias": (
                "snapshot.rs",
                'use std::{*}; fn controlled_process_root_grouped_glob_alias() { process::Command::new("sh"); }',
            ),
            "process-raw-identifier": (
                "snapshot.rs",
                'use std::r#process::Command as C; fn controlled_process_raw_identifier() { C::new("sh"); }',
            ),
            "process-raw-module-alias": (
                "snapshot.rs",
                'use std::r#process as p; fn controlled_process_raw_module_alias() { p::Command::new("sh"); }',
            ),
            "process-raw-grouped-alias": (
                "snapshot.rs",
                'use ::std::r#process::{Command as C}; fn controlled_process_raw_grouped_alias() { C::new("sh"); }',
            ),
            "environment-raw-module-alias": (
                "platform.rs",
                'use std::r#env as e; fn controlled_environment_raw_module_alias() { e::current_dir(); }',
            ),
            "network-raw-module-alias": (
                "platform.rs",
                'use std::r#net as n; fn controlled_network_raw_module_alias() { n::TcpStream::connect("127.0.0.1:9"); }',
            ),
            "macro-capability-expansion": (
                "snapshot.rs",
                'macro_rules! controlled { ($root:ident) => { fn controlled_macro_capability() { $root::process::Command::new("sh"); } } } controlled!(std);',
            ),
            "process-path-braced-alias": (
                "snapshot.rs",
                'use ::std::process::{Command as C}; fn controlled_process_path_braced_alias() { C::new("sh"); }',
            ),
            "process-grouped-root-self-alias": (
                "snapshot.rs",
                'use std::{self as s}; fn controlled_process_grouped_root_self_alias() { s::process::Command::new("sh"); }',
            ),
            "process-spaced-grouped-root-self-alias": (
                "snapshot.rs",
                'use std:: { self as s}; fn controlled_process_spaced_grouped_root_self_alias() { s::process::Command::new("sh"); }',
            ),
            "process-pub-grouped-root-self-alias": (
                "snapshot.rs",
                'pub use std::{self as s}; fn controlled_process_pub_grouped_root_self_alias() { s::process::Command::new("sh"); }',
            ),
            "process-leading-pub-grouped-root-self-alias": (
                "snapshot.rs",
                'pub use ::std::{self as s}; fn controlled_process_leading_pub_grouped_root_self_alias() { s::process::Command::new("sh"); }',
            ),
            "environment-args": (
                "platform.rs",
                "std::env::args();",
            ),
            "environment-vars": (
                "platform.rs",
                "std::env::vars();",
            ),
            "environment-current-exe": (
                "platform.rs",
                "std::env::current_exe();",
            ),
            "environment-current-dir": (
                "platform.rs",
                "std::env::current_dir();",
            ),
            "environment-set-var": (
                "platform.rs",
                'std::env::set_var("X", "Y");',
            ),
            "environment-remove-var": (
                "platform.rs",
                'std::env::remove_var("X");',
            ),
            "environment-home-dir": (
                "platform.rs",
                "std::env::home_dir();",
            ),
            "environment-join-paths": (
                "platform.rs",
                "std::env::join_paths(std::iter::empty::<&str>());",
            ),
            "environment": (
                "platform.rs",
                'std::env::var_os("HOME");',
            ),
            "environment-alias": (
                "platform.rs",
                'use std::env as e; fn controlled_environment_alias() { e::var_os("HOME"); }',
            ),
            "environment-braced-alias": (
                "platform.rs",
                'use std::{env as e}; fn controlled_environment_braced_alias() { e::current_dir(); }',
            ),
            "environment-spaced-braced-alias": (
                "platform.rs",
                'use std::{ env as e}; fn controlled_environment_spaced_braced_alias() { e::current_dir(); }',
            ),
            "environment-leading-colon-alias": (
                "platform.rs",
                'use ::std::env as e; fn controlled_environment_leading_colon_alias() { e::current_dir(); }',
            ),
            "unix-network-grouped-alias": (
                "platform.rs",
                'use std::os::{unix::net as n}; fn controlled_unix_network_grouped_alias() { n::UnixStream::connect("/tmp/forbidden"); }',
            ),
            "temporary-directory": (
                "platform.rs",
                "std::env::temp_dir();",
            ),
            "neighbor": (
                "store.rs",
                'Path::new("../Mac-Win");',
            ),
            "recursive-cleanup": (
                "store.rs",
                'std::fs::remove_dir_all(Path::new("foreign"));',
            ),
        }
        for name, (relative, mutant) in mutants.items():
            with self.subTest(mutant=name), tempfile.TemporaryDirectory(
                prefix="compatforge-bottle-side-effect-"
            ) as temporary:
                root = repository._copy_validation_tree(Path(temporary))
                self._copy_runtime_sources(root)
                path = root / "crates" / "compatforge-bottle" / "src" / relative
                content = path.read_text(encoding="utf-8")
                marker = "#[cfg(all(test"
                if marker in content:
                    content = content.replace(
                        marker,
                        f"// controlled Task 11 mutant\n{mutant}\n{marker}",
                        1,
                    )
                else:
                    content += f"\n// controlled Task 11 mutant\n{mutant}\n"
                path.write_text(content, encoding="utf-8")
                errors = validator.validate_bottle_migration_repository(root)
                self.assertTrue(
                    errors,
                    f"validator accepted controlled {name} capability mutant",
                )

    def test_same_line_after_cfg_test_attribute_is_not_hidden(self) -> None:
        validator = self._validator()
        repository = BottleMigrationRepositoryTests
        mutants = (
            'const CONTROLLED_TEST: () = (); fn controlled_forbidden_capability() { std::net::TcpStream::connect("127.0.0.1:9"); }',
            'fn controlled_test() {} fn controlled_forbidden_capability() { std::net::TcpStream::connect("127.0.0.1:9"); }',
            'mod controlled_test {} fn controlled_forbidden_capability() { std::net::TcpStream::connect("127.0.0.1:9"); }',
            'impl ControlledTest {} fn controlled_forbidden_capability() { std::net::TcpStream::connect("127.0.0.1:9"); }',
        )
        for mutant in mutants:
            with self.subTest(mutant=mutant), tempfile.TemporaryDirectory(
                prefix="compatforge-bottle-side-effect-"
            ) as temporary:
                root = repository._copy_validation_tree(Path(temporary))
                self._copy_runtime_sources(root)
                path = root / "crates" / "compatforge-bottle" / "src" / "platform.rs"
                content = path.read_text(encoding="utf-8")
                content += f"\n#[cfg(test)]\n{mutant}\n"
                path.write_text(content, encoding="utf-8")
                errors = validator.validate_bottle_migration_repository(root)
                self.assertTrue(
                    errors,
                    f"validator hid a production capability after cfg(test): {mutant}",
                )

        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-side-effect-") as temporary:
            root = repository._copy_validation_tree(Path(temporary))
            self._copy_runtime_sources(root)
            path = root / "crates" / "compatforge-bottle" / "src" / "platform.rs"
            content = path.read_text(encoding="utf-8")
            content += (
                "\n#[cfg(test)]\n"
                "fn controlled_test() {\n"
                "} fn controlled_forbidden_capability() { "
                'std::net::TcpStream::connect("127.0.0.1:9"); }\n'
            )
            path.write_text(content, encoding="utf-8")
            errors = validator.validate_bottle_migration_repository(root)
            self.assertTrue(errors, "validator hid a capability after a same-line cfg item close")

    def test_cfg_not_test_mutants_are_not_hidden_from_the_guard(self) -> None:
        validator = self._validator()
        repository = BottleMigrationRepositoryTests
        cfg_mutants = (
            "#[cfg(not(test))]",
            '#[cfg(not(any(test, target_os = "macos")))]',
            '#[cfg(any(test, not(target_os = "macos")))]',
            '#[cfg(all(test = false, target_os = "windows"))]',
        )
        for cfg in cfg_mutants:
            with self.subTest(cfg=cfg), tempfile.TemporaryDirectory(
                prefix="compatforge-bottle-side-effect-"
            ) as temporary:
                root = repository._copy_validation_tree(Path(temporary))
                self._copy_runtime_sources(root)
                path = root / "crates" / "compatforge-bottle" / "src" / "platform.rs"
                content = path.read_text(encoding="utf-8")
                content += (
                    f"\n{cfg}\n"
                    "fn controlled_forbidden_capability() { "
                    'std::net::TcpStream::connect("127.0.0.1:9"); }\n'
                )
                path.write_text(content, encoding="utf-8")
                errors = validator.validate_bottle_migration_repository(root)
                self.assertTrue(errors, f"validator hid a {cfg} capability mutant")

        with tempfile.TemporaryDirectory(prefix="compatforge-bottle-side-effect-") as temporary:
            root = repository._copy_validation_tree(Path(temporary))
            self._copy_runtime_sources(root)
            path = root / "crates" / "compatforge-bottle" / "src" / "platform.rs"
            content = path.read_text(encoding="utf-8")
            content += (
                '\n#[cfg(test)]\n'
                'mod controlled_test { const BRACE: &str = "{"; }\n'
                'fn controlled_forbidden_capability() { '
                'std::net::TcpStream::connect("127.0.0.1:9"); }\n'
            )
            path.write_text(content, encoding="utf-8")
            errors = validator.validate_bottle_migration_repository(root)
            self.assertTrue(errors, "validator hid a brace-in-string capability mutant")

    def test_side_effect_markers_in_comments_and_literals_are_ignored(self) -> None:
        validator = self._validator()
        repository = BottleMigrationRepositoryTests
        non_code_mutants = (
            '// std::net::TcpStream::connect("127.0.0.1:9");',
            '/* std::process::Command::new("sh"); */',
            'const TEXT: &str = "std::env::current_dir std::env::args UnixStream Mac-Win";',
            'const RAW: &str = r#"std::fs::remove_dir_all(std::env::temp_dir())"#;',
            '// Path::new("../Mac-Win");',
            'const NEIGHBOR_TEXT: &str = r#"Path::new("../Mac-Win")"#;',
        )
        for mutant in non_code_mutants:
            with self.subTest(mutant=mutant), tempfile.TemporaryDirectory(
                prefix="compatforge-bottle-side-effect-"
            ) as temporary:
                root = repository._copy_validation_tree(Path(temporary))
                self._copy_runtime_sources(root)
                path = root / "crates" / "compatforge-bottle" / "src" / "platform.rs"
                path.write_text(path.read_text(encoding="utf-8") + f"\n{mutant}\n", encoding="utf-8")
                errors = validator.validate_bottle_migration_repository(root)
                self.assertFalse(errors, f"validator treated non-code marker as capability: {mutant}")



if __name__ == "__main__":
    unittest.main()
