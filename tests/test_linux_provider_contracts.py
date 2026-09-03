from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_SCHEMA = ROOT / "schemas" / "linux-provider.schema.json"
BOOTSTRAP_SCHEMA = ROOT / "schemas" / "linux-bootstrap-request.schema.json"


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


if __name__ == "__main__":
    unittest.main()
