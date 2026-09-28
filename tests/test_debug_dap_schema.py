"""Small dependency-free validator for the closed debug.dap schema subset."""

import json
from pathlib import Path
import re
import unittest

SCHEMAS = Path(__file__).parents[1] / "schemas"
SERVICE = json.loads((SCHEMAS / "service-request.schema.json").read_text())
DAP = json.loads((SCHEMAS / "debug-dap-request.schema.json").read_text())
SESSION = json.loads((SCHEMAS / "debug-session-request.schema.json").read_text())


def accepts(schema, value):
    if "$ref" in schema:
        assert schema["$ref"] == "debug-session-request.schema.json#/$defs/handle"
        return accepts(SESSION["$defs"]["handle"], value)
    if "oneOf" in schema:
        return sum(accepts(part, value) for part in schema["oneOf"]) == 1
    if "type" in schema:
        kinds = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        matching = {"object": lambda: type(value) is dict,
                    "string": lambda: type(value) is str,
                    "integer": lambda: type(value) is int,
                    "null": lambda: value is None}
        if not any(matching[kind]() for kind in kinds):
            return False
    if "const" in schema and value != schema["const"]:
        return False
    if "enum" in schema and value not in schema["enum"]:
        return False
    if "minimum" in schema and value < schema["minimum"]:
        return False
    if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
        return False
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        if not set(schema.get("required", [])) <= set(value):
            return False
        if schema.get("additionalProperties") is False and not set(value) <= set(properties):
            return False
        if any(not accepts(properties[key], item) for key, item in value.items() if key in properties):
            return False
    return True


class DebugDapSchemaTests(unittest.TestCase):
    def test_service_operation_references_closed_dap_payload(self):
        self.assertIn("debug.dap", SERVICE["properties"]["operation"]["enum"])
        self.assertTrue(any(branch.get("if", {}).get("properties", {}).get("operation", {}).get("const") == "debug.dap"
                            and branch.get("then", {}).get("properties", {}).get("payload", {}).get("$ref")
                            == "debug-dap-request.schema.json" for branch in SERVICE["allOf"]))

    def test_payload_accepts_poll_and_safe_request_but_rejects_repl_and_foreign_handle(self):
        handle = {"sessionId": "debug-" + "a" * 32, "capability": "b" * 64}
        poll = {"schemaVersion": "1", "handle": handle}
        self.assertTrue(accepts(DAP, poll))
        request = {**poll, "message": {"seq": 1, "type": "request", "command": "stackTrace",
                                     "arguments": {"threadId": 1, "levels": 8}}}
        self.assertTrue(accepts(DAP, request))
        for invalid in [
            {**poll, "message": {**request["message"], "command": "evaluate"}},
            {**poll, "message": {**request["message"], "seq": 0}},
            {**poll, "message": {**request["message"], "type": "response"}},
            {**poll, "handle": {"sessionId": "debug-short", "capability": "b" * 64}},
            {**poll, "env": {"LD_PRELOAD": "/tmp/x"}},
        ]:
            self.assertFalse(accepts(DAP, invalid))


if __name__ == "__main__":
    unittest.main()
