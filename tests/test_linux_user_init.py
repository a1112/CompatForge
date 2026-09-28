import importlib.util
import copy
from pathlib import Path
import unittest
import tempfile
import json
import os
import subprocess
import sys
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("linux_user_init", Path(__file__).parents[1] / "tools/linux_user_init.py")
init = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(init)


def template():
    return {"schemaVersion": 1, "cliSha256": "a" * 64, "runtimePackDigest": "sha256:" + "b" * 64,
            "runtime": {"materializedRoot": "/usr", "wine": "bin/wine", "wineserver": "bin/wineserver", "version": "11.14",
                        "wineSha256": "c" * 64, "wineserverSha256": "d" * 64},
            "bottleFont": {"path": "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc", "digest": "sha256:" + "e" * 64, "family": "Noto Sans CJK SC"}}


def debugger_template():
    value = template()
    file = lambda path: {"path": path, "sha256": "sha256:" + "f" * 64}
    value["debuggerRuntime"] = {"schemaVersion": 1, "runtimePackDigest": value["runtimePackDigest"],
                                "worker": file("/usr/lib/compatforge/compatforge-debug-worker.py"),
                                "wine": file("/usr/bin/winedbg"),
                                "winedbgModule": file("/usr/lib/wine/x86_64-windows/winedbg.exe"),
                                "gdb": file("/opt/compatforge/debugger/usr/bin/gdb"),
                                "gdbRoot": "/opt/compatforge/debugger", "sourceMap": {}}
    return value


class TemplateTests(unittest.TestCase):
    def test_interrupted_debugger_refresh_finishes_only_the_expected_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            def run(argv):
                if argv[1] == "local":
                    Path(argv[-1]).write_text('{}')
                    return {"packDigest": template()["runtimePackDigest"]}
                return {"operation": "applications.seed-defaults", "result": {"seeded": True}}
            init.initialize(home, template(), run)
            root = home / ".config/compatforge"
            old_context = (root / "context.json").read_bytes()
            original_replace = os.replace
            calls = 0
            def interrupt_after_service(source, target):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("simulated power loss")
                return original_replace(source, target)
            with patch.object(init.os, "replace", side_effect=interrupt_after_service):
                with self.assertRaises(OSError):
                    init.initialize(home, debugger_template(), run, refresh_debugger=True)
            with self.assertRaises(ValueError):
                init.initialize(home, debugger_template(), run)
            self.assertTrue(init.initialize(home, debugger_template(), run, refresh_debugger=True)["refreshedDebugger"])
            self.assertEqual((root / "context.json").read_bytes(), old_context)
            self.assertEqual(init.initialize(home, debugger_template(), run)["reused"], True)

    def test_debugger_runtime_is_validated_and_explicit_refresh_preserves_context(self):
        init.validate_template(debugger_template())
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            def run(argv):
                if argv[1] == "local":
                    Path(argv[-1]).write_text('{}')
                    return {"packDigest": template()["runtimePackDigest"]}
                return {"operation": "applications.seed-defaults", "result": {"seeded": True}}
            init.initialize(home, template(), run)
            root = home / ".config/compatforge"
            context_bytes = (root / "context.json").read_bytes()
            with self.assertRaises(ValueError): init.initialize(home, debugger_template(), run)
            result = init.initialize(home, debugger_template(), run, refresh_debugger=True)
            self.assertTrue(result["refreshedDebugger"])
            self.assertEqual((root / "context.json").read_bytes(), context_bytes)
            self.assertEqual(json.loads((root / "service.json").read_text())["debuggerRuntime"], debugger_template()["debuggerRuntime"])
            self.assertEqual(init.initialize(home, debugger_template(), run)["reused"], True)
            altered = debugger_template(); altered["debuggerRuntime"]["gdb"]["path"] = "/tmp/gdb"
            with self.assertRaises(ValueError): init.initialize(home, altered, run, refresh_debugger=True)
    def test_preexisting_unowned_staging_context_is_not_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            stage = home / ".config/.compatforge-init-v1"; stage.mkdir(parents=True, mode=0o700)
            personal = stage / "context.json"; personal.write_text("preexisting user file")
            def run(argv):
                if argv[1] == "local":
                    Path(argv[-1]).write_text('{}')
                    return {"packDigest": template()["runtimePackDigest"]}
                return {"operation": "applications.seed-defaults", "result": {"seeded": True}}
            with self.assertRaises(ValueError): init.initialize(home, template(), run)
            self.assertEqual(personal.read_text(), "preexisting user file")

    @unittest.skipUnless(os.name == "posix", "FIFO is POSIX")
    def test_fifo_is_rejected_immediately_and_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fifo"; os.mkfifo(path)
            script = "import sys;sys.path.insert(0,sys.argv[1]);import linux_user_init as i\ntry:i.read_regular(sys.argv[2])\nexcept ValueError:print('rejected')\n"
            result = subprocess.run([sys.executable, "-c", script, str(Path(__file__).parents[1] / "tools"), str(path)],
                                    capture_output=True, timeout=2, text=True)
            self.assertEqual(result.stdout.strip(), "rejected")
            self.assertTrue(path.exists())

    def test_closed_template_rejects_unreviewed_paths_family_and_digest(self):
        init.validate_template(template())
        for key, value in [("extra", True), ("cliSha256", "bad"), ("schemaVersion", True)]:
            altered = template(); altered[key] = value
            with self.assertRaises(ValueError): init.validate_template(altered)
        for key, value in [("wine", "../wine"), ("materializedRoot", "/tmp/runtime"), ("wineserverSha256", "bad")]:
            altered = template(); altered["runtime"][key] = value
            with self.assertRaises(ValueError): init.validate_template(altered)
        altered = template(); altered["bottleFont"]["family"] = "arbitrary"
        with self.assertRaises(ValueError): init.validate_template(altered)

    def test_initialization_is_idempotent_and_preserves_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            calls = []
            def run(argv):
                calls.append(argv)
                if argv[1:4] == ["local", "linux", "context"]:
                    Path(argv[-1]).write_text('{"generatedBy":"existing-cli"}\n')
                    return {"packDigest": template()["runtimePackDigest"]}
                return {"operation": "applications.seed-defaults", "result": {"seeded": True}}
            init.initialize(home, template(), run)
            config = home / ".config/compatforge/context.json"
            self.assertEqual(json.loads(config.read_text())["generatedBy"], "existing-cli")
            config_bytes = config.read_bytes()
            init.initialize(home, template(), run)
            self.assertEqual(config.read_bytes(), config_bytes)
            self.assertEqual(sum(args[1] == "local" for args in calls), 1)
            updated = template(); updated["cliSha256"] = "f" * 64
            init.initialize(home, updated, run)
            self.assertEqual(config.read_bytes(), config_bytes)
            self.assertEqual(sum(args[1] == "local" for args in calls), 1)
            config.write_text("user edit")
            with self.assertRaises(ValueError): init.initialize(home, template(), run)
            self.assertEqual(config.read_text(), "user edit")

    def test_failed_seed_never_publishes_config_and_retry_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            def run(argv):
                if argv[1] == "local":
                    Path(argv[-1]).write_text('{}')
                    return {"packDigest": template()["runtimePackDigest"]}
                raise RuntimeError("interrupted seed")
            with self.assertRaises(RuntimeError): init.initialize(home, template(), run)
            self.assertFalse((home / ".config/compatforge").exists())
            def retry(argv):
                if argv[1] == "local":
                    Path(argv[-1]).write_text('{}')
                    return {"packDigest": template()["runtimePackDigest"]}
                return {"operation": "applications.seed-defaults", "result": {"seeded": True}}
            init.initialize(home, template(), retry)
            self.assertTrue((home / ".config/compatforge/init-v1.json").is_file())

    def test_conflicting_template_never_rewrites_existing_config(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            def run(argv):
                if argv[1] == "local":
                    Path(argv[-1]).write_text('{}')
                    return {"packDigest": template()["runtimePackDigest"]}
                return {"operation": "applications.seed-defaults", "result": {"seeded": True}}
            init.initialize(home, template(), run)
            altered = template(); altered["runtime"]["wineSha256"] = "f" * 64
            with self.assertRaises(ValueError): init.initialize(home, altered, run)


if __name__ == "__main__": unittest.main()
