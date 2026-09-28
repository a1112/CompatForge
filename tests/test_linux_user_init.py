import importlib.util
import copy
from pathlib import Path
import unittest
import tempfile
import json
import os
import subprocess
import sys

SPEC = importlib.util.spec_from_file_location("linux_user_init", Path(__file__).parents[1] / "tools/linux_user_init.py")
init = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(init)


def template():
    return {"schemaVersion": 1, "cliSha256": "a" * 64, "runtimePackDigest": "sha256:" + "b" * 64,
            "runtime": {"materializedRoot": "/usr", "wine": "bin/wine", "wineserver": "bin/wineserver", "version": "11.14",
                        "wineSha256": "c" * 64, "wineserverSha256": "d" * 64},
            "bottleFont": {"path": "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc", "digest": "sha256:" + "e" * 64, "family": "Noto Sans CJK SC"}}


class TemplateTests(unittest.TestCase):
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
