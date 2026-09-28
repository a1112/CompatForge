import importlib.util
import tempfile
import unittest
import json
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("build_linux_desktop_bundle", Path(__file__).parents[1] / "tools/build_linux_desktop_bundle.py")
bundle = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(bundle)


class BundleTests(unittest.TestCase):
    def test_closed_bundle_pins_actual_executables_and_has_private_init(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); cli = root / "cli"; lib = root / "lib"
            raw = bytearray(64); raw[:6] = b"\x7fELF\x02\x01"; raw[18:20] = b"\x3e\x00"
            cli.write_bytes(raw); lib.write_bytes(raw + b"lib")
            receipt = bundle.build(cli, lib, "a" * 40, root / "out")
            self.assertEqual(receipt["schemaVersion"], 2)
            self.assertEqual(receipt["sourceCommit"], "a" * 40)
            self.assertEqual(receipt["files"]["usr/libexec/compatforge/user-init"]["mode"], 0o755)
            self.assertEqual(receipt["files"]["usr/lib/compatforge/compatforge-debug-worker.py"]["mode"], 0o755)
            template = json.loads((root / "out/usr/share/compatforge/linux-desktop.json").read_bytes())
            self.assertEqual(template["cliSha256"], receipt["files"]["usr/bin/compatforge-cli"]["sha256"])
            self.assertEqual(template["debuggerRuntime"]["worker"]["sha256"],
                             "sha256:" + receipt["files"]["usr/lib/compatforge/compatforge-debug-worker.py"]["sha256"])
            with self.assertRaises(ValueError): bundle.build(cli, lib, "a" * 40, root / "out")
            cli.write_bytes(b"not ELF")
            with self.assertRaises(ValueError): bundle.build(cli, lib, "a" * 40, root / "invalid")


if __name__ == "__main__": unittest.main()
