import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("linux_gui_acceptance", Path(__file__).parents[1] / "tools/linux_gui_acceptance.py")
runner = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(runner)


class RebootTests(unittest.TestCase):
    def test_cancel_wait_requires_joined_stream_not_just_terminal_record(self):
        class Client:
            def __init__(self): self.calls = []
            def call(self, operation, payload):
                self.calls.append(operation)
                job = {"id": "job-1", "status": "cancelled"}
                if operation == "jobs.get": return job
                return {"job": job, "streamEnded": len(self.calls) >= 2}
        client = Client()
        runner.Client.wait(client, {"id": "job-1"}, "cancelled", timeout=2)
        self.assertEqual(client.calls, ["jobs.poll", "jobs.poll"])

    def test_requires_new_kernel_identity_equal_selections_and_real_file_hashes(self):
        before = {"bootId": "boot-a", "selectedGenerations": {"7zip": "gen-a"}, "files": {"中文.txt": "a" * 64}}
        after = {**before, "bootId": "boot-b"}
        self.assertTrue(runner.compare_reboot(before, after))
        with self.assertRaises(ValueError): runner.compare_reboot(before, before)
        with self.assertRaises(ValueError): runner.compare_reboot(before, {**after, "files": {"中文.txt": "b" * 64}})
        with self.assertRaises(ValueError): runner.compare_reboot(before, {**after, "selectedGenerations": {"7zip": None}})


if __name__ == "__main__": unittest.main()
