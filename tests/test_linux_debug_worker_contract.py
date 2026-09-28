import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

WORKER = Path(__file__).parents[1] / "packaging/linux/compatforge-debug-worker.py"
SPEC = importlib.util.spec_from_file_location("compatforge_debug_worker", WORKER)
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


class WorkerContractTests(unittest.TestCase):
    def test_control_ids_are_exact_and_monotonic(self):
        self.assertEqual(worker.request_id({"requestId": 1}, 1), 1)
        for value in [None, True, 0, 2, "1", 2**63]:
            with self.assertRaises(ValueError):
                worker.request_id({"requestId": value}, 1)

    def test_overflow_metadata_never_repeats_unbounded_backend_fields(self):
        huge = {"type": "response", "command": "x" * (worker.MAX - 100),
                "request_seq": 8, "body": {"value": "private"}}
        metadata = worker.oversized_metadata(huge)
        self.assertEqual(metadata, {"type": "response", "command": None, "request_seq": 8})
        self.assertLess(len(json.dumps({"requestId": 2, "oversized": metadata}).encode()), 256)
        self.assertEqual(worker.oversized_metadata({"type": "request", "command": "runInTerminal"}),
                         {"type": "event", "command": None, "request_seq": None})
        self.assertEqual(worker.oversized_metadata({"type": "response", "command": ["bad"]})["command"], None)

    def test_near_limit_dap_body_cannot_overflow_worker_wrapper(self):
        small = {"seq": 1, "type": "event", "event": "output", "body": {"output": "x" * 100}}
        self.assertTrue(worker.response_fits([small]))
        self.assertTrue(worker.response_fits([small, small]))
        near_limit = {"seq": 2, "type": "event", "event": "output",
                      "body": {"output": "x" * (worker.MAX - 200)}}
        self.assertFalse(worker.response_fits([near_limit]))
        self.assertFalse(worker.response_fits([small, near_limit]))

    @unittest.skipUnless(os.name == "posix", "worker pipe uses Linux selectors")
    def test_near_limit_frame_returns_typed_overflow_and_preserves_pipe(self):
        oversized = {"seq": 2, "type": "response", "request_seq": 8,
                     "command": "variables", "success": True,
                     "body": {"variables": [{"name": "large", "value": "x" * (worker.MAX - 300)}]}}
        small = {"seq": 3, "type": "event", "event": "stopped", "body": {"reason": "step"}}
        self.assertFalse(worker.response_fits([oversized]))
        self.assertTrue(worker.response_fits([small]))
        frames = b"".join(
            f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw
            for raw in (json.dumps(item, separators=(",", ":")).encode() for item in (oversized, small))
        )
        with tempfile.TemporaryDirectory() as directory:
            frame_file = Path(directory) / "frames"
            frame_file.write_bytes(frames)
            process = subprocess.Popen([sys.executable, "-c",
                                        "import pathlib,sys,time;sys.stdout.buffer.write(pathlib.Path(sys.argv[1]).read_bytes());"
                                        "sys.stdout.buffer.flush();time.sleep(2)", str(frame_file)],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            try:
                pipe = worker.DapPipe(process)
                with self.assertRaises(worker.OversizedDapResponse) as caught:
                    pipe.drain(1)
                self.assertEqual(caught.exception.message["command"], "variables")
                self.assertEqual(pipe.drain(1), [small])
                self.assertIsNone(process.poll())
            finally:
                process.kill()
                process.wait(timeout=2)
                process.stdin.close()
                process.stdout.close()


if __name__ == "__main__":
    unittest.main()
