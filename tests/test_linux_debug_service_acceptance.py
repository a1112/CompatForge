from collections import deque
import unittest

from tests.linux_debug_service_acceptance import DapClient


class DapAcceptanceClientTests(unittest.TestCase):
    def test_pause_event_cannot_consume_earlier_attach_stop(self):
        client = DapClient.__new__(DapClient)
        client.events = deque([
            {"seq": 4, "type": "event", "event": "stopped", "body": {"reason": "attach"}},
            {"seq": 42, "type": "event", "event": "stopped", "body": {"reason": "stopped"}},
        ])
        stopped = client.event("stopped", after_seq=40)
        self.assertEqual(stopped["body"]["reason"], "stopped")
        self.assertFalse(client.events)


if __name__ == "__main__":
    unittest.main()
