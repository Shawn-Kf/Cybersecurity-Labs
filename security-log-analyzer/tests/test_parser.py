
import json
import tempfile
import unittest
from pathlib import Path

from parser import load_events


class TestParser(unittest.TestCase):

    def load_from_data(self, data):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "events.json"
            file_path.write_text(json.dumps(data), encoding="utf-8")
            return load_events(file_path)

    def test_missing_required_field(self):
        data = [{
            "timestamp": "2026-09-20T10:01:12",
            "event_id": 4625,
            "username": "alice",
            "source_ip": "192.168.1.50",
            "status": "failed",
            # logon_type intentionally missing
        }]

        with self.assertRaisesRegex(ValueError, "missing fields"):
            self.load_from_data(data)

    def test_invalid_ip_address(self):
        data = [{
            "timestamp": "2026-09-20T10:01:12",
            "event_id": 4625,
            "username": "alice",
            "source_ip": "not-an-ip",
            "status": "failed",
            "logon_type": 3,
        }]

        with self.assertRaisesRegex(ValueError, "invalid"):
            self.load_from_data(data)

    def test_invalid_timestamp(self):
        data = [{
            "timestamp": "not-a-timestamp",
            "event_id": 4625,
            "username": "alice",
            "source_ip": "192.168.1.50",
            "status": "failed",
            "logon_type": 3,
        }]

        with self.assertRaisesRegex(ValueError, "invalid"):
            self.load_from_data(data)

    def test_json_must_be_a_list(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "events.json"
            file_path.write_text('{"event": "not a list"}', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "JSON list"):
                load_events(file_path)


if __name__ == "__main__":
    unittest.main()
