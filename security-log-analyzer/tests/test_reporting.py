
import json
import tempfile
import unittest
from pathlib import Path

from reporting import save_report


class TestReporting(unittest.TestCase):

    def test_report_is_saved_as_json(self):
        alerts = [
            {
                "alert_type": "brute_force",
                "source_ip": "192.168.1.25",
                "username": "john",
                "failed_attempts": 4,
                "severity": "medium",
                "potential_ioc": {
                    "type": "source_ip",
                    "value": "192.168.1.25",
                },
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.json"

            saved_path = save_report(alerts, output_path)

            self.assertTrue(saved_path.exists())

            with saved_path.open("r", encoding="utf-8") as file:
                report = json.load(file)

            self.assertEqual(report["total_alerts"], 1)
            self.assertEqual(len(report["alerts"]), 1)
            self.assertEqual(
                report["alerts"][0]["source_ip"],
                "192.168.1.25",
            )
            self.assertIn("generated_at", report)

    def test_empty_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "empty.json"

            save_report([], output_path)

            with output_path.open("r", encoding="utf-8") as file:
                report = json.load(file)

            self.assertEqual(report["total_alerts"], 0)
            self.assertEqual(report["alerts"], [])


if __name__ == "__main__":
    unittest.main()
