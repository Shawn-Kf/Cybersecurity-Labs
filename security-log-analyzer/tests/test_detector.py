
import unittest
from datetime import datetime, timedelta

from models import SecurityEvent
from detector import detect_brute_force
from spray_detector import detect_password_spraying


class TestSecurityDetectors(unittest.TestCase):

    def make_event(
        self,
        seconds_ago,
        username="john",
        source_ip="192.168.1.25",
        status="failed",
    ):
        base_time = datetime(2026, 9, 20, 10, 0, 0)

        return SecurityEvent(
            timestamp=base_time + timedelta(seconds=seconds_ago),
            event_id=4625 if status == "failed" else 4624,
            username=username,
            source_ip=source_ip,
            status=status,
            logon_type=3,
        )

    def test_brute_force_detected(self):
        events = [
            self.make_event(0),
            self.make_event(10),
            self.make_event(20),
            self.make_event(30),
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["username"], "john")

    def test_three_attempts_do_not_trigger(self):
        events = [
            self.make_event(0),
            self.make_event(10),
            self.make_event(20),
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(alerts, [])

    def test_attempts_outside_window_do_not_trigger(self):
        events = [
            self.make_event(0),
            self.make_event(90),
            self.make_event(180),
            self.make_event(270),
        ]

        alerts = detect_brute_force(events, window_seconds=60)

        self.assertEqual(alerts, [])

    def test_successful_logins_do_not_trigger_brute_force(self):
        events = [
            self.make_event(0, status="success"),
            self.make_event(10, status="success"),
            self.make_event(20, status="success"),
            self.make_event(30, status="success"),
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(alerts, [])

    def test_password_spraying_detected(self):
        usernames = ["mary", "kofi", "ama", "kwame", "abena"]

        events = [
            self.make_event(
                seconds_ago=i * 5,
                username=username,
                source_ip="192.168.1.75",
            )
            for i, username in enumerate(usernames)
        ]

        alerts = detect_password_spraying(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["account_count"], 5)

    
    def test_spray_attempts_outside_window_do_not_trigger(self):
        usernames = ["mary", "kofi", "ama", "kwame", "abena"]

        events = [
            self.make_event(
                seconds_ago=i * 90,
                username=username,
                source_ip="192.168.1.75",
            )
            for i, username in enumerate(usernames)
        ]

        alerts = detect_password_spraying(
            events,
            threshold=5,
            window_seconds=60,
        )

        self.assertEqual(alerts, [])



if __name__ == "__main__":
    unittest.main()
