
from collections import defaultdict
from datetime import timedelta

from models import SecurityEvent


def detect_brute_force(
    events: list[SecurityEvent],
    threshold: int = 4,
    window_seconds: int = 60,
) -> list[dict]:
    """Detect repeated failed logins to one account from one IP."""

    attempts = defaultdict(list)

    for event in events:
        if event.event_id != 4625 or event.status.lower() != "failed":
            continue

        key = (event.source_ip, event.username)
        attempts[key].append(event.timestamp)

    alerts = []

    for (source_ip, username), timestamps in attempts.items():
        timestamps.sort()
        left = 0

        for right in range(len(timestamps)):
            while (
                timestamps[right] - timestamps[left]
                > timedelta(seconds=window_seconds)
            ):
                left += 1

            count = right - left + 1

            if count >= threshold:
                alerts.append({
                    "alert_type": "brute_force",
                    "source_ip": source_ip,
                    "username": username,
                    "failed_attempts": count,
                    "window_seconds": window_seconds,
                    "severity": "medium",
                })
                break

    return alerts
