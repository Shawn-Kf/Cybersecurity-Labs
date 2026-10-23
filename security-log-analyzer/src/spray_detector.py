
from collections import defaultdict
from datetime import timedelta

from models import SecurityEvent


def detect_password_spraying(
    events: list[SecurityEvent],
    threshold: int = 5,
    window_seconds: int = 60,
) -> list[dict]:
    """Detect failed logins against multiple accounts from one IP."""

    events_by_ip = defaultdict(list)

    for event in events:
        if event.event_id != 4625 or event.status.lower() != "failed":
            continue

        events_by_ip[event.source_ip].append(
            (event.timestamp, event.username)
        )

    alerts = []

    for source_ip, attempts in events_by_ip.items():
        attempts.sort(key=lambda item: item[0])

        for right in range(len(attempts)):
            window_start = (
                attempts[right][0] - timedelta(seconds=window_seconds)
            )

            usernames = {
                username
                for timestamp, username in attempts[:right + 1]
                if timestamp >= window_start
            }

            if len(usernames) >= threshold:
                alerts.append({
                    "alert_type": "password_spraying",
                    "source_ip": source_ip,
                    "targeted_accounts": sorted(usernames),
                    "account_count": len(usernames),
                    "window_seconds": window_seconds,
                    "severity": "high",
                })
                break

    return alerts
