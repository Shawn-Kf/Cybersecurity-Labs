
import json
import ipaddress
from datetime import datetime
from pathlib import Path

from models import SecurityEvent
from analyzer import analyze_events
from reporting import save_report


REQUIRED_FIELDS = {
    "timestamp",
    "event_id",
    "username",
    "source_ip",
    "status",
    "logon_type",
}


def load_events(file_path):
    """Load and validate security events from a JSON file."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Event file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            raw_events = json.load(file)
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in {path}, line {error.lineno}: {error.msg}"
        ) from error

    if not isinstance(raw_events, list):
        raise ValueError("The event file must contain a JSON list.")

    events = []

    for index, event in enumerate(raw_events):
        label = f"Event at index {index}"

        if not isinstance(event, dict):
            raise ValueError(f"{label} must be a JSON object.")

        missing = REQUIRED_FIELDS - event.keys()
        if missing:
            raise ValueError(
                f"{label} is missing fields: {', '.join(sorted(missing))}"
            )

        try:
            timestamp = datetime.fromisoformat(event["timestamp"])

            if isinstance(event["event_id"], bool) or not isinstance(
                event["event_id"], int
            ):
                raise ValueError("event_id must be an integer.")

            if not isinstance(event["username"], str) or not event["username"].strip():
                raise ValueError("username must be a non-empty string.")

            if not isinstance(event["status"], str) or not event["status"].strip():
                raise ValueError("status must be a non-empty string.")

            if isinstance(event["logon_type"], bool) or not isinstance(
                event["logon_type"], int
            ):
                raise ValueError("logon_type must be an integer.")

            ipaddress.ip_address(event["source_ip"])

        except (TypeError, ValueError) as error:
            raise ValueError(f"{label} is invalid: {error}") from error

        events.append(
            SecurityEvent(
                timestamp=timestamp,
                event_id=event["event_id"],
                username=event["username"].strip(),
                source_ip=event["source_ip"],
                status=event["status"].strip(),
                logon_type=event["logon_type"],
            )
        )

    return events


if __name__ == "__main__":
    file_path = "data/authentication_events.json"

    try:
        events = load_events(file_path)
        print(f"Loaded {len(events)} security events.")

        alerts = analyze_events(events)

        print("\n=== SECURITY ANALYSIS REPORT ===")

        if not alerts:
            print("No suspicious patterns detected.")
        else:
            for alert in alerts:
                print(alert)

        report_path = save_report(alerts)
        print(f"\nJSON report saved to: {report_path}")

    except (OSError, ValueError) as error:
        print(f"Error: {error}")
