
from detector import detect_brute_force
from spray_detector import detect_password_spraying


def analyze_events(events):
    brute_force_alerts = detect_brute_force(events)
    spray_alerts = detect_password_spraying(events)

    alerts = brute_force_alerts + spray_alerts

    for alert in alerts:
        if alert["alert_type"] == "password_spraying":
            alert["severity"] = "high"
        elif alert["failed_attempts"] >= 10:
            alert["severity"] = "high"
        else:
            alert["severity"] = "medium"

        alert["potential_ioc"] = {
            "type": "source_ip",
            "value": alert["source_ip"],
        }

    return alerts
