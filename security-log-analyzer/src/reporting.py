
import json
from datetime import datetime, timezone
from pathlib import Path


def save_report(alerts, output_path="reports/security_report.json"):
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_alerts": len(alerts),
        "alerts": alerts,
    }

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return output_file
