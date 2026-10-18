
import json
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent

with open(BASE_DIR / "security_logs.json", encoding="utf-8") as file:
    logs = json.load(file)

# Count failed logins by IP address
failed_by_ip = Counter(
    log.get("source_ip", "Unknown")
    for log in logs
    if log.get("event_type") == "FailedLogin"
    and log.get("status") == "FAILED"
)

alerts = []

for ip, count in failed_by_ip.items():
    if count >= 3:
        alerts.append({
            "alert_id": f"ALERT-{len(alerts) + 1:03d}",
            "alert_type": "Repeated Failed Login",
            "source_ip": ip,
            "failed_attempts": count,
            "severity": "HIGH" if count < 5 else "CRITICAL",
            "status": "OPEN",
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "recommendation": (
                "Review authentication events and verify the activity. "
                "Do not block an IP based on this sample alone."
            )
        })

with open(BASE_DIR / "alerts.json", "w", encoding="utf-8") as file:
    json.dump(alerts, file, indent=4)

print("===== SOC THREAT DETECTION =====")
print(f"Events analyzed: {len(logs)}")
print(f"Alerts generated: {len(alerts)}")

for alert in alerts:
    print(f"\nAlert: {alert['alert_id']}")
    print(f"Type: {alert['alert_type']}")
    print(f"Source IP: {alert['source_ip']}")
    print(f"Failed attempts: {alert['failed_attempts']}")
    print(f"Severity: {alert['severity']}")
    print(f"Status: {alert['status']}")

print("\nReport saved to alerts.json")
