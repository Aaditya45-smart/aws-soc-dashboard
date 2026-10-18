
import json
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ALLOWED_STATUSES = {"Open", "Investigating", "Closed"}


def read_json(path, default):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, data):
    path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8"
    )


class SOCHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/api/events":
            return super().do_GET()

        try:
            logs = read_json(BASE_DIR / "security_logs.json", [])
            alerts = read_json(BASE_DIR / "alerts.json", [])
            statuses = read_json(BASE_DIR / "incident_status.json", {})

            high_risk_ips = {
                alert["source_ip"] for alert in alerts
                if alert.get("severity") in {"HIGH", "CRITICAL"}
            }

            events = []

            for log in logs:
                ip = log.get("source_ip", "Unknown")
                is_suspicious = ip in high_risk_ips
                default_status = "Open" if is_suspicious else "Closed"

                events.append({
                    "id": log.get("event_id", "UNKNOWN"),
                    "type": log.get("event_type", "Unknown"),
                    "source": ip,
                    "username": log.get("username", "Unknown"),
                    "result": log.get("status", "Unknown"),
                    "severity": "HIGH" if is_suspicious else (
                        "MEDIUM" if log.get("status") == "FAILED" else "LOW"
                    ),
                    "status": statuses.get(
                        log.get("event_id"), default_status
                    )
                })

            return self.send_json(events)

        except (OSError, ValueError, KeyError, TypeError) as error:
            print("Read error:", error)
            return self.send_json({"error": "Unable to read incident data"}, 500)

    def do_POST(self):
        if self.path != "/api/status":
            return self.send_json({"error": "Not found"}, 404)

        try:
            length = int(self.headers.get("Content-Length", "0"))

            if length < 1 or length > 4096:
                return self.send_json({"error": "Invalid request size"}, 400)

            payload = json.loads(self.rfile.read(length))
            event_id = payload.get("id")
            status = payload.get("status")

            if not isinstance(event_id, str) or status not in ALLOWED_STATUSES:
                return self.send_json({"error": "Invalid ID or status"}, 400)

            logs = read_json(BASE_DIR / "security_logs.json", [])
            known_ids = {log.get("event_id") for log in logs}

            if event_id not in known_ids:
                return self.send_json({"error": "Event not found"}, 404)

            path = BASE_DIR / "incident_status.json"
            statuses = read_json(path, {})
            statuses[event_id] = status
            write_json(path, statuses)

            return self.send_json({
                "message": "Incident status saved",
                "id": event_id,
                "status": status
            })

        except (OSError, ValueError, TypeError) as error:
            print("Update error:", error)
            return self.send_json({"error": "Unable to update status"}, 500)


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8000), SOCHandler)
    print("SOC Dashboard: http://127.0.0.1:8000")
    print("Local demo server. Do not expose it to the public internet.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()
