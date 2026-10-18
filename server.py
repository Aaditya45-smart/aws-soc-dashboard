
import json
import os
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit

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
    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = urlsplit(self.path).path

        if route == "/api/events":
            try:
                logs = read_json(BASE_DIR / "security_logs.json", [])
                alerts = read_json(BASE_DIR / "alerts.json", [])
                statuses = read_json(BASE_DIR / "incident_status.json", {})

                high_risk_ips = {
                    alert["source_ip"]
                    for alert in alerts
                    if alert.get("severity") in {"HIGH", "CRITICAL"}
                }

                events = []

                for log in logs:
                    event_id = log.get("event_id", "UNKNOWN")
                    ip = log.get("source_ip", "Unknown")
                    suspicious = ip in high_risk_ips
                    result = log.get("status", "Unknown")

                    events.append({
                        "id": event_id,
                        "type": log.get("event_type", "Unknown"),
                        "source": ip,
                        "username": log.get("username", "Unknown"),
                        "result": result,
                        "severity": (
                            "HIGH" if suspicious
                            else "MEDIUM" if result == "FAILED"
                            else "LOW"
                        ),
                        "status": statuses.get(
                            event_id,
                            "Open" if suspicious else "Closed"
                        )
                    })

                return self.send_json(events)

            except (OSError, ValueError, KeyError, TypeError) as error:
                print("Read error:", error)
                return self.send_json(
                    {"error": "Unable to read incident data"}, 500
                )

        # Publicly serve only the dashboard page.
        if route in {"/", "/index.html"}:
            try:
                page = (BASE_DIR / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)
            except OSError:
                self.send_json({"error": "Dashboard page not found"}, 404)
            return

        # Do not expose Python or JSON files to website visitors.
        return self.send_json({"error": "Not found"}, 404)

    def do_POST(self):
        if urlsplit(self.path).path != "/api/status":
            return self.send_json({"error": "Not found"}, 404)

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 4096:
                return self.send_json({"error": "Invalid request size"}, 400)

            payload = json.loads(self.rfile.read(length))
            event_id = payload.get("id")
            status = payload.get("status")

            if (
                not isinstance(event_id, str)
                or status not in ALLOWED_STATUSES
            ):
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
            return self.send_json(
                {"error": "Unable to update status"}, 500
            )

    def log_message(self, format, *args):
        # Keep normal request logging in Render logs.
        super().log_message(format, *args)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), SOCHandler)

    print(f"SOC Dashboard server running on port {port}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()
