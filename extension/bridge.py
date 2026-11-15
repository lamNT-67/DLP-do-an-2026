"""Loopback bridge for root /extension/ Chrome/Edge extension and the main Python Agent.
Run: C:\\DLP\\venv\\Scripts\\python.exe bridge.py --agent-dir C:\\DLP\\agent
Lab-only: localhost is not a strong security/authentication boundary.
"""
import argparse
import base64
import binascii
import configparser
import importlib
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "127.0.0.1"
PORT = 18765
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_REQUEST = 2_850_000
REFRESH_SECONDS = 20


class PolicyState:
    def __init__(self, agent_dir):
        sys.path.insert(0, str(agent_dir))
        self.client_module = importlib.import_module("policy_client")
        self.inspector = importlib.import_module("content_inspection")
        self.utils = importlib.import_module("policy_utils")
        config = configparser.ConfigParser()
        if not config.read(str(Path(agent_dir) / "config.ini"), encoding="utf-8"):
            raise RuntimeError("Missing config.ini in Agent directory")
        a = config["agent"]
        if not a.get("api_token", "").strip():
            raise RuntimeError("Agent API token not yet registered; start Agent first")
        self.hostname = a["hostname"]
        self.client = self.client_module.PolicyClient(a["server_url"], self.hostname, a["api_token"])
        self.lock = threading.RLock()
        self.last_refresh = 0
        self.policies = None

    def get_policies(self):
        with self.lock:
            now = time.monotonic()
            if self.policies is None or now - self.last_refresh > REFRESH_SECONDS:
                response = self.client.get_policy()
                self.last_refresh = now
                # Never continue enforcing stale policies after a failed refresh.
                self.policies = response.get("applicable_policies", []) if isinstance(response, dict) else None
            return self.policies

    def inspect(self, data):
        channel = data.get("channel")
        if channel not in ("BROWSER_CHROME", "BROWSER_EDGE"):
            raise ValueError("Invalid browser channel")
        filename = data.get("file_name")
        encoded = data.get("content_base64")
        destination = data.get("destination", "")
        if not isinstance(filename, str) or not filename or len(filename) > 240 or "\x00" in filename:
            raise ValueError("Invalid filename")
        if not isinstance(encoded, str) or len(encoded) > 2_800_000:
            raise ValueError("Invalid content")
        if not isinstance(destination, str) or len(destination) > 255 or not destination.startswith(("http://", "https://")):
            raise ValueError("Invalid destination")
        filename = os.path.basename(filename.replace("\\", "/"))
        if filename in ("", ".", ".."):
            raise ValueError("Invalid basename")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise ValueError("Invalid base64")
        if len(content) > MAX_FILE_BYTES:
            return {"decision": "BLOCK", "reason": "FILE_TOO_LARGE"}

        policies = self.get_policies()
        if policies is None:
            return {"decision": "BLOCK", "reason": "POLICY_UNAVAILABLE"}

        matched = [p for p in policies if channel in (p.get("exit_points") or [])]
        if not matched:
            return {"decision": "ALLOW", "reason": "NOT_GOVERNED"}

        suffix = Path(filename).suffix
        # File scope is checked separately per policy; never merge policies before verdict.
        matching = [p for p in matched if self.utils.file_in_scope(filename, p.get("file_types") or [])]
        if not matching:
            return {"decision": "ALLOW", "reason": "FILE_OUT_OF_SCOPE"}

        # Isolated temporary directory: safe basename and extension for real-type detection.
        with tempfile.TemporaryDirectory(prefix="dlp-browser-") as directory:
            path = os.path.join(directory, "upload" + suffix)
            with open(path, "wb") as stream:
                stream.write(content)
            first_logged = None
            for policy in matching:
                status = {
                    "is_governed": True,
                    "effective_action": policy.get("action", "REPORT_ONLY"),
                    "content_rules": policy.get("content_rules") or [],
                    "file_types": policy.get("file_types") or [],
                    "allowed_files": policy.get("allowed_files") or [],
                    "allowed_locations": policy.get("allowed_locations") or [],
                }
                # Inspect with the real file content, but enforce allowlist by original filename.
                allowed = any(str(f).lower() == filename.lower() or
                              os.path.basename(str(f).replace("\\", "/")).lower() == filename.lower()
                              for f in status["allowed_files"])
                if allowed:
                    continue
                result = self.inspector.inspect_file(path, status, destination=destination)
                verdict = result.get("verdict")
                if verdict == "BLOCK":
                    self.report(channel, policy, filename, destination, result, "BLOCKED_BROWSER")
                    return {"decision": "BLOCK", "reason": result.get("reason", "CONTENT_MATCH"),
                            "policy_id": policy.get("policy_id"), "reported": True}
                if verdict == "LOG" and first_logged is None:
                    first_logged = (policy, result)
            if first_logged:
                policy, result = first_logged
                self.report(channel, policy, filename, destination, result, "LOGGED")
                return {"decision": "REPORT_ONLY", "reason": result.get("reason", "MONITORED"),
                        "policy_id": policy.get("policy_id")}
        return {"decision": "ALLOW", "reason": "CLEAN"}

    def report(self, channel, policy, filename, destination, result, action):
        fields = self.inspector.to_report_fields(result)
        event = {
            "hostname": self.hostname,
            "policy_id": int(policy["policy_id"]),
            "exit_point_type": channel,
            "action_taken": action,
            "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "file_path": filename,
            "file_hash_sha256": fields["file_hash_sha256"],
            "matched_rule_ids": fields["matched_rule_ids"],
            "confidence_score": fields["confidence_score"],
            "destination_value": destination,
            "process_name": "chrome.exe" if channel == "BROWSER_CHROME" else "msedge.exe",
        }
        if not self.client.send_report(event):
            print("[DLP bridge] WARNING: failed to report", action, filename, flush=True)


class Handler(BaseHTTPRequestHandler):
    state = None

    def reply(self, status, obj):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path != "/health":
            self.reply(404, {"error": "not_found"})
            return
        self.reply(200, {"ok": True, "service": "dlp-python-browser-bridge"})

    def do_POST(self):
        if self.path != "/inspect-content":
            self.reply(404, {"error": "not_found"})
            return
        if self.headers.get("X-DLP-Client") != "BrowserExtension":
            self.reply(403, {"error": "invalid_client"})
            return
        length = self.headers.get("Content-Length", "")
        if not length.isdigit() or int(length) > MAX_REQUEST:
            self.reply(413, {"error": "invalid_size"})
            return
        try:
            body = self.rfile.read(int(length))
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("Expected JSON object")
            result = self.state.inspect(data)
            self.reply(200, result)
        except (ValueError, KeyError, TypeError) as exc:
            self.reply(400, {"error": str(exc)[:100]})
        except Exception as exc:
            print("[DLP bridge] Error:", type(exc).__name__, str(exc), flush=True)
            self.reply(503, {"decision": "BLOCK", "reason": "INSPECTION_ERROR"})

    def log_message(self, fmt, *args):
        print("[DLP bridge] " + fmt % args, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-dir", default=r"C:\DLP\agent",
                        help="Installed Python Agent directory containing config.ini and inspection modules")
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    state = PolicyState(Path(args.agent_dir))
    Handler.state = state
    server = ThreadingHTTPServer((HOST, args.port), Handler)
    print(f"[DLP bridge] Listening at http://{HOST}:{args.port}, agent={args.agent_dir}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
