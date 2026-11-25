"""Run native Windows curl against a loopback-only synthetic upload and API fixture."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import curl_agent
import log_writer


MARKER = b"SYNTHETIC_CURL_DLP_TEST"
TOKEN = "loopback-test-token"
HOST = "CURL-LAB"


class Receiver(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.requests = {}
        self.policies = []
        self.reports = []


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def handle_expect_100(self):
        return True  # Count headers before sending 100 Continue below.

    def _reply(self, status, body=None):
        data = json.dumps(body).encode("ascii") if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _handle(self):
        self.close_connection = True
        route = urlsplit(self.path).path
        expected = int(self.headers.get("Content-Length", 0))
        if route in {"/agent_policy.php", "/agent_report.php"}:
            if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                self._reply(401)
            elif route == "/agent_policy.php":
                self._reply(200, {"applicable_policies": self.server.policies})
            else:
                self.server.reports.append(json.loads(self.rfile.read(expected)))
                self._reply(201, {"status": "ok", "id": len(self.server.reports)})
            return

        measurement = {"method": self.command, "expected": expected, "bytes": 0,
                       "body_finished": threading.Event()}
        self.server.requests.setdefault(route, []).append(measurement)
        self.connection.settimeout(9)
        try:
            if self.headers.get("Expect", "").lower() == "100-continue":
                time.sleep(0.65)
                self.send_response_only(100)
                self.end_headers()
            while measurement["bytes"] < expected:
                part = self.rfile.read1(min(65536, expected - measurement["bytes"]))
                if not part:
                    break
                measurement["bytes"] += len(part)
            if route not in {"/fast-block", "/partial-block"}:
                time.sleep(0.55)  # Give the watcher one full poll for the functional cases.
            self._reply(200)
        except (ConnectionError, TimeoutError):
            pass
        finally:
            measurement["body_finished"].set()

    do_GET = do_HEAD = do_PUT = do_POST = _handle


def _policy(action):
    return {"policy_id": 17, "name": "Synthetic loopback policy", "action": action,
            "exit_points": ["CLIENT_CURL"], "file_types": [], "allowed_locations": [],
            "allowed_files": [],
            "content_rules": [{"id": 31, "rule_name": "Synthetic loopback marker", "rule_type": "REGEX",
                               "pattern": MARKER.decode("ascii"), "severity": "HIGH",
                               "category": "INTERNAL_DOC"}]}


def _records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def _run_case(case, args, action, root, curl, server, policy, journal, monitor):
    event_count = len(_records(log_writer.LOG_FILE))
    server.policies = [_policy(action)]
    policy.refresh()
    url = f"http://127.0.0.1:{server.server_port}/{case}?token=synthetic-query-secret"
    output = str(root / "response.json") if case == "download" else "NUL"
    command = [curl, "-q", "--noproxy", "*", "--max-time", "10", "--http1.1",
               "-sS", "-o", output, *args, url]
    with subprocess.Popen(command, cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as child:
        try:
            deadline = time.monotonic() + 15
            time.sleep(curl_agent.POLL_INTERVAL)
            bytes_before_poll = sum(r["bytes"] for r in server.requests.get(f"/{case}", []))
            while child.poll() is None and time.monotonic() < deadline:
                # Filter out every PID except the child created by this fixture.
                mine = (p for p in psutil.process_iter(["name"]) if p.pid == child.pid)
                monitor.poll(policy.status, mine)
                time.sleep(curl_agent.POLL_INTERVAL)
            if child.poll() is None:
                raise RuntimeError(f"curl did not exit for {case}")
        finally:
            if child.poll() is None:
                child.kill()
        exit_code = child.wait()

    requests = server.requests.get(f"/{case}", [])
    for request in requests:
        if not request["body_finished"].wait(3):
            raise RuntimeError(f"Receiver did not finish measuring {case}")
    journal.reports.join()
    events = _records(log_writer.LOG_FILE)[event_count:]
    deliveries = {event["event_id"]: event for event in _records(log_writer.CURL_DELIVERY_FILE)}
    decisions = [
        {"verdict": e["content_inspection"]["verdict"], "reason": e["content_inspection"]["reason"],
         "action": e["action_taken"], **e.get("enforcement", {}),
         "server_log_id": deliveries.get(e["event_id"], {}).get("server_log_id")}
        for e in events
    ]
    return {"case": case, "curl_exit": exit_code, "requests": len(requests),
            "bytes_before_first_poll": bytes_before_poll,
            "received_bytes": sum(r["bytes"] for r in requests),
            "expected_bytes": sum(r["expected"] for r in requests),
            "complete_requests": sum(r["bytes"] == r["expected"] for r in requests),
            "decisions": decisions}


def _assert_cases(results, marked_bytes):
    by_name = {result["case"]: result for result in results}
    clean_uploads = ("clean-put", "clean-form", "clean-data")
    for name in ("get", "head", "download", "literal", *clean_uploads, "report-only", "unsupported"):
        result = by_name[name]
        _require(result["curl_exit"] == 0 and result["requests"] == result["complete_requests"] == 1, name)
    for name in ("get", "head", "download", "literal"):
        _require(not by_name[name]["decisions"], name)
    for name in (*clean_uploads, "report-only", "blocked-before-body",
                 "partial-block", "unsupported"):
        _require(len(by_name[name]["decisions"]) == 1, name)
    for name in clean_uploads:
        _require(by_name[name]["decisions"][0]["action"] == "ALLOWED", name)
    report_only = by_name["report-only"]
    _require(report_only["decisions"][0]["action"] == "LOGGED"
             and report_only["decisions"][0]["server_log_id"] is not None
             and report_only["received_bytes"] == marked_bytes, "report-only")
    for name in ("blocked-before-body", "partial-block"):
        decision = by_name[name]["decisions"][0]
        _require(decision["action"] == "BLOCKED_KILL" and decision["server_log_id"] is not None, name)
    _require(by_name["unsupported"]["decisions"][0]["reason"] == "UNSUPPORTED_OPTION", "unsupported")
    # Receiver bytes are observations, including complete transfers that beat polling.
    # Zero bytes in one controlled case cannot establish prevention.


def _require(condition, case):
    if not condition:
        raise RuntimeError(f"Unexpected behavior for {case}; see receiver output above.")


def main():
    curl = shutil.which("curl.exe")
    if sys.platform != "win32" or not curl:
        raise SystemExit("Requires Windows and native curl.exe.")
    os.environ["NO_PROXY"] = "127.0.0.1"
    with tempfile.TemporaryDirectory(prefix="curl DLP lab ") as directory, Receiver() as server:
        root = Path(directory)
        log_writer.LOG_FILE = root / "dlp_events.log"
        log_writer.CURL_DELIVERY_FILE = root / "curl_delivery.log"
        clean = root / "public file.txt"
        clean.write_bytes(b"synthetic public content")
        clean_form = root / "public, form file.txt"
        clean_form.write_bytes(b"synthetic public multipart content")
        marked = root / "marked file.txt"
        marked.write_bytes(MARKER)
        large = root / "large marked file.txt"
        large.write_bytes(MARKER + b"\n" + b"x" * (512 * 1024 - len(MARKER) - 1))
        expect = ["-H", "Expect: 100-continue", "--expect100-timeout", "4"]

        http = threading.Thread(target=server.serve_forever, daemon=True)
        http.start()
        client = curl_agent.CurlPolicyClient(f"http://127.0.0.1:{server.server_port}", HOST, TOKEN)
        policy = curl_agent.CurlPolicy(client)
        journal = curl_agent.CurlJournal(HOST, client)
        monitor = curl_agent.CurlMonitor(journal.record)
        cases = [
            ("get", [], "BLOCK"),
            ("head", ["-I"], "BLOCK"),
            ("download", [], "BLOCK"),
            ("literal", ["-d", MARKER.decode("ascii")], "BLOCK"),
            ("clean-put", ["-T", clean.name, *expect], "BLOCK"),
            ("clean-form", ["-F", f'foo=@"{clean_form.name}";type=text/plain',
                            "-F", f"bar=<{clean.name}", *expect], "BLOCK"),
            ("clean-data", ["-d", f"@{clean.name}", *expect], "BLOCK"),
            ("report-only", ["--data-binary", f"@{marked}"], "REPORT_ONLY"),
            ("blocked-before-body", ["-T", marked.name, *expect], "BLOCK"),
            ("partial-block", ["-T", large.name, "--limit-rate", "64k", "-H", "Expect:"], "BLOCK"),
            ("fast-block", ["-T", marked.name, "-H", "Expect:"], "BLOCK"),
            ("unsupported", ["--data-urlencode", f"@{marked.name}"], "BLOCK"),
        ]
        try:
            results = []
            for name, args, action in cases:
                result = _run_case(name, args, action, root, curl, server, policy, journal, monitor)
                print(json.dumps(result), flush=True)
                results.append(result)
            _assert_cases(results, len(MARKER))
            _require((root / "response.json").is_file(), "download file")
            telemetry = json.dumps([server.reports, _records(log_writer.LOG_FILE),
                                    _records(log_writer.CURL_DELIVERY_FILE)])
            _require("synthetic-query-secret" not in telemetry and MARKER.decode("ascii") not in telemetry,
                     "telemetry redaction")
        finally:
            journal.close()
            server.shutdown()
            http.join()


if __name__ == "__main__":
    main()
