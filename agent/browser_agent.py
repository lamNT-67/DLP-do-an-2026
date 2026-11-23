"""browser_agent.py - Cau noi giua extension Chrome/Edge va engine kiem tra noi dung DLP.

Extension (agent/browser_extension) goi 3 duong tren 127.0.0.1:18765:
  GET  /rules            : policy rut gon theo kenh chrome / edge
  POST /inspect-content  : gui noi dung file (base64) de quet -> ALLOW | BLOCK | REPORT_ONLY
  POST /event            : bao 1 lan chan theo duoi file do extension tu quyet dinh
Chi nghe 127.0.0.1. Token server khong bao gio gui cho trinh duyet.
"""
import base64
import configparser
import datetime
import json
import platform
import re
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psutil

from content_inspection import inspect_file, to_log_inspection, to_report_fields
from log_writer import write_log_event
from policy_client import PolicyClient
from policy_utils import decision_status, get_exit_point_status

BIND_HOST, BIND_PORT = "127.0.0.1", 18765
HOSTS = {"127.0.0.1:%d" % BIND_PORT, "localhost:%d" % BIND_PORT}
EXT_ORIGINS = ("chrome-extension://", "moz-extension://")
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_BODY_BYTES = 3000000
POLICY_REFRESH_SECONDS = 60
HEARTBEAT_INTERVAL_SECONDS = 45
CHANNELS = {"chrome": "BROWSER_CHROME", "edge": "BROWSER_EDGE"}
BROWSER_PROCESS = {"chrome": "chrome.exe", "edge": "msedge.exe"}


def _iso_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_config(path="config.ini"):
    cfg = configparser.ConfigParser()
    if not Path(path).exists():
        raise FileNotFoundError("Khong tim thay %s." % path)
    cfg.read(path, encoding="utf-8-sig")
    return cfg


def save_config(cfg, path="config.ini"):
    with open(path, "w", encoding="utf-8") as f:
        cfg.write(f)


def _ensure_registered(cfg, path="config.ini"):
    hostname = cfg["agent"]["hostname"]
    api_token = cfg["agent"].get("api_token", "").strip()
    client = PolicyClient(server_url=cfg["agent"]["server_url"], hostname=hostname, api_token=api_token)
    if not api_token:
        ek = cfg["agent"].get("enrollment_key", "").strip()
        if not ek:
            raise ValueError("Thieu ca api_token va enrollment_key.")
        result = client.register(enrollment_key=ek, os_info=platform.platform())
        if result is None:
            raise RuntimeError("Dang ky that bai.")
        cfg["agent"]["api_token"] = client.api_token
        save_config(cfg, path)
    return client


def _ext_of_type(ft):
    return str(ft.get("extension", "")).lstrip(".").lower()


def _clean_name(name):
    if not isinstance(name, str):
        return None
    name = name.replace("\\", "/").rsplit("/", 1)[-1].strip()
    name = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", name).rstrip(" .")
    return name[:200] or None


def _peer_process(port):
    """Tim tien trinh trinh duyet da mo ket noi toi agent -> (ten, pid, user)."""
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.pid and c.laddr and c.raddr and c.laddr.port == port and c.raddr.port == BIND_PORT:
                p = psutil.Process(c.pid)
                return p.name(), c.pid, p.username()
    except (psutil.Error, OSError):
        pass
    return None, None, None


def _console_user():
    try:
        users = psutil.users()
        return users[0].name if users else None
    except Exception:
        return None


class BrowserGuard:
    def __init__(self, client, hostname):
        self.client = client
        self.hostname = hostname
        self._lock = threading.Lock()
        self._policies = None   # None = chua lay duoc policy

    def set_policies(self, policies):
        with self._lock:
            self._policies = list(policies or [])

    def snapshot(self):
        with self._lock:
            return self._policies

    def _status(self, channel):
        pol = self.snapshot()
        return None if pol is None else get_exit_point_status(pol, CHANNELS[channel])

    # ---- GET /rules ----
    def rules(self):
        pol = self.snapshot()
        if pol is None:
            return 503, {"updated": False}
        out = {"updated": True}
        for channel, ept in CHANNELS.items():
            items = []
            for p in pol:
                if ept not in (p.get("exit_points") or []):
                    continue
                exts = []
                # Chi policy "chi co loai file" moi chan theo duoi. Co content rule thi quet noi dung.
                if not p.get("content_rules"):
                    exts = sorted({_ext_of_type(ft) for ft in (p.get("file_types") or []) if _ext_of_type(ft)})
                items.append({"policy_id": p.get("policy_id"), "action": p.get("action"), "extensions": exts})
            out[channel] = items
        return 200, out

    # ---- POST /inspect-content ----
    def inspect(self, body, dest, peer_port):
        channel = body.get("channel")
        name = _clean_name(body.get("file_name"))
        b64 = body.get("content_base64")
        if channel not in CHANNELS or not name or not isinstance(b64, str):
            return 400, {"decision": "BLOCK", "reason": "INVALID_REQUEST"}
        status = self._status(channel)
        if status is None:
            return 200, {"decision": "BLOCK", "reason": "POLICY_UNAVAILABLE"}
        if not status["is_governed"]:
            return 200, {"decision": "ALLOW", "reason": "NOT_GOVERNED"}
        try:
            data = base64.b64decode(b64, validate=True)
        except ValueError:
            return 400, {"decision": "BLOCK", "reason": "INVALID_BASE64"}
        if len(data) > MAX_FILE_BYTES:
            return 200, {"decision": "BLOCK", "reason": "FILE_TOO_LARGE"}
        m = re.search(r"\.([A-Za-z0-9]{1,10})$", name)
        tmpdir = tempfile.mkdtemp(prefix="dlpbrowser_")
        try:
            path = str(Path(tmpdir) / ("upload" + ("." + m.group(1) if m else "")))
            Path(path).write_bytes(data)
            res = inspect_file(path, status, destination=dest, enforce_file_scope=True, file_name=name)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
        res["file_path"], res["file_name"] = name, name   # khong lo duong dan tam

        if res["verdict"] == "ALLOW":
            return 200, {"decision": "ALLOW", "reason": res["reason"]}
        status = decision_status(status, res)
        blocking = res["verdict"] == "BLOCK"
        action = "BLOCKED_BROWSER" if blocking else "LOGGED"
        peer = _peer_process(peer_port)
        threading.Thread(target=self._record, args=(channel, status, res, action, dest, peer),
                         daemon=True).start()
        return 200, {"decision": "BLOCK" if blocking else "REPORT_ONLY", "reason": res["reason"]}

    # ---- POST /event ----
    def event(self, body, dest, peer_port):
        channel = body.get("channel")
        name = _clean_name(body.get("file_name"))
        pid = body.get("policy_id")
        if channel not in CHANNELS or not name or not isinstance(pid, int) or isinstance(pid, bool):
            return 400, {"ok": False, "error": "invalid event"}
        ept = CHANNELS[channel]
        match = next((p for p in (self.snapshot() or [])
                      if p.get("policy_id") == pid and ept in (p.get("exit_points") or [])
                      and p.get("action") == "BLOCK" and not p.get("content_rules")), None)
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        exts = {_ext_of_type(ft) for ft in ((match or {}).get("file_types") or [])}
        if not match or ext not in exts:
            return 403, {"ok": False, "error": "policy mismatch"}
        res = {"verdict": "BLOCK", "reason": "FILE_TYPE_BLOCKED", "confidence_level": "HIGH",
               "file_path": name, "file_name": name, "file_hash_sha256": None,
               "matched_rule_ids": [], "matched_rule_names": [], "match_count": 0, "rule_details": []}
        status = {"policy_ids": [pid], "effective_action": "BLOCK"}
        peer = _peer_process(peer_port)
        threading.Thread(target=self._record, args=(channel, status, res, "BLOCKED_BROWSER", dest, peer),
                         daemon=True).start()
        return 202, {"ok": True}

    def _record(self, channel, status, res, action, dest, peer):
        pname, ppid, user = peer
        pname = pname or BROWSER_PROCESS[channel]
        user = user or _console_user()
        ept = CHANNELS[channel]
        fields = to_report_fields(res)
        payload = {"hostname": self.hostname, "exit_point_type": ept,
                   "policy_id": status["policy_ids"][0] if status["policy_ids"] else None,
                   "action_taken": action, "occurred_at": _iso_now(), "file_path": fields["file_path"],
                   "file_hash_sha256": fields["file_hash_sha256"],
                   "matched_rule_ids": fields["matched_rule_ids"],
                   "confidence_score": fields["confidence_score"], "destination_value": dest or None,
                   "process_name": pname, "username": user}
        rep = self.client.send_report(payload)
        write_log_event(self.hostname, "browser", ept,
                        "violation" if action != "LOGGED" else "logged", status["effective_action"],
                        {"process_name": pname, "process_pid": ppid, "user": user},
                        {"destination_ip": None, "destination_domain": dest or None,
                         "destination_port": None, "file_path": fields["file_path"]},
                        to_log_inspection(res), action, rep)
        print("[browser_agent] %s - %s (%s, %s) -> %s: %s (reported=%s)" % (
            action, pname, res.get("reason"), res.get("confidence_level"), dest, fields["file_path"], rep))


class Handler(BaseHTTPRequestHandler):
    guard = None
    allowed_ids = set()
    timeout = 10

    def log_message(self, *args):
        pass

    def _reply(self, code, obj):
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _allowed(self, need_origin):
        if (self.headers.get("Host") or "").lower() not in HOSTS:
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            return not need_origin
        if not origin.startswith(EXT_ORIGINS):
            return False
        if self.allowed_ids:
            return origin.split("://", 1)[1].rstrip("/") in self.allowed_ids
        return True

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if not self._allowed(False):
            return self._reply(403, {"error": "forbidden"})
        if path == "/rules":
            code, out = self.guard.rules()
            return self._reply(code, out)
        if path == "/health":
            return self._reply(200, {"ok": True})
        self._reply(404, {"error": "not found"})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path not in ("/inspect-content", "/event"):
            return self._reply(404, {"error": "not found"})
        if not self._allowed(True):
            return self._reply(403, {"decision": "BLOCK", "reason": "FORBIDDEN_ORIGIN"})
        if path == "/inspect-content" and self.headers.get("X-DLP-Client") != "BrowserContent":
            return self._reply(403, {"decision": "BLOCK", "reason": "FORBIDDEN_CLIENT"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            return self._reply(413, {"decision": "BLOCK", "reason": "BAD_SIZE"})
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("body")
            dest = re.sub(r"[^\x20-\x7e]", "", str(self.headers.get("X-DLP-Destination")
                                                    or body.get("destination") or ""))[:255]
            peer_port = self.client_address[1]
            if path == "/inspect-content":
                code, out = self.guard.inspect(body, dest, peer_port)
            else:
                code, out = self.guard.event(body, dest, peer_port)
        except Exception as e:
            print("[browser_agent] Loi xu ly yeu cau: %s" % type(e).__name__)
            code, out = 400, {"decision": "BLOCK", "reason": "BAD_REQUEST"}
        self._reply(code, out)


def run():
    cfg = load_config()
    client = _ensure_registered(cfg)
    hostname = cfg["agent"]["hostname"]
    ids = {x.strip() for x in cfg.get("browser", "extension_ids", fallback="").split(",") if x.strip()}
    guard = BrowserGuard(client, hostname)
    Handler.guard, Handler.allowed_ids = guard, ids
    try:
        server = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    except OSError as e:
        print("[browser_agent] Khong mo duoc %s:%d: %s" % (BIND_HOST, BIND_PORT, e))
        sys.exit(1)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print("[browser_agent] Bat dau giam sat tren %s, nghe %s:%d ..." % (hostname, BIND_HOST, BIND_PORT))
    last_hb = last_fetch = 0.0
    while True:
        now = time.time()
        if now - last_hb >= HEARTBEAT_INTERVAL_SECONDS:
            last_hb = now
            if client.send_heartbeat(agent_version="1.0.0"):
                print("[browser_agent] Heartbeat OK")
        if now - last_fetch >= POLICY_REFRESH_SECONDS:
            f = client.get_policy()
            if f is not None:
                guard.set_policies(f.get("applicable_policies", []))
                last_fetch = now
            else:
                last_fetch = now - POLICY_REFRESH_SECONDS + 10   # thu lai sau 10 giay
        time.sleep(1)


if __name__ == "__main__":
    run()
