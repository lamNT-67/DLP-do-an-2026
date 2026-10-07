import time
import platform
import subprocess
import configparser
import datetime
import socket
from pathlib import Path

import psutil

from policy_client import PolicyClient
from log_writer import write_log_event
from content_inspection_stub import scan_content_with_rules
from policy_utils import get_exit_point_status
from domain_blocker import DomainBlocker, DropLogTailer

POLL_INTERVAL_SECONDS = 10
POLICY_REFRESH_SECONDS = 60
HEARTBEAT_INTERVAL_SECONDS = 45
PROACTIVE_SYNC_SECONDS = 60
REPORT_COOLDOWN_SECONDS = 60

NO_INSPECTION = {"matched_rule_ids": [], "matched_rule_names": [], "confidence_level": "LOW"}


def _iso_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_config(path="config.ini"):
    cfg = configparser.ConfigParser()
    if not Path(path).exists():
        raise FileNotFoundError("Khong tim thay " + path)
    cfg.read(path)
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
            raise ValueError("Thieu ca api_token va enrollment_key trong config.ini.")
        print("[network_agent] Dang tu dang ky...")
        result = client.register(enrollment_key=ek, os_info=platform.platform())
        if result is None:
            raise RuntimeError("Dang ky that bai.")
        print("[network_agent] Dang ky thanh cong, device_id=%s." % result.get("device_id"))
        cfg["agent"]["api_token"] = client.api_token
        save_config(cfg, path)
    return client


def _match_blacklist(remote_ip, remote_port, blacklist, blocker):
    for entry in blacklist:
        t = entry.get("target_type", "").upper()
        v = str(entry.get("value", ""))
        if t == "IP" and v == remote_ip:
            return entry
        if t == "PORT" and v == str(remote_port):
            return entry
        if t == "DOMAIN":
            try:
                ips = set(i[4][0] for i in socket.getaddrinfo(v, None))
            except socket.gaierror:
                ips = set()
            if remote_ip in ips or remote_ip in blocker.known.get(v, set()):
                return entry
    return None


def _block_connection(pid, remote_ip, remote_port):
    if platform.system() != "Windows":
        return "BLOCKED_FIREWALL"
    ok = False
    for proto in ("TCP", "UDP"):
        rn = "DLP_Block_%s_%s_%s" % (remote_ip, remote_port, proto)
        try:
            chk = subprocess.run(["powershell", "-Command",
                "Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue" % rn],
                capture_output=True, text=True)
            if not chk.stdout.strip():
                subprocess.run(["powershell", "-Command",
                    "New-NetFirewallRule -DisplayName '%s' -Direction Outbound "
                    "-RemoteAddress %s -RemotePort %s -Protocol %s -Action Block"
                    % (rn, remote_ip, remote_port, proto)], check=True, capture_output=True)
            ok = True
        except subprocess.CalledProcessError as e:
            print("[network_agent] Loi firewall (%s): %s" % (proto, e))
    if ok:
        return "BLOCKED_FIREWALL"
    try:
        psutil.Process(pid).terminate()
        return "BLOCKED_KILL"
    except psutil.NoSuchProcess:
        return "LOGGED"


def _get_process_name(pid):
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "unknown"


def _report_and_log(client, hostname, policy_id, state, action, dest_value, process,
                    pid, target, inspection):
    payload = {"hostname": hostname, "exit_point_type": "NETWORK_WEB", "policy_id": policy_id,
               "action_taken": action, "occurred_at": _iso_now(), "file_path": None,
               "file_hash_sha256": None, "matched_rule_ids": inspection["matched_rule_ids"],
               "confidence_score": None if inspection is NO_INSPECTION else inspection["confidence_level"],
               "destination_value": dest_value[:250], "process_name": process}
    reported = client.send_report(payload)
    write_log_event(hostname, "network", "NETWORK_WEB",
                    "logged" if action == "LOGGED" else "violation", state,
                    {"process_name": process, "process_pid": pid, "user": None},
                    target, inspection, action, reported)
    return reported


def run():
    cfg = load_config()
    client = _ensure_registered(cfg)
    hostname = cfg["agent"]["hostname"]

    blocker = DomainBlocker()
    tailer = DropLogTailer()
    if cfg["agent"].get("firewall_drop_log", "true").strip().lower() == "true":
        tailer.enable_logging()

    policy_cache, last_fetch, last_sync = None, 0.0, 0.0
    last_heartbeat = 0.0
    reactive_ips = set()
    recent = {}

    print("[network_agent] Bat dau giam sat tren %s ..." % hostname)
    while True:
        now = time.time()

        if now - last_heartbeat >= HEARTBEAT_INTERVAL_SECONDS:
            last_heartbeat = now
            if client.send_heartbeat(agent_version="1.0.0"):
                print("[network_agent] Heartbeat OK")

        if policy_cache is None or (now - last_fetch) >= POLICY_REFRESH_SECONDS:
            f = client.get_policy()
            if f is not None:
                policy_cache, last_fetch = f, now
            elif policy_cache is None:
                print("[network_agent] Chua lay duoc policy lan dau, thu lai sau...")
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

        status = get_exit_point_status(policy_cache.get("applicable_policies", []), "NETWORK_WEB")
        blacklist = policy_cache.get("network_blacklist", [])
        policy_id = status["policy_ids"][0] if status["policy_ids"] else None
        state = status["effective_action"]

        unconditional = status["is_governed"] and state == "BLOCK" and not status["content_rules"]
        if now - last_sync >= PROACTIVE_SYNC_SECONDS:
            last_sync = now
            domains = [e["value"] for e in blacklist if e.get("target_type", "").upper() == "DOMAIN"]
            ips = [e["value"] for e in blacklist if e.get("target_type", "").upper() == "IP"]
            try:
                for kind, label, addrs in blocker.sync(domains, ips, unconditional):
                    print("[network_agent] Proactive %s: %s (%d IP)" % (kind, label, len(addrs)))
                    if kind in ("ADDED", "UPDATED"):
                        _report_and_log(client, hostname, policy_id, state, "BLOCKED_FIREWALL",
                                        "%s (%d IP)" % (label, len(addrs)), "dlp-agent", None,
                                        {"destination_ip": None, "destination_domain": label,
                                         "destination_port": None, "file_path": None}, NO_INSPECTION)
            except Exception as e:
                print("[network_agent] Loi khi dong bo firewall:", e)

        try:
            for d in tailer.read_new_drops(blocker.blocked_ips() | reactive_ips):
                label = blocker.ip_owner(d["dst_ip"]) or d["dst_ip"]
                print("[network_agent] Firewall da chan %d goi toi %s (%s:%s)"
                      % (d["count"], label, d["dst_ip"], d["dst_port"]))
                _report_and_log(client, hostname, policy_id, state, "BLOCKED_FIREWALL",
                                "%s %s:%s x%d" % (label, d["dst_ip"], d["dst_port"], d["count"]),
                                "windows-firewall", None,
                                {"destination_ip": d["dst_ip"], "destination_domain": None,
                                 "destination_port": d["dst_port"], "file_path": None}, NO_INSPECTION)
        except Exception as e:
            print("[network_agent] Loi khi doc log firewall:", e)

        if status["is_governed"]:
            try:
                conns = psutil.net_connections(kind="inet")
            except psutil.AccessDenied:
                print("[network_agent] Can quyen Administrator de doc net_connections day du.")
                conns = []
            for c in conns:
                if not c.raddr:
                    continue
                ip, port = c.raddr.ip, c.raddr.port
                m = _match_blacklist(ip, port, blacklist, blocker)
                if not m:
                    continue
                if m.get("target_type", "").upper() == "DOMAIN":
                    blocker.learn_ip(m["value"], ip)
                if now - recent.get((ip, port), 0) < REPORT_COOLDOWN_SECONDS:
                    continue
                recent[(ip, port)] = now

                pname = _get_process_name(c.pid) if c.pid else "unknown"
                insp = scan_content_with_rules(m.get("value", ""), status["content_rules"])
                should_block = state == "BLOCK" and (not status["content_rules"] or insp["matched_rule_ids"])
                action = _block_connection(c.pid, ip, port) if should_block else "LOGGED"
                if action == "BLOCKED_FIREWALL":
                    reactive_ips.add(ip)
                rep = _report_and_log(client, hostname, policy_id, state, action, "%s:%s" % (ip, port),
                                      pname, c.pid,
                                      {"destination_ip": ip, "destination_domain": None,
                                       "destination_port": port, "file_path": None}, insp)
                print("[network_agent] %s - %s -> %s:%s (reported=%s)" % (action, pname, ip, port, rep))

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run()
