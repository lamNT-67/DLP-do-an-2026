import time, platform, subprocess, configparser, datetime
from pathlib import Path
import psutil
from policy_client import PolicyClient
from log_writer import write_log_event
from content_inspection_stub import scan_content_with_rules
from policy_utils import get_exit_point_status, file_always_blocked

POLL_INTERVAL_SECONDS = 2
POLICY_REFRESH_SECONDS = 60
HEARTBEAT_INTERVAL_SECONDS = 45
MAX_READ_BYTES = 200000
SSH_SFTP_PROCESS_NAMES = {"ssh.exe", "scp.exe", "sftp.exe", "winscp.exe"}
FTP_PROCESS_NAMES = {"ftp.exe", "filezilla.exe"}
SKIP_EXTENSIONS = {".dll", ".exe", ".sys", ".log", ".tmp", ".ini", ".config"}


def _iso_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_config(path="config.ini"):
    cfg = configparser.ConfigParser()
    if not Path(path).exists():
        raise FileNotFoundError(f"Khong tim thay {path}.")
    cfg.read(path)
    return cfg


def save_config(cfg, path="config.ini"):
    with open(path, "w", encoding="utf-8") as f:
        cfg.write(f)


def _ensure_registered(cfg, path="config.ini"):
    hostname = cfg["agent"]["hostname"]
    server_url = cfg["agent"]["server_url"]
    api_token = cfg["agent"].get("api_token", "").strip()
    client = PolicyClient(server_url=server_url, hostname=hostname, api_token=api_token)
    if not api_token:
        ek = cfg["agent"].get("enrollment_key", "").strip()
        if not ek:
            raise ValueError("Thieu ca api_token va enrollment_key.")
        result = client.register(enrollment_key=ek, os_info=platform.platform())
        if result is None:
            raise RuntimeError("Dang ky that bai.")
        print(f"[sftp_scp_agent] Dang ky thanh cong, device_id={result.get('device_id')}.")
        cfg["agent"]["api_token"] = client.api_token
        save_config(cfg, path)
    return client


def _read_file_snippet(fp):
    try:
        with open(fp, "rb") as f: raw = f.read(MAX_READ_BYTES)
        return raw.decode("utf-8", errors="ignore")
    except (PermissionError, FileNotFoundError, OSError):
        return ""


def _detect_transferring_processes():
    found = []
    for proc in psutil.process_iter(["pid", "name"]):
        try: n = (proc.info["name"] or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        if n in SSH_SFTP_PROCESS_NAMES: found.append((proc, "NETWORK_SCP_SFTP"))
        elif n in FTP_PROCESS_NAMES: found.append((proc, "NETWORK_FTP"))
    return found


def _get_open_files(proc):
    try: files = proc.open_files()
    except (psutil.NoSuchProcess, psutil.AccessDenied): return []
    return [f.path for f in files if Path(f.path).suffix.lower() not in SKIP_EXTENSIONS]


def _get_remote_endpoint(proc):
    try: conns = proc.net_connections(kind="inet")
    except (psutil.NoSuchProcess, psutil.AccessDenied): return None, None
    for c in conns:
        if c.raddr: return c.raddr.ip, c.raddr.port
    return None, None


def _block_process_and_connection(proc, ip, port):
    killed = False
    try: proc.terminate(); killed = True
    except psutil.NoSuchProcess: killed = True
    except psutil.AccessDenied: pass
    if ip and port and platform.system() == "Windows":
        for proto in ("TCP", "UDP"):
            rn = f"DLP_Block_{ip}_{port}_{proto}"
            try:
                chk = subprocess.run(["powershell", "-Command",
                    f"Get-NetFirewallRule -DisplayName '{rn}' -ErrorAction SilentlyContinue"],
                    capture_output=True, text=True)
                if not chk.stdout.strip():
                    subprocess.run(["powershell", "-Command",
                        f"New-NetFirewallRule -DisplayName '{rn}' -Direction Outbound "
                        f"-RemoteAddress {ip} -RemotePort {port} -Protocol {proto} -Action Block"],
                        check=True, capture_output=True)
            except subprocess.CalledProcessError as e:
                print(f"[sftp_scp_agent] Loi firewall ({proto}): {e}")
    return "BLOCKED_KILL" if killed else "LOGGED"


def run():
    cfg = load_config()
    client = _ensure_registered(cfg)
    policy_cache, last_fetch = None, 0.0
    last_heartbeat = 0.0
    already = set()
    print(f"[sftp_scp_agent] Bat dau giam sat tren {cfg['agent']['hostname']} ...")
    while True:
        now = time.time()

        if now - last_heartbeat >= HEARTBEAT_INTERVAL_SECONDS:
            last_heartbeat = now
            if client.send_heartbeat(agent_version="1.0.0"):
                print("[sftp_scp_agent] Heartbeat OK")

        if policy_cache is None or (now - last_fetch) >= POLICY_REFRESH_SECONDS:
            f = client.get_policy()
            if f is not None: policy_cache, last_fetch = f, now
            elif policy_cache is None:
                time.sleep(POLL_INTERVAL_SECONDS); continue

        aps = policy_cache.get("applicable_policies", [])
        for proc, ept in _detect_transferring_processes():
            status = get_exit_point_status(aps, ept)
            if not status["is_governed"]: continue
            try: pname, pid = proc.name(), proc.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue

            for fp in _get_open_files(proc):
                key = (pid, fp)
                if key in already: continue
                always = file_always_blocked(fp, status["file_types"])
                if always:
                    insp = {"matched_rule_ids": [], "matched_rule_names": [], "confidence_level": "CRITICAL"}
                    should_act = True
                else:
                    content = _read_file_snippet(fp)
                    insp = scan_content_with_rules(content, status["content_rules"])
                    should_act = bool(insp["matched_rule_ids"])

                if status["effective_action"] == "BLOCK" and should_act:
                    ip, port = _get_remote_endpoint(proc)
                    action = _block_process_and_connection(proc, ip, port)
                elif should_act:
                    action = "LOGGED"
                else:
                    already.add(key); continue

                payload = {"hostname": cfg["agent"]["hostname"], "exit_point_type": ept,
                           "policy_id": status["policy_ids"][0] if status["policy_ids"] else None,
                           "action_taken": action, "occurred_at": _iso_now(), "file_path": fp,
                           "file_hash_sha256": None, "matched_rule_ids": insp["matched_rule_ids"],
                           "confidence_score": insp["confidence_level"], "destination_value": None,
                           "process_name": pname}
                rep = client.send_report(payload)
                write_log_event(cfg["agent"]["hostname"],
                                 "scp_sftp" if ept == "NETWORK_SCP_SFTP" else "ftp", ept,
                                 "violation" if action != "LOGGED" else "logged",
                                 status["effective_action"],
                                 {"process_name": pname, "process_pid": pid, "user": None},
                                 {"destination_ip": None, "destination_domain": None, "destination_port": None, "file_path": fp},
                                 insp, action, rep)
                print(f"[sftp_scp_agent] {action} - {pname} (PID {pid}) dang truyen file: {fp} (reported={rep})")
                already.add(key)

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run()
