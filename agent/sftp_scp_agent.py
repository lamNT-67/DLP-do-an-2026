import os, time, platform, subprocess, configparser, datetime
from pathlib import Path
import psutil
from policy_client import PolicyClient
from log_writer import write_log_event
from content_inspection_stub import scan_content_with_rules
from file_text import read_file_text
from policy_utils import get_exit_point_status, file_always_blocked, file_in_scope

POLL_INTERVAL_SECONDS = 0.25
POLICY_REFRESH_SECONDS = 60
HEARTBEAT_INTERVAL_SECONDS = 45
MAX_READ_BYTES = 200000
SSH_SFTP_PROCESS_NAMES = {"ssh.exe", "scp.exe", "sftp.exe", "winscp.exe"}
FTP_PROCESS_NAMES = {"ftp.exe", "filezilla.exe"}
SKIP_EXTENSIONS = {".dll", ".exe", ".sys", ".log", ".tmp", ".ini", ".config"}
MAX_FILES_PER_COMMAND = 200
PORT_RULE_PREFIX = "DLP_BlockSftp_Port"
PROACTIVE_PORTS = {"NETWORK_SCP_SFTP": [22], "NETWORK_FTP": [21, 990]}


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
    return read_file_text(fp)


def _ept_of(name):
    name = (name or "").lower()
    if name in SSH_SFTP_PROCESS_NAMES:
        return "NETWORK_SCP_SFTP"
    if name in FTP_PROCESS_NAMES:
        return "NETWORK_FTP"
    return None


def _pname(proc):
    try:
        return proc.name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ""


def _find_root(proc):
    """scp.exe sinh ra ssh.exe: lay tien trinh goc trong nhom de xu ly ca cay."""
    cur = proc
    while True:
        try:
            par = cur.parent()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            break
        if par is None or _ept_of(_pname(par)) is None:
            break
        cur = par
    return cur


def _tree(proc):
    try:
        return [proc] + proc.children(recursive=True)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return [proc]


def _suspend_tree(procs):
    for p in procs:
        try: p.suspend()
        except (psutil.NoSuchProcess, psutil.AccessDenied): pass


def _resume_tree(procs):
    for p in procs:
        try: p.resume()
        except (psutil.NoSuchProcess, psutil.AccessDenied): pass


def _kill_tree(procs):
    ok = False
    for p in reversed(procs):
        try:
            p.kill(); ok = True
        except psutil.NoSuchProcess:
            ok = True
        except psutil.AccessDenied:
            pass
    return ok


def _expand_path(path):
    p = Path(path)
    if p.is_file():
        return [str(p)]
    out = []
    if p.is_dir():
        for root, _dirs, files in os.walk(p):
            for fn in files:
                out.append(os.path.join(root, fn))
                if len(out) >= MAX_FILES_PER_COMMAND:
                    return out
    return out


def _files_from_cmdline(cmdline, cwd=None):
    """Lay file local trong lenh scp/sftp/winscp/ftp (tham so la duong dan ton tai)."""
    found = []
    for arg in (cmdline or [])[1:]:
        cands = [arg]
        low = arg.lower()
        for prefix in ("put ", "mput ", "send ", "/upload "):
            if low.startswith(prefix):
                cands.append(arg[len(prefix):].strip().strip('"'))
        for c in cands:
            if not c or c.startswith("-"):
                continue
            if cwd and not os.path.isabs(c) and not c.startswith("/"):
                c = os.path.join(cwd, c)
            if c.startswith("/") and not os.path.exists(c):
                continue
            try:
                exists = os.path.exists(c)
            except (OSError, ValueError):
                exists = False
            if exists:
                for f in _expand_path(c):
                    if Path(f).suffix.lower() not in SKIP_EXTENSIONS and f not in found:
                        found.append(f)
    return found[:MAX_FILES_PER_COMMAND]


def _safe_cwd(proc):
    try:
        return proc.cwd()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return None

def _get_open_files(proc):
    try: files = proc.open_files()
    except (psutil.NoSuchProcess, psutil.AccessDenied): return []
    return [f.path for f in files if Path(f.path).suffix.lower() not in SKIP_EXTENSIONS]


def _get_remote_endpoint(procs):
    for proc in procs:
        try: conns = proc.net_connections(kind="inet")
        except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        for c in conns:
            if c.raddr: return c.raddr.ip, c.raddr.port
    return None, None


def _ps(command):
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                           capture_output=True, text=True, timeout=60)
        return r.stdout
    except (OSError, subprocess.SubprocessError) as e:
        print(f"[sftp_scp_agent] powershell loi: {e}")
        return ""


def _ensure_port_rules(ports_by_ept, enabled_epts):
    """Chan han cong 22 (SCP/SFTP) va 21/990 (FTP) o firewall khi policy BLOCK khong co dieu kien."""
    if platform.system() != "Windows":
        return
    for ept, ports in ports_by_ept.items():
        for port in ports:
            name = f"{PORT_RULE_PREFIX}{port}"
            if ept in enabled_epts:
                _ps(f"if (-not (Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue)) "
                    f"{{ New-NetFirewallRule -DisplayName '{name}' -Direction Outbound -Protocol TCP "
                    f"-RemotePort {port} -Action Block | Out-Null }}")
            else:
                _ps(f"Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue")


def _block_process_and_connection(procs, ip, port):
    killed = _kill_tree(procs)
    if ip and port and platform.system() == "Windows":
        for proto in ("TCP", "UDP"):
            rn = f"DLP_BlockSftp_{ip}_{port}_{proto}"
            _ps(f"if (-not (Get-NetFirewallRule -DisplayName '{rn}' -ErrorAction SilentlyContinue)) "
                f"{{ New-NetFirewallRule -DisplayName '{rn}' -Direction Outbound -RemoteAddress {ip} "
                f"-RemotePort {port} -Protocol {proto} -Action Block | Out-Null }}")
    return "BLOCKED_KILL" if killed else "LOGGED"


def _inspect_file(fp, status):
    """Tra ve (should_act, insp). Policy: duong ra -> loai file -> noi dung."""
    none = {"matched_rule_ids": [], "matched_rule_names": [], "confidence_level": "LOW"}
    if not file_in_scope(fp, status["file_types"]):
        return False, none                      # khac loai file cua policy: khong quet, cho qua
    if file_always_blocked(fp, status["file_types"]):
        return True, dict(none, confidence_level="CRITICAL")
    if status["content_rules"]:
        insp = scan_content_with_rules(_read_file_snippet(fp), status["content_rules"])
        return bool(insp["matched_rule_ids"]), insp
    if status["file_types"]:                    # co loai file, khong co rule noi dung: chan theo loai file
        return True, dict(none, confidence_level="HIGH")
    return status["effective_action"] == "BLOCK", dict(none, confidence_level="HIGH")

def _remove_rules(pattern):
    if platform.system() != "Windows":
        return
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command",
            f"Get-NetFirewallRule -DisplayName '{pattern}' -ErrorAction SilentlyContinue | "
            f"Remove-NetFirewallRule -ErrorAction SilentlyContinue"],
            capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        print(f"[sftp_scp_agent] Loi khi go rule {pattern}: {e}")


def run():
    cfg = load_config()
    client = _ensure_registered(cfg)
    policy_cache, last_fetch = None, 0.0
    last_heartbeat = 0.0
    already = set()
    seen_roots, killed_roots = set(), set()
    last_port_state = None
    reactive_clean = False
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
        blocking = any(get_exit_point_status(aps, e)["effective_action"] == "BLOCK"
                       for e in ("NETWORK_SCP_SFTP", "NETWORK_FTP"))
        if blocking:
            reactive_clean = False
        elif not reactive_clean:
            _remove_rules("DLP_BlockSftp_*")
            last_port_state = None
            already.clear()
            reactive_clean = True
            print("[sftp_scp_agent] Khong con policy chan SCP/SFTP/FTP, da go cac rule DLP_BlockSftp_*")
        unconditional = set()
        for e in ("NETWORK_SCP_SFTP", "NETWORK_FTP"):
            st = get_exit_point_status(aps, e)
            if st["is_governed"] and st["effective_action"] == "BLOCK" \
                    and not st["content_rules"] and not st["file_types"]:
                unconditional.add(e)
        if unconditional != last_port_state:
            _ensure_port_rules(PROACTIVE_PORTS, unconditional)
            last_port_state = set(unconditional)

        hostname = cfg["agent"]["hostname"]
        for proc in psutil.process_iter(["pid", "name"]):
            ept = _ept_of(proc.info.get("name"))
            if not ept:
                continue
            status = get_exit_point_status(aps, ept)
            if not status["is_governed"]:
                continue
            root = _find_root(proc)
            try: rkey = (root.pid, root.create_time())
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
            if rkey in killed_roots:
                _kill_tree([proc]); continue
            blocking = status["effective_action"] == "BLOCK"
            procs = _tree(root)
            first = rkey not in seen_roots
            if first:
                seen_roots.add(rkey)
                if blocking:
                    _suspend_tree(procs)   # dung ngay, chua cho file di
            try: rpname, rpid = root.name(), root.pid
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue

            files = []
            if first:
                try: files += _files_from_cmdline(root.cmdline(), _safe_cwd(root))
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
            for p in procs:
                files += [f for f in _get_open_files(p) if f not in files]

            killed = False
            for fp in files:
                key = (rkey, fp)
                if key in already: continue
                already.add(key)
                should_act, insp = _inspect_file(fp, status)
                if not should_act:
                    continue
                if blocking:
                    ip, port = _get_remote_endpoint(procs)
                    action = _block_process_and_connection(procs, ip, port)
                    killed_roots.add(rkey); killed = True
                else:
                    action = "LOGGED"
                payload = {"hostname": hostname, "exit_point_type": ept,
                           "policy_id": status["policy_ids"][0] if status["policy_ids"] else None,
                           "action_taken": action, "occurred_at": _iso_now(), "file_path": fp,
                           "file_hash_sha256": None, "matched_rule_ids": insp["matched_rule_ids"],
                           "confidence_score": insp["confidence_level"], "destination_value": None,
                           "process_name": rpname}
                rep = client.send_report(payload)
                write_log_event(hostname,
                                 "scp_sftp" if ept == "NETWORK_SCP_SFTP" else "ftp", ept,
                                 "violation" if action != "LOGGED" else "logged",
                                 status["effective_action"],
                                 {"process_name": rpname, "process_pid": rpid, "user": None},
                                 {"destination_ip": None, "destination_domain": None, "destination_port": None, "file_path": fp},
                                 insp, action, rep)
                print(f"[sftp_scp_agent] {action} - {rpname} (PID {rpid}) dang truyen file: {fp} (reported={rep})")
                if killed: break
            if first and blocking and not killed:
                _resume_tree(procs)   # file sach: cho di tiep

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run()