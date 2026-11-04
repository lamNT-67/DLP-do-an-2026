import ipaddress
import os
import platform
import re
import socket
import subprocess
import time

RULE_PREFIX = "DLP_Pro_"
STATIC_LABEL = "static-IPs"
QUIC_SUFFIX = "_QUIC"
MAX_IPS_PER_DOMAIN = 64
FIREWALL_LOG = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "LogFiles", "Firewall", "pfirewall.log")


def _ps(command):
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                           capture_output=True, text=True, timeout=60)
        return r.stdout
    except (OSError, subprocess.SubprocessError) as e:
        print("[domain_blocker] powershell error:", e)
        return ""


def _dry_run(command):
    print("[domain_blocker] (dry-run, not Windows):", command[:100])
    return "DLP_OK"


def _default_resolver(domain):
    ips = set()
    try:
        for info in socket.getaddrinfo(domain, None):
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    return ips


def _clean_ip(value):
    try:
        ip = ipaddress.ip_address(str(value).split("%")[0])
    except ValueError:
        return None
    return str(ip) if ip.is_global else None


def split_target(value):
    """'https://x.com' -> ('x.com', 'https'); 'x.com' -> ('x.com', None)."""
    v = str(value).strip()
    for scheme in ("https", "http"):
        if v.lower().startswith(scheme + "://"):
            host = v[len(scheme) + 3:].split("/")[0].split(":")[0]
            return host, scheme
    return v, None


def scheme_port(scheme):
    return {"https": 443, "http": 80}.get(scheme)


def _rule_name(label):
    return RULE_PREFIX + re.sub(r"[^A-Za-z0-9._-]", "_", label)


class DomainBlocker:
    def __init__(self, runner=None, resolver=None):
        if runner is None:
            runner = _ps if platform.system() == "Windows" else _dry_run
        self._run = runner
        self._resolve = resolver or _default_resolver
        self.known = {}
        self.applied = {}
        self._first_sync = True

    def learn_ip(self, domain, ip):
        ip = _clean_ip(ip)
        if ip:
            s = self.known.setdefault(domain, set())
            if len(s) < MAX_IPS_PER_DOMAIN:
                s.add(ip)

    def blocked_ips(self):
        out = set()
        for ips in self.applied.values():
            out |= ips
        return out

    def ip_owner(self, ip):
        for label, ips in self.known.items():
            if ip in ips:
                return label
        return None

    def sync(self, domains, static_ips, enabled):
        desired = {}
        if enabled:
            for d in domains:
                for ip in self._resolve(split_target(d)[0]):
                    self.learn_ip(d, ip)
                if self.known.get(d):
                    desired[d] = set(self.known[d])
            statics = set(c for c in (_clean_ip(i) for i in static_ips) if c)
            if statics:
                self.known[STATIC_LABEL] = statics
                desired[STATIC_LABEL] = set(statics)

        changes = []
        wanted_names = set()
        for label in desired:
            wanted_names |= set(self._rule_names(label))

        if self._first_sync:
            self._first_sync = False
            out = self._run("(Get-NetFirewallRule -DisplayName '%s*' "
                            "-ErrorAction SilentlyContinue).DisplayName" % RULE_PREFIX)
            existing = set(l.strip() for l in out.splitlines()
                           if l.strip().startswith(RULE_PREFIX))
            for name in existing - wanted_names:
                self._remove(name)
                changes.append(("REMOVED", name[len(RULE_PREFIX):], set()))

        for label, ips in desired.items():
            name = _rule_name(label)
            frozen = frozenset(ips)
            ports = scheme_port(split_target(label)[1])
            if self.applied.get(name) == frozen:
                continue
            existed = name in self.applied
            if self._upsert(name, sorted(ips), ports):
                self.applied[name] = frozen
                changes.append(("UPDATED" if existed else "ADDED", label, set(ips)))

        for name in list(self.applied):
            if name not in wanted_names:
                self._remove(name)
                self._remove(name + QUIC_SUFFIX)
                del self.applied[name]
                changes.append(("REMOVED", name[len(RULE_PREFIX):], set()))
        return changes

    def _rule_names(self, label):
        name = _rule_name(label)
        if split_target(label)[1] == "https":
            return [name, name + QUIC_SUFFIX]
        return [name]

    def _upsert(self, name, ips, port=None):
        arr = ",".join("'%s'" % i for i in ips)
        cmd = ("try { $n='%s'; $a=@(%s); "
               "if (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue) "
               "{ Set-NetFirewallRule -DisplayName $n -RemoteAddress $a -ErrorAction Stop } "
               "else { New-NetFirewallRule -DisplayName $n -Direction Outbound "
               "-RemoteAddress $a %s -Action Block -ErrorAction Stop | Out-Null }; "
               "%s"
               "Write-Output 'DLP_OK' } "
               "catch { Write-Output ('DLP_FAIL ' + $_.Exception.Message) }")
        proto = ("-Protocol TCP -RemotePort %d" % port) if port else ""
        quic = ""
        if port == 443:   # chan them QUIC (UDP 443) de Chrome khong lach duong
            q = name + QUIC_SUFFIX
            quic = ("$q='%s'; if (Get-NetFirewallRule -DisplayName $q -ErrorAction SilentlyContinue) "
                    "{ Set-NetFirewallRule -DisplayName $q -RemoteAddress $a -ErrorAction Stop } "
                    "else { New-NetFirewallRule -DisplayName $q -Direction Outbound -RemoteAddress $a "
                    "-Protocol UDP -RemotePort 443 -Action Block -ErrorAction Stop | Out-Null }; " % q)
        cmd = cmd % (name, arr, proto, quic)
        out = self._run(cmd)
        if "DLP_OK" in out:
            return True
        print("[domain_blocker] Could not apply rule %s (need Administrator?): %s"
              % (name, out.strip()[:200]))
        return False

    def _remove(self, name):
        self._run("Remove-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue" % name)


class DropLogTailer:
    def __init__(self, path=FIREWALL_LOG, min_interval=60, runner=None):
        self.path = path
        self.min_interval = min_interval
        self._run = runner or (_ps if platform.system() == "Windows" else _dry_run)
        self._pos = None
        self._last_emit = {}

    def enable_logging(self):
        self._run("Set-NetFirewallProfile -Profile Domain,Private,Public "
                  "-LogBlocked True -LogMaxSizeKilobytes 4096")

    def read_new_drops(self, watched_ips):
        if not watched_ips or not os.path.exists(self.path):
            return []
        size = os.path.getsize(self.path)
        if self._pos is None:
            self._pos = size
            return []
        if size < self._pos:
            self._pos = 0
        if size == self._pos:
            return []

        with open(self.path, "rb") as f:
            f.seek(self._pos)
            chunk = f.read()
        self._pos += len(chunk)

        counts = {}
        for line in chunk.decode("ascii", "ignore").splitlines():
            if not line or line.startswith("#"):
                continue
            p = line.split()
            if len(p) < 8 or p[2] != "DROP":
                continue
            if len(p) >= 17 and p[16] != "SEND":
                continue
            if p[5] not in watched_ips:
                continue
            entry = counts.setdefault(p[5], {"dst_ip": p[5], "dst_port": p[7],
                                             "protocol": p[3], "count": 0})
            entry["count"] += 1

        now = time.time()
        events = []
        for dst, entry in counts.items():
            if now - self._last_emit.get(dst, 0) >= self.min_interval:
                self._last_emit[dst] = now
                events.append(entry)
        return events
