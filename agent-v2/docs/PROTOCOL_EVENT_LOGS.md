# Protocol firewall blocks -> DLP Server logs (Windows VM)

The DLP Agent can automatically block native Windows OpenSSH clients on standard
SSH TCP port 22, and native FTP/curl on port 21, when the optional
`protocol_firewall_enabled` mode is enabled and an active BLOCK policy applies.

Previously this enforced firewall rules but **never sent event logs**.
The new `ProtocolEventMonitor` reads Windows Security **Event ID 5157**
(Windows Filtering Platform denied connection), correlates the executable and
destination port against active Agent policies, and reports via
`agent_report.php` with `action_taken=BLOCKED_FIREWALL`.

**The log is a blocked connection, not a verified uploaded file.**
Windows Firewall/WFP cannot determine the filename inside encrypted SCP/SFTP.
`file_path` therefore is NULL. The destination is `IP:port`, process is
typically `ssh.exe`, and the exit point comes from a matching policy. If
SCP and SFTP rules are both enabled, the monitor cannot distinguish which
underlying SSH command was attempted.

## Prerequisites / setup

**1. On the Windows VM, run an elevated PowerShell:**

```powershell
auditpol /set /subcategory:"Filtering Platform Connection" /failure:enable
auditpol /get /subcategory:"Filtering Platform Connection"
```

The Windows security audit policy must show **Failure** enabled.
On non-English Windows, use the corresponding localized audit subcategory.
This setting increases Windows Security Event Log volume.

**2. Pull the latest agent-test branch and reinstall Agent:**

```powershell
git pull origin agent-test
powershell -ExecutionPolicy Bypass -File .\\installer\\install.ps1
Restart-Service DLPAgent
```

The installer command above assumes the current directory is `agent-v2`.

**3. Confirm Agent config has** `"protocol_firewall_enabled": true`
and a policy with `NETWORK_SCP_SFTP` or `CLIENT_SCP` set to `BLOCK`.
Wait for normal policy sync.

**4. Confirm Audit Event 5157 exists before debugging Server logs:**

```powershell
scp.exe secret.txt kali@192.168.106.131:/home/kali/Public/
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  Id = 5157
  StartTime = (Get-Date).AddMinutes(-5)
} -MaxEvents 10 | Select-Object TimeCreated, Message
```

Expect a `5157` event mentioning `ssh.exe` (or the actual client), destination
`192.168.106.131`, and destination port `22`. The Windows Agent runs under
LocalSystem, which ordinarily can read the Security log.

**5. In phpMyAdmin:**

```sql
SELECT id, exit_point_type, action_taken, file_path,
       destination_value, process_name, occurred_at
FROM logs WHERE action_taken='BLOCKED_FIREWALL'
ORDER BY id DESC LIMIT 10;
```

Expected: `BLOCKED_FIREWALL`, policy's CLI/legacy exit point, `ssh.exe`,
`192.168.106.131:22`, and blank File field.

## Troubleshooting

- **SCP blocked but no 5157:** Windows audit policy is not enabled, or the
  connection failed for reasons other than WFP blocking, or events are not yet
  visible. Restart a NEW SCP attempt *after* enabling auditing.
- **5157 exists but no DLP log:** verify Agent is rebuilt and restarted from
  the code containing `ProtocolEventMonitor.cs`; verify active policy cache
  includes BLOCK, `protocol_firewall_enabled=true`, and
  `agent_report.php` is current. Run installed EXE in elevated terminal
  *after stopping Windows Service* to inspect warnings.
- **No Firewall rules:** check `Get-NetFirewallRule -DisplayName 'DLPAgent Protocol *'`.
- **Only 404/400 responses from API:** deploy the corresponding PHP code and
  run application-channel migration. `BLOCKED_FIREWALL` is already supported
  by the existing DLP log action enum.
- **Connection blocked via a non-DLP firewall rule:** the monitor may match
  a current DLP policy by application+port, but Windows 5157 does not
  independently prove that the specific DLP rule was responsible. Treat it
  as correlated evidence, not tamper-proof attribution.

The monitor checks recent Security events periodically and only emits events
seen after it initializes; it is a lab audit integration rather than durable
production-grade telemetry. No queue/retry or high-volume accounting is
implemented. Disabling failure auditing later, if desired, is a separate
administrator operation; the Agent will not silently alter audit policy.
