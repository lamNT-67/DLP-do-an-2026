# DLP Server -> Wazuh TCP Syslog integration

## Architecture

```
Windows DLP Agent V2 --HTTP POST agent_report.php--> DLP Server (PHP / MySQL)
                                                     | writes logs and outbox in one DB transaction
                                                     v
                                            TCP Syslog to Wazuh Manager
                                                     ^
                                      CLI retry worker for failed deliveries
```

**The Windows Agent never connects to Wazuh**, receives no Wazuh destination in its policy and needs no new binaries for this integration. The Server sends metadata only, not file contents or enrollment/API tokens. It forwards records **after the DLP Server accepts and stores them**. Failed Wazuh sends do not change Agent DLP verdicts. Duplicate events are possible if a network write succeeds but Server crashes before updating the outbox; each event contains a unique `log_id` for deduplication.

## Deployment (XAMPP / Windows DLP Server)

1. Deploy the changed Server code and run BOTH SQL migrations on existing `dlp_system` MySQL database:
   - `server/sql/migrations/add_wazuh_settings.sql`
   - `server/sql/migrations/add_wazuh_outbox.sql`
   Fresh databases created with current `server/sql/schema.sql` already include both tables.
2. Admin > Settings > Wazuh SIEM Integration: set Wazuh Manager IP and **TCP syslog** port (e.g. 514).
3. For each accepted `POST /api/agent_report.php`, DLP Server writes its `logs` row and an outbox entry, then attempts a best-effort delivery of one due log immediately.
4. Set up Windows Task Scheduler to retry pending events each minute. Example (adjust XAMPP and repo paths):
   - Program: `C:\xampp\php\php.exe`
   - Arguments: `C:\xampp\htdocs\dlp_server\cli\wazuh_flush.php`
   - Trigger: Repeat every 1 minute indefinitely.
   - Run as a dedicated restricted account that can read server PHP files and connect to MySQL.
   Or run manually in CMD:
   ```cmd
   C:\xampp\php\php.exe C:\xampp\htdocs\dlp_server\cli\wazuh_flush.php
   ```
   Worker output is `{"sent":N,"failed":N,"skipped":N}`. It accepts **CLI only**, not HTTP.
5. Inspect pending delivery status in phpMyAdmin:
   ```sql
   SELECT log_id, attempts, next_attempt_at, sent_at, last_error
   FROM dlp_wazuh_outbox ORDER BY log_id DESC LIMIT 20;
   ```
   `sent_at` indicates successful TCP write, **not Wazuh ingestion or alerting**. Failed records are retried with exponential backoff up to 5 minutes.

## Wazuh Manager configuration (Ubuntu)

Edit `/var/ossec/etc/ossec.conf`, add a separate block within `<ossec_config>` (keep existing 1514/TCP secure Agent service untouched):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>192.168.106.142</allowed-ips>
</remote>
```

**Set `allowed-ips` to the DLP Server's IP, not the Windows Agent VM IP.** If necessary, allow inbound TCP/514 through Wazuh Ubuntu firewall, then:

```bash
sudo systemctl restart wazuh-manager
sudo ss -lntp | grep ':514'
```

On the DLP Server, verify network access to Wazuh TCP/514:
```powershell
Test-NetConnection <WAZUH-MANAGER-IP> -Port 514
```

Official receiver reference: https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html

## Example event

```text
<134>Nov 03 22:30:00 PC-01 DLPServer: {"integration":"DLPServer","log_id":55,"hostname":"PC-01","policy_id":2,"exit_point_type":"BROWSER_CHROME","action_taken":"BLOCKED_BROWSER","file_path":"secret.txt","occurred_at":"2026-11-03 15:30:00Z"}
```

Forwarded event fields include log_id, hostname, policy_id, exit_point_type, action_taken, file_path, SHA256 hash, matched_rule_ids, confidence_score, destination_value, process_name and occurred_at. Wazuh may need a custom decoder/rule to display the metadata and trigger a DLP alert. Check `/var/ossec/logs/alerts/alerts.json` or use `wazuh-logtest`; reception itself does not necessarily create an alert.

## Known limits

- Syslog TCP is **unencrypted and unauthenticated**: use only in isolated lab networks, not untrusted/public networks.
- Sender requires PHP streams (standard PHP) and MySQL. TCP connect timeout is 1.5 seconds, write timeout 2 seconds.
- No delivery acknowledgment from Wazuh, only TCP write success. Retry may create duplicates; deduplicate using `log_id`.
- If Wazuh IP/port is not configured, newly ingested logs are stored in DLP MySQL only, without outbox entries. Old logs are not retroactively enqueued.
- Changing the destination IP/port updates the next send attempt; queue uses the current saved destination.
- Server-admin IP/port validation prevents invalid targets but **is not an SSRF protection boundary against a malicious admin**. Restrict who can edit SIEM configuration.
- Endpoint-side Wazuh forwarding was removed from Agent V2; do not publish or install old binaries with `WazuhSyslogForwarder.cs`.
