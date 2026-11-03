# Wazuh SIEM integration for Agent V2 (TCP syslog, lab)

## Data flow

```
DLP event (USB / Browser / HTTP / SCP-SFTP-FTP / Firewall)
    -> Agent V2 -> HTTP POST agent_report.php -> DLP Server MySQL
    -> [only after HTTP 2xx] Agent V2 -> TCP syslog -> Wazuh Manager 4.x
```

The Agent copies **metadata** from the accepted report (hostname, policy ID, exit point, action, file path, destination, process, rule IDs, UTC timestamp). File contents, server access tokens, and enrollment keys are not forwarded.

The web configuration consists of **IP and port only** at Admin > Settings. Agent V2 downloads `wazuh: {ip, port}` through authenticated `agent_policy.php` on its regular policy refresh (~60 seconds). A null destination disables forwarding. The Agent continues to work if Wazuh is unreachable; there is no durable retry queue yet. TCP connect/send success **does not** confirm Wazuh indexed or alerted on the event.

### One-time SQL migration

Existing MySQL installations must execute `server/sql/migrations/add_wazuh_settings.sql` using phpMyAdmin (DB: `dlp_system`). Fresh schema includes the table.

### Wazuh manager 4.x receiver (Ubuntu)

Configure a **separate TCP syslog receiver** in `/var/ossec/etc/ossec.conf`, inside `<ossec_config>`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>tcp</protocol>
  <allowed-ips>192.168.106.0/24</allowed-ips>
</remote>
```

Restrict `allowed-ips` to actual DLP endpoints instead of a broad subnet in production. Open the chosen TCP port in firewall if needed. Restart:

```bash
sudo systemctl restart wazuh-manager
sudo ss -lntp | grep ':514'
```

Wazuh default **1514/TCP** is the secure Wazuh Agent protocol, NOT generic syslog; do not point the DLP emitter at 1514. This integration uses **TCP only**, not UDP or the Dashboard/API port.

See https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/syslog.html

### Enable on DLP Server and Agent

1. Deploy updated `server/admin/settings.php`, `server/api/agent_policy.php` and run SQL migration.
2. Open DLP admin Settings -> Wazuh SIEM Integration. Enter Wazuh Manager IP and syslog TCP port (e.g. 514). Save.
3. Verify DLP Agent's `C:\ProgramData\DLPAgent\policy.json` contains:
```json
"wazuh": {"ip":"192.168.106.131","port":514}
```
4. Publish Agent V2:
```powershell
dotnet publish .\DlpAgent\DlpAgent.csproj -c Release -r win-x64 --self-contained true -o C:\DLPBuild
```
5. Stop DLPAgent service, copy published files into its actual installation directory, restart. Existing HTTP and browser enforcement settings remain unchanged.
6. Trigger a **real controlled DLP event**. Inspect the Server Logs and the Agent service logs. On Ubuntu use `sudo tcpdump -n -A -i any 'tcp port 514'` for lab diagnosis (sensitive metadata may be visible); independently verify Wazuh ingestion and rule/alert creation. You may need Wazuh local decoder/rule configuration before events appear as Dashboard alerts.

### Safety / limitations

- Plain TCP syslog **is unencrypted and unauthenticated**. Use only on a trusted isolated lab network. Production needs protected transport, an authenticated collector, or a Wazuh-supported secure Agent integration.
- This forwards only events that the DLP Server accepted with HTTP 2xx. Local detections with failed primary reports are not forwarded.
- No persistent queue, retry, transport selection, connection test button, delivery acknowledgment, or Wazuh custom decoder/rules. Dashboard visibility is not guaranteed by delivery alone.
- If the Wazuh Settings table has not been migrated, the new policy endpoint returns a database error. Migrate before deployment.
