# Browser BLOCK -> Agent -> Server logs (agent-test)

When the browser extension blocks a selected `File` by policy, it now sends
`REPORT_BROWSER_BLOCK` from its content script to its background service
worker. The worker forwards a JSON event to `http://127.0.0.1:18765/event`.
The Windows Agent rechecks policy ID, file extension and browser channel,
then sends an authenticated `agent_report.php` event:
- `exit_point_type`: `BROWSER_CHROME` or `BROWSER_EDGE` (Firefox prepared in Agent)
- `action_taken`: `BLOCKED_BROWSER`
- `file_path`: filename only, not the full local file path
- `destination_value`: website origin (domain with scheme and port)
- `process_name`: `chrome.exe` or `msedge.exe`
- `policy_id`: matching policy

**Server deployment required** before the new Agent will report successfully:

1. Run `server/sql/migrations/add_application_channels.sql` if not already applied.
2. Run `server/sql/migrations/add_blocked_browser.sql` **once** on existing `dlp_system`.
3. Copy current branch's `server/api/agent_report.php` and `server/admin/logs.php` to running XAMPP site.
4. Update Agent and reinstall it using `agent-v2/installer/install.ps1`, preserving existing token.
5. Reload the extension in `chrome://extensions` and `edge://extensions`.
6. Verify `http://127.0.0.1:18765/rules` includes the selected browser channel
   and at least one BLOCK rule for file extension `txt`.

## Lab verification

In PowerShell:

```powershell
"demo file" | Set-Content "$env:TEMP\dlp-event-test.txt"
Get-Service DLPAgent
Invoke-RestMethod http://127.0.0.1:18765/rules | ConvertTo-Json -Depth 8
```

Open `https://dlptest.com/https-post/` or another page with a simple
file picker in the installed Chrome/Edge extension profile. Select
`dlp-event-test.txt` (policy BLOCK for this file type). The extension should
cancel selection. In **Server > Logs**, remove filters, check for
`BLOCKED_BROWSER` with `BROWSER_CHROME`/`BROWSER_EDGE`.

You can also check the database:

```sql
SELECT id,exit_point_type,action_taken,file_path,destination_value,process_name,occurred_at
FROM logs
WHERE action_taken = 'BLOCKED_BROWSER'
ORDER BY id DESC LIMIT 10;
```

If the browser blocks but no log arrives, open extension Service Worker
console from chrome://extensions or edge://extensions and search for
`[DLP] Cannot contact Agent event bridge`. If the Agent rejects a report,
check its Windows Application event log for `Browser report failed: HTTP ...`.
Check the deployed API, migration, enrollment token and clock.

Events are **best effort**: not persisted offline, not guaranteed to be
delivered if the browser/Agent/Server shuts down, and duplicates are suppressed
for three seconds by filename, policy and destination. No file contents or
credentials are sent to the Server.

Security boundary: web page code can potentially spoof main-world custom
events; local code can access loopback. Agent checks a known browser-extension
origin and active policy but **cannot cryptographically attest that an upload
was actually attempted**. These are prototype diagnostic logs, not
tamper-proof enterprise audit records.
