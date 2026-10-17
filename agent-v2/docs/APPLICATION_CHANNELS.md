# Application-specific channel rollout (agent-test)

## Server migration / deployment
1. Run `server/sql/migrations/add_application_channels.sql` against your existing `dlp_system` MySQL database. Keep all previously run migrations (`add_policy_exceptions.sql`, `add_blocked_proxy.sql`).
2. Deploy the updated `server/admin/policy_form.php`, `server/api/agent_policy.php`, and `server/api/agent_report.php` from `agent-test` to the Apache/XAMPP server. Deploy relevant backend schema only for **new** databases; for existing ones use the migration.
3. Edit a DEVICE-targeted policy and use application-specific checkboxes instead of the former broad NETWORK groups. Save the policy. Restart the updated DLPAgent and inspect `C:\ProgramData\DLPAgent\policy.json`.
4. Check policy bridge: `Invoke-RestMethod http://127.0.0.1:18765/rules | ConvertTo-Json -Depth 10`.
   It now emits separate `chrome`, `edge`, `firefox`, `scp`, `sftp`, `ftp`, `winscp`, `filezilla` rule arrays.

## What is genuinely enforced now

| Policy channel | Implementation | Limitation |
|---|---|---|
| BROWSER_CHROME | Chrome browser extension content script | Best-effort file-input/drag-drop/form guard; some page JS/API upload flows bypass |
| BROWSER_EDGE | Install same Chromium extension in Edge | Same limitations as Chrome |
| BROWSER_FIREFOX | Firefox development extension | Same limits; temporary extension must be installed |
| CLIENT_SCP | `guarded-upload.ps1 -Protocol SCP` | Only when invoked via launcher; direct `scp.exe` is **not** blocked |
| CLIENT_SFTP | `guarded-upload.ps1 -Protocol SFTP` | Only launcher; other SFTP clients are **not** blocked |
| CLIENT_FTP | `guarded-upload.ps1 -Protocol FTP` | Only launcher; FileZilla is **not** blocked |
| CLIENT_WINSCP | Policy transport/data model only | **No automatic enforcement yet** |
| CLIENT_FILEZILLA | Policy transport/data model only | **No automatic enforcement yet** |

Legacy `NETWORK_WEB` maps to all browser channels in the read-only bridge, `NETWORK_SCP_SFTP` to SCP/SFTP/WinSCP, and `NETWORK_FTP` to FTP/FileZilla. This keeps old policies readable while transitioning, but does **not** add enforcement for WinSCP/FileZilla.

The separate HTTP proxy at 127.0.0.1:18766 remains a **lab-only explicit proxy**, cannot identify which browser originated traffic, and currently matches legacy `NETWORK_WEB` only. It is not a substitute for a browser integration and does not inspect HTTPS.

## Browser testing

Chrome: load unpacked extension from `agent-v2/browser-extension` at `chrome://extensions`.

Edge: load the same Chromium extension folder from `edge://extensions`.

Firefox: use `about:debugging#/runtime/this-firefox` and load `agent-v2/browser-extension/firefox/manifest.json`.

With a blocking file extension, test an ordinary HTML file input or drag-drop site. Verify selected files are cleared, and that the other browser has no channel rule when only one browser is selected. Do not claim that generic HTTPS uploads or direct SCP have been universally blocked.

## Next engineering stage

- Add a managed Windows process-control mode for known transfer clients with explicit **whole-application/network** blocking, not misrepresented as per-file blocking.
- Add upload detection and logging for supported browsers, plus test cases for fetch/XHR and dynamic uploads; user-mode browser integration cannot provide universal tamper-proof protection.
- Determine whether selective File Type control for native WinSCP/FileZilla requires explicit client integration, filesystem minifilter or other endpoint security component. Never infer file upload solely from a process opening a file and having an outbound connection.
