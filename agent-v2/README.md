# DLP Agent v2 — Windows Service prototype

**Branch:** `agent-test`. This is a new, independent C#/.NET 8 prototype. It does **not** replace or modify `agent/` (legacy Python).

## Current scope

- Register a single device using the existing PHP `agent_register.php` API.
- Persist the unique API token protected with Windows DPAPI (LocalMachine scope).
- Send heartbeat every 45 seconds (configurable).
- Fetch policies every 60 seconds (configurable), validate the JSON response, and cache it atomically.
- Install as a Windows Service called **DLPAgent**, set to automatic startup and restart-on-failure.
- Preserve token and configuration across service restarts and machine reboots.
- Avoid the previous race where two independent services both register the same hostname.
- **USB file-type monitor (test version):** detect newly created/renamed files on removable drives, match the active policy's USB exit point and extension, respect allowed_files / allowed_locations, then send events via agent_report.php. BLOCK takes priority over REPORT_ONLY. Default is **log-only**, with no file deletion until explicitly enabled.

**Not yet implemented:** kernel-level pre-write USB interception, SCP/SFTP enforcement, browser upload prevention, screenshot blocking, event retry queue, MSI packaging. USB enforcement is currently **best effort, post-write**: data may already have been copied to USB before deletion and some copies may be missed. No firewall rules or process kills are created. Use only in a disposable test VM, not as reliable DLP protection.

## Requirements

- Windows 10/11 x64 test VM.
- .NET 8 SDK for building. Output is self-contained; SDK/runtime not required on destination machine once published.
- Elevated PowerShell to register the Windows Service.
- Reachable PHP Server API (`http://SERVER/dlp_server/api`), enrollment key from server settings.
- Run `server/sql/migrations/add_policy_exceptions.sql` on existing databases before requesting active policies.

## Install

Open **PowerShell as Administrator**, from the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\agent-v2\installer\install.ps1 -ServerUrl "http://192.168.1.10/dlp_server/api" -EnrollmentKey "YOUR_ENROLLMENT_KEY" -Hostname "PC-TEST-01"
```

Use HTTPS outside an isolated lab. The installer prompts for missing values; specifying an enrollment key on the command line may leave it in shell history, so prefer omitting `-EnrollmentKey` and typing it at the prompt.

The installer builds a self-contained `win-x64` executable in a temporary folder, copies it to `C:\Program Files\DLPAgent`, creates `C:\ProgramData\DLPAgent\agent.json` with restricted ACLs, and registers a single LocalSystem Windows Service. After the first successful registration, `enrollment_key` is cleared from disk and the encrypted token is stored as `token.dat`.

To check after install or after reboot:

```powershell
Get-Service DLPAgent
sc.exe qc DLPAgent
Get-Content "C:\ProgramData\DLPAgent\policy.json"
```

The policy JSON appears after the first successful sync. Review service errors in **Event Viewer → Windows Logs → Application**. Alternatively, stop the service and run `DlpAgent.exe` manually from an elevated terminal for console logs (do not run both at once).

If the hostname already exists on the Server and `token.dat` is lost, registration will return HTTP 409. Restore the prior token securely or explicitly remove the stale device from Server before re-enrolling. Do **not** delete server data without reviewing logs.

## USB File Type block test

1. In Admin, create an **active** policy targeting this Device (or its Group), select **USB**, choose a file type (e.g. `.txt`), and choose **BLOCK**. Wait until `policy.json` reflects the change. Policy needs to match the actual file extension; no content scanning is performed.
2. Start in observation mode. Default `usb_monitor_enabled: true` and `usb_enforce_block: false`; this logs matches to Server with `action_taken: LOGGED`, without deleting files.
3. For an isolated VM/test USB with disposable files only, edit `C:\\ProgramData\\DLPAgent\\agent.json` as Administrator and set `"usb_enforce_block": true`. Restart the service with `Restart-Service DLPAgent`. A newly copied matching file on a Windows drive identified as `DriveType.Removable` will be **deleted after creation if possible** and reported with `BLOCKED_DELETE`.
4. A nonmatching file must remain. An `allowed_files` or `allowed_locations` exception also causes the file to be skipped. Do not test on valuable drives/files.

**Limits:** Requires a USB volume exposed as `DriveType.Removable`; USB external disks exposed as Fixed may not be monitored. FileSystemWatcher can miss events, and locked/long-running transfers can be missed. It does not guarantee prevention of data exfiltration; even a deleted file may have been copied. This is not a production endpoint-protection mechanism.


## Web upload and protocol upload prototypes (agent-test)

**Chrome Web Upload Guard:** The Windows Service exposes a minimal, read-only policy snapshot at `http://127.0.0.1:18765/rules` (bound only to localhost). In Chrome, open `chrome://extensions`, enable Developer mode, choose **Load unpacked**, and select `agent-v2/browser-extension`. The extension refreshes matching `NETWORK_WEB` file extensions from the Agent. Test a disposable `.txt` file using a basic HTML file picker or drag/drop form on a test webpage while an active BLOCK policy includes `NETWORK_WEB` and `.txt`. Matching selections are cleared and some file drops/submits are blocked in the page before normal handlers run. The extension needs to be installed in each browser profile; a service alone cannot block Chrome uploads.

**Firefox Web Upload Guard:** Open `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on** and choose `agent-v2/browser-extension/firefox/manifest.json`. This is a temporary development extension and disappears after browser restart unless packaged/signed properly.

**Limitations:** This is a **best-effort extension prototype**, not reliable browser upload interception. It does not guarantee prevention of fetch/XHR, dynamically generated blobs, paste uploads, network requests triggered before an extension is initialized, specialized drag/drop implementations, or unsupported tabs. Web pages cannot normally read the bridge response through CORS; however it is readable by any local process, so it intentionally contains no secret/token. Browser rule matching uses file extensions only and does not yet apply allowed-files/allowed-locations exceptions or report per-upload events to the Server. If no fresh Agent policy is available, the extension fails open to preserve browsing; do not rely on it as a security boundary.

**SCP/SFTP/FTP guarded command launcher:** For a *controlled lab transfer* use `agent-v2/protocol-guard/guarded-upload.ps1`. This launcher checks the locally synchronized Agent policy and denies transfers of matching file extensions for `NETWORK_SCP_SFTP` (SCP and SFTP) or `NETWORK_FTP` (FTP) **before invoking the client**:

```powershell
powershell -ExecutionPolicy Bypass -File .\agent-v2\protocol-guard\guarded-upload.ps1 -Protocol SCP -File C:\Lab\secret.txt -Destination "kali@192.168.106.131:/tmp/" -DryRun
powershell -ExecutionPolicy Bypass -File .\agent-v2\protocol-guard\guarded-upload.ps1 -Protocol SCP -File C:\Lab\secret.txt -Destination "kali@192.168.106.131:/tmp/"
```

For `-Protocol SFTP`, use an `sftp://...` URL and `curl.exe` with SFTP support; FTP uses `ftp://...` or `ftps://...`. Authentication is delegated to the chosen system client. Use `-DryRun` first. This launcher has **no capability to intercept arbitrary** `scp.exe`, WinSCP, FileZilla, or browser traffic if the user does not invoke the launcher. It does not create a firewall rule, terminate processes, or send protocol events to the Server. The CLI guard fails closed when it cannot fetch Agent policy. For true system-wide enforcement, additional OS/network integration is required. Do not claim those protocols are universally blocked yet.

## Uninstall


```powershell
powershell -ExecutionPolicy Bypass -File .\agent-v2\installer\uninstall.ps1
```

Add `-RemoveState` to delete the local encrypted token and cached policy too. Uninstall does not delete the device record from the PHP Server. No firewall rules are added.

## About MSI

An actual `.msi` package is a follow-on deliverable; this branch currently supplies an installer **PowerShell script**, not a built MSI. It has not been compiled or smoke-tested on Windows in this environment. Test in a disposable VM first.
