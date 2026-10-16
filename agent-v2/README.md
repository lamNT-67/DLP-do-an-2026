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

**Not yet implemented:** USB/SCP/SFTP interception, browser upload prevention, screenshot blocking, file type enforcement, policy exception evaluation, event reporting, MSI packaging. This build is intentionally **monitoring/control-plane only** and creates no firewall rules or process-kill actions. Do not use it as DLP protection yet.

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

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File .\agent-v2\installer\uninstall.ps1
```

Add `-RemoveState` to delete the local encrypted token and cached policy too. Uninstall does not delete the device record from the PHP Server. No firewall rules are added.

## About MSI

An actual `.msi` package is a follow-on deliverable; this branch currently supplies an installer **PowerShell script**, not a built MSI. It has not been compiled or smoke-tested on Windows in this environment. Test in a disposable VM first.
