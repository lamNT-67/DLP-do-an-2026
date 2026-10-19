# Protocol blocking — Windows User Mode / Windows Firewall (LAB)

## Scope and limitations

This module implements actual automatic outbound firewall blocks for **known Windows CLI client executables**, without an extension or proxy. It does **not** inspect the contents of encrypted traffic or selectively block by file extension. It is intentionally disabled by default.

| Server policy Exit Point | Executable (Windows built-in path) | Outbound TCP remote port | Control |
|---|---|---:|---|
| `CLIENT_SCP` | `C:\\Windows\\System32\\OpenSSH\\scp.exe` | 22 | Entire SCP connection |
| `CLIENT_SFTP` | `C:\\Windows\\System32\\OpenSSH\\sftp.exe`, `C:\\Windows\\System32\\curl.exe` | 22 | Entire SFTP connection |
| `CLIENT_FTP` | `C:\\Windows\\System32\\ftp.exe`, `C:\\Windows\\System32\\curl.exe` | 21 | Entire FTP control connection |
| `NETWORK_SCP_SFTP` (legacy) | SCP and SFTP above | 22 | Both |
| `NETWORK_FTP` (legacy) | FTP above | 21 | FTP |

**OpenSSH Windows behavior:** `scp.exe` and `sftp.exe` may spawn `C:\\Windows\\System32\\OpenSSH\\ssh.exe`, which owns the TCP 22 socket. The Agent now also creates a `DLPAgent Protocol SSH-TRANSPORT` rule when SCP or SFTP blocking is selected. This **also prevents ordinary interactive `ssh.exe` connections to port 22**. A program-specific Windows Firewall rule cannot distinguish between the SSH session's SCP/SFTP subsystem and interactive shell usage. Verify with `scp -v` and `Get-NetFirewallRule -DisplayName 'DLPAgent Protocol *'` on the test VM.

Rules use built-in `New-NetFirewallRule` with `-Program`, `-Protocol TCP`, `-RemotePort`, `-Direction Outbound`, and `-Action Block`. Only files at these **standard Windows paths** are covered. Alternate installs, custom clients, nonstandard ports, proxies, other protocols and tunneling can bypass these rules. This does not block SSH terminal commands (`ssh.exe`) and does not intercept WinSCP or FileZilla.

**Important policy semantics:** A BLOCK policy with `CLIENT_SCP` and selected `.txt` causes *every* matching `scp.exe` connection to TCP 22 to fail, **including JPGs**. The file_types field is ignored by this firewall module. Use this only when full-protocol denial is intended. `REPORT_ONLY` does not create blocks. Windows Firewall blocks themselves do not produce per-file DLP server logs with this prototype.

## Enable on an isolated Windows VM

1. Update XAMPP server's policy form and create an active BLOCK policy assigned to the VM Device. Select `CLIENT_SCP` (for SCP test). Checkboxes for file types are currently used by other modules, not firewall.
2. Pull `agent-test`, update/reinstall Agent with `installer/install.ps1`.
3. Edit `C:\\ProgramData\\DLPAgent\\agent.json` as Administrator (keep valid JSON), adding:
   ```json
   "protocol_firewall_enabled": true
   ```
   Ensure the previous JSON field has a separating comma.
4. `Restart-Service DLPAgent`. Wait for policy refresh (typically 60 sec).
5. Inspect the actual rules in an elevated PowerShell:
   ```powershell
   Get-NetFirewallRule -DisplayName 'DLPAgent Protocol *' |
     Get-NetFirewallApplicationFilter | Select-Object Program
   Get-NetFirewallRule -DisplayName 'DLPAgent Protocol *' |
     Get-NetFirewallPortFilter | Select-Object Protocol, RemotePort
   ```
   If there are no rules, verify that the machine's `policy.json` includes a BLOCK policy with `CLIENT_SCP`, the config toggle is enabled, and Windows Defender Firewall is functioning.
6. Test **directly** (not through the guarded launcher):
   ```powershell
   scp.exe "$env:TEMP\\secret.txt" kali@192.168.106.131:/home/kali/Public/
   ```
   Expected: outbound TCP connection to port 22 is blocked for Windows system `scp.exe` and upload fails. If a previously established connection stays open, retry a new process.
7. Change Server policy to REPORT_ONLY / disable it, wait for sync; the Agent removes its own firewall rules and new SCP connections should work again. Do not test on a machine with important SSH/FTP workflows.

## Disabling / uninstall cleanup

Rules persist in Windows Firewall even if Agent is stopped. **Simply switching config `protocol_firewall_enabled` to false does not remove pre-existing firewall rules.** To disable:
1. Change policy to REPORT_ONLY (or deactivate policy) and allow the running enabled Agent to sync and clear rules.
2. Or run elevated:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\\protocol-guard\\clear-firewall-rules.ps1
   ```
   Then set `protocol_firewall_enabled` to false and restart Agent.
   
Use this cleanup script before uninstalling if protocol firewall mode has been used.

## App-specific integration requirements

- Chrome/Edge: extension remains required for current selective HTTPS file-type upload blocking; **no explicit proxy**.
- Firefox: requires Firefox extension for selective browser upload protection.
- SCP/SFTP/FTP CLI: no extension/proxy for these full-port blocks; selective per-file mode is still only a guarded launcher.
- WinSCP/FileZilla: **not covered by these CLI rules**; can be added later as a separate executable + port firewall block without extension or proxy. Selective per-file blocking in these native apps needs deeper client integration or another OS control point, not ordinary firewall rules.
