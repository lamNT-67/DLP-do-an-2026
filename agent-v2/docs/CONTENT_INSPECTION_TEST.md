# Managed SCP/SFTP/FTP file inspection — first working scope

**This does NOT intercept arbitrary direct scp.exe, sftp.exe, curl.exe or WinSCP/FileZilla uploads.** It replaces the old port-blocking demonstration with content-aware enforcement for transfers launched through `guarded-upload.ps1`. Windows Service continues to synchronize policies and submit logs; the inspection subprocess scans with the invoking user's permissions.

## What changed

- `DlpAgent.exe --inspect-file SCP|SFTP|FTP C:\\path\\file.txt`: retrieves the local policy via 127.0.0.1:18765 and scans files before upload. Returns JSON `BLOCK`, `ALLOW`, or `REPORT_ONLY`.
- Applies the matching `CLIENT_SCP`, `CLIENT_SFTP`, `CLIENT_FTP` or older `NETWORK_SCP_SFTP`/`NETWORK_FTP` policy.
- Selected File Types define the scan scope; `always_block_regardless_content` blocks regardless of content.
- When Content Rules are selected, matches Regex or comma-separated Dictionary values for **small plain-text files**: txt, csv, log, json, xml, md, ini, cfg, conf, yaml, yml, ps1, bat, sql, html, htm, js, css.
- If no Content Rules are selected, a selected File Type is matched unconditionally.
- File paths/names and directory allow lists are considered.
- Limits reads to 2 MiB and regex evaluation to 150ms/rule; selected files too large or formats not supported with Content Rules are blocked conservatively.
- Managed launcher sends event to DLP Agent, which forwards `BLOCKED_TRANSFER` or `LOGGED` to PHP Server, including filename, destination and matched rule IDs.

## Database / Server update

Run `server/sql/migrations/add_blocked_transfer.sql` against existing `dlp_system`, then deploy updated `server/api/agent_report.php` and `server/admin/logs.php` from `agent-test`.

## Safe Windows setup

1. **Remove experimental whole-protocol firewall rules**, from Administrator PowerShell in `agent-v2`:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\\protocol-guard\\clear-firewall-rules.ps1
   ```
2. Set `"protocol_firewall_enabled": false` in `C:\\ProgramData\\DLPAgent\\agent.json`. Just setting false is insufficient to remove previously created rules; do step 1 too.
3. Pull branch `agent-test` and reinstall Windows Service:
   ```powershell
   git pull origin agent-test
   dotnet build .\\DlpAgent\\DlpAgent.csproj -c Release
   powershell -ExecutionPolicy Bypass -File .\\installer\\install.ps1
   ```
4. Ensure the Server assigned a BLOCK policy to `PC-TEST-01` (or its group), with Exit Point `CLIENT_SCP` or `NETWORK_SCP_SFTP`, File Type `txt`, optional Content Rule `PII_CCCD`.

## Verification

Create files:

```powershell
Set-Content "$env:TEMP\\sensitive.txt" "CCCD: 012345678901"
Set-Content "$env:TEMP\\normal.txt" "Hello world"
```

From the `agent-v2` directory:

```powershell
& "$env:ProgramFiles\\DLPAgent\\DlpAgent.exe" --inspect-file SCP "$env:TEMP\\sensitive.txt"
& "$env:ProgramFiles\\DLPAgent\\DlpAgent.exe" --inspect-file SCP "$env:TEMP\\normal.txt"

powershell -ExecutionPolicy Bypass -File .\\protocol-guard\\guarded-upload.ps1 `
  -Protocol SCP -File "$env:TEMP\\sensitive.txt" `
  -Destination "kali@192.168.106.131:/home/kali/Public/" -DryRun
powershell -ExecutionPolicy Bypass -File .\\protocol-guard\\guarded-upload.ps1 `
  -Protocol SCP -File "$env:TEMP\\normal.txt" `
  -Destination "kali@192.168.106.131:/home/kali/Public/" -DryRun
```

The sensitive file should return `BLOCK` and should never invoke `scp.exe`. The normal one should return `ALLOW` when only `PII_CCCD` content rule is selected. A real transfer without `-DryRun` should work for normal files, provided Kali SSH credentials and networking work.

In the Server Logs tab, check `BLOCKED_TRANSFER`; a local report failure is printed by the script, while blocking still happens.

**Important limitations:** `scp.exe secret.txt ...` directly remains **unprotected**. The test VM browser extension is unrelated to this script. File types beyond the listed plain-text formats (e.g. docx, xlsx, pdf) are not yet parsed for content and selected files are conservatively denied if content checks are configured. Large text files are denied instead of partially inspected. Regex and dictionary matches are for text, not OCR or compressed archive extraction. The CLI local event channel is not cryptographically authenticated and is not tamper-resistant. The localhost policy snapshot exposes rule patterns to local users; do not use this design for production without secure IPC, access controls and a client-integrity model.
