# File type only policy for managed SCP / SFTP / FTP (lab)

## Behavior

Content scanning has been REMOVED from the managed transfer path. No Regex,
Dictionary, file reads or byte inspection. For SCP/SFTP/FTP, the Agent uses
only the **source filename extension** selected in an applicable policy.
For example, policy with exit point `CLIENT_SCP` (or `NETWORK_SCP_SFTP`),
File Type `txt`, action `BLOCK`: `secret.txt` is rejected before any
network connection; `photo.jpg` is allowed. Selected File Types mean BLOCK
regardless of `always_block_regardless_content` or Content Rules. Policy
exceptions for allowed file names/paths and directory paths still apply.

**IMPORTANT:** A standard unmodified `scp.exe` command is NOT transparently
controlled. Only commands using the managed wrapper/launcher are checked.
Direct `C:\\Windows\\System32\\OpenSSH\\scp.exe` and other SCP clients bypass
this lab mechanism. Shell alias/function does NOT prevent a user from bypassing
the wrapper.

## Deploy

1. In Admin PowerShell, remove old broad port 22 firewall rules:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\\protocol-guard\\clear-firewall-rules.ps1
   Get-NetFirewallRule -DisplayName 'DLPAgent Protocol *' -ErrorAction SilentlyContinue
   ```
2. Change `C:\\ProgramData\\DLPAgent\\agent.json` to
   `"protocol_firewall_enabled": false`, restart service.
3. Pull branch and rebuild:
   ```powershell
   git pull origin agent-test
   dotnet build .\\DlpAgent\\DlpAgent.csproj -c Release
   powershell -ExecutionPolicy Bypass -File .\\installer\\install.ps1
   ```
4. Deploy updated `server/api/agent_report.php`, `server/admin/logs.php`
   and run migration `server/sql/migrations/add_blocked_transfer.sql` once.

## Make `scp` work in current PowerShell session

Run from `agent-v2` directory:

```powershell
$wrapper = (Resolve-Path .\\protocol-guard\\scp-wrapper.ps1).Path
function global:scp { & $wrapper -ScpArgs $args }
Get-Command scp
```

Run `Get-Command scp` to verify `CommandType = Function` before relying on
checks. Function is scoped to current PowerShell session only. Close/reopen
the terminal to return to normal native `scp`.

## Try policy BLOCK `.txt`

```powershell
Set-Content "$env:TEMP\\secret.txt" "Test"
Set-Content "$env:TEMP\\image.jpg" "Test"
scp "$env:TEMP\\secret.txt" kali@192.168.106.131:/home/kali/Public/
scp "$env:TEMP\\image.jpg" kali@192.168.106.131:/home/kali/Public/
```

The first command should print `DLP BLOCK`, exit before launching SSH and
submit `BLOCKED_TRANSFER` to Agent/Server (assuming server migration is deployed).
The second command invokes the installed Windows OpenSSH `scp.exe` normally.

For an inspector-only test:
```powershell
& "$env:ProgramFiles\\DLPAgent\\DlpAgent.exe" --inspect-file SCP "$env:TEMP\\secret.txt"
```
Note `--inspect-file` is retained for CLI compatibility: it **does not
read the file content** anymore. It checks that the local file exists and
evaluates only its name/extension.

The wrapper intentionally rejects advanced SCP options (`-r`, `-P`, `-i`),
wildcards, remote sources and non-upload usages: unsupported syntax fails
closed, not silently allowed. Multiple local files can be provided and each
is checked before a single SCP process starts. This is a demonstrator, not a
production-wide transparent SCP interception or bypass-proof DLP system.
