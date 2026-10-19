# Lab-only controlled upload launcher. This is NOT transparent system-wide interception.
# Examples:
# .\guarded-upload.ps1 -Protocol SCP -File C:\Lab\test.txt -Destination user@192.168.1.50:/tmp/
# .\guarded-upload.ps1 -Protocol FTP -File C:\Lab\test.txt -Destination ftp://192.168.1.50/upload/test.txt
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('SCP','SFTP','FTP')][string]$Protocol,
    [Parameter(Mandatory)][string]$File,
    [Parameter(Mandatory)][string]$Destination,
    [string]$Username,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$source = (Resolve-Path -LiteralPath $File -ErrorAction Stop).ProviderPath
if (-not [IO.File]::Exists($source)) { throw 'Source must be a regular file' }
# Run the same C# inspection engine as the Agent, but under the CALLER'S
# Windows account. It cannot inspect files the user does not have permission to read.
$agentExe = Join-Path $env:ProgramFiles 'DLPAgent\DlpAgent.exe'
if (-not (Test-Path -LiteralPath $agentExe -PathType Leaf)) {
    throw "DLP inspection executable not found: $agentExe"
}
# Exit status 4 means inspection/policy unavailable. Fail closed.
$raw = & $agentExe --inspect-file $Protocol $source
if ($LASTEXITCODE -ne 0) {
    throw "DLP inspection failed (exit $LASTEXITCODE). Refusing transfer."
}
try { $decision = ($raw | Out-String | ConvertFrom-Json -ErrorAction Stop) }
catch { throw "DLP inspector returned invalid JSON. Refusing transfer." }
Write-Host ("DLP: decision={0}; reason={1}; policy={2}" -f $decision.decision, $decision.reason, $decision.policy_id)
if ($decision.policy_id -and $decision.decision -in @('BLOCK','REPORT_ONLY')) {
    $body = @{
        channel = $Protocol
        policy_id = [int]$decision.policy_id
        action = [string]$decision.decision
        file_name = [IO.Path]::GetFileName($source)
        destination = $Destination
        matched_rule_ids = @($decision.matched_rule_ids)
    } | ConvertTo-Json -Depth 6 -Compress
    try {
        $headers = @{ 'X-DLP-Client' = 'ManagedTransfer' }
        $null = Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:18765/transfer-event' `
            -ContentType 'application/json' -Headers $headers -Body $body -TimeoutSec 10
        Write-Host 'DLP event successfully reported to Agent'
    } catch {
        # Do NOT allow a blocked file through because the log server is unavailable.
        Write-Warning "DLP report not confirmed by Agent: $_"
    }
}
if ($decision.decision -eq 'BLOCK') {
    Write-Warning "DLP BLOCK: $Protocol transfer denied ($($decision.reason))."
    exit 3
}
if ($decision.decision -ne 'ALLOW' -and $decision.decision -ne 'REPORT_ONLY') {
    throw "Unknown DLP decision. Refusing transfer."
}
if ($DryRun) {
    Write-Host "DLP ALLOW (dry-run): $source -> $Destination via $Protocol"
    exit 0
}
switch ($Protocol) {
    'SCP' {
        if ($Destination -notmatch '^[^\\\s]+@[^\\\s:]+:.+' -and $Destination -notmatch '^[^\\\s:]+:.+') {
            throw 'For SCP, destination must be remote user@host:/path (no local-to-local copies)'
        }
        & scp.exe -- $source $Destination
    }
    'SFTP' {
        # curl SFTP support varies by Windows build; verify curl.exe -V lists sftp first.
        if ($Destination -notmatch '^sftp://') { throw 'SFTP destination must start with sftp://' }
        $args = @('--fail','--show-error','--upload-file',$source,$Destination)
        if ($Username) { $args += @('--user', $Username) }
        & curl.exe @args
    }
    'FTP' {
        if ($Destination -notmatch '^ftps?://') { throw 'FTP destination must start with ftp:// or ftps://' }
        $args = @('--fail','--show-error','--upload-file',$source,$Destination)
        if ($Username) { $args += @('--user', $Username) }
        & curl.exe @args
    }
}
exit $LASTEXITCODE
