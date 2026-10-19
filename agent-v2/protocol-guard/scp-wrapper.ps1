# SCP-only managed command wrapper for PowerShell sessions.
# Supports one or multiple local source files and one remote destination.
# Deliberately rejects flags, recursive transfers, remote sources, and globbing.
# Unknown syntax fails closed rather than silently invoking uninspected SCP.
param(
    [Parameter(Mandatory=$true)][string[]]$ScpArgs
)
$ErrorActionPreference = 'Stop'
if ($ScpArgs.Count -lt 2) { throw 'Usage: scp <local-file> [local-file...] user@host:/remote/path/' }
$destination = $ScpArgs[-1]
if ($destination -notmatch '^(?:[^\\\s:]+@)?[^\\\s:]+:.+') {
    throw 'DLP SCP wrapper supports uploads to remote user@host:/path/ only'
}
$files = @($ScpArgs[0..($ScpArgs.Count - 2)])
foreach ($arg in $files) {
    if ($arg.StartsWith('-') -or $arg -match '[*?]') {
        throw "DLP SCP wrapper does not support options/wildcards: $arg"
    }
    if ($arg -match '^(?:[^\\\s:]+@)?[^\\\s:]+:.+') {
        throw "DLP SCP wrapper does not support remote source files: $arg"
    }
    $resolved = Resolve-Path -LiteralPath $arg -ErrorAction Stop
    if ($resolved.Count -ne 1 -or -not [IO.File]::Exists($resolved.ProviderPath)) {
        throw "DLP SCP wrapper requires existing regular local file: $arg"
    }
    $file = $resolved.ProviderPath
    $agentExe = Join-Path $env:ProgramFiles 'DLPAgent\DlpAgent.exe'
    if (-not (Test-Path -LiteralPath $agentExe)) { throw 'DLP Agent executable missing' }
    $json = & $agentExe --inspect-file SCP $file
    if ($LASTEXITCODE -ne 0) { throw 'DLP local file-type policy unavailable: fail closed' }
    try { $check = ($json | Out-String | ConvertFrom-Json -ErrorAction Stop) }
    catch { throw 'Invalid DLP policy decision: fail closed' }
    Write-Host ("DLP {0}: {1} ({2})" -f $check.decision, [IO.Path]::GetFileName($file), $check.reason)
    if ($check.policy_id -and $check.decision -in @('BLOCK','REPORT_ONLY')) {
        $payload = @{
            channel = 'SCP'
            policy_id = [int]$check.policy_id
            action = [string]$check.decision
            file_name = [IO.Path]::GetFileName($file)
            destination = $destination
            matched_rule_ids = @()
        } | ConvertTo-Json -Depth 4 -Compress
        try {
            $null = Invoke-RestMethod -Uri 'http://127.0.0.1:18765/transfer-event' -Method Post `
                -ContentType 'application/json' -Headers @{ 'X-DLP-Client'='ManagedTransfer' } `
                -Body $payload -TimeoutSec 10
        } catch {
            if ($check.decision -eq 'BLOCK') {
                Write-Warning "DLP blocked file but logging failed: $_"
            } else {
                throw "DLP report-only event could not reach Agent: $_"
            }
        }
    }
    if ($check.decision -eq 'BLOCK') {
        Write-Warning "DLP BLOCK: .$([IO.Path]::GetExtension($file).TrimStart('.')) is denied; connection was not opened."
        exit 3
    }
    if ($check.decision -notin @('ALLOW','REPORT_ONLY')) { throw 'Unknown policy action' }
}
# Do not resolve via PATH (would recurse into wrapper). Use built-in Windows OpenSSH.
$nativeScp = Join-Path $env:WINDIR 'System32\OpenSSH\scp.exe'
if (-not [IO.File]::Exists($nativeScp)) { throw "Windows OpenSSH scp.exe missing: $nativeScp" }
& $nativeScp @ScpArgs
exit $LASTEXITCODE
