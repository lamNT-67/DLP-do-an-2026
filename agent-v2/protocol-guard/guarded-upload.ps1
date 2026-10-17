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
$extension = [IO.Path]::GetExtension($source).TrimStart('.').ToLowerInvariant()
$bucket = $Protocol.ToLowerInvariant()
try {
    $policy = Invoke-RestMethod -Uri 'http://127.0.0.1:18765/rules' -TimeoutSec 3
    if (-not $policy.updated) { throw 'Agent has no synchronized policy' }
} catch {
    throw 'DLP local policy not reachable. Refusing guarded upload (fail closed).'
}
$rules = @($policy.$bucket | Where-Object { @($_.extensions) -contains $extension })
if ($rules | Where-Object { $_.action -eq 'BLOCK' }) {
    Write-Warning "DLP BLOCK: $Protocol upload denied for .$extension file (policy matched)."
    exit 3
}
if ($rules | Where-Object { $_.action -eq 'REPORT_ONLY' }) {
    Write-Host "DLP REPORT_ONLY: .$extension matched. This launcher does not yet send an event."
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
