[CmdletBinding()]
param([switch]$RemoveState)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator.'
}
$svc = Get-Service DLPAgent -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Stop-Service DLPAgent -Force
        (Get-Service DLPAgent).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete DLPAgent
    if ($LASTEXITCODE -ne 0) { throw 'Unable to remove DLPAgent service' }
}
Start-Sleep 2
$installDir = Join-Path $env:ProgramFiles 'DLPAgent'
if (Test-Path $installDir) { Remove-Item $installDir -Force -Recurse }
if ($RemoveState) {
    $dataDir = Join-Path $env:ProgramData 'DLPAgent'
    if (Test-Path $dataDir) { Remove-Item $dataDir -Force -Recurse }
    Write-Warning 'Local registration token removed; device registration on server is NOT removed.'
} else {
    Write-Host 'Local registration and policy state preserved. Use -RemoveState to remove it.'
}
Write-Host 'Uninstalled DLPAgent'
