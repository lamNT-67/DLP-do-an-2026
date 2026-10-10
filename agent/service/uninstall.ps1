# Go agent: xoa service + firewall rule DLP_*. Them -RemoveFiles de xoa luon C:\DLP va log.
param([switch]$RemoveFiles)
$ErrorActionPreference = 'Continue'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    if ($RemoveFiles) { $argList += '-RemoveFiles' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

$nssm = 'C:\DLP\tools\nssm.exe'
foreach ($n in 'DLPNetworkAgent', 'DLPSftpScpAgent') {
    if (Get-Service $n -ErrorAction SilentlyContinue) {
        Stop-Service $n -Force -ErrorAction SilentlyContinue
        if (Test-Path $nssm) { & $nssm remove $n confirm 2>&1 | Out-Null }
        else { sc.exe delete $n | Out-Null }
        Write-Host "Da xoa service $n"
    }
}

Get-NetFirewallRule -DisplayName 'DLP_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host 'Da xoa firewall rule DLP_*'

if ($RemoveFiles) {
    Start-Sleep 2
    Remove-Item 'C:\DLP' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item 'C:\ProgramData\DLP' -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Da xoa C:\DLP va C:\ProgramData\DLP'
}
Read-Host "`nNhan Enter de dong"
