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

. (Join-Path $PSScriptRoot 'curl_task.ps1')
$curlDeployment = $null
try {
    $curlDeployment = Open-CurlDeployment $false
    Uninstall-CurlTask $curlDeployment $RemoveFiles.IsPresent
} catch {
    Close-CurlDeployment $curlDeployment
    Write-Error ("Uninstall stopped before shared teardown: " + $_.Exception.Message)
    exit 1
}
try {
$nssm = 'C:\DLP\tools\nssm.exe'
foreach ($n in 'DLPNetworkAgent', 'DLPSftpScpAgent', 'DLPBrowserAgent') {
    if (Get-Service $n -ErrorAction SilentlyContinue) {
        Stop-Service $n -Force -ErrorAction SilentlyContinue
        if (Test-Path $nssm) { & $nssm remove $n confirm 2>&1 | Out-Null }
        else { sc.exe delete $n | Out-Null }
        Write-Host "Da xoa service $n"
    }
}

Stop-ScheduledTask -TaskName 'DLPNotifier' -ErrorAction SilentlyContinue
Stop-ScheduledTask -TaskName 'DLPClipboardAgent' -ErrorAction SilentlyContinue; Get-CimInstance Win32_Process -Filter "name='python.exe'" | Where-Object { $_.CommandLine -like '*clipboard_agent*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; Unregister-ScheduledTask -TaskName 'DLPClipboardAgent' -Confirm:$false -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name WebCaptureEnabled -ErrorAction SilentlyContinue; Unregister-ScheduledTask -TaskName 'DLPNotifier' -Confirm:$false -ErrorAction SilentlyContinue
Write-Host 'Da xoa tac vu thong bao DLPNotifier'
Get-NetFirewallRule -DisplayName 'DLP_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host 'Da xoa firewall rule DLP_*'

if ($RemoveFiles) {
    Start-Sleep 2
    Remove-Item 'C:\DLP' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item 'C:\ProgramData\DLP' -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host 'Da xoa C:\DLP va C:\ProgramData\DLP'
}
} finally { Close-CurlDeployment $curlDeployment }
Read-Host "`nNhan Enter de dong"
