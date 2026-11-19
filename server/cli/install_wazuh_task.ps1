# Run as Administrator ON THE WINDOWS DLP SERVER (XAMPP).
# Installs a local Task Scheduler job that retries queued DLP -> Wazuh events each minute.
param(
    [string]$PhpExe = 'C:\xampp\php\php.exe',
    [string]$TaskName = 'DLP-Wazuh-Forwarder'
)
$ErrorActionPreference = 'Stop'

$worker = Join-Path $PSScriptRoot 'wazuh_flush.php'
if (-not (Test-Path -LiteralPath $PhpExe -PathType Leaf)) {
    throw "PHP executable not found: $PhpExe. Specify -PhpExe with your real XAMPP PHP path."
}
if (-not (Test-Path -LiteralPath $worker -PathType Leaf)) {
    throw "Wazuh CLI worker not found: $worker"
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open PowerShell as Administrator on the Windows DLP Server.'
}

$action = New-ScheduledTaskAction -Execute $PhpExe -Argument ('"{0}"' -f $worker)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 1) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "Installed $TaskName. PHP: $PhpExe. Worker: $worker"
Get-ScheduledTaskInfo -TaskName $TaskName | Format-List LastRunTime,LastTaskResult,NextRunTime
