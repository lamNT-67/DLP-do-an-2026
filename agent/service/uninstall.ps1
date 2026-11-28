param([switch]$RemoveFiles, [switch]$NoPrompt)
$ErrorActionPreference = 'Stop'

if (-not [Environment]::Is64BitProcess -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    Write-Host 'Use 64-bit Windows PowerShell on AMD64 Windows to run DLP uninstall.' -ForegroundColor Red
    exit 1
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argsForChild = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    if ($RemoveFiles) { $argsForChild += '-RemoveFiles' }
    if ($NoPrompt) { $argsForChild += '-NoPrompt' }
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    try {
        $child = Start-Process -FilePath $powershell -Verb RunAs -ArgumentList $argsForChild -Wait -PassThru
        exit $child.ExitCode
    } catch {
        for ($cause = $_.Exception; $cause; $cause = $cause.InnerException) {
            if ($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -eq 1223) { exit 1223 }
        }
        Write-Host ("Could not start elevated DLP uninstall. " + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}

$state = $null
$curlDeployment = $null
$layout = $null
$recovery = $null
$recoveryHandle = $null
$cutoverStarted = $false
$exitCode = 0
$originalModulePath = $env:PSModulePath
try {
    $env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
    foreach ($file in 'curl_task.ps1', 'installer_python.ps1', 'installer_migration.ps1', 'installer_services.ps1') {
        . (Join-Path $PSScriptRoot $file)
    }
    $state = Open-DlpSetupState
    $curlDeployment = Open-CurlDeployment $false
    if ($curlDeployment) { $folder = $curlDeployment.Folder }
    else {
        $scheduler = New-Object -ComObject 'Schedule.Service'
        $scheduler.Connect()
        $folder = $scheduler.GetFolder('\')
    }
    $inventory = Get-DlpSharedInventory $folder
    if ($RemoveFiles) {
        $layout = Open-DlpLayout 'C:\DLP' 'C:\ProgramData\DLP'
        Assert-DlpInstallIdentity $layout $inventory $curlDeployment
    }
    $recovery = New-DlpRecoveryDirectory $state
    if ($layout) {
        $recoveryHandle = Open-DlpProtectedDirectory $recovery
        Assert-DlpSameVolume $layout.Volume $recoveryHandle
    }

    if ($curlDeployment) { Enter-CurlMaintenance $curlDeployment $curlDeployment.Task }
    Start-DlpCutover $state $recovery
    $cutoverStarted = $true
    Stop-DlpSharedWork $folder $inventory
    Remove-DlpSharedRegistrations $folder $inventory
    Uninstall-CurlTask $curlDeployment $RemoveFiles.IsPresent
    if ($layout) { Move-DlpLayout $layout $recoveryHandle $recovery }

    if ($inventory.Tasks.ContainsKey('DLPClipboardAgent')) {
        $edge = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
        $setting = Get-ItemProperty -LiteralPath $edge -Name WebCaptureEnabled -ErrorAction SilentlyContinue
        if ($setting -and $setting.WebCaptureEnabled -eq 0) { Remove-ItemProperty -LiteralPath $edge -Name WebCaptureEnabled }
    }
    $patterns = @()
    if ($inventory.Services.ContainsKey('DLPNetworkAgent')) { $patterns += 'DLP_Block_*' }
    if ($inventory.Services.ContainsKey('DLPSftpScpAgent')) { $patterns += 'DLP_BlockSftp_*' }
    foreach ($pattern in $patterns) {
        Get-NetFirewallRule -PolicyStore PersistentStore -DisplayName $pattern -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    }
    [IO.File]::Delete($state.Pending)
    Write-Host 'DLP services and scheduled tasks withdrawn.'
    if ($layout.Install -or $layout.Data) { Write-Host "Shared files and logs retained at '$recovery'." }
} catch {
    $exitCode = 1
    Write-Host ("DLP uninstall failed. " + $_.Exception.Message) -ForegroundColor Red
    if ($cutoverStarted) { Write-Warning "Cutover is held for review at '$recovery'. See INSTALLER_PYTHON.md." }
} finally {
    try {
        if ($recoveryHandle) { $recoveryHandle.Dispose() }
        if ($layout) { Close-DlpLayout $layout }
        if ($curlDeployment) { Close-CurlDeployment $curlDeployment }
    } finally {
        if ($state) { $state.Lock.Dispose() }
        $env:PSModulePath = $originalModulePath
    }
    if (-not $NoPrompt) { Read-Host 'Press Enter to close' }
}
exit $exitCode
