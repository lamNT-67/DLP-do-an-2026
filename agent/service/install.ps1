# DLP Agent installer: cai network_agent + sftp_scp_agent thanh Windows Service (tu chay cung may)
param(
    [string]$ServerUrl,
    [string]$Hostname,
    [string]$EnrollmentKey,
    [switch]$NoPrompt,
    [string]$CurlPython,
    [switch]$AllowInsecureLabServer
)
$ErrorActionPreference = 'Stop'

if (-not [Environment]::Is64BitProcess -or [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    Write-Host 'Use 64-bit Windows PowerShell on AMD64 Windows to run DLP setup.' -ForegroundColor Red
    exit 1
}

# ---- Tu xin quyen Administrator ----
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($EnrollmentKey) {
        Write-Host 'Enter the enrollment key after elevation, or use -EnrollmentKey in an already elevated console.' -ForegroundColor Red
        exit 1
    }
    Write-Host 'Requesting Administrator rights...'
    # Serialize only the non-secret inputs. The child splats decoded values
    # as data, including spaces, quotes and PowerShell metacharacters.
    $request = @{ Script = $PSCommandPath; ServerUrl = $ServerUrl; Hostname = $Hostname
        NoPrompt = [bool]$NoPrompt; CurlPython = $CurlPython
        AllowInsecureLabServer = [bool]$AllowInsecureLabServer } | ConvertTo-Json -Compress
    $data = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($request))
    $command = @'
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
$request = ConvertFrom-Json ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{0}')))
$options = @{{ ServerUrl = $request.ServerUrl; Hostname = $request.Hostname
    NoPrompt = $request.NoPrompt; CurlPython = $request.CurlPython
    AllowInsecureLabServer = $request.AllowInsecureLabServer }}
try {{
    & $request.Script @options
    exit $LASTEXITCODE
}} catch {{
    Write-Host ("DLP setup failed: " + $_.Exception.Message) -ForegroundColor Red
    exit 1
}}
'@ -f $data
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    try {
        $child = Start-Process -FilePath $powershell -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded) -Wait -PassThru
        exit $child.ExitCode
    } catch {
        for ($cause = $_.Exception; $cause; $cause = $cause.InnerException) {
            if ($cause -is [ComponentModel.Win32Exception] -and $cause.NativeErrorCode -eq 1223) {
                Write-Host 'Administrator approval was cancelled.'
                exit 1223
            }
        }
        Write-Host ("Could not start elevated DLP setup: " + $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
}

$InstallDir = 'C:\DLP'
$AgentDir = Join-Path $InstallDir 'agent'
$DataDir = 'C:\ProgramData\DLP'
$LogDir = Join-Path $DataDir 'logs'
$Source = Split-Path $PSScriptRoot -Parent

function Step($Message) { Write-Host ([Environment]::NewLine + '==> ' + $Message) -ForegroundColor Cyan }

$state = $null
$layout = $null
$recovery = $null
$recoveryHandle = $null
$curlDeployment = $null
$enrollment = $null
$sharedCutoverStarted = $false
$installed = $false
$createdServices = [Collections.Generic.List[string]]::new()
$createdTasks = [Collections.Generic.List[string]]::new()
$installExitCode = 0
$originalModulePath = $env:PSModulePath
try {
    $env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
    foreach ($file in 'curl_task.ps1', 'installer_python.ps1', 'installer_migration.ps1', 'installer_enrollment.ps1', 'installer_services.ps1') {
        . (Join-Path $PSScriptRoot $file)
    }
    $state = Open-DlpSetupState
    foreach ($root in $InstallDir, $DataDir, $state.Root, $DlpRuntimes, $CurlRoot) {
        if ($Source -ieq $root -or $Source.StartsWith($root + '\', 'OrdinalIgnoreCase')) {
            throw 'Run setup from a reviewed release source outside the installed and archived DLP directories.'
        }
    }

    Step 'Inspect existing DLP paths and registrations'
    $layout = Open-DlpLayout $InstallDir $DataDir
    foreach ($issue in @($layout.InstallIssues) + @($layout.DataIssues)) {
        if ($issue) { Write-Warning $issue }
    }
    $curlDeployment = Open-CurlDeployment $true
    $folder = $curlDeployment.Folder
    $inventory = Get-DlpSharedInventory $folder
    Assert-DlpInstallIdentity $layout $inventory $curlDeployment

    Step 'Validate enrollment before cutover'
    $enrollment = Resolve-DlpEnrollment $layout $Source $ServerUrl $Hostname $EnrollmentKey -NoPrompt:$NoPrompt -AllowInsecureLabServer:$AllowInsecureLabServer

    Step 'Select protected machine-wide Python'
    $pyExe = Resolve-CurlPython $CurlPython
    if (-not $pyExe) {
        $bootstrap = Install-DlpMachinePython
        if ($bootstrap.ExitCode -eq 3010) {
            Write-Host 'Python setup requires a reboot. Restart Windows, then rerun DLP setup.'
            exit 3010
        }
        $pyExe = $bootstrap.Path
    }
    Write-Host "Using '$pyExe' for both DLP runtimes."

    Step 'Prepare fresh executable trees and retain verified enrollment'
    $recovery = New-DlpRecoveryDirectory $state
    $recoveryHandle = Open-DlpProtectedDirectory $recovery
    Assert-DlpSameVolume $layout.Volume $recoveryHandle
    New-DlpConfigFile (Join-Path $recovery 'verified-config.ini') $enrollment -Private
    $nextInstall = Join-Path $recovery 'next-install'
    $nextData = Join-Path $recovery 'next-data'
    New-DlpDirectory $nextInstall -UsersRead
    New-DlpDirectory $nextData -UsersRead
    New-DlpLogFiles $nextData
    $nextAgent = Join-Path $nextInstall 'agent'
    $nextTools = Join-Path $nextInstall 'tools'
    [IO.Directory]::CreateDirectory($nextAgent) | Out-Null
    [IO.Directory]::CreateDirectory($nextTools) | Out-Null
    & (Join-Path ([Environment]::SystemDirectory) 'robocopy.exe') $Source $nextAgent /E /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS /NP /XD logs __pycache__ dev_tools tools service .git /XF config.ini curl_managed.py install.ps1 install.bat uninstall.ps1 uninstall.bat | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "Could not stage agent files at '$nextAgent' (robocopy exit $LASTEXITCODE)." }
    foreach ($script in (@($DlpServiceScripts.Values) + @('clipboard_agent.py', 'requirements.txt'))) {
        if (-not (Test-Path -LiteralPath (Join-Path $nextAgent $script) -PathType Leaf)) {
            throw "Missing '$script' in the reviewed agent release."
        }
    }
    New-DlpConfigFile (Join-Path $nextAgent 'config.ini') $enrollment
    $notifier = Join-Path $PSScriptRoot 'notify.ps1'
    if (Test-Path -LiteralPath $notifier -PathType Leaf) {
        $notifyDir = Join-Path $nextInstall 'notify'
        [IO.Directory]::CreateDirectory($notifyDir) | Out-Null
        Copy-Item -LiteralPath $notifier -Destination (Join-Path $notifyDir 'notify.ps1')
    } elseif ($inventory.Tasks.ContainsKey('DLPNotifier')) {
        throw "The reviewed release is missing '$notifier' for the existing notifier task."
    }
    Save-DlpNssm (Join-Path $PSScriptRoot 'nssm.exe') $recovery (Join-Path $nextTools 'nssm.exe')
    Assert-DlpProtectedTree $nextInstall

    Step 'Stage shared and managed Curl Python runtimes'
    New-DlpDirectory $DlpRuntimes -UsersRead
    $venvDir = Join-Path $DlpRuntimes (Split-Path -Leaf $recovery)
    $venvPy = New-DlpPythonVenv $pyExe $venvDir (Join-Path $nextAgent 'requirements.txt')
    Write-Host "Shared agent Python: $venvPy"
    New-CurlRelease $curlDeployment $Source $pyExe

    Step 'Request cooperative Curl shutdown'
    Enter-CurlMaintenance $curlDeployment $curlDeployment.Task

    Step 'Fence and verify shared services and task shutdown'
    Start-DlpCutover $state $recovery
    $sharedCutoverStarted = $true
    Stop-DlpSharedWork $folder $inventory

    Step 'Archive the previous installation and publish the replacement'
    Move-DlpLayout $layout $recoveryHandle $recovery -Publish
    $cfg = Join-Path $AgentDir 'config.ini'
    Assert-DlpProtectedTree $InstallDir
    foreach ($path in $DataDir, $LogDir) { Assert-CurlProtectedPath $path }

    Step 'Register and verify replacement services'
    Remove-DlpSharedRegistrations $folder $inventory
    foreach ($name in $DlpServiceScripts.Keys) { Install-DlpService $name $venvPy $LogDir $createdServices }
    Invoke-DlpSc @('config', 'DLPNetworkAgent', 'start=', 'demand')
    Invoke-DlpNssm $DlpNssm @('start', 'DLPNetworkAgent')
    if (-not $enrollment.agent.api_token) {
        $enrolled = Wait-DlpEnrollment $cfg $enrollment
        Publish-DlpEnrolledConfig $cfg $recovery $enrolled
    }
    foreach ($name in $DlpServiceScripts.Keys | Where-Object { $_ -ne 'DLPNetworkAgent' }) {
        Invoke-DlpSc @('config', $name, 'start=', 'demand')
        Invoke-DlpNssm $DlpNssm @('start', $name)
    }
    Wait-DlpServiceHealth $venvPy $pyExe
    foreach ($name in $DlpServiceScripts.Keys) { Invoke-DlpSc @('config', $name, 'start=', 'auto') }

    $scheduler = $curlDeployment.Scheduler
    if (Test-Path -LiteralPath (Join-Path $InstallDir 'notify\notify.ps1') -PathType Leaf) {
        Register-DlpDesktopTask $scheduler $folder 'DLPNotifier' $DlpNotifierArgs $createdTasks
    }
    Register-DlpDesktopTask $scheduler $folder 'DLPClipboardAgent' (Get-DlpClipboardArgs $venvPy) $createdTasks
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name WebCaptureEnabled -PropertyType DWord -Value 0 -Force | Out-Null

    Step 'Register managed Curl for the next eligible interactive logon'
    foreach ($path in $InstallDir, $AgentDir, $cfg) { Assert-CurlProtectedPath $path }
    Complete-CurlInstall $curlDeployment
    $installed = $true
    [IO.File]::Delete($state.Pending)
    Write-Host "DLP setup complete. Services and workers verified. Logs: $LogDir" -ForegroundColor Green
    if ($layout.Install -or $layout.Data) { Write-Host "Prior files and historical logs retained at '$recovery'." }
} catch {
    $installExitCode = 1
    $message = $_.Exception.Message
    foreach ($secret in $EnrollmentKey, $enrollment.agent.api_token, $enrollment.agent.enrollment_key) {
        if ($secret) { $message = $message.Replace($secret, '[redacted]') }
    }
    Write-Host ("DLP setup failed. " + $message) -ForegroundColor Red
    if ($sharedCutoverStarted) {
        if (-not $installed) { Stop-DlpFailedInstall $folder $createdServices $createdTasks }
        Write-Warning "Cutover is held for review. Recovery data: '$recovery'. See INSTALLER_PYTHON.md."
    }
    if ($curlDeployment) {
        $holdCurl = $sharedCutoverStarted -or $layout.InstallIssues.Count
        try { Undo-CurlInstall $curlDeployment -KeepDisabled:$holdCurl }
        catch { Write-Warning ("Curl recovery held for review. " + $_.Exception.Message) }
    }
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
exit $installExitCode
