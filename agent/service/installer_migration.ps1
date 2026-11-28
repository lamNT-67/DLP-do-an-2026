# Shared filesystem and recovery operations for install and uninstall.
function New-DlpDirectory([string]$Path, [switch]$UsersRead) {
    $sddl = 'O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if ($UsersRead) { $sddl += '(A;OICI;0x1200A9;;;BU)' }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($sddl)
    [IO.Directory]::CreateDirectory($Path, $acl) | Out-Null
    Assert-CurlProtectedPath $Path
}

function Assert-DlpNoPendingCutover([string]$Root, [string]$Pending) {
    if (-not (Test-Path -LiteralPath $Pending)) { return }
    Assert-CurlProtectedPath $Pending
    $id = [IO.File]::ReadAllText($Pending)
    if (-not (Test-CurlId $id)) { throw "Interrupted setup marker '$Pending' needs administrator review." }
    throw "An interrupted DLP cutover needs review. See '$(Join-Path $Root $id)' and the recovery instructions in INSTALLER_PYTHON.md."
}

function Open-DlpSetupState {
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    Assert-DlpProtectedLocation $programFiles
    $root = Join-Path $programFiles 'DLP-Setup'
    New-DlpDirectory $root
    $lock = Join-Path $root 'setup.lock'
    $pending = Join-Path $root 'pending'
    if (Test-Path -LiteralPath $lock) { Assert-CurlProtectedPath $lock }
    try { $stream = [IO.File]::Open($lock, 'OpenOrCreate', 'ReadWrite', 'None') }
    catch { throw "Cannot lock '$lock'. Close the other DLP setup or uninstall process and retry." }
    try {
        Assert-DlpNoPendingCutover $root $pending
        if (-not ('DlpInstaller.Paths' -as [type])) {
            $oldTemp, $oldTmp = $env:TEMP, $env:TMP
            try {
                $env:TEMP = $root
                $env:TMP = $root
                Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $PSScriptRoot 'installer_paths.cs'))) -ErrorAction Stop
            } finally { $env:TEMP = $oldTemp; $env:TMP = $oldTmp }
        }
        return @{ Root = $root; Pending = $pending; Lock = $stream }
    } catch { $stream.Dispose(); throw }
}

function Open-DlpChild($Parent, [string]$Path, [switch]$Directory, [switch]$Rename) {
    try { return [DlpInstaller.Paths]::OpenChild($Parent, (Split-Path -Leaf $Path), $Directory.IsPresent, $Rename.IsPresent) }
    catch { throw "Cannot open '$Path' safely. $($_.Exception.GetBaseException().Message)" }
}

function Open-DlpProtectedDirectory([string]$Path) {
    Assert-DlpProtectedLocation $Path
    $volume = [IO.Path]::GetPathRoot($Path)
    $handle = [DlpInstaller.Paths]::OpenVolume($volume)
    try {
        foreach ($component in ($Path.Substring($volume.Length) -split '\\')) {
            if (-not $component) { continue }
            $child = [DlpInstaller.Paths]::OpenChild($handle, $component, $true, $false)
            if (-not $child) { throw "Protected directory '$Path' disappeared." }
            $handle.Dispose()
            $handle = $child
        }
        return $handle
    } catch { $handle.Dispose(); throw }
}

function Get-DlpHandleAcl($Handle, [switch]$Directory) {
    $acl = if ($Directory) { [Security.AccessControl.DirectorySecurity]::new() } else { [Security.AccessControl.FileSecurity]::new() }
    $acl.SetSecurityDescriptorBinaryForm([DlpInstaller.Paths]::SecurityDescriptor($Handle))
    return $acl
}

function Get-DlpLegacyIssue($Handle, [string]$Path, [switch]$Directory) {
    if (-not $Handle) { return }
    try { Assert-CurlAdminAcl (Get-DlpHandleAcl $Handle -Directory:$Directory) 0xD0156 $Path }
    catch [Security.SecurityException] { return $_.Exception.Message }
}

function Read-DlpEnrollmentSnapshot($Root, [string]$InstallDir) {
    if (-not $Root) { return }
    $agentPath = Join-Path $InstallDir 'agent'
    $agent = Open-DlpChild $Root $agentPath -Directory
    if (-not $agent) { return }
    try {
        $issue = Get-DlpLegacyIssue $agent $agentPath -Directory
        $path = Join-Path $agentPath 'config.ini'
        $file = Open-DlpChild $agent $path
        if (-not $file) { return @{ Issues = @($issue | Where-Object { $_ }); Identity = ''; Bytes = $null } }
        try {
            $issues = @($issue; Get-DlpLegacyIssue $file $path) | Where-Object { $_ }
            $identity = [DlpInstaller.Paths]::Identity($agent) + '/' + [DlpInstaller.Paths]::Identity($file)
            $bytes = [DlpInstaller.Paths]::ReadConfig($file)
            return @{ Issues = @($issues); Identity = $identity; Bytes = $bytes }
        } catch { throw "Cannot read '$path' safely. $($_.Exception.GetBaseException().Message)" }
        finally { $file.Dispose() }
    } finally { $agent.Dispose() }
}

function Open-DlpLayout([string]$InstallDir, [string]$DataDir) {
    $volume = [IO.Path]::GetPathRoot($InstallDir)
    Assert-DlpProtectedLocation $volume
    $layout = @{ InstallDir = $InstallDir; DataDir = $DataDir; Volume = $null; DataParent = $null; Install = $null; Data = $null }
    try {
        $layout.Volume = [DlpInstaller.Paths]::OpenVolume($volume)
        $dataParentPath = Split-Path -Parent $DataDir
        $layout.DataParent = Open-DlpChild $layout.Volume $dataParentPath -Directory
        if (-not $layout.DataParent) { throw "Missing '$dataParentPath'." }
        # Windows grants Users creation rights at ProgramData. The parent
        # must still prevent other users from replacing a protected child.
        Assert-CurlAdminAcl (Get-DlpHandleAcl $layout.DataParent -Directory) 0xD0040 $dataParentPath -ObjectOnly
        $layout.Install = Open-DlpChild $layout.Volume $InstallDir -Directory
        $layout.Data = Open-DlpChild $layout.DataParent $DataDir -Directory
        $logPath = Join-Path $DataDir 'logs'
        $logIssue = $null
        if ($layout.Data) {
            $logs = Open-DlpChild $layout.Data $logPath -Directory
            if (-not $logs) { throw "Cannot identify '$DataDir' as DLP data. Expected '$logPath'." }
            try { $logIssue = Get-DlpLegacyIssue $logs $logPath -Directory }
            finally { $logs.Dispose() }
        }
        $layout.Config = Read-DlpEnrollmentSnapshot $layout.Install $InstallDir
        $layout.InstallIssues = @(Get-DlpLegacyIssue $layout.Install $InstallDir -Directory
            $layout.Config.Issues) | Where-Object { $_ }
        $layout.DataIssues = @(Get-DlpLegacyIssue $layout.Data $DataDir -Directory
            $logIssue) | Where-Object { $_ }
        return $layout
    } catch { Close-DlpLayout $layout; throw }
}

function Close-DlpLayout($Layout) {
    foreach ($name in 'Install', 'Data', 'DataParent', 'Volume') {
        if ($Layout -and $Layout[$name]) { $Layout[$name].Dispose() }
    }
}

function New-DlpRecoveryDirectory($State) {
    $path = Join-Path $State.Root ([guid]::NewGuid().ToString('N'))
    New-DlpDirectory $path
    return $path
}

function Assert-DlpInstallIdentity($Layout, $Inventory, $Curl) {
    $registered = $Inventory.Services.Count -or $Inventory.Tasks.Count -or ($Curl -and $Curl.Task)
    if ($Layout.InstallIssues.Count -and (-not $registered -or -not $Layout.Config.Bytes)) {
        throw "Unsafe legacy '$($Layout.InstallDir)' has no recognized DLP registration or readable enrollment configuration. Review the manual recovery procedure."
    }
    if ($registered -and -not $Layout.Config.Bytes) {
        throw "A DLP registration exists without '$($Layout.InstallDir)\agent\config.ini'. Review the manual recovery procedure."
    }
    if ($Layout.Data -and -not $Layout.Config.Bytes -and -not $registered) {
        throw "Cannot establish ownership of '$($Layout.DataDir)'. Archive it after administrator review."
    }
    if ($Layout.Install -and -not $Layout.Config.Bytes -and -not $registered -and
        @(Get-ChildItem -LiteralPath $Layout.InstallDir -Force).Count) {
        throw "Cannot establish ownership of the contents of '$($Layout.InstallDir)'. Review the manual recovery procedure."
    }
}

function Start-DlpCutover($State, [string]$Recovery) {
    $bytes = [Text.Encoding]::ASCII.GetBytes((Split-Path -Leaf $Recovery))
    $stream = [IO.File]::Open($State.Pending, 'CreateNew', 'Write', 'None')
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Assert-DlpSameVolume($First, $Second) {
    if (([DlpInstaller.Paths]::Identity($First) -split ':')[0] -ne
        ([DlpInstaller.Paths]::Identity($Second) -split ':')[0]) {
        throw 'Automatic DLP cutover requires Program Files, C:\DLP and ProgramData on the same NTFS volume.'
    }
}

function Get-DlpRenameSource($Parent, [string]$Path, $Expected) {
    $source = Open-DlpChild $Parent $Path -Directory -Rename
    try {
        if ([bool]$source -ne [bool]$Expected -or
            ($source -and [DlpInstaller.Paths]::Identity($source) -cne [DlpInstaller.Paths]::Identity($Expected))) {
            throw "Directory identity changed at '$Path'. Files were preserved."
        }
        return $source
    } catch { if ($source) { $source.Dispose() }; throw }
}

function Move-DlpDirectory($Source, $DestinationParent, [string]$Destination) {
    try { [DlpInstaller.Paths]::Rename($Source, $DestinationParent, (Split-Path -Leaf $Destination)) }
    catch { throw "Cannot move directory to '$Destination'. $($_.Exception.GetBaseException().Message)" }
}

function Move-DlpLayout($Layout, $RecoveryHandle, [string]$Recovery, [switch]$Publish) {
    $install = $null
    $data = $null
    $nextInstall = $null
    $nextData = $null
    try {
        $install = Get-DlpRenameSource $Layout.Volume $Layout.InstallDir $Layout.Install
        $data = Get-DlpRenameSource $Layout.DataParent $Layout.DataDir $Layout.Data
        $snapshot = Read-DlpEnrollmentSnapshot $install $Layout.InstallDir
        $before = if ($Layout.Config.Bytes) { [Convert]::ToBase64String($Layout.Config.Bytes) }
        $after = if ($snapshot.Bytes) { [Convert]::ToBase64String($snapshot.Bytes) }
        if ($snapshot.Identity -cne $Layout.Config.Identity -or $before -cne $after) {
            throw "Enrollment changed at '$($Layout.InstallDir)\agent\config.ini' during preflight. Review the recovery data."
        }
        if ($Publish) {
            $nextInstall = Open-DlpChild $RecoveryHandle (Join-Path $Recovery 'next-install') -Directory -Rename
            $nextData = Open-DlpChild $RecoveryHandle (Join-Path $Recovery 'next-data') -Directory -Rename
            if (-not $nextInstall -or -not $nextData) { throw "Protected staging is incomplete at '$Recovery'." }
        }
        if ($install) { Move-DlpDirectory $install $RecoveryHandle (Join-Path $Recovery 'previous-install') }
        if ($data) { Move-DlpDirectory $data $RecoveryHandle (Join-Path $Recovery 'previous-data') }
        if ($Publish) {
            Move-DlpDirectory $nextData $Layout.DataParent $Layout.DataDir
            Move-DlpDirectory $nextInstall $Layout.Volume $Layout.InstallDir
        }
    } finally {
        foreach ($handle in $nextData, $nextInstall, $data, $install) { if ($handle) { $handle.Dispose() } }
    }
}

function New-DlpLogFiles([string]$DataDir) {
    $logDir = Join-Path $DataDir 'logs'
    [IO.Directory]::CreateDirectory($logDir) | Out-Null
    $acl = [Security.AccessControl.FileSecurity]::new()
    # READ and FILE_APPEND_DATA apply only to the two clipboard journal files.
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12008D;;;BU)')
    foreach ($name in 'dlp_events.log', 'clipboard_delivery.log') {
        $path = Join-Path $logDir $name
        $stream = [IO.FileStream]::new($path, 'CreateNew', 'Write', 'None', 4096, 'None', $acl)
        $stream.Dispose()
    }
}
