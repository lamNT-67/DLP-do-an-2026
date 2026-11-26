# Curl-specific deployment functions. Called only by the elevated DLP installer/uninstaller.
$CurlTaskName = 'DLPCurlAgent'
$CurlRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'DLP-Curl'
$CurlRegistry = 'SOFTWARE\DLP\ManagedCurl'
$CurlRootAcl = 'D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;;KR;;;BU)'
$CurlInstanceAcl = 'D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CIIO;KA;;;CO)(A;;0x4;;;BU)'
$CurlFiles = @('curl_managed.py', 'curl_lifecycle.py', 'curl_desktop.py', 'curl_agent.py',
    'curl_worker.py', 'curl_windows.py', 'content_inspection.py', 'log_writer.py',
    'policy_client.py', 'policy_utils.py', 'requirements.txt')

function Test-CurlId($Value) {
    $Value -is [string] -and $Value -cmatch '\A[0-9a-f]{32}\z'
}

function Assert-CurlAdminAcl($Acl, [int]$WriteMask) {
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $sidType = [Security.Principal.SecurityIdentifier]
    # Generic bits can remain unmapped in access rules, including inherit-only ACEs.
    $writeRights = $WriteMask -bor 0x50000000  # GENERIC_WRITE | GENERIC_ALL
    if ($Acl.GetOwner($sidType).Value -notin $trusted) { throw 'Curl runtime requires an administrator-owned installation.' }
    foreach ($rule in $Acl.GetAccessRules($true, $true, $sidType)) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in $trusted) { continue }
        if ($rule.IdentityReference.Value -eq 'S-1-3-0' -and ($rule.PropagationFlags -band 2)) { continue }
        $rights = if ($Acl -is [Security.AccessControl.RegistrySecurity]) { $rule.RegistryRights } else { $rule.FileSystemRights }
        if ([int]$rights -band $writeRights) { throw 'Curl runtime path grants write access outside Administrators and SYSTEM.' }
    }
}

function Assert-CurlProtectedPath([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point in managed Curl path: $Path" }
    Assert-CurlAdminAcl (Get-Acl -LiteralPath $item.FullName -ErrorAction Stop) 0xD0156
}

function Initialize-CurlConfigRoot([string]$InstallDir) {
    if (-not (Test-Path -LiteralPath $InstallDir)) {
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200A9;;;BU)')
        [IO.Directory]::CreateDirectory($InstallDir, $acl) | Out-Null
    }
    Assert-CurlProtectedPath $InstallDir
    $dir = Join-Path $InstallDir 'agent'
    if (Test-Path -LiteralPath $dir) {
        Assert-CurlProtectedPath $dir
        $config = Join-Path $dir 'config.ini'
        if (Test-Path -LiteralPath $config) { Assert-CurlProtectedPath $config }
    }
}

function Get-CurlProgramFiles([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    foreach ($base in @([Environment]::GetFolderPath('ProgramFiles'), [Environment]::GetFolderPath('ProgramFilesX86'))) {
        if ($base -and $full.StartsWith($base + '\', 'OrdinalIgnoreCase')) { return $base }
    }
    throw 'Use -CurlPython with an all-users base python.exe installed under Program Files.'
}

function Resolve-CurlPython([string]$Choice, [string]$DefaultPython) {
    $options = @()
    if ($Choice) { $options = @($Choice) }
    else {
        $options += $DefaultPython
        foreach ($entry in Get-ChildItem 'HKLM:\SOFTWARE\Python\PythonCore' -ErrorAction SilentlyContinue | Sort-Object PSChildName -Descending) {
            $key = Get-Item -LiteralPath ($entry.PSPath + '\InstallPath') -ErrorAction SilentlyContinue
            if ($key) {
                if ($key.GetValue('ExecutablePath')) { $options += $key.GetValue('ExecutablePath') }
                elseif ($key.GetValue('')) { $options += Join-Path $key.GetValue('') 'python.exe' }
            }
        }
    }
    foreach ($path in $options) {
        if (-not $path -or [IO.Path]::GetFileName($path) -ne 'python.exe') { continue }
        try {
            $path = [IO.Path]::GetFullPath($path)
            $base = Get-CurlProgramFiles $path
            $component = $path
            while ($component -ne $base) {
                Assert-CurlProtectedPath $component
                $component = Split-Path -Parent $component
            }
            Assert-CurlProtectedPath $base
            # Don't select a venv as the base of another venv.
            if (Test-Path -LiteralPath (Join-Path (Split-Path -Parent (Split-Path -Parent $path)) 'pyvenv.cfg')) { continue }
            return $path
        } catch { if ($Choice) { throw } }
    }
    throw 'Managed Curl needs an all-users installation. Pass -CurlPython with a protected Program Files base python.exe.'
}

function New-CurlRegistryAcl([string]$Sddl) {
    $acl = New-Object Security.AccessControl.RegistrySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BA' + $Sddl)
    return $acl
}

function Assert-CurlRegistryAcl($Key, [string]$Expected) {
    $actual = $Key.GetAccessControl()
    $expectedAcl = New-CurlRegistryAcl $Expected
    $section = [Security.AccessControl.AccessControlSections]::Access
    if ($actual.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin 'S-1-5-32-544','S-1-5-18' -or
        $actual.GetSecurityDescriptorSddlForm($section) -ne $expectedAcl.GetSecurityDescriptorSddlForm($section)) {
        throw 'Unexpected Curl lifecycle registry owner or permissions.'
    }
}

function Get-CurlTask($Folder) {
    try { return $Folder.GetTask($CurlTaskName) }
    catch {
        for ($cause = $_.Exception; $cause; $cause = $cause.InnerException) {
            if ($cause.HResult -eq -2147024894) { return $null }  # ERROR_FILE_NOT_FOUND
        }
        throw
    }
}

function Get-CurlLayout([string]$Generation) {
    if (-not (Test-CurlId $Generation)) { throw 'Invalid managed Curl release ID.' }
    $dir = Join-Path $CurlRoot $Generation
    return @{ Dir = $dir; Python = Join-Path $dir 'venv\Scripts\python.exe'
        Args = '-E -s -B "' + (Join-Path $dir 'curl_managed.py') + '"' }
}

function Assert-CurlOwnership($Task, [string]$Owner, [string]$Generation) {
    if (-not (Test-CurlId $Owner)) { throw 'Unexpected Curl task owner ID.' }
    $layout = Get-CurlLayout $Generation
    $def = $Task.Definition
    $act = $def.Actions.Item(1)
    if ($def.RegistrationInfo.Description -cne "DLP managed Curl $Owner" -or
        $def.Actions.Count -ne 1 -or $act.Type -ne 0 -or $act.Path -ine $layout.Python -or
        $act.Arguments -cne $layout.Args -or $act.WorkingDirectory -ine $layout.Dir) {
        throw 'DLPCurlAgent name collision or action drift. Existing task left in place.'
    }
}

function Assert-CurlSettings($Task, [bool]$Enabled) {
    $def = $Task.Definition
    $pri = $def.Principal
    $group = [string]$pri.GroupId
    if ($group -ne 'S-1-5-32-545') {
        $group = ([Security.Principal.NTAccount]::new($group)).Translate([Security.Principal.SecurityIdentifier]).Value
    }
    $s = $def.Settings
    $trg = $def.Triggers.Item(1)
    if ($group -ne 'S-1-5-32-545' -or $pri.RunLevel -ne 0 -or $pri.LogonType -ne 4 -or
        $def.Triggers.Count -ne 1 -or $trg.Type -ne 9 -or -not $trg.Enabled -or $trg.UserId -or
        [Xml.XmlConvert]::ToTimeSpan($trg.ExecutionTimeLimit) -ne [timespan]::Zero -or
        $Task.Enabled -ne $Enabled -or $s.MultipleInstances -ne 0 -or $s.RunOnlyIfIdle -or
        $s.DisallowStartIfOnBatteries -or $s.StopIfGoingOnBatteries -or $s.AllowHardTerminate -or
        [Xml.XmlConvert]::ToTimeSpan($s.ExecutionTimeLimit) -ne [timespan]::Zero -or
        $s.RestartCount -ne 3 -or [Xml.XmlConvert]::ToTimeSpan($s.RestartInterval) -ne [timespan]::FromMinutes(1)) {
        throw 'Scheduled Task effective settings failed the Curl deployment check.'
    }
}

function Register-CurlRelease($Context, [string]$Generation, [bool]$Replace) {
    $layout = Get-CurlLayout $Generation
    $def = $Context.Scheduler.NewTask(0)
    $def.RegistrationInfo.Description = 'DLP managed Curl ' + $Context.Owner
    $def.Principal.GroupId = 'S-1-5-32-545'
    $def.Principal.RunLevel = 0
    $trigger = $def.Triggers.Create(9)  # TASK_TRIGGER_LOGON
    $trigger.Enabled = $true
    $trigger.ExecutionTimeLimit = 'PT0S'
    $action = $def.Actions.Create(0)
    $action.Path = $layout.Python
    $action.Arguments = $layout.Args
    $action.WorkingDirectory = $layout.Dir
    $s = $def.Settings
    $s.Enabled = $false
    $s.ExecutionTimeLimit = 'PT0S'
    $s.DisallowStartIfOnBatteries = $false
    $s.StopIfGoingOnBatteries = $false
    $s.RunOnlyIfIdle = $false
    $s.AllowHardTerminate = $false
    $s.MultipleInstances = 0  # TASK_INSTANCES_PARALLEL; singleton is per logon.
    $s.RestartCount = 3
    $s.RestartInterval = 'PT1M'
    $flags = if ($Replace) { 4 } else { 2 }  # update only / create only
    $descriptor = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)'
    $task = $Context.Folder.RegisterTaskDefinition($CurlTaskName, $def, $flags, 'S-1-5-32-545', $null, 4, $descriptor)
    Assert-CurlOwnership $task $Context.Owner $Generation
    Assert-CurlSettings $task $false
    return $task
}

function Read-CurlRecord($Key, [string]$Id) {
    $value = $Key.GetValue('Record', $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    if ($value -isnot [string] -or $value.Length -gt 2048 -or $Key.GetValueKind('Record') -ne 'String') {
        throw 'Missing or oversized managed Curl instance record.'
    }
    $r = ConvertFrom-Json -InputObject $value -ErrorAction Stop
    $fields = @('version','instance','local_stop','state','operation','pending_resumes','worker_cleanup_confirmed','report_drained','runtime_failed')
    if (@($r.PSObject.Properties.Name).Count -ne $fields.Count -or
        @($fields | Where-Object { $_ -cnotin $r.PSObject.Properties.Name }).Count -or
        ($r.version -isnot [int] -and $r.version -isnot [long]) -or $r.version -ne 1 -or
        $r.instance -cne $Id -or -not (Test-CurlId $Id) -or -not (Test-CurlId $r.local_stop) -or
        $r.instance -ceq $r.local_stop -or $r.state -cnotin 'running','complete','incomplete') {
        throw 'Invalid managed Curl instance identity or schema.'
    }
    if ($r.state -ceq 'running') {
        if ($r.operation -isnot [string] -or $r.operation -cne '' -or $null -ne $r.pending_resumes -or
            $null -ne $r.worker_cleanup_confirmed -or $null -ne $r.report_drained -or $null -ne $r.runtime_failed) {
            throw 'Malformed running Curl instance record.'
        }
    } elseif (-not (Test-CurlId $r.operation) -or ($r.pending_resumes -isnot [int] -and $r.pending_resumes -isnot [long]) -or
        $r.pending_resumes -lt 0 -or $r.pending_resumes -gt [int]::MaxValue -or $r.worker_cleanup_confirmed -isnot [bool] -or
        $r.report_drained -isnot [bool] -or $r.runtime_failed -isnot [bool]) {
        throw 'Malformed terminal Curl receipt.'
    }
    return $r
}

function Get-CurlRecords($Instances) {
    $records = @{}
    foreach ($id in $Instances.GetSubKeyNames()) {
        if (-not (Test-CurlId $id)) { throw 'Unknown Curl lifecycle record. Cleanup unconfirmed.' }
        $key = $Instances.OpenSubKey($id)
        try {
            # A new instance creates its key immediately before publishing Record.
            for ($attempt = 0; $key -and $attempt -lt 8 -and $key.GetValueNames() -cnotcontains 'Record'; $attempt++) {
                Start-Sleep -Milliseconds 125
            }
            $records[$id] = Read-CurlRecord $key $id
        } finally { if ($key) { $key.Dispose() } }
    }
    return $records
}

function Assert-CurlCleanup($Records, $Plan) {
    $expected = @{}
    foreach ($prior in $Plan.records) {
        if (-not $Records.ContainsKey($prior.instance)) { throw 'A managed Curl instance record disappeared.' }
        $expected[$prior.instance] = $prior
    }
    $running = $false
    foreach ($r in $Records.Values) {
        $prior = $expected[$r.instance]
        if ($prior -and $prior.local_stop -cne $r.local_stop) { throw 'Curl instance identity changed during maintenance.' }
        if ($r.state -ceq 'running') { $running = $true; continue }
        if ($r.state -cne 'complete' -or $r.pending_resumes -ne 0 -or -not $r.worker_cleanup_confirmed) {
            throw 'Curl cleanup incomplete. Keep the runtime and disabled task for investigation.'
        }
        if ($prior -and $prior.state -ceq 'complete') {
            $restamped = $prior.operation -ceq $r.local_stop -and $r.operation -ceq $Plan.operation
            if ($r.operation -cne $prior.operation -and -not $restamped) { throw 'Historical Curl receipt changed.' }
        } elseif ($r.operation -cne $Plan.operation) { throw 'Stale Curl cleanup receipt for this stop operation.' }
        if ((-not $prior -or $prior.state -cne 'complete') -and (-not $r.report_drained -or $r.runtime_failed)) {
            Write-Warning "Curl instance $($r.instance) cleaned up. Report drained=$($r.report_drained), runtime failed=$($r.runtime_failed)."
        }
    }
    return (-not $running)
}

function Test-CurlInterpreterExited([string]$Generation) {
    if (-not $Generation) { return $true }
    $layout = Get-CurlLayout $Generation
    $entry = Join-Path $layout.Dir 'curl_managed.py'
    # The venv redirector can have a separate base interpreter PID. Observe both
    # independently of Task Scheduler and never use a receipt PID or signal a process.
    foreach ($process in Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -Property CommandLine,ExecutablePath -ErrorAction Stop) {
        if (-not $process.CommandLine) { throw 'Could not inspect a Python process. Curl interpreter exit unconfirmed.' }
        if ($process.CommandLine.IndexOf($entry, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $false }
    }
    return $true
}

function Enter-CurlMaintenance($Context, $Task) {
    try { Wait-CurlMaintenance $Context $Task }
    catch {
        # A corrupt snapshot/record can fail before the ordinary disable step.
        # Leave the owned registration fenced while an administrator investigates.
        if ($Task) { $Task.Enabled = $false }
        throw
    }
}

function Wait-CurlMaintenance($Context, $Task) {
    $key = $Context.Key
    $challenge = [string]$key.GetValue('Maintenance','')
    # Instances is not readable/enumerable by unrelated users. Never publish
    # instance/local-stop IDs in values on the users-readable control key.
    $saved = [string]$Context.Instances.GetValue('MaintenancePlan','')
    if ($saved) {
        $plan = ConvertFrom-Json -InputObject $saved -ErrorAction Stop
        if (-not (Test-CurlId $plan.operation) -or ($challenge -and $challenge -cne $plan.operation)) {
            throw 'Curl maintenance transaction is inconsistent.'
        }
    } else {
        if ($challenge -and -not (Test-CurlId $challenge)) { throw 'Invalid protected Curl maintenance operation.' }
        if (-not $challenge) { $challenge = [guid]::NewGuid().ToString('N') }
        $key.SetValue('Maintenance', $challenge)
        $key.Flush()
        $records = Get-CurlRecords $Context.Instances
        $plan = @{ operation = $challenge; enabled = [bool]($Task -and $Task.Enabled)
            records = @($records.Values | Select-Object instance,local_stop,state,operation) }
        $Context.Instances.SetValue('MaintenancePlan', ($plan | ConvertTo-Json -Compress -Depth 4))
        $Context.Instances.Flush()
    }
    if (-not $Context.Switched) { $Context.OldEnabled = $plan.enabled }
    $key.SetValue('Maintenance', $plan.operation)
    if ($Task) { $Task.Enabled = $false }
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    do {
        $generation = if ($Context.Switched -and $Task) { $Context.Staged } else { $Context.Old }
        $taskQuiet = -not $Task -or $Task.GetInstances(0).Count -eq 0
        if ($taskQuiet -and (Test-CurlInterpreterExited $generation)) {
            if (-not (Assert-CurlCleanup (Get-CurlRecords $Context.Instances) $plan)) {
                throw 'Curl interpreter/task exited without a complete receipt. Forced exit or cleanup unconfirmed.'
            }
            if ($Task -and $Task.Enabled) { throw 'Curl task was re-enabled during maintenance.' }
            $Context.Quiesced = $true
            return
        }
        Start-Sleep -Milliseconds 250
    } while ($deadline.Elapsed.TotalSeconds -lt 45)
    throw 'Curl cleanup unconfirmed: a watcher, task instance or receipt did not settle in 45 seconds. Files preserved.'
}

function Exit-CurlMaintenance($Context) {
    $Context.Instances.DeleteValue('MaintenancePlan', $false)
    $Context.Instances.Flush()
    $Context.Key.SetValue('Maintenance', '')
}

function Open-CurlDeployment([bool]$Install) {
    if (-not [Environment]::Is64BitProcess) { throw 'Managed Curl deployment requires 64-bit Windows PowerShell.' }
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
    $ctx = @{ Key = $null; Instances = $null; Lock = $null; Owner = ''; Old = ''; Staged = ''; Quiesced = $false; Switched = $false }
    try {
        $ctx.Scheduler = New-Object -ComObject 'Schedule.Service'
        $ctx.Scheduler.Connect()
        $ctx.Folder = $ctx.Scheduler.GetFolder('\')
        $task = Get-CurlTask $ctx.Folder
        $ctx.Key = $hklm.OpenSubKey($CurlRegistry, $true)
        if (-not $ctx.Key -and $task) { throw 'Unowned DLPCurlAgent task. Refusing to change it.' }
        if (-not $ctx.Key -and -not $Install) {
            if (Test-Path -LiteralPath $CurlRoot) { throw 'Unowned Curl deployment directory requires review.' }
            return $null
        }
        Assert-CurlProtectedPath (Split-Path -Parent $CurlRoot)
        if (-not (Test-Path -LiteralPath $CurlRoot)) { [IO.Directory]::CreateDirectory($CurlRoot) | Out-Null }
        Assert-CurlProtectedPath $CurlRoot
        $lockPath = Join-Path $CurlRoot 'deploy.lock'
        if (Test-Path -LiteralPath $lockPath) { Assert-CurlProtectedPath $lockPath }
        $ctx.Lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
        $task = Get-CurlTask $ctx.Folder
        if (-not $ctx.Key) {
            if ($task -or @(Get-ChildItem -LiteralPath $CurlRoot -Force | Where-Object Name -ne 'deploy.lock').Count) {
                throw 'Unknown existing Curl deployment.'
            }
            $parent = $hklm.CreateSubKey('SOFTWARE\DLP')
            try {
                Assert-CurlAdminAcl ($parent.GetAccessControl()) 0xD0006
                if ($parent.GetSubKeyNames() -contains 'ManagedCurl') { throw 'Retry after concurrent Curl installer.' }
                $ctx.Key = $parent.CreateSubKey('ManagedCurl', 'ReadWriteSubTree', (New-CurlRegistryAcl $CurlRootAcl))
            } finally { $parent.Dispose() }
            $ctx.Key.SetValue('OwnerId',[guid]::NewGuid().ToString('N'))
            $ctx.Key.SetValue('Current','')
            $ctx.Key.SetValue('Maintenance','')
            $ctx.Instances = $ctx.Key.CreateSubKey('Instances', 'ReadWriteSubTree', (New-CurlRegistryAcl $CurlInstanceAcl))
        }
        Assert-CurlRegistryAcl $ctx.Key $CurlRootAcl
        if (-not $ctx.Instances) { $ctx.Instances = $ctx.Key.OpenSubKey('Instances',$true) }
        Assert-CurlRegistryAcl $ctx.Instances $CurlInstanceAcl
        $ctx.Owner = [string]$ctx.Key.GetValue('OwnerId')
        $ctx.Old = [string]$ctx.Key.GetValue('Current')
        if (-not (Test-CurlId $ctx.Owner)) { throw 'Missing protected Curl owner marker.' }
        if ($task) {
            Assert-CurlOwnership $task $ctx.Owner $ctx.Old
            Assert-CurlSettings $task ([bool]$task.Enabled)
            $ctx.OldEnabled = [bool]$task.Enabled
        }
        elseif ($ctx.Old) { throw 'Owned Curl task is missing. Reconcile the protected deployment record first.' }
        $ctx.Task = $task
        return $ctx
    } catch { Close-CurlDeployment $ctx; throw }
    finally { $hklm.Dispose() }
}

function Close-CurlDeployment($Context) {
    if ($Context) {
        foreach ($name in 'Instances','Key','Lock') { if ($Context[$name]) { $Context[$name].Dispose() } }
    }
}

function New-CurlRelease($Context, [string]$Source, [string]$Python) {
    $id = [guid]::NewGuid().ToString('N')
    $layout = Get-CurlLayout $id
    if (Test-Path -LiteralPath $layout.Dir) { throw 'Curl release already exists.' }
    New-Item -ItemType Directory -Path $layout.Dir -ErrorAction Stop | Out-Null
    Assert-CurlProtectedPath $layout.Dir
    [IO.File]::WriteAllText((Join-Path $layout.Dir 'owner'), $Context.Owner)
    $Context.Staged = $id
    foreach ($file in $CurlFiles) {
        Copy-Item -LiteralPath (Join-Path $Source $file) -Destination (Join-Path $layout.Dir $file) -ErrorAction Stop
    }
    Push-Location -LiteralPath $layout.Dir
    try {
        & $Python -I -B -m venv --copies (Join-Path $layout.Dir 'venv')
        if ($LASTEXITCODE) { throw 'Managed Curl venv creation failed.' }
        & $layout.Python -I -B -m pip --isolated install --disable-pip-version-check -r (Join-Path $layout.Dir 'requirements.txt')
        if ($LASTEXITCODE) { throw 'Managed Curl requirements installation failed.' }
        & $layout.Python -I -B -c 'import psutil, requests, pypdf'
        if ($LASTEXITCODE) { throw 'Managed Curl dependency preflight failed.' }
    } finally { Pop-Location }
}

function Remove-CurlRelease($Context, [string]$Id) {
    if (-not $Id) { return }
    $layout = Get-CurlLayout $Id
    $dir = [IO.Path]::GetFullPath($layout.Dir)
    if ((Split-Path -Parent $dir) -ine $CurlRoot -or (Split-Path -Leaf $dir) -cne $Id) { throw 'Unsafe Curl release path.' }
    Assert-CurlProtectedPath $dir
    $marker = Join-Path $dir 'owner'
    Assert-CurlProtectedPath $marker
    if ([IO.File]::ReadAllText($marker) -cne $Context.Owner) { throw 'Unowned Curl release. Files preserved.' }
    # Never descend through junctions, symbolic links or user-writable directories.
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($dir)
    while ($pending.Count) {
        foreach ($item in Get-ChildItem -LiteralPath $pending.Pop() -Force -ErrorAction Stop) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point inside Curl release. Files preserved.' }
            if ($item.PSIsContainer) { Assert-CurlProtectedPath $item.FullName; $pending.Push($item.FullName) }
        }
    }
    Remove-Item -LiteralPath $dir -Force -Recurse -ErrorAction Stop
}

function Complete-CurlInstall($Context) {
    if (-not $Context.Quiesced) { throw 'Curl maintenance did not complete.' }
    $oldTask = Get-CurlTask $Context.Folder
    if ($oldTask) { Assert-CurlOwnership $oldTask $Context.Owner $Context.Old }
    elseif ($Context.Old) { throw 'Curl task disappeared during install.' }
    $Context.Switched = $true
    $task = Register-CurlRelease $Context $Context.Staged ([bool]$oldTask)
    $Context.Key.SetValue('Current',$Context.Staged)
    Exit-CurlMaintenance $Context
    $task.Enabled = $true
    Assert-CurlSettings $task $true
    $Context.Installed = $true
    if ($Context.Old) { Remove-CurlRelease $Context $Context.Old }
}

function Undo-CurlInstall($Context) {
    if (-not $Context -or $Context.Installed) { return }
    if ($Context.Quiesced) {
        $task = Get-CurlTask $Context.Folder
        if ($Context.Switched -and $task) {
            # Registration or enable may have taken effect before returning an error.
            $oldStillRegistered = $false
            if ($Context.Old) {
                try { Assert-CurlOwnership $task $Context.Owner $Context.Old; $oldStillRegistered = $true } catch { }
            }
            if (-not $oldStillRegistered) {
                Assert-CurlOwnership $task $Context.Owner $Context.Staged
                $Context.Quiesced = $false
                Enter-CurlMaintenance $Context $task
                if ($Context.Old) { $task = Register-CurlRelease $Context $Context.Old $true }
                else { $Context.Folder.DeleteTask($CurlTaskName,0); $task = $null }
            }
        }
        if ($Context.Old) { Assert-CurlOwnership $task $Context.Owner $Context.Old }
        $Context.Key.SetValue('Current', $Context.Old)
        Exit-CurlMaintenance $Context
        if ($Context.Old) { $task.Enabled = $Context.OldEnabled; Assert-CurlSettings $task $Context.OldEnabled }
    }
    # Only the new unregistered/rolled-back generation is disposable.
    if ($Context.Staged -and ($Context.Quiesced -or -not $Context.Switched)) { Remove-CurlRelease $Context $Context.Staged }
}

function Uninstall-CurlTask($Context, [bool]$RemoveFiles) {
    if (-not $Context) { return }
    Enter-CurlMaintenance $Context $Context.Task
    if ($Context.Task) {
        $task = Get-CurlTask $Context.Folder
        Assert-CurlOwnership $task $Context.Owner $Context.Old
        $Context.Folder.DeleteTask($CurlTaskName,0)
        $Context.Key.SetValue('Current','')
    }
    if ($RemoveFiles) {
        foreach ($release in Get-ChildItem -LiteralPath $CurlRoot -Directory -Force -ErrorAction Stop) {
            if (Test-CurlId $release.Name) { Remove-CurlRelease $Context $release.Name }
        }
    }
    Exit-CurlMaintenance $Context
}
