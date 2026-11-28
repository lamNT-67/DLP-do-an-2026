$DlpServiceScripts = [ordered]@{
    DLPNetworkAgent = 'network_agent.py'
    DLPSftpScpAgent = 'sftp_scp_agent.py'
    DLPBrowserAgent = 'browser_agent.py'
}
$DlpDesktopTasks = @('DLPClipboardAgent', 'DLPNotifier')
$DlpNssm = 'C:\DLP\tools\nssm.exe'
$DlpRuntimes = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'DLP-Runtimes'
$DlpSystemPowerShell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$DlpNotifierArgs = '-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File "C:\DLP\notify\notify.ps1"'

function Test-DlpRuntimePython([string]$Path) {
    $legacy = 'C:\DLP\venv\Scripts\python.exe'
    $roots = @('C:\DLP\runtimes', $DlpRuntimes) | ForEach-Object { [regex]::Escape($_) }
    return $Path -ieq $legacy -or $Path -match ('\A(?:' + ($roots -join '|') + ')\\[0-9a-f]{32}\\Scripts\\python\.exe\z')
}

function Get-DlpClipboardArgs([string]$Python) {
    return '-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -Command "$env:DLP_LOG_DIR=''C:\ProgramData\DLP\logs''; Set-Location C:\DLP\agent; & ''{0}'' clipboard_agent.py"' -f $Python
}

function Assert-DlpServiceRegistration($Service, [string]$Name, [string]$Application, [string]$Directory, [string]$Arguments) {
    $script = 'C:\DLP\agent\' + $DlpServiceScripts[$Name]
    if ($Service.Name -ine $Name -or $Service.PathName -notin $DlpNssm, ('"' + $DlpNssm + '"') -or
        $Service.ServiceType -ne 'Own Process' -or $Service.StartName -ne 'LocalSystem' -or
        $Directory -ine 'C:\DLP\agent' -or -not (Test-DlpRuntimePython $Application) -or
        $Arguments -notin "-u $script", "-E -s -u $script") {
        throw "Unrecognized DLP service registration '$Name'. Review its executable, account and NSSM parameters."
    }
}

function Get-DlpService([string]$Name) {
    return Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
}

function Get-DlpOwnedService([string]$Name) {
    $service = Get-DlpService $Name
    if (-not $service) { return }
    $location = "HKLM\SYSTEM\CurrentControlSet\Services\$Name"
    $acl = [Security.AccessControl.FileSecurity]::new()
    try { $acl.SetSecurityDescriptorBinaryForm([DlpInstaller.Paths]::ServiceSecurityDescriptor($Name)) }
    catch { throw "Cannot verify ownership of service '$Name'. $($_.Exception.GetBaseException().Message)" }
    Assert-CurlAdminAcl $acl 0xD0032 "SCM service $Name"
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$Name")
    if (-not $key) { throw "Missing '$location' for service '$Name'." }
    try {
        Assert-CurlAdminAcl ($key.GetAccessControl()) 0xD0006 $location
        $parameters = $key.OpenSubKey('Parameters')
        if (-not $parameters) { throw "Missing NSSM parameters at '$location'." }
        try {
            Assert-CurlAdminAcl ($parameters.GetAccessControl()) 0xD0006 "$location\Parameters"
            if ($parameters.GetSubKeyNames() | Where-Object { $_ -ne 'AppExit' }) {
                throw "Unexpected NSSM settings at '$location\Parameters'. Review the service before setup."
            }
            $app = $parameters.GetValue('Application', '', 'DoNotExpandEnvironmentNames')
            $directory = $parameters.GetValue('AppDirectory', '', 'DoNotExpandEnvironmentNames')
            $args = $parameters.GetValue('AppParameters', '', 'DoNotExpandEnvironmentNames')
            Assert-DlpServiceRegistration $service $Name $app $directory $args
            $stdout = $parameters.GetValue('AppStdout', '', 'DoNotExpandEnvironmentNames')
            $stderr = $parameters.GetValue('AppStderr', '', 'DoNotExpandEnvironmentNames')
            if ($stdout -ine "C:\ProgramData\DLP\logs\$Name.out.log" -or $stderr -ine "C:\ProgramData\DLP\logs\$Name.err.log") {
                throw "Unrecognized log paths for DLP service '$Name'. Review its NSSM configuration."
            }
            return @{ Service = $service; Application = $app; Signature = "$($service.PathName)|$app|$directory|$args" }
        } finally { $parameters.Dispose() }
    } finally { $key.Dispose() }
}

function Get-DlpClipboardPython([string]$Arguments) {
    $marker = '__DLP_PYTHON__'
    $quoted = Get-DlpClipboardArgs $marker
    $pattern = [regex]::Escape($quoted).Replace("'$marker'", "'([^']+)'")
    if ($Arguments -cmatch ('\A' + $pattern + '\z')) {
        $python = $Matches[1]
        if (Test-DlpRuntimePython $python) { return $python }
    }
    $legacy = 'C:\DLP\venv\Scripts\python.exe'
    if ($Arguments -ceq $quoted.Replace("'$marker'", $legacy)) { return $legacy }
}

function Test-DlpDesktopAction([string]$Name, [string]$Arguments) {
    if ($Name -eq 'DLPNotifier') { return $Arguments -ceq $DlpNotifierArgs }
    return [bool](Get-DlpClipboardPython $Arguments)
}

function Get-DlpOwnedTask($Folder, [string]$Name) {
    $task = Get-RegisteredDlpTask $Folder $Name
    if (-not $task) { return }
    $definition = $task.Definition
    if ($definition.Actions.Count -ne 1 -or $definition.Triggers.Count -ne 1) {
        throw "Unrecognized scheduled task '\$Name'. Review its action and trigger before setup."
    }
    $principal = $definition.Principal
    $group = [string]$principal.GroupId
    if ($group -and $group -ne 'S-1-5-32-545') {
        try { $group = ([Security.Principal.NTAccount]::new($group)).Translate([Security.Principal.SecurityIdentifier]).Value }
        catch { throw "Cannot verify the group principal for scheduled task '\$Name'." }
    }
    $action = $definition.Actions.Item(1)
    $trigger = $definition.Triggers.Item(1)
    if ($group -ne 'S-1-5-32-545' -or $principal.RunLevel -ne 0 -or $principal.LogonType -ne 4 -or
        $action.Type -ne 0 -or $action.WorkingDirectory -or
        $action.Path -notin 'powershell.exe', $DlpSystemPowerShell -or
        $trigger.Type -ne 9 -or $trigger.UserId -or
        -not (Test-DlpDesktopAction $Name $action.Arguments)) {
        throw "Unrecognized scheduled task '\$Name'. Review its action and principal before setup."
    }
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($task.GetSecurityDescriptor(5))
    Assert-CurlAdminAcl $acl 0xD0156 "Task Scheduler \$Name"
    $python = if ($Name -eq 'DLPClipboardAgent') { Get-DlpClipboardPython $action.Arguments }
    return @{ Task = $task; Signature = "$($action.Path)|$($action.Arguments)"; Python = $python }
}

function Get-DlpSharedInventory($Folder) {
    $services = @{}
    $tasks = @{}
    foreach ($name in $DlpServiceScripts.Keys) {
        $entry = Get-DlpOwnedService $name
        if ($entry) { $services[$name] = $entry }
    }
    foreach ($name in $DlpDesktopTasks) {
        $entry = Get-DlpOwnedTask $Folder $name
        if ($entry) { $tasks[$name] = $entry }
    }
    return @{ Services = $services; Tasks = $tasks }
}

function Assert-DlpSameInventory($Before, $After) {
    foreach ($kind in 'Services', 'Tasks') {
        $names = @($Before[$kind].Keys) + @($After[$kind].Keys)
        foreach ($name in ($names | Sort-Object -Unique)) {
            if ($Before[$kind][$name].Signature -cne $After[$kind][$name].Signature) {
                throw "Registration '$name' changed during setup."
            }
        }
    }
}

function Invoke-DlpSc([string[]]$Arguments) {
    $global:LASTEXITCODE = $null
    & (Join-Path ([Environment]::SystemDirectory) 'sc.exe') @Arguments | Out-Null
    if ($global:LASTEXITCODE -ne 0) { throw "SCM '$($Arguments[0])' failed for '$($Arguments[1])' (exit $global:LASTEXITCODE)." }
}

function Invoke-DlpNssm([string]$Path, [string[]]$Arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $global:LASTEXITCODE = $null
        & $Path @Arguments 2>&1 | Out-Null
        if ($global:LASTEXITCODE -ne 0) {
            $detail = if ($null -eq $global:LASTEXITCODE) { 'process launch did not complete' } else { "exit $global:LASTEXITCODE" }
            throw "NSSM '$($Arguments[0])' failed for '$($Arguments[1])' ($detail)."
        }
    } finally { $ErrorActionPreference = $previous }
}

function Get-DlpProcesses {
    Get-CimInstance -ClassName Win32_Process -Property Name, ProcessId, ParentProcessId, CreationDate, ExecutablePath, CommandLine, SessionId -ErrorAction Stop
}

function Get-DlpProcessTree($Processes, $Root) {
    if (-not $Root.CreationDate) { throw "Could not verify the creation time of DLP process $($Root.ProcessId)." }
    $pending = [Collections.Generic.Queue[object]]::new()
    $pending.Enqueue($Root)
    $seen = @{}
    while ($pending.Count) {
        $parent = $pending.Dequeue()
        if ($seen.ContainsKey($parent.ProcessId)) { continue }
        $seen[$parent.ProcessId] = $true
        $parent
        foreach ($child in $Processes) {
            if ($child.ParentProcessId -eq $parent.ProcessId -and $child.CreationDate -ge $parent.CreationDate) {
                $pending.Enqueue($child)
            }
        }
    }
}

function Test-DlpSharedProcess($Process) {
    if ($Process.ExecutablePath -and ($Process.ExecutablePath.StartsWith('C:\DLP\', 'OrdinalIgnoreCase') -or
        $Process.ExecutablePath.StartsWith($DlpRuntimes + '\', 'OrdinalIgnoreCase'))) { return $true }
    if ($Process.Name -in 'python.exe', 'pythonw.exe') {
        return $Process.CommandLine -match '\bC:\\DLP\\agent\\(?:network_agent|sftp_scp_agent|browser_agent|clipboard_agent)\.py(?=["\s]|$)'
    }
    return $Process.Name -eq 'powershell.exe' -and $Process.CommandLine -match '\s-File\s+"?C:\\DLP\\notify\\notify\.ps1(?=["\s]|$)'
}

function Get-DlpClipboardCommandImage([string]$CommandLine) {
    # Accept the task's single script argument, optionally quoted or absolute.
    $script = '(?:C:\\DLP\\agent\\)?clipboard_agent\.py'
    if ($CommandLine -match ('\A(?:"([^"]+)"|([^"\s]+))[ \t]+(?:"' + $script + '"|' + $script + ')[ \t]*\z')) {
        if ($Matches[1]) { return $Matches[1] }
        return $Matches[2]
    }
}

function Open-DlpClipboardWorker($Process, [bool]$CanTerminate) {
    return [DlpInstaller.ClipboardWorker]::Open($Process.ProcessId, $Process.CreationDate.ToUniversalTime().ToFileTimeUtc(),
        $Process.SessionId, $Process.ExecutablePath, $CanTerminate)
}

function Update-DlpClipboardWorkers([string]$Python, $Workers, $Processes, [long]$Elapsed) {
    # Observe parents before their children. Retain even an exited parent's
    # handle to keep its identity available for late child observations.
    foreach ($process in ($Processes | Sort-Object @{ Expression = { -not $_.CreationDate } }, CreationDate)) {
        $id = [uint32]$process.ProcessId
        $parent = $Workers[[uint32]$process.ParentProcessId]
        if ($parent -and $process.CreationDate -and $process.CreationDate -lt $parent.Observed.CreationDate) { $parent = $null }
        if ($Workers.ContainsKey($id)) {
            if ($Workers[$id].Observed.CreationDate -ne $process.CreationDate) { $id }
            continue
        }
        $launcher = $Python -and $process.ExecutablePath -ieq $Python
        $commandImage = Get-DlpClipboardCommandImage $process.CommandLine
        if (-not $launcher -and -not $parent -and (-not $commandImage -or $process.Name -notin 'python.exe','pythonw.exe')) { continue }
        if (-not $commandImage -or -not $process.ExecutablePath -or -not $process.CreationDate -or
            -not $process.SessionId -or ($launcher -and $commandImage -ine $Python) -or
            ($parent -and (-not $parent.Launcher -or $launcher -or $process.SessionId -ne $parent.Observed.SessionId -or
                [IO.Path]::GetFileName($process.ExecutablePath) -ine 'python.exe' -or $commandImage -notin $Python, $process.ExecutablePath))) {
            $id
            continue
        }
        $handle = $null
        try {
            $handle = Open-DlpClipboardWorker $process ($launcher -or [bool]$parent)
            if (-not $handle) { $id; continue }  # The inventory went stale. Recheck on the next poll.
            $directory = $handle.WorkingDirectory()
            if ($directory -ine 'C:\DLP\agent') {
                if ($launcher -or $parent) { $id }
                continue
            }
            if ((-not $launcher -and -not $parent) -or ($parent -and $handle.CreationTime -le $parent.Handle.CreationTime)) {
                $id  # Relative script alone cannot establish ownership.
                continue
            }
            $Workers[$id] = @{ Observed = $process; Handle = $handle; Launcher = $launcher
                FirstSeen = $Elapsed; QuitRequested = $false; Terminated = $false }
            $handle = $null
        } catch {
            if (-not $handle -or -not $handle.HasExited) {
                throw "Could not verify Clipboard worker PID ${id}. $($_.Exception.GetBaseException().Message)"
            }
        } finally { if ($handle) { $handle.Dispose() } }
    }
}

function Get-DlpClipboardElapsed($Timer) { return $Timer.ElapsedMilliseconds }

function Stop-DlpClipboardTask($Entry) {
    if (-not (Test-DlpRuntimePython $Entry.Python)) { throw 'Cannot identify the owned Clipboard task runtime.' }
    $task = $Entry.Task
    $workers = @{}
    $quiet = 0
    $schedulerStopRequested = $false
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        do {
            if ($task.Enabled) { throw 'The owned Clipboard task must remain disabled during shutdown.' }
            $processes = @(Get-DlpProcesses)
            $unverified = @(Update-DlpClipboardWorkers $Entry.Python $workers $processes (Get-DlpClipboardElapsed $timer))
            $live = @($workers.Values | Where-Object { -not $_.Handle.HasExited })
            $instances = $task.GetInstances(0).Count
            $elapsed = Get-DlpClipboardElapsed $timer
            if ($elapsed -ge 15000) { break }
            if (-not $instances -and -not $live.Count -and -not $unverified.Count) {
                if (++$quiet -ge 2) { return }
            } else { $quiet = 0 }

            if (-not $unverified.Count) {
                if ($task.Enabled) { throw 'The owned Clipboard task was re-enabled during shutdown.' }
                foreach ($worker in $live) {
                    if (-not $worker.QuitRequested -and -not $worker.Terminated) {
                        $worker.QuitRequested = $worker.Handle.RequestExit()
                    }
                }
                if ($elapsed -ge 2000 -and $instances -and -not $schedulerStopRequested) {
                    try { $task.Stop(0) }
                    catch { if ($task.GetInstances(0).Count) { throw } }
                    $schedulerStopRequested = $true
                }
                if ($elapsed -ge 3000) {
                    foreach ($worker in $live) {
                        if ($worker.Terminated -or ($elapsed - $worker.FirstSeen) -lt 2000) { continue }
                        # Let the venv launcher return naturally when its
                        # interpreter exits. Terminate only verified leaves.
                        if ($live | Where-Object { $_.Observed.ParentProcessId -eq $worker.Observed.ProcessId }) { continue }
                        $worker.Handle.Terminate()
                        $worker.Terminated = $true
                    }
                }
            }
            Start-Sleep -Milliseconds 250
        } while ((Get-DlpClipboardElapsed $timer) -lt 15000)
        $remaining = ($live | ForEach-Object { $_.Observed.ProcessId }) -join ', '
        $ambiguous = $unverified -join ', '
        throw "Clipboard shutdown is unconfirmed. Verified worker PIDs [$remaining]. Unverified PIDs [$ambiguous]. Review the pending recovery state."
    } finally {
        foreach ($worker in $workers.Values) { $worker.Handle.Dispose() }
    }
}

function Stop-DlpVerifiedService([string]$Name) {
    $controller = Get-Service -Name $Name -ErrorAction Stop
    try {
        if ($controller.Status -notin 'Stopped', 'StopPending') {
            Invoke-DlpSc @('stop', $Name)
        }
        $controller.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    } catch { throw "Service '$Name' did not stop cleanly. $($_.Exception.Message)" }
    finally { $controller.Dispose() }
}

function Stop-DlpSharedWork($Folder, $Inventory) {
    $current = Get-DlpSharedInventory $Folder
    Assert-DlpSameInventory $Inventory $current
    foreach ($name in $current.Services.Keys) { Invoke-DlpSc @('config', $name, 'start=', 'disabled') }
    foreach ($name in $current.Tasks.Keys) { $current.Tasks[$name].Task.Enabled = $false }

    $processes = @(Get-DlpProcesses)
    $tracked = @{}
    foreach ($name in $current.Services.Keys) {
        $service = Get-DlpService $name
        if (-not $service -or $service.StartMode -ne 'Disabled') { throw "Could not fence '$name'." }
        if ($service.ProcessId) {
            $root = $processes | Where-Object ProcessId -eq $service.ProcessId | Select-Object -First 1
            if (-not $root -or $root.ExecutablePath -ine $DlpNssm) { throw "Could not verify the running wrapper for '$name'." }
            foreach ($process in (Get-DlpProcessTree $processes $root)) { $tracked[$process.ProcessId] = $process.CreationDate }
        }
        Stop-DlpVerifiedService $name
    }
    foreach ($name in $current.Tasks.Keys) {
        if ($name -eq 'DLPClipboardAgent') { continue }
        $task = $current.Tasks[$name].Task
        if ($task.GetInstances(0).Count -gt 0) { $task.Stop(0) }
    }
    if ($current.Tasks.ContainsKey('DLPClipboardAgent')) { Stop-DlpClipboardTask $current.Tasks.DLPClipboardAgent }

    $deadline = [Diagnostics.Stopwatch]::StartNew()
    do {
        $taskActive = @($current.Tasks.Values | Where-Object { $_.Task.Enabled -or $_.Task.GetInstances(0).Count }).Count
        $processes = @(Get-DlpProcesses)
        $activity = @($processes | Where-Object {
            ($tracked.ContainsKey($_.ProcessId) -and $tracked[$_.ProcessId] -eq $_.CreationDate) -or
            (Test-DlpSharedProcess $_)
        } | ForEach-Object ProcessId)
        if (-not $activity.Count) {
            # Keep the final cutover check observational. A newly observed
            # interpreter or a worker without its registration can hold it.
            $activity = @(Update-DlpClipboardWorkers '' @{} $processes 0)
        }
        if (-not $taskActive -and -not $activity.Count) {
            foreach ($name in $current.Services.Keys) {
                $service = Get-DlpService $name
                if ($service.State -ne 'Stopped' -or $service.StartMode -ne 'Disabled' -or $service.ProcessId) {
                    throw "Service '$name' is no longer fenced and stopped."
                }
            }
            return
        }
        Start-Sleep -Milliseconds 250
    } while ($deadline.Elapsed.TotalSeconds -lt 15)
    $pids = $activity -join ', '
    throw "DLP task or worker shutdown is unconfirmed. Remaining worker PIDs [$pids]. Close only the identified DLP instances and follow the recovery instructions."
}

function Remove-DlpSharedRegistrations($Folder, $Inventory) {
    $current = Get-DlpSharedInventory $Folder
    Assert-DlpSameInventory $Inventory $current
    foreach ($name in $current.Services.Keys) {
        $service = $current.Services[$name].Service
        if ($service.StartMode -ne 'Disabled' -or $service.State -ne 'Stopped' -or $service.ProcessId) {
            throw "Service '$name' must be fenced and stopped before removal."
        }
        Invoke-DlpSc @('delete', $name)
        $deadline = [Diagnostics.Stopwatch]::StartNew()
        while (Get-DlpService $name) {
            if ($deadline.Elapsed.TotalSeconds -ge 10) { throw "Service '$name' is still marked for deletion. Close service consoles and review setup recovery." }
            Start-Sleep -Milliseconds 250
        }
    }
    foreach ($name in $current.Tasks.Keys) {
        $task = $current.Tasks[$name].Task
        if ($task.Enabled -or $task.GetInstances(0).Count) { throw "Task '\$name' is not fenced and stopped." }
        $Folder.DeleteTask($name, 0)
    }
}

function Save-DlpNssm([string]$Bundled, [string]$Recovery, [string]$Destination) {
    if (Test-Path -LiteralPath $Bundled -PathType Leaf) {
        Copy-Item -LiteralPath $Bundled -Destination $Destination
    } else {
        # NSSM's Windows 10+ recommended release, pinned by the WinGet manifest.
        $version = 'nssm-2.24-101-g897c7ad'
        $zip = Join-Path $Recovery "$version.zip"
        Save-DlpSetupDownload "https://nssm.cc/ci/$version.zip" $zip
        if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash -ne '99F5045FFFBFFB745D67FE3A065A953C4A3D9C253B868892D9B685B0EE7D07B8') {
            throw "NSSM SHA-256 mismatch at '$zip'. Obtain a reviewed x64 NSSM and place it beside install.ps1."
        }
        Expand-Archive -LiteralPath $zip -DestinationPath $Recovery
        Copy-Item -LiteralPath (Join-Path $Recovery "$version\win64\nssm.exe") -Destination $Destination
    }
    Assert-CurlProtectedPath $Destination
    Assert-DlpAmd64Image $Destination
}

function Install-DlpService([string]$Name, [string]$Python, [string]$LogDir, $Created) {
    Invoke-DlpSc @('create', $Name, 'binPath=', $DlpNssm, 'start=', 'disabled')
    $Created.Add($Name)
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$Name", $true)
    try {
        $parameters = $key.CreateSubKey('Parameters')
        try {
            $parameters.SetValue('Application', $Python, 'ExpandString')
            $parameters.SetValue('AppDirectory', 'C:\DLP\agent', 'ExpandString')
            $parameters.SetValue('AppParameters', "-E -s -u C:\DLP\agent\$($DlpServiceScripts[$Name])", 'ExpandString')
        } finally { $parameters.Dispose() }
    } finally { $key.Dispose() }
    $settings = @(
        @('DisplayName', "DLP $Name"), @('Description', "DLP Agent - $($DlpServiceScripts[$Name])"),
        @('AppStdout', "$LogDir\$Name.out.log"), @('AppStderr', "$LogDir\$Name.err.log"),
        @('AppRotateFiles', '1'), @('AppRotateOnline', '1'), @('AppRotateBytes', '5242880'),
        @('AppExit', 'Default', 'Restart'), @('AppRestartDelay', '5000'), @('AppEnvironmentExtra', "DLP_LOG_DIR=$LogDir")
    )
    foreach ($setting in $settings) { Invoke-DlpNssm $DlpNssm (@('set', $Name) + $setting) }
    if (-not (Get-DlpOwnedService $Name)) { throw "NSSM service '$Name' disappeared during configuration." }
}

function Get-DlpServiceWorkers($Processes, $Service, [string]$Python, [string]$BasePython) {
    if ($Service.State -ne 'Running' -or -not $Service.ProcessId) { return }
    $root = $Processes | Where-Object ProcessId -eq $Service.ProcessId | Select-Object -First 1
    if (-not $root -or $root.ExecutablePath -ine $DlpNssm) { return }
    $script = [regex]::Escape('C:\DLP\agent\' + $DlpServiceScripts[$Service.Name])
    return Get-DlpProcessTree $Processes $root | Where-Object {
        $_.ExecutablePath -in $Python, $BasePython -and $_.CommandLine -match ('\s-E\s+-s\s+-u\s+"?' + $script + '(?:"|\s|$)')
    }
}

function Register-DlpDesktopTask($Scheduler, $Folder, [string]$Name, [string]$Arguments, $Created) {
    $definition = $Scheduler.NewTask(0)
    $definition.Principal.GroupId = 'S-1-5-32-545'
    $definition.Principal.RunLevel = 0
    $trigger = $definition.Triggers.Create(9)
    $trigger.Enabled = $true
    $action = $definition.Actions.Create(0)
    $action.Path = $DlpSystemPowerShell
    $action.Arguments = $Arguments
    $definition.Settings.ExecutionTimeLimit = 'PT0S'
    $definition.Settings.DisallowStartIfOnBatteries = $false
    $definition.Settings.StopIfGoingOnBatteries = $false
    if ($Name -eq 'DLPNotifier') { $definition.Settings.MultipleInstances = 0 }  # Parallel logons; one notifier per logon.
    $descriptor = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)'
    $task = $Folder.RegisterTaskDefinition($Name, $definition, 2, 'S-1-5-32-545', $null, 4, $descriptor)
    $Created.Add($Name)
    if (-not (Get-DlpOwnedTask $Folder $Name)) { throw "Scheduled task '\$Name' disappeared during registration." }
    Start-ScheduledTask -TaskPath '\' -TaskName $Name -ErrorAction Stop
}

function Stop-DlpFailedInstall($Folder, $Services, $Tasks) {
    foreach ($name in $Services) {
        try {
            $service = Get-DlpService $name
            if (-not $service) { continue }
            if ($service.PathName -notin $DlpNssm, ('"' + $DlpNssm + '"') -or $service.StartName -ne 'LocalSystem') {
                throw 'Service identity changed.'
            }
            Invoke-DlpSc @('config', $name, 'start=', 'disabled')
            Stop-DlpVerifiedService $name
        } catch { Write-Warning "Verify that new service '$name' is disabled and stopped. $($_.Exception.Message)" }
    }
    foreach ($name in $Tasks) {
        try {
            $entry = Get-DlpOwnedTask $Folder $name
            $task = $entry.Task
            if ($task) {
                $task.Enabled = $false
                if ($name -eq 'DLPClipboardAgent') { Stop-DlpClipboardTask $entry }
                elseif ($task.GetInstances(0).Count) { $task.Stop(0) }
                if ($task.GetInstances(0).Count) { throw 'Task instances remain.' }
            }
        } catch { Write-Warning "Verify that new task '\$name' is disabled and stopped. $($_.Exception.Message)" }
    }
}

function Wait-DlpServiceHealth([string]$Python, [string]$BasePython) {
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    $stable = [Diagnostics.Stopwatch]::new()
    $previous = ''
    do {
        $processes = @(Get-DlpProcesses)
        $healthy = @{}
        foreach ($name in $DlpServiceScripts.Keys) {
            $service = Get-DlpService $name
            $workers = @(Get-DlpServiceWorkers $processes $service $Python $BasePython)
            if ($workers.Count) {
                $healthy[$name] = ($workers | Sort-Object ProcessId | ForEach-Object { "$($_.ProcessId):$($_.CreationDate.Ticks)" }) -join ','
                if ($name -eq 'DLPBrowserAgent') {
                    $listeners = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 18765 -State Listen -ErrorAction SilentlyContinue)
                    if (-not @($listeners | Where-Object { $_.OwningProcess -in $workers.ProcessId }).Count) { $healthy.Remove($name) }
                }
            }
        }
        $identity = ($DlpServiceScripts.Keys | ForEach-Object { $healthy[$_] }) -join '|'
        if ($healthy.Count -ne $DlpServiceScripts.Count -or $identity -cne $previous) { $stable.Reset() }
        if ($healthy.Count -eq $DlpServiceScripts.Count -and -not $stable.IsRunning) { $stable.Start() }
        if ($stable.Elapsed.TotalSeconds -ge 6) { return }
        $previous = $identity
        Start-Sleep -Milliseconds 500
    } while ($deadline.Elapsed.TotalSeconds -lt 35)
    $missing = @($DlpServiceScripts.Keys | Where-Object { -not $healthy.ContainsKey($_) }) -join ', '
    throw "DLP worker health was not stable. Services without a healthy worker or listener at last check [$missing]. Review the service logs."
}
