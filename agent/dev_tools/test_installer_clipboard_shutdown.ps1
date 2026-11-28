# Non-elevated fixtures. Real process operations only target a child created by this script.
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from a non-elevated console.' }
$service = Join-Path (Split-Path -Parent $PSScriptRoot) 'service'
. (Join-Path $service 'installer_services.ps1')
Add-Type -Path (Join-Path $service 'installer_paths.cs')

$launcher = 'C:\DLP\venv\Scripts\python.exe'
$interpreter = 'C:\Program Files\DLP-C1-Lab\Python312\python.exe'
$script:passed = 0
function Check([string]$Name, [scriptblock]$Body) {
    & $Body
    $script:passed++
    Write-Output "PASS $Name"
}
function Assert($Condition) { if (-not $Condition) { throw 'Assertion failed.' } }
function Reject([scriptblock]$Body, [string]$Pattern) {
    try { & $Body } catch { if ($_.Exception.Message -like $Pattern) { return }; throw }
    throw "Expected failure matching $Pattern"
}

function Worker([uint32]$Id, [uint32]$Parent, [string]$Image, [int]$Order = 1) {
    [pscustomobject]@{
        Name = [IO.Path]::GetFileName($Image); ProcessId = $Id; ParentProcessId = $Parent
        CreationDate = ([datetime]'2026-01-01T00:00:00Z').AddSeconds($Order); SessionId = 2
        ExecutablePath = $Image; CommandLine = ('"{0}" clipboard_agent.py' -f $Image); Directory = 'C:\DLP\agent'
        FirstVisible = 1; LastVisible = 100; ExitsAt = 100; Delay = 3; Graceful = $false; StaleSnapshot = $false
    }
}

function Scenario($Processes, [int]$TaskExit = 0) {
    $state = @{
        Poll = 0; Processes = @($Processes)
        Quit = [Collections.Generic.HashSet[uint32]]::new()
        Forced = [Collections.Generic.List[uint32]]::new()
        Disposal = [Collections.Generic.HashSet[uint32]]::new()
    }
    $task = [pscustomobject]@{ Enabled = $false; ExitsAt = $TaskExit; StopCalls = 0; State = $state }
    $task | Add-Member ScriptMethod GetInstances {
        param($flags)
        return @{ Count = [int]($this.State.Poll -lt $this.ExitsAt) }
    }
    $task | Add-Member ScriptMethod Stop {
        param($flags)
        if ($this.Enabled) { throw 'Scheduler stop before fence.' }
        $this.StopCalls++
        $this.ExitsAt = $this.State.Poll + 2
    }
    $state.Entry = @{ Python = $launcher; Task = $task }
    return $state
}

# Each Check provides a scenario. No fake PID is opened by the native helper.
function Get-DlpProcesses {
    $scenario.Poll++
    $scenario.Processes | Where-Object {
        $scenario.Poll -ge $_.FirstVisible -and $scenario.Poll -le $_.LastVisible -and $scenario.Poll -lt $_.ExitsAt
    }
}
function Open-DlpClipboardWorker($Process, [bool]$CanTerminate) {
    if ($scenario.Entry.Task.Enabled) { throw 'PID inspection before the task was disabled.' }
    if ($Process.StaleSnapshot) { return }
    $handle = [pscustomobject]@{ Record = $Process; State = $scenario; CanTerminate = $CanTerminate
        CreationTime = $Process.CreationDate.ToFileTimeUtc() }
    $handle | Add-Member ScriptProperty HasExited { $this.State.Poll -ge $this.Record.ExitsAt }
    $handle | Add-Member ScriptMethod WorkingDirectory { $this.Record.Directory }
    $handle | Add-Member ScriptMethod RequestExit {
        $null = $this.State.Quit.Add($this.Record.ProcessId)
        if ($this.Record.Graceful) { $this.Record.ExitsAt = $this.State.Poll + $this.Record.Delay }
        return $this.Record.Graceful
    }
    $handle | Add-Member ScriptMethod Terminate {
        if (-not $this.CanTerminate -or $this.State.Entry.Task.Enabled) { throw 'Unverified force stop.' }
        $this.State.Forced.Add($this.Record.ProcessId)
        $this.Record.ExitsAt = $this.State.Poll + $this.Record.Delay
    }
    $handle | Add-Member ScriptMethod Dispose { $null = $this.State.Disposal.Add($this.Record.ProcessId) }
    return $handle
}
function Start-Sleep([int]$Milliseconds) {}
function Get-DlpClipboardElapsed($Timer) { return $scenario.Poll * 250 }

Check 'the LAB01 launcher and interpreter are stopped leaf-first and their delayed exit is confirmed' {
    $root = Worker 9228 8000 $launcher
    $child = Worker 9240 9228 $interpreter 2
    $unrelated = Worker 9250 8000 $interpreter
    $unrelated.Directory = 'C:\Other\project'
    $substring = Worker 9260 8000 $interpreter
    $substring.CommandLine = '"C:\Program Files\DLP-C1-Lab\Python312\python.exe" demo.py clipboard_agent.py'
    $scenario = Scenario @($child, $unrelated, $substring, $root)
    Stop-DlpClipboardTask $scenario.Entry
    Assert (($scenario.Forced -join ',') -eq '9240,9228')
    Assert ($scenario.Poll -gt $root.ExitsAt -and $scenario.Poll -gt $child.ExitsAt)
    Assert ($scenario.Quit.Count -eq 2 -and $unrelated.ExitsAt -eq 100 -and $substring.ExitsAt -eq 100)
    Assert ($scenario.Disposal.Contains([uint32]9228) -and $scenario.Disposal.Contains([uint32]9240))
}
Check 'an accessible Clipboard message loop is allowed to exit cooperatively' {
    $root = Worker 9228 8000 $launcher
    $child = Worker 9240 9228 $interpreter 2
    $root.Graceful = $true
    $child.Graceful = $true
    $scenario = Scenario @($root, $child) 5
    Stop-DlpClipboardTask $scenario.Entry
    Assert ($scenario.Quit.Count -eq 2 -and $scenario.Forced.Count -eq 0 -and $scenario.Entry.Task.StopCalls -eq 0)
}
Check 'scheduler stop is issued once and its delayed idle state is observed' {
    $scenario = Scenario @() 100
    Stop-DlpClipboardTask $scenario.Entry
    Assert ($scenario.Entry.Task.StopCalls -eq 1 -and $scenario.Poll -gt $scenario.Entry.Task.ExitsAt)
}
Check 'a stale PID snapshot is rescanned without signalling the reused PID' {
    $old = Worker 9228 8000 $launcher
    $old.StaleSnapshot = $true
    $old.LastVisible = 1
    $replacement = Worker 9228 8001 $interpreter 2
    $replacement.FirstVisible = 2
    $replacement.Directory = 'C:\Other\project'
    $scenario = Scenario @($old, $replacement)
    Stop-DlpClipboardTask $scenario.Entry
    Assert ($scenario.Quit.Count -eq 0 -and $scenario.Forced.Count -eq 0 -and $replacement.ExitsAt -eq 100)
}
Check 'a late interpreter can be matched to a pinned launcher after the launcher exits' {
    $root = Worker 9228 8000 $launcher
    $root.ExitsAt = 5
    $child = Worker 9240 9228 $interpreter 2
    $child.FirstVisible = 6
    $child.CommandLine = '"C:\DLP\venv\Scripts\python.exe" clipboard_agent.py'
    $scenario = Scenario @($root, $child)
    Stop-DlpClipboardTask $scenario.Entry
    Assert (($scenario.Forced -join ',') -eq '9240' -and $scenario.Poll -gt $child.ExitsAt)
}
Check 'an orphan interpreter, the wrong working directory, and an unexpected child each hold cutover' {
    $orphan = Worker 9240 9228 $interpreter 2
    $scenario = Scenario @($orphan)
    Reject { Stop-DlpClipboardTask $scenario.Entry } '*Unverified PIDs*9240*'
    Assert ($scenario.Forced.Count -eq 0 -and $scenario.Quit.Count -eq 0)

    $wrongDirectory = Worker 9228 8000 $launcher
    $wrongDirectory.Directory = 'C:\Other\project'
    $scenario = Scenario @($wrongDirectory)
    Reject { Stop-DlpClipboardTask $scenario.Entry } '*Unverified PIDs*9228*'
    Assert ($scenario.Forced.Count -eq 0 -and $scenario.Quit.Count -eq 0)

    $root = Worker 9228 8000 $launcher
    $unexpected = Worker 9240 9228 $interpreter 2
    $unexpected.SessionId = 3
    $scenario = Scenario @($root, $unexpected) 100
    Reject { Stop-DlpClipboardTask $scenario.Entry } '*Unverified PIDs*9240*'
    Assert ($scenario.Forced.Count -eq 0 -and $scenario.Quit.Count -eq 0 -and $scenario.Entry.Task.StopCalls -eq 0)
}
Check 'a verified worker that never signals exit cannot pass the cutover gate' {
    $root = Worker 9228 8000 $launcher
    $root.Delay = 100
    $scenario = Scenario @($root)
    Reject { Stop-DlpClipboardTask $scenario.Entry } '*Verified worker PIDs*9228*'
    Assert (($scenario.Forced -join ',') -eq '9228' -and -not $scenario.Entry.Task.Enabled)
}
Check 'the final shared gate holds a late interpreter until it exits' {
    $orphan = Worker 9240 9228 $interpreter 2
    $orphan.FirstVisible = 4
    $orphan.ExitsAt = 7
    $scenario = Scenario @($orphan)
    $scenario.Entry.Task.Enabled = $true
    $inventory = @{ Services = @{}; Tasks = @{ DLPClipboardAgent = $scenario.Entry } }
    function Get-DlpSharedInventory { return $inventory }
    Stop-DlpSharedWork $null $inventory
    Assert ($scenario.Poll -ge $orphan.ExitsAt -and $scenario.Quit.Count -eq 0 -and $scenario.Forced.Count -eq 0)
}
Check 'a task that was not fenced authorizes no process operations' {
    $scenario = Scenario @((Worker 9228 8000 $launcher))
    $scenario.Entry.Task.Enabled = $true
    Reject { Stop-DlpClipboardTask $scenario.Entry } '*must remain disabled*'
    Assert ($scenario.Poll -eq 0 -and $scenario.Quit.Count -eq 0 -and $scenario.Forced.Count -eq 0)
}

Check 'native process handles verify creation time and directory and report actual exit' {
    $code = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Start-Sleep -Seconds 12'))
    $options = @{
        FilePath = $DlpSystemPowerShell; ArgumentList = @('-NoProfile', '-NonInteractive', '-EncodedCommand', $code)
        WorkingDirectory = $PSScriptRoot; WindowStyle = 'Hidden'; PassThru = $true
    }
    $child = Start-Process @options
    $verified = $null
    try {
        $time = $child.StartTime.ToUniversalTime().ToFileTimeUtc()
        $wrong = [DlpInstaller.ClipboardWorker]::Open($child.Id, ($time - 10000000), $child.SessionId, $DlpSystemPowerShell, $true)
        if ($wrong) { $wrong.Dispose(); throw 'An incorrect creation time matched the process.' }
        $verified = [DlpInstaller.ClipboardWorker]::Open($child.Id, $time, $child.SessionId, $DlpSystemPowerShell, $true)
        Assert ($verified -and -not $verified.HasExited -and $verified.WorkingDirectory() -ieq $PSScriptRoot)
        $verified.Terminate()
        Assert ($child.WaitForExit(5000) -and $verified.HasExited)
    } finally {
        if ($verified) { $verified.Dispose() }
        $null = $child.WaitForExit(15000)
        $child.Dispose()
    }
}
Write-Output "$script:passed Clipboard shutdown tests passed."
