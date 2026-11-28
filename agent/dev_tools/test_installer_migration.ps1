# Requires an ordinary Windows token. Only synthetic fixtures are mutated.
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from a non-elevated console.' }
$service = Join-Path (Split-Path -Parent $PSScriptRoot) 'service'
foreach ($file in 'curl_task.ps1', 'installer_python.ps1', 'installer_migration.ps1', 'installer_enrollment.ps1', 'installer_services.ps1') {
    . (Join-Path $service $file)
}
Add-Type -Path (Join-Path $service 'installer_paths.cs')

$script:passed = 0
function Assert($Condition) { if (-not $Condition) { throw 'Assertion failed.' } }
function Reject([scriptblock]$Body, [string]$Pattern) {
    try { & $Body } catch { if ($_.Exception.Message -like $Pattern) { return }; throw }
    throw "Expected failure matching $Pattern"
}
function Check([string]$Name, [scriptblock]$Body) {
    & $Body
    $script:passed++
    Write-Output "PASS $Name"
}

$sample = [Text.Encoding]::UTF8.GetBytes(@'
[agent]
hostname = LAB-PC
server_url = https://lab.example/dlp/api
api_token = migration-test-token
enrollment_key = unused-test-key
firewall_drop_log = false
[browser]
extension_ids = one@example, two@example
'@)
$layout = @{ InstallDir = 'C:\DLP'; Config = @{ Bytes = $sample }; InstallIssues = @('unsafe legacy ACL') }
$source = Split-Path -Parent $service
$script:requests = [Collections.Generic.List[string]]::new()
$script:reportedName = 'LAB-PC'
function Read-DlpPolicyResponse([uri]$Uri, [string]$Token) {
    Assert ($Token -eq 'migration-test-token')
    $script:requests.Add($Uri.AbsoluteUri)
    [pscustomobject]@{ hostname = $script:reportedName }
}

function Get-ConfigRights($Acl) {
    $rights = @{}
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $rights[$rule.IdentityReference.Value] = [int]$rule.FileSystemRights
    }
    return $rights
}

Check 'enrollment file ACLs allow Users read access only to key-free config' {
    $config = Read-DlpConfig $sample 'test config'
    $private = Get-DlpConfigFileAcl $config
    $rights = Get-ConfigRights $private
    Assert ($private.AreAccessRulesProtected -and $private.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544')
    Assert ($rights.Count -eq 2 -and $rights['S-1-5-18'] -eq 0x1F01FF -and $rights['S-1-5-32-544'] -eq 0x1F01FF)
    $config.agent.Remove('enrollment_key')
    $readable = Get-DlpConfigFileAcl $config
    $rights = Get-ConfigRights $readable
    Assert ($readable.AreAccessRulesProtected -and $rights.Count -eq 3 -and $rights['S-1-5-32-545'] -eq 0x120089)
    Assert (-not (Get-ConfigRights (Get-DlpConfigFileAcl $config -Private)).ContainsKey('S-1-5-32-545'))
}

Check 'unattended fresh install requires a server and a real key' {
    $clean = @{ InstallDir = 'C:\DLP' }
    $absentSource = Join-Path $source ([guid]::NewGuid().ToString('N'))
    Reject { Resolve-DlpEnrollment $clean $absentSource '' 'LAB-PC' 'test' -NoPrompt } '*requires -ServerUrl*'
    Reject { Resolve-DlpEnrollment $clean $absentSource 'https://lab.example/api' 'LAB-PC' '' -NoPrompt } '*key or existing device token*'
    Reject { Resolve-DlpEnrollment $clean $absentSource 'https://lab.example/api' 'LAB-PC' 'DAN-ENROLLMENT-KEY-TU-TRANG-SETTINGS-VAO-DAY' -NoPrompt } '*key or existing device token*'
    Reject { Resolve-DlpEnrollment $clean $absentSource 'https://lab.example/api?x=1' 'LAB-PC' 'test' -NoPrompt } '*without credentials*'
}
Check 'legacy tokens are sent only for independently approved server and hostname' {
    $script:requests.Clear()
    Reject { Resolve-DlpEnrollment $layout $source '' 'LAB-PC' '' -NoPrompt } '*independently supplied -ServerUrl*'
    Reject { Resolve-DlpEnrollment $layout $source 'https://other.example/dlp/api' 'LAB-PC' '' -NoPrompt } '*differs from the saved enrollment URL*'
    Reject { Resolve-DlpEnrollment $layout $source 'https://lab.example/dlp/api' 'OTHER-PC' '' -NoPrompt } '*differs from the saved device identity*'
    Assert ($script:requests.Count -eq 0)
    $config = Resolve-DlpEnrollment $layout $source 'https://lab.example/dlp/api/' 'LAB-PC' '' -NoPrompt
    Assert ($script:requests.Count -eq 1 -and $script:requests[0] -eq 'https://lab.example/dlp/api/agent_policy.php')
    $export = Read-DlpConfig (ConvertTo-DlpConfigBytes $config) 'recovery file'
    Assert ($export.agent.api_token -eq 'migration-test-token' -and -not $export.agent.enrollment_key)
    Assert ($export.agent.firewall_drop_log -eq 'false' -and $export.browser.extension_ids -eq 'one@example, two@example')
}
Check 'server must confirm the enrolled identity' {
    $script:reportedName = 'OTHER-PC'
    Reject { Resolve-DlpEnrollment $layout $source 'https://lab.example/dlp/api' 'LAB-PC' '' -NoPrompt } '*different enrolled hostname*'
    $script:reportedName = 'LAB-PC'
}
Check 'setup publishes fresh enrollment before starting the other consumers' {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $service 'install.ps1'), [ref]$tokens, [ref]$errors)
    Assert ($errors.Count -eq 0)
    $commands = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
    $starts = @($commands | Where-Object { $_.GetCommandName() -eq 'Invoke-DlpNssm' -and $_.Extent.Text -like "*'start'*" })
    $publish = $commands | Where-Object { $_.GetCommandName() -eq 'Publish-DlpEnrolledConfig' }
    $wait = $commands | Where-Object { $_.GetCommandName() -eq 'Wait-DlpEnrollment' }
    Assert ($starts.Count -eq 2 -and $starts[0].Extent.Text -like "*'DLPNetworkAgent'*")
    Assert ($starts[0].Extent.EndOffset -lt $wait.Extent.StartOffset -and $wait.Extent.EndOffset -lt $publish.Extent.StartOffset)
    Assert ($publish.Extent.EndOffset -lt $starts[1].Extent.StartOffset)
    foreach ($command in ($commands | Where-Object { $_.GetCommandName() -in 'Complete-CurlInstall', 'Register-DlpDesktopTask' })) {
        Assert ($publish.Extent.EndOffset -lt $command.Extent.StartOffset)
    }
}
Check 'non-loopback HTTP requires isolated lab approval' {
    $httpSample = [Text.Encoding]::UTF8.GetBytes([Text.Encoding]::UTF8.GetString($sample).Replace('https://', 'http://'))
    $http = @{ InstallDir = 'C:\DLP'; Config = @{ Bytes = $httpSample }; InstallIssues = @('unsafe legacy ACL') }
    $script:requests.Clear()
    Reject { Resolve-DlpEnrollment $http $source 'http://lab.example/dlp/api' 'LAB-PC' '' -NoPrompt } '*AllowInsecureLabServer*'
    Assert ($script:requests.Count -eq 0)
    $config = Resolve-DlpEnrollment $http $source 'http://lab.example/dlp/api' 'LAB-PC' '' -NoPrompt -AllowInsecureLabServer
    Assert ($config.agent.api_token -eq 'migration-test-token')
}
Check 'duplicate INI fields and extra sections are rejected without echoing values' {
    $duplicate = [Text.Encoding]::UTF8.GetBytes("[agent]`nhostname = LAB-PC`nhostname = OTHER-PC")
    Reject { Read-DlpConfig $duplicate 'config.ini' } '*duplicate enrollment setting*line 3*'
    $extra = [Text.Encoding]::UTF8.GetBytes("[agent]`nhostname = LAB-PC`n[other]")
    Reject { Read-DlpConfig $extra 'config.ini' } '*unsupported*line 3*'
}
Check 'writable roots need a recognized installation identity' {
    $inventory = @{ Services = @{}; Tasks = @{} }
    Reject { Assert-DlpInstallIdentity $layout $inventory $null } '*no recognized DLP registration*'
    $inventory.Services.DLPNetworkAgent = @{}
    Assert-DlpInstallIdentity $layout $inventory $null
}
Check 'legacy service and desktop actions are recognized by full definition' {
    $oldPython = 'C:\DLP\venv\Scripts\python.exe'
    $cim = @{ Name = 'DLPNetworkAgent'; PathName = 'C:\DLP\tools\nssm.exe'; ServiceType = 'Own Process'; StartName = 'LocalSystem' }
    Assert-DlpServiceRegistration $cim 'DLPNetworkAgent' $oldPython 'C:\DLP\agent' '-u C:\DLP\agent\network_agent.py'
    Reject { Assert-DlpServiceRegistration $cim 'DLPNetworkAgent' 'C:\Other\python.exe' 'C:\DLP\agent' '-u C:\DLP\agent\network_agent.py' } '*Unrecognized DLP service registration*'
    $oldArgs = (Get-DlpClipboardArgs $oldPython).Replace("'$oldPython'", $oldPython)
    Assert (Test-DlpDesktopAction 'DLPClipboardAgent' $oldArgs)
    Assert (-not (Test-DlpDesktopAction 'DLPClipboardAgent' ($oldArgs + ' extra')))
    Assert (Test-DlpDesktopAction 'DLPNotifier' $DlpNotifierArgs)
}
Check 'native NSSM wrapper requires and reports the actual command exit' {
    $native = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
    Invoke-DlpNssm $native @('/d', '/c', 'exit', '0')
    Reject { Invoke-DlpNssm $native @('/d', '/c', 'exit', '7') } '*exit 7*'
}
Check 'wrapper-only status cannot satisfy the worker health check' {
    $app = Join-Path $DlpRuntimes ('a' * 32 + '\Scripts\python.exe')
    $base = 'C:\Program Files\Python313\python.exe'
    $cim = @{ Name = 'DLPNetworkAgent'; ProcessId = 50; State = 'Running' }
    $wrapper = [pscustomobject]@{ ProcessId = 50; ParentProcessId = 1; CreationDate = [datetime]'2026-01-01'; ExecutablePath = $DlpNssm }
    $worker = [pscustomobject]@{
        ProcessId = 51; ParentProcessId = 50; CreationDate = $wrapper.CreationDate.AddSeconds(1)
        ExecutablePath = $base; CommandLine = '"C:\Program Files\Python313\python.exe" -E -s -u C:\DLP\agent\network_agent.py'
    }
    $unrelated = [pscustomobject]@{
        ProcessId = 52; ParentProcessId = 1; CreationDate = $worker.CreationDate
        ExecutablePath = $base; CommandLine = 'python unrelated.py'
    }
    Assert (-not @(Get-DlpServiceWorkers @($wrapper, $unrelated) $cim $app $base).Count)
    $found = @(Get-DlpServiceWorkers @($wrapper, $worker, $unrelated) $cim $app $base)
    Assert ($found.Count -eq 1 -and $found[0].ProcessId -eq 51)
    Assert (-not (Test-DlpSharedProcess $unrelated))
}
Check 'unrelated or changed registrations fail the cutover identity check' {
    $before = @{ Services = @{ DLPNetworkAgent = @{ Signature = 'original' } }; Tasks = @{} }
    $after = @{ Services = @{ DLPNetworkAgent = @{ Signature = 'changed' } }; Tasks = @{} }
    Reject { Assert-DlpSameInventory $before $after } '*DLPNetworkAgent*changed*'
}
Check 'shared shutdown fences only recognized registrations and checks the stop result' {
    $events = [Collections.Generic.List[string]]::new()
    $controlled = [pscustomobject]@{ StartMode = 'Auto'; State = 'Running'; ProcessId = 0 }
    $task = [pscustomobject]@{ Enabled = $true; Active = 1 }
    $task | Add-Member ScriptMethod GetInstances { param($flags) return @{ Count = $this.Active } }
    $task | Add-Member ScriptMethod Stop { param($flags) $this.Active = 0 }
    $known = @{ Services = @{ DLPNetworkAgent = @{ Signature = 'verified' } }
        Tasks = @{ DLPClipboardAgent = @{ Signature = 'verified'; Task = $task } } }
    function Get-DlpSharedInventory { return $known }
    function Get-DlpService { return $controlled }
    function Invoke-DlpSc($Arguments) {
        Assert ($Arguments[0] -eq 'config' -and $Arguments[1] -eq 'DLPNetworkAgent' -and $Arguments[-1] -eq 'disabled')
        $events.Add('fence service')
        $controlled.StartMode = 'Disabled'
    }
    function Stop-DlpVerifiedService($Name) {
        Assert ($Name -eq 'DLPNetworkAgent' -and -not $task.Enabled -and $controlled.StartMode -eq 'Disabled')
        $events.Add('stop service')
        $controlled.State = 'Stopped'
    }
    function Stop-DlpClipboardTask($Entry) {
        Assert (-not $Entry.Task.Enabled)
        $Entry.Task.Stop(0)
    }
    function Get-DlpProcesses { [pscustomobject]@{ ProcessId = 200; Name = 'python.exe'; CommandLine = 'python unrelated.py' } }
    Stop-DlpSharedWork $null $known
    Assert ($events.Count -eq 2 -and $task.Active -eq 0)
    $controlled.State = 'Running'
    function Stop-DlpVerifiedService {}
    Reject { Stop-DlpSharedWork $null $known } '*no longer fenced and stopped*'
}

function Open-FixtureRoot([string]$Path) {
    $root = [IO.Path]::GetPathRoot($Path)
    $handle = [DlpInstaller.Paths]::OpenVolume($root)
    try {
        foreach ($name in ($Path.Substring($root.Length) -split '\\')) {
            $child = [DlpInstaller.Paths]::OpenChild($handle, $name, $true, $false)
            if (-not $child) { throw "Missing fixture '$Path'." }
            $handle.Dispose()
            $handle = $child
        }
        return $handle
    } catch { $handle.Dispose(); throw }
}

$temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$scratch = Join-Path $temp ('DlpMigrationTest-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($scratch)
$anchor = $null
$archive = $null
$oldInstall = $null
$oldData = $null
try {
    foreach ($dir in 'active\agent', 'data\logs', 'recovery\next-install', 'recovery\next-data', 'collision') {
        $null = [IO.Directory]::CreateDirectory((Join-Path $scratch $dir))
    }
    $configPath = Join-Path $scratch 'active\agent\config.ini'
    [IO.File]::WriteAllBytes($configPath, $sample)
    [IO.File]::WriteAllText((Join-Path $scratch 'active\old.exe'), 'inert legacy fixture')
    [IO.File]::WriteAllText((Join-Path $scratch 'data\logs\history.log'), 'synthetic history')
    $anchor = Open-FixtureRoot $scratch
    $activePath = Join-Path $scratch 'active'
    $dataPath = Join-Path $scratch 'data'
    $archivePath = Join-Path $scratch 'recovery'
    $oldInstall = Open-DlpChild $anchor $activePath -Directory
    $oldData = Open-DlpChild $anchor $dataPath -Directory
    $archive = Open-DlpChild $anchor $archivePath -Directory
    $fixture = @{ Volume = $anchor; DataParent = $anchor; Install = $oldInstall; Data = $oldData
        InstallDir = $activePath; DataDir = $dataPath; Config = Read-DlpEnrollmentSnapshot $oldInstall $activePath }

    Check 'native fresh enrollment keeps failed publication private and publishes only the validated token' {
        $fixtureSids = ((Get-Acl -LiteralPath $scratch).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) |
            Where-Object { $_.AccessControlType -eq 'Allow' -and $_.IdentityReference.Value -like 'S-1-5-21-*' }).IdentityReference
        $productionAcl = ${function:Get-DlpConfigFileAcl}
        function Get-DlpConfigFileAcl($Config, [switch]$Private) {
            # Give this non-elevated fixture's user and sandbox identities
            # access to act as setup and the service.
            $original = & $productionAcl $Config -Private:$Private
            $acl = [Security.AccessControl.FileSecurity]::new()
            $acl.SetSecurityDescriptorSddlForm($original.GetSecurityDescriptorSddlForm('Access'))
            foreach ($sid in $fixtureSids) {
                $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
            }
            return $acl
        }
        $live = Join-Path $scratch 'enrollment.ini'
        $failedRecovery = Join-Path $scratch 'failed-enrollment'
        $successfulRecovery = Join-Path $scratch 'successful-enrollment'
        foreach ($path in $failedRecovery, $successfulRecovery) { [IO.Directory]::CreateDirectory($path) | Out-Null }
        $issued = Read-DlpConfig $sample 'network agent output'
        $initial = Read-DlpConfig $sample 'initial config'
        $initial.agent.api_token = ''
        New-DlpConfigFile $live $initial
        Assert (-not (Get-ConfigRights ([IO.File]::GetAccessControl($live))).ContainsKey('S-1-5-32-545'))
        # The network agent truncates and writes the same file to save its token.
        [IO.File]::WriteAllBytes($live, (ConvertTo-DlpConfigBytes $issued))
        Assert (-not (Get-ConfigRights ([IO.File]::GetAccessControl($live))).ContainsKey('S-1-5-32-545'))

        Reject { Publish-DlpEnrolledConfig $live $failedRecovery $issued } '*sanitized configuration*'
        $script:reportedName = 'OTHER-PC'
        try { Reject { Wait-DlpEnrollment $live $initial } '*different enrolled hostname*' }
        finally { $script:reportedName = 'LAB-PC' }
        $enrolled = Wait-DlpEnrollment $live $initial
        Assert (-not $enrolled.agent.ContainsKey('enrollment_key'))
        $reader = [IO.File]::Open($live, 'Open', 'Read', 'Read')
        try { Reject { Publish-DlpEnrolledConfig $live $failedRecovery $enrolled } '*Could not publish sanitized configuration*' }
        finally { $reader.Dispose() }
        $unchanged = Read-DlpConfig ([IO.File]::ReadAllBytes($live)) $live
        Assert ($unchanged.agent.enrollment_key -eq $initial.agent.enrollment_key)
        Assert (-not (Get-ConfigRights ([IO.File]::GetAccessControl($live))).ContainsKey('S-1-5-32-545'))
        $backup = Join-Path $failedRecovery 'enrolled-config.ini'
        Assert (-not (Get-ConfigRights ([IO.File]::GetAccessControl($backup))).ContainsKey('S-1-5-32-545'))
        Assert ((Read-DlpConfig ([IO.File]::ReadAllBytes($backup)) $backup).agent.api_token -eq $issued.agent.api_token)

        Publish-DlpEnrolledConfig $live $successfulRecovery $enrolled
        $published = Read-DlpConfig ([IO.File]::ReadAllBytes($live)) $live
        Assert ($published.agent.api_token -eq $issued.agent.api_token -and -not $published.agent.ContainsKey('enrollment_key'))
        Assert ((Get-ConfigRights ([IO.File]::GetAccessControl($live)))['S-1-5-32-545'] -eq 0x120089)
    }

    Check 'interrupted cutover marker blocks retry and identifies its recovery directory' {
        $state = @{ Pending = (Join-Path $scratch 'pending') }
        $recovery = Join-Path $scratch ('a' * 32)
        Start-DlpCutover $state $recovery
        try {
            # Only the host-owned ACL check is faked for this synthetic file.
            function Assert-CurlProtectedPath {}
            Reject { Assert-DlpNoPendingCutover $scratch $state.Pending } "*interrupted DLP cutover*$recovery*"
        } finally { [IO.File]::Delete($state.Pending) }
    }
    Check 'native config reader rejects hard links and concurrent writers' {
        $hardLink = Join-Path $scratch 'linked.ini'
        New-Item -ItemType HardLink -Path $hardLink -Target $configPath | Out-Null
        try { Reject { Read-DlpEnrollmentSnapshot $oldInstall $activePath } '*exactly one hard link*' }
        finally { [IO.File]::Delete($hardLink) }
        $writer = [IO.File]::Open($configPath, 'Open', 'Write', 'ReadWrite')
        try { Reject { Read-DlpEnrollmentSnapshot $oldInstall $activePath } '*Cannot open*config.ini*safely*' }
        finally { $writer.Dispose() }
    }
    Check 'native directory handles reject junctions without following the target' {
        $link = Join-Path $scratch 'junction'
        New-Item -ItemType Junction -Path $link -Target (Join-Path $scratch 'collision') | Out-Null
        try { Reject { Open-DlpChild $anchor $link -Directory } '*Reparse point*' }
        finally { [IO.Directory]::Delete($link) }
    }
    Check 'native no-replace rename preserves the source on a destination collision' {
        $renameHandle = Get-DlpRenameSource $anchor $activePath $oldInstall
        try { Reject { Move-DlpDirectory $renameHandle $anchor (Join-Path $scratch 'collision') } '*Cannot move directory*collision*' }
        finally { $renameHandle.Dispose() }
        Assert ([IO.File]::Exists($configPath))
    }
    Check 'cutover detects changed enrollment before moving either legacy root' {
        [IO.File]::WriteAllText($configPath, 'changed snapshot')
        Reject { Move-DlpLayout $fixture $archive $archivePath -Publish } '*Enrollment changed*config.ini*'
        Assert ([IO.Directory]::Exists($dataPath) -and [IO.Directory]::Exists($activePath))
        [IO.File]::WriteAllBytes($configPath, $sample)
    }
    Check 'native cutover retains old logs and code in archives only' {
        Move-DlpLayout $fixture $archive $archivePath -Publish
        Assert ([IO.Directory]::Exists($activePath) -and [IO.Directory]::Exists($dataPath))
        Assert (-not [IO.File]::Exists((Join-Path $activePath 'old.exe')))
        Assert ([IO.File]::Exists((Join-Path $archivePath 'previous-install\old.exe')))
        Assert ([IO.File]::ReadAllText((Join-Path $archivePath 'previous-data\logs\history.log')) -eq 'synthetic history')
    }
} finally {
    foreach ($handle in $oldData, $oldInstall, $archive, $anchor) { if ($handle) { $handle.Dispose() } }
    $resolved = (Resolve-Path -LiteralPath $scratch).ProviderPath
    if ($resolved -ine $scratch -or (Split-Path -Parent $resolved) -ine $temp) { throw 'Unexpected fixture cleanup path.' }
    # Only the fixed synthetic files and empty directories can be removed.
    foreach ($file in 'active\agent\config.ini', 'active\old.exe', 'data\logs\history.log', 'linked.ini', 'enrollment.ini',
        'failed-enrollment\enrolled-config.ini', 'successful-enrollment\enrolled-config.ini',
        'recovery\previous-install\agent\config.ini', 'recovery\previous-install\old.exe', 'recovery\previous-data\logs\history.log') {
        $path = Join-Path $scratch $file
        if ([IO.File]::Exists($path)) { [IO.File]::Delete($path) }
    }
    foreach ($dir in 'junction', 'active\agent', 'active', 'data\logs', 'data', 'collision', 'failed-enrollment', 'successful-enrollment',
        'recovery\next-install', 'recovery\next-data',
        'recovery\previous-install\agent', 'recovery\previous-install', 'recovery\previous-data\logs', 'recovery\previous-data', 'recovery') {
        $path = Join-Path $scratch $dir
        if ([IO.Directory]::Exists($path)) { [IO.Directory]::Delete($path) }
    }
    [IO.Directory]::Delete($scratch)
}
Write-Output "$script:passed migration installer tests passed."
