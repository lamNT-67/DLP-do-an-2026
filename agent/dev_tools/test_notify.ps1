$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'service\notify.ps1')
Initialize-DlpNotifier

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User
if (([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run these notifier fixtures without elevation.'
}
$identity.Dispose()
$script:passed = 0
function Check([string]$Name, [scriptblock]$Body) {
    & $Body
    $script:passed++
    Write-Output "PASS $Name"
}
function Assert($Condition) { if (-not $Condition) { throw 'Assertion failed.' } }

$started = [DateTimeOffset]'2026-01-01T00:00:00.123456+00:00'
$logon = @{ SessionId = 2; Luid = '00000000000003e4' }
$utf8 = [Text.UTF8Encoding]::new($false)
$lf = [string][char]10

function New-Block {
    # Matches the managed CurlJournal local schema, including the report-independent stop result.
    [pscustomobject]@{
        timestamp = '2026-01-01T07:00:00.654321+07:00'
        event_id = [guid]::NewGuid().ToString('N')
        agent_module = 'curl'
        exit_point_type = 'CLIENT_CURL'
        event_type = 'violation'
        policy_state = 'BLOCK'
        source = [pscustomobject]@{ process_name = 'curl.exe'; process_pid = 93; process_create_time = 123.25
            session_id = $logon.SessionId; logon_luid = $logon.Luid }
        target = [pscustomobject]@{ file_path = 'sample.txt'; destination_value = 'upload.test:443' }
        content_inspection = [pscustomobject]@{ verdict = 'BLOCK'; reason = 'CONTENT_MATCH'; coverage = $false }
        action_taken = 'BLOCKED_KILL'
        enforcement = [pscustomobject]@{ suspension = 'SUSPENDED'; termination_attempted = $true
            termination = 'CONFIRMED'; resume = 'PROCESS_EXITED' }
        reported_to_server = $false
    }
}

Check 'confirmed Curl block displays a file and destination independently of server delivery' {
    $seen = [Collections.Generic.HashSet[string]]::new()
    $record = (New-Block | ConvertTo-Json -Depth 6 -Compress) | ConvertFrom-Json
    $message = Get-DlpCurlNotification $record $logon $started $seen
    Assert ($message.Title -eq 'DLP - Tai len curl bi chan')
    Assert ($message.Text -match 'Curl da bi dung' -and $message.Text -match 'sample\.txt' -and
        $message.Text -match 'upload\.test:443' -and $message.Text -notmatch 'bytes|CONTENT_MATCH')
    Assert (-not (Get-DlpCurlNotification $record $logon $started $seen))
    Assert (Get-DlpCurlNotification (New-Block) $logon $started $seen) # Same file and destination, distinct event.
}

Check 'ALLOW, REPORT_ONLY, failed, unconfirmed and malformed decisions stay quiet' {
    $seen = [Collections.Generic.HashSet[string]]::new()
    foreach ($change in @(
        { $_.action_taken = 'ALLOWED' },
        { $_.action_taken = 'LOGGED' },
        { $_.policy_state = 'REPORT_ONLY' },
        { $_.content_inspection.verdict = 'LOG' },
        { $_.content_inspection.coverage = $true },
        { $_.event_type = 'coverage' },
        { $_.enforcement.termination = 'TERMINATION_FAILED' },
        { $_.enforcement.termination = 'TERMINATION_UNCONFIRMED' },
        { $_.enforcement.termination = 'EXITED_BEFORE_TERMINATION' },
        { $_.enforcement.termination_attempted = $false },
        { $_.enforcement.termination_attempted = 'true' },
        { $_.event_id = 'invalid' },
        { $_.action_taken = @('BLOCKED_KILL') },
        { $_.enforcement = @($_.enforcement) }
    )) {
        $event = New-Block
        $event | ForEach-Object $change
        Assert (-not (Get-DlpCurlNotification $event $logon $started $seen))
    }
    Assert ($seen.Count -eq 0)
}

Check 'unknown and foreign logons and historical records cannot notify' {
    $seen = [Collections.Generic.HashSet[string]]::new()
    $event = New-Block
    $event.source.session_id = 3
    Assert (-not (Get-DlpCurlNotification $event $logon $started $seen))
    $event.source.session_id = 2
    $event.source.logon_luid = '0000000000001234'
    Assert (-not (Get-DlpCurlNotification $event $logon $started $seen))
    $event.source.PSObject.Properties.Remove('logon_luid')
    Assert (-not (Get-DlpCurlNotification $event $logon $started $seen))
    $event.source | Add-Member -NotePropertyName logon_luid -NotePropertyValue $logon.Luid
    foreach ($stamp in 'invalid', '2026-01-01T00:00:00.123456+00:00', '2025-12-31T23:59:59+00:00') {
        $event.timestamp = $stamp
        Assert (-not (Get-DlpCurlNotification $event $logon $started $seen))
    }
    Assert ($seen.Count -eq 0)
}

Check 'private notification fields omit paths, credentials, and content and accept an IPv6 endpoint' {
    $seen = [Collections.Generic.HashSet[string]]::new()
    $event = New-Block
    $event.target.file_path = 'C:\private\SECRET.txt'
    $event.target.destination_value = 'https://user:SECRET@upload.test/private?token=SECRET'
    $event.content_inspection.reason = 'SECRET'
    $message = Get-DlpCurlNotification $event $logon $started $seen
    Assert ($message.Text -eq 'Curl da bi dung theo chinh sach bao mat.')
    $event = New-Block
    $event.target.file_path = ('a' * 120) + '.txt'
    $event.target.destination_value = '[2001:db8::1]:443'
    $message = Get-DlpCurlNotification $event $logon $started $seen
    Assert ($message.Text -match '\.\.\.' -and $message.Text -match '\[2001:db8::1\]:443' -and $message.Text.Length -lt 255)
}

Check 'shared journal keeps other module alerts and excludes Curl records' {
    $last = @{}
    Assert (-not (Get-DlpSharedNotification (New-Block) $last))
    $other = [pscustomobject]@{
        agent_module = 'network'
        action_taken = 'BLOCKED_FIREWALL'
        source = @{ process_name = 'windows-firewall' }
        target = @{ destination_domain = 'blocked.test' }
    }
    $message = Get-DlpSharedNotification $other $last
    Assert ($message.Title -eq 'DLP - Hanh dong bi chan' -and $message.Text -match 'Ung dung' -and $message.Text -match 'blocked\.test')
    Assert (-not (Get-DlpSharedNotification $other $last))
    $other.source.process_name = 'dlp-agent'
    $other.target.destination_domain = 'background.test'
    Assert (-not (Get-DlpSharedNotification $other $last))
}

Check 'notifier registration permits parallel limited interactive logons' {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'service\installer_services.ps1')
    $actions = [pscustomobject]@{ Entry = @{} }
    $actions | Add-Member ScriptMethod Create { param($type) return $this.Entry }
    $triggers = [pscustomobject]@{ Entry = @{} }
    $triggers | Add-Member ScriptMethod Create { param($type) $this.Entry.Type = $type; return $this.Entry }
    $definition = @{ Principal = @{}; Settings = @{}; Actions = $actions; Triggers = $triggers }
    $scheduler = [pscustomobject]@{ Definition = $definition }
    $scheduler | Add-Member ScriptMethod NewTask { param($flags) return $this.Definition }
    $folder = [pscustomobject]@{ Group = $null; LogonType = $null }
    $folder | Add-Member ScriptMethod RegisterTaskDefinition {
        param($name, $task, $flags, $group, $password, $logonType, $descriptor)
        $this.Group = $group
        $this.LogonType = $logonType
    }
    function Get-DlpOwnedTask { return $true }
    function Start-ScheduledTask { param($TaskPath, $TaskName) }
    $created = [Collections.Generic.List[string]]::new()
    Register-DlpDesktopTask $scheduler $folder 'DLPNotifier' $DlpNotifierArgs $created
    Assert ($created.Count -eq 1 -and $created[0] -eq 'DLPNotifier' -and
        $folder.Group -eq 'S-1-5-32-545' -and $folder.LogonType -eq 4 -and
        $definition.Principal.RunLevel -eq 0 -and $definition.Settings.MultipleInstances -eq 0 -and
        $triggers.Entry.Type -eq 9 -and $triggers.Entry.Enabled -and -not $triggers.Entry.UserId -and
        $actions.Entry.Path -eq $DlpSystemPowerShell -and $actions.Entry.Arguments -eq $DlpNotifierArgs)
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('dlp-notify-test-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($scratch)
try {
    Check 'journals start independently and an existing partial record is never replayed' {
        $existing = Join-Path $scratch 'existing.log'
        $missing = Join-Path $scratch 'missing.log'
        [IO.File]::WriteAllText($existing, '{"n":1}' + $lf + '{"n":2', $utf8)
        $oldTail = [DlpNotifier.JournalTail]::new($existing, $null)
        $newTail = [DlpNotifier.JournalTail]::new($missing, $null)
        Assert ($oldTail.Poll().Length -eq 0 -and $newTail.Poll().Length -eq 0)
        [IO.File]::AppendAllText($existing, '}' + $lf + '{"n":3}' + $lf, $utf8)
        [IO.File]::WriteAllText($missing, '{"n":4}' + $lf, $utf8)
        Assert (($oldTail.Poll() -join ',') -eq '{"n":3}' -and ($newTail.Poll() -join ',') -eq '{"n":4}')
        Assert ($oldTail.Poll().Length -eq 0 -and $newTail.Poll().Length -eq 0)
    }

    Check 'tail recovers after truncate-regrow and same-length rotation' {
        $file = Join-Path $scratch 'rotate.log'
        $tail = [DlpNotifier.JournalTail]::new($file, $null)
        $null = $tail.Poll()
        [IO.File]::WriteAllText($file, '{"n":1}' + $lf, $utf8)
        Assert (($tail.Poll() -join ',') -eq '{"n":1}')
        [IO.File]::WriteAllText($file, '{"n":2}' + $lf + '{"n":3}' + $lf, $utf8)
        Assert (($tail.Poll() -join ',') -eq '{"n":2},{"n":3}')
        [IO.File]::Move($file, (Join-Path $scratch 'archived.log'))
        [IO.File]::WriteAllText($file, '{"n":4}' + $lf + '{"n":5}' + $lf, $utf8)
        Assert (($tail.Poll() -join ',') -eq '{"n":4},{"n":5}')
    }

    Check 'tail buffers split UTF-8 and drops malformed or oversized records' {
        $file = Join-Path $scratch 'split.log'
        $tail = [DlpNotifier.JournalTail]::new($file, $null)
        $null = $tail.Poll()
        $name = 't' + [char]0x1EAD + 'p.txt'
        $row = '{"n":"' + $name + '"}'
        $bytes = $utf8.GetBytes($row)
        [IO.File]::WriteAllBytes($file, [byte[]]($bytes[0..7]))
        Assert ($tail.Poll().Length -eq 0)
        $append = [IO.File]::Open($file, 'Append', 'Write', 'ReadWrite')
        try {
            $append.Write($bytes, 8, $bytes.Length - 8)
            $append.WriteByte(10)
            $invalid = [byte[]](123, 255, 125, 10)
            $append.Write($invalid, 0, $invalid.Length)
        } finally { $append.Dispose() }
        [IO.File]::AppendAllText($file, '[' + $row + ']' + $lf + '{"n":"' + ('x' * 132000) + '"}' + $lf + '{"n":"last"}' + $lf, $utf8)
        Assert (($tail.Poll() -join ',') -eq ($row + ',{"n":"last"}'))
    }

    Check 'the same Curl event rotated into the active file is displayed once' {
        $file = Join-Path $scratch 'events.log'
        $tail = [DlpNotifier.JournalTail]::new($file, $null)
        $seen = [Collections.Generic.HashSet[string]]::new()
        $null = $tail.Poll()
        $row = New-Block | ConvertTo-Json -Depth 6 -Compress
        [IO.File]::WriteAllText($file, $row + $lf, $utf8)
        Assert (Get-DlpCurlNotification ($tail.Poll()[0] | ConvertFrom-Json) $logon $started $seen)
        [IO.File]::Move($file, (Join-Path $scratch 'events.old'))
        [IO.File]::WriteAllText($file, $row + $lf, $utf8)
        Assert (-not (Get-DlpCurlNotification ($tail.Poll()[0] | ConvertFrom-Json) $logon $started $seen))
    }

    Check 'the private journal ACL must belong to the originating account' {
        $directory = Join-Path $scratch 'private'
        $file = Join-Path $directory 'dlp_events.log'
        $tail = [DlpNotifier.JournalTail]::new($file, $sid)
        $validate = [DlpNotifier.JournalTail].GetMethod('PrivateAcl', [Reflection.BindingFlags]'Instance, NonPublic')
        # Check the writer's descriptor and use its protected DACL for the fixture directory.
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $descriptor = "O:$($sid.Value)D:P(A;OICI;FA;;;$($sid.Value))(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
        $security.SetSecurityDescriptorSddlForm($descriptor)
        Assert ($validate.Invoke($tail, @($security, $true)))
        $authenticatedUsers = [Security.Principal.SecurityIdentifier]::new('S-1-5-11')
        $other = [DlpNotifier.JournalTail]::new($file, $authenticatedUsers)
        Assert (-not $validate.Invoke($other, @($security, $true)))
        $null = [IO.Directory]::CreateDirectory($directory, $security)
        $security.SetSecurityDescriptorSddlForm($descriptor + '(A;OICI;FR;;;AU)')
        Assert (-not $validate.Invoke($tail, @($security, $true)))

        [IO.File]::WriteAllText($file, '{"n":1}' + $lf, $utf8)
        Assert ($tail.Poll().Length -eq 0)
        [IO.File]::AppendAllText($file, '{"n":2}' + $lf, $utf8)
        Assert (($tail.Poll() -join ',') -eq '{"n":2}')

        $fileSecurity = [IO.File]::GetAccessControl($file)
        $fileSecurity.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($authenticatedUsers, 'Read', 'Allow'))
        [IO.File]::SetAccessControl($file, $fileSecurity)
        [IO.File]::AppendAllText($file, '{"n":3}' + $lf, $utf8)
        Assert ($tail.Poll().Length -eq 0)
    }
} finally {
    $resolved = (Resolve-Path -LiteralPath $scratch).Path
    if ($resolved -ne [IO.Path]::GetFullPath($scratch)) { throw 'Unsafe notifier fixture cleanup path.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}

Write-Output "$script:passed notifier tests passed."
