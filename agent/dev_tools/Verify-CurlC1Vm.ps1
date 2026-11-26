#Requires -Version 5.1
<#
.SYNOPSIS
    Verify the existing Curl C1 lab task on DLP-LAB01 and save evidence.
.DESCRIPTION
    Collects evidence from actual logons. On-demand launches and temporary
    diagnostics use only already signed-in test users. They cannot satisfy
    the logon-trigger gate. The existing task definition is read-only.
#>
[CmdletBinding()]
param(
    [string]$RuntimeRoot = 'C:\Program Files\DLP-C1-Lab',
    [string[]]$ReceiptDirectory = @(),
    [ValidateRange(1, 30)][int]$HistoryDays = 7,
    [switch]$EvidenceOnly,
    [switch]$SelfTest
)

$script:C1TaskName = 'DLP-Curl-C1-Lab'
$script:C1TaskPath = '\DLP-Curl-C1-Lab'
$script:C1Accounts = @('DLPTestA', 'DLPTestB')
$script:C1Channel = 'Microsoft-Windows-TaskScheduler/Operational'
$script:C1KnownDenials = @('TOKEN_CONTEXT_UNSUPPORTED', 'PROCESS_IDENTITY_UNAVAILABLE', 'ORIGIN_TOKEN_UNAVAILABLE')

function Initialize-C1Native {
    if ('CurlC1Vm.Native' -as [type]) { return }
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace CurlC1Vm {
    public class Session {
        public int Id;
        public string Station, State, User, Domain;
    }
    public class Token {
        public string Sid, SidHash, AuthenticationId, Image;
        public int SessionId, Integrity, LogonType, LsaSessionId;
        public bool Elevated, Restricted, AppContainer, UIAccess;
        public DateTime? LogonUtc;
    }
    public sealed class ProcessPin : IDisposable {
        internal IntPtr Handle;
        public ProcessPin(int pid) {
            Handle = Native.OpenProcess(0x00101000, false, pid);
            if (Handle == IntPtr.Zero) throw new Win32Exception();
        }
        public bool IsRunning() {
            uint state = Native.WaitForSingleObject(Handle, 0);
            if (state == 258) return true;
            if (state == 0) return false;
            throw new Win32Exception();
        }
        public Token ReadToken() { return Native.ReadToken(Handle); }
        public void Dispose() {
            if (Handle != IntPtr.Zero) Native.CloseHandle(Handle);
            Handle = IntPtr.Zero;
        }
    }
    public static class Native {
        [StructLayout(LayoutKind.Sequential)] struct SessionInfo {
            public int Id;
            public IntPtr Station;
            public int State;
        }
        [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low, High; }
        [StructLayout(LayoutKind.Sequential)] struct LsaString {
            public ushort Length, MaximumLength;
            public IntPtr Buffer;
        }
        [StructLayout(LayoutKind.Sequential)] struct LogonData {
            public uint Size;
            public Luid Id;
            public LsaString User, Domain, Package;
            public uint LogonType, Session;
            public IntPtr Sid;
            public long LogonTime;
        }
        [DllImport("wtsapi32.dll", SetLastError=true)] static extern bool WTSEnumerateSessionsW(
            IntPtr server, int reserved, int version, out IntPtr data, out int count);
        [DllImport("wtsapi32.dll", SetLastError=true)] static extern bool WTSQuerySessionInformationW(
            IntPtr server, int session, int kind, out IntPtr data, out int bytes);
        [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr data);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError=true)] internal static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageName(
            IntPtr handle, int flags, StringBuilder path, ref int length);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(
            IntPtr token, int kind, IntPtr buffer, int size, out int needed);
        [DllImport("secur32.dll")] static extern uint LsaGetLogonSessionData(ref Luid id, out IntPtr data);
        [DllImport("secur32.dll")] static extern uint LsaFreeReturnBuffer(IntPtr data);

        static string SessionValue(int id, int kind) {
            IntPtr data; int size;
            if (!WTSQuerySessionInformationW(IntPtr.Zero, id, kind, out data, out size)) return null;
            try { return size > 2 ? Marshal.PtrToStringUni(data) : null; }
            finally { WTSFreeMemory(data); }
        }
        public static Session[] Sessions() {
            IntPtr data; int count;
            if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out data, out count)) throw new Win32Exception();
            try {
                var result = new Session[count];
                var names = new[] { "Active", "Connected", "ConnectQuery", "Shadow", "Disconnected",
                                    "Idle", "Listen", "Reset", "Down", "Init" };
                int size = Marshal.SizeOf(typeof(SessionInfo));
                for (int i=0; i<count; i++) {
                    var info = (SessionInfo)Marshal.PtrToStructure(IntPtr.Add(data, i * size), typeof(SessionInfo));
                    result[i] = new Session { Id=info.Id, Station=Marshal.PtrToStringUni(info.Station),
                        State=info.State >= 0 && info.State < names.Length ? names[info.State] : "Unknown",
                        User=SessionValue(info.Id, 5), Domain=SessionValue(info.Id, 7) };
                }
                return result;
            } finally { WTSFreeMemory(data); }
        }
        static T Information<T>(IntPtr token, int kind, Func<IntPtr,T> decode) {
            int size;
            GetTokenInformation(token, kind, IntPtr.Zero, 0, out size);
            if (size <= 0 || size > 1048576) throw new Win32Exception();
            IntPtr data=Marshal.AllocHGlobal(size);
            try {
                if (!GetTokenInformation(token, kind, data, size, out size)) throw new Win32Exception();
                return decode(data);
            } finally { Marshal.FreeHGlobal(data); }
        }
        static int Word(IntPtr token, int kind) {
            return Information(token, kind, p => Marshal.ReadInt32(p));
        }
        public static string HashSid(string sid) {
            var identity = new SecurityIdentifier(sid);
            var bytes = new byte[identity.BinaryLength];
            identity.GetBinaryForm(bytes, 0);
            using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
        }
        internal static Token ReadToken(IntPtr process) {
            var path = new StringBuilder(32768);
            int size = path.Capacity;
            if (!QueryFullProcessImageName(process, 0, path, ref size)) throw new Win32Exception();
            IntPtr token;
            if (!OpenProcessToken(process, 8, out token)) throw new Win32Exception();
            try {
                var sid = Information(token, 1, p => new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
                var integrity = Information(token, 25, p => new SecurityIdentifier(Marshal.ReadIntPtr(p)).Value);
                var id = Information(token, 10, p => (Luid)Marshal.PtrToStructure(IntPtr.Add(p, 8), typeof(Luid)));
                var result = new Token { Sid=sid, SidHash=HashSid(sid), Image=path.ToString(),
                    AuthenticationId=(((ulong)id.High << 32) | id.Low).ToString(System.Globalization.CultureInfo.InvariantCulture),
                    SessionId=Word(token,12), Integrity=Int32.Parse(integrity.Substring(integrity.LastIndexOf('-')+1)),
                    Elevated=Word(token,20)!=0, AppContainer=Word(token,29)!=0, Restricted=Word(token,11)!=0,
                    UIAccess=Word(token,26)!=0 };
                IntPtr data;
                if (LsaGetLogonSessionData(ref id, out data)==0 && data != IntPtr.Zero) {
                    try {
                        if (Marshal.ReadInt32(data) >= Marshal.SizeOf(typeof(LogonData))) {
                            var logon=(LogonData)Marshal.PtrToStructure(data,typeof(LogonData));
                            result.LogonType=(int)logon.LogonType;
                            result.LsaSessionId=(int)logon.Session;
                            if (logon.LogonTime > 0) result.LogonUtc=DateTime.FromFileTimeUtc(logon.LogonTime);
                        }
                    } finally { LsaFreeReturnBuffer(data); }
                }
                return result;
            } finally { CloseHandle(token); }
        }
    }
}
'@
}

function New-C1Gate($Name, $Status, $Reason) {
    [pscustomobject]@{ Gate = $Name; Status = $Status; Reason = $Reason }
}

function Get-C1Overall($Gates) {
    if ($Gates.Status -contains 'FAIL') { return 'FAIL' }
    if ($Gates.Status -contains 'NOT VERIFIED' -or @($Gates).Count -eq 0) { return 'NOT VERIFIED' }
    return 'PASS'
}

function New-C1ReportDirectory($Id) {
    $path = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) "DLP-C1-Verification-$Id"
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    [void][IO.Directory]::CreateDirectory($path, $acl)
    return $path
}

function ConvertTo-C1Sid($Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try {
        if ($Value -match '^S-1-') { return ([Security.Principal.SecurityIdentifier]::new($Value)).Value }
        if ($Value -notmatch '\\|@') { $Value = "$env:COMPUTERNAME\$Value" }
        return ([Security.Principal.NTAccount]::new($Value)).Translate([Security.Principal.SecurityIdentifier]).Value
    } catch { return $null }
}

function Test-C1PlainLocalPath($Path) {
    if ($Path -notmatch '^[A-Za-z]:\\') { return $false }
    try {
        $cursor = [IO.Path]::GetFullPath($Path)
        while ($cursor) {
            $attributes = [IO.File]::GetAttributes($cursor)
            if ($attributes -band [IO.FileAttributes]::ReparsePoint) { return $false }
            $cursor = [IO.Path]::GetDirectoryName($cursor)
        }
        return $true
    } catch { return $false }
}

function Read-C1SmallText($Path, [int]$Limit = 65536) {
    if (-not (Test-C1PlainLocalPath $Path)) { throw 'Path missing, nonlocal, or contains a reparse point.' }
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream = [IO.File]::Open($Path, 'Open', 'Read', $share)
    try {
        if ($stream.Length -gt $Limit) { throw 'Evidence file exceeds read limit.' }
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true, 4096, $true)
        try {
            $buffer = New-Object char[] ($Limit + 1)
            $length = $reader.ReadBlock($buffer, 0, $buffer.Length)
            if ($length -gt $Limit) { throw 'Evidence file exceeds read limit.' }
            return [string]::new($buffer, 0, $length)
        } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function Get-C1Users($Sessions) {
    $shells = @(Get-Process -Name explorer -ErrorAction SilentlyContinue)
    foreach ($name in $script:C1Accounts) {
        $sid = ConvertTo-C1Sid "$env:COMPUTERNAME\$name"
        $profile = $null
        if ($sid) {
            $properties = Get-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid" -ErrorAction SilentlyContinue
            if ($properties.ProfileImagePath) { $profile = [Environment]::ExpandEnvironmentVariables($properties.ProfileImagePath) }
        }
        $local = if ($profile) { Join-Path $profile 'AppData\Local' }
        $localSetting = if ($sid) { Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -ErrorAction SilentlyContinue }
        if ($localSetting.'Local AppData') {
            $localValue = [string]$localSetting.'Local AppData'
            if ($profile) { $localValue = $localValue -ireplace '%USERPROFILE%', $profile.Replace('$', '$$') }
            if ($localValue -notmatch '%') { $local = $localValue }
        }
        $matching = @($Sessions | Where-Object {
            $_.Id -gt 0 -and $_.User -eq $name -and $_.Domain -eq $env:COMPUTERNAME -and
            $_.State -in 'Active', 'Connected', 'Disconnected'
        })
        $user = [pscustomobject]@{ Name = $name; Sid = $sid; Profile = $profile; LocalAppData = $local
            Sessions = $matching; Session = $null; Reference = $null; ShellPids = @(); ProbeErrors = @() }
        if ($sid -and $matching.Count -eq 1) {
            $user.Session = $matching[0]
            $tokens = @(foreach ($shell in $shells | Where-Object SessionId -eq $user.Session.Id) {
                $pin = $null
                try {
                    $pin = New-Object CurlC1Vm.ProcessPin($shell.Id)
                    $token = $pin.ReadToken()
                    if ($pin.IsRunning() -and $token.Sid -eq $sid -and $token.SessionId -eq $user.Session.Id -and
                        $token.Image -eq "$env:SystemRoot\explorer.exe") {
                        $user.ShellPids += $shell.Id
                        $token
                    }
                } catch { $user.ProbeErrors += "Explorer PID $($shell.Id) $($_.Exception.Message)" }
                finally { if ($pin) { $pin.Dispose() } }
            })
            $distinct = @($tokens | Group-Object AuthenticationId)
            if ($distinct.Count -eq 1) { $user.Reference = $tokens[0] }
            if ($distinct.Count -gt 1) { $user.ProbeErrors += 'Multiple Explorer authentication IDs in the same session.' }
        }
        $user
    }
}

function Test-C1SupportedUser($User) {
    $token = $User.Reference
    return ($null -ne $token -and $null -ne $token.LogonUtc -and $token.LsaSessionId -eq $token.SessionId -and
            $token.LogonType -in 2, 10, 11, 12 -and -not $token.Elevated -and -not $token.Restricted -and
            -not $token.AppContainer -and -not $token.UIAccess -and $token.Integrity -ge 8192 -and $token.Integrity -lt 12288)
}

function Get-C1ScopeDifferences($Row, $Reference) {
    if (-not $Reference) { return 'independent Explorer token unavailable' }
    if (-not $Row) { return 'watcher scope row missing' }
    if ($Row.user_sid_sha256 -cne $Reference.SidHash) { 'binary SID hash differs' }
    if ([string]$Row.authentication_id -cne [string]$Reference.AuthenticationId) { 'authentication LUID differs' }
    if ([string]$Row.session_id -cne [string]$Reference.SessionId) { 'Windows session ID differs' }
    if ([string]$Row.integrity_level -cne [string]$Reference.Integrity) { 'integrity RID differs' }
}

function Get-C1History($TaskPath) {
    $result = [pscustomobject]@{ Enabled = $null; Error = $null; Events = @() }
    try {
        $channel = Get-WinEvent -ListLog $script:C1Channel -ErrorAction Stop
        $result.Enabled = [bool]$channel.IsEnabled
        $window = [long]$HistoryDays * 86400000
        $filter = "*[System[TimeCreated[timediff(@SystemTime) <= $window]] and EventData[Data[@Name='TaskName'] = '$TaskPath']]"
        $records = @(Get-WinEvent -LogName $script:C1Channel -FilterXPath $filter -ErrorAction Stop)
        $result.Events = @(foreach ($record in $records | Sort-Object RecordId) {
            $data = @{}
            foreach ($field in ([xml]$record.ToXml()).Event.EventData.Data) {
                if ($field.Name) { $data[[string]$field.Name] = [string]$field.'#text' }
            }
            $guid = [guid]::Empty
            $raw = if ($data.InstanceId) { $data.InstanceId } else { $data.TaskInstanceId }
            $instance = if ([guid]::TryParse($raw, [ref]$guid) -and $guid -ne [guid]::Empty) { $guid.ToString('D') }
            $context = if ($data.UserContext) { $data.UserContext } else { $data.UserName }
            [pscustomobject]@{ Id = $record.Id; RecordId = $record.RecordId; Utc = $record.TimeCreated.ToUniversalTime()
                Instance = $instance; User = $context; Sid = ConvertTo-C1Sid $context; Data = $data }
        })
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $result.Error = $_.Exception.Message }
    }
    return $result
}

function Get-C1Runs($History) {
    foreach ($group in $History.Events | Where-Object Instance | Group-Object Instance) {
        $events = @($group.Group | Sort-Object Utc, RecordId)
        $trigger = $events | Where-Object Id -eq 119 | Select-Object -First 1
        $start = $events | Where-Object Id -eq 100 | Select-Object -First 1
        $end = $events | Where-Object Id -eq 102 | Select-Object -Last 1
        $actions = @($events | Where-Object Id -eq 201)
        $failures = @($events | Where-Object Id -in 103, 111, 202, 203, 329)
        $code = $null
        if ($actions.Count -eq 1 -and $actions[0].Data.ResultCode -match '^\d+$') {
            $code = [uint32]$actions[0].Data.ResultCode
        }
        [pscustomobject]@{ Instance = $group.Name; LogonTrigger = $trigger; Start = $start; End = $end
            Actions = $actions; ExitCode = $code; Failures = $failures; FirstUtc = $events[0].Utc
            LastUtc = $events[-1].Utc; RecordIds = @($events.RecordId) }
    }
}

function Get-C1TaskDefinition($Task, [xml]$TaskXml) {
    if (-not $Task) {
        return [pscustomobject]@{ Gate = New-C1Gate 'Existing task definition' 'FAIL' 'The specified lab task was not found.'
            MayRun = $false; Info = $null }
    }
    $xml = if ($TaskXml) { $TaskXml } else { [xml](Export-ScheduledTask -TaskName $script:C1TaskName -TaskPath '\' -ErrorAction Stop) }
    $xmlPrincipals = @($xml.Task.Principals.ChildNodes | Where-Object LocalName -eq 'Principal')
    $declared = $xmlPrincipals | Select-Object -First 1
    $effective = $Task.Principal
    $group = if ($effective.GroupId) { [string]$effective.GroupId } else { [string]$declared.GroupId }
    $user = if ($effective.UserId) { [string]$effective.UserId } else { [string]$declared.UserId }
    # A group principal can export only GroupId. RunLevel defaults to limited.
    $runLevel = if ([string]$effective.RunLevel) { [string]$effective.RunLevel }
        elseif ($declared.RunLevel) { [string]$declared.RunLevel } else { 'LeastPrivilege' }
    $logonType = if ([string]$effective.LogonType) { [string]$effective.LogonType }
        elseif ($declared.LogonType) { [string]$declared.LogonType } elseif ($group) { 'Group' }
    $allowedLogonTypes = if ($group) { @('Group', '4') } else { @('Interactive', 'InteractiveToken', '3') }

    # Use DOM nodes so PowerShell does not coerce <LogonTrigger /> to an empty string.
    $xmlLogons = @($xml.Task.Triggers.ChildNodes | Where-Object {
        $_.LocalName -eq 'LogonTrigger' -and [string]$_.Enabled -in '', 'true', '1'
    })
    $triggers = $xmlLogons
    if ($null -ne $Task.Triggers) {
        $triggers = @($Task.Triggers | Where-Object {
            $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' -and [string]$_.Enabled -in 'true', '1'
        })
    }
    $execs = @($xml.Task.Actions.ChildNodes | Where-Object NodeType -eq 'Element')
    $settings = $xml.Task.Settings
    $info = [pscustomobject]@{ State = [string]$Task.State
        Enabled = [string]$settings.Enabled -notin 'false', '0' -and [string]$Task.Settings.Enabled -notin 'false', '0'
        LogonTriggers = @($triggers | ForEach-Object { [pscustomobject]@{ User = [string]$_.UserId; Delay = [string]$_.Delay } })
        Principal = @([pscustomobject]@{ User = $user; Group = $group; LogonType = $logonType; RunLevel = $runLevel })
        Actions = @($execs | ForEach-Object { [pscustomobject]@{ Kind = $_.LocalName; Command = [string]$_.Command
            Arguments = [string]$_.Arguments; WorkingDirectory = [string]$_.WorkingDirectory } })
        Settings = [pscustomobject]@{ MultipleInstancesPolicy = [string]$settings.MultipleInstancesPolicy
            ExecutionTimeLimit = [string]$settings.ExecutionTimeLimit; RunOnlyIfIdle = [string]$settings.RunOnlyIfIdle
            DisallowStartIfOnBatteries = [string]$settings.DisallowStartIfOnBatteries
            StopIfGoingOnBatteries = [string]$settings.StopIfGoingOnBatteries
            AllowDemandStart = $settings.AllowStartOnDemand -ne 'false' }
    }
    $unlimited = $false
    if ($settings.ExecutionTimeLimit) {
        try { $unlimited = [Xml.XmlConvert]::ToTimeSpan($settings.ExecutionTimeLimit) -eq [timespan]::Zero } catch { $unlimited = $false }
    }
    $problems = @(if (-not $info.Enabled -or $info.State -eq 'Disabled') { 'Task disabled' }
        if ($xmlPrincipals.Count -ne 1 -or $runLevel -notin 'Limited', 'LeastPrivilege', '0' -or
            ($declared.RunLevel -and $declared.RunLevel -ne 'LeastPrivilege') -or
            ($declared.LogonType -and $declared.LogonType -notin $allowedLogonTypes) -or
            $logonType -notin $allowedLogonTypes -or ([bool]$user -eq [bool]$group)) { 'Expected one limited interactive principal' }
        if ($triggers.Count -eq 0 -or $xmlLogons.Count -eq 0) { 'Enabled logon trigger missing' }
        if ($execs.Count -ne 1 -or $execs[0].LocalName -ne 'Exec') { 'Expected one executable action' }
        if ($settings.MultipleInstancesPolicy -ne 'Parallel') { 'Parallel instance policy missing' }
        if (-not $unlimited) { 'Unlimited execution time missing' }
        if ($settings.RunOnlyIfIdle -eq 'true') { 'Task depends on idle state' }
        if ($settings.DisallowStartIfOnBatteries -ne 'false' -or $settings.StopIfGoingOnBatteries -ne 'false') { 'Battery settings do not allow startup and continued execution' })
    $status = if ($problems.Count) { 'FAIL' } else { 'PASS' }
    $reason = if ($problems.Count) { $problems -join '. ' } else { 'Enabled limited interactive logon task with one action and explicit execution settings.' }
    [pscustomobject]@{ Gate = New-C1Gate 'Existing task definition' $status $reason
        MayRun = -not $problems.Count -and $info.Settings.AllowDemandStart; Info = $info }
}

function Find-C1Runtime($Definition) {
    $actionText = ($Definition.Info.Actions | ForEach-Object { "$($_.Command) $($_.Arguments)" }) -join ' '
    $root = [IO.Path]::GetFullPath($RuntimeRoot).TrimEnd('\')
    $prefix = $root + '\'
    $encodedAction = [regex]::Match($actionText, '(?i)-EncodedCommand\s+"?([A-Za-z0-9+/=]{1,32768})')
    if ($encodedAction.Success) {
        try { $actionText += "`n" + [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedAction.Groups[1].Value)) }
        catch { }
    }
    $absolute = '[A-Za-z]:\\[^"''<>|\r\n]*?\.(?:exe|py|ps1|jsonl)(?=["''\s;)]|$)'
    $paths = @([regex]::Matches($actionText, $absolute, 'IgnoreCase') | ForEach-Object Value)
    foreach ($wrapper in $paths | Where-Object { $_.StartsWith($prefix, 'OrdinalIgnoreCase') -and $_ -like '*.ps1' }) {
        if (Test-C1PlainLocalPath $wrapper) {
            try { $actionText += "`n$(Read-C1SmallText $wrapper)" } catch { continue }
        }
    }
    $paths = @([regex]::Matches($actionText, $absolute, 'IgnoreCase') | ForEach-Object Value)
    $probeName = 'curl_windows_runtime_check.py'
    $probes = @($paths | Where-Object { $_.StartsWith($prefix, 'OrdinalIgnoreCase') -and [IO.Path]::GetFileName($_) -eq $probeName })
    $probes += @((Join-Path $root "agent\dev_tools\$probeName"), (Join-Path $root "dev_tools\$probeName"), (Join-Path $root $probeName))
    $probe = $probes | Where-Object { Test-C1PlainLocalPath $_ } | Select-Object -First 1
    $pythonCandidates = @($paths | Where-Object { [IO.Path]::GetFileName($_) -eq 'python.exe' })
    $pythonCandidates += @((Join-Path $root 'venv\Scripts\python.exe'), (Join-Path $root '.venv\Scripts\python.exe'),
                           (Join-Path $root 'python.exe'), 'C:\DLP\venv\Scripts\python.exe')
    $python = $pythonCandidates | Where-Object {
        ($_.StartsWith($prefix, 'OrdinalIgnoreCase') -or $_ -eq 'C:\DLP\venv\Scripts\python.exe') -and (Test-C1PlainLocalPath $_)
    } | Select-Object -First 1
    $isLabAction = $probe -and $actionText -match [regex]::Escape($probeName) -and $actionText -match '(?i)--output(?:[\s=]|$)'
    [pscustomobject]@{ Root = $root; Probe = $probe; Python = $python; RecognizedAction = [bool]$isLabAction
        OutputHints = @($paths | Where-Object { $_ -like '*.jsonl' } | Sort-Object -Unique) }
}

function Read-C1Receipt($File, $ProfileUser) {
    $record = [pscustomobject]@{ Path = $File.FullName; ProfileUser = $ProfileUser; CreatedUtc = $File.CreationTimeUtc
        WrittenUtc = $File.LastWriteTimeUtc; OwnerSid = $null; Rows = @(); Error = $null }
    try {
        $text = Read-C1SmallText $record.Path
        if (-not $ProfileUser) {
            $owner = Get-Acl -LiteralPath $record.Path -ErrorAction SilentlyContinue
            $record.OwnerSid = ConvertTo-C1Sid $owner.Owner
        }
        $record.Rows = @(foreach ($line in ($text -split '\r?\n')) {
            if ($line.Trim()) {
                $row = ConvertFrom-Json -InputObject $line -ErrorAction Stop
                if ($row -isnot [pscustomobject] -or $row.case -isnot [string]) { throw 'Unexpected receipt row.' }
                $row
            }
        })
        $File.Refresh()
        if ($File.LastWriteTimeUtc -ne $record.WrittenUtc) { throw 'Receipt changed while being collected.' }
    } catch { $record.Error = $_.Exception.Message }
    return $record
}

function Get-C1Receipts($Users, $Runtime) {
    $directories = [ordered]@{}
    foreach ($u in $Users | Where-Object LocalAppData) {
        foreach ($sub in '', 'DLP', 'DLP\Curl', 'DLP\Curl\logs', 'DLP-C1-Lab', 'DLP-Curl-C1-Lab') {
            $dir = if ($sub) { Join-Path $u.LocalAppData $sub } else { $u.LocalAppData }
            $directories[$dir] = $u.Name
        }
    }
    $common = [Environment]::GetFolderPath('CommonApplicationData')
    foreach ($dir in @($Runtime.Root, (Join-Path $Runtime.Root 'receipts'), (Join-Path $common 'DLP-C1-Lab'),
                       (Join-Path $common 'DLP-C1-Lab\receipts')) + $ReceiptDirectory) {
        if ($dir -and -not $directories.Contains($dir)) { $directories[$dir] = $null }
    }
    $seen = @{}
    foreach ($dir in $directories.Keys) {
        if (-not (Test-C1PlainLocalPath $dir)) { continue }
        $files = Get-ChildItem -LiteralPath $dir -File -Filter '*.jsonl' -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^(?:DLP-)?Curl-C1[-_]' -and $_.Name -notmatch '^DLP-Curl-C1-Verify-' } |
            Sort-Object CreationTimeUtc -Descending | Select-Object -First 40
        foreach ($file in $files) {
            if ($seen.ContainsKey($file.FullName)) { continue }
            $seen[$file.FullName] = $true
            Read-C1Receipt $file $directories[$dir]
        }
    }
    foreach ($path in $Runtime.OutputHints) {
        if ($seen.ContainsKey($path) -or -not (Test-C1PlainLocalPath $path)) { continue }
        $profile = $Users | Where-Object {
            $_.LocalAppData -and $path.StartsWith($_.LocalAppData.TrimEnd('\') + '\', 'OrdinalIgnoreCase')
        } | Select-Object -First 1
        $file = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($file -and -not $file.PSIsContainer) { Read-C1Receipt $file $profile.Name }
    }
}

function Get-C1ReceiptCandidates($User, $Receipts, $BootUtc) {
    $sidHash = if ($User.Sid) { [CurlC1Vm.Native]::HashSid($User.Sid) }
    foreach ($receipt in $Receipts) {
        $watchers = @($receipt.Rows | Where-Object case -ceq 'watcher')
        if ($receipt.ProfileUser -ne $User.Name -and (-not $sidHash -or $watchers.user_sid_sha256 -cnotcontains $sidHash)) { continue }
        $fresh = if ($receipt.CreatedUtc -lt $BootUtc) { 'prior boot' }
            elseif ($User.Reference -and $receipt.CreatedUtc -lt $User.Reference.LogonUtc) { 'before current logon' }
            elseif (-not $User.Reference) { 'current logon unknown' }
            else { 'during current logon' }
        [pscustomobject]@{ Path = $receipt.Path; ProfileUser = $receipt.ProfileUser; CreatedUtc = $receipt.CreatedUtc
            WrittenUtc = $receipt.WrittenUtc; OwnerSid = $receipt.OwnerSid; Freshness = $fresh; Error = $receipt.Error
            ScopeDifferences = @(Get-C1ScopeDifferences ($watchers | Select-Object -First 1) $User.Reference)
            Stages = @($receipt.Rows.case); Rows = $receipt.Rows }
    }
}

function Select-C1InstanceReceipt($User, $Run, $Runs, $Candidates, $SinceUtc, $IgnoredPaths = @()) {
    if (-not $Run.Start -or -not $Run.End) { return @() }
    $first = $Run.Start.Utc.AddSeconds(-1)
    if ($SinceUtc -and $SinceUtc -gt $first) { $first = $SinceUtc }
    $last = $Run.End.Utc.AddSeconds(2)
    foreach ($receipt in $Candidates) {
        if ($receipt.Freshness -ne 'during current logon' -or $receipt.CreatedUtc -lt $first -or
            $receipt.WrittenUtc -lt $receipt.CreatedUtc -or $receipt.WrittenUtc -gt $last -or
            $IgnoredPaths -contains $receipt.Path) { continue }
        # Two plausible task instances for this account cannot share a timestamp-only receipt.
        $others = @($Runs | Where-Object {
            $_.Instance -ne $Run.Instance -and $_.Start.Sid -eq $User.Sid -and
            $_.Start.Utc.AddSeconds(-1) -le $receipt.CreatedUtc -and
            (-not $_.End -or $_.End.Utc.AddSeconds(2) -ge $receipt.WrittenUtc)
        })
        if (-not $others.Count) { $receipt }
    }
}

function Get-C1RunGates($User, $Run, $Receipts, $RequireLogon) {
    $actions = @($Run.Actions)
    if ($RequireLogon) {
        if ($Run.LogonTrigger -and $Run.Start -and $Run.LogonTrigger.Sid -eq $User.Sid -and $Run.Start.Sid -eq $User.Sid) {
            New-C1Gate 'Real logon trigger' 'PASS' "Event 119 and task start share instance $($Run.Instance)."
        } elseif ($Run.Start -and $Run.Start.Sid -and $Run.Start.Sid -ne $User.Sid) {
            New-C1Gate 'Real logon trigger' 'FAIL' 'The event 119 run started as a different account.'
        } else { New-C1Gate 'Real logon trigger' 'NOT VERIFIED' 'No correlated event 119 and task start for the current interactive logon.' }
    }
    if ($Run.Failures.Count -or ($null -ne $Run.ExitCode -and $Run.ExitCode -ne 0)) {
        New-C1Gate 'Task exit status' 'FAIL' "Instance failed or action returned $($Run.ExitCode). Check history and diagnostic stderr."
    } elseif ($Run.Start -and $Run.End -and $Run.Start.Sid -eq $User.Sid -and $Run.End.Sid -eq $User.Sid -and
              $actions.Count -eq 1 -and $null -ne $Run.ExitCode -and $Run.ExitCode -eq 0) {
        New-C1Gate 'Task exit status' 'PASS' 'Per-instance task completion and action result zero.'
    } else { New-C1Gate 'Task exit status' 'NOT VERIFIED' 'No complete zero result for the same task instance and account.' }

    $receiptsForRun = @($Receipts | Where-Object { $_ })
    $receipt = if ($receiptsForRun.Count -eq 1) { $receiptsForRun[0] }
    if ($receipt.ProfileUser -and $receipt.ProfileUser -ne $User.Name) {
        New-C1Gate 'Receipt freshness and association' 'FAIL' 'The correlated receipt was found in a different test account profile.'
    } elseif ($receipt -and -not $receipt.Error -and $receipt.Rows.Count -and
              ($receipt.ProfileUser -eq $User.Name -or $receipt.OwnerSid -eq $User.Sid)) {
        New-C1Gate 'Receipt freshness and association' 'PASS' 'Unique receipt in the current logon and task action window.'
    } else {
        New-C1Gate 'Receipt freshness and association' 'NOT VERIFIED' "Need one readable receipt in the matched instance window. Candidates $($receiptsForRun.Count)."
    }
    $watchers = @($receipt.Rows | Where-Object case -ceq 'watcher')
    $watcher = if ($watchers.Count -eq 1 -and -not $receipt.Error) { $watchers[0] }
    $differences = @(Get-C1ScopeDifferences $watcher $User.Reference)
    if ($watcher -and $User.Reference -and ($differences.Count -or $watcher.supported -eq $false -or
        $watcher.venv -isnot [bool] -or -not $watcher.venv)) {
        New-C1Gate 'Task token matches interactive shell' 'FAIL' ("Watcher scope or venv mismatch. $($differences -join ', ')")
    } elseif ($watcher -and (Test-C1SupportedUser $User)) {
        New-C1Gate 'Task token matches interactive shell' 'PASS' 'SID hash, authentication LUID, session and integrity match the independently read Explorer token.'
    } else { New-C1Gate 'Task token matches interactive shell' 'NOT VERIFIED' 'Independent limited shell context or a unique watcher row is missing.' }

    $workers = @($receipt.Rows | Where-Object case -ceq 'impersonation-and-inheritance')
    if ($workers.Count -eq 1 -and $watcher -and -not $differences.Count) {
        $worker = $workers[0]
        $workerDifferences = @(Get-C1ScopeDifferences $worker.scope $User.Reference)
        if ($workerDifferences.Count -or $worker.synthetic_env_inherited -isnot [bool] -or $worker.synthetic_env_inherited) {
            New-C1Gate 'Worker impersonation and inheritance' 'FAIL' ("Worker scope or inheritance check failed. $($workerDifferences -join ', ')")
        } else { New-C1Gate 'Worker impersonation and inheritance' 'PASS' 'Worker scope matches the shell and the probe confirmed sentinel exclusion.' }
    } else { New-C1Gate 'Worker impersonation and inheritance' 'NOT VERIFIED' 'No unique impersonation result in a verified watcher context.' }

    $timeouts = @($receipt.Rows | Where-Object case -ceq 'worker-tree-timeout')
    if ($timeouts.Count -eq 1 -and $watcher -and -not $differences.Count -and $workers.Count -eq 1) {
        if ($timeouts[0].descendant_removed -is [bool] -and $timeouts[0].descendant_removed) {
            New-C1Gate 'Worker timeout cleanup' 'PASS' 'The original scheduled fixture observed the descendant removed after its timeout.'
        } else { New-C1Gate 'Worker timeout cleanup' 'FAIL' 'The correlated timeout observation did not confirm descendant removal.' }
    } else {
        $last = if ($receipt.Stages) { @($receipt.Stages)[-1] } else { 'none' }
        New-C1Gate 'Worker timeout cleanup' 'NOT VERIFIED' "No unique, correlated timeout result. Last receipt stage $last."
    }
}

function Get-C1TaskInfo($TaskName) {
    try {
        $info = Get-ScheduledTaskInfo -TaskName $TaskName -TaskPath '\' -ErrorAction Stop
        [pscustomobject]@{ LastRunUtc = $info.LastRunTime.ToUniversalTime(); LastTaskResult = $info.LastTaskResult
            NumberOfMissedRuns = $info.NumberOfMissedRuns }
    } catch { [pscustomobject]@{ Error = $_.Exception.Message } }
}

function Start-C1InSession($ComTask, $User) {
    $requested = [datetime]::UtcNow
    # TASK_RUN_USE_SESSION_ID alone preserves identity and task constraints.
    $instance = $ComTask.RunEx($null, 4, [int]$User.Session.Id, $null)
    if (-not $instance -or -not $instance.InstanceGuid) { throw 'RunEx returned no task instance.' }
    [pscustomobject]@{ RequestedUtc = $requested; Instance = ([guid]$instance.InstanceGuid).ToString('D') }
}

function Test-C1InstanceRunning($ComTask, $Id) {
    foreach ($instance in $ComTask.GetInstances(0)) {
        if ($instance.InstanceGuid -and ([guid]$instance.InstanceGuid).ToString('D') -eq $Id) { return $true }
    }
    return $false
}

function Wait-C1Run($ComTask, $Launch, [int]$Seconds = 45) {
    $deadline = [datetime]::UtcNow.AddSeconds($Seconds)
    do {
        if ([datetime]::UtcNow -ge $Launch.RequestedUtc.AddSeconds(2) -and
            -not (Test-C1InstanceRunning $ComTask $Launch.Instance)) { return $true }
        Start-Sleep -Milliseconds 250
    } while ([datetime]::UtcNow -lt $deadline)
    return $false
}

function Quote-C1Literal($Value) { "'" + $Value.Replace("'", "''") + "'" }

function Start-C1Aux($Folder, $OwnedTasks, $Runtime, $User, $RunId, $Mode, [int]$OriginPid = 0) {
    if (-not $Runtime.Python -or -not $Runtime.Probe -or -not (Test-C1PlainLocalPath $User.LocalAppData)) {
        throw 'A trusted lab Python, probe or local user profile is unavailable.'
    }
    $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $taskName = "DLP-Curl-C1-Verify-$RunId-$Mode-$suffix"
    $fileName = "$taskName.jsonl"
    $pythonArguments = @('-B', $Runtime.Probe)
    switch ($Mode) {
        'hold' { $pythonArguments += '--hold-origin' }
        'peer' { $pythonArguments += @('--origin-pid', [string]$OriginPid, '--expect', 'foreign') }
        'worker' {
            # Isolate the missing worker stage. The existing probe retains its five-second timeout.
            $workerCode = @'
import contextlib, os, runpy, sys, tempfile
from pathlib import Path
probe, receipt = sys.argv[1:]
with open(receipt, "x", encoding="utf-8") as output, contextlib.redirect_stdout(output):
    sys.path.insert(0, str(Path(probe).parent))
    fixture = runpy.run_path(probe)
    scope = fixture["watcher_scope"]()
    fixture["_emit"](case="watcher", **fixture["_scope_fields"](scope), venv=sys.prefix != sys.base_prefix)
    curl = Path(os.environ["SystemRoot"]) / "System32" / "curl.exe"
    with tempfile.TemporaryDirectory(prefix="curl-c1-worker-diagnostic-") as root:
        with fixture["_holding_origin"](curl) as child:
            process = fixture["psutil"].Process(child.pid)
            with fixture["open_origin"](process.pid, process.create_time(), scope) as origin:
                from curl_worker import run_inspection_worker
                fixture["_check_worker"](origin, scope, Path(root), run_inspection_worker)
'@
            $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($workerCode))
            $pythonArguments = @('-B', '-c', "exec(__import__('base64').b64decode('$encoded'))", $Runtime.Probe)
        }
        default { throw 'Unknown diagnostic mode.' }
    }
    if ($Mode -ne 'worker') { $pythonArguments += '--output' }
    $template = @'
$receipt = Join-Path -Path $env:LOCALAPPDATA -ChildPath __FILE__
$errorFile = $receipt + '.stderr.txt'
$probeArgs = @(__ARGS__, $receipt)
& __PYTHON__ @probeArgs 2> $errorFile
exit $LASTEXITCODE
'@
    $command = $template.Replace('__FILE__', (Quote-C1Literal $fileName)).Replace('__PYTHON__', (Quote-C1Literal $Runtime.Python))
    $command = $command.Replace('__ARGS__', (($pythonArguments | ForEach-Object { Quote-C1Literal $_ }) -join ', '))
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -Argument "-NoProfile -NonInteractive -EncodedCommand $encodedCommand" -WorkingDirectory $Runtime.Root
    $principal = New-ScheduledTaskPrincipal -UserId $User.Sid -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    $definition = New-ScheduledTask -Action $action -Principal $principal -Settings $settings
    Register-ScheduledTask -InputObject $definition -TaskName $taskName -TaskPath '\' -ErrorAction Stop | Out-Null
    $OwnedTasks.Add($taskName)
    $com = $Folder.GetTask($taskName)
    $launch = Start-C1InSession $com $User
    [pscustomobject]@{ Name = $taskName; Com = $com; Launch = $launch; Mode = $Mode
        Receipt = Join-Path $User.LocalAppData $fileName; FileName = $fileName; SessionId = $User.Session.Id }
}

function Read-C1AuxReceipt($Helper, $User) {
    $file = Get-Item -LiteralPath $Helper.Receipt -ErrorAction SilentlyContinue
    if ($file -and $file.CreationTimeUtc -ge $Helper.Launch.RequestedUtc) { Read-C1Receipt $file $User.Name }
}

function Get-C1AuxResult($Helper, $User) {
    $exited = Wait-C1Run $Helper.Com $Helper.Launch 35
    $info = Get-C1TaskInfo $Helper.Name
    $receipt = Read-C1AuxReceipt $Helper $User
    $stderr = $null
    $file = $Helper.Receipt + '.stderr.txt'
    if (Test-C1PlainLocalPath $file) {
        try { $stderr = Read-C1SmallText $file 16384 } catch { $stderr = $_.Exception.Message }
    }
    $scope = @($receipt.Rows | Where-Object case -ceq 'watcher')
    [pscustomobject]@{ Name = $Helper.Name; Instance = $Helper.Launch.Instance; Exited = $exited
        Info = $info; ExitVerified = $exited -and $info.LastRunUtc -and $info.LastRunUtc -ge $Helper.Launch.RequestedUtc.AddSeconds(-1)
        Receipt = $receipt; Stderr = $stderr
        ScopeDifferences = @(Get-C1ScopeDifferences ($scope | Select-Object -First 1) $User.Reference) }
}

function Get-C1HeldOrigin($Helper, $User) {
    $deadline = [datetime]::UtcNow.AddSeconds(20)
    do {
        $receipt = Read-C1AuxReceipt $Helper $User
        $rows = @($receipt.Rows | Where-Object case -ceq 'held-origin')
        $processId = 0
        if ($rows.Count -eq 1 -and -not $receipt.Error -and [int]::TryParse([string]$rows[0].pid, [ref]$processId) -and $processId -gt 0) {
            $pin = New-Object CurlC1Vm.ProcessPin($processId)
            try {
                $token = $pin.ReadToken()
                $process = Get-CimInstance Win32_Process -Filter "ProcessId = $processId" -ErrorAction Stop
                $parent = if ($process.ParentProcessId) { Get-CimInstance Win32_Process -Filter "ProcessId = $($process.ParentProcessId)" -ErrorAction Stop }
                if (-not $pin.IsRunning() -or $token.Image -ne "$env:SystemRoot\System32\curl.exe" -or
                    $token.Sid -ne $User.Sid -or $token.SessionId -ne $User.Session.Id -or
                    $token.AuthenticationId -ne $User.Reference.AuthenticationId -or
                    $parent.CommandLine -notlike '*--hold-origin*' -or $parent.CommandLine -notlike "*$($Helper.FileName)*") {
                    throw 'The live PID is not identified as the synthetic Curl holder in the expected logon.'
                }
                return [pscustomobject]@{ Pin = $pin; Pid = $processId; Token = $token; ReceiptPath = $receipt.Path }
            } catch { $pin.Dispose(); throw }
        }
        if ([datetime]::UtcNow -ge $Helper.Launch.RequestedUtc.AddSeconds(2) -and
            -not (Test-C1InstanceRunning $Helper.Com $Helper.Launch.Instance)) { break }
        Start-Sleep -Milliseconds 250
    } while ([datetime]::UtcNow -lt $deadline)
    throw 'No fresh synthetic holder receipt was produced while the task was active.'
}

function Invoke-C1CrossUser($Folder, $OwnedTasks, $Runtime, $Observer, $Origin, $RunId) {
    $name = "Cross-user $($Observer.Name) to $($Origin.Name)"
    $held = $null
    $holder = $null
    try {
        $holder = Start-C1Aux $Folder $OwnedTasks $Runtime $Origin $RunId 'hold'
        $held = Get-C1HeldOrigin $holder $Origin
        $peer = Start-C1Aux $Folder $OwnedTasks $Runtime $Observer $RunId 'peer' $held.Pid
        $result = Get-C1AuxResult $peer $Observer
        $outcomes = @($result.Receipt.Rows | Where-Object case -ceq 'external-origin')
        $details = [pscustomobject]@{ Observer = $Observer.Name; Origin = $Origin.Name; OriginPid = $held.Pid
            OriginToken = $held.Token; HolderReceipt = $held.ReceiptPath; ObserverProbe = $result }
        if (-not $held.Pin.IsRunning() -or $result.Receipt.Error -or $result.ScopeDifferences.Count) {
            return [pscustomobject]@{ Gate = New-C1Gate $name 'NOT VERIFIED' 'A pinned live holder, matching observer scope and unique result are required.'; Detail = $details }
        }
        if (($outcomes.Count -eq 1 -and $outcomes[0].accepted -is [bool] -and $outcomes[0].accepted) -or
            ($result.ExitVerified -and $result.Info.LastTaskResult -ne 0 -and
             $result.Stderr -like '*The external curl should have been outside the supported scope*')) {
            return [pscustomobject]@{ Gate = New-C1Gate $name 'FAIL' 'The probe accepted the verified foreign Curl process.'; Detail = $details }
        }
        if ($outcomes.Count -eq 1 -and $result.ExitVerified -and $result.Info.LastTaskResult -eq 0 -and
            $outcomes[0].accepted -is [bool] -and -not $outcomes[0].accepted -and $outcomes[0].reason -cin $script:C1KnownDenials) {
            return [pscustomobject]@{ Gate = New-C1Gate $name 'PASS' "The live foreign Curl was rejected as $($outcomes[0].reason)."; Detail = $details }
        }
        [pscustomobject]@{ Gate = New-C1Gate $name 'NOT VERIFIED' 'The diagnostic did not prove an allowed rejection and a zero exit.'; Detail = $details }
    } catch {
        [pscustomobject]@{ Gate = New-C1Gate $name 'NOT VERIFIED' $_.Exception.Message
            Detail = if ($holder) { [pscustomobject]@{ Holder = $holder.Name; Receipt = Read-C1AuxReceipt $holder $Origin } } }
    } finally {
        if ($held) { $held.Pin.Dispose() }
    }
}

function Remove-C1AuxTasks($Folder, $OwnedTasks) {
    if ($OwnedTasks.Count -eq 0) { return }
    $deadline = [datetime]::UtcNow.AddSeconds(125)
    Write-Host 'Waiting for temporary probes to finish their own cleanup.'
    do {
        $running = @($OwnedTasks | Where-Object { $Folder.GetTask($_).GetInstances(0).Count -gt 0 })
        if (-not $running.Count) { break }
        Start-Sleep -Seconds 1
    } while ([datetime]::UtcNow -lt $deadline)
    foreach ($taskName in $OwnedTasks) {
        try {
            $instances = $Folder.GetTask($taskName).GetInstances(0)
            if ($instances.Count) {
                # Only these uniquely named tasks were created by this verifier.
                foreach ($instance in $instances) { $instance.Stop() }
                New-C1Gate "Temporary task cleanup $taskName" 'NOT VERIFIED' 'A diagnostic timed out and was cancelled. Cooperative cleanup was unconfirmed.'
            }
            Unregister-ScheduledTask -TaskName $taskName -TaskPath '\' -Confirm:$false -ErrorAction Stop
        } catch { New-C1Gate "Temporary task cleanup $taskName" 'NOT VERIFIED' $_.Exception.Message }
    }
}

function Invoke-C1OriginalOnDemand($ComTask, $User, $Users, $Runtime, $BootUtc, $ExistingReceipts) {
    try {
        if ($ComTask.GetInstances(0).Count -gt 0) {
            return [pscustomobject]@{ Error = 'The original task is still running. No second instance was requested.'; Gates = @() }
        }
        $launch = Start-C1InSession $ComTask $User
        $exited = Wait-C1Run $ComTask $launch
        $history = Get-C1History $script:C1TaskPath
        $runs = @(Get-C1Runs $history)
        $run = $runs | Where-Object Instance -eq $launch.Instance | Select-Object -First 1
        $current = @(Get-C1ReceiptCandidates $User @(Get-C1Receipts $Users $Runtime) $BootUtc)
        $matched = @(Select-C1InstanceReceipt $User $run $runs $current $launch.RequestedUtc @($ExistingReceipts.Path))
        [pscustomobject]@{ Instance = $launch.Instance; RequestedUtc = $launch.RequestedUtc; Exited = $exited
            Run = $run; Gates = @(Get-C1RunGates $User $run $matched $false); Receipts = $matched
            NewProfileReceipts = @($current | Where-Object { $_.CreatedUtc -ge $launch.RequestedUtc -and $ExistingReceipts.Path -notcontains $_.Path })
            LastTaskInfo = Get-C1TaskInfo $script:C1TaskName }
    } catch { [pscustomobject]@{ Error = $_.Exception.Message; Gates = @() } }
}

function Wait-C1OriginalIdle($ComTask) {
    if ($ComTask.GetInstances(0).Count -eq 0) { return }
    Write-Host 'Waiting for the existing lab task to finish before collecting its receipt.'
    $deadline = [datetime]::UtcNow.AddSeconds(45)
    do {
        Start-Sleep -Milliseconds 500
        if ($ComTask.GetInstances(0).Count -eq 0) { return }
    } while ([datetime]::UtcNow -lt $deadline)
}

function Add-C1UserChecks($Report, $Users, $Runs, $History, $Receipts, $Definition, $Runtime, $Folder, $OwnedTasks) {
    $changed = $History.Events | Where-Object Id -in 106, 140, 141 | Sort-Object Utc -Descending | Select-Object -First 1
    foreach ($user in $Users) {
        Write-Host "Checking $($user.Name)."
        $candidates = @(Get-C1ReceiptCandidates $user $Receipts $Report.BootUtc)
        $valid = Test-C1SupportedUser $user
        $sessionStatus = if ($valid) { 'PASS' } else { 'NOT VERIFIED' }
        $sessionReason = if ($valid) { 'One signed-in session and a supported live Explorer token.' }
            elseif (-not $user.Sid) { 'The expected local account could not be resolved.' }
            elseif ($user.Sessions.Count -ne 1) { "Expected one eligible WTS session. Found $($user.Sessions.Count)." }
            else { 'Unable to verify a supported Explorer token and its LSA logon.' }
        $gates = @(New-C1Gate 'Existing limited interactive context' $sessionStatus $sessionReason)
        $selectedRun = if ($valid) {
            $Runs | Where-Object {
                $_.LogonTrigger.Sid -eq $user.Sid -and $_.LogonTrigger.Utc -ge $user.Reference.LogonUtc -and
                $_.LogonTrigger.Utc -ge $Report.BootUtc -and (-not $changed -or $_.LogonTrigger.RecordId -gt $changed.RecordId)
            } | Sort-Object { $_.LogonTrigger.RecordId } -Descending | Select-Object -First 1
        }
        $match = @(Select-C1InstanceReceipt $user $selectedRun $Runs $candidates)
        $gates += @(Get-C1RunGates $user $selectedRun $match $true)
        $entry = [pscustomobject]@{ Name = $user.Name; Gates = $gates; Context = $user; LogonRun = $selectedRun
            LogonReceipts = $match; ReceiptInventory = $candidates; OnDemand = $null; WorkerDiagnostic = $null }
        $Report.Accounts += $entry
        if (-not $valid -or $EvidenceOnly -or -not $Folder -or (Get-C1Overall $gates) -eq 'PASS') { continue }

        $identityEvidenceMissing = @($gates | Where-Object {
            $_.Gate -in 'Receipt freshness and association', 'Task token matches interactive shell' -and $_.Status -ne 'PASS'
        }).Count -gt 0
        if ($identityEvidenceMissing -and $Definition.MayRun -and $Runtime.RecognizedAction) {
            $entry.OnDemand = Invoke-C1OriginalOnDemand ($Folder.GetTask($script:C1TaskName)) $user $Users $Runtime $Report.BootUtc $Receipts
        }
        $cleanupPassed = @($gates + @($entry.OnDemand.Gates) | Where-Object { $_.Gate -eq 'Worker timeout cleanup' -and $_.Status -eq 'PASS' }).Count -gt 0
        if ($Runtime.Probe -and $Runtime.Python -and -not $cleanupPassed) {
            try {
                $invocation = Start-C1Aux $Folder $OwnedTasks $Runtime $user $Report.RunId 'worker'
                $diagnostic = Get-C1AuxResult $invocation $user
                $timeouts = @($diagnostic.Receipt.Rows | Where-Object case -ceq 'worker-tree-timeout')
                $diagnosticStatus = 'NOT VERIFIED'
                $diagnosticReason = 'Targeted worker run did not produce a correlated timeout result. See stderr in the report.'
                if ($diagnostic.ExitVerified -and -not $diagnostic.ScopeDifferences.Count -and -not $diagnostic.Receipt.Error) {
                    if ($diagnostic.Info.LastTaskResult -eq 0 -and $timeouts.Count -eq 1 -and
                        $timeouts[0].descendant_removed -is [bool] -and $timeouts[0].descendant_removed) {
                        $diagnosticStatus = 'PASS'
                        $diagnosticReason = 'Worker cleanup passed in the temporary diagnostic. Original task evidence is evaluated separately.'
                    } elseif ($diagnostic.Stderr -like '*synthetic worker descendant survived timeout cleanup*') {
                        $diagnosticStatus = 'FAIL'
                        $diagnosticReason = 'The targeted diagnostic reported a surviving worker descendant.'
                    }
                }
                $entry.WorkerDiagnostic = [pscustomobject]@{ Gate = New-C1Gate 'Supplemental worker timeout' $diagnosticStatus $diagnosticReason; Detail = $diagnostic }
            } catch {
                $entry.WorkerDiagnostic = [pscustomobject]@{ Gate = New-C1Gate 'Supplemental worker timeout' 'NOT VERIFIED' $_.Exception.Message }
            }
        }
    }
}

function Save-C1Report($Report, $Directory) {
    $lines = @("Curl Checkpoint 2C.1 on $($Report.Computer)", "Overall assessment $($Report.FinalAssessment)",
               "Run $($Report.RunId) at $($Report.StartedUtc.ToString('u'))", "Boot $($Report.BootUtc)", '')
    $lines += @($Report.Gates | ForEach-Object { "[$($_.Status)] $($_.Gate) - $($_.Reason)" })
    foreach ($entry in $Report.Accounts) {
        $lines += @('', $entry.Name)
        if ($entry.Context.Reference) {
            $scope = $entry.Context.Reference
            $lines += "Explorer SID $($scope.Sid), LUID $($scope.AuthenticationId), session $($scope.SessionId), integrity $($scope.Integrity)."
        }
        $lines += @($entry.Gates | ForEach-Object { "[$($_.Status)] $($_.Gate) - $($_.Reason)" })
        foreach ($receipt in $entry.ReceiptInventory | Sort-Object CreatedUtc -Descending | Select-Object -First 8) {
            $last = if ($receipt.Stages.Count) { $receipt.Stages[-1] } else { 'none' }
            $differences = $receipt.ScopeDifferences -join ', '
            $lines += "Receipt $($receipt.Path) | $($receipt.Freshness) | last $last | scope differences $differences | read error $($receipt.Error)"
            $observed = $receipt.Rows | Where-Object case -ceq 'watcher' | Select-Object -First 1
            if ($observed) { $lines += "  Receipt SID hash $($observed.user_sid_sha256), LUID $($observed.authentication_id), session $($observed.session_id), integrity $($observed.integrity_level)." }
        }
        if ($entry.OnDemand) {
            $lines += "On-demand diagnostic $($entry.OnDemand.Instance) $($entry.OnDemand.Error)"
            $lines += @($entry.OnDemand.Gates | ForEach-Object { "  [$($_.Status)] $($_.Gate) - $($_.Reason)" })
        }
        if ($entry.WorkerDiagnostic) {
            $diagnostic = $entry.WorkerDiagnostic
            $lines += "[$($diagnostic.Gate.Status)] $($diagnostic.Gate.Gate) - $($diagnostic.Gate.Reason)"
            if ($diagnostic.Detail.Stderr) { $lines += $diagnostic.Detail.Stderr.Trim() }
        }
    }
    $lines += @('', 'Scheduler history and cross-user evidence')
    $lines += "Operational channel enabled $($Report.History.Enabled), event count $(@($Report.History.Events).Count), error $($Report.History.Error)."
    foreach ($event in $Report.History.Events | Where-Object Id -in 100, 101, 102, 103, 110, 111, 119, 201, 202, 203, 322, 329, 332 |
        Sort-Object RecordId -Descending | Select-Object -First 16) {
        $lines += "  $($event.Utc.ToString('u')) event $($event.Id) record $($event.RecordId) instance $($event.Instance) account $($event.User) result $($event.Data.ResultCode)"
    }
    $lines += @($Report.CrossUser | ForEach-Object { "[$($_.Gate.Status)] $($_.Gate.Gate) - $($_.Gate.Reason)" })
    $lines += @('', 'Logon-trigger acceptance requires scheduler event 119 and matching task, token, receipt and exit evidence.',
               'On-demand and auxiliary probes are diagnostic. User receipts are operational evidence within the test-account trust boundary.')
    $jsonPath = Join-Path $Directory 'report.json'
    $textPath = Join-Path $Directory 'report.txt'
    $encoding = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($jsonPath, ($Report | ConvertTo-Json -Depth 20), $encoding)
    [IO.File]::WriteAllLines($textPath, [string[]]$lines, $encoding)
    Write-Host "Final assessment $($Report.FinalAssessment)"
    Write-Host "Evidence $jsonPath"
    Write-Host "Review   $textPath"
}

function Invoke-C1Verification {
    if ($env:COMPUTERNAME -ine 'DLP-LAB01') { throw 'This harness is restricted to DLP-LAB01.' }
    $admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in elevated Windows PowerShell.' }
    $id = [guid]::NewGuid().ToString('N').Substring(0, 12)
    $directory = New-C1ReportDirectory $id
    $report = [pscustomobject]@{ Computer = $env:COMPUTERNAME; RunId = $id; StartedUtc = [datetime]::UtcNow; BootUtc = $null
        EvidenceOnly = [bool]$EvidenceOnly; FinalAssessment = 'NOT VERIFIED'; Gates = @(); Accounts = @(); Sessions = @()
        CrossUser = @(); Definition = $null; Runtime = $null; History = $null; LastTaskInfoBefore = $null; LastTaskInfoAfter = $null }
    $owned = New-Object 'System.Collections.Generic.List[string]'
    $folder = $null
    try {
        Initialize-C1Native
        $report.BootUtc = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime()
        $report.Sessions = @([CurlC1Vm.Native]::Sessions())
        $task = Get-ScheduledTask -TaskName $script:C1TaskName -TaskPath '\' -ErrorAction SilentlyContinue
        $definition = Get-C1TaskDefinition $task
        $report.Definition = $definition.Info
        $report.Gates += $definition.Gate
        $report.Runtime = Find-C1Runtime $definition
        $report.LastTaskInfoBefore = Get-C1TaskInfo $script:C1TaskName
        $users = @(Get-C1Users $report.Sessions)
        if (-not $EvidenceOnly) {
            try {
                $service = New-Object -ComObject 'Schedule.Service' -ErrorAction Stop
                $service.Connect()
                $folder = $service.GetFolder('\')
            } catch { $report.Gates += New-C1Gate 'Scheduler diagnostics launch' 'NOT VERIFIED' $_.Exception.Message }
        }
        if ($folder -and $task) {
            try { Wait-C1OriginalIdle ($folder.GetTask($script:C1TaskName)) }
            catch { $report.Gates += New-C1Gate 'Existing task instance lookup' 'NOT VERIFIED' $_.Exception.Message }
        }
        $report.History = Get-C1History $script:C1TaskPath
        $runs = @(Get-C1Runs $report.History)
        $receipts = @(Get-C1Receipts $users $report.Runtime)
        Add-C1UserChecks $report $users $runs $report.History $receipts $definition $report.Runtime $folder $owned
        foreach ($pair in @(,@(0, 1)) + @(,@(1, 0))) {
            $observer = $users[$pair[0]]
            $origin = $users[$pair[1]]
            if ($folder -and (Test-C1SupportedUser $observer) -and (Test-C1SupportedUser $origin) -and
                $observer.Sid -ne $origin.Sid -and $observer.Session.Id -ne $origin.Session.Id) {
                $report.CrossUser += Invoke-C1CrossUser $folder $owned $report.Runtime $observer $origin $id
            } else {
                $report.CrossUser += [pscustomobject]@{ Gate = New-C1Gate "Cross-user $($observer.Name) to $($origin.Name)" 'NOT VERIFIED' 'Requires both distinct, signed-in limited logons and diagnostic execution enabled.' }
            }
        }
        $report.LastTaskInfoAfter = Get-C1TaskInfo $script:C1TaskName
        if ($folder) { $report.History = Get-C1History $script:C1TaskPath }
        $latest = @(Get-C1Users @([CurlC1Vm.Native]::Sessions()))
        foreach ($entry in $report.Accounts | Where-Object { $_.Context.Reference }) {
            $current = $latest | Where-Object Name -eq $entry.Name
            if (-not (Test-C1SupportedUser $current) -or $current.Reference.AuthenticationId -ne $entry.Context.Reference.AuthenticationId -or
                $current.Reference.SessionId -ne $entry.Context.Reference.SessionId) {
                $entry.Gates += New-C1Gate 'Session continuity' 'NOT VERIFIED' 'Interactive logon changed during verification.'
            }
        }
    } catch { $report.Gates += New-C1Gate 'Harness completion' 'NOT VERIFIED' $_.Exception.Message }
    finally {
        try { if ($folder) { $report.Gates += @(Remove-C1AuxTasks $folder $owned) } }
        catch { $report.Gates += New-C1Gate 'Temporary task cleanup' 'NOT VERIFIED' $_.Exception.Message }
        foreach ($name in $script:C1Accounts) {
            if ($report.Accounts.Name -notcontains $name) {
                $gates = @(New-C1Gate 'Existing limited interactive context' 'NOT VERIFIED' 'Account evidence collection did not run.')
                $gates += @(Get-C1RunGates ([pscustomobject]@{ Name = $name }) $null @() $true)
                $report.Accounts += [pscustomobject]@{ Name = $name; Gates = $gates; Context = $null; ReceiptInventory = @() }
            }
        }
        foreach ($label in 'Cross-user DLPTestA to DLPTestB', 'Cross-user DLPTestB to DLPTestA') {
            if ($report.CrossUser.Gate.Gate -notcontains $label) {
                $report.CrossUser += [pscustomobject]@{ Gate = New-C1Gate $label 'NOT VERIFIED' 'Cross-user evidence collection did not run.' }
            }
        }
        $all = @($report.Gates) + @($report.Accounts | ForEach-Object Gates) + @($report.CrossUser | ForEach-Object Gate)
        # A positive diagnostic failure blocks acceptance. Diagnostic successes never replace original-task evidence.
        $all += @($report.Accounts | ForEach-Object { $_.WorkerDiagnostic.Gate } | Where-Object Status -eq 'FAIL')
        $report.FinalAssessment = Get-C1Overall $all
        Save-C1Report $report $directory
    }
    switch ($report.FinalAssessment) { 'PASS' { return 0 } 'FAIL' { return 1 } default { return 2 } }
}

function Test-C1TaskDefinitionRegression {
    $export = @'
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Principals>
  <Principal id="Author">
    <GroupId>S-1-5-32-545</GroupId>
  </Principal>
</Principals>
<Triggers>
  <LogonTrigger />
</Triggers>
<Settings>
  <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
  <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
  <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
  <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
</Settings>
<Actions><Exec><Command>powershell.exe</Command></Exec></Actions>
</Task>
'@
    $cases = @(
        @{ Name = 'VM export and effective CIM values'; Status = 'PASS' }
        @{ Name = 'Omitted defaults with XML alone'; Status = 'PASS'; XmlOnly = $true }
        @{ Name = 'Elevated CIM principal'; Reason = 'limited interactive'; Change = { $task.Principal.RunLevel = 'Highest' } }
        @{ Name = 'Explicitly elevated XML'; Reason = 'limited interactive'; Old = '</GroupId>'; New = '</GroupId><RunLevel>HighestAvailable</RunLevel>' }
        @{ Name = 'Password CIM logon'; Reason = 'limited interactive'; Change = { $task.Principal.LogonType = 'Password' } }
        @{ Name = 'Explicitly incompatible XML logon'; Reason = 'limited interactive'; Old = '</GroupId>'; New = '</GroupId><LogonType>S4U</LogonType>' }
        @{ Name = 'Disabled CIM trigger'; Reason = 'Enabled logon trigger'; Change = { $task.Triggers[0].Enabled = $false } }
        @{ Name = 'Explicitly disabled XML trigger'; Reason = 'Enabled logon trigger'; Old = '<LogonTrigger />'; New = '<LogonTrigger><Enabled>false</Enabled></LogonTrigger>' }
        @{ Name = 'Non-logon CIM trigger'; Reason = 'Enabled logon trigger'; Change = { $task.Triggers[0].CimClass.CimClassName = 'MSFT_TaskDailyTrigger' } }
        @{ Name = 'Disabled task state'; Reason = 'Task disabled'; Change = { $task.State = 'Disabled' } }
        @{ Name = 'Disabled task setting in XML'; Reason = 'Task disabled'; Old = '<Settings>'; New = '<Settings><Enabled>false</Enabled>' }
        @{ Name = 'Disabled task setting in CIM'; Reason = 'Task disabled'; Change = { $task.Settings.Enabled = $false } }
    )
    foreach ($case in $cases) {
        $task = [pscustomobject]@{ State = 'Ready' }
        if (-not $case.XmlOnly) {
            $task = [pscustomobject]@{ State = 'Ready'; Settings = [pscustomobject]@{ Enabled = $true }
                Principal = [pscustomobject]@{ RunLevel = 'Limited'; LogonType = 'Group'; GroupId = 'Users' }
                Triggers = @([pscustomobject]@{ Enabled = $true
                    CimClass = [pscustomobject]@{ CimClassName = 'MSFT_TaskLogonTrigger' } }) }
        }
        if ($case.Change) { & $case.Change }
        $xml = if ($case.Old) { $export.Replace($case.Old, $case.New) } else { $export }
        $expected = if ($case.Status) { $case.Status } else { 'FAIL' }
        $definition = Get-C1TaskDefinition $task ([xml]$xml)
        if ($definition.Gate.Status -ne $expected -or $definition.MayRun -ne ($expected -eq 'PASS') -or
            ($case.Reason -and $definition.Gate.Reason -notlike "*$($case.Reason)*")) {
            throw "$($case.Name) expected $expected, got $($definition.Gate.Status). $($definition.Gate.Reason)"
        }
        if ($case.Name -eq 'VM export and effective CIM values' -and
            ($definition.Info.Principal[0].RunLevel -ne 'Limited' -or $definition.Info.Principal[0].Group -ne 'Users' -or
             $definition.Info.Principal[0].LogonType -ne 'Group' -or $definition.Info.LogonTriggers.Count -ne 1)) {
            throw 'Task definition report did not use the effective CIM values.'
        }
        Write-Host "PASS $($case.Name)"
    }
    $user = [pscustomobject]@{ Name = 'DLPTestA'; Reference = $null }
    $missing = @(Get-C1RunGates $user $null @() $true)
    if ((Test-C1SupportedUser $user) -or @($missing | Where-Object Status -ne 'NOT VERIFIED').Count) {
        throw 'A missing interactive session or correlated run was accepted.'
    }
    Write-Host 'PASS Missing session and correlated evidence stay NOT VERIFIED'
    Write-Host "$($cases.Count + 1) regression cases passed."
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($SelfTest) { Test-C1TaskDefinitionRegression; exit 0 }
    exit (Invoke-C1Verification)
}
