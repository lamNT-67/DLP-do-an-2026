function Initialize-DlpNotifier {
    if ('DlpNotifier.JournalTail' -as [type]) { return }
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace DlpNotifier
{
    public sealed class Logon
    {
        public SecurityIdentifier Sid { get; private set; }
        public int SessionId { get; private set; }
        public string Luid { get; private set; }

        [StructLayout(LayoutKind.Sequential)]
        struct TokenStatistics
        {
            public ulong TokenId, AuthenticationId;
            public long ExpirationTime;
            public uint TokenType, ImpersonationLevel, DynamicCharged, DynamicAvailable, GroupCount, PrivilegeCount;
            public ulong ModifiedId;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr token, int kind, out int value, int size, out int written);

        [DllImport("advapi32.dll", EntryPoint = "GetTokenInformation", SetLastError = true)]
        static extern bool GetStatistics(IntPtr token, int kind, out TokenStatistics value, int size, out int written);

        public static Logon Current()
        {
            using (var identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query | TokenAccessLevels.Duplicate))
            {
                if (!Environment.UserInteractive || identity.IsSystem ||
                    !new WindowsPrincipal(identity).IsInRole(new SecurityIdentifier("S-1-5-4")))
                    return null;
                int session, elevated, written;
                TokenStatistics stats;
                const int tokenSessionId = 12, tokenElevation = 20, tokenStatistics = 10;
                if (!GetTokenInformation(identity.Token, tokenSessionId, out session, sizeof(int), out written) || session == 0 ||
                    !GetTokenInformation(identity.Token, tokenElevation, out elevated, sizeof(int), out written) || elevated != 0 ||
                    !GetStatistics(identity.Token, tokenStatistics, out stats, Marshal.SizeOf(typeof(TokenStatistics)), out written) ||
                    stats.TokenType != 1)
                    return null;
                return new Logon { Sid = identity.User, SessionId = session, Luid = stats.AuthenticationId.ToString("x16") };
            }
        }
    }

    public sealed class JournalTail
    {
        const int PollBytes = 256 * 1024;
        const int MaxLineBytes = 128 * 1024;
        static readonly Encoding Utf8 = new UTF8Encoding(false, true);
        readonly string path;
        readonly SecurityIdentifier user;
        readonly byte[] block = new byte[8192];
        readonly byte[] line = new byte[MaxLineBytes];
        readonly byte[] boundary = new byte[128];
        bool initialized, discardLine;
        int lineLength, boundaryLength;
        long offset;
        FileInformation previous;

        [StructLayout(LayoutKind.Sequential)]
        struct FileInformation
        {
            public FileAttributes Attributes;
            public uint CreatedLow, CreatedHigh, AccessedLow, AccessedHigh, WrittenLow, WrittenHigh;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;

            public bool SameFile(FileInformation other)
            {
                return Volume == other.Volume && IndexHigh == other.IndexHigh && IndexLow == other.IndexLow &&
                    CreatedHigh == other.CreatedHigh && CreatedLow == other.CreatedLow;
            }
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string path, uint access, FileShare share, IntPtr security,
            uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle file, out FileInformation information);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        static extern uint GetFinalPathNameByHandleW(SafeFileHandle file, StringBuilder name, uint size, uint flags);

        public JournalTail(string journalPath, SecurityIdentifier privateUser)
        {
            path = Path.GetFullPath(journalPath);
            user = privateUser;
        }

        bool PrivateDirectory()
        {
            string root = Path.GetPathRoot(path);
            if (root.Length != 3 || root[1] != ':' || new DriveInfo(root).DriveType != DriveType.Fixed) return false;
            var directory = new DirectoryInfo(Path.GetDirectoryName(path));
            var ancestors = new Stack<string>();
            for (var item = directory; item != null; item = item.Parent) ancestors.Push(item.FullName);
            foreach (string ancestor in ancestors)
            {
                var attributes = File.GetAttributes(ancestor);
                if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != FileAttributes.Directory)
                    return false;
            }
            return PrivateAcl(directory.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner), true);
        }

        bool Trusted(SecurityIdentifier sid)
        {
            return sid != null && (sid.Equals(user) || sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
                sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid));
        }

        bool PrivateAcl(FileSystemSecurity security, bool directory)
        {
            var descriptor = new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(), 0);
            if (!Trusted(descriptor.Owner) || descriptor.DiscretionaryAcl == null) return false;
            bool foundUser = false;
            const AceFlags inherit = AceFlags.ContainerInherit | AceFlags.ObjectInherit;
            foreach (GenericAce entry in descriptor.DiscretionaryAcl)
            {
                var ace = entry as CommonAce;
                if (ace == null || ace.AceType != AceType.AccessAllowed || !Trusted(ace.SecurityIdentifier) ||
                    ace.AccessMask != 0x1f01ff || (ace.AceFlags & (AceFlags.InheritOnly | AceFlags.NoPropagateInherit)) != 0 ||
                    (directory && (ace.AceFlags & inherit) != inherit))
                    return false;
                foundUser |= ace.SecurityIdentifier.Equals(user);
            }
            return foundUser;
        }

        bool ExpectedPath(SafeFileHandle handle)
        {
            var name = new StringBuilder(path.Length + 5);
            uint length = GetFinalPathNameByHandleW(handle, name, (uint)name.Capacity, 0);
            return length > 0 && length < name.Capacity &&
                String.Equals(name.ToString(), @"\\?\" + path, StringComparison.OrdinalIgnoreCase);
        }

        public string[] Poll()
        {
            var records = new List<string>();
            try
            {
                if (user != null && !PrivateDirectory()) return records.ToArray();
                // Read only. Sharing delete lets a writer replace the active journal.
                using (var handle = CreateFileW(path, 0x80000000, FileShare.ReadWrite | FileShare.Delete, IntPtr.Zero,
                    3, 0x00200000, IntPtr.Zero)) // OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT
                {
                    if (handle.IsInvalid)
                    {
                        int error = Marshal.GetLastWin32Error();
                        if (error == 2 || error == 3) initialized = true;
                        return records.ToArray();
                    }
                    FileInformation info;
                    if (!GetFileInformationByHandle(handle, out info) ||
                        (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0 ||
                        (user != null && (info.Links != 1 || !ExpectedPath(handle))))
                        return records.ToArray();
                    using (var file = new FileStream(handle, FileAccess.Read))
                    {
                        if (user == null || PrivateAcl(file.GetAccessControl(), false))
                            ReadNewRecords(file, info, records);
                    }
                }
            }
            catch (FileNotFoundException) { initialized = true; }
            catch (DirectoryNotFoundException) { initialized = true; }
            catch (IOException) { } // Keep the cursor and retry on a transient open/read failure.
            catch (UnauthorizedAccessException) { }
            return records.ToArray();
        }

        void ReadNewRecords(FileStream file, FileInformation info, List<string> records)
        {
            if (!initialized)
            {
                // Begin at EOF. If an older record is incomplete, discard its continuation.
                offset = file.Length;
                int tailLength = (int)Math.Min(offset, boundary.Length);
                file.Position = offset - tailLength;
                if (file.Read(boundary, 0, tailLength) != tailLength) return;
                boundaryLength = tailLength;
                discardLine = tailLength > 0 && boundary[tailLength - 1] != (byte)'\n';
                previous = info;
                initialized = true;
                return;
            }
            if (!previous.SameFile(info) || !BoundaryMatches(file))
            {
                offset = 0;
                lineLength = boundaryLength = 0;
                discardLine = false;
                previous = info;
            }

            file.Position = offset;
            long remaining = Math.Min(file.Length - offset, PollBytes);
            while (remaining > 0)
            {
                int count = file.Read(block, 0, (int)Math.Min(block.Length, remaining));
                if (count == 0) break;
                for (int i = 0; i < count; i++)
                {
                    byte value = block[i];
                    if (value == (byte)'\n')
                    {
                        if (!discardLine && lineLength != 0)
                        {
                            try
                            {
                                string row = Utf8.GetString(line, 0, lineLength).TrimStart('\uFEFF').Trim();
                                if (row.StartsWith("{", StringComparison.Ordinal) && row.EndsWith("}", StringComparison.Ordinal))
                                    records.Add(row);
                            }
                            catch (DecoderFallbackException) { }
                        }
                        discardLine = false;
                        lineLength = 0;
                    }
                    else if (lineLength == line.Length) discardLine = true;
                    else if (!discardLine) line[lineLength++] = value;
                }
                int take = Math.Min(count, boundary.Length);
                int keep = Math.Min(boundaryLength, boundary.Length - take);
                Array.Copy(boundary, boundaryLength - keep, boundary, 0, keep);
                Array.Copy(block, count - take, boundary, keep, take);
                boundaryLength = keep + take;
                offset += count;
                remaining -= count;
            }
        }

        bool BoundaryMatches(FileStream file)
        {
            if (file.Length < offset) return false;
            file.Position = offset - boundaryLength;
            if (file.Read(block, 0, boundaryLength) != boundaryLength) return false;
            for (int i = 0; i < boundaryLength; i++)
                if (block[i] != boundary[i]) return false;
            return true;
        }
    }
}
'@
}

function Limit-DlpBalloonField([string]$Value) {
    if ($Value.Length -le 85) { return $Value }
    $length = 82
    if ([char]::IsHighSurrogate($Value[$length - 1])) { $length-- }
    return $Value.Substring(0, $length) + '...'
}

function Get-DlpCurlNotification($Event, $Logon, [DateTimeOffset]$Started, $Seen) {
    $source = $Event.source
    $inspection = $Event.content_inspection
    $enforcement = $Event.enforcement
    if ($Event -isnot [pscustomobject] -or $source -isnot [pscustomobject] -or
        $inspection -isnot [pscustomobject] -or $enforcement -isnot [pscustomobject] -or
        -not ([object]::Equals($Event.agent_module, 'curl') -and
        [object]::Equals($Event.exit_point_type, 'CLIENT_CURL') -and
        [object]::Equals($Event.event_type, 'violation') -and
        [object]::Equals($Event.policy_state, 'BLOCK') -and
        [object]::Equals($Event.action_taken, 'BLOCKED_KILL') -and
        [object]::Equals($inspection.verdict, 'BLOCK') -and
        [object]::Equals($enforcement.termination, 'CONFIRMED') -and
        [object]::Equals($enforcement.termination_attempted, $true) -and
        [object]::Equals($source.process_name, 'curl.exe') -and
        [object]::Equals($source.logon_luid, $Logon.Luid))) { return }
    if ($null -ne $inspection.coverage -and -not [object]::Equals($inspection.coverage, $false)) { return }
    if (($source.session_id -isnot [int] -and $source.session_id -isnot [long]) -or
        $source.session_id -ne $Logon.SessionId -or
        $Event.event_id -isnot [string] -or $Event.event_id -cnotmatch '\A[0-9a-f]{32}\z') { return }

    $time = [DateTimeOffset]::MinValue
    if ($Event.timestamp -isnot [string] -or
        $Event.timestamp -cnotmatch '\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[-+]\d\d:\d\d)\z' -or
        -not [DateTimeOffset]::TryParse($Event.timestamp, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$time) -or
        $time -le $Started -or -not $Seen.Add($Event.event_id)) { return }

    # The writer supplies a basename and host:port. Only display those shapes.
    $file = $Event.target.file_path
    $destination = $Event.target.destination_value
    $body = @('Curl da bi dung theo chinh sach bao mat.')
    if ($file -is [string] -and -not [string]::IsNullOrWhiteSpace($file) -and
        $file -notmatch '[\\/:*?"<>|\p{Cc}\p{Cf}\p{Zl}\p{Zp}]') {
        $body += 'Tep: ' + (Limit-DlpBalloonField $file)
    }
    if ($destination -is [string] -and $destination -cmatch '\A(?:[a-z0-9_.-]{1,253}|\[[0-9a-f:.]{2,45}\]):([0-9]{1,5})\z' -and
        [int]$Matches[1] -le 65535) {
        $body += 'Dich: ' + (Limit-DlpBalloonField $destination)
    }
    return @{ Title = 'DLP - Tai len curl bi chan'; Text = $body -join [Environment]::NewLine }
}

function Get-DlpSharedNotification($Event, $Last) {
    if ($Event.action_taken -isnot [string] -or $Event.action_taken -notlike 'BLOCKED*' -or
        $Event.source.process_name -eq 'dlp-agent' -or
        $Event.agent_module -eq 'curl' -or $Event.exit_point_type -eq 'CLIENT_CURL') { return }

    if ($Event.target.file_path) { $dest = [string]$Event.target.file_path }
    elseif ($Event.target.destination_domain) { $dest = [string]$Event.target.destination_domain }
    else { $dest = "$($Event.target.destination_ip):$($Event.target.destination_port)" }
    $proc = $Event.source.process_name
    if (-not $proc -or $proc -eq 'windows-firewall') { $proc = 'Ung dung' }
    $now = [DateTime]::UtcNow
    if ($Last[$dest] -and ($now - $Last[$dest]).TotalSeconds -lt 30) { return }
    $Last[$dest] = $now
    return @{ Title = 'DLP - Hanh dong bi chan'; Text = ($proc, "Dich: $dest", 'Chinh sach bao mat khong cho phep.') -join [Environment]::NewLine }
}

function Start-DlpNotifier {
    Initialize-DlpNotifier
    $logon = [DlpNotifier.Logon]::Current()
    if (-not $logon) { return }
    $first = $false
    $mutex = [Threading.Mutex]::new($false, "Local\DLP.Notifier.$($logon.Sid.Value).$($logon.Luid)", [ref]$first)
    $icon = $null
    try {
        if (-not $first) { return }
        $shared = [DlpNotifier.JournalTail]::new('C:\ProgramData\DLP\logs\dlp_events.log', $null)
        $profile = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
        $private = if ($profile) {
            [DlpNotifier.JournalTail]::new((Join-Path $profile 'DLP-Curl\dlp_events.log'), $logon.Sid)
        }
        $started = [DateTimeOffset]::UtcNow
        $null = $shared.Poll()
        if ($private) { $null = $private.Poll() }
        $last = @{}
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)

        Add-Type -AssemblyName System.Windows.Forms, System.Drawing -ErrorAction Stop
        $icon = New-Object System.Windows.Forms.NotifyIcon
        $icon.Icon = [System.Drawing.SystemIcons]::Shield
        $icon.Visible = $true
        while ($true) {
            foreach ($journal in @($shared, $private)) {
                if (-not $journal) { continue }
                foreach ($row in $journal.Poll()) {
                    try { $event = ConvertFrom-Json -InputObject $row -ErrorAction Stop }
                    catch { continue }
                    $message = if ($journal -eq $private) {
                        Get-DlpCurlNotification $event $logon $started $seen
                    } else {
                        Get-DlpSharedNotification $event $last
                    }
                    if ($message) { $icon.ShowBalloonTip(8000, $message.Title, $message.Text, 'Warning') }
                }
            }
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Seconds 1
        }
    } finally {
        if ($icon) { $icon.Dispose() }
        $mutex.Dispose()
    }
}

if ($MyInvocation.InvocationName -ne '.') { Start-DlpNotifier }
