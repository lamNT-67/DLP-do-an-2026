#Requires -Version 5.1
<#
.SYNOPSIS
Measures rapid and paced text clipboard writes in a Windows PowerShell guest session.
.DESCRIPTION
Mode labels the run. Select the matching agent state or policy before running.
Probes use the clipdiag- prefix and alphabetic identifiers. Verify that the
active policy allows those strings. Each run writes its own files under
%TEMP%\DLPClipboardDiag. Clipboard values and exception messages stay out of
the output.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('OFF', 'REPORT_ONLY', 'BLOCK')]
    [string]$Mode,

    [ValidateRange(1, 50)]
    [int]$RapidCount = 20,

    [ValidateRange(1, 50)]
    [int]$PacedCount = 10,

    [ValidateRange(100, 2000)]
    [int]$PaceMilliseconds = 150
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or
    [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    throw 'Run in the interactive guest session with Windows PowerShell (powershell.exe -Sta).'
}

$nativeProbeLoaded = $false
try {
    if (-not ('DlpClipboardDiag.NativeMethods' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace DlpClipboardDiag
{
    public static class NativeMethods
    {
        [DllImport("user32.dll", ExactSpelling = true)]
        public static extern uint GetClipboardSequenceNumber();

        [DllImport("user32.dll", ExactSpelling = true)]
        public static extern IntPtr GetClipboardOwner();

        [DllImport("user32.dll", ExactSpelling = true)]
        public static extern IntPtr GetOpenClipboardWindow();

        [DllImport("user32.dll", ExactSpelling = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);
    }
}
'@
    }
    $nativeProbeLoaded = $true
} catch {
    # Clipboard cmdlets can still be measured without the optional Win32 metadata.
}

function Get-ClipboardSequence {
    if ($nativeProbeLoaded) {
        try {
            $sequence = [DlpClipboardDiag.NativeMethods]::GetClipboardSequenceNumber()
            if ($sequence -ne 0) { return $sequence }
        } catch {
            # Record unavailable metadata as null.
        }
    }
    return $null
}

function Get-WindowDetails([IntPtr]$Window) {
    if ($Window -eq [IntPtr]::Zero) { return $null }

    [uint32]$windowProcessId = 0
    $threadId = [DlpClipboardDiag.NativeMethods]::GetWindowThreadProcessId($Window, [ref]$windowProcessId)
    $process = if ($windowProcessId) { Get-Process -Id $windowProcessId -ErrorAction SilentlyContinue }
    [ordered]@{
        hwnd = '0x{0:X}' -f $Window.ToInt64()
        pid = $(if ($windowProcessId) { $windowProcessId })
        thread_id = $(if ($threadId) { $threadId })
        process_name = $(if ($null -ne $process) { $process.ProcessName })
    }
}

function Get-ClipboardWindows {
    if (-not $nativeProbeLoaded) { return $null }
    try {
        $sampledUtc = [DateTime]::UtcNow.ToString('o')
        $opener = [DlpClipboardDiag.NativeMethods]::GetOpenClipboardWindow()
        $owner = [DlpClipboardDiag.NativeMethods]::GetClipboardOwner()
        [ordered]@{
            sampled_utc = $sampledUtc
            opener = Get-WindowDetails $opener
            owner = Get-WindowDetails $owner
        }
    } catch {
        return $null
    }
}

function Get-ExceptionChain([Exception]$Exception) {
    while ($null -ne $Exception) {
        [ordered]@{
            type = $Exception.GetType().FullName
            hresult = '0x{0:X8}' -f $Exception.HResult
        }
        $Exception = $Exception.InnerException
    }
}

function Write-DiagnosticRows([object[]]$Rows) {
    [string[]]$lines = foreach ($row in $Rows) {
        ConvertTo-Json -InputObject $row -Depth 8 -Compress
    }
    [IO.File]::AppendAllLines($detailPath, $lines, $utf8)
}

$Mode = $Mode.ToUpperInvariant()
$startedUtc = [DateTime]::UtcNow
$runId = [Guid]::NewGuid().ToString('N')
$root = Join-Path $env:TEMP 'DLPClipboardDiag'
$runDirectory = Join-Path (Join-Path $root $Mode) ($startedUtc.ToString('yyyyMMddTHHmmssfffZ') + '-' + $runId)
$null = [IO.Directory]::CreateDirectory($runDirectory)
$detailPath = Join-Path $runDirectory 'events.jsonl'
$summaryPath = Join-Path $runDirectory 'summary.json'
$utf8 = [Text.UTF8Encoding]::new($false)
$readbackDelayMilliseconds = 250

Write-DiagnosticRows -Rows @([ordered]@{
    record_type = 'run'
    mode = $Mode
    run_id = $runId
    started_utc = $startedUtc.ToString('o')
    powershell_version = $PSVersionTable.PSVersion.ToString()
    session_id = [Diagnostics.Process]::GetCurrentProcess().SessionId
    writer_pid = $PID
    native_probe_loaded = $nativeProbeLoaded
    rapid_count = $RapidCount
    paced_count = $PacedCount
    pace_ms = $PaceMilliseconds
    readback_delay_ms = $readbackDelayMilliseconds
})
Write-Output ('Output directory  {0}' -f $runDirectory)

$probeAttempts = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::Ordinal)
$attempt = 0
$phaseStats = @{}
foreach ($phase in 'rapid', 'paced') {
    $count = if ($phase -eq 'rapid') { $RapidCount } else { $PacedCount }
    $rows = [Collections.Generic.List[object]]::new()
    $failed = 0
    $maxElapsedMs = 0.0

    for ($index = 0; $index -lt $count; $index++) {
        if ($phase -eq 'paced') { Start-Sleep -Milliseconds $PaceMilliseconds }
        $attempt++
        $probeText = 'clipdiag-{0}-{1}' -f $runId, $attempt
        # Map digits to letters outside the hex alphabet to keep probes unique.
        for ($digit = 0; $digit -lt 10; $digit++) {
            $probeText = $probeText.Replace('0123456789'[$digit], 'ghijklmnop'[$digit])
        }
        $probeAttempts[$probeText] = $attempt

        $sequenceBefore = Get-ClipboardSequence
        $writeUtc = [DateTime]::UtcNow.ToString('o')
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $writeException = $null
        try {
            $null = Set-Clipboard -Value $probeText -ErrorAction Stop
        } catch {
            $writeException = $_.Exception
        }
        $timer.Stop()
        $sequenceAfter = Get-ClipboardSequence
        $lastWriteOk = $null -eq $writeException
        $windows = if (-not $lastWriteOk) { Get-ClipboardWindows }
        $elapsedMs = [Math]::Round($timer.Elapsed.TotalMilliseconds, 3)
        if (-not $lastWriteOk) { $failed++ }
        $maxElapsedMs = [Math]::Max($maxElapsedMs, $elapsedMs)

        $rows.Add([ordered]@{
            record_type = 'write'
            phase = $phase
            attempt = $attempt
            started_utc = $writeUtc
            success = $lastWriteOk
            elapsed_ms = $elapsedMs
            sequence_before = $sequenceBefore
            sequence_after = $sequenceAfter
            exceptions = @(Get-ExceptionChain $writeException)
            windows_after_failure = $windows
        })
    }

    # Serialize after each phase to keep file I/O out of the rapid loop.
    Write-DiagnosticRows -Rows $rows.ToArray()
    $phaseStats[$phase] = @{ attempts = $count; failures = $failed; max_ms = $maxElapsedMs }
}

Start-Sleep -Milliseconds $readbackDelayMilliseconds
$sequenceBefore = Get-ClipboardSequence
$readUtc = [DateTime]::UtcNow.ToString('o')
$timer = [Diagnostics.Stopwatch]::StartNew()
$readException = $null
$readText = $null
try {
    $readText = Get-Clipboard -Raw -ErrorAction Stop
} catch {
    $readException = $_.Exception
}
$timer.Stop()
$sequenceAfter = Get-ClipboardSequence
$matchedAttempt = $null
$readback = if ($null -ne $readException) {
    'READ_ERROR'
} elseif ([string]::IsNullOrEmpty($readText)) {
    'EMPTY_TEXT'
} elseif ($readText -ceq $probeText) {
    $matchedAttempt = $attempt
    'MATCH_LAST_ATTEMPT'
} elseif ($probeAttempts.ContainsKey($readText)) {
    $matchedAttempt = $probeAttempts[$readText]
    'MATCH_EARLIER_PROBE'
} elseif ($readText.StartsWith('[DLP]', [StringComparison]::Ordinal)) {
    'DLP_NOTICE_PREFIX'
} else {
    'OTHER_TEXT'
}

Write-DiagnosticRows -Rows @([ordered]@{
    record_type = 'readback'
    started_utc = $readUtc
    elapsed_ms = [Math]::Round($timer.Elapsed.TotalMilliseconds, 3)
    sequence_before = $sequenceBefore
    sequence_after = $sequenceAfter
    result = $readback
    matched_attempt = $matchedAttempt
    exceptions = @(Get-ExceptionChain $readException)
    windows_after_read = Get-ClipboardWindows
})

$summary = [ordered]@{
    mode = $Mode
    run_id = $runId
    started_utc = $startedUtc.ToString('o')
    rapid_attempts = $phaseStats.rapid.attempts
    rapid_failures = $phaseStats.rapid.failures
    rapid_max_ms = $phaseStats.rapid.max_ms
    paced_attempts = $phaseStats.paced.attempts
    paced_failures = $phaseStats.paced.failures
    paced_max_ms = $phaseStats.paced.max_ms
    pace_ms = $PaceMilliseconds
    last_write_ok = $lastWriteOk
    readback = $readback
    native_probe_loaded = $nativeProbeLoaded
}
[IO.File]::WriteAllText($summaryPath, (ConvertTo-Json -InputObject $summary), $utf8)
Write-Output ('{0}  rapid {1}/{2} failures  paced {3}/{4} failures  readback {5}' -f
    $Mode, $summary.rapid_failures, $RapidCount, $summary.paced_failures, $PacedCount, $readback)
