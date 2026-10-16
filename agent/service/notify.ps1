$log = "C:\ProgramData\DLP\logs\dlp_events.log"
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$icon = New-Object System.Windows.Forms.NotifyIcon
$icon.Icon = [System.Drawing.SystemIcons]::Shield
$icon.Visible = $true
$last = @{}

while (-not (Test-Path $log)) { Start-Sleep 5 }
$fs = New-Object IO.FileStream($log, 'Open', 'Read', 'ReadWrite')
$sr = New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)
$null = $sr.ReadToEnd()

while ($true) {
    while (($line = $sr.ReadLine()) -ne $null) {
        try { $e = $line | ConvertFrom-Json } catch { continue }
        if ($e.action_taken -notlike 'BLOCKED*') { continue }
        if ($e.source.process_name -eq 'dlp-agent') { continue }

        if ($e.target.file_path) { $dest = $e.target.file_path }
        elseif ($e.target.destination_domain) { $dest = $e.target.destination_domain }
        else { $dest = "$($e.target.destination_ip):$($e.target.destination_port)" }

        $proc = $e.source.process_name
        if (-not $proc -or $proc -eq 'windows-firewall') { $proc = 'Ung dung' }

        $now = Get-Date
        if ($last[$dest] -and ($now - $last[$dest]).TotalSeconds -lt 30) { continue }
        $last[$dest] = $now

        $icon.BalloonTipIcon  = 'Warning'
        $icon.BalloonTipTitle = 'DLP - Hanh dong bi chan'
        $icon.BalloonTipText  = "$proc`nDich: $dest`nChinh sach bao mat khong cho phep."
        $icon.ShowBalloonTip(8000)
    }
    if ($fs.Length -lt $fs.Position) { $fs.Position = 0; $sr.DiscardBufferedData() }
    Start-Sleep 1
    [System.Windows.Forms.Application]::DoEvents()
}
