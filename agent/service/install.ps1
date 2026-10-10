# DLP Agent installer: cai network_agent + sftp_scp_agent thanh Windows Service (tu chay cung may)
param(
    [string]$ServerUrl,
    [string]$Hostname,
    [string]$EnrollmentKey,
    [switch]$NoPrompt
)
$ErrorActionPreference = 'Stop'

# ---- Tu xin quyen Administrator ----
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Requesting Administrator rights...'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    foreach ($k in $PSBoundParameters.Keys) {
        $v = $PSBoundParameters[$k]
        if ($v -is [switch]) { if ($v.IsPresent) { $argList += "-$k" } }
        else { $argList += "-$k"; $argList += ('"{0}"' -f $v) }
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

$InstallDir = 'C:\DLP'
$AgentDir   = Join-Path $InstallDir 'agent'
$VenvDir    = Join-Path $InstallDir 'venv'
$ToolsDir   = Join-Path $InstallDir 'tools'
$LogDir     = 'C:\ProgramData\DLP\logs'
$Source     = Split-Path $PSScriptRoot -Parent
$Services   = @(
    @{ Name = 'DLPNetworkAgent'; Script = 'network_agent.py'  },
    @{ Name = 'DLPSftpScpAgent'; Script = 'sftp_scp_agent.py' }
)

function Step($m) { Write-Host ("`n==> " + $m) -ForegroundColor Cyan }

function Get-IniValue($path, $key) {
    $line = Get-Content $path | Where-Object { $_ -match "^\s*$key\s*=" } | Select-Object -First 1
    if ($line) { return ($line -split '=', 2)[1].Trim() }
    return ''
}
function Set-IniValue($path, $key, $value) {
    $lines = @(Get-Content $path)
    $found = $false
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match "^\s*$key\s*=") { $lines[$i] = "$key = $value"; $found = $true }
    }
    if (-not $found) { throw "Khong thay khoa '$key' trong $path" }
    [IO.File]::WriteAllLines($path, $lines, (New-Object Text.UTF8Encoding($false)))
}
function Invoke-Nssm {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & $nssm @args 2>&1 | Out-Null
    $ErrorActionPreference = $old
}

try {
    # ---- 1. Python ----
    Step 'Tim Python'
    $pyExe = $null
    foreach ($c in 'python.exe', 'py.exe') {
        $cmd = Get-Command $c -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -notmatch 'WindowsApps') { $pyExe = $cmd.Source; break }
    }
    if (-not $pyExe) { throw 'Khong tim thay Python 3. Cai tu https://www.python.org/downloads/ (tick "Add python.exe to PATH") roi chay lai.' }
    $pyArgs = @()
    if ($pyExe -match 'py\.exe$') { $pyArgs = @('-3') }
    & $pyExe @pyArgs --version

    # ---- 2. Dung service cu ----
    Step 'Dung service cu (neu co)'
    foreach ($s in $Services) {
        if (Get-Service $s.Name -ErrorAction SilentlyContinue) {
            Stop-Service $s.Name -Force -ErrorAction SilentlyContinue
        }
    }

    # ---- 3. Chep file ----
    Step "Chep agent vao $AgentDir"
    New-Item -ItemType Directory -Force $AgentDir, $ToolsDir, $LogDir | Out-Null
    robocopy $Source $AgentDir /E /NFL /NDL /NJH /NJS /NP /XD logs __pycache__ dev_tools tools service .git /XF config.ini install.ps1 install.bat uninstall.ps1 uninstall.bat | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy loi (ma $LASTEXITCODE)" }

    # ---- 4. config.ini ----
    Step 'Cau hinh config.ini'
    $cfg = Join-Path $AgentDir 'config.ini'
    if (Test-Path $cfg) {
        Write-Host 'Giu nguyen config.ini hien co (khong ghi de token).'
    } else {
        $srcCfg  = Join-Path $Source 'config.ini'
        $example = Join-Path $Source 'config.ini.example'
        if (Test-Path $srcCfg) {
            Copy-Item $srcCfg $cfg
        } elseif (Test-Path $example) {
            Copy-Item $example $cfg
            if (-not $ServerUrl) {
                $def = Get-IniValue $cfg 'server_url'
                if ($NoPrompt) { $ServerUrl = $def }
                else {
                    $in = Read-Host "Server URL (vd http://192.168.1.10/dlp_server/api) [$def]"
                    if ($in) { $ServerUrl = $in } else { $ServerUrl = $def }
                }
            }
            if (-not $Hostname) {
                $def = $env:COMPUTERNAME
                if ($NoPrompt) { $Hostname = $def }
                else {
                    $in = Read-Host "Hostname cua may nay [$def]"
                    if ($in) { $Hostname = $in } else { $Hostname = $def }
                }
            }
            if (-not $EnrollmentKey -and -not $NoPrompt) {
                $EnrollmentKey = Read-Host 'Enrollment key (lay trong trang Settings cua Admin Web)'
            }
            if ($EnrollmentKey) { Set-IniValue $cfg 'enrollment_key' $EnrollmentKey }
            Set-IniValue $cfg 'server_url' $ServerUrl
            Set-IniValue $cfg 'hostname' $Hostname
        } else {
            throw 'Khong co config.ini lan config.ini.example trong thu muc agent.'
        }
    }

    # ---- 5. venv + thu vien ----
    Step 'Tao moi truong Python (venv) va cai thu vien'
    $venvPy = Join-Path $VenvDir 'Scripts\python.exe'
    if (-not (Test-Path $venvPy)) {
        & $pyExe @pyArgs -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) { throw 'Tao venv that bai.' }
    }
    $req = Join-Path $AgentDir 'requirements.txt'
    if (Test-Path $req) { & $venvPy -m pip install --disable-pip-version-check -r $req }
    else { & $venvPy -m pip install --disable-pip-version-check psutil requests }
    if ($LASTEXITCODE -ne 0) { throw 'pip install that bai (kiem tra ket noi mang).' }

    # ---- 6. NSSM ----
    Step 'Chuan bi NSSM'
    $nssm    = Join-Path $ToolsDir 'nssm.exe'
    $bundled = Join-Path $PSScriptRoot 'nssm.exe'
    if (Test-Path $bundled) {
        Copy-Item $bundled $nssm -Force
    } elseif (-not (Test-Path $nssm)) {
        $found = Get-Command nssm -ErrorAction SilentlyContinue
        if ($found) {
            Copy-Item $found.Source $nssm -Force
        } else {
            Write-Host 'Dang tai NSSM tu nssm.cc ...'
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $zip = Join-Path $env:TEMP 'nssm.zip'
            $tmp = Join-Path $env:TEMP 'nssm_extract'
            Invoke-WebRequest 'https://nssm.cc/release/nssm-2.24.zip' -OutFile $zip -UseBasicParsing
            Expand-Archive $zip $tmp -Force
            $exe = Get-ChildItem $tmp -Recurse -Filter nssm.exe | Where-Object { $_.FullName -match 'win64' } | Select-Object -First 1
            Copy-Item $exe.FullName $nssm -Force
        }
    }
    if (-not (Test-Path $nssm)) { throw 'Khong co nssm.exe. Chep nssm.exe vao agent\service\ roi chay lai.' }

    # ---- 7. Cai service ----
    Step 'Cai dat service'
    foreach ($s in $Services) {
        $n = $s.Name
        if (Get-Service $n -ErrorAction SilentlyContinue) { Invoke-Nssm remove $n confirm; Start-Sleep 2 }
        Invoke-Nssm install $n $venvPy "-u $AgentDir\$($s.Script)"
        Invoke-Nssm set $n AppDirectory $AgentDir
        Invoke-Nssm set $n DisplayName "DLP $n"
        Invoke-Nssm set $n Description "DLP Agent - $($s.Script)"
        Invoke-Nssm set $n Start SERVICE_AUTO_START
        Invoke-Nssm set $n AppStdout "$LogDir\$n.out.log"
        Invoke-Nssm set $n AppStderr "$LogDir\$n.err.log"
        Invoke-Nssm set $n AppRotateFiles 1
        Invoke-Nssm set $n AppRotateOnline 1
        Invoke-Nssm set $n AppRotateBytes 5242880
        Invoke-Nssm set $n AppExit Default Restart
        Invoke-Nssm set $n AppRestartDelay 5000
        Invoke-Nssm start $n
        Write-Host "  da cai: $n"
    }

    # ---- 8. Kiem tra ----
    Step 'Ket qua'
    Start-Sleep 8
    Get-Service ($Services | ForEach-Object { $_.Name }) | Format-Table Status, Name -AutoSize
    foreach ($s in $Services) {
        $f = "$LogDir\$($s.Name).out.log"
        if (Test-Path $f) { Write-Host "--- $f" -ForegroundColor DarkGray; Get-Content $f -Tail 5 }
    }
    Write-Host "`nXong. Agent se tu chay moi khi may khoi dong." -ForegroundColor Green
}
catch {
    Write-Host ("`nLOI: " + $_.Exception.Message) -ForegroundColor Red
}
finally {
    if (-not $NoPrompt) { Read-Host "`nNhan Enter de dong" }
}


