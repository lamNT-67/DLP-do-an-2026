# Run from an elevated PowerShell window on Windows with .NET 8 SDK installed.
[CmdletBinding()]
param(
    [string]$ServerUrl,
    [string]$EnrollmentKey,
    [string]$Hostname = $env:COMPUTERNAME
)
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator.'
}
$dataDir = Join-Path $env:ProgramData 'DLPAgent'
$configPath = Join-Path $dataDir 'agent.json'
$isReinstall = Test-Path -LiteralPath $configPath
if (-not $isReinstall) {
    if (-not $ServerUrl) { $ServerUrl = Read-Host 'Server API URL (http://IP/dlp_server/api)' }
    if (-not $EnrollmentKey) { $EnrollmentKey = Read-Host 'Enrollment key' }
    if (-not $Hostname) { throw 'Hostname cannot be empty' }
    $parsedUrl = $null
    if (-not [Uri]::TryCreate($ServerUrl, [UriKind]::Absolute, [ref]$parsedUrl) -or
        $parsedUrl.Scheme -notin @('http','https')) {
        throw 'ServerUrl must start with http:// or https://'
    }
    if ($parsedUrl.Scheme -eq 'http') {
        Write-Warning 'HTTP exposes enrollment credentials on the network. Only use in an isolated lab; use HTTPS otherwise.'
    }
} else {
    Write-Host 'Existing agent.json found; retaining saved server URL, hostname and registration.'
}
$root = Split-Path $PSScriptRoot -Parent
$project = Join-Path $root 'DlpAgent\DlpAgent.csproj'
$publish = Join-Path $env:TEMP 'DlpAgent-v2-publish'
$installDir = Join-Path $env:ProgramFiles 'DLPAgent'
$exe = Join-Path $installDir 'DlpAgent.exe'
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'Install .NET 8 SDK from Microsoft first.'
}
Write-Host 'Publishing self-contained Windows x64 executable...'
& dotnet publish $project -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:DebugType=None -o $publish
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed' }
New-Item -ItemType Directory -Force $installDir, $dataDir | Out-Null
$service = Get-Service -Name 'DLPAgent' -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name 'DLPAgent' -Force
        (Get-Service -Name 'DLPAgent').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
}
Copy-Item (Join-Path $publish '*') $installDir -Recurse -Force

# Set inheritance on the folder BEFORE writing configuration. This gives new files
# the required SYSTEM / Administrators access rather than removing it afterwards.
# On reinstall also repair any existing state file left with an empty ACL.
function Assert-Icacls {
    param([string]$Target, [string[]]$Options)
    & icacls.exe $Target @Options | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to set ACL on $Target (icacls exit code $LASTEXITCODE)" }
}
Assert-Icacls $dataDir @('/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
Assert-Icacls $dataDir @('/inheritance:r')

$tokenPath = Join-Path $dataDir 'token.dat'
if (-not $isReinstall) {
    $config = @{
        server_url = $ServerUrl.TrimEnd('/')
        hostname = $Hostname
        enrollment_key = $EnrollmentKey
        heartbeat_seconds = 45
        policy_refresh_seconds = 60
        usb_monitor_enabled = $true
        usb_enforce_block = $false
        http_proxy_enabled = $false
    } | ConvertTo-Json
    [IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))
} else {
    Write-Host 'Existing config preserved, including server URL and hostname.'
    if (Test-Path $tokenPath) { Write-Host 'Existing encrypted token preserved.' }
}
# Do not apply /inheritance:r /T to files: it can remove their only
# inherited access entries, causing an empty ACL and "Access denied".
# Explicitly repair known state files, including old installations.
foreach ($stateFile in @($configPath, $tokenPath, (Join-Path $dataDir 'policy.json'))) {
    if (Test-Path -LiteralPath $stateFile) {
        Assert-Icacls $stateFile @('/grant:r', '*S-1-5-18:F', '*S-1-5-32-544:F')
        Assert-Icacls $stateFile @('/inheritance:r')
    }
}
# Check config read access before installing/starting the service.
try {
    $null = [IO.File]::ReadAllText($configPath)
} catch {
    throw "Config is not readable after ACL repair: $configPath : $($_.Exception.Message)"
}

if (-not $service) {
    # New-Service handles Service Control Manager argument quoting correctly,
    # including the spaces in C:\Program Files.
    New-Service -Name 'DLPAgent' -BinaryPathName ('"' + $exe + '"') `
        -DisplayName 'DLP Agent' -StartupType Automatic -ErrorAction Stop | Out-Null
} else {
    Set-Service -Name 'DLPAgent' -StartupType Automatic -ErrorAction Stop
}
# sc.exe needs separate arguments: option= VALUE (not a single string).
& sc.exe failure DLPAgent reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service recovery configuration failed' }
Start-Service DLPAgent
Start-Sleep -Seconds 5
Get-Service DLPAgent | Format-Table Name, Status, StartType -AutoSize
Write-Host "Installed. Service starts automatically after reboot. State: $dataDir"
Write-Host 'Check Event Viewer > Windows Logs > Application for DLPAgent messages.'
