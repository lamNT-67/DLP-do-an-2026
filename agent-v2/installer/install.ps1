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
$root = Split-Path $PSScriptRoot -Parent
$project = Join-Path $root 'DlpAgent\DlpAgent.csproj'
$publish = Join-Path $env:TEMP 'DlpAgent-v2-publish'
$installDir = Join-Path $env:ProgramFiles 'DLPAgent'
$dataDir = Join-Path $env:ProgramData 'DLPAgent'
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

$configPath = Join-Path $dataDir 'agent.json'
$tokenPath = Join-Path $dataDir 'token.dat'
if (-not (Test-Path $configPath)) {
    $config = @{
        server_url = $ServerUrl.TrimEnd('/')
        hostname = $Hostname
        enrollment_key = $EnrollmentKey
        heartbeat_seconds = 45
        policy_refresh_seconds = 60
    } | ConvertTo-Json
    [IO.File]::WriteAllText($configPath, $config, [Text.UTF8Encoding]::new($false))
} else {
    Write-Host 'Existing config preserved, including server URL and hostname.'
    if (Test-Path $tokenPath) { Write-Host 'Existing encrypted token preserved.' }
}
# Restrict state files: SYSTEM and local Administrators only.
& icacls.exe $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to restrict agent data permissions' }

if (-not $service) {
    & sc.exe create DLPAgent ('binPath= "' + $exe + '"') 'start= auto' 'obj= LocalSystem' 'DisplayName= DLP Agent'
    if ($LASTEXITCODE -ne 0) { throw 'sc.exe create failed' }
} else {
    & sc.exe config DLPAgent 'start= auto'
    if ($LASTEXITCODE -ne 0) { throw 'sc.exe config failed' }
}
& sc.exe failure DLPAgent 'reset= 86400' 'actions= restart/5000/restart/5000/restart/5000' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service recovery configuration failed' }
Start-Service DLPAgent
Start-Sleep -Seconds 5
Get-Service DLPAgent | Format-Table Name, Status, StartType -AutoSize
Write-Host "Installed. Service starts automatically after reboot. State: $dataDir"
Write-Host 'Check Event Viewer > Windows Logs > Application for DLPAgent messages.'
