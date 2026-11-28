# Validate the subset of INI options consumed by the current agents.
function Read-DlpConfig([byte[]]$Bytes, [string]$Path) {
    if ($null -eq $Bytes -or $Bytes.Length -gt 65536) { throw "Invalid enrollment file size at '$Path'." }
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes).TrimStart([char]0xFEFF) }
    catch { throw "Expected UTF-8 enrollment data at '$Path'." }
    $supported = @{
        agent = @('hostname', 'server_url', 'api_token', 'enrollment_key', 'firewall_drop_log')
        browser = @('extension_ids')
    }
    $config = @{}
    $section = ''
    $number = 0
    foreach ($line in ($text -split '\r?\n')) {
        $number++
        if ($line -match '^\s*(?:[;#].*)?$') { continue }
        if ($line -cmatch '^\s*\[([a-z]+)\]\s*$' -and $supported.ContainsKey($Matches[1]) -and -not $config.ContainsKey($Matches[1])) {
            $section = $Matches[1]
            $config[$section] = @{}
        } elseif ($section -and $line -match '^\s*([a-z_]+)\s*[=:]\s*([^\x00-\x1f\x7f]*)$' -and
            $Matches[1] -in $supported[$section] -and -not $config[$section].ContainsKey($Matches[1])) {
            $config[$section][$Matches[1].ToLowerInvariant()] = $Matches[2].Trim()
        } else { throw "Unsupported or duplicate enrollment setting at '${Path}' line $number." }
    }
    if (-not $config.agent) { throw "Missing [agent] enrollment settings at '$Path'." }
    return $config
}

function ConvertTo-DlpServerUrl([string]$Value) {
    $url = $null
    if ($Value -notmatch '^https?://[^\x00-\x20\x7f\\%]+$' -or -not [uri]::TryCreate($Value, 'Absolute', [ref]$url) -or
        $url.UserInfo -or $url.Query -or $url.Fragment -or -not $url.Host -or $url.AbsoluteUri.Contains('%')) {
        throw 'Enter an absolute DLP server API URL without credentials, escapes, a query or a fragment.'
    }
    return $url
}

function Assert-DlpEnrollmentFields($Config, [string]$Path) {
    if ($Config.agent.hostname -notmatch '\A[A-Za-z0-9][A-Za-z0-9._-]{0,99}\z') { throw "Invalid hostname in '$Path'." }
    if ($Config.agent.api_token) {
        if ($Config.agent.api_token -notmatch '\A[A-Za-z0-9._~-]{1,255}\z') { throw "Invalid device token format in '$Path'." }
    } elseif ($Config.agent.enrollment_key -notmatch '\A[!-~]{1,64}\z' -or
        $Config.agent.enrollment_key -match '%' -or $Config.agent.enrollment_key -eq 'DAN-ENROLLMENT-KEY-TU-TRANG-SETTINGS-VAO-DAY') {
        throw "A valid enrollment key or existing device token is required in '$Path'."
    }
    if ($Config.agent.ContainsKey('firewall_drop_log') -and $Config.agent.firewall_drop_log -notin 'true', 'false') {
        throw "Invalid firewall_drop_log in '$Path'."
    }
    if ($Config.browser.extension_ids -and $Config.browser.extension_ids -notmatch '\A[A-Za-z0-9._@{}, -]{1,4096}\z') {
        throw "Invalid browser extension_ids in '$Path'."
    }
}

function Read-DlpPolicyResponse([uri]$Uri, [string]$Token) {
    $request = [Net.WebRequest]::CreateHttp($Uri)
    $request.AllowAutoRedirect = $false
    $request.Timeout = 10000
    $request.ReadWriteTimeout = 10000
    if ($Uri.IsLoopback) { $request.Proxy = $null }
    $request.Headers['Authorization'] = "Bearer $Token"
    $response = $request.GetResponse()
    try {
        if ($response.StatusCode -ne [Net.HttpStatusCode]::OK) { throw 'Expected an HTTP 200 policy response.' }
        $reader = [IO.StreamReader]::new($response.GetResponseStream(), [Text.Encoding]::UTF8)
        try { return ConvertFrom-Json -InputObject ($reader.ReadToEnd()) -ErrorAction Stop }
        finally { $reader.Dispose() }
    } finally { $response.Dispose() }
}

function Assert-DlpEnrollmentToken($Config) {
    $previous = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $reply = Read-DlpPolicyResponse ($Config.agent.server_url + '/agent_policy.php') $Config.agent.api_token
    } catch {
        $failure = $_.Exception.GetBaseException()
        $detail = ''
        if ($failure -is [Net.WebException] -and $failure.Response) {
            $detail = " (HTTP $([int]$failure.Response.StatusCode))"
            $failure.Response.Dispose()
        }
        throw "The approved DLP server could not validate the saved device token$detail. Verify server access and device credentials."
    } finally { [Net.ServicePointManager]::SecurityProtocol = $previous }
    if ($reply.hostname -isnot [string] -or $reply.hostname -cne $Config.agent.hostname) {
        throw 'The DLP server returned a different enrolled hostname. Check the device identity.'
    }
}

function ConvertTo-DlpConfigBytes($Config) {
    $lines = foreach ($section in 'agent', 'browser') {
        if (-not $Config.ContainsKey($section)) { continue }
        "[$section]"
        foreach ($key in ($Config[$section].Keys | Sort-Object)) { "$key = $($Config[$section][$key])" }
        ''
    }
    return ,([Text.UTF8Encoding]::new($false).GetBytes(($lines -join [Environment]::NewLine) + [Environment]::NewLine))
}

function Get-DlpConfigFileAcl($Config, [switch]$Private) {
    $sddl = 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    if (-not $Private -and -not $Config.agent.ContainsKey('enrollment_key')) { $sddl += '(A;;FR;;;BU)' }
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($sddl)
    return $acl
}

function New-DlpConfigFile([string]$Path, $Config, [switch]$Private) {
    $bytes = ConvertTo-DlpConfigBytes $Config
    $acl = Get-DlpConfigFileAcl $Config -Private:$Private
    $stream = [IO.FileStream]::new($Path, 'CreateNew', 'Write', 'None', 4096, 'None', $acl)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Publish-DlpEnrolledConfig([string]$Path, [string]$Recovery, $Config) {
    if (-not $Config.agent.api_token -or $Config.agent.ContainsKey('enrollment_key')) {
        throw 'Publishing enrollment requires a validated device token and a sanitized configuration.'
    }
    New-DlpConfigFile (Join-Path $Recovery 'enrolled-config.ini') $Config -Private
    $temporary = Join-Path (Split-Path -Parent $Path) ('.config-' + [guid]::NewGuid().ToString('N') + '.tmp')
    New-DlpConfigFile $temporary $Config -Private
    try {
        [DlpInstaller.Paths]::ReplaceConfig($temporary, $Path)
        # Only the replacement receives Users access. The original file's
        # private ACL is never relaxed, including if replacement fails.
        $acl = [Security.AccessControl.FileSecurity]::new()
        $acl.SetSecurityDescriptorSddlForm((Get-DlpConfigFileAcl $Config).GetSecurityDescriptorSddlForm('Access'), 'Access')
        [IO.File]::SetAccessControl($Path, $acl)
    } catch {
        throw "Could not publish sanitized configuration at '$Path'. $($_.Exception.GetBaseException().Message)"
    } finally { [IO.File]::Delete($temporary) }
}

function Resolve-DlpEnrollment($Layout, [string]$Source, [string]$ServerUrl, [string]$Hostname,
    [string]$EnrollmentKey, [switch]$NoPrompt, [switch]$AllowInsecureLabServer) {
    $path = Join-Path $Layout.InstallDir 'agent\config.ini'
    $bytes = $Layout.Config.Bytes
    $legacy = $Layout.InstallIssues.Count -gt 0
    if ($null -eq $bytes) {
        $path = Join-Path $Source 'config.ini'
        if (Test-Path -LiteralPath $path -PathType Leaf) { $bytes = [IO.File]::ReadAllBytes($path) }
    }
    if ($null -ne $bytes) {
        $config = Read-DlpConfig $bytes $path
        Assert-DlpEnrollmentFields $config $path
        $savedUrl = ConvertTo-DlpServerUrl $config.agent.server_url
        if ($legacy) {
            if (-not $config.agent.api_token) { throw "Unsafe legacy '$path' has no device token. Recover the enrolled configuration before retrying." }
            if (-not $ServerUrl -and -not $NoPrompt) { $ServerUrl = Read-Host 'Enter the known DLP server API URL to approve migration' }
            if (-not $ServerUrl) { throw 'Legacy migration requires an independently supplied -ServerUrl for the enrolled device.' }
            if (-not $Hostname) {
                $Hostname = $env:COMPUTERNAME
                if ($Hostname -cne $config.agent.hostname -and -not $NoPrompt) {
                    $Hostname = Read-Host 'Enter the hostname recorded for this device in DLP Admin'
                }
            }
            if (-not $Hostname) { throw 'Legacy migration requires the enrolled hostname.' }
        }
        if ($ServerUrl -and (ConvertTo-DlpServerUrl $ServerUrl).AbsoluteUri.TrimEnd('/') -cne $savedUrl.AbsoluteUri.TrimEnd('/')) {
            throw 'The approved server URL differs from the saved enrollment URL. Review the existing device configuration.'
        }
        if ($Hostname -and $Hostname -cne $config.agent.hostname) { throw 'The supplied hostname differs from the saved device identity.' }
        $url = $savedUrl
    } else {
        $path = 'setup enrollment inputs'
        if (-not $ServerUrl -and -not $NoPrompt) {
            $ServerUrl = Read-Host 'DLP server API URL [http://localhost/dlp_server/api]'
            if (-not $ServerUrl) { $ServerUrl = 'http://localhost/dlp_server/api' }
        }
        if (-not $ServerUrl) { throw 'Fresh unattended setup requires -ServerUrl and -EnrollmentKey or a valid source config.ini.' }
        if (-not $Hostname) {
            $Hostname = $env:COMPUTERNAME
            if (-not $NoPrompt) {
                $answer = Read-Host "Hostname [$Hostname]"
                if ($answer) { $Hostname = $answer }
            }
        }
        if (-not $EnrollmentKey -and -not $NoPrompt) {
            $secret = Read-Host 'Enrollment key (from Admin Web Settings)' -AsSecureString
            try { $EnrollmentKey = [Net.NetworkCredential]::new('', $secret).Password }
            finally { $secret.Dispose() }
        }
        $config = @{ agent = @{ hostname = $Hostname; api_token = ''; enrollment_key = $EnrollmentKey } }
        $url = ConvertTo-DlpServerUrl $ServerUrl
    }
    Assert-DlpEnrollmentFields $config $path
    if ($url.Scheme -eq 'http' -and -not $url.IsLoopback -and -not $AllowInsecureLabServer) {
        if ($NoPrompt -or (Read-Host 'HTTP exposes credentials on the network. Type LAB to approve this isolated lab server') -cne 'LAB') {
            throw 'Use HTTPS or explicitly approve the isolated lab server with -AllowInsecureLabServer.'
        }
    }
    $config.agent.server_url = $url.AbsoluteUri.TrimEnd('/')
    if ($config.agent.api_token) {
        Assert-DlpEnrollmentToken $config
        $config.agent.Remove('enrollment_key')
    }
    return $config
}

function Wait-DlpEnrollment([string]$Path, $Expected) {
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    do {
        try {
            $config = Read-DlpConfig ([IO.File]::ReadAllBytes($Path)) $Path
            if ($config.agent.api_token) {
                if ($config.agent.hostname -cne $Expected.agent.hostname -or $config.agent.server_url -cne $Expected.agent.server_url) {
                    throw 'Device enrollment changed its approved server or hostname.'
                }
                Assert-DlpEnrollmentFields $config $Path
                Assert-DlpEnrollmentToken $config
                $config.agent.Remove('enrollment_key')
                return $config
            }
        } catch [IO.IOException] {
            # The agent can have the file open while saving its initial token.
        }
        Start-Sleep -Milliseconds 500
    } while ($deadline.Elapsed.TotalSeconds -lt 30)
    throw "DLPNetworkAgent did not write a device token to '$Path'. Check the enrollment key and service logs."
}
