# Windows PowerShell 5.1. Dot-source curl_task.ps1 first for the shared ACL checks.
$DlpPythonRegistry = 'SOFTWARE\Python\PythonCore'
$DlpRegistryViews = @('Registry64', 'Registry32')
# SHA-256 from the 64-bit installer row on the respective python.org release page.
$DlpPythonReleases = @(
    @{ Version = [version]'3.13.17'; Sha256 = '5da012101ba2e17113a9a1cd901e9ce1441086f2b7ecb5de06ec94163899a190' },
    @{ Version = [version]'3.14.9'; Sha256 = 'a247a0b612244a803f507b39fb7121e3602e4160d59c3b99d98e735289c53394' }
)

function Assert-DlpProtectedLocation([string]$Path) {
    # The volume root may allow creation of unrelated directories. It must
    # still prevent untrusted users from replacing existing children.
    $volume = [IO.Path]::GetPathRoot($Path)
    if (([IO.DriveInfo]::new($volume)).DriveType -ne 'Fixed') { throw "'$Path' must be on a fixed local drive." }
    $rootItem = Get-Item -LiteralPath $volume -Force -ErrorAction Stop
    if ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse point at '$volume'." }
    Assert-CurlAdminAcl (Get-Acl -LiteralPath $volume -ErrorAction Stop) 0xD0140 $volume -ObjectOnly
    if ($Path -eq $volume) { return }
    $component = $volume
    foreach ($name in ($Path.Substring($volume.Length) -split '\\')) {
        $component = Join-Path $component $name
        Assert-CurlProtectedPath $component
    }
}

function Assert-DlpProtectedTree([string]$Path) {
    Assert-CurlProtectedPath $Path
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push($Path)
    while ($pending.Count) {
        foreach ($item in Get-ChildItem -LiteralPath $pending.Pop() -Force -ErrorAction Stop) {
            Assert-CurlProtectedPath $item.FullName
            if ($item.PSIsContainer) { $pending.Push($item.FullName) }
        }
    }
}

function New-DlpPrivateStage {
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    Assert-DlpProtectedLocation $programFiles
    $path = Join-Path $programFiles ('DLP-Setup-' + [guid]::NewGuid().ToString('N'))
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    [IO.Directory]::CreateDirectory($path, $acl) | Out-Null
    Assert-CurlProtectedPath $path
    return $path
}

function Get-DlpRegisteredPython([Microsoft.Win32.RegistryKey]$Hive, [string]$Prefix = '') {
    $core = $Hive.OpenSubKey($Prefix + $DlpPythonRegistry)
    if (-not $core) { return }
    try {
        foreach ($tag in $core.GetSubKeyNames()) {
            $install = $core.OpenSubKey("$tag\InstallPath")
            if (-not $install) { continue }
            try {
                $path = $install.GetValue('ExecutablePath', $null, 'DoNotExpandEnvironmentNames')
                if (-not $path) {
                    $directory = $install.GetValue('', $null, 'DoNotExpandEnvironmentNames')
                    if ($directory -is [string] -and $directory) { $path = [IO.Path]::Combine($directory, 'python.exe') }
                }
                [pscustomobject]@{ Tag = $tag; Path = $path }
            } finally { $install.Dispose() }
        }
    } finally { $core.Dispose() }
}

function Get-DlpMachinePython {
    foreach ($view in $DlpRegistryViews) {
        $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', $view)
        try { Get-DlpRegisteredPython $hive } finally { $hive.Dispose() }
    }
}

function Assert-DlpPsfSignature([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.GetNameInfo('SimpleName', $false) -cne 'Python Software Foundation') {
        throw "Authenticode verification failed for '$Path' (status $($signature.Status)). Expected a valid Python Software Foundation signer."
    }
    Assert-DlpMachineSigningChain $signature.SignerCertificate $Path
}

function Assert-DlpMachineSigningChain($Certificate, [string]$Path) {
    # Authenticode validates the signature and signing time. Also require a
    # machine-trusted chain so a root added by a user cannot approve a publisher.
    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new($true)
    try {
        $chain.ChainPolicy.VerificationFlags = 'IgnoreNotTimeValid'
        $chain.ChainPolicy.RevocationMode = 'NoCheck'
        $chain.ChainPolicy.ApplicationPolicy.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.3')) | Out-Null
        if (-not $chain.Build($Certificate)) {
            $status = ($chain.ChainStatus | ForEach-Object Status) -join ', '
            throw "Machine code-signing chain validation failed for '$Path': $status."
        }
    } finally { $chain.Dispose() }
}

function Assert-DlpAmd64Image([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Missing DOS header.' }
        $stream.Position = 0x3C
        $stream.Position = $reader.ReadUInt32()
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) { throw 'Expected an AMD64 PE image.' }
    } catch { throw "Architecture check failed for '${Path}': $($_.Exception.Message)" }
    finally { $reader.Dispose() }
}

function Invoke-DlpPython([string]$Python, [string]$WorkingDirectory, [string[]]$Arguments) {
    $originalPath = $env:PATH
    $originalTemp = $env:TEMP
    $originalTmp = $env:TMP
    $originalPip = $env:PIP_CONFIG_FILE
    $originalPreference = $ErrorActionPreference
    Push-Location -LiteralPath $WorkingDirectory
    try {
        $env:PATH = [Environment]::SystemDirectory + ';' + [Environment]::GetFolderPath('Windows')
        $env:TEMP = $WorkingDirectory
        $env:TMP = $WorkingDirectory
        $env:PIP_CONFIG_FILE = 'nul'
        $ErrorActionPreference = 'Continue'
        $output = & $Python @Arguments 2>&1
        $code = $LASTEXITCODE
        if ($code -ne 0) { throw "Python operation failed for '$Python' in '$WorkingDirectory' (exit $code)." }
        return $output
    } finally {
        $ErrorActionPreference = $originalPreference
        $env:PIP_CONFIG_FILE = $originalPip
        $env:TMP = $originalTmp
        $env:TEMP = $originalTemp
        $env:PATH = $originalPath
        Pop-Location
    }
}

function Test-DlpPythonCandidate([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:\\[^:]+$' -or $Path -ne [IO.Path]::GetFullPath($Path) -or
        [IO.Path]::GetFileName($Path) -ine 'python.exe') {
        throw "Expected an absolute, canonical python.exe path. Received '$Path'."
    }
    $programFiles = @([Environment]::GetFolderPath('ProgramFiles'), [Environment]::GetFolderPath('ProgramFilesX86'))
    if (-not @($programFiles | Where-Object { $_ -and $Path.StartsWith($_ + '\', 'OrdinalIgnoreCase') }).Count) {
        throw "'$Path' is outside Program Files. Use an all-users Python installation."
    }
    $homeDir = Split-Path -Parent $Path
    Assert-DlpProtectedLocation $homeDir
    Assert-DlpProtectedTree $homeDir
    foreach ($directory in @($homeDir, (Split-Path -Parent $homeDir))) {
        if (Test-Path -LiteralPath (Join-Path $directory 'pyvenv.cfg')) { throw "'$Path' belongs to a virtual environment." }
    }
    if (Get-ChildItem -LiteralPath $homeDir -Filter '*._pth' -Force) { throw "'$homeDir' contains a Python search-path override." }
    Assert-DlpPsfSignature $Path
    Assert-DlpAmd64Image $Path
    $productVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path).ProductVersion
    $version = $null
    if (-not [version]::TryParse($productVersion, [ref]$version) -or
        $version.Major -ne 3 -or $version.Minor -lt 10 -or $version.Minor -gt 14 -or $version.Build -lt 0) {
        throw "'$Path' has product version '$productVersion'. Expected standard CPython 3.10 through 3.14."
    }
    $dll = Join-Path $homeDir ('python{0}{1}.dll' -f $version.Major, $version.Minor)
    Assert-CurlProtectedPath $dll
    Assert-DlpPsfSignature $dll
    Assert-DlpAmd64Image $dll
    $probe = 'import ensurepip, struct, sys, venv; ensurepip.version(); print(sys.version.split()[0]); print(struct.calcsize(''P'')); print(sys.implementation.name)'
    $result = @(Invoke-DlpPython $Path $homeDir @('-I', '-S', '-B', '-c', $probe))
    if ($result.Count -ne 3 -or $result[0] -ne $version.ToString(3) -or $result[1] -ne '8' -or $result[2] -ne 'cpython') {
        throw "Isolated version, architecture or venv probe failed for '$Path'."
    }
    return [pscustomobject]@{ Path = $Path; Version = $version }
}

function Resolve-CurlPython([string]$Choice) {
    if ($Choice) { return (Test-DlpPythonCandidate $Choice).Path }
    $candidates = foreach ($path in (Get-DlpMachinePython | ForEach-Object Path | Sort-Object -Unique)) {
        try { Test-DlpPythonCandidate $path }
        catch { Write-Warning ("Skipping machine-wide Python candidate '${path}': " + $_.Exception.Message) }
    }
    $best = $candidates | Sort-Object Version -Descending | Select-Object -First 1
    if ($best) { return $best.Path }
}

function Test-DlpPythonInstallerConflict([version]$Version) {
    $minor = '{0}.{1}' -f $Version.Major, $Version.Minor
    $namePattern = '^Python ' + [regex]::Escape($minor) + '(?:\.|\s|$)'
    foreach ($view in $DlpRegistryViews) {
        foreach ($scope in 'LocalMachine', 'Users') {
            $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey($scope, $view)
            try {
                $prefixes = @('')
                if ($scope -eq 'Users') { $prefixes = @($hive.GetSubKeyNames() | Where-Object { $_ -match '^S-1-[0-9-]+$' } | ForEach-Object { $_ + '\' }) }
                foreach ($prefix in $prefixes) {
                    if (Get-DlpRegisteredPython $hive $prefix | Where-Object Tag -Match ('^' + [regex]::Escape($minor) + '(?:\D|$)')) { return $true }
                    $uninstall = $hive.OpenSubKey($prefix + 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
                    if (-not $uninstall) { continue }
                    try {
                        foreach ($keyName in $uninstall.GetSubKeyNames()) {
                            $key = $uninstall.OpenSubKey($keyName)
                            if (-not $key) { continue }
                            try { if ($key.GetValue('DisplayName') -match $namePattern) { return $true } }
                            finally { $key.Dispose() }
                        }
                    } finally { $uninstall.Dispose() }
                }
            } finally { $hive.Dispose() }
        }
    }
    # Installer inventory includes installed MSI components for unloaded users.
    # ProductsEx queries inventory without triggering MSI repair.
    $installer = New-Object -ComObject WindowsInstaller.Installer -ErrorAction Stop
    try {
        foreach ($product in $installer.ProductsEx('', 'S-1-1-0', 7)) {
            # Advertised entries have no installed name. Only state 1 is safe to skip.
            $state = $product.InstallProperty('State')
            if ($state -isnot [string] -or $state -cnotin '1', '5') { throw 'Could not determine an MSI product state.' }
            if ($state -ceq '1') { continue }

            $name = $product.InstallProperty('InstalledProductName')
            if ($name -isnot [string] -or [string]::IsNullOrWhiteSpace($name)) { throw 'An installed MSI product has no name.' }
            if ($name -match $namePattern) { return $true }
        }
    } catch {
        throw "Cannot verify Windows Installer product conflicts for Python $minor. $($_.Exception.Message)"
    }
    return $false
}

function Save-DlpSetupDownload([string]$Uri, [string]$Path) {
    $previous = [Net.ServicePointManager]::SecurityProtocol
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Uri -OutFile $Path -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 120 -ErrorAction Stop
    } finally { [Net.ServicePointManager]::SecurityProtocol = $previous }
}

function Invoke-DlpPsfInstaller([string]$Installer, [string]$Target, [string]$Stage) {
    $originalTemp = $env:TEMP
    $originalTmp = $env:TMP
    $originalPath = $env:PATH
    try {
        $env:TEMP = $Stage
        $env:TMP = $Stage
        $env:PATH = [Environment]::SystemDirectory + ';' + [Environment]::GetFolderPath('Windows')
        $arguments = '/quiet /norestart InstallAllUsers=1 PrependPath=0 AppendPath=0 Include_launcher=0 AssociateFiles=0 Shortcuts=0 Include_test=0 Include_pip=1 TargetDir="{0}" /log "{1}"' -f
            $Target, (Join-Path $Stage 'python-install.log')
        $child = Start-Process -FilePath $Installer -ArgumentList $arguments -WorkingDirectory $Stage -Wait -PassThru -ErrorAction Stop
        return $child.ExitCode
    } finally {
        $env:PATH = $originalPath
        $env:TMP = $originalTmp
        $env:TEMP = $originalTemp
    }
}

function Install-DlpMachinePython {
    if (-not $DlpPythonReleases.Count) { throw 'No trusted Python release metadata is configured.' }
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    Assert-DlpProtectedLocation $programFiles
    foreach ($release in $DlpPythonReleases) {
        $version = $release.Version
        if ($version -isnot [version] -or $version.Build -lt 0 -or $release.Sha256 -notmatch '\A[0-9a-fA-F]{64}\z') {
            throw 'Invalid pinned Python release metadata. Review installer_python.ps1 before retrying.'
        }
        $target = Join-Path $programFiles ('DLP-Python-{0}.{1}' -f $version.Major, $version.Minor)
        if ((Test-Path -LiteralPath $target) -or (Test-DlpPythonInstallerConflict $version)) {
            Write-Warning "Skipping Python $version bootstrap because the version family or target '$target' already exists."
            continue
        }
        $stage = New-DlpPrivateStage
        $fileName = "python-$version-amd64.exe"
        $installer = Join-Path $stage $fileName
        Write-Host "Downloading pinned Python $version from python.org."
        Save-DlpSetupDownload "https://www.python.org/ftp/python/$version/$fileName" $installer
        Assert-CurlProtectedPath $installer
        if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash -ne $release.Sha256) {
            throw "SHA-256 mismatch for '$installer'."
        }
        Assert-DlpPsfSignature $installer
        if ((Test-Path -LiteralPath $target) -or (Test-DlpPythonInstallerConflict $version)) {
            throw "Python installer conflict detected before launch. Check '$target' and retry."
        }
        $code = Invoke-DlpPsfInstaller $installer $target $stage
        if ($code -in 1641, 3010) {
            return @{ ExitCode = 3010; Path = $null }
        }
        if ($code -ne 0) { throw "Python $version setup failed (exit $code). See '$stage\python-install.log'." }
        $expected = Join-Path $target 'python.exe'
        if ($expected -notin @(Get-DlpMachinePython | ForEach-Object Path)) {
            throw "Python setup did not register '$expected' in HKLM. See '$stage\python-install.log'."
        }
        $installed = Test-DlpPythonCandidate $expected
        if ($installed.Version.ToString(3) -ne $version.ToString(3)) { throw "Unexpected Python version at '$expected'." }
        Remove-Item -LiteralPath $installer -ErrorAction Stop
        return @{ ExitCode = 0; Path = $installed.Path }
    }
    throw 'No pinned Python version can be installed without a vendor conflict. Supply -CurlPython with a verified, compatible machine-wide interpreter.'
}

function New-DlpPythonVenv([string]$Python, [string]$Path, [string]$Requirements) {
    $parent = Split-Path -Parent $Path
    Assert-CurlProtectedPath $parent
    if (Test-Path -LiteralPath $Path) { throw "Python environment already exists at '$Path'." }
    Invoke-DlpPython $Python $parent @('-I', '-S', '-B', '-m', 'venv', '--copies', $Path) | Out-Null
    $venv = Join-Path $Path 'Scripts\python.exe'
    Assert-DlpProtectedTree $Path
    Invoke-DlpPython $venv $parent @('-I', '-B', '-m', 'pip', '--isolated', 'install', '--disable-pip-version-check', '--only-binary=:all:', '-r', $Requirements) | Out-Null
    Invoke-DlpPython $venv $parent @('-I', '-B', '-c', 'import psutil, requests, pypdf') | Out-Null
    return $venv
}
