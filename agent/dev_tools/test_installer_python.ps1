# Non-elevated tests. Installer launch, download, validation inputs and cutover are faked.
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run these tests from a non-elevated console.' }
$service = Join-Path (Split-Path -Parent $PSScriptRoot) 'service'
. (Join-Path $service 'curl_task.ps1')
. (Join-Path $service 'installer_python.ps1')

$script:passed = 0
function Check([string]$Name, [scriptblock]$Body) {
    & $Body
    $script:passed++
    Write-Output "PASS $Name"
}
function Assert($Condition, [string]$Message = 'Assertion failed.') {
    if (-not $Condition) { throw $Message }
}
function Reject([scriptblock]$Body, [string]$Pattern) {
    try { & $Body } catch { if ($_.Exception.Message -like $Pattern) { return }; throw }
    throw "Expected failure matching $Pattern"
}

function Invoke-DlpPython { throw 'Python must not run in this test.' }
Check 'per-user Python, a launcher and relative paths fail before any execution' {
    Reject { Test-DlpPythonCandidate 'C:\Users\Example\AppData\Local\Python\python.exe' } '*AppData*outside Program Files*'
    Reject { Test-DlpPythonCandidate 'python.exe' } '*absolute*python.exe*'
    Reject { Test-DlpPythonCandidate 'C:\Windows\py.exe' } '*absolute*python.exe*'
}
Check 'default Windows volume inherit-only writes do not bypass the full Curl ACL check' {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;BA)')
    Assert-CurlAdminAcl $acl 0xD0140 'C:\' -ObjectOnly
    Reject { Assert-CurlAdminAcl $acl 0xD0156 'C:\DLP' } "*C:\DLP*SID S-1-5-11*explicit*"
}
Check 'ACL diagnostics include the inherited trustee, access mask and path' {
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:AI(A;;FA;;;BA)(A;ID;0x1301bf;;;AU)')
    Reject { Assert-CurlAdminAcl $acl 0xD0156 'C:\DLP\agent\config.ini' } "*C:\DLP\agent\config.ini*SID S-1-5-11*Modify*0x*inherited*"
}
Check 'ownership diagnostics name the owner SID' {
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:AUG:BAD:P(A;;FA;;;BA)')
    Reject { Assert-CurlAdminAcl $acl 0xD0156 'C:\DLP\agent\config.ini' } "*C:\DLP\agent\config.ini*owner SID S-1-5-11*"
}

Check 'elevation waits, forwards only nonsecret data and propagates the child exit' {
    $capture = @{ Command = $null }
    function Start-Process($FilePath, $Verb, $ArgumentList, [switch]$Wait, [switch]$PassThru) {
        Assert ($Verb -eq 'RunAs' -and $Wait -and $PassThru) 'Elevation must wait for the child.'
        Assert ($FilePath -eq (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe')) 'Elevation must use system PowerShell.'
        $capture.Command = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($ArgumentList[-1]))
        [pscustomobject]@{ ExitCode = 3010 }
    }
    $installer = Join-Path $service 'install.ps1'
    $python = 'C:\Program Files\Python & Tools\python.exe'
    & $installer -CurlPython $python -NoPrompt
    Assert ($LASTEXITCODE -eq 3010) "Expected exit 3010, got $LASTEXITCODE."
    $match = [regex]::Match($capture.Command, "FromBase64String\('([A-Za-z0-9+/=]+)'\)")
    Assert $match.Success 'Elevation data was not captured.'
    $payload = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($match.Groups[1].Value)) | ConvertFrom-Json
    Assert ($payload.CurlPython -ceq $python -and $payload.NoPrompt -and -not $payload.PSObject.Properties['EnrollmentKey'])
    $capture.Command = $null
    & $installer -EnrollmentKey 'TEST-CANARY'
    Assert ($LASTEXITCODE -eq 1 -and -not $capture.Command)
}

Check 'UAC cancellation returns the cancellation exit code' {
    function Start-Process { throw [ComponentModel.Win32Exception]::new(1223) }
    & (Join-Path $service 'install.ps1') -NoPrompt
    Assert ($LASTEXITCODE -eq 1223)
}

$script:signatureStatus = 'Valid'
$script:publisher = 'Python Software Foundation'
function Get-AuthenticodeSignature {
    param($LiteralPath)
    $signer = [pscustomobject]@{}
    $signer | Add-Member ScriptMethod GetNameInfo { param($type, $issuer) return $script:publisher }
    [pscustomobject]@{ Status = $script:signatureStatus; SignerCertificate = $signer }
}
function Assert-DlpMachineSigningChain { $script:events.Add('machine chain') }
$script:events = [Collections.Generic.List[string]]::new()
Check 'unsigned and wrong-publisher images are rejected before machine chain verification' {
    $script:signatureStatus = 'NotSigned'
    Reject { Assert-DlpPsfSignature 'C:\stage\python.exe' } '*python.exe*NotSigned*'
    $script:signatureStatus = 'Valid'
    $script:publisher = 'Other Publisher'
    Reject { Assert-DlpPsfSignature 'C:\stage\python.exe' } '*python.exe*Expected a valid Python Software Foundation signer*'
    Assert ($script:events.Count -eq 0)
    $script:publisher = 'Python Software Foundation'
    Assert-DlpPsfSignature 'C:\stage\python.exe'
    Assert ($script:events -contains 'machine chain')
}

$script:registered = @('C:\Program Files\Python39\python.exe', 'C:\Program Files\Python313\python.exe')
function Get-DlpMachinePython { foreach ($path in $script:registered) { [pscustomobject]@{ Path = $path } } }
function Test-DlpPythonCandidate([string]$Path) {
    $script:events.Add("probe $Path")
    if ($Path -like '*Bad*') { throw 'Candidate rejected.' }
    $version = if ($Path -like '*Python39*') { [version]'3.9.9' } else { [version]'3.13.17' }
    [pscustomobject]@{ Path = $Path; Version = $version }
}
Check 'machine discovery ranks numeric versions and skips failed candidates' {
    $script:registered += 'C:\Program Files\Bad\python.exe'
    $path = Resolve-CurlPython
    Assert ($path -eq 'C:\Program Files\Python313\python.exe')
    Assert (@($DlpRegistryViews).Count -eq 2 -and 'Registry64' -in $DlpRegistryViews -and 'Registry32' -in $DlpRegistryViews)
}
Check 'an invalid explicit override does not fall back to discovery' {
    $script:events.Clear()
    Reject { Resolve-CurlPython 'C:\Program Files\Bad\python.exe' } '*Candidate rejected*'
    Assert ($script:events.Count -eq 1)
}

function Assert-DlpProtectedLocation {}
function Assert-CurlProtectedPath {}
function New-DlpPrivateStage { 'C:\Program Files\DLP-Setup-test' }
function Test-Path { $false }
# Supply a read-only MSI inventory to the real conflict scan without consulting
# the test host's registry or requiring administrator access to ProductsEx.
$DlpRegistryViews = @()
function New-Object($ComObject, $ErrorAction) {
    Assert ($ComObject -eq 'WindowsInstaller.Installer' -and $ErrorAction -eq 'Stop')
    $installer = [pscustomobject]@{}
    $installer | Add-Member ScriptMethod ProductsEx {
        param($Product, $UserSid, $Context)
        Assert ($Product -eq '' -and $UserSid -eq 'S-1-1-0' -and $Context -eq 7)
        return $script:msiProducts
    }
    return $installer
}
function New-MsiProduct([string]$State, [string]$Name, [switch]$UnreadableName) {
    $product = [pscustomobject]@{ State = $State; Name = $Name; UnreadableName = $UnreadableName.IsPresent }
    $product | Add-Member ScriptMethod InstallProperty {
        param($Property)
        switch ($Property) {
            'State' { return $this.State }
            'InstalledProductName' {
                if ($this.UnreadableName) { throw [Runtime.InteropServices.COMException]::new('InstalledProductName unavailable.', -2147467259) }
                return $this.Name
            }
            default { throw "Unexpected MSI property '$Property'." }
        }
    }
    return $product
}
function Save-DlpSetupDownload([string]$Uri, [string]$Path) { $script:events.Add("download $Uri") }
function Get-FileHash { [pscustomobject]@{ Hash = $script:hash } }
function Invoke-DlpPsfInstaller { $script:events.Add('launch'); return $script:vendorExit }
function Remove-Item {}
$advertisedProduct = New-MsiProduct -State '1' -UnreadableName
$script:msiProducts = @($advertisedProduct)
$script:hash = $DlpPythonReleases[0].Sha256
$script:vendorExit = 0

Check 'advertised MSI products are skipped and the requested installed Python family is detected' {
    $script:msiProducts = @($advertisedProduct, (New-MsiProduct '5' 'Lab Editor 3.13'), (New-MsiProduct '5' 'Python 3.13.17 Core Interpreter'))
    Assert (Test-DlpPythonInstallerConflict ([version]'3.13.17'))
    Assert (-not (Test-DlpPythonInstallerConflict ([version]'3.14.9')))
    $script:msiProducts = @($advertisedProduct)
}
Check 'unresolved installed MSI products and unknown MSI states stop bootstrap before download' {
    $script:events.Clear()
    foreach ($product in (New-MsiProduct -State '5' -UnreadableName), (New-MsiProduct '5' ' '), (New-MsiProduct -State '0')) {
        $script:msiProducts = @($advertisedProduct, $product)
        Reject { Install-DlpMachinePython } '*Cannot verify Windows Installer product conflicts for Python 3.13*'
        Assert ($script:events.Count -eq 0)
    }
    $script:msiProducts = @($advertisedProduct)
}

Check 'bad digest prevents signature checks and installer launch' {
    $script:events.Clear()
    $script:hash = 'bad digest'
    Reject { Install-DlpMachinePython } '*SHA-256 mismatch*'
    Assert ($script:events.Count -eq 1)
    $script:hash = $DlpPythonReleases[0].Sha256
}
Check 'a pinned digest does not bypass Authenticode publisher validation' {
    $script:events.Clear()
    $script:publisher = 'Other Publisher'
    Reject { Install-DlpMachinePython } '*Authenticode verification failed*'
    Assert ($script:events -notcontains 'launch')
    $script:publisher = 'Python Software Foundation'
}
Check 'a vendor conflict selects the alternate pin and reboot exits before probing' {
    $script:events.Clear()
    $script:msiProducts = @($advertisedProduct, (New-MsiProduct '5' 'Python 3.13.17 Core Interpreter'))
    $script:hash = $DlpPythonReleases[1].Sha256
    $script:vendorExit = 3010
    $result = Install-DlpMachinePython
    Assert ($result.ExitCode -eq 3010 -and -not $result.Path)
    Assert ($script:events.Count -eq 3 -and $script:events[0] -like '*3.14.9-amd64.exe')
    Assert ($script:events[1] -eq 'machine chain' -and $script:events[2] -eq 'launch')
}
Check 'conflicts for both pins stop before download' {
    $script:events.Clear()
    $script:msiProducts = @($advertisedProduct, (New-MsiProduct '5' 'Python 3.13.17 Core Interpreter'), (New-MsiProduct '5' 'Python 3.14.9 Core Interpreter'))
    Reject { Install-DlpMachinePython } '*without a vendor conflict*'
    Assert ($script:events.Count -eq 0)
    $script:msiProducts = @($advertisedProduct)
    $script:hash = $DlpPythonReleases[0].Sha256
}
Check 'vendor exit zero still requires the expected HKLM target' {
    $script:events.Clear()
    $script:vendorExit = 0
    Reject { Install-DlpMachinePython } '*did not register*C:\Program Files\DLP-Python-3.13\python.exe*'
    Assert (-not @($script:events | Where-Object { $_ -like 'probe *' }).Count)
}
Check 'vendor success returns the revalidated machine target' {
    $target = 'C:\Program Files\DLP-Python-3.13\python.exe'
    $script:registered = @($target)
    $result = Install-DlpMachinePython
    Assert ($result.ExitCode -eq 0 -and $result.Path -eq $target)
}
Check 'missing release metadata stops before download or launch' {
    $DlpPythonReleases = @()
    $script:events.Clear()
    Reject { Install-DlpMachinePython } '*No trusted Python release metadata*'
    Assert ($script:events.Count -eq 0)
}

Check 'both venvs are prepared from the selected base before Curl or service stops' {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $service 'install.ps1'), [ref]$tokens, [ref]$errors)
    Assert ($errors.Count -eq 0)
    $commands = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
    $shared, $curl, $maintenance, $stop = foreach ($name in 'New-DlpPythonVenv', 'New-CurlRelease', 'Enter-CurlMaintenance', 'Stop-DlpSharedWork') {
        $commands | Where-Object { $_.GetCommandName() -eq $name } | Select-Object -First 1
    }
    Assert ($shared.Extent.Text -like 'New-DlpPythonVenv $pyExe *' -and $curl.Extent.Text -like 'New-CurlRelease $curlDeployment $Source $pyExe')
    Assert ($shared.Extent.EndOffset -lt $maintenance.Extent.StartOffset -and $curl.Extent.EndOffset -lt $maintenance.Extent.StartOffset)
    Assert ($maintenance.Extent.EndOffset -lt $stop.Extent.StartOffset)
}
Write-Output "$script:passed Python installer tests passed."
