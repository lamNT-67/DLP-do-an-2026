# Run with Windows PowerShell 5.1. Scheduler, registry, process and removal operations are in-memory fakes.
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'service\curl_task.ps1')
$script:passed = 0
function Check([string]$Name, [scriptblock]$Body) {
    & $Body
    $script:passed++
    Write-Output "PASS $Name"
}
function Assert($Condition) { if (-not $Condition) { throw 'Assertion failed.' } }
function Reject([scriptblock]$Body, [string]$Pattern) {
    try { & $Body } catch { if ($_.Exception.Message -like $Pattern) { return }; throw }
    throw "Expected failure matching $Pattern"
}
function Bag {
    $obj = [pscustomobject]@{ Values = @{}; Records = @{} }
    $obj | Add-Member ScriptMethod GetValue { param($k,$default) if ($this.Values.ContainsKey($k)) { $this.Values[$k] } else { $default } }
    $obj | Add-Member ScriptMethod SetValue { param($k,$v) $this.Values[$k] = $v }
    $obj | Add-Member ScriptMethod DeleteValue { param($k,$unused) $this.Values.Remove($k) }
    $obj | Add-Member ScriptMethod GetValueKind { param($k) 'String' }
    $obj | Add-Member ScriptMethod Flush { }
    return $obj
}
function Collection {
    $c = [pscustomobject]@{ Count=0; Member=$null }
    $c | Add-Member ScriptMethod Create { param($kind) $this.Count++; $this.Member=@{Type=$kind}; return $this.Member }
    $c | Add-Member ScriptMethod Item { param($index) return $this.Member }
    return $c
}
function Context {
    $scheduler = [pscustomobject]@{}
    $scheduler | Add-Member ScriptMethod NewTask {
        param($flags)
        return @{ RegistrationInfo=@{}; Principal=@{LogonType=4}; Actions=Collection; Triggers=Collection; Settings=@{} }
    }
    $folder = [pscustomobject]@{ Live=$null; LastFlags=0; Deleted=$false }
    $folder | Add-Member ScriptMethod GetTask { param($what) $this.Live }
    $folder | Add-Member ScriptMethod RegisterTaskDefinition {
        param($name,$def,$flags,$group,$password,$mode,$sddl)
        if ($name -ne 'DLPCurlAgent' -or $group -ne 'S-1-5-32-545' -or $password -or $mode -ne 4 -or
            $sddl -cne 'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)') { throw 'Wrong task registration identity or DACL.' }
        if (($flags -eq 2 -and $this.Live) -or ($flags -eq 4 -and -not $this.Live)) { throw 'Create/update collision.' }
        $this.LastFlags = $flags
        $this.Live=[pscustomobject]@{Enabled=$def.Settings.Enabled; Definition=$def; Remaining=0; Probes=0}
        $this.Live | Add-Member ScriptMethod GetInstances {
            param($flags)
            $this.Probes++
            if ($this.Remaining -gt 0) { $this.Remaining--; return [pscustomobject]@{ Count=1 } }
            return [pscustomobject]@{ Count=0 }
        }
        return $this.Live
    }
    $folder | Add-Member ScriptMethod DeleteTask { param($what,$flags) $this.Deleted=$true; $this.Live=$null }
    return @{ Scheduler=$scheduler; Folder=$folder; Key=Bag; Instances=Bag; Owner='a'*32; Old=''; Staged='c'*32; Quiesced=$false; Switched=$false }
}
function Receipt([string]$State, [string]$Op) {
    return [pscustomobject]@{version=1;instance='1'*32;local_stop='2'*32;state=$State;operation=$Op
        pending_resumes=0;worker_cleanup_confirmed=$true;report_drained=$true;runtime_failed=$false}
}
# No test calls the OS process enumeration, registry, deployment filesystem or Scheduler.
function Get-CimInstance { param($ClassName,$Filter,$Property,$ErrorAction) return $script:processes }
function Get-CurlRecords($Instances) { return $Instances.Records }
function Remove-CurlRelease($Context,$Id) { $Context.Removed=$Id }
$script:processes = @()

Check 'reject inherited authenticated-user writes and accept protected read/execute ACL' {
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:(A;OICI;FA;;;BA)(A;OICIIO;SDGXGWGR;;;AU)')
    Reject { Assert-CurlAdminAcl $acl 0xD0156 } '*grants write*'
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200A9;;;BU)')
    Assert-CurlAdminAcl $acl 0xD0156
}
Check 'reject GENERIC_WRITE without any specific write bits' {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;BA)(A;;GW;;;BU)')
    Reject { Assert-CurlAdminAcl $acl 0xD0156 } '*grants write*'
}
Check 'reject GENERIC_ALL without any specific write bits' {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;BA)(A;;GA;;;BU)')
    Reject { Assert-CurlAdminAcl $acl 0xD0156 } '*grants write*'
}
Check 'reject inherit-only and inherited child-file write grants' {
    $parent = [Security.AccessControl.DirectorySecurity]::new()
    $child = [Security.AccessControl.FileSecurity]::new()
    foreach ($rights in 'GW','GA') {
        $parent.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;;FA;;;BA)(A;OIIO;${rights};;;AU)")
        Reject { Assert-CurlAdminAcl $parent 0xD0156 } '*grants write*'
        $child.SetSecurityDescriptorSddlForm("O:BAG:BAD:AI(A;;FA;;;BA)(A;ID;${rights};;;AU)")
        Reject { Assert-CurlAdminAcl $child 0xD0156 } '*grants write*'
    }
}
Check 'reject generic write grants when validating a registry key' {
    $acl = [Security.AccessControl.RegistrySecurity]::new()
    foreach ($rights in 'GW','GA') {
        $acl.SetSecurityDescriptorSddlForm("O:BAG:BAD:P(A;;KA;;;BA)(A;CIIO;${rights};;;AU)")
        Reject { Assert-CurlAdminAcl $acl 0xD0006 } '*grants write*'
    }
}
Check 'allow untrusted generic read and execute including child inheritance' {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;BA)(A;OICI;GRGX;;;BU)(A;OIIO;GRGX;;;AU)')
    Assert-CurlAdminAcl $acl 0xD0156
}
Check 'allow trusted administrators and SYSTEM generic write and full access' {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;GA;;;BA)(A;OIIO;GW;;;SY)')
    Assert-CurlAdminAcl $acl 0xD0156
}
Check 'create and verify disabled group-logon registration' {
    $c=Context
    $t=Register-CurlRelease $c $c.Staged $false
    Assert ($c.Folder.LastFlags -eq 2 -and -not $t.Enabled)
    Assert ($t.Definition.Actions.Member.WorkingDirectory -eq (Get-CurlLayout $c.Staged).Dir)
}
Check 'normal install enables a fresh release only after maintenance' {
    $c=Context
    Enter-CurlMaintenance $c $null
    Complete-CurlInstall $c
    Assert ($c.Installed -and $c.Folder.Live.Enabled -and $c.Key.Values.Current -eq $c.Staged)
    Assert ($c.Key.Values.Maintenance -ceq '' -and -not $c.Instances.Values.ContainsKey('MaintenancePlan'))
}
Check 'foreign task blocks modification' {
    $c=Context
    $c.Old='b'*32; $c.Quiesced=$true
    $t=Register-CurlRelease $c $c.Old $false
    $t.Definition.RegistrationInfo.Description='different product'
    Reject { Complete-CurlInstall $c } '*collision*'
    Assert (-not $c.Switched -and $c.Folder.LastFlags -eq 2)
}
Check 'explicitly elevated task fails effective verification' {
    $c=Context; $t=Register-CurlRelease $c $c.Staged $false
    $t.Definition.Principal.RunLevel=1
    Reject { Assert-CurlSettings $t $false } '*settings*'
}
Check 'idle, battery, finite execution, instance serialization and restart drift rejected' {
    foreach ($field in 'RunOnlyIfIdle','DisallowStartIfOnBatteries','StopIfGoingOnBatteries','MultipleInstances','RestartCount','ExecutionTimeLimit') {
        $c=Context; $t=Register-CurlRelease $c $c.Staged $false
        $t.Definition.Settings[$field]=if ($field -eq 'ExecutionTimeLimit') {'PT10S'} else {1}
        Reject { Assert-CurlSettings $t $false } '*settings*'
    }
}
Check 'wait for tracked Scheduler instances before authorizing replacement' {
    $c=Context; $c.Old='b'*32; $t=Register-CurlRelease $c $c.Old $false
    $t.Enabled=$true; $t.Remaining=1
    Enter-CurlMaintenance $c $t
    Assert ($t.Probes -eq 2 -and -not $t.Enabled -and $c.OldEnabled -and $c.Quiesced)
    Assert (-not $c.Key.Values.ContainsKey('MaintenancePlan'))
}
Check 'independent interpreter observation includes venv redirector child' {
    $gen='b'*32; $entry=Join-Path (Get-CurlLayout $gen).Dir 'curl_managed.py'
    $script:processes = @([pscustomobject]@{CommandLine='python.exe -E -s -B "'+$entry+'"'; ExecutablePath='C:\Program Files\Python\python.exe'})
    try { Assert (-not (Test-CurlInterpreterExited $gen)) } finally { $script:processes=@() }
}
Check 'forced exit with running record keeps both runtimes and holds teardown' {
    $c=Context; $c.Old='b'*32; $c.Task=Register-CurlRelease $c $c.Old $false; $c.Task.Enabled=$true
    $r=Receipt running ''; $c.Instances.Records[$r.instance]=$r
    Reject { Uninstall-CurlTask $c $true } '*without a complete receipt*'
    Assert (-not $c.Folder.Deleted -and -not $c.Task.Enabled -and $c.Key.Values.Maintenance -and -not $c.Quiesced)
}
Check 'malformed protected maintenance snapshot still disables the owned task' {
    $c=Context; $c.Old='b'*32; $c.Task=Register-CurlRelease $c $c.Old $false
    $c.Task.Enabled=$true; $c.Instances.SetValue('MaintenancePlan','{"operation":"bad"}')
    Reject { Enter-CurlMaintenance $c $c.Task } '*inconsistent*'
    Assert (-not $c.Task.Enabled -and -not $c.Quiesced)
}
Check 'successful replacement cleans previous owned release' {
    $c=Context; $c.Old='b'*32; $c.Task=Register-CurlRelease $c $c.Old $false
    Enter-CurlMaintenance $c $c.Task
    Complete-CurlInstall $c
    Assert ($c.Installed -and $c.Folder.Live.Enabled -and $c.Folder.LastFlags -eq 4 -and $c.Removed -eq $c.Old)
}
Check 'rollback restores previous release and its prior enabled/disabled state' {
    foreach ($enabled in $true,$false) {
        $c=Context; $c.Old='b'*32; $c.Task=Register-CurlRelease $c $c.Old $false
        $c.Task.Enabled=$enabled
        Enter-CurlMaintenance $c $c.Task
        $c.Switched=$true
        Register-CurlRelease $c $c.Staged $true | Out-Null
        $c.Key.SetValue('Current',$c.Staged)
        Undo-CurlInstall $c
        Assert ($c.Key.Values.Current -ceq $c.Old -and $c.Folder.Live.Enabled -eq $enabled -and $c.Removed -ceq $c.Staged)
        Assert-CurlOwnership $c.Folder.Live $c.Owner $c.Old
    }
}
Check 'uninstall removes only the owned task after verified stop' {
    $c=Context; $c.Old='b'*32; $c.Task=Register-CurlRelease $c $c.Old $false
    $c.Task.Enabled=$true
    Uninstall-CurlTask $c $false
    Assert ($c.Quiesced -and $c.Folder.Deleted -and $c.Key.Values.Current -ceq '' -and $c.Key.Values.Maintenance -ceq '')
}
Check 'validate parseable, bounded, typed receipts' {
    $bag=Bag; $r=Receipt complete ('f'*32)
    $bag.SetValue('Record', ($r | ConvertTo-Json -Compress))
    Assert ((Read-CurlRecord $bag $r.instance).state -ceq 'complete')
    $r.pending_resumes=$false; $bag.SetValue('Record', ($r | ConvertTo-Json -Compress))
    Reject { Read-CurlRecord $bag $r.instance } '*Malformed terminal*'
}
Check 'missing, stale, incomplete and mismatched receipts block replacement' {
    $r=Receipt complete ('f'*32); $id=$r.instance; $records=@{}; $plan=@{operation='f'*32;records=@(@{instance=$id;local_stop=$r.local_stop;state='running'})}
    Reject { Assert-CurlCleanup $records $plan } '*disappeared*'
    $records[$id]=$r
    Assert (Assert-CurlCleanup $records $plan)
    $r.operation='a'*32; Reject { Assert-CurlCleanup $records $plan } '*stale*'
    $r.operation=$plan.operation; $r.pending_resumes=1; Reject { Assert-CurlCleanup $records $plan } '*incomplete*'
    $r.pending_resumes=0; $r.worker_cleanup_confirmed=$false; Reject { Assert-CurlCleanup $records $plan } '*incomplete*'
    $r.local_stop='e'*32; Reject { Assert-CurlCleanup $records $plan } '*identity changed*'
}
Write-Output "$script:passed Curl installer tests passed."
