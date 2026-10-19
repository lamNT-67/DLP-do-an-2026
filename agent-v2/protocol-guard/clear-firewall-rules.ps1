# Run as Administrator to remove ONLY DLPAgent protocol rules.
# Use after disabling protocol_firewall_enabled or before uninstalling the agent.
# No third-party/non-DLP firewall rules are touched.
#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$managed = @(Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'DLPAgent Protocol *' })
if ($managed.Count -eq 0) {
    Write-Host "No DLPAgent protocol rules found."
    exit 0
}
$managed | Select-Object DisplayName, Enabled, Direction, Action | Format-Table -AutoSize
$managed | Remove-NetFirewallRule -ErrorAction Stop
Write-Host "Removed $($managed.Count) DLPAgent protocol firewall rules."
