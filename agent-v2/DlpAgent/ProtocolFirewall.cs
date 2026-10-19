using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DlpAgent;

/// <summary>
/// Opt-in, coarse protocol/application egress blocking via built-in Windows Firewall.
/// BLOCK policy means block the whole selected process+port, NOT a file type.
/// Does not inspect encrypted uploads or prevent nonstandard-port/custom-client bypass.
/// </summary>
internal sealed class ProtocolFirewall
{
    private const string Prefix = "DLPAgent Protocol";
    private readonly ILogger _logger;
    private string? _appliedSignature;

    internal ProtocolFirewall(ILogger logger) => _logger = logger;

    internal async Task ApplyPolicyAsync(string policyJson, CancellationToken ct)
    {
        using var doc = JsonDocument.Parse(policyJson);
        var blocked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in doc.RootElement.GetProperty("applicable_policies").EnumerateArray())
        {
            if (p.GetProperty("action").GetString() != "BLOCK" ||
                !p.TryGetProperty("exit_points", out var points) || points.ValueKind != JsonValueKind.Array)
                continue;
            foreach (var pt in points.EnumerateArray())
            {
                switch (pt.GetString())
                {
                    case "CLIENT_SCP": blocked.Add("SCP"); break;
                    case "CLIENT_SFTP": blocked.Add("SFTP"); break;
                    case "CLIENT_FTP": blocked.Add("FTP"); break;
                    case "NETWORK_SCP_SFTP": blocked.Add("SCP"); blocked.Add("SFTP"); break;
                    case "NETWORK_FTP": blocked.Add("FTP"); break;
                }
            }
        }

        // Explicit, opt-in semantics: any BLOCK policy on a channel blocks ALL
        // traffic from these client executables to conventional protocol ports.
        // The policy's file_types are intentionally NOT used for firewall decisions.
        var specs = new List<(string Tag, string Executable, int Port)>();
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        // OpenSSH scp.exe/sftp.exe can delegate the actual TCP socket to ssh.exe.
        // The Windows Firewall -Program filter must match the socket-owning process.
        // This is intentionally coarse: matching ssh.exe also blocks interactive SSH
        // over TCP 22, not just SCP/SFTP transfers.
        if (blocked.Contains("SCP") || blocked.Contains("SFTP"))
            specs.Add(("SSH-TRANSPORT", Path.Combine(system, "OpenSSH", "ssh.exe"), 22));
        if (blocked.Contains("SCP"))
            specs.Add(("SCP", Path.Combine(system, "OpenSSH", "scp.exe"), 22));
        if (blocked.Contains("SFTP"))
        {
            specs.Add(("SFTP", Path.Combine(system, "OpenSSH", "sftp.exe"), 22));
            specs.Add(("SFTP-CURL", Path.Combine(system, "curl.exe"), 22));
        }
        if (blocked.Contains("FTP"))
        {
            specs.Add(("FTP", Path.Combine(system, "ftp.exe"), 21));
            specs.Add(("FTP-CURL", Path.Combine(system, "curl.exe"), 21));
        }

        var signature = string.Join(";", specs.OrderBy(x => x.Tag).Select(x => x.Tag + "|" + x.Executable + "|" + x.Port));
        if (signature == _appliedSignature) return;

        // Only touch firewall rules in our own named namespace.
        // Fail closed: do not tear down an existing rule set when the script fails.
        var additions = new StringBuilder();
        foreach (var (tag, executable, port) in specs)
        {
            additions.AppendLine($@"
if (Test-Path -LiteralPath '{Q(executable)}' -PathType Leaf) {{
    New-NetFirewallRule -DisplayName '{Prefix} {tag}' -Direction Outbound -Action Block -Enabled True -Profile Any -Program '{Q(executable)}' -Protocol TCP -RemotePort {port} -ErrorAction Stop | Out-Null
}} else {{
    Write-Warning 'DLP skipped missing executable: {Q(executable)}'
}}");
        }
        // Rebuild on policy refresh only when target set changes; remove stale
        // managed rules, add current rules. Never touch unrelated firewall rules.
        var script = $@"
$ErrorActionPreference = 'Stop'
$existing = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {{ $_.DisplayName -like '{Prefix} *' }})
$existing | Remove-NetFirewallRule -ErrorAction Stop
{additions}
";
        try
        {
            var start = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-NonInteractive");
            start.ArgumentList.Add("-EncodedCommand");
            start.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not start PowerShell");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(25));
            var stdout = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var stderr = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token);
            var error = await stderr;
            var output = await stdout;
            if (process.ExitCode != 0)
                throw new InvalidOperationException($"Windows Firewall failed (exit {process.ExitCode}): {error}");
            _appliedSignature = signature;
            _logger.LogWarning("DLP protocol firewall applied: {Channels}; rules: {Count}. WHOLE protocol port blocked, NOT per-file.",
                string.Join(",", blocked.Order()), specs.Count);
            if (!string.IsNullOrWhiteSpace(output)) _logger.LogInformation("Firewall: {Output}", output);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            _logger.LogError(e, "Protocol firewall update failed; verify Windows Firewall service and administrator privileges");
        }
    }

    private static string Q(string input) => input.Replace("'", "''");
}
