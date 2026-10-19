using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using System.Text.Json;

namespace DlpAgent;

// Watches Windows Security / WFP Event 5157 after Windows audit policy has been enabled.
// This proves a network connection was denied; it does not identify file names, nor
// distinguish scp from sftp when both use ssh.exe as their underlying transport.
internal sealed class ProtocolEventMonitor
{
    private readonly ILogger _logger;
    private readonly List<Rule> _rules = new();
    private long _lastRecordId;
    private bool _initialized;
    private DateTimeOffset _nextPoll = DateTimeOffset.MinValue;
    private bool _warnedAudit;
    private record Rule(int PolicyId, string ExitPoint, string Process, int Port);

    internal ProtocolEventMonitor(ILogger logger) => _logger = logger;

    internal void UpdatePolicy(string body)
    {
        using var doc = JsonDocument.Parse(body);
        var next = new List<Rule>();
        foreach (var policy in doc.RootElement.GetProperty("applicable_policies").EnumerateArray())
        {
            if (policy.GetProperty("action").GetString() != "BLOCK") continue;
            var id = policy.GetProperty("policy_id").GetInt32();
            if (!policy.TryGetProperty("exit_points", out var points) || points.ValueKind != JsonValueKind.Array) continue;
            foreach (var point in points.EnumerateArray())
            {
                switch (point.GetString())
                {
                    case "NETWORK_SCP_SFTP":
                        next.Add(new(id, "NETWORK_SCP_SFTP", "ssh.exe", 22));
                        next.Add(new(id, "NETWORK_SCP_SFTP", "scp.exe", 22));
                        next.Add(new(id, "NETWORK_SCP_SFTP", "sftp.exe", 22));
                        break;
                    case "CLIENT_SCP":
                        next.Add(new(id, "CLIENT_SCP", "ssh.exe", 22));
                        next.Add(new(id, "CLIENT_SCP", "scp.exe", 22));
                        break;
                    case "CLIENT_SFTP":
                        next.Add(new(id, "CLIENT_SFTP", "ssh.exe", 22));
                        next.Add(new(id, "CLIENT_SFTP", "sftp.exe", 22));
                        next.Add(new(id, "CLIENT_SFTP", "curl.exe", 22));
                        break;
                    case "NETWORK_FTP":
                    case "CLIENT_FTP":
                        next.Add(new(id, point.GetString()!, "ftp.exe", 21));
                        next.Add(new(id, point.GetString()!, "curl.exe", 21));
                        break;
                }
            }
        }
        _rules.Clear();
        _rules.AddRange(next.Distinct());
    }

    internal async Task PollAsync(Func<int, string, string, string, CancellationToken, Task> report, CancellationToken ct)
    {
        if (DateTimeOffset.UtcNow < _nextPoll) return;
        _nextPoll = DateTimeOffset.UtcNow.AddSeconds(5);
        try
        {
            // Time window keeps Security log queries bounded; RecordId avoids duplicates.
            var query = new EventLogQuery("Security", PathType.LogName,
                "*[System[(EventID=5157) and TimeCreated[timediff(@SystemTime) <= 120000]]]")
            {
                ReverseDirection = true
            };
            using var reader = new EventLogReader(query);
            var found = new List<(long Id, string Application, string Dest, int Port)>();
            long maximum = _lastRecordId;
            for (var i = 0; i < 200; i++)
            {
                ct.ThrowIfCancellationRequested();
                using var entry = reader.ReadEvent();
                if (entry is null) break;
                var recordId = entry.RecordId ?? 0;
                maximum = Math.Max(maximum, recordId);
                if (_initialized && recordId <= _lastRecordId) break;
                var xml = XElement.Parse(entry.ToXml());
                XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
                var fields = xml.Descendants(ns + "Data")
                    .Where(e => e.Attribute("Name") is not null)
                    .GroupBy(e => (string)e.Attribute("Name")!)
                    .ToDictionary(g => g.Key, g => g.First().Value, StringComparer.OrdinalIgnoreCase);
                if (!fields.TryGetValue("Application", out var application) ||
                    !fields.TryGetValue("DestAddress", out var destination) ||
                    !fields.TryGetValue("DestPort", out var portText) ||
                    !int.TryParse(portText, out var port)) continue;
                found.Add((recordId, application, destination, port));
            }

            // At service startup, do not re-report arbitrary historical audit events.
            if (!_initialized)
            {
                _initialized = true;
                _lastRecordId = maximum;
                _logger.LogInformation("Protocol event monitor initialized at Security record {RecordId}", maximum);
                return;
            }

            foreach (var ev in found.OrderBy(x => x.Id))
            {
                var process = Path.GetFileName(ev.Application);
                var matching = _rules.FirstOrDefault(r =>
                    r.Port == ev.Port && r.Process.Equals(process, StringComparison.OrdinalIgnoreCase));
                if (matching is null) continue;
                await report(matching.PolicyId, matching.ExitPoint, process, ev.Dest + ":" + ev.Port, ct);
            }
            _lastRecordId = maximum;
        }
        catch (EventLogException ex)
        {
            if (!_warnedAudit)
            {
                _warnedAudit = true;
                _logger.LogWarning(ex, "Cannot read Security WFP 5157 events; check LocalSystem access and enable Windows Filtering Platform Connection failure auditing");
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Protocol audit collection failed; retrying");
        }
    }
}
