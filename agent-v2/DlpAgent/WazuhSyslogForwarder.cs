using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DlpAgent;

/// <summary>
/// Optional, best-effort TCP syslog forwarding of events already accepted by the DLP Server.
/// Wazuh Manager 4.x must explicitly listen for TCP syslog on the configured port.
/// </summary>
internal sealed class WazuhSyslogForwarder(ILogger logger)
{
    private readonly object _gate = new();
    private IPEndPoint? _destination;

    internal void Configure(JsonElement policy)
    {
        IPEndPoint? next = null;
        if (policy.TryGetProperty("wazuh", out var wazuh) && wazuh.ValueKind == JsonValueKind.Object &&
            wazuh.TryGetProperty("ip", out var ipNode) && wazuh.TryGetProperty("port", out var portNode) &&
            IPAddress.TryParse(ipNode.GetString(), out var address) &&
            portNode.TryGetInt32(out var port) && port is >= 1 and <= 65535)
            next = new IPEndPoint(address, port);
        lock (_gate) _destination = next;
        logger.LogInformation("Wazuh TCP syslog: {State}", next is null ? "disabled" : "configured");
    }

    internal async Task ForwardAsync(string eventJson, string hostname, CancellationToken ct)
    {
        IPEndPoint? target;
        lock (_gate) target = _destination;
        if (target is null) return;
        try
        {
            using var parsed = JsonDocument.Parse(eventJson);
            var root = parsed.RootElement;
            // Limit to explicit metadata. Never forward file contents, enrollment keys or API tokens.
            var record = new
            {
                integration = "DLPAgent",
                hostname,
                policy_id = ReadInt(root, "policy_id"),
                exit_point_type = ReadString(root, "exit_point_type"),
                action_taken = ReadString(root, "action_taken"),
                file_path = ReadString(root, "file_path"),
                destination_value = ReadString(root, "destination_value"),
                process_name = ReadString(root, "process_name"),
                matched_rule_ids = root.TryGetProperty("matched_rule_ids", out var ids) && ids.ValueKind == JsonValueKind.Array
                    ? ids.EnumerateArray().Select(x => x.GetInt32()).Take(30).ToArray() : Array.Empty<int>(),
                occurred_at = ReadString(root, "occurred_at")
            };
            var json = JsonSerializer.Serialize(record);
            // RFC3164-style syslog header with JSON message, TCP newline framing.
            var safeHost = new string(hostname.Where(c => char.IsLetterOrDigit(c) || c is '-' or '.').Take(80).ToArray());
            if (safeHost.Length == 0) safeHost = "dlp-endpoint";
            var timestamp = DateTimeOffset.Now.ToString("MMM dd HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
            var bytes = Encoding.UTF8.GetBytes($"<134>{timestamp} {safeHost} DLPAgent: {json}\n");
            if (bytes.Length > 4096) throw new InvalidDataException("Syslog event exceeds safe size");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            using var socket = new TcpClient(target.AddressFamily);
            await socket.ConnectAsync(target.Address, target.Port, timeout.Token);
            await socket.GetStream().WriteAsync(bytes, timeout.Token);
            logger.LogInformation("Wazuh syslog event forwarded to {Endpoint}", target);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Could not forward DLP event to Wazuh syslog; primary Server reporting unchanged");
        }
    }

    private static string? ReadString(JsonElement value, string key) =>
        value.TryGetProperty(key, out var node) && node.ValueKind == JsonValueKind.String ? node.GetString() : null;

    private static int? ReadInt(JsonElement value, string key) =>
        value.TryGetProperty(key, out var node) && node.ValueKind == JsonValueKind.Number && node.TryGetInt32(out var n) ? n : null;
}
