using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DlpAgent;

// Read-only endpoint for browser extensions; never binds to a non-loopback address.
// It deliberately exposes only file extensions and decisions, not tokens or policy secrets.
internal sealed class NetworkPolicy : IDisposable
{
    private readonly ILogger _logger;
    private readonly HttpListener _listener = new();
    private CancellationTokenSource? _shutdown;
    private Task? _loop;
    private readonly Func<int, string, string, string, CancellationToken, Task> _report;
    private readonly Func<int, string, string, string, string, int[], CancellationToken, Task> _transferReport;
    private readonly Dictionary<string, DateTimeOffset> _recent = new();
    private readonly object _recentLock = new();
    private volatile string _inspectionPolicy = @"{""applicable_policies"":[]}";
    private volatile string _rules = "{\"updated\":false,\"web\":[],\"scp\":[],\"ftp\":[]}";
    internal NetworkPolicy(ILogger logger, Func<int, string, string, string, CancellationToken, Task> report,
        Func<int, string, string, string, string, int[], CancellationToken, Task> transferReport)
    {
        _logger = logger;
        _report = report;
        _transferReport = transferReport;
    }

    internal void Update(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var buckets = new Dictionary<string, List<object>> {
            ["web"] = [], ["chrome"] = [], ["edge"] = [], ["firefox"] = [],
            ["scp"] = [], ["sftp"] = [], ["ftp"] = [], ["winscp"] = [], ["filezilla"] = []
        };
        foreach (var policy in doc.RootElement.GetProperty("applicable_policies").EnumerateArray())
        {
            if (!policy.TryGetProperty("exit_points", out var exitPoints) || exitPoints.ValueKind != JsonValueKind.Array) continue;
            var points = exitPoints.EnumerateArray().Select(x => x.GetString()).ToHashSet();
            var action = policy.GetProperty("action").GetString();
            if (action is not ("BLOCK" or "REPORT_ONLY")) continue;
            if (!policy.TryGetProperty("file_types", out var fileTypes) || fileTypes.ValueKind != JsonValueKind.Array) continue;
            var extensions = fileTypes.EnumerateArray()
                .Where(x => x.TryGetProperty("extension", out var e) && e.ValueKind == JsonValueKind.String)
                .Select(x => x.GetProperty("extension").GetString()?.TrimStart('.').ToLowerInvariant())
                .Where(x => !string.IsNullOrEmpty(x)).Distinct().ToArray();
            var id = policy.GetProperty("policy_id").GetInt32();
            var rule = new { policy_id = id, action, extensions };
            if (points.Contains("NETWORK_WEB")) {
                buckets["web"].Add(rule);
                buckets["chrome"].Add(rule); buckets["edge"].Add(rule); buckets["firefox"].Add(rule);
            }
            if (points.Contains("BROWSER_CHROME")) buckets["chrome"].Add(rule);
            if (points.Contains("BROWSER_EDGE")) buckets["edge"].Add(rule);
            if (points.Contains("BROWSER_FIREFOX")) buckets["firefox"].Add(rule);
            if (points.Contains("NETWORK_SCP_SFTP")) {
                buckets["scp"].Add(rule); buckets["sftp"].Add(rule); buckets["winscp"].Add(rule);
            }
            if (points.Contains("CLIENT_SCP")) buckets["scp"].Add(rule);
            if (points.Contains("CLIENT_SFTP")) buckets["sftp"].Add(rule);
            if (points.Contains("CLIENT_WINSCP")) buckets["winscp"].Add(rule);
            if (points.Contains("NETWORK_FTP")) {
                buckets["ftp"].Add(rule); buckets["filezilla"].Add(rule);
            }
            if (points.Contains("CLIENT_FTP")) buckets["ftp"].Add(rule);
            if (points.Contains("CLIENT_FILEZILLA")) buckets["filezilla"].Add(rule);
        }
        // Local controlled-transfer inspection requires content rules; do not publish these on /rules.
        _inspectionPolicy = JsonSerializer.Serialize(new
        {
            applicable_policies = doc.RootElement.GetProperty("applicable_policies").EnumerateArray().Select(p => new
            {
                policy_id = p.GetProperty("policy_id").GetInt32(),
                action = p.GetProperty("action").GetString(),
                exit_points = p.GetProperty("exit_points").EnumerateArray().Select(x => x.GetString()).ToArray(),
                file_types = p.GetProperty("file_types").EnumerateArray().Select(x => new { extension = x.GetProperty("extension").GetString() }).ToArray(),
                content_rules = p.TryGetProperty("content_rules", out var contentRules) && contentRules.ValueKind == JsonValueKind.Array
                    ? contentRules.EnumerateArray().Select(cr => new {
                        id = cr.GetProperty("id").GetInt32(),
                        rule_type = cr.GetProperty("rule_type").GetString(),
                        pattern = cr.GetProperty("pattern").GetString()
                    }).ToArray() : Array.Empty<object>(),
                allowed_files = p.TryGetProperty("allowed_files", out var allowedFiles) ? allowedFiles.EnumerateArray().Select(x => x.GetString()).ToArray() : Array.Empty<string>(),
                allowed_locations = p.TryGetProperty("allowed_locations", out var allowedLocations) ? allowedLocations.EnumerateArray().Select(x => x.GetString()).ToArray() : Array.Empty<string>()
            }).ToArray()
        });
        _rules = JsonSerializer.Serialize(new {
            updated = true,
            web = buckets["web"],
            chrome = buckets["chrome"], edge = buckets["edge"], firefox = buckets["firefox"],
            scp = buckets["scp"], sftp = buckets["sftp"], ftp = buckets["ftp"],
            winscp = buckets["winscp"], filezilla = buckets["filezilla"]
        });
    }

    internal void Start()
    {
        _listener.Prefixes.Add("http://127.0.0.1:18765/");
        _listener.Start();
        _shutdown = new CancellationTokenSource();
        _loop = Task.Run(() => LoopAsync(_shutdown.Token));
        _logger.LogInformation("Browser policy bridge listening on 127.0.0.1:18765");
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            HttpListenerContext context;
            try { context = await _listener.GetContextAsync().WaitAsync(ct); }
            catch (Exception e) when (e is OperationCanceledException or HttpListenerException or ObjectDisposedException) { break; }
            try
            {
                var request = context.Request;
                var response = context.Response;
                response.Headers.Add("Cache-Control", "no-store");
                response.Headers.Add("X-Content-Type-Options", "nosniff");
                // Requests from extension background scripts are allowed; web pages
                // cannot read this endpoint through CORS. No write endpoints exist.
                if (request.HttpMethod == "GET" && request.Url?.AbsolutePath == "/rules")
                {
                    response.ContentType = "application/json; charset=utf-8";
                    var bytes = Encoding.UTF8.GetBytes(_rules);
                    response.ContentLength64 = bytes.Length;
                    await response.OutputStream.WriteAsync(bytes, ct);
                }
                else if (request.HttpMethod == "GET" && request.Url?.AbsolutePath == "/inspection-policy" &&
                         request.Headers["X-DLP-Client"] == "ManagedTransfer")
                {
                    // Lab-only managed-transfer policy endpoint; includes content rule patterns.
                    // Header is not an authentication boundary; this is a lab integration.
                    response.ContentType = "application/json; charset=utf-8";
                    var data = Encoding.UTF8.GetBytes(_inspectionPolicy);
                    response.ContentLength64 = data.Length;
                    await response.OutputStream.WriteAsync(data, ct);
                }
                else if (request.HttpMethod == "POST" && request.Url?.AbsolutePath == "/inspect-content")
                {
                    await InspectBrowserContentAsync(context, ct);
                }
                else if (request.HttpMethod == "POST" && request.Url?.AbsolutePath == "/transfer-event")
                {
                    await ReceiveTransferEventAsync(context, ct);
                }
                else if (request.HttpMethod == "POST" && request.Url?.AbsolutePath == "/event")
                {
                    await ReceiveEventAsync(context, ct);
                }
                else response.StatusCode = 404;
                response.Close();
            }
            catch (Exception e) { _logger.LogDebug(e, "Policy bridge request failed"); }
        }
    }

    // Lab-only endpoint. Origin/header restrictions are not an authentication boundary.
    // Accepts up to 2 MiB of file bytes, base64 encoded in JSON.
    private async Task InspectBrowserContentAsync(HttpListenerContext context, CancellationToken ct)
    {
        var request = context.Request;
        var response = context.Response;
        var origin = request.Headers["Origin"] ?? "";
        if ((!origin.StartsWith("chrome-extension://", StringComparison.Ordinal) &&
             !origin.StartsWith("moz-extension://", StringComparison.Ordinal)) ||
            request.Headers["X-DLP-Client"] != "BrowserContent" ||
            request.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) != true)
        {
            response.StatusCode = 403;
            return;
        }
        const int maxRequestBytes = 2_900_000;
        if (request.ContentLength64 > maxRequestBytes)
        {
            response.StatusCode = 413;
            return;
        }
        try
        {
            using var incoming = new MemoryStream();
            var buffer = new byte[8192];
            int count;
            while ((count = await request.InputStream.ReadAsync(buffer.AsMemory(), ct)) > 0)
            {
                if (incoming.Length + count > maxRequestBytes)
                {
                    response.StatusCode = 413;
                    return;
                }
                incoming.Write(buffer, 0, count);
            }
            using var doc = JsonDocument.Parse(incoming.ToArray());
            var data = doc.RootElement;
            var channel = data.GetProperty("channel").GetString() ?? "";
            var fileName = data.GetProperty("file_name").GetString() ?? "";
            var b64 = data.GetProperty("content_base64").GetString() ?? "";
            if (channel is not ("chrome" or "edge" or "firefox") ||
                b64.Length > 2_800_000 || b64.Length == 0)
            {
                response.StatusCode = 400;
                return;
            }
            var bytes = Convert.FromBase64String(b64);
            var result = ContentInspectionEngine.CheckBytes(_inspectionPolicy,
                "BROWSER_" + channel.ToUpperInvariant(), fileName, bytes);
            using var verdictDoc = JsonDocument.Parse(JsonSerializer.Serialize(result));
            var verdict = verdictDoc.RootElement;
            var decision = verdict.GetProperty("decision").GetString();
            var policyId = verdict.GetProperty("policy_id");
            if (decision == "BLOCK" && policyId.ValueKind == JsonValueKind.Number)
            {
                try {
                    // A confirmed local inspection verdict; the page-side guard still needs to enforce it.
                    await _report(policyId.GetInt32(), channel, fileName,
                        request.Headers["X-DLP-Destination"] ?? "", ct);
                }
                catch (Exception ex) when (ex is not OperationCanceledException) {
                    _logger.LogWarning(ex, "Content inspection block log not delivered");
                }
            }
            var responseBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(result));
            response.ContentType = "application/json; charset=utf-8";
            response.ContentLength64 = responseBytes.Length;
            await response.OutputStream.WriteAsync(responseBytes, ct);
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException or ArgumentException or DecoderFallbackException)
        {
            _logger.LogWarning(ex, "Browser content inspection rejected");
            response.StatusCode = 422; // Background treats errors as DENY.
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Browser content inspection unavailable");
            response.StatusCode = 503;
        }
    }

    private async Task ReceiveEventAsync(HttpListenerContext context, CancellationToken ct)
    {
        var request = context.Request;
        var response = context.Response;
        // Extension-origin check reduces cross-site request forgery from normal pages.
        // Browser extensions and other processes on this host are not a strong trust boundary.
        var origin = request.Headers["Origin"] ?? "";
        if (!origin.StartsWith("chrome-extension://", StringComparison.Ordinal) &&
            !origin.StartsWith("moz-extension://", StringComparison.Ordinal))
        {
            response.StatusCode = 403;
            return;
        }
        if (request.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) != true ||
            request.ContentLength64 > 4096)
        {
            response.StatusCode = 400;
            return;
        }
        try
        {
            // Extension fetch may send chunked JSON without Content-Length.
            // Enforce the same 4 KiB cap while reading, regardless of framing.
            using var incoming = new MemoryStream();
            var buffer = new byte[1024];
            while (true)
            {
                var n = await request.InputStream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, 4097 - (int)incoming.Length)), ct);
                if (n == 0) break;
                incoming.Write(buffer, 0, n);
                if (incoming.Length > 4096) { response.StatusCode = 413; return; }
            }
            var body = Encoding.UTF8.GetString(incoming.ToArray());
            using var doc = JsonDocument.Parse(body);
            var node = doc.RootElement;
            var channel = node.GetProperty("channel").GetString() ?? "";
            var fileName = node.GetProperty("file_name").GetString() ?? "";
            var destination = node.GetProperty("destination").GetString() ?? "";
            var policyId = node.GetProperty("policy_id").GetInt32();
            var field = channel switch { "chrome" => "chrome", "edge" => "edge", "firefox" => "firefox", _ => "" };
            if (field == "" || fileName.Length is < 1 or > 240 || destination.Length > 255 ||
                fileName.Contains('/') || fileName.Contains('\\'))
            {
                response.StatusCode = 400;
                return;
            }
            // Validate reported policy + extension against latest server rules.
            // Do not blindly trust an event generated by untrusted browser JavaScript.
            var extension = Path.GetExtension(fileName).TrimStart('.');
            using var rules = JsonDocument.Parse(_rules);
            if (!rules.RootElement.TryGetProperty(field, out var policies) ||
                !policies.EnumerateArray().Any(p =>
                    p.GetProperty("policy_id").GetInt32() == policyId &&
                    p.GetProperty("action").GetString() == "BLOCK" &&
                    p.GetProperty("extensions").EnumerateArray().Any(e =>
                        string.Equals(e.GetString(), extension, StringComparison.OrdinalIgnoreCase))))
            {
                response.StatusCode = 409;
                return;
            }
            // Prevent double reports from the file-input and page-world hooks.
            var key = field + "|" + policyId + "|" + fileName + "|" + destination;
            lock (_recentLock)
            {
                var now = DateTimeOffset.UtcNow;
                if (_recent.TryGetValue(key, out var last) && now - last < TimeSpan.FromSeconds(3))
                {
                    response.StatusCode = 202;
                    return;
                }
                _recent[key] = now;
                if (_recent.Count > 512)
                    foreach (var stale in _recent.Where(p => now - p.Value > TimeSpan.FromMinutes(2)).Select(p => p.Key).ToArray())
                        _recent.Remove(stale);
            }
            await _report(policyId, channel, fileName, destination, ct);
            _logger.LogInformation("Browser DLP report received: {Browser} {File} policy={Policy}", field, fileName, policyId);
            response.StatusCode = 202;
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
        {
            response.StatusCode = 400;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Could not forward browser DLP event to server");
            response.StatusCode = 502;
        }
    }

    private async Task ReceiveTransferEventAsync(HttpListenerContext context, CancellationToken ct)
    {
        var req = context.Request;
        var response = context.Response;
        // Local managed launcher, not browser JavaScript. Only loopback + no Origin;
        // this is a lab integration, NOT a tamper-proof source of evidence.
        if (req.Headers["Origin"] is not null || req.Headers["X-DLP-Client"] != "ManagedTransfer")
        {
            response.StatusCode = 403;
            return;
        }
        if (req.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) != true ||
            req.ContentLength64 is < 2 or > 4096)
        {
            response.StatusCode = 400;
            return;
        }
        try
        {
            using var reader = new StreamReader(req.InputStream, Encoding.UTF8, leaveOpen: true);
            var body = await reader.ReadToEndAsync(ct);
            if (body.Length > 4096) { response.StatusCode = 413; return; }
            using var doc = JsonDocument.Parse(body);
            var data = doc.RootElement;
            var channel = data.GetProperty("channel").GetString()?.ToUpperInvariant() ?? "";
            var policyId = data.GetProperty("policy_id").GetInt32();
            var action = data.GetProperty("action").GetString() ?? "";
            var fileName = data.GetProperty("file_name").GetString() ?? "";
            var destination = data.GetProperty("destination").GetString() ?? "";
            var matchedIds = data.GetProperty("matched_rule_ids").EnumerateArray().Select(x => x.GetInt32()).ToArray();
            if (channel is not ("SCP" or "SFTP" or "FTP") ||
                action is not ("BLOCK" or "REPORT_ONLY") ||
                fileName.Length is < 1 or > 240 || fileName.Contains('/') || fileName.Contains('\\') ||
                destination.Length > 255 || matchedIds.Length > 30)
            {
                response.StatusCode = 400;
                return;
            }
            using var p = JsonDocument.Parse(_inspectionPolicy);
            var relevant = channel switch
            {
                "SCP" => new[] { "CLIENT_SCP", "NETWORK_SCP_SFTP" },
                "SFTP" => new[] { "CLIENT_SFTP", "NETWORK_SCP_SFTP" },
                _ => new[] { "CLIENT_FTP", "NETWORK_FTP" }
            };
            // Validate the policy ID, channel and decision against the last policy snapshot.
            var match = p.RootElement.GetProperty("applicable_policies").EnumerateArray().Any(pol =>
                pol.GetProperty("policy_id").GetInt32() == policyId &&
                pol.GetProperty("action").GetString() == action &&
                pol.GetProperty("exit_points").EnumerateArray().Any(ep => relevant.Contains(ep.GetString())) &&
                (pol.GetProperty("file_types").EnumerateArray().Any(ft =>
                    string.Equals(ft.GetProperty("extension").GetString()?.TrimStart('.'),
                        Path.GetExtension(fileName).TrimStart('.'), StringComparison.OrdinalIgnoreCase)) ||
                 (matchedIds.Length > 0 && pol.TryGetProperty("content_rules", out var contentRules) &&
                  contentRules.ValueKind == JsonValueKind.Array &&
                  matchedIds.All(id => contentRules.EnumerateArray().Any(cr =>
                      cr.GetProperty("id").GetInt32() == id)))));
            if (!match) { response.StatusCode = 409; return; }
            await _transferReport(policyId, channel, action, fileName, destination, matchedIds, ct);
            response.StatusCode = 202;
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        {
            response.StatusCode = 400;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Transfer event could not be reported");
            response.StatusCode = 502;
        }
    }

    public void Dispose()
    {
        _shutdown?.Cancel();
        if (_listener.IsListening) _listener.Stop();
        _listener.Close();
        _shutdown?.Dispose();
    }
}
