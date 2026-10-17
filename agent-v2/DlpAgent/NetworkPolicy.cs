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
    private readonly Dictionary<string, DateTimeOffset> _recent = new();
    private readonly object _recentLock = new();
    private volatile string _rules = "{\"updated\":false,\"web\":[],\"scp\":[],\"ftp\":[]}";
    internal NetworkPolicy(ILogger logger, Func<int, string, string, string, CancellationToken, Task> report)
    {
        _logger = logger;
        _report = report;
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

    public void Dispose()
    {
        _shutdown?.Cancel();
        if (_listener.IsListening) _listener.Stop();
        _listener.Close();
        _shutdown?.Dispose();
    }
}
