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
    private volatile string _rules = "{\"updated\":false,\"web\":[],\"scp\":[],\"ftp\":[]}";
    internal NetworkPolicy(ILogger logger) { _logger = logger; }

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
                if (request.HttpMethod != "GET" || request.Url?.AbsolutePath != "/rules")
                {
                    response.StatusCode = 404;
                }
                else
                {
                    response.ContentType = "application/json; charset=utf-8";
                    var bytes = Encoding.UTF8.GetBytes(_rules);
                    response.ContentLength64 = bytes.Length;
                    await response.OutputStream.WriteAsync(bytes, ct);
                }
                response.Close();
            }
            catch (Exception e) { _logger.LogDebug(e, "Policy bridge request failed"); }
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
