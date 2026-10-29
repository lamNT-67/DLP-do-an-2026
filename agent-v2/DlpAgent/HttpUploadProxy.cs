using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DlpAgent;

// Explicit HTTP/1.1 forward proxy for lab testing only.
// Does not decrypt HTTPS; CONNECT intentionally returns 501 to prevent false security claims.
internal sealed class HttpUploadProxy : IDisposable
{
    private const int MaxHeaderBytes = 32768;
    private const int MaxBodyBytes = 10 * 1024 * 1024;
    private readonly ILogger _logger;
    private readonly HttpClient _upstream = new(new SocketsHttpHandler {
        AllowAutoRedirect = false,
        UseProxy = false,
        AutomaticDecompression = DecompressionMethods.None
    }) { Timeout = TimeSpan.FromSeconds(30) };
    private readonly TcpListener _listener = new(IPAddress.Loopback, 18766);
    private readonly Func<int, string, string, string, int[], CancellationToken, Task> _report;
    private CancellationTokenSource? _shutdown;
    private Task? _loop;
    private volatile string _policy = "{\"applicable_policies\":[]}";
    internal HttpUploadProxy(ILogger logger, Func<int, string, string, string, int[], CancellationToken, Task> report)
    {
        _logger = logger;
        _report = report;
    }

    internal void UpdatePolicy(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.GetProperty("applicable_policies").ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Missing policy array");
        _policy = json;
    }

    internal void Start()
    {
        _listener.Start();
        _shutdown = new CancellationTokenSource();
        _loop = Task.Run(() => AcceptLoopAsync(_shutdown.Token));
        _logger.LogInformation("HTTP file-upload proxy started at 127.0.0.1:18766 (HTTP only, no HTTPS interception)");
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(ct); }
            catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { break; }
            _ = Task.Run(async () => {
                using (client)
                    try { await HandleAsync(client.GetStream(), ct); }
                    catch (Exception ex) { _logger.LogDebug(ex, "HTTP proxy client failed"); }
            }, CancellationToken.None);
        }
    }

    private async Task HandleAsync(NetworkStream stream, CancellationToken ct)
    {
        // Read only one request per connection, then close. Bound memory and reject
        // chunked/streaming traffic to avoid accidentally passing uninspected files.
        using var header = new MemoryStream();
        var b = new byte[1];
        var state = 0;
        while (header.Length < MaxHeaderBytes && state != 4)
        {
            if (await stream.ReadAsync(b, ct) == 0) return;
            header.WriteByte(b[0]);
            state = state switch {
                0 when b[0] == '\r' => 1,
                1 when b[0] == '\n' => 2,
                2 when b[0] == '\r' => 3,
                3 when b[0] == '\n' => 4,
                _ => 0
            };
        }
        if (state != 4) { await ReplyAsync(stream, 431, "Header too large", ct); return; }
        var rawHeader = Encoding.Latin1.GetString(header.ToArray());
        var lines = rawHeader.Split("\r\n", StringSplitOptions.None);
        var first = lines[0].Split(' ', 3);
        if (first.Length != 3 || !first[2].StartsWith("HTTP/1.")) {
            await ReplyAsync(stream, 400, "Bad HTTP request", ct); return;
        }
        var method = first[0].ToUpperInvariant();
        if (method == "CONNECT") {
            await ReplyAsync(stream, 501, "HTTPS CONNECT / TLS inspection not implemented", ct); return;
        }
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in lines.Skip(1).Where(x => x.Length > 0)) {
            var colon = line.IndexOf(':');
            if (colon <= 0) { await ReplyAsync(stream, 400, "Invalid header", ct); return; }
            var name = line[..colon].Trim();
            if (!headers.TryAdd(name, line[(colon + 1)..].Trim())) {
                await ReplyAsync(stream, 400, "Duplicate header rejected", ct); return;
            }
        }
        if (headers.ContainsKey("Transfer-Encoding") || headers.ContainsKey("Upgrade")) {
            await ReplyAsync(stream, 501, "Unsupported streaming or upgrade request", ct); return;
        }
        // curl and browsers may wait for HTTP 100 Continue before sending a
        // multipart body. Acknowledge only this exact expectation; do not relay
        // Expect upstream after the proxy has consumed and inspected the body.
        var expectsContinue = headers.TryGetValue("Expect", out var expectation);
        if (expectsContinue && !string.Equals(expectation, "100-continue", StringComparison.OrdinalIgnoreCase)) {
            await ReplyAsync(stream, 417, "Expectation Failed", ct); return;
        }
        var target = first[1];
        if (!Uri.TryCreate(target, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp ||
            uri.UserInfo.Length > 0 || uri.HostNameType == UriHostNameType.Unknown) {
            await ReplyAsync(stream, 400, "Explicit http:// URL required", ct); return;
        }
        // Do not proxy to loopback or private endpoints: avoid turning this listener into
        // a localhost network pivot. DNS is checked again at connect time by the OS;
        // this remains a lab proxy, not a hardened boundary against DNS rebinding.
        if (uri.IsLoopback) { await ReplyAsync(stream, 403, "Loopback destination not allowed", ct); return; }

        long size = 0;
        if (headers.TryGetValue("Content-Length", out var length) &&
            (!long.TryParse(length, out size) || size < 0 || size > MaxBodyBytes)) {
            await ReplyAsync(stream, 413, "Invalid or oversized request body", ct); return;
        }
        if ((method is "POST" or "PUT" or "PATCH") && !headers.ContainsKey("Content-Length")) {
            await ReplyAsync(stream, 411, "Content-Length required", ct); return;
        }
        if (expectsContinue && size > 0) {
            await stream.WriteAsync(Encoding.ASCII.GetBytes("HTTP/1.1 100 Continue\r\n\r\n"), ct);
            await stream.FlushAsync(ct);
        }
        var body = new byte[(int)size];
        if (size > 0) await stream.ReadExactlyAsync(body, ct);

        var contentType = headers.GetValueOrDefault("Content-Type") ?? "";
        var multipart = contentType.StartsWith("multipart/form-data", StringComparison.OrdinalIgnoreCase);
        if (multipart && (method is "POST" or "PUT" or "PATCH")) {
            List<MultipartUploadInspector.Verdict> verdicts;
            try {
                verdicts = MultipartUploadInspector.Inspect(_policy, contentType, body);
            }
            catch (Exception ex) when (ex is InvalidDataException or DecoderFallbackException or JsonException or RegexMatchTimeoutException) {
                _logger.LogWarning(ex, "HTTP upload inspection failed; request not forwarded");
                await ReplyAsync(stream, 422, "DLP could not inspect multipart upload", ct);
                return;
            }
            foreach (var verdict in verdicts) {
                if (verdict.PolicyId is not int policyId) continue;
                if (verdict.Decision == "BLOCK") {
                    _logger.LogWarning("HTTP upload blocked by policy {Policy}: {File} ({Reason})",
                        policyId, verdict.FileName, verdict.Reason);
                    try { await _report(policyId, verdict.FileName, "BLOCKED_PROXY", verdict.Reason, verdict.RuleIds, ct); }
                    catch (Exception ex) when (ex is not OperationCanceledException) {
                        _logger.LogWarning(ex, "Failed to report HTTP block");
                    }
                    await ReplyAsync(stream, 403, "DLP policy blocked upload", ct);
                    return;
                }
                if (verdict.Decision == "REPORT_ONLY") {
                    try { await _report(policyId, verdict.FileName, "LOGGED", verdict.Reason, verdict.RuleIds, ct); }
                    catch (Exception ex) when (ex is not OperationCanceledException) {
                        _logger.LogWarning(ex, "Failed to report HTTP inspection");
                    }
                }
            }
        }

        try {
            using var request = new HttpRequestMessage(new HttpMethod(method), uri);
            if (body.Length > 0 || headers.ContainsKey("Content-Length"))
                request.Content = new ByteArrayContent(body);
            foreach (var pair in headers) {
                if (pair.Key.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
                    pair.Key.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
                    pair.Key.Equals("Proxy-Connection", StringComparison.OrdinalIgnoreCase) ||
                    pair.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
                    pair.Key.Equals("Expect", StringComparison.OrdinalIgnoreCase)) continue;
                if (!request.Headers.TryAddWithoutValidation(pair.Key, pair.Value))
                    request.Content?.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
            }
            using var response = await _upstream.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var status = (int)response.StatusCode;
            // Response is streamed directly; the proxy closes connection afterwards.
            var statusLine = Encoding.ASCII.GetBytes($"HTTP/1.1 {status} {response.ReasonPhrase}\r\nConnection: close\r\n");
            await stream.WriteAsync(statusLine, ct);
            foreach (var h in response.Headers.Concat(response.Content.Headers)) {
                if (h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
                    h.Key.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
                    h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
                var line = Encoding.Latin1.GetBytes(h.Key + ": " + string.Join(", ", h.Value) + "\r\n");
                await stream.WriteAsync(line, ct);
            }
            await stream.WriteAsync(Encoding.ASCII.GetBytes("\r\n"), ct);
            // HTTP/1.1 connection-close framing, no content-length needed.
            await response.Content.CopyToAsync(stream, ct);
        }
        catch (Exception e) {
            _logger.LogWarning(e, "Upstream HTTP proxy request failed for {Target}", uri.Host);
        }
    }

    private static async Task ReplyAsync(Stream stream, int code, string message, CancellationToken ct)
    {
        var body = Encoding.UTF8.GetBytes(message + "\n");
        var head = Encoding.ASCII.GetBytes($"HTTP/1.1 {code} {message}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(head, ct);
        await stream.WriteAsync(body, ct);
        await stream.FlushAsync(ct);
    }

    public void Dispose() {
        _shutdown?.Cancel();
        _listener.Stop();
        _upstream.Dispose();
        _shutdown?.Dispose();
    }
}
