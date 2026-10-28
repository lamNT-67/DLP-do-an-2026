using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace DlpAgent;

internal static class Program
{
    public static async Task Main(string[] args)
    {
        if (args.Length == 3 && args[0] == "--inspect-file")
        {
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                using var request = new HttpRequestMessage(HttpMethod.Get, "http://127.0.0.1:18765/inspection-policy");
                request.Headers.Add("X-DLP-Client", "ManagedTransfer");
                using var response = await client.SendAsync(request);
                response.EnsureSuccessStatusCode();
                var policy = await response.Content.ReadAsStringAsync();
                Console.WriteLine(JsonSerializer.Serialize(ContentInspectionEngine.Check(policy, args[1], args[2])));
                return;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("DLP inspection failed: " + e.Message);
                Environment.ExitCode = 4; // Managed launcher must fail closed.
                return;
            }
        }
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(options => options.ServiceName = "DLPAgent");
        builder.Services.AddHostedService<AgentWorker>();
        using var host = builder.Build();
        await host.RunAsync();
    }
}

internal sealed class AgentSettings
{
    [JsonPropertyName("server_url")] public string ServerUrl { get; set; } = "";
    [JsonPropertyName("hostname")] public string Hostname { get; set; } = Environment.MachineName;
    [JsonPropertyName("enrollment_key")] public string EnrollmentKey { get; set; } = "";
    [JsonPropertyName("heartbeat_seconds")] public int HeartbeatSeconds { get; set; } = 45;
    [JsonPropertyName("policy_refresh_seconds")] public int PolicyRefreshSeconds { get; set; } = 60;
    [JsonPropertyName("usb_monitor_enabled")] public bool UsbMonitorEnabled { get; set; } = true;
    [JsonPropertyName("usb_enforce_block")] public bool UsbEnforceBlock { get; set; } = false;
    [JsonPropertyName("http_proxy_enabled")] public bool HttpProxyEnabled { get; set; } = false;
    [JsonPropertyName("protocol_firewall_enabled")] public bool ProtocolFirewallEnabled { get; set; } = false;
}

internal sealed class AgentWorker(ILogger<AgentWorker> logger) : BackgroundService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true, WriteIndented = true };
    private static readonly string StateDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DLPAgent");
    private static readonly string ConfigPath = Path.Combine(StateDir, "agent.json");
    private static readonly string TokenPath = Path.Combine(StateDir, "token.dat");
    private static readonly string PolicyPath = Path.Combine(StateDir, "policy.json");
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private AgentSettings _settings = new();
    private string? _token;
    private UsbMonitor? _usb;
    private NetworkPolicy? _networkPolicy;
    private HttpUploadProxy? _httpProxy;
    private ProtocolFirewall? _protocolFirewall;
    private ProtocolEventMonitor? _protocolEventMonitor;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            if (!File.Exists(ConfigPath))
            {
                logger.LogError("Missing config: {Path}. Run installer first.", ConfigPath);
                return;
            }
            _settings = JsonSerializer.Deserialize<AgentSettings>(await File.ReadAllTextAsync(ConfigPath, stoppingToken), JsonOptions)
                ?? throw new InvalidOperationException("Invalid agent config");
            if (!Uri.TryCreate(_settings.ServerUrl.TrimEnd('/') + "/", UriKind.Absolute, out var baseUrl) ||
                (baseUrl.Scheme != Uri.UriSchemeHttp && baseUrl.Scheme != Uri.UriSchemeHttps))
                throw new InvalidOperationException("server_url must be an absolute http(s) URL pointing to /api");
            _http.BaseAddress = baseUrl;
            _settings.Hostname = _settings.Hostname.Trim();
            if (_settings.Hostname.Length == 0) throw new InvalidOperationException("hostname is empty");
            _settings.HeartbeatSeconds = Math.Clamp(_settings.HeartbeatSeconds, 10, 3600);
            _settings.PolicyRefreshSeconds = Math.Clamp(_settings.PolicyRefreshSeconds, 10, 3600);
            _token = LoadToken();
            logger.LogInformation("DLP Agent started for {Hostname}; server={Server}", _settings.Hostname, baseUrl);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "DLP Agent configuration error");
            return;
        }

        // Cached policy is retained for diagnostics; no enforcement until modules are implemented.
        if (File.Exists(PolicyPath))
            logger.LogInformation("Found cached policy at {Path}", PolicyPath);

        if (_settings.UsbMonitorEnabled)
        {
            _usb = new UsbMonitor(logger, _settings.UsbEnforceBlock);
            logger.LogWarning("USB monitor enabled. Actual deletion on BLOCK policies: {Enabled}", _settings.UsbEnforceBlock);
        }

        _networkPolicy = new NetworkPolicy(logger, ReportBrowserAsync, ReportTransferAsync);
        try { _networkPolicy.Start(); }
        catch (Exception ex) { logger.LogWarning(ex, "Browser policy bridge cannot start; USB/service can still run"); }

        if (_settings.HttpProxyEnabled)
        {
            _httpProxy = new HttpUploadProxy(logger, ReportHttpAsync);
            try { _httpProxy.Start(); }
            catch (Exception ex) { logger.LogWarning(ex, "HTTP proxy cannot start (port 18766?)"); }
        }

        if (_settings.ProtocolFirewallEnabled)
        {
            _protocolFirewall = new ProtocolFirewall(logger);
            _protocolEventMonitor = new ProtocolEventMonitor(logger);
            logger.LogWarning("PROTOCOL FIREWALL MODE ENABLED. Any matching BLOCK policy denies the entire client protocol on default ports; selected file_types do not restrict firewall rules.");
        }

        DateTimeOffset nextHeartbeat = DateTimeOffset.MinValue, nextPolicy = DateTimeOffset.MinValue;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (_token is null)
                {
                    if (!await RegisterAsync(stoppingToken))
                    {
                        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
                        continue;
                    }
                }
                _usb?.RefreshDrives();
                if (_usb is not null) await _usb.DrainAsync(ReportUsbAsync, stoppingToken);
                var now = DateTimeOffset.UtcNow;
                if (now >= nextHeartbeat)
                {
                    await HeartbeatAsync(stoppingToken);
                    nextHeartbeat = now.AddSeconds(_settings.HeartbeatSeconds);
                }
                if (now >= nextPolicy)
                {
                    await RefreshPolicyAsync(stoppingToken);
                    nextPolicy = now.AddSeconds(_settings.PolicyRefreshSeconds);
                }
                if (_protocolEventMonitor is not null)
                    await _protocolEventMonitor.PollAsync(ReportProtocolAsync, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { logger.LogWarning(ex, "Agent cycle failed; will retry"); }
            try { await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
        _httpProxy?.Dispose();
        _networkPolicy?.Dispose();
        _usb?.Dispose();
        _http.Dispose();
    }

    private string? LoadToken()
    {
        if (!File.Exists(TokenPath)) return null;
        try
        {
            var bytes = ProtectedData.Unprotect(File.ReadAllBytes(TokenPath), null, DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(bytes);
        }
        catch (CryptographicException ex)
        {
            logger.LogError(ex, "Unable to decrypt saved token; refusing automatic re-enrollment");
            // Prevent duplicate device registrations when a token exists but cannot be read.
            throw;
        }
    }

    private async Task<bool> RegisterAsync(CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(_settings.EnrollmentKey))
        {
            logger.LogError("Not registered and enrollment_key missing in config");
            return false;
        }
        var payload = new {
            hostname = _settings.Hostname, enrollment_key = _settings.EnrollmentKey,
            os_info = Environment.OSVersion.VersionString, agent_version = "2.0.0-test"
        };
        using var resp = await _http.PostAsJsonAsync("agent_register.php", payload, ct);
        if (resp.StatusCode == HttpStatusCode.Conflict)
        {
            logger.LogError("Registration rejected (409). Hostname already exists: recover token or reset device on server.");
            return false;
        }
        if (!resp.IsSuccessStatusCode)
        {
            logger.LogWarning("Registration failed: HTTP {Status}", (int)resp.StatusCode);
            return false;
        }
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var token = doc.RootElement.GetProperty("api_token").GetString();
        if (string.IsNullOrWhiteSpace(token)) throw new InvalidOperationException("Server returned empty API token");
        Directory.CreateDirectory(StateDir);
        var encrypted = ProtectedData.Protect(Encoding.UTF8.GetBytes(token), null, DataProtectionScope.LocalMachine);
        var tmp = TokenPath + ".tmp";
        await File.WriteAllBytesAsync(tmp, encrypted, ct);
        File.Move(tmp, TokenPath, true);
        _token = token;
        // Do not retain enrollment key on disk after registration.
        _settings.EnrollmentKey = "";
        await File.WriteAllTextAsync(ConfigPath, JsonSerializer.Serialize(_settings, JsonOptions), ct);
        logger.LogInformation("Device registered and token stored encrypted");
        return true;
    }

    private async Task HeartbeatAsync(CancellationToken ct)
    {
        using var req = Request(HttpMethod.Post, "agent_heartbeat.php");
        req.Content = JsonContent.Create(new { hostname = _settings.Hostname, agent_version = "2.0.0-test" });
        using var resp = await _http.SendAsync(req, ct);
        if (resp.IsSuccessStatusCode) logger.LogInformation("Heartbeat OK");
        else logger.LogWarning("Heartbeat HTTP {Status}", (int)resp.StatusCode);
    }

    private async Task RefreshPolicyAsync(CancellationToken ct)
    {
        using var req = Request(HttpMethod.Get, "agent_policy.php");
        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
        {
            logger.LogWarning("Policy fetch HTTP {Status}", (int)resp.StatusCode);
            return;
        }
        var body = await resp.Content.ReadAsStringAsync(ct);
        using var json = JsonDocument.Parse(body);
        if (!json.RootElement.TryGetProperty("applicable_policies", out var policies) || policies.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException("Server policy response missing applicable_policies array");
        // Atomic cache replacement: preserve old policy on interrupted writes.
        var temp = PolicyPath + ".tmp";
        await File.WriteAllTextAsync(temp, body, ct);
        File.Move(temp, PolicyPath, true);
        _usb?.UpdatePolicy(body);
        _networkPolicy?.Update(body);
        _httpProxy?.UpdatePolicy(body);
        if (_protocolFirewall is not null) await _protocolFirewall.ApplyPolicyAsync(body, ct);
        _protocolEventMonitor?.UpdatePolicy(body);
        logger.LogInformation("Policy refreshed: {Count} applicable policies", policies.GetArrayLength());
    }

    private async Task ReportUsbAsync(UsbDecision decision, CancellationToken ct)
    {
        if (_token is null) return;
        try
        {
            using var req = Request(HttpMethod.Post, "agent_report.php");
            req.Content = JsonContent.Create(new
            {
                hostname = _settings.Hostname,
                policy_id = decision.PolicyId,
                exit_point_type = "USB",
                action_taken = decision.Action,
                file_path = decision.FilePath,
                occurred_at = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            });
            using var response = await _http.SendAsync(req, ct);
            if (!response.IsSuccessStatusCode)
                logger.LogWarning("USB report HTTP {Status}: {File}", (int)response.StatusCode, decision.FilePath);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            logger.LogWarning(e, "USB event report failed for {File}", decision.FilePath);
        }
    }

    private async Task ReportHttpAsync(int policyId, string fileName, string action, CancellationToken ct)
    {
        if (_token is null) return;
        try
        {
            using var request = Request(HttpMethod.Post, "agent_report.php");
            request.Content = JsonContent.Create(new
            {
                hostname = _settings.Hostname,
                policy_id = policyId,
                exit_point_type = "NETWORK_WEB",
                action_taken = action,
                file_path = fileName,
                occurred_at = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            });
            using var response = await _http.SendAsync(request, ct);
            if (!response.IsSuccessStatusCode)
                logger.LogWarning("HTTP upload log rejected with status {Status}", (int)response.StatusCode);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "HTTP upload event reporting failed");
        }
    }

    private async Task ReportBrowserAsync(int policyId, string channel, string fileName, string destination, CancellationToken ct)
    {
        if (_token is null) throw new InvalidOperationException("Agent is not enrolled");
        var exit = channel switch
        {
            "chrome" => "BROWSER_CHROME",
            "edge" => "BROWSER_EDGE",
            "firefox" => "BROWSER_FIREFOX",
            _ => throw new ArgumentOutOfRangeException(nameof(channel))
        };
        using var req = Request(HttpMethod.Post, "agent_report.php");
        req.Content = JsonContent.Create(new {
            hostname = _settings.Hostname,
            policy_id = policyId,
            exit_point_type = exit,
            action_taken = "BLOCKED_BROWSER",
            file_path = fileName,
            destination_value = destination,
            process_name = channel == "edge" ? "msedge.exe" : channel == "chrome" ? "chrome.exe" : "firefox.exe",
            occurred_at = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        });
        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var reason = await resp.Content.ReadAsStringAsync(ct);
            logger.LogWarning("Browser report failed: HTTP {Status}: {Message}", (int)resp.StatusCode, reason);
            throw new HttpRequestException($"Browser report rejected HTTP {(int)resp.StatusCode}");
        }
    }

    private async Task ReportProtocolAsync(int policyId, string exitPoint, string processName, string destination, CancellationToken ct)
    {
        if (_token is null) throw new InvalidOperationException("Agent is not enrolled");
        using var request = Request(HttpMethod.Post, "agent_report.php");
        request.Content = JsonContent.Create(new
        {
            hostname = _settings.Hostname,
            policy_id = policyId,
            exit_point_type = exitPoint,
            action_taken = "BLOCKED_FIREWALL",
            // WFP 5157 proves connection denial; it cannot recover the requested filename.
            file_path = (string?)null,
            destination_value = destination,
            process_name = processName,
            occurred_at = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        });
        using var resp = await _http.SendAsync(request, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var reason = await resp.Content.ReadAsStringAsync(ct);
            logger.LogWarning("Protocol block report failed: HTTP {Status}: {Body}", (int)resp.StatusCode, reason);
            throw new HttpRequestException($"Protocol report HTTP {(int)resp.StatusCode}");
        }
        logger.LogInformation("Protocol firewall event reported: {Process} -> {Destination}", processName, destination);
    }

    private async Task ReportTransferAsync(int policyId, string channel, string action, string fileName,
        string destination, int[] matchedRuleIds, CancellationToken ct)
    {
        if (_token is null) throw new InvalidOperationException("Agent not registered");
        var exit = channel switch
        {
            "SCP" => "CLIENT_SCP",
            "SFTP" => "CLIENT_SFTP",
            "FTP" => "CLIENT_FTP",
            _ => throw new InvalidOperationException("Invalid channel")
        };
        using var req = Request(HttpMethod.Post, "agent_report.php");
        req.Content = JsonContent.Create(new
        {
            hostname = _settings.Hostname,
            policy_id = policyId,
            exit_point_type = exit,
            action_taken = action == "BLOCK" ? "BLOCKED_TRANSFER" : "LOGGED",
            file_path = fileName,
            destination_value = destination,
            process_name = channel.ToLowerInvariant() + ".exe",
            matched_rule_ids = matchedRuleIds,
            occurred_at = DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        });
        using var response = await _http.SendAsync(req, ct);
        if (!response.IsSuccessStatusCode)
            throw new HttpRequestException($"Transfer log HTTP {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync(ct)}");
    }

    private HttpRequestMessage Request(HttpMethod method, string relativeUrl)
    {
        var req = new HttpRequestMessage(method, relativeUrl);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        return req;
    }
}
