using System.Collections.Concurrent;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace DlpAgent;

// Best-effort post-write USB enforcement for lab use; NOT a filesystem minifilter.
// FileSystemWatcher events arrive after writes may already have occurred.
internal sealed class UsbMonitor : IDisposable
{
    private readonly ILogger _logger;
    private readonly Channel<string> _events = Channel.CreateBounded<string>(
        new BoundedChannelOptions(1024) { SingleReader = true, SingleWriter = false, FullMode = BoundedChannelFullMode.DropWrite });
    private readonly Dictionary<string, FileSystemWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _recent = new(StringComparer.OrdinalIgnoreCase);
    private UsbRules _rules = UsbRules.Empty;
    private readonly bool _enforce;

    internal UsbMonitor(ILogger logger, bool enforce)
    {
        _logger = logger;
        _enforce = enforce;
    }

    internal void UpdatePolicy(string json)
    {
        _rules = UsbRules.Parse(json);
        _logger.LogInformation("USB rules refreshed; extensions={Count}; enforcement={Enabled}",
            _rules.Extensions.Count, _enforce);
    }

    internal void RefreshDrives()
    {
        var roots = DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
            .Select(d => Path.GetFullPath(d.RootDirectory.FullName))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var root in _watchers.Keys.Where(k => !roots.Contains(k)).ToArray())
        {
            _watchers[root].Dispose();
            _watchers.Remove(root);
            _logger.LogInformation("USB disconnected: {Drive}", root);
        }
        foreach (var root in roots)
        {
            if (_watchers.ContainsKey(root)) continue;
            try
            {
                var watcher = new FileSystemWatcher(root)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.CreationTime,
                    InternalBufferSize = 32768
                };
                watcher.Created += OnFile;
                watcher.Changed += OnFile;
                watcher.Renamed += OnRename;
                watcher.Error += (_, e) => _logger.LogWarning(e.GetException(), "USB watcher error on {Root}", root);
                watcher.EnableRaisingEvents = true;
                _watchers.Add(root, watcher);
                _logger.LogInformation("USB monitoring attached to {Root}", root);
            }
            catch (Exception e) { _logger.LogWarning(e, "Could not attach USB watcher to {Root}", root); }
        }
    }

    private void OnFile(object sender, FileSystemEventArgs e) => _events.Writer.TryWrite(e.FullPath);
    private void OnRename(object sender, RenamedEventArgs e) => _events.Writer.TryWrite(e.FullPath);

    internal async Task DrainAsync(Func<UsbDecision, CancellationToken, Task> report, CancellationToken ct)
    {
        var count = 0;
        while (count++ < 40 && _events.Reader.TryRead(out var path))
        {
            ct.ThrowIfCancellationRequested();
            var rule = _rules.Decide(path);
            if (rule is null) continue;
            if (!_watchers.Keys.Any(root => path.StartsWith(root, StringComparison.OrdinalIgnoreCase))) continue;
            if (_recent.TryGetValue(path, out var seen) && DateTimeOffset.UtcNow - seen < TimeSpan.FromSeconds(20)) continue;
            _recent[path] = DateTimeOffset.UtcNow;
            if (_recent.Count > 2000)
                foreach (var k in _recent.Where(x => DateTimeOffset.UtcNow - x.Value > TimeSpan.FromMinutes(2)).Select(x => x.Key).ToArray())
                    _recent.TryRemove(k, out _);

            var action = "LOGGED";
            if (rule.Action == "BLOCK" && _enforce)
            {
                // Recheck this is a regular file. Never delete directories or files outside a removable drive.
                for (var attempt = 0; attempt < 12; attempt++)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        if (!File.Exists(path)) break;
                        var info = new FileInfo(path);
                        if ((info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0) break;
                        // Avoid deleting a file actively being written; cannot prevent data being written before deletion.
                        using (var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None)) { }
                        File.Delete(path);
                        if (!File.Exists(path)) action = "BLOCKED_DELETE";
                        break;
                    }
                    catch (IOException) { await Task.Delay(500, ct); }
                    catch (UnauthorizedAccessException e) { _logger.LogWarning(e, "USB file cannot be removed: {File}", path); break; }
                }
            }
            _logger.LogInformation("USB matched {Extension}; policy={Policy}; result={Action}; file={File}",
                Path.GetExtension(path), rule.PolicyId, action, path);
            await report(new UsbDecision(rule.PolicyId, path, action), ct);
        }
    }

    public void Dispose()
    {
        foreach (var watcher in _watchers.Values) watcher.Dispose();
        _watchers.Clear();
    }
}

internal sealed record UsbDecision(int PolicyId, string FilePath, string Action);

internal sealed record UsbRule(int PolicyId, string Action, HashSet<string> Extensions,
    string[] AllowedFiles, string[] AllowedLocations)
{
    internal bool Matches(string file)
    {
        var ext = Path.GetExtension(file).TrimStart('.');
        if (!Extensions.Contains(ext)) return false;
        if (AllowedFiles.Any(x => string.Equals(x, Path.GetFileName(file), StringComparison.OrdinalIgnoreCase) ||
                                  string.Equals(x, file, StringComparison.OrdinalIgnoreCase))) return false;
        if (AllowedLocations.Any(x => IsAllowedFolder(path: file, configuredFolder: x))) return false;
        return true;
    }

    private static bool IsAllowedFolder(string path, string configuredFolder)
    {
        // Ignore non-path exceptions (such as domains) in the USB file monitor.
        if (string.IsNullOrWhiteSpace(configuredFolder) || !Path.IsPathFullyQualified(configuredFolder))
            return false;
        try
        {
            var folder = Path.GetFullPath(configuredFolder).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return path.StartsWith(folder, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }
    }
}

internal sealed class UsbRules
{
    internal static UsbRules Empty => new([]);
    private readonly List<UsbRule> _policies;
    internal HashSet<string> Extensions { get; }

    private UsbRules(List<UsbRule> policies)
    {
        _policies = policies;
        Extensions = policies.SelectMany(p => p.Extensions).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    internal static UsbRules Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("applicable_policies", out var list) || list.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Missing applicable_policies array");
        var result = new List<UsbRule>();
        foreach (var p in list.EnumerateArray())
        {
            if (!p.TryGetProperty("exit_points", out var exits) || exits.ValueKind != JsonValueKind.Array ||
                !exits.EnumerateArray().Any(e => e.ValueKind == JsonValueKind.String && e.GetString() == "USB"))
                continue;
            if (!p.TryGetProperty("policy_id", out var pid) || !pid.TryGetInt32(out var id) || id < 1) continue;
            var action = p.TryGetProperty("action", out var act) ? act.GetString() : null;
            if (action is not ("BLOCK" or "REPORT_ONLY")) continue;
            var exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (p.TryGetProperty("file_types", out var files) && files.ValueKind == JsonValueKind.Array)
                foreach (var f in files.EnumerateArray())
                    if (f.TryGetProperty("extension", out var extension) && extension.ValueKind == JsonValueKind.String)
                    {
                        var e = (extension.GetString() ?? "").Trim().TrimStart('.');
                        if (e.Length > 0 && e.All(ch => char.IsLetterOrDigit(ch))) exts.Add(e);
                    }
            if (exts.Count == 0) continue;
            result.Add(new UsbRule(id, action, exts,
                GetStrings(p, "allowed_files"), GetStrings(p, "allowed_locations")));
        }
        return new UsbRules(result);
    }

    private static string[] GetStrings(JsonElement p, string key) =>
        p.TryGetProperty(key, out var list) && list.ValueKind == JsonValueKind.Array
            ? list.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String)
                .Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToArray()
            : [];

    internal UsbRule? Decide(string path)
    {
        // BLOCK wins when multiple applicable policies match the same file.
        return _policies.Where(p => p.Matches(path))
            .OrderBy(p => p.Action == "BLOCK" ? 0 : 1).FirstOrDefault();
    }
}
