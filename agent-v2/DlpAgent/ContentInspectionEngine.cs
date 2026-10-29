using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DlpAgent;

/// <summary>
/// Bounded, local user-mode content inspection for controlled file transfers.
/// No kernel interception; callers must invoke this before sending bytes.
/// </summary>
internal static class ContentInspectionEngine
{
    private const int MaxBytes = 2 * 1024 * 1024;
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".txt", ".csv", ".json", ".log", ".md", ".xml" };

    internal static object Check(string policyJson, string channel, string file)
    {
        if (!File.Exists(file)) throw new FileNotFoundException("Source file not found", file);
        var path = Path.GetFullPath(file);
        return Evaluate(policyJson, channel, path, () => ReadBoundedText(path));
    }

    // Browser Extension supplies bytes directly; no temporary file is written to disk.
    internal static object CheckBytes(string policyJson, string channel, string fileName, byte[] bytes)
    {
        if (string.IsNullOrWhiteSpace(fileName) || fileName.Length > 240 ||
            Path.GetFileName(fileName) != fileName || fileName.Contains('\\') || fileName.Contains('/'))
            throw new InvalidDataException("Invalid file name");
        if (bytes.Length > MaxBytes) throw new InvalidDataException("File exceeds inspection limit");
        return Evaluate(policyJson, channel, fileName, () => DecodeText(bytes));
    }

    private static string DecodeText(byte[] bytes)
    {
        var offset = bytes.AsSpan().StartsWith(new byte[] { 0xef, 0xbb, 0xbf }) ? 3 : 0;
        var text = new UTF8Encoding(false, true).GetString(bytes, offset, bytes.Length - offset);
        if (text.IndexOf('\0') >= 0) throw new InvalidDataException("Binary content unsupported");
        return text;
    }

    private static object Evaluate(string policyJson, string channel, string path, Func<string> readText)
    {
        var extension = Path.GetExtension(path);
        var points = channel.ToUpperInvariant() switch
        {
            "SCP" => new[] { "CLIENT_SCP", "NETWORK_SCP_SFTP" },
            "SFTP" => new[] { "CLIENT_SFTP", "NETWORK_SCP_SFTP" },
            "FTP" => new[] { "CLIENT_FTP", "NETWORK_FTP" },
            "BROWSER_CHROME" => new[] { "BROWSER_CHROME", "NETWORK_WEB" },
            "BROWSER_EDGE" => new[] { "BROWSER_EDGE", "NETWORK_WEB" },
            "BROWSER_FIREFOX" => new[] { "BROWSER_FIREFOX", "NETWORK_WEB" },
            _ => throw new ArgumentException("Unsupported transfer protocol", nameof(channel))
        };
        using var document = JsonDocument.Parse(policyJson);
        if (!document.RootElement.TryGetProperty("applicable_policies", out var policies) ||
            policies.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Policy response missing applicable_policies");

        object? reportOnly = null;
        string? content = null;
        foreach (var policy in policies.EnumerateArray())
        {
            string? action = policy.GetProperty("action").GetString();
            if (action is not ("BLOCK" or "REPORT_ONLY")) continue;
            if (!HasExitPoint(policy, points) || Allowed(policy, path)) continue;
            int policyId = policy.GetProperty("policy_id").GetInt32();
            bool fileTypeMatch = MatchesExtension(policy, extension);
            int[] ruleIds = Array.Empty<int>();
            if (!fileTypeMatch && policy.TryGetProperty("content_rules", out var rules) &&
                rules.ValueKind == JsonValueKind.Array && rules.GetArrayLength() != 0)
            {
                // Do not silently allow files when a configured content rule cannot be inspected.
                if (!TextExtensions.Contains(extension))
                    throw new InvalidDataException("Content inspection unsupported for file type " + extension);
                if (content is null) content = readText();
                ruleIds = MatchContentRules(rules, content);
            }
            if (!fileTypeMatch && ruleIds.Length == 0) continue;

            var verdict = new
            {
                decision = action,
                reason = fileTypeMatch ? "FILE_TYPE" : "CONTENT_RULE",
                policy_id = (int?)policyId,
                matched_rule_ids = ruleIds,
                scan_status = fileTypeMatch ? "FILE_TYPE_MATCH" : "CONTENT_MATCH"
            };
            if (action == "BLOCK") return verdict;
            reportOnly ??= verdict;
        }
        return reportOnly ?? new
        {
            decision = "ALLOW", reason = "NO_MATCH", policy_id = (int?)null,
            matched_rule_ids = Array.Empty<int>(), scan_status = "COMPLETE"
        };
    }

    private static string ReadBoundedText(string file)
    {
        using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 8192, options: FileOptions.SequentialScan);
        if (stream.Length > MaxBytes)
            throw new InvalidDataException($"Content inspection file exceeds {MaxBytes} byte limit");
        using var reader = new StreamReader(stream, new UTF8Encoding(false, true), detectEncodingFromByteOrderMarks: true);
        var text = reader.ReadToEnd();
        if (text.IndexOf('\0') >= 0)
            throw new InvalidDataException("Binary content is unsupported");
        return text;
    }

    private static int[] MatchContentRules(JsonElement rules, string text)
    {
        var matched = new List<int>();
        foreach (var rule in rules.EnumerateArray())
        {
            var pattern = rule.GetProperty("pattern").GetString();
            if (string.IsNullOrWhiteSpace(pattern)) continue;
            var kind = rule.GetProperty("rule_type").GetString()?.ToUpperInvariant();
            bool hit;
            if (kind == "DICTIONARY")
            {
                hit = pattern.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .Any(term => term.Length > 0 && text.Contains(term, StringComparison.OrdinalIgnoreCase));
            }
            else if (kind == "REGEX")
            {
                try
                {
                    hit = Regex.IsMatch(text, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                        TimeSpan.FromMilliseconds(200));
                }
                catch (Exception ex) when (ex is ArgumentException or RegexMatchTimeoutException)
                {
                    throw new InvalidDataException("Invalid or timed-out content rule " + rule.GetProperty("id").GetInt32(), ex);
                }
            }
            else throw new InvalidDataException("Unsupported content rule type: " + kind);
            if (hit) matched.Add(rule.GetProperty("id").GetInt32());
        }
        return matched.ToArray();
    }

    private static bool HasExitPoint(JsonElement policy, string[] relevant) =>
        policy.TryGetProperty("exit_points", out var values) && values.ValueKind == JsonValueKind.Array &&
        values.EnumerateArray().Any(p => relevant.Contains(p.GetString(), StringComparer.OrdinalIgnoreCase));

    private static bool MatchesExtension(JsonElement policy, string extension) =>
        policy.TryGetProperty("file_types", out var values) && values.ValueKind == JsonValueKind.Array &&
        values.EnumerateArray().Any(p => p.TryGetProperty("extension", out var ext) &&
            string.Equals(ext.GetString()?.TrimStart('.'), extension.TrimStart('.'), StringComparison.OrdinalIgnoreCase));

    private static bool Allowed(JsonElement policy, string file)
    {
        var filename = Path.GetFileName(file);
        if (policy.TryGetProperty("allowed_files", out var files) && files.ValueKind == JsonValueKind.Array &&
            files.EnumerateArray().Any(v => string.Equals(v.GetString(), file, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(v.GetString(), filename, StringComparison.OrdinalIgnoreCase))) return true;
        return policy.TryGetProperty("allowed_locations", out var dirs) && dirs.ValueKind == JsonValueKind.Array &&
            dirs.EnumerateArray().Any(v => {
                var dir = v.GetString();
                if (string.IsNullOrWhiteSpace(dir)) return false;
                dir = Path.GetFullPath(dir).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                return file.StartsWith(dir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
            });
    }
}
