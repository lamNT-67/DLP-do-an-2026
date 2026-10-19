using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DlpAgent;

// Conservative, bounded inspection for plain-text files uploaded with a managed launcher.
// Scans under the invoking user's Windows token, never the Windows Service's SYSTEM token.
internal static class FileInspectionEngine
{
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    { "txt", "csv", "log", "json", "xml", "md", "ini", "cfg", "conf", "yaml", "yml", "ps1", "bat", "sql", "html", "htm", "js", "css" };
    private const long MaxBytes = 2 * 1024 * 1024;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(150);

    internal static object Check(string policyJson, string channel, string file)
    {
        if (!System.IO.File.Exists(file)) throw new FileNotFoundException("Source file is missing", file);
        var info = new FileInfo(file);
        if (info.Length > MaxBytes)
            return new { decision = "BLOCK", reason = "FILE_TOO_LARGE_TO_INSPECT", policy_id = (int?)null, matched_rule_ids = Array.Empty<int>() };
        var extension = info.Extension.TrimStart('.').ToLowerInvariant();
        var points = channel.ToUpperInvariant() switch
        {
            "SCP" => new[] { "CLIENT_SCP", "NETWORK_SCP_SFTP" },
            "SFTP" => new[] { "CLIENT_SFTP", "NETWORK_SCP_SFTP" },
            "FTP" => new[] { "CLIENT_FTP", "NETWORK_FTP" },
            _ => throw new ArgumentException("Unsupported transfer channel")
        };
        using var doc = JsonDocument.Parse(policyJson);
        var policies = doc.RootElement.GetProperty("applicable_policies");
        // No-content policies: selected extensions are blocked.
        // With content rules: only matching regex/dictionary or explicit always-block triggers.
        bool read = false;
        string content = "";
        object? reportMatch = null;
        foreach (var policy in policies.EnumerateArray())
        {
            if (!policy.TryGetProperty("exit_points", out var exitPoints) ||
                !exitPoints.EnumerateArray().Any(x => points.Contains(x.GetString())) ||
                policy.GetProperty("action").GetString() is not ("BLOCK" or "REPORT_ONLY")) continue;
            var path = Path.GetFullPath(file);
            if (ContainsAllowed(policy, "allowed_files", info.Name) ||
                ContainsAllowed(policy, "allowed_files", path) ||
                ContainsAllowedDirectory(policy, path)) continue;

            var files = policy.GetProperty("file_types").EnumerateArray().ToArray();
            var selected = files.FirstOrDefault(f => string.Equals(f.GetProperty("extension").GetString()?.TrimStart('.'),
                extension, StringComparison.OrdinalIgnoreCase));
            // Policies without a file_types selection do not match arbitrary files.
            if (selected.ValueKind == JsonValueKind.Undefined) continue;
            var id = policy.GetProperty("policy_id").GetInt32();
            var rules = policy.TryGetProperty("content_rules", out var cr) && cr.ValueKind == JsonValueKind.Array
                ? cr.EnumerateArray().ToArray() : Array.Empty<JsonElement>();
            bool matched = false;
            string reason;
            var ids = new List<int>();
            if (selected.TryGetProperty("always_block_regardless_content", out var ab) && ab.ValueKind == JsonValueKind.True)
            {
                matched = true;
                reason = "ALWAYS_BLOCK_FILE_TYPE";
            }
            else if (rules.Length == 0)
            {
                matched = true;
                reason = "FILE_TYPE";
            }
            else if (!TextExtensions.Contains(extension))
            {
                // Explicitly fail closed for selected types we cannot extract content from.
                matched = true;
                reason = "UNSUPPORTED_CONTENT_FORMAT";
            }
            else
            {
                if (!read)
                {
                    // Strict UTF-8 text scan, with BOM-aware UTF16 fallback.
                    var bytes = System.IO.File.ReadAllBytes(file);
                    var enc = bytes.Length >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe
                        ? Encoding.Unicode : new UTF8Encoding(false, true);
                    try { content = enc.GetString(bytes); }
                    catch (DecoderFallbackException) {
                        return new { decision = "BLOCK", reason = "UNREADABLE_TEXT", policy_id = (int?)id, matched_rule_ids = Array.Empty<int>() };
                    }
                    read = true;
                }
                foreach (var rule in rules)
                {
                    var pattern = rule.GetProperty("pattern").GetString() ?? "";
                    if (pattern.Length is 0 or > 4096) continue;
                    var type = rule.GetProperty("rule_type").GetString();
                    try
                    {
                        bool hit = type == "REGEX"
                            ? Regex.IsMatch(content, pattern, RegexOptions.CultureInvariant, RegexTimeout)
                            : type == "DICTIONARY" && pattern.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                                .Any(term => content.Contains(term, StringComparison.OrdinalIgnoreCase));
                        if (hit) ids.Add(rule.GetProperty("id").GetInt32());
                    }
                    catch (Exception e) when (e is ArgumentException or RegexMatchTimeoutException)
                    {
                        // Invalid/expensive rule must not silently let sensitive data leave.
                        return new { decision = "BLOCK", reason = "INVALID_OR_TIMED_OUT_RULE", policy_id = (int?)id, matched_rule_ids = Array.Empty<int>() };
                    }
                }
                matched = ids.Count > 0;
                reason = "CONTENT_RULE";
            }
            if (!matched) continue;
            var result = new { decision = policy.GetProperty("action").GetString() == "BLOCK" ? "BLOCK" : "REPORT_ONLY",
                reason, policy_id = (int?)id, matched_rule_ids = ids.ToArray() };
            if (result.decision == "BLOCK") return result;
            reportMatch ??= result;
        }
        return reportMatch ?? new { decision = "ALLOW", reason = "NO_MATCH", policy_id = (int?)null, matched_rule_ids = Array.Empty<int>() };
    }

    private static bool ContainsAllowed(JsonElement policy, string name, string file)
    {
        if (!policy.TryGetProperty(name, out var allowed) || allowed.ValueKind != JsonValueKind.Array) return false;
        return allowed.EnumerateArray().Any(x => string.Equals(x.GetString(), file, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ContainsAllowedDirectory(JsonElement policy, string path)
    {
        if (!policy.TryGetProperty("allowed_locations", out var allowed) || allowed.ValueKind != JsonValueKind.Array) return false;
        return allowed.EnumerateArray().Any(x => {
            var dir = x.GetString()?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return !string.IsNullOrWhiteSpace(dir) && path.StartsWith(dir + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        });
    }
}
