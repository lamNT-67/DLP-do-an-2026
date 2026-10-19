using System.Text.Json;

namespace DlpAgent;

/// <summary>
/// Simple managed-upload gate: checks only the source filename extension against
/// assigned BLOCK / REPORT_ONLY file-type policies. No file reads or content scan.
/// </summary>
internal static class FileTypePolicyEngine
{
    internal static object Check(string policyJson, string channel, string file)
    {
        // Source file is resolved by caller, never inspect content.
        if (!File.Exists(file)) throw new FileNotFoundException("Source file not found", file);
        var extension = Path.GetExtension(file).TrimStart('.').ToLowerInvariant();
        var relevant = channel.ToUpperInvariant() switch
        {
            "SCP" => new[] { "CLIENT_SCP", "NETWORK_SCP_SFTP" },
            "SFTP" => new[] { "CLIENT_SFTP", "NETWORK_SCP_SFTP" },
            "FTP" => new[] { "CLIENT_FTP", "NETWORK_FTP" },
            _ => throw new ArgumentException("Unsupported transfer protocol")
        };
        using var doc = JsonDocument.Parse(policyJson);
        object? reportMatch = null;
        foreach (var policy in doc.RootElement.GetProperty("applicable_policies").EnumerateArray())
        {
            var action = policy.GetProperty("action").GetString();
            if (action is not ("BLOCK" or "REPORT_ONLY")) continue;
            if (!policy.TryGetProperty("exit_points", out var points) ||
                points.ValueKind != JsonValueKind.Array ||
                !points.EnumerateArray().Any(p => relevant.Contains(p.GetString()))) continue;
            if (!policy.TryGetProperty("file_types", out var types) || types.ValueKind != JsonValueKind.Array ||
                !types.EnumerateArray().Any(t => string.Equals(
                    t.GetProperty("extension").GetString()?.TrimStart('.'), extension, StringComparison.OrdinalIgnoreCase)))
                continue;
            var fullPath = Path.GetFullPath(file);
            if (IsAllowed(policy, "allowed_files", fullPath) || IsAllowed(policy, "allowed_files", Path.GetFileName(file)) ||
                IsInAllowedDirectory(policy, fullPath)) continue;

            var result = new
            {
                decision = action,
                reason = "FILE_TYPE",
                policy_id = (int?)policy.GetProperty("policy_id").GetInt32(),
                matched_rule_ids = Array.Empty<int>()
            };
            if (action == "BLOCK") return result;
            reportMatch ??= result;
        }
        return reportMatch ?? new
        {
            decision = "ALLOW", reason = "NO_MATCH", policy_id = (int?)null,
            matched_rule_ids = Array.Empty<int>()
        };
    }

    private static bool IsAllowed(JsonElement policy, string key, string path)
    {
        return policy.TryGetProperty(key, out var list) && list.ValueKind == JsonValueKind.Array &&
               list.EnumerateArray().Any(v => string.Equals(v.GetString(), path, StringComparison.OrdinalIgnoreCase));
    }
    private static bool IsInAllowedDirectory(JsonElement policy, string path)
    {
        return policy.TryGetProperty("allowed_locations", out var list) && list.ValueKind == JsonValueKind.Array &&
               list.EnumerateArray().Any(v =>
               {
                   var directory = v.GetString()?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                   return !string.IsNullOrWhiteSpace(directory) &&
                          path.StartsWith(directory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
               });
    }
}
