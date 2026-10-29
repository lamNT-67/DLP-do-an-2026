using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DlpAgent;

/// <summary>
/// Bounded multipart/form-data parser and content inspection for the explicit HTTP lab proxy.
/// Never forwards a request until every file part has been examined.
/// </summary>
internal static class MultipartUploadInspector
{
    private const int MaxPartBytes = 2 * 1024 * 1024;
    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".txt", ".csv", ".json", ".log", ".md", ".xml" };
    private static readonly Regex FileNamePattern = new(
        "(?:^|;)\\s*filename\\s*=\\s*(?:\\\"(?<filename>[^\\\"]*)\\\"|(?<filename>[^;]*))",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(200));

    internal record Verdict(string FileName, string Decision, string Reason, int? PolicyId, int[] RuleIds);

    internal static List<Verdict> Inspect(string policyJson, string contentType, byte[] body)
    {
        var boundary = GetBoundary(contentType);
        var parts = ExtractFiles(body, boundary);
        using var doc = JsonDocument.Parse(policyJson);
        if (!doc.RootElement.TryGetProperty("applicable_policies", out var policies) ||
            policies.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException("Missing applicable_policies");
        var results = new List<Verdict>();
        foreach (var part in parts)
        {
            Verdict? reportOnly = null, blocked = null;
            foreach (var policy in policies.EnumerateArray())
            {
                var action = policy.GetProperty("action").GetString();
                if (action is not ("BLOCK" or "REPORT_ONLY")) continue;
                if (!policy.TryGetProperty("exit_points", out var exits) || exits.ValueKind != JsonValueKind.Array ||
                    !exits.EnumerateArray().Any(e => e.GetString() == "NETWORK_WEB")) continue;
                if (IsAllowedFile(policy, part.Name)) continue;
                var extension = Path.GetExtension(part.Name);
                bool typeMatch = policy.TryGetProperty("file_types", out var types) &&
                    types.ValueKind == JsonValueKind.Array &&
                    types.EnumerateArray().Any(t => t.TryGetProperty("extension", out var ext) &&
                        string.Equals(ext.GetString()?.TrimStart('.'), extension.TrimStart('.'), StringComparison.OrdinalIgnoreCase));

                int[] matches = Array.Empty<int>();
                if (!typeMatch && policy.TryGetProperty("content_rules", out var rules) &&
                    rules.ValueKind == JsonValueKind.Array && rules.GetArrayLength() != 0)
                {
                    if (part.Content.Length > MaxPartBytes)
                        throw new InvalidDataException("Upload part exceeds 2 MiB inspection limit");
                    if (!TextExtensions.Contains(extension))
                        throw new InvalidDataException("Unsupported upload content type: " + extension);
                    var text = new UTF8Encoding(false, true).GetString(part.Content);
                    if (text.IndexOf('\0') >= 0)
                        throw new InvalidDataException("Binary content cannot be inspected");
                    var ids = new List<int>();
                    foreach (var rule in rules.EnumerateArray())
                    {
                        string pattern = rule.GetProperty("pattern").GetString() ?? "";
                        if (pattern.Length == 0) continue;
                        string kind = rule.GetProperty("rule_type").GetString()?.ToUpperInvariant() ?? "";
                        bool hit;
                        if (kind == "DICTIONARY")
                            hit = pattern.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                                .Any(term => term.Length > 0 && text.Contains(term, StringComparison.OrdinalIgnoreCase));
                        else if (kind == "REGEX")
                        {
                            try {
                                hit = Regex.IsMatch(text, pattern,
                                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                                    TimeSpan.FromMilliseconds(200));
                            }
                            catch (Exception ex) when (ex is RegexMatchTimeoutException or ArgumentException) {
                                throw new InvalidDataException("Regex rule invalid or timed out", ex);
                            }
                        }
                        else throw new InvalidDataException("Unsupported content rule type: " + kind);
                        if (hit) ids.Add(rule.GetProperty("id").GetInt32());
                    }
                    matches = ids.ToArray();
                }
                if (!typeMatch && matches.Length == 0) continue;
                var verdict = new Verdict(part.Name, action!, typeMatch ? "FILE_TYPE" : "CONTENT_RULE",
                    policy.GetProperty("policy_id").GetInt32(), matches);
                if (action == "BLOCK") { blocked = verdict; break; }
                reportOnly ??= verdict;
            }
            results.Add(blocked ?? reportOnly ?? new Verdict(part.Name, "ALLOW", "NO_MATCH", null, Array.Empty<int>()));
        }
        return results;
    }

    private static bool IsAllowedFile(JsonElement policy, string filename) =>
        policy.TryGetProperty("allowed_files", out var files) && files.ValueKind == JsonValueKind.Array &&
        files.EnumerateArray().Any(f => string.Equals(f.GetString(), filename, StringComparison.OrdinalIgnoreCase));

    private static string GetBoundary(string contentType)
    {
        var parameter = contentType.Split(';', StringSplitOptions.TrimEntries)
            .FirstOrDefault(s => s.StartsWith("boundary=", StringComparison.OrdinalIgnoreCase));
        var boundary = parameter is null ? "" : parameter["boundary=".Length..].Trim().Trim('"');
        if (boundary.Length is < 1 or > 70 || boundary.Any(c => c < 33 || c > 126 || c == '"'))
            throw new InvalidDataException("Invalid multipart boundary");
        return boundary;
    }

    private record FilePart(string Name, byte[] Content);

    private static List<FilePart> ExtractFiles(byte[] body, string boundary)
    {
        var marker = Encoding.ASCII.GetBytes("--" + boundary);
        var nextMarker = Encoding.ASCII.GetBytes("\r\n--" + boundary);
        var delimiter = Encoding.ASCII.GetBytes("\r\n\r\n");
        if (!body.AsSpan().StartsWith(marker))
            throw new InvalidDataException("Missing first multipart boundary");
        var files = new List<FilePart>();
        int index = marker.Length;
        while (true)
        {
            if (index + 2 > body.Length) throw new InvalidDataException("Truncated multipart boundary");
            if (body[index] == '-' && body[index + 1] == '-') return files;
            if (body[index] != '\r' || body[index + 1] != '\n')
                throw new InvalidDataException("Invalid multipart separator");
            index += 2;
            int headerEndOffset = body.AsSpan(index).IndexOf(delimiter);
            if (headerEndOffset < 0 || headerEndOffset > 8192)
                throw new InvalidDataException("Missing or oversized part headers");
            var header = Encoding.Latin1.GetString(body, index, headerEndOffset);
            int dataStart = index + headerEndOffset + delimiter.Length;
            int nextOffset = body.AsSpan(dataStart).IndexOf(nextMarker);
            if (nextOffset < 0) throw new InvalidDataException("Missing closing multipart boundary");
            int next = dataStart + nextOffset + 2;
            var headerLines = header.Split("\r\n");
            var disposition = headerLines.FirstOrDefault(l =>
                l.StartsWith("Content-Disposition:", StringComparison.OrdinalIgnoreCase));
            if (disposition is null) throw new InvalidDataException("Missing Content-Disposition");
            var filenameMatch = FileNamePattern.Match(disposition);
            if (filenameMatch.Success)
            {
                var name = filenameMatch.Groups["filename"].Value.Trim();
                if (name.Length == 0 || name.Length > 240 || name.Contains('/') || name.Contains('\\'))
                    throw new InvalidDataException("Invalid upload filename");
                var file = body.AsSpan(dataStart, nextOffset).ToArray();
                files.Add(new FilePart(name, file));
            }
            index = next + marker.Length;
            if (next + marker.Length > body.Length || !body.AsSpan(next).StartsWith(marker))
                throw new InvalidDataException("Unexpected multipart boundary");
        }
    }
}
