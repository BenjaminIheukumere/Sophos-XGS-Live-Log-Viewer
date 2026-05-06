using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.App.Services;

public static partial class IncidentCaptureService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    public static string CreateCaptureZip(
        IReadOnlyCollection<LogEntry> entries,
        LogDefinition logDefinition,
        FilterPreset filterPreset,
        TimeSpan window,
        DateTimeOffset capturedAt,
        string? outputDirectory = null)
    {
        var windowStart = capturedAt - window;
        var captureRoot = outputDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            "Sophos XGS Live Log Viewer",
            "Captures");
        Directory.CreateDirectory(captureRoot);

        var fileName = $"sxlv-capture-{Sanitize(logDefinition.Key)}-{capturedAt:yyyyMMdd-HHmmss}.zip";
        var outputPath = Path.Combine(captureRoot, fileName);
        var tempRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "SophosXgsLiveLogViewer",
            "capture-" + Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(tempRoot);
        try
        {
            var orderedEntries = entries
                .Where(entry => entry.ReceivedAt >= windowStart && entry.ReceivedAt <= capturedAt)
                .OrderBy(entry => entry.ReceivedAt)
                .ToList();

            var fieldKeys = orderedEntries
                .SelectMany(entry => entry.Fields.Keys)
                .Where(field => !string.IsNullOrWhiteSpace(field))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(field => field, StringComparer.OrdinalIgnoreCase)
                .ToList();

            File.WriteAllText(Path.Combine(tempRoot, "logs.csv"), BuildCsv(orderedEntries, fieldKeys), Encoding.UTF8);
            File.WriteAllText(Path.Combine(tempRoot, "logs.json"), BuildJson(orderedEntries), Encoding.UTF8);
            File.WriteAllText(Path.Combine(tempRoot, "metadata.json"), BuildMetadata(logDefinition, filterPreset, windowStart, capturedAt, orderedEntries.Count), Encoding.UTF8);
            File.WriteAllText(Path.Combine(tempRoot, "incident-notes.md"), BuildNotes(logDefinition, filterPreset, windowStart, capturedAt, orderedEntries.Count), Encoding.UTF8);

            if (File.Exists(outputPath))
            {
                File.Delete(outputPath);
            }

            ZipFile.CreateFromDirectory(tempRoot, outputPath, CompressionLevel.Optimal, includeBaseDirectory: false);
            return outputPath;
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempRoot))
                {
                    Directory.Delete(tempRoot, recursive: true);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static string BuildCsv(IReadOnlyList<LogEntry> entries, IReadOnlyList<string> fieldKeys)
    {
        var builder = new StringBuilder();
        var headers = new[] { "Received Time", "Event Time", "Disposition" }
            .Concat(fieldKeys.Select(ColumnNameFormatter.ToDisplayName))
            .Concat(["Raw"]);

        builder.AppendLine(string.Join(',', headers.Select(EscapeCsv)));
        foreach (var entry in entries)
        {
            var values = new[]
                {
                    entry.ReceivedAt.ToString("O", CultureInfo.InvariantCulture),
                    entry.OccurredAt.ToString("O", CultureInfo.InvariantCulture),
                    entry.Disposition.ToString()
                }
                .Concat(fieldKeys.Select(field => entry.Fields.TryGetValue(field, out var value) ? value : string.Empty))
                .Concat([entry.RawLine]);

            builder.AppendLine(string.Join(',', values.Select(EscapeCsv)));
        }

        return builder.ToString();
    }

    private static string BuildJson(IReadOnlyList<LogEntry> entries)
    {
        var rows = entries.Select(entry => new
        {
            receivedAt = entry.ReceivedAt,
            occurredAt = entry.OccurredAt,
            disposition = entry.Disposition.ToString(),
            fields = entry.Fields,
            raw = entry.RawLine
        });

        return JsonSerializer.Serialize(rows, JsonOptions);
    }

    private static string BuildMetadata(
        LogDefinition logDefinition,
        FilterPreset filterPreset,
        DateTimeOffset windowStart,
        DateTimeOffset capturedAt,
        int rowCount)
    {
        var metadata = new
        {
            app = "Sophos XGS Live Log Viewer by Benjamin Iheukumere",
            version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "unknown",
            generatedAt = capturedAt,
            windowStart,
            windowEnd = capturedAt,
            log = new
            {
                key = logDefinition.Key,
                name = logDefinition.DisplayName
            },
            filters = filterPreset.Conditions,
            rowCount
        };

        return JsonSerializer.Serialize(metadata, JsonOptions);
    }

    private static string BuildNotes(
        LogDefinition logDefinition,
        FilterPreset filterPreset,
        DateTimeOffset windowStart,
        DateTimeOffset capturedAt,
        int rowCount)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# Incident Notes");
        builder.AppendLine();
        builder.AppendLine($"Capture window: {windowStart:yyyy-MM-dd HH:mm:ss zzz} - {capturedAt:yyyy-MM-dd HH:mm:ss zzz}");
        builder.AppendLine($"Log source: {logDefinition.DisplayName}");
        builder.AppendLine($"Rows: {rowCount.ToString("N0", CultureInfo.InvariantCulture)}");
        builder.AppendLine();
        builder.AppendLine("## Active Filters");
        builder.AppendLine();

        if (filterPreset.Conditions.Count == 0)
        {
            builder.AppendLine("- None");
        }
        else
        {
            foreach (var condition in filterPreset.Conditions)
            {
                builder.AppendLine($"- {condition.Connector} {ColumnNameFormatter.ToDisplayName(condition.Field)} {condition.Operator} {condition.Value}");
            }
        }

        builder.AppendLine();
        builder.AppendLine("## Notes");
        builder.AppendLine();
        builder.AppendLine("- ");
        builder.AppendLine();
        builder.AppendLine("## Privacy");
        builder.AppendLine();
        builder.AppendLine("This capture can contain IP addresses, usernames, URLs, domains and raw firewall log content. Share it only with authorized recipients.");

        return builder.ToString();
    }

    private static string EscapeCsv(string value)
    {
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    private static string Sanitize(string value)
    {
        return UnsafeFileNameChars().Replace(value, "-").Trim('-');
    }

    [GeneratedRegex(@"[^A-Za-z0-9._-]+", RegexOptions.Compiled)]
    private static partial Regex UnsafeFileNameChars();
}
