using System.IO.Compression;
using SophosXgsLiveLogViewer.App.Models;
using SophosXgsLiveLogViewer.App.Services;
using SophosXgsLiveLogViewer.App.ViewModels;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class IncidentCaptureServiceTests
{
    [Fact]
    public void CreateCaptureZip_WritesExpectedIncidentFiles()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sxlv-capture-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var capturedAt = new DateTimeOffset(2026, 5, 6, 12, 0, 0, TimeSpan.Zero);
        var logDefinition = LogDefinition.Find("firewall")!;
        var preset = FilterPresetService.CreatePreset("firewall", "Firewall", Array.Empty<FilterCondition>());
        var entries = new[]
        {
            new LogEntry
            {
                ReceivedAt = capturedAt.AddSeconds(-10),
                OccurredAt = capturedAt.AddDays(-2),
                Disposition = LogDisposition.Denied,
                RawLine = "log_type=\"Firewall\" status=\"Deny\" src_ip=\"192.0.2.10\"",
                Fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["log_type"] = "Firewall",
                    ["status"] = "Deny",
                    ["src_ip"] = "192.0.2.10"
                }
            },
            new LogEntry
            {
                ReceivedAt = capturedAt.AddMinutes(-10),
                OccurredAt = capturedAt.AddSeconds(-10),
                Disposition = LogDisposition.Allowed,
                RawLine = "log_type=\"Firewall\" status=\"Allow\" src_ip=\"198.51.100.10\"",
                Fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["log_type"] = "Firewall",
                    ["status"] = "Allow",
                    ["src_ip"] = "198.51.100.10"
                }
            }
        };

        try
        {
            var zipPath = IncidentCaptureService.CreateCaptureZip(
                entries,
                logDefinition,
                preset,
                TimeSpan.FromSeconds(60),
                capturedAt,
                directory);

            Assert.True(File.Exists(zipPath));
            using var archive = ZipFile.OpenRead(zipPath);
            var names = archive.Entries.Select(entry => entry.FullName).ToHashSet(StringComparer.OrdinalIgnoreCase);

            Assert.Contains("logs.csv", names);
            Assert.Contains("logs.json", names);
            Assert.Contains("metadata.json", names);
            Assert.Contains("incident-notes.md", names);

            var csvEntry = archive.GetEntry("logs.csv")!;
            using var reader = new StreamReader(csvEntry.Open());
            var csv = reader.ReadToEnd();
            Assert.Contains("192.0.2.10", csv);
            Assert.DoesNotContain("198.51.100.10", csv);
            Assert.Contains("Received Time", csv);
            Assert.Contains("Event Time", csv);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
