using SophosXgsLiveLogViewer.App.Models;
using SophosXgsLiveLogViewer.App.Services;
using SophosXgsLiveLogViewer.App.ViewModels;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class FilterPresetServiceTests
{
    [Fact]
    public void SaveAndLoad_RoundTripsFilterPresetWithoutProfileData()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sxlv-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "preset.sxlv-filter.json");

        try
        {
            var preset = FilterPresetService.CreatePreset(
                "firewall",
                "Firewall",
                [
                    new FilterCondition
                    {
                        Connector = "AND",
                        Field = "src_ip",
                        Operator = "Equals",
                        Value = "192.0.2.10"
                    }
                ],
                "Blocked source");

            FilterPresetService.Save(path, preset);
            var loaded = FilterPresetService.Load(path);
            var raw = File.ReadAllText(path);

            Assert.Equal("firewall", loaded.LogKey);
            Assert.Single(loaded.Conditions);
            Assert.Equal("src_ip", loaded.Conditions[0].Field);
            Assert.DoesNotContain("Password", raw, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Host", raw, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void Validate_RejectsUnknownLogSource()
    {
        var preset = new FilterPreset
        {
            LogKey = "unknown",
            Conditions =
            [
                new FilterConditionPreset
                {
                    Field = "src_ip",
                    Operator = "Equals",
                    Value = "192.0.2.10"
                }
            ]
        };

        Assert.Throws<InvalidDataException>(() => FilterPresetService.Validate(preset));
    }
}
