using SophosXgsLiveLogViewer.App.Services;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class SshLogStreamServiceTests
{
    [Fact]
    public void TryParseCpuUsage_ParsesTotalAndCores()
    {
        var parsed = SshLogStreamService.TryParseCpuUsage(
            ["cpu:31.2", "cpu0:18.4", "cpu1:82.9"],
            out var usage);

        Assert.True(parsed);
        Assert.Equal(31.2, usage.TotalUsagePercent, precision: 1);
        Assert.Equal(2, usage.Cores.Count);
        Assert.Equal("cpu1", usage.Cores[1].Name);
        Assert.Equal(82.9, usage.Cores[1].UsagePercent, precision: 1);
    }

    [Fact]
    public void TryParseCpuUsage_UsesAverageWhenTotalIsMissing()
    {
        var parsed = SshLogStreamService.TryParseCpuUsage(
            ["cpu0:10", "cpu1:30"],
            out var usage);

        Assert.True(parsed);
        Assert.Equal(20, usage.TotalUsagePercent, precision: 1);
    }
}
