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

    [Theory]
    [InlineData("Are you sure you want to Continue (y/n):")]
    [InlineData("ACCESS WARNING\r\nAre you sure you want to Continue (y/n):")]
    [InlineData("Custom banner. Do you want to proceed yes/no?")]
    public void IsLoginBannerConfirmationPrompt_DetectsContinuePrompt(string text)
    {
        Assert.True(SshLogStreamService.IsLoginBannerConfirmationPrompt(text));
    }

    [Theory]
    [InlineData("Main Menu")]
    [InlineData("SFOS 22.0.0 GA-Build")]
    [InlineData("Certificate renewed successfully")]
    public void IsLoginBannerConfirmationPrompt_IgnoresNormalShellOutput(string text)
    {
        Assert.False(SshLogStreamService.IsLoginBannerConfirmationPrompt(text));
    }
}
