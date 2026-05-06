using SophosXgsLiveLogViewer.App.Models;
using SophosXgsLiveLogViewer.App.Services;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class DemoLogStreamServiceTests
{
    [Fact]
    public async Task RunAsync_EmitsParseableEntries()
    {
        var service = new DemoLogStreamService();
        var entries = new List<LogEntry>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));

        try
        {
            await service.RunAsync(
                LogDefinition.All,
                LogFilter.MatchAll,
                entry =>
                {
                    entries.Add(entry);
                    if (entries.Count >= 8)
                    {
                        cts.Cancel();
                    }
                },
                _ => { },
                _ => { },
                cts.Token);
        }
        catch (OperationCanceledException)
        {
        }

        Assert.True(entries.Count >= 8);
        Assert.Contains(entries, entry => entry.Disposition == LogDisposition.Denied);
        Assert.Contains(entries, entry => !string.IsNullOrWhiteSpace(entry.LogType));
    }
}
