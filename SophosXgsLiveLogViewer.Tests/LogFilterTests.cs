using SophosXgsLiveLogViewer.App.Models;
using SophosXgsLiveLogViewer.App.Services;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class LogFilterTests
{
    [Fact]
    public void Compile_MatchesCombinedIpAndPortFilter()
    {
        var filter = LogFilter.Compile("SourceIP IN (192.168.1.10,192.168.1.11) AND NOT SourceIP 192.168.1.99 AND DestinationIP 8.8.8.8 AND DestinationPort 443");
        var entry = new LogEntry
        {
            SourceIp = "192.168.1.10",
            DestinationIp = "8.8.8.8",
            DestinationPort = "443"
        };

        Assert.True(filter.IsMatch(entry));
    }

    [Fact]
    public void Compile_RejectsNegatedSource()
    {
        var filter = LogFilter.Compile("SourceIP IN (192.168.1.10,192.168.1.11) AND NOT SourceIP 192.168.1.10");
        var entry = new LogEntry
        {
            SourceIp = "192.168.1.10"
        };

        Assert.False(filter.IsMatch(entry));
    }

    [Fact]
    public void Compile_SupportsContainsOperator()
    {
        var filter = LogFilter.Compile("message:blocked AND protocol TCP");
        var entry = new LogEntry
        {
            Message = "Packet blocked by firewall rule",
            Protocol = "TCP"
        };

        Assert.True(filter.IsMatch(entry));
    }
}
