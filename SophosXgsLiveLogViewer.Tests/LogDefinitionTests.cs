using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class LogDefinitionTests
{
    [Fact]
    public void MatchesEvent_MapsFirewallEvents()
    {
        var definition = LogDefinition.Find("firewall");
        var entry = new LogEntry
        {
            LogType = "Firewall",
            Component = "Firewall Rule"
        };

        Assert.NotNull(definition);
        Assert.True(definition.MatchesEvent(entry));
    }

    [Fact]
    public void MatchesEvent_MapsWebFilterEvents()
    {
        var definition = LogDefinition.Find("web_filter");
        var entry = new LogEntry
        {
            LogType = "Content Filtering",
            Component = "HTTP"
        };

        Assert.NotNull(definition);
        Assert.True(definition.MatchesEvent(entry));
    }

    [Fact]
    public void MatchesEvent_MapsIpsEvents()
    {
        var definition = LogDefinition.Find("ips");
        var entry = new LogEntry
        {
            LogType = "IDP",
            Component = "Signatures"
        };

        Assert.NotNull(definition);
        Assert.True(definition.MatchesEvent(entry));
    }

    [Fact]
    public void MatchesEvent_MapsTroubleshootingFileSource()
    {
        var definition = LogDefinition.Find("system");
        var entry = new LogEntry
        {
            SourceLogFile = "/log/syslog.log",
            LogType = "File",
            Component = "syslog.log"
        };

        Assert.NotNull(definition);
        Assert.True(definition.MatchesEvent(entry));
    }

    [Fact]
    public void MatchesEvent_MapsLetsEncryptLogFile()
    {
        var definition = LogDefinition.Find("lets_encrypt");
        var entry = new LogEntry
        {
            SourceLogFile = "/log/letsencrypt.log",
            LogType = "File",
            Component = "letsencrypt.log",
            Message = "ACME certificate renewed successfully"
        };

        Assert.NotNull(definition);
        Assert.Equal("Let's Encrypt", definition.DisplayName);
        Assert.True(definition.MatchesEvent(entry));
    }

    [Fact]
    public void ToString_ReturnsDisplayName()
    {
        var definition = LogDefinition.Find("web_filter");

        Assert.NotNull(definition);
        Assert.Equal("Web filter", definition.ToString());
    }
}
