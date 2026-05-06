using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class FirewallProfileTests
{
    [Fact]
    public void Clone_PreservesSourceMode()
    {
        var profile = new FirewallProfile
        {
            SourceMode = LogSourceMode.Demo
        };

        var clone = profile.Clone();

        Assert.Equal(LogSourceMode.Demo, clone.SourceMode);
    }
}
