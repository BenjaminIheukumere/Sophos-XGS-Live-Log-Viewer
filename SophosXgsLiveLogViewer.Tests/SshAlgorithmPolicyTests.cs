using SophosXgsLiveLogViewer.App.Models;
using SophosXgsLiveLogViewer.App.Services;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class SshAlgorithmPolicyTests
{
    [Fact]
    public void StrictMode_RemovesLegacySshAlgorithms()
    {
        var profile = new FirewallProfile
        {
            Host = "192.0.2.1",
            Username = "admin",
            Password = "secret",
            SshSecurityMode = SshSecurityMode.Strict
        };

        var connectionInfo = SshLogStreamService.CreateConnectionInfo(profile);

        Assert.False(connectionInfo.KeyExchangeAlgorithms.ContainsKey("diffie-hellman-group1-sha1"));
        Assert.False(connectionInfo.KeyExchangeAlgorithms.ContainsKey("diffie-hellman-group14-sha1"));
        Assert.False(connectionInfo.Encryptions.ContainsKey("3des-cbc"));
        Assert.False(connectionInfo.Encryptions.ContainsKey("aes128-cbc"));
        Assert.False(connectionInfo.HmacAlgorithms.ContainsKey("hmac-sha1"));
        Assert.False(connectionInfo.HostKeyAlgorithms.ContainsKey("ssh-rsa"));
    }

    [Fact]
    public void CompatibilityMode_KeepsDefaultSshAlgorithms()
    {
        var profile = new FirewallProfile
        {
            Host = "192.0.2.1",
            Username = "admin",
            Password = "secret",
            SshSecurityMode = SshSecurityMode.Compatibility
        };

        var connectionInfo = SshLogStreamService.CreateConnectionInfo(profile);

        Assert.True(connectionInfo.KeyExchangeAlgorithms.ContainsKey("diffie-hellman-group1-sha1"));
        Assert.True(connectionInfo.Encryptions.ContainsKey("3des-cbc"));
        Assert.True(connectionInfo.HmacAlgorithms.ContainsKey("hmac-sha1"));
    }
}
