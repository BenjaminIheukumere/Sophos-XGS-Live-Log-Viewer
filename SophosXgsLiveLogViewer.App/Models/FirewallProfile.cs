namespace SophosXgsLiveLogViewer.App.Models;

public sealed class FirewallProfile
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public string Name { get; set; } = string.Empty;

    public string Host { get; set; } = string.Empty;

    public int Port { get; set; } = 22;

    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public string? ExpectedHostKeySha256 { get; set; }

    public bool UseSophosAdvancedShell { get; set; } = true;

    public LogSourceMode SourceMode { get; set; } = LogSourceMode.SophosEventDatabase;

    public List<string> SelectedLogKeys { get; set; } = ["firewall"];

    public string ExtraLogFiles { get; set; } = string.Empty;

    public FirewallProfile Clone()
    {
        return new FirewallProfile
        {
            Id = Id,
            Name = Name,
            Host = Host,
            Port = Port,
            Username = Username,
            Password = Password,
            ExpectedHostKeySha256 = ExpectedHostKeySha256,
            UseSophosAdvancedShell = UseSophosAdvancedShell,
            SourceMode = SourceMode,
            SelectedLogKeys = [.. SelectedLogKeys],
            ExtraLogFiles = ExtraLogFiles
        };
    }

    public override string ToString()
    {
        return Name;
    }
}
