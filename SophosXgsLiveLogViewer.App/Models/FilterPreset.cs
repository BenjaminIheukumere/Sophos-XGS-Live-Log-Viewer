namespace SophosXgsLiveLogViewer.App.Models;

public sealed class FilterPreset
{
    public int Version { get; set; } = 1;

    public string Name { get; set; } = string.Empty;

    public string LogKey { get; set; } = "firewall";

    public string LogName { get; set; } = "Firewall";

    public List<FilterConditionPreset> Conditions { get; set; } = [];
}

public sealed class FilterConditionPreset
{
    public string Connector { get; set; } = "AND";

    public string Field { get; set; } = string.Empty;

    public string Operator { get; set; } = "Equals";

    public string Value { get; set; } = string.Empty;
}
