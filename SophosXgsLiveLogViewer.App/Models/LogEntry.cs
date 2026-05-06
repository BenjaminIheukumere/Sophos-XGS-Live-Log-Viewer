namespace SophosXgsLiveLogViewer.App.Models;

public sealed class LogEntry
{
    public DateTimeOffset OccurredAt { get; init; } = DateTimeOffset.Now;

    public string SourceLogFile { get; init; } = string.Empty;

    public string LogType { get; init; } = string.Empty;

    public string Component { get; init; } = string.Empty;

    public string Subtype { get; init; } = string.Empty;

    public string Status { get; init; } = string.Empty;

    public string Username { get; init; } = string.Empty;

    public string FirewallRule { get; init; } = string.Empty;

    public string FirewallRuleName { get; init; } = string.Empty;

    public string NatRule { get; init; } = string.Empty;

    public string NatRuleName { get; init; } = string.Empty;

    public string InInterface { get; init; } = string.Empty;

    public string OutInterface { get; init; } = string.Empty;

    public string SourceIp { get; init; } = string.Empty;

    public string DestinationIp { get; init; } = string.Empty;

    public string SourcePort { get; init; } = string.Empty;

    public string DestinationPort { get; init; } = string.Empty;

    public string Protocol { get; init; } = string.Empty;

    public string Message { get; init; } = string.Empty;

    public string RawLine { get; init; } = string.Empty;

    public LogDisposition Disposition { get; init; } = LogDisposition.Neutral;

    public IReadOnlyDictionary<string, string> Fields { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}
