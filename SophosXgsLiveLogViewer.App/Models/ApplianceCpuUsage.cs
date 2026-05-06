namespace SophosXgsLiveLogViewer.App.Models;

public sealed record CpuCoreUsage(string Name, double UsagePercent);

public sealed record ApplianceCpuUsage(DateTimeOffset ObservedAt, double TotalUsagePercent, IReadOnlyList<CpuCoreUsage> Cores);
