using SophosXgsLiveLogViewer.App.Models;
using SophosXgsLiveLogViewer.App.Services;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class LogColumnPolicyTests
{
    [Fact]
    public void SelectDefaultFields_LimitsFirewallColumnsToImportantFields()
    {
        var log = LogDefinition.Find("firewall")!;
        string[] available =
        [
            "log_component", "log_subtype", "status", "src_ip", "src_port", "dst_ip", "dst_port",
            "protocol", "fw_rule_id", "fw_rule_name", "in_interface", "out_interface", "nat_rule_id",
            "nat_rule_name", "bytes_sent", "bytes_received", "packets_sent", "packets_received", "raw_id"
        ];

        var selected = LogColumnPolicy.SelectDefaultFields(log, available);

        Assert.True(selected.Count <= LogColumnPolicy.MaxDefaultFieldColumns);
        Assert.Contains("src_ip", selected);
        Assert.Contains("dst_ip", selected);
        Assert.Contains("dst_port", selected);
        Assert.DoesNotContain("raw_id", selected);
    }

    [Fact]
    public void SelectDefaultFields_OnlyUsesAvailableFields()
    {
        var log = LogDefinition.Find("web_filter")!;
        string[] available = ["src_ip", "url", "category", "unknown_extra"];

        var selected = LogColumnPolicy.SelectDefaultFields(log, available);

        Assert.All(selected, field => Assert.Contains(field, available));
    }
}
