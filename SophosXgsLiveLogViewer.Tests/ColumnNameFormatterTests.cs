using SophosXgsLiveLogViewer.App.Services;
using SophosXgsLiveLogViewer.App.ViewModels;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class ColumnNameFormatterTests
{
    [Theory]
    [InlineData("dstip", "Destination IP")]
    [InlineData("dst_ip", "Destination IP")]
    [InlineData("src_ip", "Source IP")]
    [InlineData("fw_rule_name", "Firewall Rule Name")]
    [InlineData("nat_rule_id", "NAT Rule ID")]
    [InlineData("url", "URL")]
    public void ToDisplayName_NormalizesKnownSophosFields(string key, string expected)
    {
        Assert.Equal(expected, ColumnNameFormatter.ToDisplayName(key));
    }

    [Fact]
    public void FilterCondition_DisplayTextUsesNormalizedFieldName()
    {
        var condition = new FilterCondition
        {
            Connector = "AND",
            Field = "dst_ip",
            Operator = "Equals",
            Value = "8.8.8.8"
        };

        Assert.Equal("AND Destination IP Equals 8.8.8.8", condition.DisplayText);
    }

    [Fact]
    public void FieldOption_ToStringUsesNormalizedFieldName()
    {
        var option = new FieldOption("dst_ip");

        Assert.Equal("Destination IP", option.ToString());
    }
}
