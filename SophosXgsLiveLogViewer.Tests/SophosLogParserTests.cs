using SophosXgsLiveLogViewer.App.Models;
using SophosXgsLiveLogViewer.App.Services;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class SophosLogParserTests
{
    [Fact]
    public void Parse_NormalizesCommonFirewallFields()
    {
        const string raw = "device=\"SFW\" timestamp=\"2026-04-29T13:48:45+0200\" log_type=\"Firewall\" log_component=\"Firewall Rule\" log_subtype=\"Allowed\" status=\"Allow\" fw_rule_id=\"6\" fw_rule_name=\"LAN\" nat_rule_id=\"2\" in_interface=\"Port1\" out_interface=\"Port2\" src_ip=\"192.168.200.222\" dst_ip=\"62.153.148.173\" src_port=\"56087\" dst_port=\"443\" protocol=\"TCP\" message=\"ok\"";

        var entry = SophosLogParser.Parse(raw, "/log/fwlog.log");

        Assert.Equal("Firewall", entry.LogType);
        Assert.Equal("Firewall Rule", entry.Component);
        Assert.Equal("Allowed", entry.Subtype);
        Assert.Equal("Allow", entry.Status);
        Assert.Equal("192.168.200.222", entry.SourceIp);
        Assert.Equal("62.153.148.173", entry.DestinationIp);
        Assert.Equal("443", entry.DestinationPort);
        Assert.Equal(LogDisposition.Allowed, entry.Disposition);
    }

    [Fact]
    public void Parse_ClassifiesDeniedTraffic()
    {
        const string raw = "log_type=\"Firewall\" log_component=\"Appliance Access\" log_subtype=\"Denied\" status=\"Deny\" src_ip=\"23.234.70.214\" dst_ip=\"192.168.178.20\" dst_port=\"4443\" protocol=\"TCP\"";

        var entry = SophosLogParser.Parse(raw, "/log/fwlog.log");

        Assert.Equal(LogDisposition.Denied, entry.Disposition);
    }

    [Theory]
    [InlineData("0. Exit")]
    [InlineData("Device Management")]
    [InlineData("SFVH_S001_SFOS 22.0.0 GA-Build411# tail -f -n 50 '/log/fwlog.log'")]
    [InlineData("For Sophos End User Terms of Use - https://www.sophos.com/en-us/legal/sophos-end-user-terms-of-use.aspx")]
    public void TryParse_RejectsShellAndMenuNoise(string raw)
    {
        var parsed = SophosLogParser.TryParse(raw, string.Empty, out var entry);

        Assert.False(parsed);
        Assert.Null(entry);
    }

    [Fact]
    public void TryParseDatabaseRow_ParsesEventDbColumns()
    {
        string[] columns = ["rowid", "log_type", "log_component", "log_subtype", "status", "src_ip", "dst_ip", "dst_port", "protocol", "message"];
        string[] values = ["100", "Firewall", "Firewall Rule", "Denied", "Deny", "10.0.0.5", "8.8.8.8", "53", "UDP", "Blocked"];

        var parsed = SophosLogParser.TryParseDatabaseRow(columns, values, out var entry);

        Assert.True(parsed);
        Assert.NotNull(entry);
        Assert.Equal("Firewall", entry.LogType);
        Assert.Equal("10.0.0.5", entry.SourceIp);
        Assert.Equal(LogDisposition.Denied, entry.Disposition);
    }

    [Fact]
    public void TryParseDatabaseRow_ParsesRawJsonPayload()
    {
        string[] columns = ["rowid", "payload"];
        string[] values = ["101", """{"log_type":"Content Filtering","log_component":"HTTP","log_subtype":"Denied","status":"Deny","src_ip":"10.1.1.10","dst_ip":"203.0.113.5","dst_port":443,"message":"blocked"}"""];

        var parsed = SophosLogParser.TryParseDatabaseRow(columns, values, out var entry);

        Assert.True(parsed);
        Assert.NotNull(entry);
        Assert.Equal("Content Filtering", entry.LogType);
        Assert.Equal("HTTP", entry.Component);
        Assert.Equal("443", entry.DestinationPort);
        Assert.Equal(LogDisposition.Denied, entry.Disposition);
    }

    [Fact]
    public void TryParseDatabaseRow_ParsesRealSophosV22JsonShape()
    {
        string[] columns = ["rowid", "log"];
        string[] values =
        [
            "6752",
            """{ "device_name": "fw.example.local", "datetime": "2026-04-29 17:43:15", "tz_offset": "+0200", "log_type": "Firewall", "log_component": "Appliance Access", "log_subtype": "Denied", "status": "Deny", "fw_rule_id": "N\/A", "in_interface": "Port2", "src_ip": "146.70.211.180", "dst_ip": "192.168.178.20", "protocol": "TCP", "src_port": "65085", "dst_port": "4443", "message": "" }"""
        ];

        var parsed = SophosLogParser.TryParseDatabaseRow(columns, values, out var entry);

        Assert.True(parsed);
        Assert.NotNull(entry);
        Assert.Equal("Firewall", entry.LogType);
        Assert.Equal("Appliance Access", entry.Component);
        Assert.Equal("146.70.211.180", entry.SourceIp);
        Assert.Equal("4443", entry.DestinationPort);
        Assert.Equal(LogDisposition.Denied, entry.Disposition);
        Assert.Equal(17, entry.OccurredAt.Hour);
    }
}
