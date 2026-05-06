using System.Text.RegularExpressions;

namespace SophosXgsLiveLogViewer.App.Services;

public static partial class ColumnNameFormatter
{
    private static readonly Dictionary<string, string> KnownNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ["time"] = "Time",
        ["datetime"] = "Date Time",
        ["timestamp"] = "Timestamp",
        ["log_type"] = "Log Type",
        ["logtype"] = "Log Type",
        ["log_component"] = "Log Component",
        ["logcomponent"] = "Log Component",
        ["log_subtype"] = "Log Subtype",
        ["logsubtype"] = "Log Subtype",
        ["status"] = "Status",
        ["action"] = "Action",
        ["message"] = "Message",
        ["reason"] = "Reason",
        ["severity"] = "Severity",
        ["priority"] = "Priority",
        ["src_ip"] = "Source IP",
        ["source_ip"] = "Source IP",
        ["sourceip"] = "Source IP",
        ["srcip"] = "Source IP",
        ["dst_ip"] = "Destination IP",
        ["destination_ip"] = "Destination IP",
        ["destinationip"] = "Destination IP",
        ["dstip"] = "Destination IP",
        ["dest_ip"] = "Destination IP",
        ["destip"] = "Destination IP",
        ["src_port"] = "Source Port",
        ["source_port"] = "Source Port",
        ["dst_port"] = "Destination Port",
        ["destination_port"] = "Destination Port",
        ["dest_port"] = "Destination Port",
        ["protocol"] = "Protocol",
        ["in_interface"] = "In Interface",
        ["in_display_interface"] = "In Interface",
        ["out_interface"] = "Out Interface",
        ["out_display_interface"] = "Out Interface",
        ["fw_rule_id"] = "Firewall Rule ID",
        ["fw_rule_name"] = "Firewall Rule Name",
        ["fw_rule_section"] = "Firewall Rule Section",
        ["nat_rule_id"] = "NAT Rule ID",
        ["nat_rule_name"] = "NAT Rule Name",
        ["user"] = "User",
        ["username"] = "Username",
        ["user_name"] = "Username",
        ["user_group"] = "User Group",
        ["web_policy"] = "Web Policy",
        ["web_policy_id"] = "Web Policy ID",
        ["category"] = "Category",
        ["category_type"] = "Category Type",
        ["url"] = "URL",
        ["domain"] = "Domain",
        ["app_name"] = "Application",
        ["app_category"] = "Application Category",
        ["app_risk"] = "Application Risk",
        ["signature_id"] = "Signature ID",
        ["signature_msg"] = "Signature Message",
        ["classification"] = "Classification",
        ["bytes_sent"] = "Bytes Sent",
        ["bytes_received"] = "Bytes Received",
        ["sent_bytes"] = "Bytes Sent",
        ["recv_bytes"] = "Bytes Received",
        ["packets_sent"] = "Packets Sent",
        ["packets_received"] = "Packets Received",
        ["con_id"] = "Connection ID",
        ["con_event"] = "Connection Event",
        ["device_name"] = "Device Name",
        ["messageid"] = "Message ID",
        ["tz_offset"] = "Time Zone Offset",
        ["file_name"] = "File Name",
        ["gateway_name"] = "Gateway Name",
        ["gw_name"] = "Gateway Name",
        ["profile_name"] = "Profile Name",
        ["hb_status"] = "Heartbeat Status"
    };

    public static string ToDisplayName(string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        var normalized = key.Trim();
        if (KnownNames.TryGetValue(normalized, out var known))
        {
            return known;
        }

        var words = WordSplitRegex()
            .Replace(normalized, " ")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        return string.Join(' ', words.Select(FormatWord));
    }

    private static string FormatWord(string word)
    {
        var lower = word.ToLowerInvariant();
        return lower switch
        {
            "id" => "ID",
            "ip" => "IP",
            "url" => "URL",
            "uri" => "URI",
            "mac" => "MAC",
            "dns" => "DNS",
            "dhcp" => "DHCP",
            "ssl" => "SSL",
            "tls" => "TLS",
            "ips" => "IPS",
            "idp" => "IDP",
            "vpn" => "VPN",
            "cpu" => "CPU",
            "nat" => "NAT",
            "waf" => "WAF",
            "ha" => "HA",
            "wan" => "WAN",
            "lan" => "LAN",
            "http" => "HTTP",
            "https" => "HTTPS",
            "sni" => "SNI",
            _ => char.ToUpperInvariant(lower[0]) + lower[1..]
        };
    }

    [GeneratedRegex(@"[_\-.]+|(?<=[a-z0-9])(?=[A-Z])", RegexOptions.Compiled)]
    private static partial Regex WordSplitRegex();
}
