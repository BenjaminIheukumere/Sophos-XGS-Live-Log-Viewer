using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.App.Services;

public static class LogColumnPolicy
{
    public const int MaxDefaultFieldColumns = 10;

    private static readonly HashSet<string> DefaultExcludedFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "log_type",
        "status"
    };

    private static readonly HashSet<string> FastModeHiddenFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "source"
    };

    public static IReadOnlyList<string> PreferredFieldOrder { get; } =
    [
        "log_type", "log_component", "log_subtype", "status", "message", "reason", "severity",
        "src_ip", "src_port", "src_country", "dst_ip", "dst_port", "dst_country", "protocol",
        "in_interface", "in_display_interface", "out_interface", "out_display_interface",
        "fw_rule_id", "fw_rule_name", "fw_rule_section", "nat_rule_id", "nat_rule_name",
        "user", "user_name", "user_group", "web_policy_id", "web_policy", "category", "category_type",
        "url", "domain", "app_name", "app_category", "app_risk", "ips_policy_id", "appfilter_policy_id",
        "bytes_sent", "bytes_received", "sent_bytes", "recv_bytes", "packets_sent", "packets_received",
        "con_id", "con_event", "datetime", "tz_offset", "messageid", "device_name"
    ];

    public static List<string> SelectDefaultFields(LogDefinition activeLog, IEnumerable<string> availableFields)
    {
        var available = availableFields
            .Where(field => !string.IsNullOrWhiteSpace(field))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (available.Count == 0)
        {
            return [];
        }

        var order = DefaultOrderFor(activeLog)
            .Concat(PreferredFieldOrder)
            .Concat(available.OrderBy(field => field, StringComparer.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return order
            .Where(field => available.Contains(field, StringComparer.OrdinalIgnoreCase))
            .Where(field => !DefaultExcludedFields.Contains(field))
            .Take(MaxDefaultFieldColumns)
            .ToList();
    }

    public static bool IsFastModeHiddenField(string field)
    {
        return FastModeHiddenFields.Contains(field);
    }

    public static IReadOnlyList<string> DefaultOrderFor(LogDefinition activeLog)
    {
        return activeLog.Key switch
        {
            "firewall" =>
            [
                "log_component", "log_subtype", "status", "src_ip", "dst_ip", "dst_port",
                "protocol", "fw_rule_id", "fw_rule_name", "in_interface", "out_interface"
            ],
            "web_filter" or "web_content_policy" or "ssl_tls_inspection" =>
            [
                "log_component", "log_subtype", "status", "src_ip", "user_name", "dst_ip",
                "dst_port", "domain", "url", "category"
            ],
            "web_server_protection" =>
            [
                "log_component", "log_subtype", "status", "src_ip", "dst_ip", "dst_port",
                "protocol", "domain", "url", "message"
            ],
            "ips" or "application_filter" =>
            [
                "log_component", "log_subtype", "status", "src_ip", "dst_ip", "dst_port",
                "protocol", "app_name", "signature_msg", "message"
            ],
            "vpn" =>
            [
                "log_component", "log_subtype", "status", "user_name", "src_ip", "dst_ip",
                "protocol", "message", "reason", "device_name"
            ],
            "admin" or "authentication" =>
            [
                "log_component", "log_subtype", "status", "user_name", "src_ip", "dst_ip",
                "message", "reason", "device_name", "priority"
            ],
            "email" =>
            [
                "log_component", "log_subtype", "status", "src_ip", "dst_ip", "sender",
                "recipient", "subject", "message", "reason"
            ],
            "lets_encrypt" =>
            [
                "log_component", "log_subtype", "status", "domain", "message", "reason",
                "device_name", "log_file", "severity", "priority"
            ],
            "malware" or "zero_day_protection" or "active_threat_response" =>
            [
                "log_component", "log_subtype", "status", "src_ip", "dst_ip", "user_name",
                "file_name", "url", "message", "reason"
            ],
            "sd_wan" =>
            [
                "log_component", "log_subtype", "status", "src_ip", "dst_ip", "dst_port",
                "protocol", "gw_name", "profile_name", "message"
            ],
            "system" or "security_heartbeat" =>
            [
                "log_component", "log_subtype", "status", "device_name", "src_ip", "dst_ip",
                "user_name", "message", "reason", "priority"
            ],
            _ =>
            [
                "log_component", "log_subtype", "status", "src_ip", "dst_ip", "dst_port",
                "protocol", "user_name", "message", "reason"
            ]
        };
    }
}
