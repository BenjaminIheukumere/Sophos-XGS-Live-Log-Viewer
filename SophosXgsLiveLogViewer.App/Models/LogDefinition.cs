namespace SophosXgsLiveLogViewer.App.Models;

public sealed record LogDefinition(string Key, string DisplayName, IReadOnlyList<string> TroubleshootingFiles)
{
    public static IReadOnlyList<LogDefinition> All { get; } =
    [
        new("admin", "Admin", ["/log/applog.log", "/log/csc.log"]),
        new("active_threat_response", "Active threat response", ["/log/atr.log", "/log/atr-service.log"]),
        new("application_filter", "Application filter", ["/log/ips.log", "/log/appcached.log"]),
        new("authentication", "Authentication", ["/log/access_server.log", "/log/nasm.log"]),
        new("email", "Email", ["/log/awarrensmtp.log", "/log/warren.log", "/log/smtpd_main.log", "/log/smtpd_reject.log", "/log/sasi.log"]),
        new("firewall", "Firewall", ["/log/fwlog.log", "/log/firewall_rule.log"]),
        new("ips", "IPS", ["/log/ips.log"]),
        new("malware", "Malware", ["/log/avd.log", "/log/sandboxd.log"]),
        new("security_heartbeat", "Security Heartbeat", ["/log/heartbeatd.log", "/log/hbtrust.log"]),
        new("ssl_tls_inspection", "SSL/TLS inspection", ["/log/ips.log", "/log/httplogd.log"]),
        new("sd_wan", "SD-WAN", ["/log/appcached.log", "/log/dgd.log"]),
        new("system", "System", ["/log/syslog.log", "/log/applog.log"]),
        new("vpn", "VPN", ["/log/strongswan.log", "/log/charon.log", "/log/sslvpn.log", "/log/ipsec_monitor.log"]),
        new("web_content_policy", "Web content policy", ["/log/awarrenhttp.log", "/log/nSXLd.log"]),
        new("web_filter", "Web filter", ["/log/awarrenhttp.log", "/log/httplogd.log", "/log/nSXLd.log"]),
        new("web_server_protection", "Web server protection", ["/log/reverseproxy.log"]),
        new("zero_day_protection", "Zero-day protection", ["/log/sandboxd.log"])
    ];

    public static LogDefinition? Find(string key)
    {
        return All.FirstOrDefault(log => string.Equals(log.Key, key, StringComparison.OrdinalIgnoreCase));
    }

    public override string ToString()
    {
        return DisplayName;
    }

    public bool MatchesEvent(LogEntry entry)
    {
        var type = entry.LogType;
        var component = entry.Component;
        var subtype = entry.Subtype;
        var message = entry.Message;

        return Key switch
        {
            "admin" => IsEvent(type) && ContainsAny(component, "Admin", "CLI", "WebAdmin", "GUI"),
            "active_threat_response" => ContainsAny(type, "ATP", "Active Threat") || ContainsAny(component, "ATP", "Active Threat", "MDR", "NDR"),
            "application_filter" => Is(type, "Content Filtering") && ContainsAny(component, "Application"),
            "authentication" => ContainsAny(type, "Authentication") || ContainsAny(component, "Authentication", "Access Gateway", "Captive", "SSO", "NTLM"),
            "email" => ContainsAny(type, "Email", "Anti-Spam") || ContainsAny(component, "SMTP", "IMAP", "POP", "Mail", "Anti-Spam"),
            "firewall" => Is(type, "Firewall"),
            "ips" => Is(type, "IDP") || ContainsAny(component, "IPS", "IDP", "Anomaly", "Signatures"),
            "malware" => Is(type, "Anti-Virus") || ContainsAny(subtype, "Virus", "PUA") || ContainsAny(message, "Malware", "Virus"),
            "security_heartbeat" => ContainsAny(type, "Heartbeat") || ContainsAny(component, "Heartbeat") || ContainsAny(entry.RawLine, "hb_status", "hb_health"),
            "ssl_tls_inspection" => Is(type, "SSL") || ContainsAny(component, "SSL"),
            "sd_wan" => Is(type, "SD-WAN") || ContainsAny(component, "SD-WAN"),
            "system" => IsEvent(type) && ContainsAny(component, "System", "HTTPS", "Gateway", "Interface", "HA", "RED", "DHCP", "DNS", "Appliance", "Version", "Health"),
            "vpn" => ContainsAny(type, "IPsec", "SSL VPN", "L2TP", "PPTP") || ContainsAny(component, "VPN", "IPsec", "SSL VPN", "L2TP", "PPTP"),
            "web_content_policy" => Is(type, "Content Filtering") && ContainsAny(component, "Web Content Policy"),
            "web_filter" => Is(type, "Content Filtering") && ContainsAny(component, "HTTP", "HTTPS"),
            "web_server_protection" => Is(type, "WAF") || ContainsAny(component, "Web Application Firewall"),
            "zero_day_protection" => Is(type, "Sandbox") || ContainsAny(type, "Zero Day", "Zero-day") || ContainsAny(component, "Sandbox"),
            _ => false
        };
    }

    private static bool IsEvent(string value)
    {
        return Is(value, "Event");
    }

    private static bool Is(string value, string expected)
    {
        return string.Equals(value, expected, StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsAny(string value, params string[] needles)
    {
        return needles.Any(needle => value.Contains(needle, StringComparison.OrdinalIgnoreCase));
    }
}
