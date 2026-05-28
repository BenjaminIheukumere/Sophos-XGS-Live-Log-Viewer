using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.App.Services;

public sealed class DemoLogStreamService
{
    private static readonly string[] SourceIps =
    [
        "192.168.178.20",
        "192.168.200.222",
        "10.10.42.17",
        "172.16.8.44",
        "23.234.70.214",
        "185.213.193.47"
    ];

    private static readonly string[] DestinationIps =
    [
        "8.8.8.8",
        "1.1.1.1",
        "52.215.148.173",
        "91.189.95.15",
        "184.32.216.13",
        "34.238.225.186"
    ];

    private static readonly int[] DestinationPorts = [53, 80, 123, 443, 4443, 8080];

    public async Task RunAsync(
        IReadOnlyCollection<LogDefinition> selectedLogs,
        LogFilter filter,
        Action<LogEntry> onEntry,
        Action<string> onStatus,
        Action<string> onDiagnostic,
        CancellationToken cancellationToken)
    {
        onStatus("Demo stream active. Local Sophos v22 event fixtures are being generated.");
        onDiagnostic("Demo source: no firewall connection is used.");
        onDiagnostic("This validates UI, parser, category filters, row coloring, and live refresh locally.");

        var selected = selectedLogs.Count > 0 ? selectedLogs.ToList() : LogDefinition.All.ToList();
        var index = 0;

        while (!cancellationToken.IsCancellationRequested)
        {
            var logDefinition = selected[index % selected.Count];
            var raw = BuildSample(logDefinition, index);

            if (SophosLogParser.TryParse(raw, "demo", out var entry) && entry is not null && filter.IsMatch(entry))
            {
                onEntry(entry);
            }

            index++;
            await Task.Delay(150, cancellationToken).ConfigureAwait(false);
        }
    }

    private static string BuildSample(LogDefinition logDefinition, int index)
    {
        var src = SourceIps[index % SourceIps.Length];
        var dst = DestinationIps[(index / 2) % DestinationIps.Length];
        var dstPort = DestinationPorts[index % DestinationPorts.Length];
        var srcPort = 42000 + (index % 20000);
        var denied = index % 5 == 0;
        var status = denied ? "Deny" : "Allow";
        var subtype = denied ? "Denied" : "Allowed";
        var timestamp = DateTimeOffset.Now.ToString("yyyy-MM-ddTHH:mm:sszzz");

        return logDefinition.Key switch
        {
            "web_filter" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_id", "050901616001"), ("log_type", "Content Filtering"), ("log_component", "HTTP"), ("log_subtype", subtype), ("status", status), ("severity", "Information"), ("fw_rule_id", "12"), ("fw_rule_name", "LAN to WAN"), ("user_name", "demo.user"), ("category", "Information Technology"), ("url", $"https://example{index % 9}.com/path"), ("src_ip", src), ("dst_ip", dst), ("protocol", "TCP"), ("src_port", srcPort.ToString()), ("dst_port", dstPort.ToString()), ("domain", $"example{index % 9}.com"), ("reason", denied ? "policy blocked" : "clean"), ("message", denied ? "Web request blocked by policy" : "Web request allowed")),
            "web_content_policy" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_id", "058420116010"), ("log_type", "Content Filtering"), ("log_component", "Web Content Policy"), ("log_subtype", "Alert"), ("action", status), ("severity", "Information"), ("user_name", "demo.user"), ("src_ip", src), ("dst_ip", dst), ("dst_port", dstPort.ToString()), ("website", "blocked-demo.local"), ("dictionary_name", "Demo Policy"), ("message", "Web content policy matched")),
            "ips" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_id", "020703406001"), ("log_type", "IDP"), ("log_component", "Signatures"), ("log_subtype", denied ? "Drop" : "Detect"), ("severity", "Warning"), ("status", status), ("idp_policy_id", "1"), ("fw_rule_id", "12"), ("signature_id", "26022"), ("signature_msg", "Demo IPS signature"), ("classification", "A Network Trojan was detected"), ("src_ip", src), ("dst_ip", dst), ("protocol", "TCP"), ("src_port", srcPort.ToString()), ("dst_port", dstPort.ToString()), ("category", "Malware Communication"), ("message", "Demo IPS event")),
            "ssl_tls_inspection" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_id", "148532619005"), ("log_type", "SSL"), ("log_component", "SSL"), ("log_subtype", denied ? "Reject" : "Decrypt"), ("severity", "Information"), ("status", status), ("src_ip", src), ("dst_ip", dst), ("src_port", srcPort.ToString()), ("dst_port", "443"), ("rule_id", "3"), ("rule_name", "TLS inspection"), ("sni", "demo.sophos.local"), ("reason", denied ? "Blocked due to web policy" : "Decrypted")),
            "web_server_protection" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("messageid", "17071"), ("log_type", "WAF"), ("log_component", "Web Application Firewall"), ("log_subtype", subtype), ("status", status), ("user", "-"), ("server", "demo-waf"), ("src_ip", src), ("local_ip", dst), ("protocol", "HTTP/1.1"), ("url", "/demo"), ("method", "GET"), ("response_code", denied ? "403" : "200"), ("reason", denied ? "policy" : "-"), ("fw_rule_id", "2"), ("message", "WAF demo event")),
            "vpn" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("messageid", "17824"), ("log_type", "Event"), ("log_component", "SSL VPN"), ("log_subtype", "System"), ("status", denied ? "Failed" : "Established"), ("severity", "Information"), ("user_name", "vpn.user"), ("src_ip", src), ("dst_ip", dst), ("bytes_sent", "1024"), ("bytes_received", "2048"), ("message", "SSL VPN demo event")),
            "authentication" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_id", "062109517507"), ("log_type", "Event"), ("log_component", "Authentication"), ("log_subtype", "Admin"), ("status", denied ? "Failed" : "Successful"), ("severity", "Notice"), ("user_name", "admin"), ("src_ip", src), ("message", "Demo authentication event")),
            "system" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_id", "066811618014"), ("log_type", "Event"), ("log_component", "System"), ("log_subtype", "System"), ("status", "Successful"), ("severity", "Information"), ("src_ip", src), ("message", "System demo event")),
            "email" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_type", "Email"), ("log_component", "SMTP"), ("log_subtype", subtype), ("status", status), ("severity", "Information"), ("src_ip", src), ("dst_ip", dst), ("src_port", srcPort.ToString()), ("dst_port", "25"), ("sender", "sender@example.com"), ("recipient", "receiver@example.com"), ("message", "SMTP demo event")),
            "lets_encrypt" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_type", "Let's Encrypt"), ("log_component", "letsencrypt.log"), ("log_subtype", denied ? "Renewal failed" : "Renewal successful"), ("status", denied ? "Failed" : "Successful"), ("severity", denied ? "Warning" : "Information"), ("domain", $"vpn{index % 4}.demo.local"), ("message", denied ? "ACME certificate renewal failed" : "ACME certificate renewed successfully")),
            "malware" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_type", "Anti-Virus"), ("log_component", "HTTP/HTTPS"), ("log_subtype", denied ? "Virus" : "Clean"), ("status", status), ("severity", "Critical"), ("src_ip", src), ("dst_ip", dst), ("src_port", srcPort.ToString()), ("dst_port", dstPort.ToString()), ("malware", "EICAR-Test-File"), ("url", "https://malware-demo.local/eicar"), ("message", denied ? "Malware was detected and blocked" : "File scanned clean")),
            "application_filter" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_type", "Content Filtering"), ("log_component", "Application"), ("log_subtype", subtype), ("status", status), ("severity", "Information"), ("src_ip", src), ("dst_ip", dst), ("src_port", srcPort.ToString()), ("dst_port", dstPort.ToString()), ("app_name", "DemoApp"), ("app_category", "Collaboration"), ("message", "Application filter demo event")),
            "sd_wan" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_type", "SD-WAN"), ("log_component", "SD-WAN"), ("log_subtype", "Route"), ("status", status), ("severity", "Information"), ("src_ip", src), ("dst_ip", dst), ("src_port", srcPort.ToString()), ("dst_port", dstPort.ToString()), ("gateway_name", "gw-demo"), ("message", "SD-WAN route demo event")),
            "security_heartbeat" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_type", "Heartbeat"), ("log_component", "Heartbeat"), ("log_subtype", "Endpoint"), ("status", denied ? "Failed" : "Successful"), ("severity", "Information"), ("src_ip", src), ("dst_ip", dst), ("hb_status", denied ? "Missing Heartbeat" : "Healthy"), ("message", "Security Heartbeat demo event")),
            "active_threat_response" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_type", "ATP"), ("log_component", "Active Threat Response"), ("log_subtype", subtype), ("status", status), ("severity", "Warning"), ("src_ip", src), ("dst_ip", dst), ("message", "Threat feed IOC demo match")),
            "zero_day_protection" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_type", "Sandbox"), ("log_component", "Sandbox"), ("log_subtype", denied ? "Malicious" : "Clean"), ("status", status), ("severity", "Warning"), ("src_ip", src), ("dst_ip", dst), ("file_name", "demo.exe"), ("message", "Zero-day protection demo event")),
            "admin" => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_type", "Event"), ("log_component", "Admin"), ("log_subtype", "Configuration"), ("status", "Successful"), ("severity", "Information"), ("user_name", "admin"), ("src_ip", src), ("message", "Administrator changed demo object")),
            _ => Kv(("device_name", "SFW"), ("timestamp", timestamp), ("log_type", "Firewall"), ("log_component", "Firewall Rule"), ("log_subtype", subtype), ("status", status), ("severity", "Information"), ("fw_rule_id", "12"), ("fw_rule_name", "LAN to WAN"), ("nat_rule_id", "2"), ("in_interface", "Port1"), ("out_interface", "Port2"), ("src_ip", src), ("dst_ip", dst), ("protocol", "TCP"), ("src_port", srcPort.ToString()), ("dst_port", dstPort.ToString()), ("message", denied ? "Packet blocked by firewall rule" : "Packet allowed by firewall rule"))
        };
    }

    private static string Kv(params (string Key, string Value)[] fields)
    {
        return string.Join(' ', fields.Select(field => $"{field.Key}=\"{field.Value.Replace("\"", "\\\"", StringComparison.Ordinal)}\""));
    }
}
