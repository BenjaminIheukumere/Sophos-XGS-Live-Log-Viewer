using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.App.Services;

public static partial class SophosLogParser
{
    public static bool TryParse(string rawLine, string sourceLogFile, out LogEntry? entry)
    {
        entry = null;
        var fields = ParseFields(rawLine);
        NormalizeAliases(fields);

        if (!LooksLikeSophosLog(fields))
        {
            return false;
        }

        entry = BuildEntry(rawLine, sourceLogFile, fields);
        return true;
    }

    public static LogEntry Parse(string rawLine, string sourceLogFile)
    {
        var fields = ParseFields(rawLine);
        NormalizeAliases(fields);

        return BuildEntry(rawLine, sourceLogFile, fields);
    }

    public static bool TryParseDatabaseRow(IReadOnlyList<string> columns, IReadOnlyList<string> values, out LogEntry? entry)
    {
        entry = null;

        if (columns.Count == 0 || values.Count == 0)
        {
            return false;
        }

        for (var index = 0; index < values.Count; index++)
        {
            if (values[index].Contains("log_type=", StringComparison.OrdinalIgnoreCase)
                && TryParse(values[index], "eventdb", out entry))
            {
                return true;
            }

            if (TryParseJsonLog(values[index], out var jsonFields))
            {
                NormalizeAliases(jsonFields);
                if (LooksLikeSophosLog(jsonFields))
                {
                    entry = BuildEntry(values[index], "eventdb", jsonFields);
                    return true;
                }
            }
        }

        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var count = Math.Min(columns.Count, values.Count);
        for (var index = 0; index < count; index++)
        {
            var column = columns[index].Trim();
            if (string.IsNullOrWhiteSpace(column))
            {
                continue;
            }

            fields[column] = values[index].Trim();
        }

        NormalizeAliases(fields);
        if (!LooksLikeSophosLog(fields))
        {
            return false;
        }

        var rawLine = string.Join(' ', fields
            .Where(pair => !string.IsNullOrWhiteSpace(pair.Value))
            .Select(pair => $"{pair.Key}=\"{pair.Value.Replace("\"", "\\\"", StringComparison.Ordinal)}\""));

        entry = BuildEntry(rawLine, "eventdb", fields);
        return true;
    }

    public static bool TryParseConntrack(string rawLine, out LogEntry? entry)
    {
        var entries = ParseConntrackFastEvents(rawLine);
        entry = entries.FirstOrDefault(entry => string.Equals(entry.LogType, "Firewall", StringComparison.OrdinalIgnoreCase));
        return entry is not null;
    }

    public static IReadOnlyList<LogEntry> ParseConntrackFastEvents(string rawLine)
    {
        if (string.IsNullOrWhiteSpace(rawLine)
            || !rawLine.Contains("orig-src=", StringComparison.OrdinalIgnoreCase)
            || !rawLine.Contains("orig-dst=", StringComparison.OrdinalIgnoreCase))
        {
            return [];
        }

        var fields = ParseFields(rawLine);
        NormalizeAliases(fields);

        if (!fields.ContainsKey("src_ip") || !fields.ContainsKey("dst_ip"))
        {
            return [];
        }

        var eventMatch = ConntrackEventRegex().Match(rawLine);
        if (eventMatch.Success)
        {
            fields["conntrack_event"] = eventMatch.Groups["event"].Value;
        }

        var action = fields.TryGetValue("fw_action", out var fwAction) ? fwAction : string.Empty;
        if (string.Equals(action, "1", StringComparison.OrdinalIgnoreCase))
        {
            fields["status"] = "Allow";
            fields["log_subtype"] = "Allowed";
        }
        else if (string.Equals(action, "0", StringComparison.OrdinalIgnoreCase))
        {
            fields["status"] = "Deny";
            fields["log_subtype"] = "Denied";
        }

        if (fields.TryGetValue("startstamp", out var startStamp) && !fields.ContainsKey("event_timestamp"))
        {
            fields["event_timestamp"] = startStamp;
        }

        var entries = new List<LogEntry>
        {
            BuildFastConntrackEntry(rawLine, fields, "Firewall", IsNonZero(fields, "fw_rule_id") ? "Firewall Rule" : "Appliance Access", "Firewall")
        };

        if (IsNonZero(fields, "webfltid") || IsNonZero(fields, "catid"))
        {
            entries.Add(BuildFastConntrackEntry(rawLine, fields, "Content Filtering", "HTTP", "Web filter"));
            entries.Add(BuildFastConntrackEntry(rawLine, fields, "Content Filtering", "Web Content Policy", "Web content policy"));
        }

        if (IsNonZero(fields, "appfltid") || IsNonZero(fields, "appid") || IsNonZero(fields, "appcatid"))
        {
            entries.Add(BuildFastConntrackEntry(rawLine, fields, "Content Filtering", "Application", "Application filter"));
        }

        if (IsNonZero(fields, "ips") || IsNonZero(fields, "ipspid") || IsNonZero(fields, "ips_nfqueue"))
        {
            entries.Add(BuildFastConntrackEntry(rawLine, fields, "IDP", "IPS", "IPS"));
        }

        if (IsNonZero(fields, "tlsruleid") || IsNonZero(fields, "icapid"))
        {
            entries.Add(BuildFastConntrackEntry(rawLine, fields, "SSL", "SSL/TLS Inspection", "SSL/TLS inspection"));
        }

        if (IsNonZero(fields, "sdwan_ruleid[0]")
            || IsNonZero(fields, "sdwan_ruleid[1]")
            || IsNonZero(fields, "sdwan_profileid[0]")
            || IsNonZero(fields, "sdwan_profileid[1]"))
        {
            entries.Add(BuildFastConntrackEntry(rawLine, fields, "SD-WAN", "SD-WAN", "SD-WAN"));
        }

        if (IsNonZero(fields, "hb_src") || IsNonZero(fields, "hb_dst"))
        {
            entries.Add(BuildFastConntrackEntry(rawLine, fields, "Heartbeat", "Heartbeat", "Security Heartbeat"));
        }

        return entries;
    }

    public static bool TryParseFastFileLine(string sourceLogFile, string rawLine, out LogEntry? entry)
    {
        if (TryParse(rawLine, sourceLogFile, out entry))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(rawLine))
        {
            entry = null;
            return false;
        }

        var logDefinition = LogDefinition.All.FirstOrDefault(log =>
            log.TroubleshootingFiles.Contains(sourceLogFile, StringComparer.OrdinalIgnoreCase));
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["log_type"] = logDefinition?.DisplayName ?? "File",
            ["log_component"] = Path.GetFileName(sourceLogFile),
            ["message"] = rawLine.Trim(),
            ["log_file"] = sourceLogFile
        };

        entry = BuildEntry(rawLine, sourceLogFile, fields);
        return true;
    }

    private static LogEntry BuildEntry(string rawLine, string sourceLogFile, IReadOnlyDictionary<string, string> fields)
    {
        var subtype = Get(fields, "log_subtype");
        var status = Get(fields, "status");
        var action = FirstNonEmpty(status, subtype, Get(fields, "action"), Get(fields, "eventtype"), Get(fields, "reason"));

        return new LogEntry
        {
            OccurredAt = ParseTimestamp(fields),
            SourceLogFile = sourceLogFile,
            LogType = Get(fields, "log_type"),
            Component = Get(fields, "log_component"),
            Subtype = subtype,
            Status = status,
            Username = FirstNonEmpty(Get(fields, "user_name"), Get(fields, "user"), Get(fields, "username")),
            FirewallRule = FirstNonEmpty(Get(fields, "fw_rule_id"), Get(fields, "firewall_rule")),
            FirewallRuleName = FirstNonEmpty(Get(fields, "fw_rule_name"), Get(fields, "firewall_rule_name")),
            NatRule = Get(fields, "nat_rule_id"),
            NatRuleName = Get(fields, "nat_rule_name"),
            InInterface = FirstNonEmpty(Get(fields, "in_interface"), Get(fields, "in_display_interface")),
            OutInterface = FirstNonEmpty(Get(fields, "out_interface"), Get(fields, "out_display_interface")),
            SourceIp = Get(fields, "src_ip"),
            DestinationIp = Get(fields, "dst_ip"),
            SourcePort = Get(fields, "src_port"),
            DestinationPort = Get(fields, "dst_port"),
            Protocol = Get(fields, "protocol"),
            Message = FirstNonEmpty(Get(fields, "message"), Get(fields, "signature_msg"), Get(fields, "classification"), action),
            RawLine = rawLine,
            Disposition = ClassifyDisposition(action, rawLine),
            Fields = fields
        };
    }

    private static bool LooksLikeSophosLog(IReadOnlyDictionary<string, string> fields)
    {
        if (fields.Count < 2)
        {
            return false;
        }

        return fields.ContainsKey("log_type")
            || fields.ContainsKey("log_component")
            || fields.ContainsKey("src_ip")
            || fields.ContainsKey("dst_ip")
            || fields.ContainsKey("status")
            || fields.ContainsKey("eventid")
            || fields.ContainsKey("message");
    }

    private static Dictionary<string, string> ParseFields(string rawLine)
    {
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (Match match in KeyValueRegex().Matches(rawLine))
        {
            var key = match.Groups["key"].Value.Trim();
            var value = match.Groups["quoted"].Success
                ? match.Groups["quoted"].Value
                : match.Groups["bare"].Value;

            if (!string.IsNullOrWhiteSpace(key))
            {
                fields[key] = value.Trim();
            }
        }

        return fields;
    }

    private static void NormalizeAliases(Dictionary<string, string> fields)
    {
        CopyAlias(fields, "sourceip", "src_ip");
        CopyAlias(fields, "source_ip", "src_ip");
        CopyAlias(fields, "srcip", "src_ip");
        CopyAlias(fields, "srcipaddr", "src_ip");
        CopyAlias(fields, "destinationip", "dst_ip");
        CopyAlias(fields, "destination_ip", "dst_ip");
        CopyAlias(fields, "dstip", "dst_ip");
        CopyAlias(fields, "dest_ip", "dst_ip");
        CopyAlias(fields, "destip", "dst_ip");
        CopyAlias(fields, "source_port", "src_port");
        CopyAlias(fields, "sport", "src_port");
        CopyAlias(fields, "destination_port", "dst_port");
        CopyAlias(fields, "dport", "dst_port");
        CopyAlias(fields, "dest_port", "dst_port");
        CopyAlias(fields, "orig-src", "src_ip");
        CopyAlias(fields, "orig-dst", "dst_ip");
        CopyAlias(fields, "orig-sport", "src_port");
        CopyAlias(fields, "orig-dport", "dst_port");
        CopyAlias(fields, "log_sub_type", "log_subtype");
        CopyAlias(fields, "logtype", "log_type");
        CopyAlias(fields, "log type", "log_type");
        CopyAlias(fields, "log_type_name", "log_type");
        CopyAlias(fields, "logcomponent", "log_component");
        CopyAlias(fields, "log component", "log_component");
        CopyAlias(fields, "log _component", "log_component");
        CopyAlias(fields, "component", "log_component");
        CopyAlias(fields, "logsubtype", "log_subtype");
        CopyAlias(fields, "log subtype", "log_subtype");
        CopyAlias(fields, "subtype", "log_subtype");
        CopyAlias(fields, "severity", "priority");
        CopyAlias(fields, "rule_id", "fw_rule_id");
        CopyAlias(fields, "rule_name", "fw_rule_name");
        CopyAlias(fields, "fwid", "fw_rule_id");
        CopyAlias(fields, "natid", "nat_rule_id");
        CopyAlias(fields, "devin", "in_interface");
        CopyAlias(fields, "devout", "out_interface");
        CopyAlias(fields, "user", "user_name");
        CopyAlias(fields, "bytes_sent", "sent_bytes");
        CopyAlias(fields, "bytes_received", "recv_bytes");
    }

    private static void CopyAlias(Dictionary<string, string> fields, string source, string destination)
    {
        if (!fields.ContainsKey(destination) && fields.TryGetValue(source, out var value))
        {
            fields[destination] = value;
        }
    }

    private static DateTimeOffset ParseTimestamp(IReadOnlyDictionary<string, string> fields)
    {
        if (fields.TryGetValue("timestamp", out var timestamp)
            && DateTimeOffset.TryParse(timestamp, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsedTimestamp))
        {
            return parsedTimestamp;
        }

        if (fields.TryGetValue("datetime", out var sophosDateTime))
        {
            var offsetText = fields.TryGetValue("tz_offset", out var offset) ? offset : string.Empty;
            if (offsetText.Length == 5 && (offsetText[0] == '+' || offsetText[0] == '-'))
            {
                offsetText = offsetText.Insert(3, ":");
            }

            var candidate = string.IsNullOrWhiteSpace(offsetText)
                ? sophosDateTime
                : $"{sophosDateTime} {offsetText}";

            if (DateTimeOffset.TryParseExact(
                    candidate,
                    ["yyyy-MM-dd HH:mm:ss zzz", "yyyy-MM-dd HH:mm:ss K", "yyyy-MM-dd HH:mm:ss"],
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeLocal,
                    out var parsedSophosDateTime))
            {
                return parsedSophosDateTime;
            }
        }

        if (fields.TryGetValue("event_timestamp", out var eventTimestamp)
            && long.TryParse(eventTimestamp, NumberStyles.Integer, CultureInfo.InvariantCulture, out var epoch))
        {
            return DateTimeOffset.FromUnixTimeSeconds(epoch).ToLocalTime();
        }

        if (fields.TryGetValue("eventtime", out var eventTime)
            && long.TryParse(eventTime, NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventEpoch))
        {
            return DateTimeOffset.FromUnixTimeSeconds(eventEpoch).ToLocalTime();
        }

        if (fields.TryGetValue("date", out var date) && fields.TryGetValue("time", out var time)
            && DateTimeOffset.TryParse($"{date} {time}", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var parsedDateTime))
        {
            return parsedDateTime;
        }

        return DateTimeOffset.Now;
    }

    private static bool TryParseJsonLog(string value, out Dictionary<string, string> fields)
    {
        fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(value) || !value.TrimStart().StartsWith('{'))
        {
            return false;
        }

        try
        {
            using var document = JsonDocument.Parse(value);
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            foreach (var property in document.RootElement.EnumerateObject())
            {
                fields[property.Name] = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString() ?? string.Empty,
                    JsonValueKind.Number => property.Value.GetRawText(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    _ => property.Value.GetRawText()
                };
            }

            return fields.Count > 0;
        }
        catch (JsonException)
        {
            fields.Clear();
            return false;
        }
    }

    private static string Get(IReadOnlyDictionary<string, string> fields, string key)
    {
        return fields.TryGetValue(key, out var value) ? value : string.Empty;
    }

    private static string FirstNonEmpty(params string[] values)
    {
        return values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value)) ?? string.Empty;
    }

    private static LogDisposition ClassifyDisposition(string action, string rawLine)
    {
        var candidate = $"{action} {rawLine}";

        if (ContainsAny(candidate, "deny", "denied", "block", "blocked", "drop", "dropped", "reject", "rejected", "fail", "failed", "virus", "malware"))
        {
            return LogDisposition.Denied;
        }

        if (ContainsAny(candidate, "allow", "allowed", "success", "successful", "clean", "delivered"))
        {
            return LogDisposition.Allowed;
        }

        return LogDisposition.Neutral;
    }

    private static bool ContainsAny(string value, params string[] needles)
    {
        return needles.Any(needle => value.Contains(needle, StringComparison.OrdinalIgnoreCase));
    }

    private static LogEntry BuildFastConntrackEntry(
        string rawLine,
        IReadOnlyDictionary<string, string> sourceFields,
        string logType,
        string component,
        string label)
    {
        var fields = new Dictionary<string, string>(sourceFields, StringComparer.OrdinalIgnoreCase)
        {
            ["log_type"] = logType,
            ["log_component"] = component
        };

        return BuildEntry(rawLine, "conntrack", fields);
    }

    private static bool IsNonZero(IReadOnlyDictionary<string, string> fields, string key)
    {
        return fields.TryGetValue(key, out var value)
            && !string.IsNullOrWhiteSpace(value)
            && !string.Equals(value, "0", StringComparison.Ordinal);
    }

    [GeneratedRegex(@"(?<key>[A-Za-z_][A-Za-z0-9_\-.\[\]]*)=(?:""(?<quoted>[^""]*)""|(?<bare>[^\s""]+))", RegexOptions.Compiled)]
    private static partial Regex KeyValueRegex();

    [GeneratedRegex(@"\[(?<event>NEW|DESTROY|UPDATE)\]", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex ConntrackEventRegex();
}
