using System.Security.Cryptography;
using System.Text;
using System.Globalization;
using System.Text.RegularExpressions;
using Renci.SshNet;
using Renci.SshNet.Common;
using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.App.Services;

public sealed partial class SshLogStreamService : IDisposable
{
    private const int InitialEventRows = 100;
    private static readonly TimeSpan LoginBannerPromptTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan LoginBannerPostAcceptDelay = TimeSpan.FromMilliseconds(300);

    private readonly object _sessionLock = new();
    private readonly object _stopTaskLock = new();
    private readonly object _lineLock = new();
    private readonly StringBuilder _lineBuffer = new();
    private readonly List<string> _eventDbColumns = [];
    private SshClient? _client;
    private ShellStream? _shell;
    private Task? _stopTask;
    private int _ignoredRowsReported;
    private bool _disposed;

    public async Task RunAsync(
        FirewallProfile profile,
        IReadOnlyCollection<LogDefinition> selectedLogs,
        LogFilter filter,
        Action<LogEntry> onEntry,
        Action<string> onStatus,
        Action<string> onDiagnostic,
        Func<string, bool> trustUnknownHostKey,
        CancellationToken cancellationToken,
        Action<ApplianceCpuUsage>? onCpuUsage = null)
    {
        ThrowIfDisposed();
        _ignoredRowsReported = 0;
        _eventDbColumns.Clear();
        lock (_lineLock)
        {
            _lineBuffer.Clear();
        }

        if (selectedLogs.Count == 0)
        {
            throw new InvalidOperationException("Es ist keine Loggruppe ausgewählt.");
        }

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var connectionInfo = CreateConnectionInfo(profile);

        using var client = new SshClient(connectionInfo);
        ShellStream? shell = null;
        lock (_sessionLock)
        {
            _client = client;
        }

        try
        {
            client.KeepAliveInterval = TimeSpan.FromSeconds(5);

            client.ErrorOccurred += (_, args) =>
            {
                onDiagnostic("SSH error: " + args.Exception.Message);
                linkedCts.Cancel();
            };

            client.HostKeyReceived += (_, args) =>
            {
                var fingerprint = BuildSha256Fingerprint(args.HostKey);

                args.CanTrust = string.IsNullOrWhiteSpace(profile.ExpectedHostKeySha256)
                    ? trustUnknownHostKey(fingerprint)
                    : string.Equals(profile.ExpectedHostKeySha256.Trim(), fingerprint, StringComparison.OrdinalIgnoreCase);
            };

            onStatus($"Connecting to {profile.Host}:{profile.Port} ...");
            onDiagnostic($"SSH target: {profile.Host}:{profile.Port}, source mode: {profile.SourceMode}");
            onDiagnostic(SshAlgorithmPolicy.Describe(profile.SshSecurityMode));
            await Task.Run(client.Connect, cancellationToken).ConfigureAwait(false);
            onDiagnostic(
                "SSH negotiated: "
                + $"KEX={connectionInfo.CurrentKeyExchangeAlgorithm}, "
                + $"HostKey={connectionInfo.CurrentHostKeyAlgorithm}, "
                + $"C2S={connectionInfo.CurrentClientEncryption}/{connectionInfo.CurrentClientHmacAlgorithm}, "
                + $"S2C={connectionInfo.CurrentServerEncryption}/{connectionInfo.CurrentServerHmacAlgorithm}");

            onStatus("SSH connected. Starting live stream ...");
            shell = client.CreateShellStream("sophos-live-log", 120, 40, 0, 0, 64 * 1024);
            lock (_sessionLock)
            {
                _shell = shell;
            }

            using (shell)
            {
                await AcceptOptionalLoginBannerAsync(shell, onDiagnostic, cancellationToken).ConfigureAwait(false);

                shell.DataReceived += (_, args) => ProcessData(args.Data, filter, onEntry, onStatus, onDiagnostic, onCpuUsage);

                if (profile.UseSophosAdvancedShell)
                {
                    await SendSophosAdvancedShellBootstrapAsync(shell, cancellationToken).ConfigureAwait(false);
                }

                var command = profile.SourceMode == LogSourceMode.SophosTroubleshootingFiles
                    ? BuildTroubleshootingTailCommand(profile, selectedLogs)
                    : BuildEventDbCommand(profile);

                shell.WriteLine(command);
                onStatus(profile.SourceMode == LogSourceMode.SophosTroubleshootingFiles
                    ? $"Live: troubleshooting files, {selectedLogs.Count} log group(s)"
                    : $"Live: fast streams + Sophos event DB, initial {InitialEventRows} rows");

                while (!linkedCts.IsCancellationRequested && client.IsConnected)
                {
                    await Task.Delay(250, linkedCts.Token).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            lock (_sessionLock)
            {
                if (ReferenceEquals(_shell, shell))
                {
                    _shell = null;
                }

                if (ReferenceEquals(_client, client))
                {
                    _client = null;
                }
            }
        }
    }

    public async Task<bool> StopAsync(TimeSpan timeout)
    {
        var stopTask = GetOrCreateStopTask();
        var completedTask = await Task.WhenAny(stopTask, Task.Delay(timeout)).ConfigureAwait(false);
        if (!ReferenceEquals(completedTask, stopTask))
        {
            return false;
        }

        await stopTask.ConfigureAwait(false);
        return true;
    }

    public void Stop()
    {
        StopCore();
    }

    private Task GetOrCreateStopTask()
    {
        lock (_stopTaskLock)
        {
            if (_stopTask is { IsCompleted: false })
            {
                return _stopTask;
            }

            _stopTask = Task.Run(StopCore);
            return _stopTask;
        }
    }

    private void StopCore()
    {
        ShellStream? shell;
        SshClient? client;
        lock (_sessionLock)
        {
            shell = _shell;
            client = _client;
            _shell = null;
            _client = null;
        }

        try
        {
            shell?.Write(new byte[] { 0x03 }, 0, 1);
        }
        catch (Exception)
        {
        }

        try
        {
            shell?.Dispose();
        }
        catch (Exception)
        {
        }

        try
        {
            if (client?.IsConnected == true)
            {
                client.Disconnect();
            }
        }
        catch (Exception)
        {
        }

        try
        {
            client?.Dispose();
        }
        catch (Exception)
        {
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _ = StopAsync(TimeSpan.FromSeconds(1));
    }

    private static void ValidateProfile(FirewallProfile profile)
    {
        if (string.IsNullOrWhiteSpace(profile.Host))
        {
            throw new InvalidOperationException("Host/IP fehlt.");
        }

        if (profile.Port is < 1 or > 65535)
        {
            throw new InvalidOperationException("SSH-Port ist ungültig.");
        }

        if (string.IsNullOrWhiteSpace(profile.Username))
        {
            throw new InvalidOperationException("Username fehlt.");
        }

        if (string.IsNullOrEmpty(profile.Password))
        {
            throw new InvalidOperationException("Passwort fehlt.");
        }
    }

    public static PasswordConnectionInfo CreateConnectionInfo(FirewallProfile profile)
    {
        ValidateProfile(profile);

        var connectionInfo = new PasswordConnectionInfo(profile.Host, profile.Port, profile.Username, profile.Password)
        {
            Timeout = TimeSpan.FromSeconds(10),
            RetryAttempts = 1
        };

        SshAlgorithmPolicy.Apply(connectionInfo, profile.SshSecurityMode);
        return connectionInfo;
    }

    private static string BuildEventDbCommand(FirewallProfile profile)
    {
        return $$"""
{{BuildCpuShellPrelude()}}
{{BuildFastFileTailCommand(profile)}}
SXLV_DB=""
printf '__SXLV_DIAG__%sStarting Sophos event DB discovery\n' "$SXLV_SEP"
for SXLV_P in /tmp/eventlogs/active.db /var/eventlogs/active.db /tmp/eventlogs/*.db /var/eventlogs/*.db; do
    [ -r "$SXLV_P" ] || continue
    SXLV_DB="$SXLV_P"
    break
done
if [ -z "$SXLV_DB" ]; then
    printf '__SXLV_ERROR__%sNo readable Sophos event log database found under /tmp/eventlogs or /var/eventlogs\n' "$SXLV_SEP"
    exit 1
fi
if ! sqlite3 --version >/dev/null 2>&1; then
    printf '__SXLV_ERROR__%ssqlite3 is not available in Advanced Shell\n' "$SXLV_SEP"
    exit 1
fi
printf '__SXLV_DB__%s%s\n' "$SXLV_SEP" "$SXLV_DB"
SXLV_TABLES="$(sqlite3 -noheader "$SXLV_DB" "select name from sqlite_master where type='table' order by name;" | tr '\n' ',' | sed 's/,$//')"
printf '__SXLV_TABLES__%s%s\n' "$SXLV_SEP" "$SXLV_TABLES"
SXLV_TABLE="$(sqlite3 -noheader "$SXLV_DB" "select name from sqlite_master where type='table' and lower(name)='tbllog' limit 1;")"
if [ -z "$SXLV_TABLE" ]; then
    SXLV_TABLE="$(sqlite3 -noheader "$SXLV_DB" "select name from sqlite_master where type='table' and lower(name) like '%log%' order by name limit 1;")"
fi
if [ -z "$SXLV_TABLE" ]; then
    printf '__SXLV_ERROR__%sNo log-like table found in %s\n' "$SXLV_SEP" "$SXLV_DB"
    exit 1
fi
SXLV_QTABLE="$(printf '%s' "$SXLV_TABLE" | sed 's/"/""/g')"
printf '__SXLV_TABLE__%s%s\n' "$SXLV_SEP" "$SXLV_TABLE"
SXLV_COLUMNS="$(sqlite3 -noheader "$SXLV_DB" "PRAGMA table_info('$SXLV_QTABLE');" | cut -d'|' -f2 | tr '\n' "$SXLV_SEP")"
printf '__SXLV_COLUMNS__%srowid%s%s\n' "$SXLV_SEP" "$SXLV_SEP" "$SXLV_COLUMNS"
SXLV_EMIT_HEALTH
SXLV_START_FAST_FIREWALL_STREAM
SXLV_START_FAST_FILE_TAILS
SXLV_LAST="$(sqlite3 "$SXLV_DB" "select coalesce(max(rowid),0) from \"$SXLV_QTABLE\";")"
SXLV_START=$((SXLV_LAST-{{InitialEventRows}}))
[ "$SXLV_START" -lt 0 ] && SXLV_START=0
printf '__SXLV_DIAG__%sInitial rowid window: %s..%s\n' "$SXLV_SEP" "$SXLV_START" "$SXLV_LAST"
while true; do
    SXLV_EMIT_CPU
    SXLV_EMIT_HEALTH
    sqlite3 -noheader -separator "$SXLV_SEP" "$SXLV_DB" "select rowid,* from \"$SXLV_QTABLE\" where rowid > $SXLV_START order by rowid limit 500;" | while IFS= read -r SXLV_ROW; do
        printf '__SXLV_ROW__%s%s\n' "$SXLV_SEP" "$SXLV_ROW"
    done
    SXLV_NEWLAST="$(sqlite3 "$SXLV_DB" "select coalesce(max(rowid),$SXLV_START) from \"$SXLV_QTABLE\";")"
    SXLV_START="$SXLV_NEWLAST"
    sleep 0.25
done
""";
    }

    private static string BuildCpuShellPrelude()
    {
        return """
SXLV_SEP="$(printf '\036')"
SXLV_BG_PIDS=""
SXLV_CPU_PREV="/tmp/sxlv_cpu_prev_$$"
SXLV_CPU_CUR="/tmp/sxlv_cpu_cur_$$"
SXLV_LAST_CPU_TS=""
SXLV_LAST_HEALTH_TS=0
SXLV_REGISTER_BG() {
    SXLV_BG_PIDS="$SXLV_BG_PIDS $1"
}
SXLV_EMIT_CPU() {
    SXLV_NOW="$(date +%s 2>/dev/null || echo 0)"
    [ "$SXLV_NOW" = "$SXLV_LAST_CPU_TS" ] && return
    SXLV_LAST_CPU_TS="$SXLV_NOW"
    awk '/^cpu[0-9]* / { idle=$5+$6; total=0; for (i=2; i<=NF; i++) total += $i; print $1, idle, total }' /proc/stat > "$SXLV_CPU_CUR" 2>/dev/null || return
    if [ -s "$SXLV_CPU_PREV" ]; then
        SXLV_CPU_LINE="$(awk -v sep="$SXLV_SEP" 'FNR==NR { idle[$1]=$2; total[$1]=$3; next } { if ($1 in total) { dt=$3-total[$1]; di=$2-idle[$1]; if (dt > 0) { usage=100*(dt-di)/dt; if (usage < 0) usage=0; if (usage > 100) usage=100; printf "%s%s:%.1f", (count++ ? sep : ""), $1, usage } } }' "$SXLV_CPU_PREV" "$SXLV_CPU_CUR")"
        [ -n "$SXLV_CPU_LINE" ] && printf '__SXLV_CPU__%s%s\n' "$SXLV_SEP" "$SXLV_CPU_LINE"
    fi
    mv "$SXLV_CPU_CUR" "$SXLV_CPU_PREV" 2>/dev/null || true
}
SXLV_EMIT_HEALTH() {
    SXLV_NOW="$(date +%s 2>/dev/null || echo 0)"
    [ $((SXLV_NOW-SXLV_LAST_HEALTH_TS)) -lt 30 ] && return
    SXLV_LAST_HEALTH_TS="$SXLV_NOW"

    SXLV_TMP_USE="$(df -P /tmp 2>/dev/null | awk 'NR==2 { gsub("%", "", $5); print $5 }')"
    case "$SXLV_TMP_USE" in
        ''|*[!0-9]*) ;;
        *)
            if [ "$SXLV_TMP_USE" -ge 95 ]; then
                printf '__SXLV_WARNING__%sSophos /tmp is %s%% full. Event DB commits can stall; free space or flush device reports on the firewall.\n' "$SXLV_SEP" "$SXLV_TMP_USE"
            fi
            ;;
    esac

    if [ -r /log/garner.log ] && tail -n 120 /log/garner.log 2>/dev/null | grep -Eiq 'database or disk is full|Transaction Couldn|No space left'; then
        printf '__SXLV_WARNING__%sSophos logging service reports failed Event DB commits in /log/garner.log. Live log data may be stale until firewall logging is repaired.\n' "$SXLV_SEP"
    fi
}
SXLV_START_FAST_FIREWALL_STREAM() {
    if [ ! -x /bin/conntrack ]; then
        printf '__SXLV_WARNING__%s/bin/conntrack is not available. Fast firewall stream is disabled.\n' "$SXLV_SEP"
        return
    fi

    ( /bin/conntrack -E -b 4194304 -e NEW 2>/dev/null | while IFS= read -r SXLV_CT_ROW; do
        [ -n "$SXLV_CT_ROW" ] && printf '__SXLV_CONNTRACK__%s%s\n' "$SXLV_SEP" "$SXLV_CT_ROW"
    done ) &
    SXLV_CT_PID=$!
    SXLV_REGISTER_BG "$SXLV_CT_PID"
    printf '__SXLV_DIAG__%sFast conntrack stream started\n' "$SXLV_SEP"
}
trap 'rm -f "$SXLV_CPU_PREV" "$SXLV_CPU_CUR"; [ -n "$SXLV_CPU_PID" ] && kill "$SXLV_CPU_PID" 2>/dev/null; for SXLV_PID in $SXLV_BG_PIDS; do kill "$SXLV_PID" 2>/dev/null; done' EXIT INT TERM
""";
    }

    private static string BuildTroubleshootingTailCommand(FirewallProfile profile, IReadOnlyCollection<LogDefinition> selectedLogs)
    {
        var files = selectedLogs
            .SelectMany(log => log.TroubleshootingFiles)
            .Concat(ParseExtraFiles(profile.ExtraLogFiles))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var file in files)
        {
            ValidateLogPath(file);
        }

        var escapedFiles = files.Select(file => "'" + file.Replace("'", "'\\''", StringComparison.Ordinal) + "'");
        return BuildCpuShellPrelude() + """

( while true; do SXLV_EMIT_CPU; SXLV_EMIT_HEALTH; sleep 1; done ) &
SXLV_CPU_PID=$!
""" + "tail -f -n 50 " + string.Join(' ', escapedFiles);
    }

    private static IEnumerable<string> ParseExtraFiles(string extraLogFiles)
    {
        if (string.IsNullOrWhiteSpace(extraLogFiles))
        {
            yield break;
        }

        var parts = extraLogFiles.Split([',', ';', '\r', '\n', '\t', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            yield return part.StartsWith("/log/", StringComparison.OrdinalIgnoreCase)
                ? part
                : "/log/" + part;
        }
    }

    private static void ValidateLogPath(string path)
    {
        if (!path.StartsWith("/log/", StringComparison.Ordinal) || !path.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Invalid log file: {path}");
        }

        if (path.Contains("..", StringComparison.Ordinal) || !LogPathRegex().IsMatch(path))
        {
            throw new InvalidOperationException($"Unsafe log file: {path}");
        }
    }

    private static string BuildFastFileTailCommand(FirewallProfile profile)
    {
        var files = LogDefinition.All
            .SelectMany(log => log.TroubleshootingFiles)
            .Concat(ParseExtraFiles(profile.ExtraLogFiles))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var file in files)
        {
            ValidateLogPath(file);
        }

        var builder = new StringBuilder();
        builder.AppendLine("""
SXLV_TAIL_FILE() {
    SXLV_FILE="$1"
    [ -r "$SXLV_FILE" ] || return
    ( tail -f -n 0 "$SXLV_FILE" 2>/dev/null | while IFS= read -r SXLV_FILE_ROW; do
        [ -n "$SXLV_FILE_ROW" ] && printf '__SXLV_FILE__%s%s%s%s\n' "$SXLV_SEP" "$SXLV_FILE" "$SXLV_SEP" "$SXLV_FILE_ROW"
    done ) &
    SXLV_TAIL_PID=$!
    SXLV_REGISTER_BG "$SXLV_TAIL_PID"
}
SXLV_START_FAST_FILE_TAILS() {
""");

        foreach (var escapedFile in files.Select(EscapeSingleQuotedShellValue))
        {
            builder.Append("    SXLV_TAIL_FILE ");
            builder.AppendLine(escapedFile);
        }

        builder.AppendLine("""
    printf '__SXLV_DIAG__%sFast file tails started for Sophos troubleshooting logs\n' "$SXLV_SEP"
}
""");

        return builder.ToString();
    }

    private static string EscapeSingleQuotedShellValue(string value)
    {
        return "'" + value.Replace("'", "'\\''", StringComparison.Ordinal) + "'";
    }

    private static async Task SendSophosAdvancedShellBootstrapAsync(ShellStream shell, CancellationToken cancellationToken)
    {
        await Task.Delay(600, cancellationToken).ConfigureAwait(false);
        shell.WriteLine("5");
        await Task.Delay(500, cancellationToken).ConfigureAwait(false);
        shell.WriteLine("3");
        await Task.Delay(800, cancellationToken).ConfigureAwait(false);
    }

    private static async Task AcceptOptionalLoginBannerAsync(
        ShellStream shell,
        Action<string> onDiagnostic,
        CancellationToken cancellationToken)
    {
        var promptDetected = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var buffer = new StringBuilder();
        var accepted = 0;

        EventHandler<ShellDataEventArgs>? handler = null;
        handler = (_, args) =>
        {
            var text = Encoding.UTF8.GetString(args.Data);
            lock (buffer)
            {
                buffer.Append(text);
                if (buffer.Length > 4096)
                {
                    buffer.Remove(0, buffer.Length - 4096);
                }

                text = buffer.ToString();
            }

            if (!IsLoginBannerConfirmationPrompt(text)
                || Interlocked.Exchange(ref accepted, 1) != 0)
            {
                return;
            }

            try
            {
                shell.WriteLine("y");
                onDiagnostic("Accepted SSH login banner confirmation prompt.");
                promptDetected.TrySetResult(true);
            }
            catch (Exception ex) when (ex is SshException or ObjectDisposedException or InvalidOperationException)
            {
                promptDetected.TrySetException(ex);
            }
        };

        shell.DataReceived += handler;
        try
        {
            var completed = await Task.WhenAny(
                promptDetected.Task,
                Task.Delay(LoginBannerPromptTimeout, cancellationToken)).ConfigureAwait(false);

            cancellationToken.ThrowIfCancellationRequested();

            if (ReferenceEquals(completed, promptDetected.Task)
                && await promptDetected.Task.ConfigureAwait(false))
            {
                await Task.Delay(LoginBannerPostAcceptDelay, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            shell.DataReceived -= handler;
        }
    }

    internal static bool IsLoginBannerConfirmationPrompt(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var normalized = StripAnsi(text)
            .Replace('\r', ' ')
            .Replace('\n', ' ')
            .Replace('\t', ' ');

        return ContainsAnyIgnoreCase(normalized, "(y/n)", "[y/n]", " y/n", "(yes/no)", "[yes/no]", "yes/no")
            && ContainsAnyIgnoreCase(normalized, "continue", "proceed");
    }

    private static string BuildSha256Fingerprint(byte[] hostKey)
    {
        var hash = SHA256.HashData(hostKey);
        return "SHA256:" + Convert.ToBase64String(hash).TrimEnd('=');
    }

    private void ProcessData(
        byte[] data,
        LogFilter filter,
        Action<LogEntry> onEntry,
        Action<string> onStatus,
        Action<string> onDiagnostic,
        Action<ApplianceCpuUsage>? onCpuUsage)
    {
        var text = Encoding.UTF8.GetString(data);

        lock (_lineLock)
        {
            _lineBuffer.Append(text);

            while (TryReadLine(_lineBuffer, out var line))
            {
                ProcessLine(line, filter, onEntry, onStatus, onDiagnostic, onCpuUsage);
            }
        }
    }

    private void ProcessLine(
        string line,
        LogFilter filter,
        Action<LogEntry> onEntry,
        Action<string> onStatus,
        Action<string> onDiagnostic,
        Action<ApplianceCpuUsage>? onCpuUsage)
    {
        var trimmed = StripAnsi(line.TrimEnd('\r')).Trim();
        if (string.IsNullOrWhiteSpace(trimmed) || IsShellNoise(trimmed))
        {
            return;
        }

        if (trimmed.StartsWith("__SXLV_", StringComparison.Ordinal))
        {
            ProcessEventDbLine(trimmed, filter, onEntry, onStatus, onDiagnostic, onCpuUsage);
            return;
        }

        if (SophosLogParser.TryParse(trimmed, "eventdb", out var entry) && entry is not null && filter.IsMatch(entry))
        {
            onEntry(entry);
        }
    }

    private void ProcessEventDbLine(
        string line,
        LogFilter filter,
        Action<LogEntry> onEntry,
        Action<string> onStatus,
        Action<string> onDiagnostic,
        Action<ApplianceCpuUsage>? onCpuUsage)
    {
        var parts = line.Split('\u001e');
        if (parts.Length == 0)
        {
            return;
        }

        switch (parts[0])
        {
            case "__SXLV_DB__":
                if (parts.Length > 1)
                {
                    onStatus("Event DB: " + parts[1]);
                    onDiagnostic("Event DB: " + parts[1]);
                }
                break;

            case "__SXLV_TABLES__":
                onDiagnostic(parts.Length > 1 ? "Tables: " + parts[1] : "Tables: <none>");
                break;

            case "__SXLV_TABLE__":
                onDiagnostic(parts.Length > 1 ? "Selected table: " + parts[1] : "Selected table: <none>");
                break;

            case "__SXLV_COLUMNS__":
                _eventDbColumns.Clear();
                _eventDbColumns.AddRange(parts.Skip(1).Where(part => !string.IsNullOrWhiteSpace(part)));
                onDiagnostic("Columns: " + string.Join(", ", _eventDbColumns));
                break;

            case "__SXLV_ROW__":
                if (_eventDbColumns.Count == 0)
                {
                    return;
                }

                var values = parts.Skip(1).ToList();
                if (SophosLogParser.TryParseDatabaseRow(_eventDbColumns, values, out var entry)
                    && entry is not null
                    && filter.IsMatch(entry))
                {
                    onEntry(entry);
                }
                else
                {
                    if (_ignoredRowsReported < 10)
                    {
                        _ignoredRowsReported++;
                        onDiagnostic("Ignored DB row sample: " + Truncate(string.Join(" | ", values), 500));
                    }
                }
                break;

            case "__SXLV_CONNTRACK__":
                if (parts.Length > 1)
                {
                    foreach (var conntrackEntry in SophosLogParser.ParseConntrackFastEvents(parts[1]))
                    {
                        if (filter.IsMatch(conntrackEntry))
                        {
                            onEntry(conntrackEntry);
                        }
                    }
                }
                break;

            case "__SXLV_FILE__":
                if (parts.Length > 2
                    && SophosLogParser.TryParseFastFileLine(parts[1], parts[2], out var fileEntry)
                    && fileEntry is not null
                    && filter.IsMatch(fileEntry))
                {
                    onEntry(fileEntry);
                }
                break;

            case "__SXLV_ERROR__":
                var error = parts.Length > 1 ? "Error: " + parts[1] : "Error while reading the event DB.";
                onStatus(error);
                onDiagnostic(error);
                break;

            case "__SXLV_WARNING__":
                var warning = parts.Length > 1 ? "Warning: " + parts[1] : "Warning from Sophos live log stream.";
                onStatus(warning);
                onDiagnostic(warning);
                break;

            case "__SXLV_DIAG__":
                if (parts.Length > 1)
                {
                    onDiagnostic(parts[1]);
                }
                break;

            case "__SXLV_CPU__":
                if (onCpuUsage is not null && TryParseCpuUsage(parts.Skip(1), out var usage))
                {
                    onCpuUsage(usage);
                }
                break;
        }
    }

    public static bool TryParseCpuUsage(IEnumerable<string> parts, out ApplianceCpuUsage usage)
    {
        var cores = new List<CpuCoreUsage>();
        double? total = null;

        foreach (var part in parts)
        {
            var separator = part.IndexOf(':', StringComparison.Ordinal);
            if (separator <= 0 || separator == part.Length - 1)
            {
                continue;
            }

            var name = part[..separator];
            var valueText = part[(separator + 1)..].Replace(',', '.');
            if (!double.TryParse(valueText, NumberStyles.Float, CultureInfo.InvariantCulture, out var percent))
            {
                continue;
            }

            percent = Math.Clamp(percent, 0, 100);
            if (string.Equals(name, "cpu", StringComparison.OrdinalIgnoreCase))
            {
                total = percent;
            }
            else if (name.StartsWith("cpu", StringComparison.OrdinalIgnoreCase))
            {
                cores.Add(new CpuCoreUsage(name, percent));
            }
        }

        if (total is null && cores.Count > 0)
        {
            total = cores.Average(core => core.UsagePercent);
        }

        usage = total is null
            ? new ApplianceCpuUsage(DateTimeOffset.Now, 0, [])
            : new ApplianceCpuUsage(DateTimeOffset.Now, total.Value, cores);

        return total is not null;
    }

    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength] + "...";
    }

    private static bool TryReadLine(StringBuilder buffer, out string line)
    {
        for (var index = 0; index < buffer.Length; index++)
        {
            if (buffer[index] != '\n')
            {
                continue;
            }

            line = buffer.ToString(0, index);
            buffer.Remove(0, index + 1);
            return true;
        }

        line = string.Empty;
        return false;
    }

    internal static bool IsShellNoise(string line)
    {
        if (IsLoginBannerConfirmationPrompt(line))
        {
            return true;
        }

        if (!line.Contains('=')
            && (line.Contains("Select Menu", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Main Menu", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Device Management", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Device Console", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Network Configuration", StringComparison.OrdinalIgnoreCase)
            || line.Contains("System Configuration", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Route Configuration", StringComparison.OrdinalIgnoreCase)
            || line.Contains("VPN Management", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Shutdown/Reboot Device", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Flush Device Reports", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Reset to Factory Defaults", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Show Firmware", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Hostname:", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Model:", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Copyright", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Sophos End User Terms", StringComparison.OrdinalIgnoreCase)
            || line.Contains("trademarks", StringComparison.OrdinalIgnoreCase)
            || line.Contains("support.", StringComparison.OrdinalIgnoreCase)
            || line.Contains("Advanced Shell", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("SFOS", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Sophos", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("[H]", StringComparison.OrdinalIgnoreCase)
            || MenuLineRegex().IsMatch(line)
            || PromptEchoRegex().IsMatch(line)
            || TailErrorRegex().IsMatch(line)))
        {
            return true;
        }

        return PromptEchoRegex().IsMatch(line)
            || TailErrorRegex().IsMatch(line);
    }

    private static string StripAnsi(string value)
    {
        return AnsiRegex().Replace(value, string.Empty);
    }

    private static bool ContainsAnyIgnoreCase(string value, params string[] needles)
    {
        return needles.Any(needle => value.Contains(needle, StringComparison.OrdinalIgnoreCase));
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    [GeneratedRegex(@"\x1B\[[0-?]*[ -/]*[@-~]", RegexOptions.Compiled)]
    private static partial Regex AnsiRegex();

    [GeneratedRegex(@"^\s*\d+\.\s+\S+", RegexOptions.Compiled)]
    private static partial Regex MenuLineRegex();

    [GeneratedRegex(@"(^|\s)#\s*tail\s+-f\s+", RegexOptions.Compiled)]
    private static partial Regex PromptEchoRegex();

    [GeneratedRegex(@"^tail:\s+", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
    private static partial Regex TailErrorRegex();

    [GeneratedRegex(@"^/log/[A-Za-z0-9_./-]+\.log$", RegexOptions.Compiled)]
    private static partial Regex LogPathRegex();
}
