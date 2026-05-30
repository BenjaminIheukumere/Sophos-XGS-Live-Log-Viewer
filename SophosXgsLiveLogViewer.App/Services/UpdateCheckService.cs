using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SophosXgsLiveLogViewer.App.Services;

public sealed class UpdateCheckService
{
    private const string LatestReleaseUrl = "https://api.github.com/repos/BenjaminIheukumere/Sophos-XGS-Live-Log-Viewer/releases/latest";
    private const string UserAgent = "Sophos-XGS-Live-Log-Viewer";
    private const string DownloadFileName = "Sophos XGS Live Log Viewer.exe";
    private const int CopyBufferSize = 1024 * 128;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly HttpClient _httpClient;

    public UpdateCheckService()
        : this(CreateHttpClient())
    {
    }

    internal UpdateCheckService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public static Version CurrentVersion =>
        Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0, 0);

    public async Task<UpdateInfo?> CheckLatestAsync(Version currentVersion, CancellationToken cancellationToken)
    {
        using var request = CreateGitHubApiRequest(HttpMethod.Get, LatestReleaseUrl);
        using var response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync(cancellationToken);
        return TryCreateUpdateInfo(json, currentVersion, out var update)
            ? update
            : null;
    }

    public async Task<string> DownloadAsync(
        UpdateInfo update,
        IProgress<DownloadProgress>? progress,
        CancellationToken cancellationToken)
    {
        ValidateDownloadUrl(update.DownloadUrl);

        var targetDirectory = BuildUpdateDirectory(update.LatestVersion);
        Directory.CreateDirectory(targetDirectory);

        var finalPath = Path.Combine(targetDirectory, DownloadFileName);
        var tempPath = finalPath + ".download";
        if (File.Exists(tempPath))
        {
            File.Delete(tempPath);
        }

        using var request = CreateBinaryDownloadRequest(HttpMethod.Get, update.DownloadUrl);
        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        response.EnsureSuccessStatusCode();

        var expectedBytes = response.Content.Headers.ContentLength.GetValueOrDefault(update.AssetSize);
        var receivedBytes = 0L;
        var buffer = new byte[CopyBufferSize];

        await using (var remoteStream = await response.Content.ReadAsStreamAsync(cancellationToken))
        await using (var fileStream = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, CopyBufferSize, useAsync: true))
        {
            while (true)
            {
                var read = await remoteStream.ReadAsync(buffer, cancellationToken);
                if (read == 0)
                {
                    break;
                }

                await fileStream.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                receivedBytes += read;
                progress?.Report(new DownloadProgress(receivedBytes, expectedBytes));
            }
        }

        File.Move(tempPath, finalPath, overwrite: true);
        return finalPath;
    }

    public static string CreateUpdaterScript(string downloadedPath, string targetPath, int processId)
    {
        var updateDirectory = Path.GetDirectoryName(downloadedPath)
            ?? throw new InvalidDataException("Downloaded update path has no directory.");
        Directory.CreateDirectory(updateDirectory);

        var scriptPath = Path.Combine(updateDirectory, "apply-update.cmd");
        var backupPath = targetPath + ".previous";
        var script = $$"""
@echo off
setlocal
set "SOURCE={{downloadedPath}}"
set "TARGET={{targetPath}}"
set "BACKUP={{backupPath}}"
set "PID={{processId}}"

:wait
tasklist /FI "PID eq %PID%" | findstr /R /C:"%PID%" >nul
if not errorlevel 1 (
    timeout /t 1 /nobreak >nul
    goto wait
)

if exist "%BACKUP%" del /f /q "%BACKUP%" >nul 2>nul
if exist "%TARGET%" move /y "%TARGET%" "%BACKUP%" >nul
copy /y "%SOURCE%" "%TARGET%" >nul
if errorlevel 1 (
    if exist "%BACKUP%" move /y "%BACKUP%" "%TARGET%" >nul
    exit /b 1
)

start "" "%TARGET%"
exit /b 0
""";

        File.WriteAllText(scriptPath, script);
        return scriptPath;
    }

    public static bool TryCreateUpdateInfo(string releaseJson, Version currentVersion, out UpdateInfo? update)
    {
        update = null;
        var release = JsonSerializer.Deserialize<GitHubRelease>(releaseJson, JsonOptions);
        if (release is null
            || release.Draft
            || release.Prerelease
            || string.IsNullOrWhiteSpace(release.TagName)
            || !TryParseVersion(release.TagName, out var latestVersion)
            || latestVersion <= NormalizeVersion(currentVersion))
        {
            return false;
        }

        var asset = (release.Assets ?? [])
            .FirstOrDefault(asset =>
                !string.IsNullOrWhiteSpace(asset.BrowserDownloadUrl)
                && asset.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase));

        if (asset is null)
        {
            return false;
        }

        ValidateDownloadUrl(asset.BrowserDownloadUrl);
        update = new UpdateInfo(latestVersion, release.HtmlUrl, asset.BrowserDownloadUrl, asset.Name, asset.Size);
        return true;
    }

    private static HttpClient CreateHttpClient()
    {
        var httpClient = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(15)
        };
        httpClient.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        return httpClient;
    }

    internal static HttpRequestMessage CreateGitHubApiRequest(HttpMethod method, string url)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        return request;
    }

    internal static HttpRequestMessage CreateBinaryDownloadRequest(HttpMethod method, string url)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));
        return request;
    }

    private static string BuildUpdateDirectory(Version version)
    {
        var basePath = Path.Combine(
            Path.GetTempPath(),
            "SophosXgsLiveLogViewer",
            Convert.ToHexString(RandomNumberGenerator.GetBytes(8)));

        return Path.Combine(basePath, "v" + ToDisplayVersion(version));
    }

    private static void ValidateDownloadUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)
            || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(uri.Host, "github.com", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Update download URL is not a trusted GitHub release URL.");
        }
    }

    private static bool TryParseVersion(string tagName, out Version version)
    {
        var trimmed = tagName.Trim().TrimStart('v', 'V');
        var versionText = new string(trimmed
            .TakeWhile(character => char.IsDigit(character) || character == '.')
            .ToArray());

        if (Version.TryParse(versionText, out var parsed))
        {
            version = NormalizeVersion(parsed);
            return true;
        }

        version = new Version(0, 0, 0, 0);
        return false;
    }

    private static Version NormalizeVersion(Version version)
    {
        return new Version(
            Math.Max(version.Major, 0),
            Math.Max(version.Minor, 0),
            Math.Max(version.Build, 0),
            Math.Max(version.Revision, 0));
    }

    private static string ToDisplayVersion(Version version)
    {
        return version.Build >= 0
            ? $"{version.Major}.{version.Minor}.{version.Build}"
            : $"{version.Major}.{version.Minor}";
    }

    private sealed record GitHubRelease(
        [property: JsonPropertyName("tag_name")]
        string TagName,
        [property: JsonPropertyName("html_url")]
        string HtmlUrl,
        bool Draft,
        bool Prerelease,
        List<GitHubAsset>? Assets);

    private sealed record GitHubAsset(
        string Name,
        [property: JsonPropertyName("browser_download_url")]
        string BrowserDownloadUrl,
        long Size);
}

public sealed record UpdateInfo(
    Version LatestVersion,
    string ReleaseUrl,
    string DownloadUrl,
    string AssetName,
    long AssetSize);

public sealed record DownloadProgress(long ReceivedBytes, long TotalBytes)
{
    public double Percent =>
        TotalBytes > 0
            ? Math.Clamp(ReceivedBytes * 100d / TotalBytes, 0d, 100d)
            : 0d;
}
