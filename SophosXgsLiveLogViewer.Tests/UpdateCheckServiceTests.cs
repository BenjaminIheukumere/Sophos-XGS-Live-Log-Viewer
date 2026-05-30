using System.IO;
using SophosXgsLiveLogViewer.App.Services;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class UpdateCheckServiceTests
{
    [Fact]
    public void TryCreateUpdateInfo_ReturnsUpdateForNewerGitHubRelease()
    {
        const string json = """
            {
              "tag_name": "v1.1.8",
              "html_url": "https://github.com/BenjaminIheukumere/Sophos-XGS-Live-Log-Viewer/releases/tag/v1.1.8",
              "draft": false,
              "prerelease": false,
              "assets": [
                {
                  "name": "Sophos.XGS.Live.Log.Viewer.exe",
                  "browser_download_url": "https://github.com/BenjaminIheukumere/Sophos-XGS-Live-Log-Viewer/releases/download/v1.1.8/Sophos.XGS.Live.Log.Viewer.exe",
                  "size": 167596814
                }
              ]
            }
            """;

        var hasUpdate = UpdateCheckService.TryCreateUpdateInfo(json, new Version(1, 1, 6), out var update);

        Assert.True(hasUpdate);
        Assert.NotNull(update);
        Assert.Equal(new Version(1, 1, 8, 0), update.LatestVersion);
        Assert.EndsWith(".exe", update.AssetName, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TryCreateUpdateInfo_IgnoresCurrentVersion()
    {
        const string json = """
            {
              "tag_name": "v1.1.6",
              "html_url": "https://github.com/BenjaminIheukumere/Sophos-XGS-Live-Log-Viewer/releases/tag/v1.1.6",
              "draft": false,
              "prerelease": false,
              "assets": [
                {
                  "name": "Sophos.XGS.Live.Log.Viewer.exe",
                  "browser_download_url": "https://github.com/BenjaminIheukumere/Sophos-XGS-Live-Log-Viewer/releases/download/v1.1.6/Sophos.XGS.Live.Log.Viewer.exe",
                  "size": 167596814
                }
              ]
            }
            """;

        var hasUpdate = UpdateCheckService.TryCreateUpdateInfo(json, new Version(1, 1, 6), out var update);

        Assert.False(hasUpdate);
        Assert.Null(update);
    }

    [Fact]
    public void TryCreateUpdateInfo_RejectsNonGitHubDownloadUrl()
    {
        const string json = """
            {
              "tag_name": "v1.1.8",
              "html_url": "https://github.com/BenjaminIheukumere/Sophos-XGS-Live-Log-Viewer/releases/tag/v1.1.8",
              "draft": false,
              "prerelease": false,
              "assets": [
                {
                  "name": "Sophos.XGS.Live.Log.Viewer.exe",
                  "browser_download_url": "https://example.com/Sophos.XGS.Live.Log.Viewer.exe",
                  "size": 167596814
                }
              ]
            }
            """;

        Assert.Throws<InvalidDataException>(() =>
            UpdateCheckService.TryCreateUpdateInfo(json, new Version(1, 1, 6), out _));
    }

    [Fact]
    public void CreateBinaryDownloadRequest_UsesOctetStreamAcceptHeader()
    {
        using var request = UpdateCheckService.CreateBinaryDownloadRequest(
            HttpMethod.Get,
            "https://github.com/BenjaminIheukumere/Sophos-XGS-Live-Log-Viewer/releases/download/v1.1.13/Sophos.XGS.Live.Log.Viewer.exe");

        Assert.Contains(request.Headers.Accept, header =>
            string.Equals(header.MediaType, "application/octet-stream", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(request.Headers.Accept, header =>
            string.Equals(header.MediaType, "application/vnd.github+json", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CreateGitHubApiRequest_UsesGitHubJsonAcceptHeader()
    {
        using var request = UpdateCheckService.CreateGitHubApiRequest(
            HttpMethod.Get,
            "https://api.github.com/repos/BenjaminIheukumere/Sophos-XGS-Live-Log-Viewer/releases/latest");

        Assert.Contains(request.Headers.Accept, header =>
            string.Equals(header.MediaType, "application/vnd.github+json", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CreateUpdaterScript_WritesScriptForReplacingCurrentExecutable()
    {
        var directory = Path.Combine(Path.GetTempPath(), "sxlv-update-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        try
        {
            var source = Path.Combine(directory, "downloaded update.exe");
            var target = Path.Combine(directory, "Sophos XGS Live Log Viewer.exe");
            File.WriteAllText(source, "new");
            File.WriteAllText(target, "old");

            var script = UpdateCheckService.CreateUpdaterScript(source, target, 12345);

            Assert.True(File.Exists(script));
            var content = File.ReadAllText(script);
            Assert.Contains(source, content);
            Assert.Contains(target, content);
            Assert.Contains("tasklist", content);
            Assert.Contains("start", content);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
