using System.Windows;
using SophosXgsLiveLogViewer.App.Services;

namespace SophosXgsLiveLogViewer.App;

public partial class UpdateWindow : Window
{
    private readonly UpdateCheckService _updateService;
    private readonly UpdateInfo _update;
    private readonly CancellationToken _cancellationToken;

    public UpdateWindow(
        Version currentVersion,
        UpdateInfo update,
        UpdateCheckService updateService,
        CancellationToken cancellationToken)
    {
        InitializeComponent();
        WindowTheme.ApplyDarkFrame(this);

        _update = update;
        _updateService = updateService;
        _cancellationToken = cancellationToken;
        VersionText.Text = $"Installed: {FormatVersion(currentVersion)}   Available: {FormatVersion(update.LatestVersion)}";
    }

    public string? DownloadedPath { get; private set; }

    private async void UpdateNow_Click(object sender, RoutedEventArgs e)
    {
        UpdateNowButton.IsEnabled = false;
        LaterButton.IsEnabled = false;
        DownloadProgressBar.Visibility = Visibility.Visible;
        StatusText.Text = "Downloading update ...";

        var progress = new Progress<DownloadProgress>(OnDownloadProgress);

        try
        {
            DownloadedPath = await _updateService.DownloadAsync(_update, progress, _cancellationToken);
            DialogResult = true;
        }
        catch (OperationCanceledException)
        {
            DialogResult = false;
        }
        catch (Exception ex)
        {
            StatusText.Text = "Update download failed.";
            MessageBox.Show(
                this,
                "The update could not be downloaded:\n\n" + ex.Message,
                "Update failed",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);

            UpdateNowButton.IsEnabled = true;
            LaterButton.IsEnabled = true;
        }
    }

    private void OnDownloadProgress(DownloadProgress progress)
    {
        if (progress.TotalBytes > 0)
        {
            DownloadProgressBar.IsIndeterminate = false;
            DownloadProgressBar.Value = progress.Percent;
            StatusText.Text = $"Downloading update ... {progress.Percent:0}%";
            return;
        }

        DownloadProgressBar.IsIndeterminate = true;
        StatusText.Text = $"Downloading update ... {FormatBytes(progress.ReceivedBytes)}";
    }

    private void Later_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private static string FormatVersion(Version version)
    {
        return version.Build >= 0
            ? $"{version.Major}.{version.Minor}.{version.Build}"
            : $"{version.Major}.{version.Minor}";
    }

    private static string FormatBytes(long bytes)
    {
        return bytes >= 1024 * 1024
            ? $"{bytes / 1024d / 1024d:0.0} MB"
            : $"{bytes / 1024d:0.0} KB";
    }
}
