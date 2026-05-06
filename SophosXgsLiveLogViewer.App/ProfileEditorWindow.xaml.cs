using System.Windows;
using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.App;

public partial class ProfileEditorWindow : Window
{
    private readonly FirewallProfile _profile;

    public ProfileEditorWindow(FirewallProfile profile)
    {
        InitializeComponent();
        WindowTheme.ApplyDarkFrame(this);
        _profile = profile.Clone();

        NameBox.Text = _profile.Name;
        HostBox.Text = _profile.Host;
        PortBox.Text = _profile.Port.ToString();
        UsernameBox.Text = _profile.Username;
        PasswordBox.Password = _profile.Password;
        HostKeyBox.Text = _profile.ExpectedHostKeySha256 ?? string.Empty;
        AdvancedShellBox.IsChecked = _profile.UseSophosAdvancedShell;
        SourceModeBox.ItemsSource = Enum.GetValues<LogSourceMode>();
        SourceModeBox.SelectedItem = _profile.SourceMode;
        ExtraFilesBox.Text = _profile.ExtraLogFiles;
        Loaded += (_, _) => NameBox.Focus();
    }

    public FirewallProfile? Profile { get; private set; }

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Text = string.Empty;

        if (string.IsNullOrWhiteSpace(NameBox.Text))
        {
            ErrorText.Text = "Profilname fehlt.";
            return;
        }

        if (string.IsNullOrWhiteSpace(HostBox.Text))
        {
            ErrorText.Text = "Host/IP fehlt.";
            return;
        }

        if (!int.TryParse(PortBox.Text, out var port) || port is < 1 or > 65535)
        {
            ErrorText.Text = "SSH-Port ist ungültig.";
            return;
        }

        if (string.IsNullOrWhiteSpace(UsernameBox.Text))
        {
            ErrorText.Text = "Username fehlt.";
            return;
        }

        _profile.Name = NameBox.Text.Trim();
        _profile.Host = HostBox.Text.Trim();
        _profile.Port = port;
        _profile.Username = UsernameBox.Text.Trim();
        _profile.Password = PasswordBox.Password;
        _profile.ExpectedHostKeySha256 = string.IsNullOrWhiteSpace(HostKeyBox.Text) ? null : HostKeyBox.Text.Trim();
        _profile.UseSophosAdvancedShell = AdvancedShellBox.IsChecked == true;
        _profile.SourceMode = SourceModeBox.SelectedItem is LogSourceMode sourceMode
            ? sourceMode
            : LogSourceMode.SophosEventDatabase;
        _profile.ExtraLogFiles = ExtraFilesBox.Text.Trim();

        Profile = _profile;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }
}
