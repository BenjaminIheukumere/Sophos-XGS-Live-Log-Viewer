using System.Windows;
using System.IO;
using System.Windows.Input;
using SophosXgsLiveLogViewer.App.Services;

namespace SophosXgsLiveLogViewer.App;

public partial class MasterPasswordWindow : Window
{
    private readonly bool _isNewVault;

    public MasterPasswordWindow(bool isNewVault)
    {
        InitializeComponent();
        WindowTheme.ApplyDarkFrame(this);
        _isNewVault = isNewVault;
        TitleText.Text = isNewVault ? "Neuen Vault anlegen" : "Vault entsperren";
        ConfirmRow.Visibility = isNewVault ? Visibility.Visible : Visibility.Collapsed;
        Loaded += (_, _) => MasterPasswordBox.Focus();
    }

    public ProfileVault? Vault { get; private set; }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        ErrorText.Text = string.Empty;

        try
        {
            if (_isNewVault)
            {
                if (!string.Equals(MasterPasswordBox.Password, ConfirmPasswordBox.Password, StringComparison.Ordinal))
                {
                    ErrorText.Text = "Masterpasswörter stimmen nicht überein.";
                    return;
                }

                Vault = ProfileVault.CreateNew(MasterPasswordBox.Password);
            }
            else
            {
                Vault = ProfileVault.Unlock(MasterPasswordBox.Password);
            }

            DialogResult = true;
        }
        catch (Exception ex) when (ex is ArgumentException or UnauthorizedAccessException or InvalidDataException)
        {
            ErrorText.Text = ex.Message;
        }
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void Window_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter)
        {
            return;
        }

        e.Handled = true;
        Ok_Click(sender, e);
    }
}
