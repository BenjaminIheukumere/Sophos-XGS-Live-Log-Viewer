using System.Diagnostics;
using System.Windows;
using System.Windows.Navigation;

namespace SophosXgsLiveLogViewer.App;

public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
        WindowTheme.ApplyDarkFrame(this);
    }

    private void Hyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri)
        {
            UseShellExecute = true
        });
        e.Handled = true;
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
