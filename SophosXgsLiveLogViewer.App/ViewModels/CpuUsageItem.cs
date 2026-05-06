using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace SophosXgsLiveLogViewer.App.ViewModels;

public sealed class CpuUsageItem : INotifyPropertyChanged
{
    private string _label = string.Empty;
    private double _usagePercent;

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Label
    {
        get => _label;
        set
        {
            if (string.Equals(_label, value, StringComparison.Ordinal))
            {
                return;
            }

            _label = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(DisplayText));
        }
    }

    public double UsagePercent
    {
        get => _usagePercent;
        set
        {
            if (Math.Abs(_usagePercent - value) < 0.05)
            {
                return;
            }

            _usagePercent = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(DisplayText));
            OnPropertyChanged(nameof(State));
        }
    }

    public string DisplayText => $"{Label} {UsagePercent:0}%";

    public string State => UsagePercent > 75
        ? "High"
        : UsagePercent < 20
            ? "Low"
            : "Medium";

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
