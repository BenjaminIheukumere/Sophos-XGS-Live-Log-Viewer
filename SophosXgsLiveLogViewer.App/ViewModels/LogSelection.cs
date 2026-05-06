using System.ComponentModel;
using System.Runtime.CompilerServices;
using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.App.ViewModels;

public sealed class LogSelection : INotifyPropertyChanged
{
    private bool _isSelected;

    public LogSelection(LogDefinition definition, bool isSelected)
    {
        Definition = definition;
        _isSelected = isSelected;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public LogDefinition Definition { get; }

    public string DisplayName => Definition.DisplayName;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value)
            {
                return;
            }

            _isSelected = value;
            OnPropertyChanged();
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
