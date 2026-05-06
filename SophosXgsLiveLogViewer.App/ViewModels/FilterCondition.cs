using System.ComponentModel;
using System.Runtime.CompilerServices;
using SophosXgsLiveLogViewer.App.Services;

namespace SophosXgsLiveLogViewer.App.ViewModels;

public sealed class FilterCondition : INotifyPropertyChanged
{
    private string _connector = "AND";
    private string _field = "src_ip";
    private string _operator = "Equals";
    private string _value = string.Empty;

    public event PropertyChangedEventHandler? PropertyChanged;

    public string Connector
    {
        get => _connector;
        set => SetField(ref _connector, value);
    }

    public string Field
    {
        get => _field;
        set => SetField(ref _field, value);
    }

    public string Operator
    {
        get => _operator;
        set => SetField(ref _operator, value);
    }

    public string Value
    {
        get => _value;
        set => SetField(ref _value, value);
    }

    public string DisplayText => $"{Connector} {ColumnNameFormatter.ToDisplayName(Field)} {Operator} {Value}";

    public override string ToString()
    {
        return DisplayText;
    }

    private void SetField(ref string target, string value, [CallerMemberName] string? propertyName = null)
    {
        if (string.Equals(target, value, StringComparison.Ordinal))
        {
            return;
        }

        target = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DisplayText)));
    }
}
