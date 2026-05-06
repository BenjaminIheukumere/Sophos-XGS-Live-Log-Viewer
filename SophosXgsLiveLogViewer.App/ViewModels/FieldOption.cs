using SophosXgsLiveLogViewer.App.Services;

namespace SophosXgsLiveLogViewer.App.ViewModels;

public sealed record FieldOption(string Key)
{
    public string DisplayName => ColumnNameFormatter.ToDisplayName(Key);

    public override string ToString()
    {
        return DisplayName;
    }
}
