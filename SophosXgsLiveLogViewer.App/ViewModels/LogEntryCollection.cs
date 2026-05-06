using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.App.ViewModels;

public sealed class LogEntryCollection : ObservableCollection<LogEntry>
{
    public void ReplaceWith(IEnumerable<LogEntry> entries)
    {
        ResetItems(entries);
    }

    public void PrependNewestBatch(IReadOnlyList<LogEntry> arrivals, int maxRows)
    {
        if (arrivals.Count == 0 || maxRows <= 0)
        {
            return;
        }

        var next = new List<LogEntry>(Math.Min(maxRows, arrivals.Count + Count));
        for (var index = arrivals.Count - 1; index >= 0 && next.Count < maxRows; index--)
        {
            next.Add(arrivals[index]);
        }

        for (var index = 0; index < Items.Count && next.Count < maxRows; index++)
        {
            next.Add(Items[index]);
        }

        ResetItems(next);
    }

    private void ResetItems(IEnumerable<LogEntry> entries)
    {
        CheckReentrancy();
        Items.Clear();

        foreach (var entry in entries)
        {
            Items.Add(entry);
        }

        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}
