using SophosXgsLiveLogViewer.App.Models;
using SophosXgsLiveLogViewer.App.ViewModels;

namespace SophosXgsLiveLogViewer.Tests;

public sealed class LogEntryCollectionTests
{
    [Fact]
    public void PrependNewestBatch_KeepsNewestAtTopAndCapsRows()
    {
        var entries = new LogEntryCollection();
        entries.ReplaceWith(
        [
            Entry("old-2"),
            Entry("old-1")
        ]);

        entries.PrependNewestBatch(
        [
            Entry("new-1"),
            Entry("new-2"),
            Entry("new-3")
        ], 4);

        Assert.Equal(["new-3", "new-2", "new-1", "old-2"], entries.Select(entry => entry.RawLine));
    }

    private static LogEntry Entry(string id)
    {
        return new LogEntry
        {
            RawLine = id
        };
    }
}
