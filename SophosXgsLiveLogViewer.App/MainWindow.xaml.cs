using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using SophosXgsLiveLogViewer.App.Models;
using SophosXgsLiveLogViewer.App.Services;
using SophosXgsLiveLogViewer.App.ViewModels;

namespace SophosXgsLiveLogViewer.App;

public partial class MainWindow : Window
{
    private const string TimeColumnKey = "time";
    private const int MaxVisibleRows = 2_000;
    private const int MaxBufferedRows = 50_000;
    private const int MaxUiBatchSize = 500;

    private readonly ObservableCollection<FirewallProfile> _profiles = [];
    private readonly LogEntryCollection _entries = [];
    private readonly Queue<LogEntry> _entryBuffer = [];
    private readonly ConcurrentQueue<LogEntry> _pendingEntries = new();
    private readonly ObservableCollection<string> _diagnostics = [];
    private readonly ObservableCollection<FilterCondition> _filterConditions = [];
    private readonly ObservableCollection<CpuUsageItem> _cpuUsageItems = [];
    private readonly List<FieldOption> _filterFieldOptions = [];
    private readonly Dictionary<string, HashSet<string>> _availableFieldsByLog = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _selectedColumnsByLogMode = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _customizedColumnSelections = new(StringComparer.OrdinalIgnoreCase);
    private readonly SshLogStreamService _streamService = new();
    private readonly DemoLogStreamService _demoStreamService = new();
    private readonly UpdateCheckService _updateCheckService = new();
    private readonly DispatcherTimer _entryDrainTimer;

    private ProfileVault? _vault;
    private CancellationTokenSource? _streamCts;
    private readonly CancellationTokenSource _updateCheckCts = new();
    private LogDefinition _activeLog = LogDefinition.All.First(log => log.Key == "firewall");
    private long _received;
    private long _displayed;
    private long _pendingWhilePaused;
    private bool _isConnected;
    private bool _manualDisconnectRequested;
    private bool _suppressLogSelectionSave;
    private bool _isDetailedMode;

    public MainWindow()
    {
        InitializeComponent();
        WindowTheme.ApplyDarkFrame(this);
        DataContext = _entries;
        VersionText.Text = "Version " + FormatVersion(UpdateCheckService.CurrentVersion);
        ProfileCombo.ItemsSource = _profiles;
        ActiveLogCombo.ItemsSource = LogDefinition.All;
        DiagnosticsList.ItemsSource = _diagnostics;
        ActiveFiltersItemsControl.ItemsSource = _filterConditions;
        CpuItemsControl.ItemsSource = _cpuUsageItems;
        FilterConnectorBox.ItemsSource = new[] { "AND", "OR" };
        FilterConnectorBox.SelectedIndex = 0;
        StreamModeToggle.IsChecked = false;
        UpdateStreamModeToggle();
        FilterOperatorBox.ItemsSource = new[] { "Equals", "Not equals", "Contains", "Not contains", "Starts with", "Ends with" };
        FilterOperatorBox.SelectedIndex = 0;
        CaptureDurationBox.ItemsSource = new[] { "30s", "60s", "5m" };
        CaptureDurationBox.SelectedIndex = 1;
        _entryDrainTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(50)
        };
        _entryDrainTimer.Tick += (_, _) => DrainPendingEntries();
        _entryDrainTimer.Start();
        Loaded += MainWindow_Loaded;
    }

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        UnlockVaultOrClose();
        if (_vault is null)
        {
            return;
        }

        LoadProfilesIntoUi();
        RefreshLogSelection();
        RebuildColumns();
        UpdateCounters();
        _ = CheckForUpdatesOnStartupAsync(_updateCheckCts.Token);
    }

    private async Task CheckForUpdatesOnStartupAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(1.5), cancellationToken);

            var update = await _updateCheckService.CheckLatestAsync(UpdateCheckService.CurrentVersion, cancellationToken);
            if (update is null || cancellationToken.IsCancellationRequested)
            {
                return;
            }

            var updateWindow = new UpdateWindow(
                UpdateCheckService.CurrentVersion,
                update,
                _updateCheckService,
                cancellationToken)
            {
                Owner = this
            };

            if (updateWindow.ShowDialog() != true || string.IsNullOrWhiteSpace(updateWindow.DownloadedPath))
            {
                return;
            }

            SetStatus($"Applying update {FormatVersion(update.LatestVersion)} ...");
            ApplyDownloadedUpdate(updateWindow.DownloadedPath);
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex)
        {
            AddDiagnostic("Update check failed: " + ex.Message);
        }
    }

    private void UnlockVaultOrClose()
    {
        var dialog = new MasterPasswordWindow(!ProfileVault.Exists)
        {
            Owner = this
        };

        if (dialog.ShowDialog() != true || dialog.Vault is null)
        {
            Close();
            return;
        }

        _vault = dialog.Vault;
    }

    private void LoadProfilesIntoUi()
    {
        _profiles.Clear();

        if (_vault is null)
        {
            return;
        }

        foreach (var profile in _vault.Profiles.OrderBy(profile => profile.Name, StringComparer.OrdinalIgnoreCase))
        {
            _profiles.Add(profile);
        }

        ProfileCombo.SelectedIndex = _profiles.Count > 0 ? 0 : -1;
    }

    private void RefreshLogSelection()
    {
        var selectedKey = SelectedProfile()?.SelectedLogKeys.FirstOrDefault() ?? "firewall";
        _activeLog = LogDefinition.Find(selectedKey) ?? LogDefinition.All.First(log => log.Key == "firewall");

        _suppressLogSelectionSave = true;
        try
        {
            ActiveLogCombo.SelectedItem = _activeLog;
        }
        finally
        {
            _suppressLogSelectionSave = false;
        }

        RebuildActiveFieldCache();
        UpdateSelectedFilesText();
        UpdateFilterFieldOptions();
        RebuildVisibleRows();
    }

    private void ActiveLogCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressLogSelectionSave || ActiveLogCombo.SelectedItem is not LogDefinition log)
        {
            return;
        }

        _activeLog = log;
        var profile = SelectedProfile();
        if (profile is not null)
        {
            profile.SelectedLogKeys = [log.Key];
            SaveVault();
        }

        RebuildActiveFieldCache();
        UpdateSelectedFilesText();
        UpdateFilterFieldOptions();
        RebuildVisibleRows();
    }

    private void ProfileCombo_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        RefreshLogSelection();
    }

    private async void Connect_Click(object sender, RoutedEventArgs e)
    {
        if (_isConnected)
        {
            return;
        }

        var profile = SelectedProfile();
        if (profile is null)
        {
            SetStatus("No profile selected.");
            return;
        }

        if (profile.SourceMode == LogSourceMode.Demo)
        {
            Demo_Click(sender, e);
            return;
        }

        var selectedLogs = new[] { _activeLog }.ToList();

        _streamCts = new CancellationTokenSource();
        _manualDisconnectRequested = false;
        _isConnected = true;
        ClearCpuUsage();
        ConnectButton.IsEnabled = false;
        DisconnectButton.IsEnabled = true;
        ProfileCombo.IsEnabled = false;
        SetStatus("Starting connection ...");
        AddDiagnostic("=== SSH session started ===");

        try
        {
            await RunSshConnectionLoopAsync(profile, selectedLogs, _streamCts.Token);
        }
        catch (OperationCanceledException)
        {
            SetStatus("Stopped.");
        }
        catch (Exception ex)
        {
            AddDiagnostic("Exception: " + ex);
            SetStatus("Error: " + ex.Message);
        }
        finally
        {
            _streamService.Stop();
            _streamCts?.Dispose();
            _streamCts = null;
            _isConnected = false;
            ClearCpuUsage();
            ConnectButton.IsEnabled = true;
            DisconnectButton.IsEnabled = false;
            ProfileCombo.IsEnabled = true;
        }
    }

    private void Disconnect_Click(object sender, RoutedEventArgs e)
    {
        _manualDisconnectRequested = true;
        _streamCts?.Cancel();
        _streamService.Stop();
        SetStatus("Stopping ...");
    }

    private async Task RunSshConnectionLoopAsync(
        FirewallProfile profile,
        IReadOnlyCollection<LogDefinition> selectedLogs,
        CancellationToken cancellationToken)
    {
        var reconnectDelay = TimeSpan.FromSeconds(1);

        while (!cancellationToken.IsCancellationRequested && !_manualDisconnectRequested)
        {
            try
            {
                await _streamService.RunAsync(
                    profile,
                    selectedLogs,
                    LogFilter.MatchAll,
                    OnLogEntryReceived,
                    message => Dispatcher.Invoke(() => SetStatus(message)),
                    message => Dispatcher.Invoke(() => AddDiagnostic(message)),
                    fingerprint => Dispatcher.Invoke(() => TrustUnknownHostKey(profile, fingerprint)),
                    cancellationToken,
                    usage => Dispatcher.Invoke(() => OnCpuUsageReceived(usage)));

                reconnectDelay = TimeSpan.FromSeconds(1);
                if (!cancellationToken.IsCancellationRequested && !_manualDisconnectRequested)
                {
                    Dispatcher.Invoke(() =>
                    {
                        SetStatus("Connection lost. Reconnecting in 1s ...");
                        AddDiagnostic("SSH session ended unexpectedly. Reconnect scheduled.");
                    });
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested || _manualDisconnectRequested)
            {
                throw;
            }
            catch (Exception ex) when (!cancellationToken.IsCancellationRequested && !_manualDisconnectRequested)
            {
                var delay = reconnectDelay;
                Dispatcher.Invoke(() =>
                {
                    SetStatus($"Connection error. Reconnecting in {delay.TotalSeconds:0}s ...");
                    AddDiagnostic("Connection error: " + ex.Message);
                });
            }
            finally
            {
                _streamService.Stop();
            }

            await Task.Delay(reconnectDelay, cancellationToken);
            reconnectDelay = TimeSpan.FromSeconds(Math.Min(reconnectDelay.TotalSeconds * 2, 10));
        }
    }

    private async void Demo_Click(object sender, RoutedEventArgs e)
    {
        if (_isConnected)
        {
            return;
        }

        var selectedLogs = LogDefinition.All;

        _streamCts = new CancellationTokenSource();
        _isConnected = true;
        ClearCpuUsage();
        ConnectButton.IsEnabled = false;
        DisconnectButton.IsEnabled = true;
        ProfileCombo.IsEnabled = false;
        AddDiagnostic("=== Demo stream started ===");

        try
        {
            await Task.Run(() => _demoStreamService.RunAsync(
                selectedLogs,
                LogFilter.MatchAll,
                OnLogEntryReceived,
                message => Dispatcher.Invoke(() => SetStatus(message)),
                message => Dispatcher.Invoke(() => AddDiagnostic(message)),
                _streamCts.Token));
        }
        catch (OperationCanceledException)
        {
            SetStatus("Demo stopped.");
        }
        finally
        {
            _streamCts?.Dispose();
            _streamCts = null;
            _isConnected = false;
            ClearCpuUsage();
            ConnectButton.IsEnabled = true;
            DisconnectButton.IsEnabled = false;
            ProfileCombo.IsEnabled = true;
        }
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        _pendingEntries.Clear();
        _entries.Clear();
        _entryBuffer.Clear();
        _availableFieldsByLog.Clear();
        _diagnostics.Clear();
        ClearCpuUsage();
        _received = 0;
        _displayed = 0;
        _pendingWhilePaused = 0;
        UpdateCounters();
    }

    private void ResetFilter_Click(object sender, RoutedEventArgs e)
    {
        ClearFilterConditions();
        _pendingWhilePaused = 0;
        FilterValueBox.Text = string.Empty;
        FilterConnectorBox.SelectedIndex = 0;
        FilterOperatorBox.SelectedIndex = 0;
        SetStatus("Filter reset.");
        UpdateFilterFieldOptions();
        RebuildVisibleRows();
    }

    private void ClearFilterConditions()
    {
        foreach (var condition in _filterConditions)
        {
            condition.PropertyChanged -= FilterCondition_PropertyChanged;
        }

        _filterConditions.Clear();
    }

    private void AddFilter_Click(object sender, RoutedEventArgs e)
    {
        var field = ResolveFilterFieldKey(FilterFieldBox.Text);
        var value = FilterValueBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(field) || string.IsNullOrWhiteSpace(value))
        {
            SetStatus("Filter field and value are required.");
            return;
        }

        var condition = new FilterCondition
        {
            Connector = FilterConnectorBox.SelectedItem as string ?? "AND",
            Field = field,
            Operator = FilterOperatorBox.SelectedItem as string ?? "Equals",
            Value = value
        };

        condition.PropertyChanged += FilterCondition_PropertyChanged;
        _filterConditions.Add(condition);
        FilterValueBox.Text = string.Empty;
        RebuildVisibleRows();
    }

    private void ImportFilters_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Import filter preset",
            Filter = "Sophos filter preset (*.sxlv-filter.json)|*.sxlv-filter.json|JSON files (*.json)|*.json|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false
        };

        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            var preset = FilterPresetService.Load(dialog.FileName);
            ApplyFilterPreset(preset);
            SetStatus($"Imported {preset.Conditions.Count:N0} filter condition(s) for {preset.LogName}.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or System.Text.Json.JsonException)
        {
            SetStatus("Filter import failed: " + ex.Message);
        }
    }

    private void ExportFilters_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var preset = CreateCurrentFilterPreset();
            var fileName = $"sxlv-filter-{_activeLog.Key}-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.sxlv-filter.json";
            var dialog = new SaveFileDialog
            {
                Title = "Export filter preset",
                FileName = fileName,
                Filter = "Sophos filter preset (*.sxlv-filter.json)|*.sxlv-filter.json|JSON files (*.json)|*.json|All files (*.*)|*.*",
                OverwritePrompt = true
            };

            if (dialog.ShowDialog(this) != true)
            {
                return;
            }

            FilterPresetService.Save(dialog.FileName, preset);
            SetStatus($"Exported {preset.Conditions.Count:N0} filter condition(s): {dialog.FileName}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            SetStatus("Filter export failed: " + ex.Message);
        }
    }

    private async void Capture_Click(object sender, RoutedEventArgs e)
    {
        if (CaptureButton.IsEnabled == false)
        {
            return;
        }

        var duration = ParseCaptureDuration(CaptureDurationBox.SelectedItem as string ?? CaptureDurationBox.Text);
        var capturedAt = DateTimeOffset.Now;
        var windowStart = capturedAt - duration;
        var preset = CreateCurrentFilterPreset();
        var rows = _entryBuffer
            .Where(entry => entry.ReceivedAt >= windowStart
                && entry.ReceivedAt <= capturedAt
                && MatchesSelectedLogAndMode(entry)
                && MatchesFilterConditions(entry))
            .ToList();

        CaptureButton.IsEnabled = false;
        SetStatus($"Writing capture for last {FormatDuration(duration)} ...");

        try
        {
            var outputPath = await Task.Run(() => IncidentCaptureService.CreateCaptureZip(
                rows,
                _activeLog,
                preset,
                duration,
                capturedAt));

            SetStatus($"Capture saved: {outputPath} ({rows.Count:N0} row(s)).");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            SetStatus("Capture failed: " + ex.Message);
        }
        finally
        {
            CaptureButton.IsEnabled = true;
        }
    }

    private void RemoveFilter_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: FilterCondition condition })
        {
            return;
        }

        condition.PropertyChanged -= FilterCondition_PropertyChanged;
        _filterConditions.Remove(condition);
        _pendingWhilePaused = 0;
        RebuildVisibleRows();
    }

    private void FilterFieldBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateFilterValueOptions();
    }

    private void FilterCondition_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        RebuildVisibleRows();
    }

    private void ColumnPicker_Click(object sender, RoutedEventArgs e)
    {
        var availableFields = GetAvailableFieldKeys();
        var availableColumns = GetAvailableColumnKeys(availableFields);
        var selectedColumns = GetSelectedColumnKeys(availableColumns);
        var menu = new ContextMenu
        {
            PlacementTarget = ColumnPickerButton
        };

        if (availableColumns.Count == 0)
        {
            menu.Items.Add(new MenuItem
            {
                Header = "No fields observed yet",
                IsEnabled = false
            });
        }
        else
        {
            var defaultColumns = GetDefaultColumnKeys(availableFields);
            foreach (var field in availableColumns)
            {
                var item = new MenuItem
                {
                    Header = defaultColumns.Contains(field, StringComparer.OrdinalIgnoreCase)
                        ? ColumnNameFormatter.ToDisplayName(field) + "  (default)"
                        : ColumnNameFormatter.ToDisplayName(field),
                    ToolTip = field,
                    IsCheckable = true,
                    IsChecked = selectedColumns.Contains(field)
                };

                item.Click += (_, _) =>
                {
                    var selectionKey = GetColumnSelectionKey();
                    if (item.IsChecked)
                    {
                        _customizedColumnSelections.Add(selectionKey);
                        selectedColumns.Add(field);
                    }
                    else
                    {
                        if (selectedColumns.Count <= 1)
                        {
                            item.IsChecked = true;
                            SetStatus("At least one column must stay visible.");
                            return;
                        }

                        _customizedColumnSelections.Add(selectionKey);
                        selectedColumns.Remove(field);
                    }

                    RebuildColumns();
                    UpdateSelectedFilesText();
                };

                menu.Items.Add(item);
            }
        }

        ColumnPickerButton.ContextMenu = menu;
        menu.IsOpen = true;
    }

    private void LogGrid_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is not DependencyObject source)
        {
            return;
        }

        var cell = FindAncestor<DataGridCell>(source);
        if (cell?.DataContext is not LogEntry entry)
        {
            return;
        }

        var field = cell.Column?.SortMemberPath;
        if (string.IsNullOrWhiteSpace(field))
        {
            return;
        }

        var value = GetGridCellValue(entry, field);
        try
        {
            Clipboard.SetText(value);
            SetStatus($"Copied {ColumnNameFormatter.ToDisplayName(field)}: {Truncate(value, 120)}");
        }
        catch (ExternalException ex)
        {
            SetStatus("Clipboard unavailable: " + ex.Message);
        }
    }

    private void AddProfile_Click(object sender, RoutedEventArgs e)
    {
        var profile = new FirewallProfile
        {
            Name = "New firewall",
            Port = 22,
            UseSophosAdvancedShell = true,
            SourceMode = LogSourceMode.SophosEventDatabase,
            SelectedLogKeys = [_activeLog.Key]
        };

        var dialog = new ProfileEditorWindow(profile) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.Profile is null)
        {
            return;
        }

        _profiles.Add(dialog.Profile);
        SyncProfilesToVault();
        ProfileCombo.SelectedItem = dialog.Profile;
    }

    private void EditProfile_Click(object sender, RoutedEventArgs e)
    {
        var existing = SelectedProfile();
        if (existing is null)
        {
            return;
        }

        var dialog = new ProfileEditorWindow(existing) { Owner = this };
        if (dialog.ShowDialog() != true || dialog.Profile is null)
        {
            return;
        }

        var index = _profiles.IndexOf(existing);
        if (index >= 0)
        {
            _profiles[index] = dialog.Profile;
            SyncProfilesToVault();
            ProfileCombo.SelectedItem = dialog.Profile;
        }
    }

    private void DeleteProfile_Click(object sender, RoutedEventArgs e)
    {
        var profile = SelectedProfile();
        if (profile is null)
        {
            return;
        }

        var result = MessageBox.Show(this, $"Delete profile '{profile.Name}'?", "Delete profile", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (result != MessageBoxResult.Yes)
        {
            return;
        }

        _profiles.Remove(profile);
        SyncProfilesToVault();
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        new AboutWindow
        {
            Owner = this
        }.ShowDialog();
    }

    private void StreamModeToggle_Click(object sender, RoutedEventArgs e)
    {
        _isDetailedMode = StreamModeToggle.IsChecked == true;
        _pendingWhilePaused = 0;
        UpdateStreamModeToggle();
        RebuildActiveFieldCache();
        RebuildVisibleRows();
        SetStatus(_isDetailedMode
            ? "Detailed mode: showing enriched Event DB rows."
            : "Fast mode: showing immediate live stream rows.");
    }

    private void UpdateStreamModeToggle()
    {
        StreamModeToggle.Content = _isDetailedMode ? "Detailed mode" : "Fast mode";
        StreamModeToggle.ToolTip = _isDetailedMode
            ? "Detailed mode uses enriched Sophos Event DB rows. Click to switch to fast live stream."
            : "Fast mode uses immediate conntrack and raw log tails. Click to switch to detailed Event DB rows.";
    }

    private void OnLogEntryReceived(LogEntry entry)
    {
        _pendingEntries.Enqueue(entry);
    }

    private void DrainPendingEntries()
    {
        if (_pendingEntries.IsEmpty)
        {
            return;
        }

        var visibleBatch = new List<LogEntry>(MaxUiBatchSize);
        var activeFieldsChanged = false;
        var processed = 0;

        while (processed < MaxUiBatchSize && _pendingEntries.TryDequeue(out var entry))
        {
            processed++;
            _received++;
            _entryBuffer.Enqueue(entry);

            while (_entryBuffer.Count > MaxBufferedRows)
            {
                _entryBuffer.Dequeue();
            }

            var matchesActiveLog = MatchesSelectedLogAndMode(entry);
            if (matchesActiveLog)
            {
                activeFieldsChanged |= AddObservedFields(_activeLog.Key, entry);
            }

            if (!matchesActiveLog || !MatchesFilterConditions(entry))
            {
                continue;
            }

            if (PauseLiveScrollButton.IsChecked == true)
            {
                _pendingWhilePaused++;
                continue;
            }

            visibleBatch.Add(entry);
        }

        if (visibleBatch.Count > 0)
        {
            _entries.PrependNewestBatch(visibleBatch, MaxVisibleRows);
            _displayed += visibleBatch.Count;
        }

        if (activeFieldsChanged)
        {
            UpdateFilterFieldOptions();
            RebuildColumns();
            UpdateSelectedFilesText();
        }

        UpdateCounters();

        if (visibleBatch.Count > 0)
        {
            ScrollNewestIntoView();
        }
    }

    private void PauseLiveScrollButton_Checked(object sender, RoutedEventArgs e)
    {
        _pendingWhilePaused = 0;
        UpdateCounters();
        SetStatus("Live display paused. Incoming matching entries are buffered.");
    }

    private void PauseLiveScrollButton_Unchecked(object sender, RoutedEventArgs e)
    {
        var pending = _pendingWhilePaused;
        _pendingWhilePaused = 0;
        RebuildVisibleRows();

        SetStatus(pending > 0
            ? $"Live display resumed. Applied {pending:N0} buffered entries."
            : "Live display resumed.");
    }

    private void OnCpuUsageReceived(ApplianceCpuUsage usage)
    {
        var items = new List<(string Label, double Percent)>
        {
            ("Total", usage.TotalUsagePercent)
        };

        items.AddRange(usage.Cores
            .OrderBy(core => ParseCpuCoreIndex(core.Name))
            .Select(core => (FormatCpuCoreLabel(core.Name), core.UsagePercent)));

        for (var index = _cpuUsageItems.Count - 1; index >= items.Count; index--)
        {
            _cpuUsageItems.RemoveAt(index);
        }

        for (var index = 0; index < items.Count; index++)
        {
            if (index >= _cpuUsageItems.Count)
            {
                _cpuUsageItems.Add(new CpuUsageItem());
            }

            _cpuUsageItems[index].Label = items[index].Label;
            _cpuUsageItems[index].UsagePercent = items[index].Percent;
        }
    }

    private void ClearCpuUsage()
    {
        _cpuUsageItems.Clear();
    }

    private bool TrustUnknownHostKey(FirewallProfile profile, string fingerprint)
    {
        if (!string.IsNullOrWhiteSpace(profile.ExpectedHostKeySha256))
        {
            return true;
        }

        var result = MessageBox.Show(
            this,
            $"Unknown SSH host key for {profile.Host}:\n\n{fingerprint}\n\nTrust this host key and save it to the profile?",
            "Verify SSH host key",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes)
        {
            SetStatus("SSH host key was not trusted.");
            return false;
        }

        profile.ExpectedHostKeySha256 = fingerprint;
        SaveVault();
        SetStatus("SSH host key saved: " + fingerprint);
        return true;
    }

    private FirewallProfile? SelectedProfile()
    {
        return ProfileCombo.SelectedItem as FirewallProfile;
    }

    private void UpdateSelectedFilesText()
    {
        var availableFields = GetAvailableFieldKeys().Count;
        var visibleColumns = GetVisibleColumnKeys().Count;
        var mode = _isDetailedMode ? "Detailed Event DB mode" : "Fast live mode";
        SelectedFilesText.Text = $"{_activeLog.DisplayName}. {mode}. {visibleColumns:N0}/{availableFields + 1:N0} column(s) visible. Log and mode switches stay in the same SSH session.";
    }

    private bool MatchesSelectedLogAndMode(LogEntry entry)
    {
        return _activeLog.MatchesEvent(entry) && MatchesCurrentStreamMode(entry);
    }

    private bool MatchesCurrentStreamMode(LogEntry entry)
    {
        if (SelectedProfile()?.SourceMode == LogSourceMode.Demo)
        {
            return true;
        }

        return _isDetailedMode
            ? string.Equals(entry.SourceLogFile, "eventdb", StringComparison.OrdinalIgnoreCase)
            : !string.Equals(entry.SourceLogFile, "eventdb", StringComparison.OrdinalIgnoreCase);
    }

    private void SyncProfilesToVault()
    {
        if (_vault is null)
        {
            return;
        }

        _vault.Profiles.Clear();
        _vault.Profiles.AddRange(_profiles);
        SaveVault();
        RefreshLogSelection();
    }

    private void SaveVault()
    {
        try
        {
            _vault?.Save();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            SetStatus("Vault could not be saved: " + ex.Message);
        }
    }

    private void AddDiagnostic(string message)
    {
        _diagnostics.Insert(0, $"{DateTimeOffset.Now:HH:mm:ss.fff}  {message}");

        while (_diagnostics.Count > 300)
        {
            _diagnostics.RemoveAt(_diagnostics.Count - 1);
        }
    }

    private void SetStatus(string message)
    {
        StatusText.Text = message;
    }

    private void UpdateCounters()
    {
        var paused = PauseLiveScrollButton.IsChecked == true
            ? $"   Paused: {_pendingWhilePaused:N0}"
            : string.Empty;
        var mode = _isDetailedMode ? "Detailed" : "Fast";
        CountersText.Text = $"Mode: {mode}   Visible window: {_entries.Count:N0}/{MaxVisibleRows:N0}   Buffer: {_entryBuffer.Count:N0}/{MaxBufferedRows:N0}   Received: {_received:N0}   Displayed: {_displayed:N0}{paused}";
    }

    private void RebuildVisibleRows()
    {
        var visibleRows = _entryBuffer
            .Reverse()
            .Where(entry => MatchesSelectedLogAndMode(entry) && MatchesFilterConditions(entry))
            .Take(MaxVisibleRows)
            .ToList();

        _entries.ReplaceWith(visibleRows);
        _displayed = visibleRows.Count;

        RebuildColumns();
        UpdateFilterFieldOptions();
        UpdateSelectedFilesText();
        UpdateCounters();
        ScrollNewestIntoView();
    }

    private void ScrollNewestIntoView()
    {
        if (PauseLiveScrollButton.IsChecked == true || _entries.Count == 0)
        {
            return;
        }

        LogGrid.ScrollIntoView(_entries[0]);
    }

    private bool MatchesFilterConditions(LogEntry entry)
    {
        if (_filterConditions.Count == 0)
        {
            return true;
        }

        bool? result = null;
        foreach (var condition in _filterConditions)
        {
            var conditionResult = MatchesFilterCondition(entry, condition);
            if (result is null)
            {
                result = conditionResult;
                continue;
            }

            result = string.Equals(condition.Connector, "OR", StringComparison.OrdinalIgnoreCase)
                ? result.Value || conditionResult
                : result.Value && conditionResult;
        }

        return result == true;
    }

    private static bool MatchesFilterCondition(LogEntry entry, FilterCondition condition)
    {
        var actual = GetEntryFieldValue(entry, condition.Field);
        var expected = condition.Value;

        return condition.Operator switch
        {
            "Not equals" => !string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase),
            "Contains" => actual.Contains(expected, StringComparison.OrdinalIgnoreCase),
            "Not contains" => !actual.Contains(expected, StringComparison.OrdinalIgnoreCase),
            "Starts with" => actual.StartsWith(expected, StringComparison.OrdinalIgnoreCase),
            "Ends with" => actual.EndsWith(expected, StringComparison.OrdinalIgnoreCase),
            _ => string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)
        };
    }

    private static string GetEntryFieldValue(LogEntry entry, string field)
    {
        return field switch
        {
            "time" => entry.OccurredAt.ToString("yyyy-MM-dd HH:mm:ss"),
            _ => entry.Fields.TryGetValue(field, out var value) ? value : string.Empty
        };
    }

    private void RebuildColumns()
    {
        var columnKeys = GetVisibleColumnKeys();
        var fieldKeys = columnKeys
            .Where(key => !string.Equals(key, TimeColumnKey, StringComparison.OrdinalIgnoreCase))
            .ToList();
        var currentSignature = string.Join('\u001f', LogGrid.Columns.OfType<DataGridTextColumn>().Select(column => column.SortMemberPath));
        var nextSignature = string.Join('\u001f', columnKeys);

        if (string.Equals(currentSignature, nextSignature, StringComparison.Ordinal))
        {
            return;
        }

        LogGrid.Columns.Clear();
        var textCellStyle = (Style)FindResource("LogGridTextCellStyle");
        if (columnKeys.Contains(TimeColumnKey, StringComparer.OrdinalIgnoreCase))
        {
            LogGrid.Columns.Add(new DataGridTextColumn
            {
                Header = ColumnNameFormatter.ToDisplayName(TimeColumnKey),
                Binding = new Binding(nameof(LogEntry.OccurredAt)) { StringFormat = "HH:mm:ss" },
                ElementStyle = textCellStyle,
                SortMemberPath = TimeColumnKey,
                Width = 92
            });
        }

        foreach (var key in fieldKeys)
        {
            LogGrid.Columns.Add(new DataGridTextColumn
            {
                Header = ColumnNameFormatter.ToDisplayName(key),
                Binding = new Binding($"Fields[{key}]"),
                ElementStyle = textCellStyle,
                SortMemberPath = key,
                Width = new DataGridLength(GetColumnWidth(key))
            });
        }
    }

    private List<string> GetVisibleColumnKeys()
    {
        var availableFields = GetAvailableFieldKeys();
        var availableColumns = GetAvailableColumnKeys(availableFields);
        return GetSelectedColumnKeys(availableColumns)
            .Where(field => availableColumns.Contains(field, StringComparer.OrdinalIgnoreCase))
            .ToList();
    }

    private List<string> GetAvailableFieldKeys()
    {
        return GetObservedFields(_activeLog.Key)
            .Where(key => !string.IsNullOrWhiteSpace(key))
            .Where(key => _isDetailedMode || !LogColumnPolicy.IsFastModeHiddenField(key))
            .OrderBy(key => key, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private HashSet<string> GetObservedFields(string logKey)
    {
        if (!_availableFieldsByLog.TryGetValue(logKey, out var fields))
        {
            fields = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _availableFieldsByLog[logKey] = fields;
        }

        return fields;
    }

    private void RebuildActiveFieldCache()
    {
        var fields = GetObservedFields(_activeLog.Key);
        fields.Clear();

        foreach (var entry in _entryBuffer)
        {
            if (MatchesSelectedLogAndMode(entry))
            {
                AddObservedFields(_activeLog.Key, entry);
            }
        }
    }

    private bool AddObservedFields(string logKey, LogEntry entry)
    {
        var fields = GetObservedFields(logKey);
        var changed = false;

        foreach (var key in entry.Fields.Keys)
        {
            if (!string.IsNullOrWhiteSpace(key))
            {
                changed |= fields.Add(key);
            }
        }

        return changed;
    }

    private List<string> GetAvailableColumnKeys(IEnumerable<string> availableFields)
    {
        return new[] { TimeColumnKey }
            .Concat(availableFields)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private List<string> GetDefaultColumnKeys(IEnumerable<string> availableFields)
    {
        return new[] { TimeColumnKey }
            .Concat(LogColumnPolicy.SelectDefaultFields(_activeLog, availableFields))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private HashSet<string> GetSelectedColumnKeys(IReadOnlyList<string> availableColumns)
    {
        var key = GetColumnSelectionKey();
        var hasCustomSelection = _customizedColumnSelections.Contains(key);
        if (!_selectedColumnsByLogMode.TryGetValue(key, out var fields))
        {
            fields = new HashSet<string>(GetDefaultColumnKeys(GetAvailableFieldKeys()), StringComparer.OrdinalIgnoreCase);
            _selectedColumnsByLogMode[key] = fields;
        }
        else if (!hasCustomSelection)
        {
            fields.Clear();
            foreach (var field in GetDefaultColumnKeys(GetAvailableFieldKeys()))
            {
                fields.Add(field);
            }
        }

        fields.RemoveWhere(field => !availableColumns.Contains(field, StringComparer.OrdinalIgnoreCase));
        if (fields.Count == 0 && availableColumns.Count > 0)
        {
            fields.Add(availableColumns[0]);
        }

        return fields;
    }

    private string GetColumnSelectionKey()
    {
        var mode = _isDetailedMode ? "detailed" : "fast";
        return $"{_activeLog.Key}:{mode}";
    }

    private static double GetColumnWidth(string key)
    {
        return key switch
        {
            "message" or "url" or "reason" => 260,
            "device_name" or "domain" or "fw_rule_name" or "nat_rule_name" => 190,
            "src_ip" or "dst_ip" or "in_display_interface" or "out_display_interface" => 145,
            _ => 115
        };
    }

    private static string GetGridCellValue(LogEntry entry, string field)
    {
        return string.Equals(field, "time", StringComparison.OrdinalIgnoreCase)
            ? entry.OccurredAt.ToString("yyyy-MM-dd HH:mm:ss")
            : GetEntryFieldValue(entry, field);
    }

    private static T? FindAncestor<T>(DependencyObject? source) where T : DependencyObject
    {
        while (source is not null)
        {
            if (source is T match)
            {
                return match;
            }

            source = VisualTreeHelper.GetParent(source);
        }

        return null;
    }

    private static string FormatCpuCoreLabel(string name)
    {
        return name.StartsWith("cpu", StringComparison.OrdinalIgnoreCase) && name.Length > 3
            ? "C" + name[3..]
            : name;
    }

    private static int ParseCpuCoreIndex(string name)
    {
        return name.StartsWith("cpu", StringComparison.OrdinalIgnoreCase)
            && int.TryParse(name[3..], out var index)
                ? index
                : int.MaxValue;
    }

    private static string FormatVersion(Version version)
    {
        return version.Build >= 0
            ? $"{version.Major}.{version.Minor}.{version.Build}"
            : $"{version.Major}.{version.Minor}";
    }

    private static void ApplyDownloadedUpdate(string downloadedPath)
    {
        var targetPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(targetPath) || !File.Exists(targetPath))
        {
            throw new InvalidOperationException("The running application path could not be resolved.");
        }

        var updaterScript = UpdateCheckService.CreateUpdaterScript(
            downloadedPath,
            targetPath,
            Environment.ProcessId);

        Process.Start(new ProcessStartInfo(updaterScript)
        {
            UseShellExecute = true,
            WindowStyle = ProcessWindowStyle.Hidden
        });

        Application.Current.Shutdown();
    }

    private static string Truncate(string value, int maxLength)
    {
        return value.Length <= maxLength ? value : value[..maxLength] + "...";
    }

    private void UpdateFilterFieldOptions()
    {
        var currentInput = FilterFieldBox.Text;
        var currentKey = ResolveFilterFieldKey(currentInput);
        var fields = new[] { "time" }
            .Concat(LogColumnPolicy.PreferredFieldOrder)
            .Concat(GetAvailableFieldKeys())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        _filterFieldOptions.Clear();
        _filterFieldOptions.AddRange(fields.Select(field => new FieldOption(field)));
        FilterFieldBox.ItemsSource = _filterFieldOptions;

        var selected = _filterFieldOptions.FirstOrDefault(option => string.Equals(option.Key, currentKey, StringComparison.OrdinalIgnoreCase));
        if (selected is not null)
        {
            FilterFieldBox.SelectedItem = selected;
        }
        else if (!string.IsNullOrWhiteSpace(currentInput))
        {
            FilterFieldBox.Text = currentInput;
        }
        else if (_filterFieldOptions.Count > 0)
        {
            FilterFieldBox.SelectedIndex = 0;
        }

        UpdateFilterValueOptions();
    }

    private void UpdateFilterValueOptions()
    {
        var field = ResolveFilterFieldKey(FilterFieldBox.Text);
        if (string.IsNullOrWhiteSpace(field))
        {
            FilterValueBox.ItemsSource = Array.Empty<string>();
            return;
        }

        var values = _entryBuffer
            .Where(MatchesSelectedLogAndMode)
            .Select(entry => GetEntryFieldValue(entry, field))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .Take(300)
            .ToList();

        var current = FilterValueBox.Text;
        FilterValueBox.ItemsSource = values;
        FilterValueBox.Text = current;
    }

    private string ResolveFilterFieldKey(string input)
    {
        var trimmed = input.Trim();
        if (string.IsNullOrWhiteSpace(trimmed) && FilterFieldBox.SelectedItem is FieldOption selectedWithoutText)
        {
            return selectedWithoutText.Key;
        }

        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return string.Empty;
        }

        if (FilterFieldBox.SelectedItem is FieldOption selected
            && (string.Equals(selected.DisplayName, trimmed, StringComparison.OrdinalIgnoreCase)
                || string.Equals(selected.Key, trimmed, StringComparison.OrdinalIgnoreCase)))
        {
            return selected.Key;
        }

        if (FilterFieldBox.SelectedValue is string selectedValue
            && !string.IsNullOrWhiteSpace(selectedValue)
            && string.Equals(selectedValue, trimmed, StringComparison.OrdinalIgnoreCase))
        {
            return selectedValue.Trim();
        }

        var match = _filterFieldOptions.FirstOrDefault(option =>
            string.Equals(option.DisplayName, trimmed, StringComparison.OrdinalIgnoreCase)
            || string.Equals(option.Key, trimmed, StringComparison.OrdinalIgnoreCase));

        return match?.Key ?? trimmed;
    }

    private FilterPreset CreateCurrentFilterPreset()
    {
        return FilterPresetService.CreatePreset(
            _activeLog.Key,
            _activeLog.DisplayName,
            _filterConditions,
            $"{_activeLog.DisplayName} investigation");
    }

    private void ApplyFilterPreset(FilterPreset preset)
    {
        var log = LogDefinition.Find(preset.LogKey)
            ?? throw new InvalidDataException("Filter preset references an unknown log source.");

        _activeLog = log;
        var profile = SelectedProfile();
        if (profile is not null)
        {
            profile.SelectedLogKeys = [log.Key];
            SaveVault();
        }

        _suppressLogSelectionSave = true;
        try
        {
            ActiveLogCombo.SelectedItem = log;
        }
        finally
        {
            _suppressLogSelectionSave = false;
        }

        ClearFilterConditions();
        foreach (var imported in preset.Conditions)
        {
            var condition = new FilterCondition
            {
                Connector = imported.Connector,
                Field = imported.Field,
                Operator = imported.Operator,
                Value = imported.Value
            };

            condition.PropertyChanged += FilterCondition_PropertyChanged;
            _filterConditions.Add(condition);
        }

        FilterConnectorBox.SelectedIndex = 0;
        FilterOperatorBox.SelectedIndex = 0;
        FilterValueBox.Text = string.Empty;
        RebuildActiveFieldCache();
        UpdateSelectedFilesText();
        UpdateFilterFieldOptions();
        RebuildVisibleRows();
    }

    private static TimeSpan ParseCaptureDuration(string value)
    {
        return value.Trim().ToLowerInvariant() switch
        {
            "30s" => TimeSpan.FromSeconds(30),
            "5m" => TimeSpan.FromMinutes(5),
            _ => TimeSpan.FromSeconds(60)
        };
    }

    private static string FormatDuration(TimeSpan duration)
    {
        return duration.TotalMinutes >= 1
            ? $"{duration.TotalMinutes:0}m"
            : $"{duration.TotalSeconds:0}s";
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        _updateCheckCts.Cancel();
        _updateCheckCts.Dispose();
        _streamCts?.Cancel();
        _streamService.Dispose();
        _vault?.Dispose();
    }
}
