using System.IO;
using System.Text.Json;
using SophosXgsLiveLogViewer.App.Models;
using SophosXgsLiveLogViewer.App.ViewModels;

namespace SophosXgsLiveLogViewer.App.Services;

public static class FilterPresetService
{
    private const int CurrentVersion = 1;
    private const int MaxPresetBytes = 256 * 1024;
    private const int MaxConditions = 50;
    private const int MaxTextLength = 512;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private static readonly HashSet<string> AllowedConnectors = new(StringComparer.OrdinalIgnoreCase)
    {
        "AND",
        "OR"
    };

    private static readonly HashSet<string> AllowedOperators = new(StringComparer.OrdinalIgnoreCase)
    {
        "Equals",
        "Not equals",
        "Contains",
        "Not contains",
        "Starts with",
        "Ends with"
    };

    public static FilterPreset CreatePreset(
        string logKey,
        string logName,
        IEnumerable<FilterCondition> conditions,
        string? name = null)
    {
        var preset = new FilterPreset
        {
            Version = CurrentVersion,
            Name = string.IsNullOrWhiteSpace(name) ? $"{logName} filter" : name.Trim(),
            LogKey = logKey,
            LogName = logName,
            Conditions = conditions.Select(condition => new FilterConditionPreset
            {
                Connector = NormalizeConnector(condition.Connector),
                Field = condition.Field,
                Operator = NormalizeOperator(condition.Operator),
                Value = condition.Value
            }).ToList()
        };

        Validate(preset);
        return preset;
    }

    public static void Save(string path, FilterPreset preset)
    {
        Validate(preset);
        File.WriteAllText(path, JsonSerializer.Serialize(preset, JsonOptions));
    }

    public static FilterPreset Load(string path)
    {
        var file = new FileInfo(path);
        if (!file.Exists)
        {
            throw new FileNotFoundException("Filter preset was not found.", path);
        }

        if (file.Length > MaxPresetBytes)
        {
            throw new InvalidDataException("Filter preset is too large.");
        }

        var preset = JsonSerializer.Deserialize<FilterPreset>(File.ReadAllText(path), JsonOptions)
            ?? throw new InvalidDataException("Filter preset is empty or invalid.");

        Validate(preset);
        return preset;
    }

    public static void Validate(FilterPreset preset)
    {
        if (preset.Version != CurrentVersion)
        {
            throw new InvalidDataException($"Filter preset version {preset.Version} is not supported.");
        }

        if (LogDefinition.Find(preset.LogKey) is null)
        {
            throw new InvalidDataException("Filter preset references an unknown log source.");
        }

        if (preset.Conditions.Count > MaxConditions)
        {
            throw new InvalidDataException($"Filter preset has more than {MaxConditions} conditions.");
        }

        foreach (var condition in preset.Conditions)
        {
            condition.Connector = NormalizeConnector(condition.Connector);
            condition.Operator = NormalizeOperator(condition.Operator);
            condition.Field = ValidateText(condition.Field, "field");
            condition.Value = ValidateText(condition.Value, "value");
        }
    }

    private static string NormalizeConnector(string connector)
    {
        var normalized = string.IsNullOrWhiteSpace(connector) ? "AND" : connector.Trim().ToUpperInvariant();
        if (!AllowedConnectors.Contains(normalized))
        {
            throw new InvalidDataException("Filter preset contains an unsupported connector.");
        }

        return normalized;
    }

    private static string NormalizeOperator(string value)
    {
        var normalized = string.IsNullOrWhiteSpace(value) ? "Equals" : value.Trim();
        var match = AllowedOperators.FirstOrDefault(operatorName => string.Equals(operatorName, normalized, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            throw new InvalidDataException("Filter preset contains an unsupported operator.");
        }

        return match;
    }

    private static string ValidateText(string value, string fieldName)
    {
        var trimmed = value.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            throw new InvalidDataException($"Filter preset condition {fieldName} is empty.");
        }

        if (trimmed.Length > MaxTextLength)
        {
            throw new InvalidDataException($"Filter preset condition {fieldName} is too long.");
        }

        return trimmed;
    }
}
