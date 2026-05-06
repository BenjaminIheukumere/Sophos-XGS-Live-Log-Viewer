using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SophosXgsLiveLogViewer.App.Models;

namespace SophosXgsLiveLogViewer.App.Services;

public sealed partial class LogFilter
{
    private static readonly LogFilter MatchAllFilter = new(_ => true, string.Empty);

    private readonly Func<LogEntry, bool> _predicate;

    private LogFilter(Func<LogEntry, bool> predicate, string expression)
    {
        _predicate = predicate;
        Expression = expression;
    }

    public string Expression { get; }

    public static LogFilter MatchAll => MatchAllFilter;

    public bool IsMatch(LogEntry entry)
    {
        return _predicate(entry);
    }

    public static LogFilter Compile(string? expression)
    {
        if (string.IsNullOrWhiteSpace(expression))
        {
            return MatchAll;
        }

        var parser = new Parser(expression);
        var predicate = parser.Parse();
        return new LogFilter(predicate, expression);
    }

    private static string GetField(LogEntry entry, string fieldName)
    {
        var normalized = NormalizeFieldName(fieldName);
        return normalized switch
        {
            "time" => entry.OccurredAt.ToString("O", CultureInfo.InvariantCulture),
            "log" or "file" => entry.SourceLogFile,
            "log_type" => entry.LogType,
            "component" or "log_component" => entry.Component,
            "subtype" or "log_subtype" => entry.Subtype,
            "status" or "action" => entry.Status,
            "username" or "user" or "user_name" => entry.Username,
            "fw_rule_id" or "firewall_rule" or "rule" => entry.FirewallRule,
            "fw_rule_name" or "firewall_rule_name" or "rulename" => entry.FirewallRuleName,
            "nat_rule_id" or "nat_rule" => entry.NatRule,
            "nat_rule_name" => entry.NatRuleName,
            "in_interface" or "interface_in" => entry.InInterface,
            "out_interface" or "interface_out" => entry.OutInterface,
            "src_ip" => entry.SourceIp,
            "dst_ip" => entry.DestinationIp,
            "src_port" => entry.SourcePort,
            "dst_port" => entry.DestinationPort,
            "protocol" => entry.Protocol,
            "message" => entry.Message,
            "raw" => entry.RawLine,
            _ => entry.Fields.TryGetValue(normalized, out var value) ? value : string.Empty
        };
    }

    private static string NormalizeFieldName(string fieldName)
    {
        var lower = fieldName.Trim().Replace("-", "_", StringComparison.Ordinal).ToLowerInvariant();

        return lower switch
        {
            "sourceip" or "srcip" or "source_ip" => "src_ip",
            "destinationip" or "dstip" or "destip" or "destination_ip" or "dest_ip" => "dst_ip",
            "sourceport" or "srcport" or "source_port" or "sport" => "src_port",
            "destinationport" or "dstport" or "destport" or "destination_port" or "dest_port" or "dport" => "dst_port",
            "logtype" => "log_type",
            "logcomponent" => "log_component",
            "logsubtype" => "log_subtype",
            _ => lower
        };
    }

    private enum TokenKind
    {
        Identifier,
        Value,
        And,
        Or,
        Not,
        In,
        Equals,
        NotEquals,
        Contains,
        LParen,
        RParen,
        Comma,
        End
    }

    private sealed record Token(TokenKind Kind, string Text);

    private sealed partial class Parser
    {
        private readonly List<Token> _tokens;
        private int _position;

        public Parser(string expression)
        {
            _tokens = Tokenize(expression);
        }

        public Func<LogEntry, bool> Parse()
        {
            var predicate = ParseOr();
            Expect(TokenKind.End);
            return predicate;
        }

        private Func<LogEntry, bool> ParseOr()
        {
            var left = ParseAnd();

            while (Match(TokenKind.Or))
            {
                var right = ParseAnd();
                var capturedLeft = left;
                left = entry => capturedLeft(entry) || right(entry);
            }

            return left;
        }

        private Func<LogEntry, bool> ParseAnd()
        {
            var left = ParseUnary();

            while (Match(TokenKind.And))
            {
                var right = ParseUnary();
                var capturedLeft = left;
                left = entry => capturedLeft(entry) && right(entry);
            }

            return left;
        }

        private Func<LogEntry, bool> ParseUnary()
        {
            if (Match(TokenKind.Not))
            {
                var inner = ParseUnary();
                return entry => !inner(entry);
            }

            if (Match(TokenKind.LParen))
            {
                var inner = ParseOr();
                Expect(TokenKind.RParen);
                return inner;
            }

            return ParseCondition();
        }

        private Func<LogEntry, bool> ParseCondition()
        {
            var field = Expect(TokenKind.Identifier).Text;

            if (Match(TokenKind.In))
            {
                var values = ParseValueList();
                return entry => values.Contains(GetField(entry, field), StringComparer.OrdinalIgnoreCase);
            }

            if (Match(TokenKind.NotEquals))
            {
                var value = ExpectValue().Text;
                return entry => !StringEquals(GetField(entry, field), value);
            }

            if (Match(TokenKind.Contains))
            {
                var value = ExpectValue().Text;
                return entry => GetField(entry, field).Contains(value, StringComparison.OrdinalIgnoreCase);
            }

            if (Match(TokenKind.Equals))
            {
                var value = ExpectValue().Text;
                return entry => StringEquals(GetField(entry, field), value);
            }

            var shorthandValue = ExpectValue().Text;
            return entry => StringEquals(GetField(entry, field), shorthandValue);
        }

        private List<string> ParseValueList()
        {
            var values = new List<string>();
            var hasParens = Match(TokenKind.LParen);

            values.Add(ExpectValue().Text);
            while (Match(TokenKind.Comma))
            {
                values.Add(ExpectValue().Text);
            }

            if (hasParens)
            {
                Expect(TokenKind.RParen);
            }

            return values;
        }

        private bool Match(TokenKind kind)
        {
            if (Peek().Kind != kind)
            {
                return false;
            }

            _position++;
            return true;
        }

        private Token Expect(TokenKind kind)
        {
            var token = Peek();
            if (token.Kind != kind)
            {
                throw new FormatException($"Filterfehler bei '{token.Text}': erwartet {kind}.");
            }

            _position++;
            return token;
        }

        private Token ExpectValue()
        {
            var token = Peek();
            if (token.Kind is not (TokenKind.Value or TokenKind.Identifier))
            {
                throw new FormatException($"Filterfehler bei '{token.Text}': Wert erwartet.");
            }

            _position++;
            return token;
        }

        private Token Peek()
        {
            return _tokens[_position];
        }

        private static bool StringEquals(string left, string right)
        {
            return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
        }

        private static List<Token> Tokenize(string expression)
        {
            var tokens = new List<Token>();

            for (var index = 0; index < expression.Length;)
            {
                var current = expression[index];
                if (char.IsWhiteSpace(current))
                {
                    index++;
                    continue;
                }

                switch (current)
                {
                    case '(':
                        tokens.Add(new Token(TokenKind.LParen, "("));
                        index++;
                        continue;
                    case ')':
                        tokens.Add(new Token(TokenKind.RParen, ")"));
                        index++;
                        continue;
                    case ',':
                        tokens.Add(new Token(TokenKind.Comma, ","));
                        index++;
                        continue;
                    case ':':
                        tokens.Add(new Token(TokenKind.Contains, ":"));
                        index++;
                        continue;
                    case '=':
                        tokens.Add(new Token(TokenKind.Equals, "="));
                        index++;
                        continue;
                    case '!':
                        if (index + 1 < expression.Length && expression[index + 1] == '=')
                        {
                            tokens.Add(new Token(TokenKind.NotEquals, "!="));
                            index += 2;
                            continue;
                        }

                        throw new FormatException("Filterfehler: '!' ist nur als '!=' erlaubt.");
                    case '"':
                    case '\'':
                        var quoted = ReadQuoted(expression, ref index, current);
                        tokens.Add(new Token(TokenKind.Value, quoted));
                        continue;
                }

                var word = ReadWord(expression, ref index);
                if (string.IsNullOrWhiteSpace(word))
                {
                    throw new FormatException($"Filterfehler bei Zeichen '{current}'.");
                }

                tokens.Add(word.ToUpperInvariant() switch
                {
                    "AND" => new Token(TokenKind.And, word),
                    "OR" => new Token(TokenKind.Or, word),
                    "NOT" => new Token(TokenKind.Not, word),
                    "IN" => new Token(TokenKind.In, word),
                    _ => new Token(IsLikelyIdentifier(word) ? TokenKind.Identifier : TokenKind.Value, word)
                });
            }

            tokens.Add(new Token(TokenKind.End, "<end>"));
            return tokens;
        }

        private static string ReadQuoted(string expression, ref int index, char quote)
        {
            var builder = new StringBuilder();
            index++;

            while (index < expression.Length)
            {
                var current = expression[index++];
                if (current == quote)
                {
                    return builder.ToString();
                }

                if (current == '\\' && index < expression.Length)
                {
                    builder.Append(expression[index++]);
                    continue;
                }

                builder.Append(current);
            }

            throw new FormatException("Filterfehler: String ist nicht geschlossen.");
        }

        private static string ReadWord(string expression, ref int index)
        {
            var start = index;
            while (index < expression.Length)
            {
                var current = expression[index];
                if (char.IsWhiteSpace(current) || current is '(' or ')' or ',' or ':' or '=' or '!')
                {
                    break;
                }

                index++;
            }

            return expression[start..index];
        }

        private static bool IsLikelyIdentifier(string word)
        {
            return IdentifierRegex().IsMatch(word);
        }

        [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_\-.]*$", RegexOptions.Compiled)]
        private static partial Regex IdentifierRegex();
    }
}
