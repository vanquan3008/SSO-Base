namespace UserService.Application.Common;

/// <summary>
/// Neutralises request-derived values before they are written to log entries, so a crafted value
/// (e.g. a URL path containing an encoded CR/LF) cannot forge additional log lines.
/// </summary>
public static class LogSanitizer
{
    private const int MaxLength = 512;
    private static readonly string LineSeparator = char.ConvertFromUtf32(0x2028);
    private static readonly string ParagraphSeparator = char.ConvertFromUtf32(0x2029);

    public static string? Clean(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return value;

        var cleaned = value
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal)
            .Replace(LineSeparator, string.Empty, StringComparison.Ordinal)
            .Replace(ParagraphSeparator, string.Empty, StringComparison.Ordinal);

        return cleaned.Length > MaxLength ? string.Concat(cleaned.AsSpan(0, MaxLength), "...") : cleaned;
    }
}
