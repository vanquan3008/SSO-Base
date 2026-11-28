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

    /// <summary>
    /// Returns the value without CR, LF, U+2028 and U+2029, truncated to 512 characters.
    /// Every returned string is produced by the replacements, never the raw input.
    /// </summary>
    public static string Clean(string? value)
    {
        // String.Replace(string, string) is ordinal; null and empty both log as an empty string.
        var cleaned = (value ?? string.Empty)
            .Replace("\r", string.Empty)
            .Replace("\n", string.Empty)
            .Replace(LineSeparator, string.Empty)
            .Replace(ParagraphSeparator, string.Empty);

        return cleaned.Length > MaxLength ? string.Concat(cleaned.AsSpan(0, MaxLength), "...") : cleaned;
    }
}
