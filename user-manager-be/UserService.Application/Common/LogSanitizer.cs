namespace UserService.Application.Common;

/// <summary>
/// Neutralises request-derived values before they are written to log entries, so a crafted value
/// (e.g. a URL path containing an encoded CR/LF) cannot forge additional log lines.
/// </summary>
public static class LogSanitizer
{
    private const int MaxLength = 512;

    /// <summary>
    /// Removes line breaks and caps the retained text at 512 characters.
    /// </summary>
    public static string Clean(string? value)
    {
        var cleaned = (value ?? string.Empty)
            .ReplaceLineEndings(string.Empty)
            .Replace("\v", string.Empty);

        return cleaned.Length > MaxLength ? string.Concat(cleaned.AsSpan(0, MaxLength), "...") : cleaned;
    }
}
