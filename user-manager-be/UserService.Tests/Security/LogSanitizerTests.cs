using UserService.Application.Common;

namespace UserService.Tests.Security;

public class LogSanitizerTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("/api/users", "/api/users")]
    [InlineData("/api\r\n2026-11-28 [INF] forged", "/api2026-11-28 [INF] forged")]
    public void Clean_RemovesLineBreaks(string? input, string expected)
        => LogSanitizer.Clean(input).Should().Be(expected);

    [Fact]
    public void Clean_RemovesUnicodeLineSeparators_AndTruncates()
    {
        LogSanitizer.Clean($"a{char.ConvertFromUtf32(0x2028)}b{char.ConvertFromUtf32(0x2029)}c").Should().Be("abc");
        LogSanitizer.Clean(new string('x', 600)).Should().Be(new string('x', 512) + "...");
    }
}
