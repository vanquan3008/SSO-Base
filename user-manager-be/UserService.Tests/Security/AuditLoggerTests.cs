using Microsoft.Extensions.Logging;
using UserService.Application.Services.Security;
using UserService.Domain.Entities;
using UserService.Domain.Repositories;
using UserService.Tests.TestDoubles;

namespace UserService.Tests.Security;

public sealed class AuditLoggerTests
{
    private readonly Mock<IAuditLogRepository> _repository = new();
    private readonly Mock<ILogger<AuditLogger>> _logger = new();
    private readonly AuditLogger _sut;

    public AuditLoggerTests()
    {
        _sut = new AuditLogger(_repository.Object, new FakeRequestContext(), new FakeClock(),
            _logger.Object, Mock.Of<IUserRepository>());
    }

    [Theory]
    [InlineData(AuditEventTypes.PasswordChanged, true, LogLevel.Information)]
    [InlineData(AuditEventTypes.PasswordReset, false, LogLevel.Warning)]
    public async Task LogAsync_UsesAuditRecordIdInApplicationLog(string eventType, bool succeeded, LogLevel level)
    {
        AuditLog? record = null;
        _repository.Setup(repository => repository.WriteAsync(It.IsAny<AuditLog>(), CancellationToken.None))
            .Callback<AuditLog, CancellationToken>((entry, _) => record = entry)
            .Returns(Task.CompletedTask);

        await _sut.LogAsync(eventType, succeeded);

        record.Should().NotBeNull();
        record!.EventType.Should().Be(eventType);
        record.Succeeded.Should().Be(succeeded);
        var log = _logger.Invocations.Single();
        log.Arguments[0].Should().Be(level);
        var fields = (IEnumerable<KeyValuePair<string, object?>>)log.Arguments[2];
        fields.Should().Contain(field => field.Key == "AuditLogId" && Equals(field.Value, record.Id));
        log.Arguments[2].ToString().Should().NotContain(eventType);
    }

    [Fact]
    public async Task LogAsync_ReportsPersistenceFailureWithoutTheEventType()
    {
        var error = new InvalidOperationException("Audit storage unavailable");
        _repository.Setup(repository => repository.WriteAsync(It.IsAny<AuditLog>(), CancellationToken.None))
            .ThrowsAsync(error);

        await _sut.LogAsync(AuditEventTypes.PasswordReset, succeeded: true);

        var log = _logger.Invocations.Single();
        log.Arguments[0].Should().Be(LogLevel.Error);
        log.Arguments[2].ToString().Should().Be("Failed to persist audit event");
        log.Arguments[3].Should().BeSameAs(error);
    }
}
