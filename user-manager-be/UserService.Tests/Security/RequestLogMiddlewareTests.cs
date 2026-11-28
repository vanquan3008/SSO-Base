using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using UserService.Api.Middleware;

namespace UserService.Tests.Security;

public sealed class RequestLogMiddlewareTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RequestLogging_WritesSingleLineRequestFields(bool fails)
    {
        var context = CreateContext();
        var logger = new Mock<ILogger<RequestLoggingMiddleware>>();
        var error = new InvalidOperationException("first\r\nsecond");
        var middleware = new RequestLoggingMiddleware(
            _ => fails ? Task.FromException(error) : Task.CompletedTask, logger.Object);

        if (fails)
        {
            var caught = await Assert.ThrowsAsync<InvalidOperationException>(() => middleware.InvokeAsync(context));
            caught.Should().BeSameAs(error);
        }
        else
        {
            await middleware.InvokeAsync(context);
        }

        var logs = logger.Invocations;
        logs.Should().HaveCountGreaterThanOrEqualTo(2);
        foreach (var log in logs)
        {
            var fields = GetFields(log);
            fields["RequestId"].Should().Be("request-id");
            fields["Method"].Should().Be("GET");
            fields["Path"].Should().Be("/api/items");
            log.Arguments[3].Should().BeNull();
        }

        var started = GetFields(logs[0]);
        started["Scheme"].Should().Be("https");
        started["Host"].Should().Be("example.com");
        if (fails)
            GetFields(logs[1])["ExceptionDetails"].Should().BeOfType<string>().Which.Should().Contain("first\\r\\nsecond");
    }

    [Fact]
    public async Task ExceptionHandling_EncodesExceptionDetailsAndRequestFields()
    {
        var context = CreateContext();
        context.TraceIdentifier = "request\u2028-id";
        var logger = new Mock<ILogger<ExceptionHandlingMiddleware>>();
        var error = new InvalidOperationException("first\r\nsecond");
        var env = Mock.Of<IHostEnvironment>(value => value.EnvironmentName == Environments.Production);
        var middleware = new ExceptionHandlingMiddleware(_ => Task.FromException(error), logger.Object, env);

        await middleware.InvokeAsync(context);

        context.Response.StatusCode.Should().Be(StatusCodes.Status500InternalServerError);
        var log = logger.Invocations.Single();
        log.Arguments[3].Should().BeNull();
        var fields = GetFields(log);
        fields["RequestId"].Should().Be("request-id");
        fields["Method"].Should().Be("GET");
        fields["Path"].Should().Be("/api/items");
        fields["Message"].Should().Be("firstsecond");
        fields["ExceptionDetails"].Should().BeOfType<string>().Which.Should().Contain("first\\r\\nsecond");
        log.Arguments[2].ToString().Should().NotContainAny("\r", "\n", "\u2028", "\u2029");
    }

    private static DefaultHttpContext CreateContext()
    {
        var context = new DefaultHttpContext { RequestServices = Mock.Of<IServiceProvider>() };
        context.Request.Method = "G\r\nET";
        context.Request.Scheme = "ht\u0085tps";
        context.Request.Headers.Host = "example\f.com";
        context.Request.Path = "/api\u2029/items";
        context.Request.Headers[RequestCorrelationId.CorrelationIdHeaderName] = "request\u2028-id";
        return context;
    }

    private static Dictionary<string, object?> GetFields(IInvocation log) =>
        ((IEnumerable<KeyValuePair<string, object?>>)log.Arguments[2]).ToDictionary();
}
