using System.Diagnostics;
using System.Text.Json;
using UserService.Application.Common;

namespace UserService.Api.Middleware;

/// <summary>
/// Request logging and timing. Resolves correlation id from incoming headers when present,
/// otherwise generates one; echoes on response for distributed tracing.
/// </summary>
public class RequestLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestLoggingMiddleware> _logger;

    public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var requestId = RequestCorrelationId.Resolve(context.Request);
        var logRequestId = LogSanitizer.Clean(requestId);
        var stopwatch = Stopwatch.StartNew();

        context.Items["RequestId"] = requestId;
        context.Items["CorrelationId"] = requestId;
        context.Response.OnStarting(() =>
        {
            context.Response.Headers.TryAdd(RequestCorrelationId.RequestIdHeaderName, requestId);
            context.Response.Headers.TryAdd(RequestCorrelationId.CorrelationIdHeaderName, requestId);
            return Task.CompletedTask;
        });

        LogRequestStarted(context, logRequestId);

        using var _ = Serilog.Context.LogContext.PushProperty("CorrelationId", logRequestId);
        try
        {
            await _next(context);
            
            stopwatch.Stop();
            LogRequestCompleted(context, logRequestId, stopwatch.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            LogRequestFailed(context, logRequestId, stopwatch.ElapsedMilliseconds, ex);
            throw; // Re-throw to let ExceptionHandlingMiddleware handle it
        }
    }

    private void LogRequestStarted(HttpContext context, string requestId)
    {
        _logger.LogInformation(
            "[{RequestId}] {Method} {Scheme}://{Host}{Path} started from {RemoteIp}",
            requestId,
            LogSanitizer.Clean(context.Request.Method),
            LogSanitizer.Clean(context.Request.Scheme),
            LogSanitizer.Clean(context.Request.Host.Value),
            LogSanitizer.Clean(context.Request.Path.Value),
            context.Connection.RemoteIpAddress);
    }

    private void LogRequestCompleted(HttpContext context, string requestId, long elapsedMs)
    {
        var logLevel = DetermineLogLevel(context.Response.StatusCode);
        
        _logger.Log(
            logLevel,
            "[{RequestId}] {Method} {Path} completed with {StatusCode} in {ElapsedMs}ms",
            requestId,
            LogSanitizer.Clean(context.Request.Method),
            LogSanitizer.Clean(context.Request.Path.Value),
            context.Response.StatusCode,
            elapsedMs);

        // Log slow requests
        if (elapsedMs > 1000)
        {
            _logger.LogWarning(
                "[{RequestId}] SLOW REQUEST: {Method} {Path} took {ElapsedMs}ms",
                requestId,
                LogSanitizer.Clean(context.Request.Method),
                LogSanitizer.Clean(context.Request.Path.Value),
                elapsedMs);
        }
    }

    private void LogRequestFailed(HttpContext context, string requestId, long elapsedMs, Exception exception)
    {
        _logger.LogError(
            "[{RequestId}] {Method} {Path} failed after {ElapsedMs}ms with exception: {ExceptionType}. {ExceptionDetails}",
            requestId,
            LogSanitizer.Clean(context.Request.Method),
            LogSanitizer.Clean(context.Request.Path.Value),
            elapsedMs,
            exception.GetType().Name,
            JsonEncodedText.Encode(exception.ToString()).ToString());
    }

    private static LogLevel DetermineLogLevel(int statusCode)
    {
        return statusCode switch
        {
            >= 500 => LogLevel.Error,
            >= 400 => LogLevel.Warning,
            _ => LogLevel.Information
        };
    }
}
