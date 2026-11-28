using System.Net;

namespace UserService.Application.Features.OAuth.Policies;

/// <summary>
/// Redirect URI rules from RFC 6749 §3.1.2, RFC 8252 §7.3/§8.3 and the OAuth Security BCP (RFC 9700 §4.1.3).
/// </summary>
public sealed class OAuthRedirectUriPolicy : IOAuthRedirectUriPolicy
{
    private readonly AppSettings _appSettings;

    public OAuthRedirectUriPolicy(AppSettings appSettings)
    {
        _appSettings = appSettings;
    }

    public bool IsAllowed(string redirectUri, IReadOnlyCollection<string> registeredRedirectUris)
    {
        // A client must register its redirect URIs; there is no host-based fallback (RFC 9700 §4.1.3).
        return TryParseWellFormed(redirectUri, out var requested)
               && registeredRedirectUris.Any(registered => Matches(redirectUri, requested, registered));
    }

    public bool IsWellFormed(string redirectUri) => TryParseWellFormed(redirectUri, out _);

    /// <summary>
    /// Absolute URI, no fragment (RFC 6749 §3.1.2), no user info, and HTTPS — or plain HTTP on a loopback
    /// host when <c>OAuth:AllowHttpForLocalhost</c> is enabled (RFC 8252 §8.3).
    /// </summary>
    private bool TryParseWellFormed(string? value, out Uri uri)
    {
        uri = null!;
        if (string.IsNullOrWhiteSpace(value) || !Uri.TryCreate(value, UriKind.Absolute, out var parsed))
            return false;
        if (parsed.Fragment.Length > 0 || value.Contains('#') || parsed.UserInfo.Length > 0)
            return false;

        var isHttps = parsed.Scheme == Uri.UriSchemeHttps;
        var isLoopbackHttp = parsed.Scheme == Uri.UriSchemeHttp && parsed.IsLoopback && _appSettings.OAuth.AllowHttpForLocalhost;
        if (!isHttps && !isLoopbackHttp)
            return false;

        uri = parsed;
        return true;
    }

    /// <summary>
    /// Simple string comparison, except that a loopback IP literal may use any port (RFC 8252 §7.3), because
    /// native apps bind an ephemeral port at runtime.
    /// </summary>
    private static bool Matches(string requestedValue, Uri requested, string registeredValue)
    {
        if (string.Equals(requestedValue, registeredValue, StringComparison.Ordinal))
            return true;

        if (!IsLoopbackIpLiteral(requested) ||
            !Uri.TryCreate(registeredValue, UriKind.Absolute, out var registered) ||
            !IsLoopbackIpLiteral(registered))
        {
            return false;
        }

        return requested.Scheme == registered.Scheme
               && string.Equals(requested.Host, registered.Host, StringComparison.OrdinalIgnoreCase)
               && string.Equals(requested.PathAndQuery, registered.PathAndQuery, StringComparison.Ordinal);
    }

    private static bool IsLoopbackIpLiteral(Uri uri)
        => uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6
           && IPAddress.TryParse(uri.DnsSafeHost, out var address)
           && IPAddress.IsLoopback(address);
}
