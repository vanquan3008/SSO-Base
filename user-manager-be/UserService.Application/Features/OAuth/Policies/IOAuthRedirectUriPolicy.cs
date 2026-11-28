namespace UserService.Application.Features.OAuth.Policies;

public interface IOAuthRedirectUriPolicy
{
    /// <summary>
    /// Whether <paramref name="redirectUri"/> may receive an authorization response for a client that registered
    /// <paramref name="registeredRedirectUris"/> (RFC 6749 §3.1.2, RFC 9700 §4.1.3: exact string matching).
    /// </summary>
    bool IsAllowed(string redirectUri, IReadOnlyCollection<string> registeredRedirectUris);

    /// <summary>Whether <paramref name="redirectUri"/> is acceptable as a redirect URI at all (used at registration).</summary>
    bool IsWellFormed(string redirectUri);
}
