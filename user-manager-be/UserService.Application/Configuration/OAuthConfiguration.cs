namespace UserService.Application.Configuration;

public class OAuthConfiguration
{
    /// <summary>Redirect URIs registered for the seeded first-party application (the admin console).</summary>
    public string[] DefaultApplicationAllowedRedirectUris { get; set; } = Array.Empty<string>();

    public bool AllowHttpForLocalhost { get; set; } = true;

    /// <summary>
    /// Client ids of first-party applications (the admin console) whose OAuth access tokens are issued for the
    /// platform API audience. Every other client receives tokens whose <c>aud</c> is its own client id, so a
    /// third-party application cannot replay a user's token against the platform API.
    /// Defaults to <c>SEED_APP_API_KEY</c> when not configured.
    /// </summary>
    public string[] FirstPartyClientIds { get; set; } = Array.Empty<string>();

    public bool IsFirstPartyClient(string? clientId)
        => !string.IsNullOrWhiteSpace(clientId)
           && FirstPartyClientIds.Any(id => string.Equals(id?.Trim(), clientId, StringComparison.Ordinal));
}
