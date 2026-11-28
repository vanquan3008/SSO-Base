namespace UserService.Application.DTOs.Applications;

/// <summary>Replaces an application's redirect URI allow-list. An empty list disables the authorization flow.</summary>
public sealed record UpdateApplicationRedirectUrisRequest(IReadOnlyList<string>? RedirectUris);
