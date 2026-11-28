using UserService.Application.Interfaces.Services;
using UserService.Application.DTOs.Applications;
using UserService.Application.Features.Applications.Commands;
using UserService.Application.Features.OAuth.Policies;
using UserService.Application.Mapping;
using UserService.Domain.Constants;
using UserService.Domain.Entities;
using UserService.Domain.Exceptions;
using UserService.Domain.Interfaces;
using UserService.Domain.Repositories;
using UserService.Domain.ValueObjects;

namespace UserService.Application.Services;

public sealed class ApplicationAppService : IApplicationAppService
{
    private const int MaxRedirectUris = 20;
    private const int MaxRedirectUrisStorageLength = 2000; // AppApplications.AllowedRedirectUris column length
    private static readonly char[] RedirectUriSeparators = { ',', '\r', '\n' };

    private readonly IApplicationRepository _applications;
    private readonly IApplicationCacheService _applicationCache;
    private readonly IUserRepository _users;
    private readonly IApplicationRoleService _applicationRoleService;
    private readonly IApplicationMembershipService _applicationMembershipService;
    private readonly IHashingService _hashingService;
    private readonly IClock _clock;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IOAuthRedirectUriPolicy _redirectUriPolicy;
    private readonly AppSettings _appSettings;

    public ApplicationAppService(
        IApplicationRepository applications,
        IApplicationCacheService applicationCache,
        IUserRepository users,
        IApplicationRoleService applicationRoleService,
        IApplicationMembershipService applicationMembershipService,
        IHashingService hashingService,
        IClock clock,
        IUnitOfWork unitOfWork,
        IOAuthRedirectUriPolicy redirectUriPolicy,
        AppSettings appSettings)
    {
        _applications = applications;
        _applicationCache = applicationCache;
        _users = users;
        _applicationRoleService = applicationRoleService;
        _applicationMembershipService = applicationMembershipService;
        _hashingService = hashingService;
        _clock = clock;
        _unitOfWork = unitOfWork;
        _redirectUriPolicy = redirectUriPolicy;
        _appSettings = appSettings;
    }

    public Task<AppApplication?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
        => _applications.GetByIdAsync(id, cancellationToken);

    public async Task<CreateApplicationResponse> CreateAsync(
        CreateApplicationCommand command,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(command.Name))
            throw new BusinessRuleValidationException("ApplicationNameRequired", "Application name is required.");
        if (!ApplicationClientTypes.IsValid(command.ClientType))
            throw new BusinessRuleValidationException("ApplicationClientTypeInvalid", "ClientType must be Public or Confidential.");

        var owner = await _users.GetByIdAsync(command.OwnerId, cancellationToken);
        if (owner == null)
            throw new UserNotFoundException(command.OwnerId);

        var name = command.Name.Trim();
        var nameTaken = await _applications.IsNameTakenAsync(command.OwnerId, name, cancellationToken);
        if (nameTaken)
            throw new BusinessRuleValidationException("ApplicationNameTaken", $"Application name '{name}' is already used by this owner.");

        var appName = AppName.Create(name);
        var appDescription = AppDescription.Create(command.Description?.Trim() ?? string.Empty);
        UrlValue? logoUrl = !string.IsNullOrWhiteSpace(command.LogoUrl) ? UrlValue.Create(command.LogoUrl.Trim()) : null;

        var apiKey = ApiKey.Generate();
        var plainSecret = ApiSecretGenerator.Generate();
        var secretHash = ApiSecretHash.Create(_hashingService.Hash(plainSecret));

        var app = AppApplication.Create(
            Guid.NewGuid(),
            command.OwnerId,
            appName,
            appDescription,
            apiKey,
            secretHash,
            command.ClientType,
            _clock.UtcNow,
            logoUrl,
            command.SubscriptionPlanId);

        if (ApplicationClientTypes.UsesClientSecret(command.ClientType))
            app.RotateClientSecret(secretHash, _clock.UtcNow);

        if (!string.IsNullOrWhiteSpace(command.AllowedRedirectUris))
            app.ReplaceRedirectUris(ParseRedirectUris(command.AllowedRedirectUris.Split(RedirectUriSeparators)));

        if (!string.IsNullOrWhiteSpace(command.BackchannelLogoutUri))
            app.SetBackchannelLogoutUri(UrlValue.Create(command.BackchannelLogoutUri.Trim()));

        await _applications.AddAsync(app, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        await SeedDefaultRolesAsync(app.Id, cancellationToken);
        await _applicationMembershipService.AddUserAsync(app.Id, command.OwnerId, "Admin", cancellationToken);

        var response = ApplicationEntityMapper.ToCreateApplicationResponse(app, owner);
        if (!ApplicationClientTypes.UsesClientSecret(command.ClientType))
            return response;

        return response with
        {
            ClientSecret = plainSecret,
            LastClientSecretRotatedAt = app.LastApiKeyRotatedAt
        };
    }

    public async Task DeleteAsync(Guid applicationId, CancellationToken cancellationToken = default)
    {
        var app = await _applications.GetByIdAsync(applicationId, cancellationToken);
        if (app is null)
            throw new ApplicationNotFoundException(applicationId);

        app.Deactivate();
        app.Delete();

        await _unitOfWork.SaveChangesAsync(cancellationToken);
    }

    public async Task<ApplicationCredentialDto> GetCredentialsAsync(
        Guid applicationId,
        CancellationToken cancellationToken = default)
    {
        var app = await _applications.GetByIdAsync(applicationId, cancellationToken);
        if (app == null)
            throw new ApplicationInactiveException(applicationId);

        return ApplicationEntityMapper.ToCredentialDto(app);
    }

    public async Task<ApplicationCredentialDto> RotateClientSecretAsync(
        Guid applicationId,
        CancellationToken cancellationToken = default)
    {
        var app = await _applications.GetByIdAsync(applicationId, cancellationToken);
        if (app == null)
            throw new ApplicationInactiveException(applicationId);

        if (!ApplicationClientTypes.UsesClientSecret(app.ClientType))
        {
            throw new BusinessRuleValidationException(
                "ClientSecretNotSupported",
                "Only confidential clients can rotate a client secret.");
        }

        var plainClientSecret = ApiSecretGenerator.Generate();
        var hashedSecret = ApiSecretHash.Create(_hashingService.Hash(plainClientSecret));

        app.RotateClientSecret(hashedSecret, _clock.UtcNow);
        await _applications.UpdateAsync(app, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        return ApplicationEntityMapper.ToCredentialDto(app, plainClientSecret);
    }

    public async Task<ApplicationCredentialDto> UpdateRedirectUrisAsync(
        Guid applicationId,
        IReadOnlyCollection<string> redirectUris,
        CancellationToken cancellationToken = default)
    {
        var app = await _applications.GetByIdAsync(applicationId, cancellationToken)
                  ?? throw new ApplicationInactiveException(applicationId);

        var parsed = ParseRedirectUris(redirectUris);
        if (parsed.Count == 0 && _appSettings.OAuth.IsFirstPartyClient(app.ApiKey.Value))
        {
            throw new BusinessRuleValidationException(
                "RedirectUriRequired",
                "The administration console needs at least one redirect URI, otherwise nobody can sign in to it.");
        }

        app.ReplaceRedirectUris(parsed);
        await _applications.UpdateAsync(app, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);

        return ApplicationEntityMapper.ToCredentialDto(app);
    }

    /// <summary>
    /// Trims, de-duplicates and validates redirect URIs against the OAuth policy. The list is stored as one
    /// comma-separated column, so commas are rejected and the total length is capped.
    /// </summary>
    private IReadOnlyList<UrlValue> ParseRedirectUris(IEnumerable<string?> values)
    {
        var uris = values
            .Select(value => value?.Trim())
            .Where(value => !string.IsNullOrEmpty(value))
            .Select(value => value!)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (uris.Count > MaxRedirectUris)
            throw new BusinessRuleValidationException("TooManyRedirectUris", $"At most {MaxRedirectUris} redirect URIs can be registered.");

        foreach (var uri in uris)
        {
            if (uri.Contains(',') || !_redirectUriPolicy.IsWellFormed(uri))
            {
                throw new BusinessRuleValidationException(
                    "InvalidRedirectUri",
                    $"Redirect URI '{uri}' must be an absolute HTTPS URI (HTTP only on loopback) without a fragment, user info or comma.");
            }
        }

        if (uris.Sum(uri => uri.Length + 1) - 1 > MaxRedirectUrisStorageLength)
            throw new BusinessRuleValidationException("RedirectUrisTooLong", $"Redirect URIs may not exceed {MaxRedirectUrisStorageLength} characters in total.");

        return uris.Select(UrlValue.Create).ToList();
    }

    public async Task<AppApplication?> UpdateLogoUrlAsync(Guid id, string? logoUrl, CancellationToken cancellationToken = default)
    {
        var app = await _applications.GetByIdAsync(id, cancellationToken);
        if (app is null) return null;

        app.SetLogoUrl(logoUrl != null ? UrlValue.Create(logoUrl) : null);
        await _applications.UpdateAsync(app, cancellationToken);
        await _unitOfWork.SaveChangesAsync(cancellationToken);
        return app;
    }

    public async Task<Guid?> ResolveApplicationIdAsync(string? clientId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return null;
        }

        var app = await _applicationCache.GetByApiKeyAsync(clientId.Trim(), cancellationToken);
        if (app == null || !app.IsActive)
        {
            throw new UserService.Domain.Exceptions.AuthenticationException("Invalid or inactive client id.");
        }

        return app.Id;
    }

    private async Task SeedDefaultRolesAsync(Guid applicationId, CancellationToken cancellationToken)
    {
        await EnsureRoleCreatedAsync(applicationId, "Admin", "Application administrator", cancellationToken);
        await EnsureRoleCreatedAsync(applicationId, "Guest", "Default guest role", cancellationToken);
        await EnsureRoleCreatedAsync(applicationId, "SuperAdmin", "Application super administrator", cancellationToken);
    }

    private async Task EnsureRoleCreatedAsync(
        Guid applicationId,
        string roleName,
        string description,
        CancellationToken cancellationToken)
    {
        var result = await _applicationRoleService.CreateRoleAsync(applicationId, roleName, description, cancellationToken);
        if (result.Succeeded)
            return;

        var firstError = result.Errors?.SelectMany(kv => kv.Value).FirstOrDefault() ?? "Unknown error";
        throw new BusinessRuleValidationException("SeedDefaultRoleFailed", $"Failed to create default role '{roleName}': {firstError}");
    }
}
