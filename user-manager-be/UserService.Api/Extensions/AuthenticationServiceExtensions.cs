using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using UserService.Application.Configuration;
using UserService.Application.Interfaces.Services.Security;
using UserService.Application.Services;
using UserService.Domain.Constants;

namespace UserService.Api.Extensions;

public static class AuthenticationServiceExtensions
{
    /// <summary>Default scheme: access tokens issued for the platform API audience (console and first-party clients).</summary>
    public const string BearerScheme = "Bearer";

    /// <summary>
    /// Access tokens issued to a registered OAuth client (<c>aud</c> = that client's id). They are accepted only by
    /// endpoints that opt in explicitly, such as UserInfo, so a third-party client cannot call the platform API
    /// with a user's token.
    /// </summary>
    public const string OAuthClientBearerScheme = "OAuthClientBearer";

    /// <summary>Use with <c>[Authorize(AuthenticationSchemes = ...)]</c> on endpoints that serve OAuth clients.</summary>
    public const string PlatformOrOAuthClientSchemes = BearerScheme + "," + OAuthClientBearerScheme;

    /// <summary>
    /// Validates RS256 access tokens against the signing key ring (supports key rotation via <c>kid</c>)
    /// and rejects tokens whose server-side session (<c>sid</c>) has been revoked.
    /// </summary>
    public static IServiceCollection AddJwtAuthentication(
        this IServiceCollection services,
        AppSettings appSettings)
    {
        var jwt = appSettings.Jwt;
        if (string.IsNullOrWhiteSpace(jwt.Issuer) || string.IsNullOrWhiteSpace(jwt.Audience))
            throw new InvalidOperationException("AppSettings:Jwt:Issuer and AppSettings:Jwt:Audience must be configured.");

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = BearerScheme;
            options.DefaultChallengeScheme = BearerScheme;
        })
        .AddJwtBearer(BearerScheme, options => Configure(options, jwt, audienceValidator: null))
        .AddJwtBearer(OAuthClientBearerScheme, options => Configure(options, jwt, AudienceIsOwnClientId));

        // Resolve keys at validation time so rotated keys are picked up without restarts.
        foreach (var scheme in new[] { BearerScheme, OAuthClientBearerScheme })
        {
            services.AddOptions<JwtBearerOptions>(scheme)
                .Configure<ISigningKeyProvider>((options, keys) =>
                    options.TokenValidationParameters.IssuerSigningKeyResolver = (_, _, _, _) => keys.GetValidationKeys());
        }

        return services;
    }

    private static void Configure(JwtBearerOptions options, JwtConfiguration jwt, AudienceValidator? audienceValidator)
    {
        options.MapInboundClaims = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwt.Issuer,
            ValidAudience = audienceValidator is null ? jwt.Audience : null,
            AudienceValidator = audienceValidator,
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
            // RFC 9068 §4: only access tokens, never ID or logout tokens (which share the issuer and keys).
            ValidTypes = new[] { TokenService.AccessTokenType },
            ClockSkew = TimeSpan.FromSeconds(30),
            RoleClaimType = ClaimTypes.Role,
            NameClaimType = ClaimTypes.Name
        };

        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var sid = context.Principal?.FindFirst(JwtClaimNames.SessionId)?.Value;
                if (string.IsNullOrEmpty(sid))
                    return;

                var validator = context.HttpContext.RequestServices.GetRequiredService<ISessionValidator>();
                if (!Guid.TryParse(sid, out var sessionId) ||
                    !await validator.IsActiveAsync(sessionId, context.HttpContext.RequestAborted))
                {
                    context.Fail("The session for this token has been revoked or has expired.");
                }
            }
        };
    }

    /// <summary>A client token's audience must be exactly the <c>client_id</c> it was issued to.</summary>
    private static bool AudienceIsOwnClientId(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters _)
    {
        var clientId = token switch
        {
            JsonWebToken json when json.TryGetPayloadValue<string>(JwtClaimNames.ClientId, out var value) => value,
            JwtSecurityToken legacy => legacy.Payload.TryGetValue(JwtClaimNames.ClientId, out var value) ? value as string : null,
            _ => null
        };

        return !string.IsNullOrEmpty(clientId) && audiences.Contains(clientId, StringComparer.Ordinal);
    }
}
