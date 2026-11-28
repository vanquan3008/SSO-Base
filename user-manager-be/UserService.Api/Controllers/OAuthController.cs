using System.Text;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using UserService.Api.Controllers.Helpers;
using UserService.Api.Contracts.OAuth;
using UserService.Api.Security;
using UserService.Application.DTOs.OAuth;
using UserService.Application.Features.OAuth.Commands;
using UserService.Application.Interfaces.Services;
using UserService.Api.Extensions;
using UserService.Application.Common;
using UserService.Domain.Constants;
using UserService.Domain.Exceptions;

namespace UserService.Api.Controllers;

/// <summary>
/// OAuth 2.0 authorization code flow with PKCE for registered applications, plus the OpenID Connect
/// pieces the platform implements (ID token, UserInfo, discovery, JWKS).
/// The hosted SPA calls <c>authorize</c>/<c>consent</c> with the user's hosted-SSO access token.
/// </summary>
[ApiController]
[Route("api/oauth")]
[Produces("application/json")]
public class OAuthController : ApiControllerBase
{
    private readonly IMediator _mediator;
    private readonly IOAuthFlowService _oauth;

    public OAuthController(IMediator mediator, IOAuthFlowService oauth)
    {
        _mediator = mediator;
        _oauth = oauth;
    }

    [Authorize]
    [HttpGet("authorize")]
    [ProducesResponseType(typeof(ApiResponse<OAuthAuthorizeResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<ApiResponse<OAuthAuthorizeResponse>>> Authorize(
        [FromQuery] OAuthAuthorizeQueryRequest query,
        CancellationToken cancellationToken = default)
    {
        var userId = User.GetRequiredCurrentUserId();
        var request = OAuthQueryRequestBinding.ToAuthorizeRequest(query, Request.Query);

        var result = await _mediator.Send(new AuthorizeOAuthCommand(userId, request), cancellationToken);
        
        if (!string.IsNullOrEmpty(result.Code))
        {
            var fullRedirectUrl = OAuthHelpers.BuildRedirectUrl(result.RedirectUri, result.Code, result.State);
            return OkResponse(result with { RedirectUri = fullRedirectUrl });
        }

        return OkResponse(result);
    }

    [Authorize]
    [HttpPost("consent")]
    [ProducesResponseType(typeof(ApiResponse<OAuthAuthorizeResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
    public async Task<ActionResult<ApiResponse<OAuthAuthorizeResponse>>> Consent(
        [FromBody] OAuthConsentApiRequest request,
        CancellationToken cancellationToken = default)
    {
        var userId = User.GetRequiredCurrentUserId();
        var consentRequest = new OAuthConsentRequest(
            request.ClientId,
            request.RedirectUri,
            request.Scopes,
            request.State,
            request.CodeChallenge,
            request.CodeChallengeMethod,
            request.Approve,
            request.Nonce);
        var result = await _mediator.Send(new ConsentOAuthCommand(userId, consentRequest), cancellationToken);
        if (!string.IsNullOrEmpty(result.Code))
            result = result with { RedirectUri = OAuthHelpers.BuildRedirectUrl(result.RedirectUri, result.Code, result.State) };
        return OkResponse(result);
    }

    /// <summary>
    /// Token endpoint. <c>application/x-www-form-urlencoded</c> requests receive a standard RFC 6749
    /// response (snake_case, <c>error</c>/<c>error_description</c>); JSON requests keep the platform's
    /// <c>ApiResponse</c> envelope for backwards compatibility. Client secrets may also be sent with HTTP Basic.
    /// </summary>
    [HttpPost("token")]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    [Consumes("application/x-www-form-urlencoded", "application/json")]
    [ProducesResponseType(typeof(ApiResponse<OAuthTokenResponse>), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ApiResponse<object>), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Token(CancellationToken cancellationToken = default)
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";

        // The content type only selects how the request is parsed and how the response is shaped.
        // Client authentication and the code/refresh exchange run through the same single path.
        var isForm = Request.HasFormContentType;
        var (basicId, basicSecret) = ReadBasicCredentials();
        var parsed = isForm
            ? await ReadFormTokenRequestAsync(cancellationToken)
            : await ReadJsonTokenRequestAsync(cancellationToken);
        var tokenRequest = parsed with
        {
            ClientId = basicId ?? parsed.ClientId,
            ClientSecret = basicSecret ?? parsed.ClientSecret
        };

        OAuthTokenResponse result;
        try
        {
            result = await _mediator.Send(new ExchangeOAuthCodeCommand(tokenRequest), cancellationToken);
        }
        catch (OAuthProtocolException ex) when (isForm)
        {
            return OAuthError(ex);
        }
        catch (FluentValidation.ValidationException ex) when (isForm)
        {
            return OAuthError(new OAuthProtocolException(OAuthErrors.InvalidRequest, string.Join(" ", ex.Errors.Select(e => e.ErrorMessage).Distinct())));
        }

        if (!isForm)
            return OkResponse(result);

        return Ok(new Dictionary<string, object?>
        {
            ["access_token"] = result.AccessToken,
            ["token_type"] = result.TokenType,
            ["expires_in"] = result.ExpiresIn,
            ["refresh_token"] = result.RefreshToken,
            ["scope"] = string.Join(' ', result.Scopes),
            ["id_token"] = result.IdToken
        }.Where(kv => kv.Value is not null).ToDictionary(kv => kv.Key, kv => kv.Value));
    }

    private async Task<OAuthTokenRequest> ReadFormTokenRequestAsync(CancellationToken cancellationToken)
    {
        var form = await Request.ReadFormAsync(cancellationToken);
        return new OAuthTokenRequest(
            form["grant_type"].ToString(),
            form["client_id"].ToString(),
            form["redirect_uri"].ToString(),
            NullIfEmpty(form["client_secret"].ToString()),
            NullIfEmpty(form["code"].ToString()),
            NullIfEmpty(form["code_verifier"].ToString()),
            NullIfEmpty(form["refresh_token"].ToString()));
    }

    private async Task<OAuthTokenRequest> ReadJsonTokenRequestAsync(CancellationToken cancellationToken)
    {
        var body = await Request.ReadFromJsonAsync<OAuthTokenApiRequest>(cancellationToken)
                   ?? throw new OAuthProtocolException(OAuthErrors.InvalidRequest, "Request body is required.");
        return new OAuthTokenRequest(
            body.GrantType,
            body.ClientId,
            body.RedirectUri,
            body.ClientSecret,
            body.Code,
            body.CodeVerifier,
            body.RefreshToken);
    }

    /// <summary>
    /// OpenID Connect UserInfo endpoint (claims depend on the granted scopes). It is the only endpoint that also
    /// accepts access tokens issued to third-party clients.
    /// </summary>
    [Authorize(AuthenticationSchemes = AuthenticationServiceExtensions.PlatformOrOAuthClientSchemes)]
    [HttpGet("userinfo")]
    [HttpPost("userinfo")]
    public async Task<IActionResult> UserInfo(CancellationToken cancellationToken = default)
    {
        var userId = User.GetRequiredCurrentUserId();
        var scopes = (User.FindFirst(JwtClaimNames.Scope)?.Value ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var info = await _oauth.GetUserInfoAsync(userId, scopes, cancellationToken);

        var claims = new Dictionary<string, object?> { ["sub"] = info.Sub };
        if (info.Email is not null) { claims["email"] = info.Email; claims["email_verified"] = info.EmailVerified; }
        if (info.Name is not null) claims["name"] = info.Name;
        if (info.PreferredUsername is not null) claims["preferred_username"] = info.PreferredUsername;
        return Ok(claims);
    }

    /// <summary>RFC 7009 token revocation (refresh tokens).</summary>
    [HttpPost("revoke")]
    [EnableRateLimiting(RateLimitPolicies.Auth)]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Revoke([FromForm] OAuthRevokeFormRequest request, CancellationToken cancellationToken = default)
    {
        var (basicId, basicSecret) = ReadBasicCredentials();
        try
        {
            await _oauth.RevokeTokenAsync(basicId ?? request.ClientId ?? string.Empty, basicSecret ?? request.ClientSecret, request.Token ?? string.Empty, cancellationToken);
            return Ok();
        }
        catch (OAuthProtocolException ex)
        {
            return OAuthError(ex);
        }
    }

    private IActionResult OAuthError(OAuthProtocolException ex)
    {
        var status = ex.Error == OAuthErrors.InvalidClient ? StatusCodes.Status401Unauthorized : StatusCodes.Status400BadRequest;
        return StatusCode(status, new { error = ex.Error, error_description = ex.ErrorDescription });
    }

    private (string? ClientId, string? ClientSecret) ReadBasicCredentials()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            return (null, null);
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header[6..].Trim()));
            var separator = decoded.IndexOf(':');
            if (separator <= 0)
                return (null, null);
            return (Uri.UnescapeDataString(decoded[..separator]), Uri.UnescapeDataString(decoded[(separator + 1)..]));
        }
        catch (FormatException)
        {
            return (null, null);
        }
    }

    private static string? NullIfEmpty(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;
}
