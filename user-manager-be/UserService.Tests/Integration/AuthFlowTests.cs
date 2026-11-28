using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using UserService.Application.Common;
using UserService.Application.DTOs.Auth;
using UserService.Application.Interfaces.Services;
using UserService.Application.Services.Security;
using UserService.Domain.Constants;

namespace UserService.Tests.Integration;

[CollectionDefinition(nameof(ApiCollection))]
public sealed class ApiCollection : ICollectionFixture<SsoApiFactory>;

[Collection(nameof(ApiCollection))]
public sealed class AuthFlowTests
{
    private readonly SsoApiFactory _factory;

    public AuthFlowTests(SsoApiFactory factory) => _factory = factory;

    private async Task<(HttpClient Client, string AccessToken)> LoginAsync(string email, string password)
    {
        var client = _factory.CreateBrowserClient();
        var response = await client.PostJsonAsync("/api/auth/login", new { email, password, clientId = SsoApiFactory.ConsoleClientId });
        var json = await response.ReadJsonAsync();
        response.StatusCode.Should().Be(HttpStatusCode.OK, json.ToString());
        var token = json.GetProperty("data").GetProperty("accessToken").GetString()!;
        client.UseBearer(token);
        return (client, token);
    }

    /// <summary>Self-registered accounts get the plain User role (the seeded test users are SuperAdmins).</summary>
    private async Task<HttpClient> RegisterPlainUserAsync()
    {
        var member = _factory.CreateBrowserClient();
        var email = $"self-{Guid.NewGuid():N}@integration.test";
        var register = await member.PostJsonAsync("/api/auth/register", new
        {
            email, password = "Str0ng#Password", username = "u" + Guid.NewGuid().ToString("N")[..10],
            firstName = "Self", lastName = "Registered", dateOfBirth = "1990-01-01"
        });
        var registered = await register.ReadJsonAsync();
        register.StatusCode.Should().Be(HttpStatusCode.Created, registered.ToString());
        member.UseBearer(registered.GetProperty("data").GetProperty("accessToken").GetString()!);
        return member;
    }

    [Fact]
    public async Task Discovery_And_Jwks_ArePublished()
    {
        var client = _factory.CreateClient();
        var discovery = await (await client.GetAsync("/.well-known/openid-configuration")).ReadJsonAsync();
        discovery.GetProperty("issuer").GetString().Should().Be("http://localhost");
        discovery.GetProperty("jwks_uri").GetString().Should().EndWith("/.well-known/jwks.json");
        discovery.GetProperty("code_challenge_methods_supported")[0].GetString().Should().Be("S256");

        var jwks = await (await client.GetAsync("/.well-known/jwks.json")).ReadJsonAsync();
        jwks.GetProperty("keys").GetArrayLength().Should().BeGreaterThan(0);
        jwks.GetProperty("keys")[0].GetProperty("kty").GetString().Should().Be("RSA");
    }

    [Fact]
    public async Task Health_Endpoints_ReportHealthy()
    {
        var client = _factory.CreateClient();
        (await client.GetAsync("/health/live")).StatusCode.Should().Be(HttpStatusCode.OK);
        var ready = await client.GetAsync("/health/ready");
        ready.StatusCode.Should().Be(HttpStatusCode.OK);
        (await ready.ReadJsonAsync()).GetProperty("status").GetString().Should().Be("healthy");
    }

    [Fact]
    public async Task FailedLogin_Returns401_WithoutRevealingWhetherAccountExists()
    {
        var client = _factory.CreateBrowserClient();
        var wrongPassword = await client.PostJsonAsync("/api/auth/login", new { email = SsoApiFactory.UserEmail, password = "nope", clientId = SsoApiFactory.ConsoleClientId });
        var unknownUser = await client.PostJsonAsync("/api/auth/login", new { email = "ghost@integration.test", password = "nope", clientId = SsoApiFactory.ConsoleClientId });

        wrongPassword.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        unknownUser.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await wrongPassword.ReadJsonAsync()).ErrorCode().Should().Be("INVALID_CREDENTIALS");
        (await unknownUser.ReadJsonAsync()).ErrorCode().Should().Be("INVALID_CREDENTIALS");
    }

    [Fact]
    public async Task Login_IssuesRs256TokenBoundToSession_AndRefreshCookieOnly()
    {
        var (client, token) = await LoginAsync(SsoApiFactory.AdminEmail, SsoApiFactory.AdminPassword);
        var header = Encoding.UTF8.GetString(Convert.FromBase64String(token.Split('.')[0].PadRight((token.Split('.')[0].Length + 3) / 4 * 4, '=')));
        header.Should().Contain("RS256");
        HttpTestExtensions.JwtPayload(token).TryGetProperty("sid", out _).Should().BeTrue();

        (await client.GetAsync("/api/users/me")).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task RefreshRotation_ReuseOfOldToken_RevokesTheWholeSession()
    {
        var (client, _) = await LoginAsync(SsoApiFactory.AdminEmail, SsoApiFactory.AdminPassword);

        // Capture the first refresh token by using the body variant (the SPA uses the cookie).
        var rotated = await client.PostJsonAsync("/api/auth/refresh", new { });
        rotated.StatusCode.Should().Be(HttpStatusCode.OK);
        var cookieAfterFirstRotation = rotated.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("RefreshToken="));
        var secondToken = Uri.UnescapeDataString(cookieAfterFirstRotation.Split(';')[0]["RefreshToken=".Length..]);

        var again = await client.PostJsonAsync("/api/auth/refresh", new { });
        again.StatusCode.Should().Be(HttpStatusCode.OK);
        client.UseBearer((await again.ReadJsonAsync()).GetProperty("data").GetProperty("accessToken").GetString()!);

        // Replaying the superseded token (grace period is 0 in tests) is treated as theft.
        var attacker = _factory.CreateBrowserClient();
        var replay = await attacker.PostJsonAsync("/api/auth/refresh", new { refreshToken = secondToken });
        replay.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await replay.ReadJsonAsync()).ErrorCode().Should().Be("REFRESH_TOKEN_REUSED");

        // The victim's session is revoked as well: access token and current refresh token stop working.
        (await client.GetAsync("/api/users/me")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await client.PostJsonAsync("/api/auth/refresh", new { })).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task CookieRefresh_WithoutCsrfHeader_IsRejected()
    {
        var (client, _) = await LoginAsync(SsoApiFactory.AdminEmail, SsoApiFactory.AdminPassword);
        client.DefaultRequestHeaders.Remove("X-Requested-With");
        var response = await client.PostJsonAsync("/api/auth/refresh", new { });
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await response.ReadJsonAsync()).ErrorCode().Should().Be("CSRF_HEADER_REQUIRED");
    }

    [Fact]
    public async Task Logout_RevokesSession_AndAccessTokenImmediately()
    {
        var (client, token) = await LoginAsync(SsoApiFactory.AdminEmail, SsoApiFactory.AdminPassword);
        (await client.PostJsonAsync("/api/auth/logout", new { })).StatusCode.Should().Be(HttpStatusCode.OK);

        var other = _factory.CreateClient();
        other.UseBearer(token);
        (await other.GetAsync("/api/users/me")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task NonAdmin_CannotReadAuditLogs_AdminCan()
    {
        var member = await RegisterPlainUserAsync();
        (await member.GetAsync("/api/users/me")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await member.GetAsync("/api/audit-logs")).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await member.PostAsync("/api/system/signing-keys/rotate", null)).StatusCode.Should().Be(HttpStatusCode.Forbidden);

        var (admin, _) = await LoginAsync(SsoApiFactory.AdminEmail, SsoApiFactory.AdminPassword);
        var response = await admin.GetAsync("/api/audit-logs?category=auth&pageSize=50");
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var events = (await response.ReadJsonAsync()).GetProperty("data").EnumerateArray().Select(e => e.GetProperty("eventType").GetString()).ToList();
        events.Should().Contain("auth.login.succeeded");
    }

    [Fact]
    public async Task Mfa_Enrolment_ChallengesLogin_AndBlocksCodeReplay()
    {
        // Use the test user so the admin account stays MFA-free for other tests.
        var (client, _) = await LoginAsync(SsoApiFactory.UserEmail, SsoApiFactory.UserPassword);
        var setup = (await (await client.PostAsync("/api/account/mfa/setup", null)).ReadJsonAsync()).GetProperty("data");
        var secret = Base32.Decode(setup.GetProperty("sharedKey").GetString()!);
        var totp = new TotpService();
        var step = TotpService.GetTimeStep(DateTime.UtcNow);

        var enable = await client.PostJsonAsync("/api/account/mfa/enable", new { code = totp.ComputeCode(secret, step) });
        enable.StatusCode.Should().Be(HttpStatusCode.OK, (await enable.ReadJsonAsync()).ToString());
        var recoveryCodes = (await enable.ReadJsonAsync()).GetProperty("data").GetProperty("recoveryCodes").EnumerateArray().Select(x => x.GetString()!).ToList();
        recoveryCodes.Should().HaveCount(10);

        try
        {
            var browser = _factory.CreateBrowserClient();
            var login = await (await browser.PostJsonAsync("/api/auth/login",
                new { email = SsoApiFactory.UserEmail, password = SsoApiFactory.UserPassword, clientId = SsoApiFactory.ConsoleClientId })).ReadJsonAsync();
            login.GetProperty("data").GetProperty("mfaRequired").GetBoolean().Should().BeTrue();
            login.GetProperty("data").GetProperty("accessToken").GetString().Should().BeEmpty();
            var mfaToken = login.GetProperty("data").GetProperty("mfaToken").GetString()!;

            // The code used for enrolment cannot be replayed.
            var replay = await browser.PostJsonAsync("/api/auth/mfa/verify", new { mfaToken, code = totp.ComputeCode(secret, step) });
            (await replay.ReadJsonAsync()).ErrorCode().Should().Be("INVALID_MFA_CODE");

            var ok = await browser.PostJsonAsync("/api/auth/mfa/verify", new { mfaToken, code = recoveryCodes[0] });
            ok.StatusCode.Should().Be(HttpStatusCode.OK);
            var at = (await ok.ReadJsonAsync()).GetProperty("data").GetProperty("accessToken").GetString()!;
            HttpTestExtensions.JwtPayload(at).GetProperty("amr").GetString().Should().Be("mfa");

            var reuse = await browser.PostJsonAsync("/api/auth/mfa/verify", new { mfaToken, code = recoveryCodes[0] });
            reuse.StatusCode.Should().Be(HttpStatusCode.Unauthorized, "recovery codes are single-use");
        }
        finally
        {
            // Reset via admin so other tests can log in with a password only.
            var (admin, _) = await LoginAsync(SsoApiFactory.AdminEmail, SsoApiFactory.AdminPassword);
            var me = await (await client.GetAsync("/api/users/me")).ReadJsonAsync();
            var users = await (await admin.GetAsync($"/api/users?search={Uri.EscapeDataString(SsoApiFactory.UserEmail)}")).ReadJsonAsync();
            var userId = users.GetProperty("data")[0].GetProperty("id").GetString();
            (await admin.PostAsync($"/api/users/{userId}/mfa/reset", null)).StatusCode.Should().Be(HttpStatusCode.OK);
        }
    }

    [Fact]
    public async Task RedirectUris_CanBeReplacedByAdmins_AndAreValidated()
    {
        var (admin, _) = await LoginAsync(SsoApiFactory.AdminEmail, SsoApiFactory.AdminPassword);
        var apps = (await (await admin.GetAsync("/api/applications")).ReadJsonAsync()).GetProperty("data");
        var console = apps.EnumerateArray().Single(a => a.GetProperty("clientId").GetString() == SsoApiFactory.ConsoleClientId);
        var url = $"/api/applications/{console.GetProperty("id").GetString()}/redirect-uris";
        var original = console.GetProperty("allowedRedirectUris").GetString()!.Split(',');

        try
        {
            var fragment = await admin.PutAsJsonAsync(url, new { redirectUris = new[] { "https://app.example.com/cb#x" } }, HttpTestExtensions.Json);
            fragment.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);

            // The first-party console must keep at least one callback, or nobody could sign in to it.
            var empty = await admin.PutAsJsonAsync(url, new { redirectUris = Array.Empty<string>() }, HttpTestExtensions.Json);
            empty.StatusCode.Should().Be(HttpStatusCode.UnprocessableEntity);

            var updated = await admin.PutAsJsonAsync(url, new
            {
                redirectUris = new[] { SsoApiFactory.RedirectUri, " https://app.example.com/cb ", "https://app.example.com/cb" }
            }, HttpTestExtensions.Json);
            var json = await updated.ReadJsonAsync();
            updated.StatusCode.Should().Be(HttpStatusCode.OK, json.ToString());
            json.GetProperty("data").GetProperty("allowedRedirectUris").GetString()!.Split(',')
                .Should().BeEquivalentTo(SsoApiFactory.RedirectUri, "https://app.example.com/cb");

            var member = await RegisterPlainUserAsync();
            var forbidden = await member.PutAsJsonAsync(url, new { redirectUris = new[] { "https://evil.test/cb" } }, HttpTestExtensions.Json);
            forbidden.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        }
        finally
        {
            await admin.PutAsJsonAsync(url, new { redirectUris = original }, HttpTestExtensions.Json);
        }
    }

    [Fact]
    public async Task TokenEndpoint_ReturnsRfc6749Errors_ForJsonAndFormRequests()
    {
        var client = _factory.CreateClient();
        var json = await client.PostJsonAsync("/api/oauth/token", new
        {
            grantType = "authorization_code", clientId = SsoApiFactory.ConsoleClientId,
            redirectUri = SsoApiFactory.RedirectUri, code = "not-a-real-code", codeVerifier = new string('a', 43)
        });
        var form = await client.PostAsync("/api/oauth/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["client_id"] = SsoApiFactory.ConsoleClientId,
            ["redirect_uri"] = SsoApiFactory.RedirectUri, ["code"] = "not-a-real-code", ["code_verifier"] = new string('a', 43)
        }));

        foreach (var response in new[] { json, form })
        {
            response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            var body = await response.ReadJsonAsync();
            body.GetProperty("error").GetString().Should().Be("invalid_grant");
            body.GetProperty("error_description").GetString().Should().NotBeNullOrWhiteSpace();
        }
    }

    [Fact]
    public async Task ThirdPartyClientToken_IsAcceptedOnlyByUserInfo()
    {
        var (_, adminToken) = await LoginAsync(SsoApiFactory.AdminEmail, SsoApiFactory.AdminPassword);
        var adminId = Guid.Parse(HttpTestExtensions.JwtPayload(adminToken).GetProperty("sub").GetString()!);

        using var scope = _factory.Services.CreateScope();
        var tokens = scope.ServiceProvider.GetRequiredService<ITokenService>();
        // Even a SuperAdmin's token, once issued to a third-party client, must not unlock the platform API.
        var clientToken = tokens.GenerateAccessToken(new AccessTokenRequest(
            adminId, SsoApiFactory.AdminEmail, "admin", new[] { RoleNames.SuperAdmin }, new[] { "*" },
            OAuthScopes: new[] { "openid", "email" }, ClientId: "third-party-app", Audience: "third-party-app"));
        var forgedAudience = tokens.GenerateAccessToken(new AccessTokenRequest(
            adminId, SsoApiFactory.AdminEmail, "admin", new[] { RoleNames.SuperAdmin },
            ClientId: "third-party-app", Audience: "another-app"));
        var idToken = tokens.GenerateIdToken(new IdTokenRequest(
            adminId, "third-party-app", null, null, DateTime.UtcNow, new[] { "openid" },
            SsoApiFactory.AdminEmail, true, "admin", "admin", null));

        var client = _factory.CreateClient();
        async Task<HttpStatusCode> GetAsync(string url, string token)
        {
            client.UseBearer(token);
            return (await client.GetAsync(url)).StatusCode;
        }

        (await GetAsync("/api/users", clientToken)).Should().Be(HttpStatusCode.Unauthorized);
        (await GetAsync("/api/oauth/userinfo", clientToken)).Should().Be(HttpStatusCode.OK);
        (await GetAsync("/api/oauth/userinfo", forgedAudience)).Should().Be(HttpStatusCode.Unauthorized);
        (await GetAsync("/api/oauth/userinfo", idToken)).Should().Be(HttpStatusCode.Unauthorized);
        (await GetAsync("/api/oauth/userinfo", adminToken)).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task OAuthCodeFlow_WithPkce_IssuesIdToken_AndDetectsCodeReplay()
    {
        var sso = _factory.CreateBrowserClient();
        var login = await sso.PostJsonAsync("/api/auth/sso/login", new { email = SsoApiFactory.SsoEmail, password = SsoApiFactory.UserPassword });
        var loginJson = await login.ReadJsonAsync();
        login.StatusCode.Should().Be(HttpStatusCode.OK, loginJson.ToString());
        var ssoToken = loginJson.GetProperty("data").GetProperty("accessToken").GetString()!;
        sso.UseBearer(ssoToken);

        var verifier = OAuthHelpers.Base64UrlEncode(RandomNumberGenerator.GetBytes(40));
        var challenge = OAuthHelpers.Base64UrlEncode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var authorize = await (await sso.GetAsync(
            $"/api/oauth/authorize?client_id={SsoApiFactory.ConsoleClientId}&redirect_uri={Uri.EscapeDataString(SsoApiFactory.RedirectUri)}" +
            $"&scope=openid%20profile%20email&state=s1&code_challenge={challenge}&code_challenge_method=S256&nonce=n-1&response_type=code")).ReadJsonAsync();
        var data = authorize.GetProperty("data");
        if (data.GetProperty("requiresConsent").GetBoolean())
        {
            var consent = await sso.PostJsonAsync("/api/oauth/consent", new
            {
                clientId = SsoApiFactory.ConsoleClientId, redirectUri = SsoApiFactory.RedirectUri,
                scopes = data.GetProperty("requestedScopes").EnumerateArray().Select(s => s.GetString()).ToArray(),
                state = "s1", codeChallenge = challenge, codeChallengeMethod = "S256", approve = true, nonce = "n-1"
            });
            data = (await consent.ReadJsonAsync()).GetProperty("data");
        }
        var code = data.GetProperty("code").GetString()!;

        var app = _factory.CreateClient();
        FormUrlEncodedContent Form(string verifierValue) => new(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code", ["client_id"] = SsoApiFactory.ConsoleClientId,
            ["redirect_uri"] = SsoApiFactory.RedirectUri, ["code"] = code, ["code_verifier"] = verifierValue
        });

        var badPkce = await app.PostAsync("/api/oauth/token", Form(new string('a', 43)));
        badPkce.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await badPkce.ReadJsonAsync()).GetProperty("error").GetString().Should().Be("invalid_grant");

        var token = await app.PostAsync("/api/oauth/token", Form(verifier));
        var tokenJson = await token.ReadJsonAsync();
        token.StatusCode.Should().Be(HttpStatusCode.OK, tokenJson.ToString());
        var idToken = HttpTestExtensions.JwtPayload(tokenJson.GetProperty("id_token").GetString()!);
        idToken.GetProperty("nonce").GetString().Should().Be("n-1");
        idToken.GetProperty("aud").GetString().Should().Be(SsoApiFactory.ConsoleClientId);
        idToken.GetProperty("sid").GetString().Should().Be(HttpTestExtensions.JwtPayload(ssoToken).GetProperty("sid").GetString());
        // The seeded console is the first-party client, so its access token targets the platform API.
        HttpTestExtensions.JwtPayload(tokenJson.GetProperty("access_token").GetString()!)
            .GetProperty("aud").GetString().Should().Be("integration-api");

        var replay = await app.PostAsync("/api/oauth/token", Form(verifier));
        replay.StatusCode.Should().Be(HttpStatusCode.BadRequest);

        // RFC 6749 §4.1.2: tokens issued from a replayed code are revoked.
        var refresh = await app.PostAsync("/api/oauth/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token", ["client_id"] = SsoApiFactory.ConsoleClientId,
            ["refresh_token"] = tokenJson.GetProperty("refresh_token").GetString()!
        }));
        refresh.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
