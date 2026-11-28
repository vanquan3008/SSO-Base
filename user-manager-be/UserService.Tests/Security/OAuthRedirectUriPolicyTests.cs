using UserService.Application.Configuration;
using UserService.Application.Features.OAuth.Policies;

namespace UserService.Tests.Security;

public class OAuthRedirectUriPolicyTests
{
    private const string Registered = "https://app.example.com/oauth/callback";

    private static OAuthRedirectUriPolicy Policy(bool allowHttpLocalhost = true) => new(new AppSettings
    {
        OAuth = new OAuthConfiguration { AllowHttpForLocalhost = allowHttpLocalhost }
    });

    [Fact]
    public void RegisteredUri_MatchesOnlyExactly()
    {
        var policy = Policy();

        policy.IsAllowed(Registered, new[] { Registered }).Should().BeTrue();

        policy.IsAllowed("https://app.example.com/oauth/callback/", new[] { Registered }).Should().BeFalse();
        policy.IsAllowed("https://app.example.com/OAuth/Callback", new[] { Registered }).Should().BeFalse();
        policy.IsAllowed("https://app.example.com/oauth/callback?next=https://evil.test", new[] { Registered }).Should().BeFalse();
        policy.IsAllowed("https://app.example.com:8443/oauth/callback", new[] { Registered }).Should().BeFalse();
        policy.IsAllowed("https://app.example.com/oauth/callback/../evil", new[] { Registered }).Should().BeFalse();
    }

    [Theory]
    [InlineData("https://app.example.com/oauth/callback#frag")]
    [InlineData("https://user:pass@app.example.com/oauth/callback")]
    [InlineData("http://app.example.com/oauth/callback")]
    [InlineData("javascript:alert(1)")]
    [InlineData("/oauth/callback")]
    public void MalformedOrInsecureUris_AreRejected_EvenIfRegistered(string uri)
    {
        Policy().IsAllowed(uri, new[] { uri }).Should().BeFalse();
        Policy().IsWellFormed(uri).Should().BeFalse();
    }

    [Fact]
    public void LoopbackIpLiteral_MayUseAnyPort()
    {
        var policy = Policy();

        policy.IsAllowed("http://127.0.0.1:51004/cb", new[] { "http://127.0.0.1/cb" }).Should().BeTrue();
        policy.IsAllowed("http://[::1]:8080/cb", new[] { "http://[::1]:5000/cb" }).Should().BeTrue();
        policy.IsAllowed("http://127.0.0.1:51004/other", new[] { "http://127.0.0.1/cb" }).Should().BeFalse();
    }

    [Fact]
    public void HttpLoopback_RequiresTheSetting()
    {
        Policy(allowHttpLocalhost: false).IsAllowed("http://localhost:4200/cb", new[] { "http://localhost:4200/cb" }).Should().BeFalse();
        Policy(allowHttpLocalhost: true).IsAllowed("http://localhost:4200/cb", new[] { "http://localhost:4200/cb" }).Should().BeTrue();
    }

    [Fact]
    public void ClientWithoutRegisteredUris_IsAlwaysRejected()
    {
        Policy().IsAllowed(Registered, Array.Empty<string>()).Should().BeFalse();
    }
}
