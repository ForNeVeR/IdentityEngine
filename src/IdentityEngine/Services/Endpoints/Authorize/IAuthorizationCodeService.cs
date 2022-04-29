using IdentityEngine.Models.Intermediate;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Endpoints.Authorize;

public interface IAuthorizationCodeService<TAuthorizationCode>
    where TAuthorizationCode : class, IAuthorizationCode
{
    Task<string> CreateAsync(
        HttpContext httpContext,
        string subjectId,
        string sessionId,
        TimeSpan codeLifetime,
        string clientId,
        string redirectUri,
        IReadOnlySet<string> scopes,
        string codeChallenge,
        string codeChallengeMethod,
        string? nonce,
        CancellationToken cancellationToken = default);


    Task<TAuthorizationCode?> VerifyAsync(
        HttpContext httpContext,
        string authorizationCode,
        string codeVerifier,
        string redirectUri,
        CancellationToken cancellationToken = default);
}
