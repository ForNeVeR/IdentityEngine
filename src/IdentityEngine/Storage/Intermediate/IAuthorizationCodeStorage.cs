using IdentityEngine.Models.Intermediate;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Storage.Intermediate;

public interface IAuthorizationCodeStorage<TAuthorizationCode>
    where TAuthorizationCode : class, IAuthorizationCode
{
    Task<string> CreateAsync(
        HttpContext httpContext,
        string subjectId,
        string sessionId,
        DateTimeOffset createdAt,
        DateTimeOffset expiresAt,
        string clientId,
        string redirectUri,
        IReadOnlySet<string> scopes,
        string codeChallenge,
        string codeChallengeMethod,
        string? nonce,
        CancellationToken cancellationToken = default);

    Task<TAuthorizationCode?> ReadAndDeleteAsync(
        HttpContext httpContext,
        string authorizationCode,
        CancellationToken cancellationToken = default);
}
