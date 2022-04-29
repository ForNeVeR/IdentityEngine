using IdentityEngine.Extensions;
using IdentityEngine.Models.Intermediate;
using IdentityEngine.Storage.Intermediate;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Endpoints.Authorize.Default;

public class AuthorizationCodeService<TAuthorizationCode> : IAuthorizationCodeService<TAuthorizationCode>
    where TAuthorizationCode : class, IAuthorizationCode
{
    private readonly IAuthorizationCodeStorage<TAuthorizationCode> _storage;
    private readonly ISystemClock _systemClock;

    public AuthorizationCodeService(IAuthorizationCodeStorage<TAuthorizationCode> storage, ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(systemClock);
        _storage = storage;
        _systemClock = systemClock;
    }

    public async Task<string> CreateAsync(
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
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var codeChallengeHash = HashCodeChallengeIfRequired(codeChallenge, codeChallengeMethod);
        var createdAt = _systemClock.UtcNow;
        var expiresAt = createdAt.Add(codeLifetime);
        return await _storage.CreateAsync(
            httpContext,
            subjectId,
            sessionId,
            createdAt,
            expiresAt,
            clientId,
            redirectUri,
            scopes,
            codeChallengeHash,
            codeChallengeMethod,
            nonce,
            cancellationToken);
    }

    public async Task<TAuthorizationCode?> VerifyAsync(
        HttpContext httpContext,
        string authorizationCode,
        string codeVerifier,
        string redirectUri,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var code = await _storage.ReadAndDeleteAsync(httpContext, authorizationCode, cancellationToken);
        if (code == null
            || _systemClock.UtcNow > code.ExpiresAt
            || codeVerifier.ToSha256() != code.CodeChallenge
            || redirectUri != code.RedirectUri)
        {
            return null;
        }

        return code;
    }


    private static string HashCodeChallengeIfRequired(string codeChallenge, string codeChallengeMethod)
    {
        if (codeChallengeMethod == Constants.Requests.Authorize.Values.CodeChallengeMethod.Plain)
        {
            return codeChallenge.ToSha256();
        }

        return codeChallenge;
    }
}
