using IdentityEngine.Models.Intermediate;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Storage.Intermediate;

public interface IAuthorizeRequestParametersStorage<TAuthorizeRequestParameters>
    where TAuthorizeRequestParameters : class, IAuthorizeRequestParameters
{
    Task<string> WriteAsync(
        HttpContext httpContext,
        DateTimeOffset requestDate,
        string clientId,
        string redirectUri,
        IReadOnlySet<string> scope,
        string codeChallenge,
        string codeChallengeMethod,
        string responseType,
        string? state,
        string responseMode,
        string? nonce,
        string? display,
        IReadOnlySet<string>? prompt,
        long? maxAge,
        string? uiLocales,
        string? loginHint,
        string[]? acrValues,
        CancellationToken cancellationToken = default);

    Task<TAuthorizeRequestParameters> ReadAsync(
        HttpContext httpContext,
        string authorizeRequestId,
        CancellationToken cancellationToken = default);
}
