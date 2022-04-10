using IdentityEngine.Models.Configuration;
using IdentityEngine.Services.Scope.Models;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Scope;

public interface IScopeValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>
    where TClient : IClient<TClientSecret>
    where TClientSecret : ISecret
    where TIdTokenScope : IIdTokenScope
    where TAccessTokenScope : IAccessTokenScope
    where TApi : IApi<TApiSecret>
    where TApiSecret : ISecret
{
    Task<ScopesValidationResult<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>> ValidateRequestedScopesAsync(
        HttpContext httpContext,
        TClient client,
        IReadOnlySet<string> requestedScopes,
        CancellationToken cancellationToken = default);
}
