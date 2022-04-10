using IdentityEngine.Models.Configuration;
using IdentityEngine.Services.Endpoints.Authorize.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace IdentityEngine.Services.Endpoints.Authorize;

public interface IAuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>
    where TClient : IClient<TClientSecret>
    where TClientSecret : ISecret
    where TIdTokenScope : IIdTokenScope
    where TAccessTokenScope : IAccessTokenScope
    where TApi : IApi<TApiSecret>
    where TApiSecret : ISecret
{
    Task<AuthorizeRequestValidationResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>> ValidateAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> authorizeRequestParameters,
        CancellationToken cancellationToken = default);
}
