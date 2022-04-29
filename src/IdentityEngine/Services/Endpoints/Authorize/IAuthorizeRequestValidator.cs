using IdentityEngine.Models.Configuration;
using IdentityEngine.Services.Endpoints.Authorize.Models.RequestValidator;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace IdentityEngine.Services.Endpoints.Authorize;

public interface IAuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    Task<AuthorizeRequestValidationResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>> ValidateAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset requestDate,
        CancellationToken cancellationToken = default);
}
