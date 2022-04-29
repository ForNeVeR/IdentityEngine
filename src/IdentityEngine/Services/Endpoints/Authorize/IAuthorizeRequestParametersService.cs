using IdentityEngine.Models.Configuration;
using IdentityEngine.Services.Endpoints.Authorize.Models.RequestValidator;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Endpoints.Authorize;

public interface IAuthorizeRequestParametersService<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    Task<string> WriteAsync(
        HttpContext httpContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> authorizeRequest,
        CancellationToken cancellationToken = default);
}
