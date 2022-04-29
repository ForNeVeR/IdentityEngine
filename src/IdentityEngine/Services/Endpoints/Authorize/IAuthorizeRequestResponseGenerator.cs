using IdentityEngine.Models.Configuration;
using IdentityEngine.Services.Endpoints.Authorize.Models.RequestInteractionHandler;
using IdentityEngine.Services.Endpoints.Authorize.Models.ResponseGenerator;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Endpoints.Authorize;

public interface IAuthorizeRequestResponseGenerator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    Task<AuthorizeResponse> CreateResponseAsync(
        HttpContext httpContext,
        ValidAuthorizeRequestInteraction<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> request,
        CancellationToken cancellationToken = default);
}
