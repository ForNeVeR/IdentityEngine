using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Intermediate;
using IdentityEngine.Services.Core.Models.UserAuthentication;
using IdentityEngine.Services.Endpoints.Authorize.Models.RequestInteractionHandler;
using IdentityEngine.Services.Endpoints.Authorize.Models.RequestValidator;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Endpoints.Authorize;

public interface IAuthorizeRequestInteractionHandler<
    TClient,
    TClientSecret,
    TIdTokenScope,
    TAccessTokenScope,
    TResource,
    TResourceSecret,
    TAuthorizeRequestUserConsent>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
    where TAuthorizeRequestUserConsent : class, IAuthorizeRequestUserConsent
{
    Task<AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>> HandleInteractionAsync(
        HttpContext httpContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> authorizeRequest,
        AuthenticatedUserSession? userSession,
        TAuthorizeRequestUserConsent? authorizeRequestConsent,
        CancellationToken cancellationToken = default);
}
