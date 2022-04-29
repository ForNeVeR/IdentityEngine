using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Intermediate;
using IdentityEngine.Services.Endpoints.Authorize.Models.RequestValidator;
using IdentityEngine.Storage.Intermediate;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Endpoints.Authorize.Default;

public class AuthorizeRequestParametersService<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret, TAuthorizeRequestParameters>
    : IAuthorizeRequestParametersService<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
    where TAuthorizeRequestParameters : class, IAuthorizeRequestParameters
{
    private readonly IAuthorizeRequestParametersStorage<TAuthorizeRequestParameters> _storage;

    public AuthorizeRequestParametersService(IAuthorizeRequestParametersStorage<TAuthorizeRequestParameters> storage)
    {
        ArgumentNullException.ThrowIfNull(storage);
        _storage = storage;
    }

    public async Task<string> WriteAsync(
        HttpContext httpContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> authorizeRequest,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        cancellationToken.ThrowIfCancellationRequested();
        return await _storage.WriteAsync(
            httpContext,
            authorizeRequest.RequestDate,
            authorizeRequest.Client.ClientId,
            authorizeRequest.RedirectUri,
            authorizeRequest.Resources.AllScopes,
            authorizeRequest.CodeChallenge,
            authorizeRequest.CodeChallengeMethod,
            authorizeRequest.ResponseType,
            authorizeRequest.State,
            authorizeRequest.ResponseMode,
            authorizeRequest.Nonce,
            authorizeRequest.Display,
            authorizeRequest.Prompt,
            authorizeRequest.MaxAge,
            authorizeRequest.UiLocales,
            authorizeRequest.LoginHint,
            authorizeRequest.AcrValues,
            cancellationToken);
    }
}
