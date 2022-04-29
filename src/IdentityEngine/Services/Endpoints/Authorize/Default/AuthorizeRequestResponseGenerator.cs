using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Intermediate;
using IdentityEngine.Services.Endpoints.Authorize.Models.RequestInteractionHandler;
using IdentityEngine.Services.Endpoints.Authorize.Models.ResponseGenerator;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Endpoints.Authorize.Default;

public class AuthorizeRequestResponseGenerator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret, TAuthorizationCode>
    : IAuthorizeRequestResponseGenerator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
    where TAuthorizationCode : class, IAuthorizationCode
{
    private readonly IAuthorizationCodeService<TAuthorizationCode> _codes;

    public AuthorizeRequestResponseGenerator(IAuthorizationCodeService<TAuthorizationCode> codes)
    {
        ArgumentNullException.ThrowIfNull(codes);
        _codes = codes;
    }

    public async Task<AuthorizeResponse> CreateResponseAsync(
        HttpContext httpContext,
        ValidAuthorizeRequestInteraction<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        ;
        var code = await CreateAuthorizationCodeAsync(httpContext, request, cancellationToken);
        return new(code, request.State);
    }

    private async Task<string> CreateAuthorizationCodeAsync(
        HttpContext httpContext,
        ValidAuthorizeRequestInteraction<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return await _codes.CreateAsync(
            httpContext,
            request.UserSession.SubjectId,
            request.UserSession.SessionId,
            request.Client.AuthorizationCodeLifetime,
            request.Client.ClientId,
            request.RedirectUri,
            request.GrantedResources.AllScopes,
            request.CodeChallenge,
            request.CodeChallengeMethod,
            request.Nonce,
            cancellationToken);
    }
}
