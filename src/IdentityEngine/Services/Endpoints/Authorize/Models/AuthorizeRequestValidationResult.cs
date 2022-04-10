using System.Diagnostics.CodeAnalysis;
using IdentityEngine.Models.Configuration;

namespace IdentityEngine.Services.Endpoints.Authorize.Models;

public class AuthorizeRequestValidationResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>
    where TClient : IClient<TClientSecret>
    where TClientSecret : ISecret
    where TIdTokenScope : IIdTokenScope
    where TAccessTokenScope : IAccessTokenScope
    where TApi : IApi<TApiSecret>
    where TApiSecret : ISecret
{
    public AuthorizeRequestValidationResult(
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret> validRequest)
    {
        ArgumentNullException.ThrowIfNull(validRequest);
        HasError = false;
        ValidRequest = validRequest;
    }

    public AuthorizeRequestValidationResult(AuthorizeRequestError error)
    {
        ArgumentNullException.ThrowIfNull(error);
        HasError = true;
        Error = error;
    }

    [MemberNotNullWhen(true, nameof(Error))]
    [MemberNotNullWhen(false, nameof(ValidRequest))]
    public bool HasError { get; }

    public ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>? ValidRequest { get; }

    public AuthorizeRequestError? Error { get; }
}
