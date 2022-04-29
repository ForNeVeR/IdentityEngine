using System.Diagnostics.CodeAnalysis;
using IdentityEngine.Models.Configuration;

namespace IdentityEngine.Services.Endpoints.Authorize.Models.RequestValidator;

public class AuthorizeRequestValidationResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    public AuthorizeRequestValidationResult(ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> validRequest)
    {
        ArgumentNullException.ThrowIfNull(validRequest);
        HasError = false;
        ValidRequest = validRequest;
    }

    public AuthorizeRequestValidationResult(AuthorizeRequestValidationError validationError)
    {
        ArgumentNullException.ThrowIfNull(validationError);
        HasError = true;
        ValidationError = validationError;
    }

    [MemberNotNullWhen(true, nameof(ValidationError))]
    [MemberNotNullWhen(false, nameof(ValidRequest))]
    public bool HasError { get; }

    public ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>? ValidRequest { get; }

    public AuthorizeRequestValidationError? ValidationError { get; }
}
