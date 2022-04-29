using System.Diagnostics.CodeAnalysis;
using IdentityEngine.Models;
using IdentityEngine.Models.Configuration;

namespace IdentityEngine.Services.Endpoints.Authorize.Models.RequestInteractionHandler;

public class AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    public AuthorizeRequestInteractionResult(ValidAuthorizeRequestInteraction<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> validRequest)
    {
        ArgumentNullException.ThrowIfNull(validRequest);
        HasError = false;
        RequireInteraction = false;
        IsValid = true;
        ValidRequest = validRequest;
    }

    public AuthorizeRequestInteractionResult(string requiredInteraction)
    {
        ArgumentNullException.ThrowIfNull(requiredInteraction);
        HasError = false;
        RequireInteraction = false;
        IsValid = true;
        RequiredInteraction = requiredInteraction;
    }

    public AuthorizeRequestInteractionResult(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        HasError = true;
        RequireInteraction = false;
        IsValid = false;
        ProtocolError = protocolError;
    }


    [MemberNotNullWhen(true, nameof(ProtocolError))]
    public bool HasError { get; }

    [MemberNotNullWhen(true, nameof(RequiredInteraction))]
    public bool RequireInteraction { get; }

    [MemberNotNullWhen(true, nameof(ValidRequest))]
    public bool IsValid { get; }

    public ValidAuthorizeRequestInteraction<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>? ValidRequest { get; }

    public string? RequiredInteraction { get; }

    public ProtocolError? ProtocolError { get; }
}
