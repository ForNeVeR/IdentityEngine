using IdentityEngine.Models.Configuration;
using IdentityEngine.Services.Core.Models.ResourceValidator;
using IdentityEngine.Services.Core.Models.UserAuthentication;

namespace IdentityEngine.Services.Endpoints.Authorize.Models.RequestInteractionHandler;

public class ValidAuthorizeRequestInteraction<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    public ValidAuthorizeRequestInteraction(
        DateTimeOffset requestDate,
        TClient client,
        string redirectUri,
        ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> grantedResources,
        string codeChallenge,
        string codeChallengeMethod,
        string responseType,
        string? state,
        string responseMode,
        AuthenticatedUserSession userSession,
        string? nonce,
        string? display,
        IReadOnlySet<string>? prompt,
        long? maxAge,
        string? uiLocales,
        string? loginHint,
        string[]? acrValues)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (string.IsNullOrWhiteSpace(redirectUri))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(redirectUri));
        }

        ArgumentNullException.ThrowIfNull(grantedResources);
        if (string.IsNullOrWhiteSpace(codeChallenge))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(codeChallenge));
        }

        if (string.IsNullOrWhiteSpace(codeChallengeMethod))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(codeChallengeMethod));
        }

        if (string.IsNullOrWhiteSpace(responseType))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseType));
        }

        ArgumentNullException.ThrowIfNull(userSession);

        RequestDate = requestDate;
        Client = client;
        RedirectUri = redirectUri;
        GrantedResources = grantedResources;
        CodeChallenge = codeChallenge;
        CodeChallengeMethod = codeChallengeMethod;
        ResponseType = responseType;
        State = state;
        ResponseMode = responseMode;
        UserSession = userSession;
        Nonce = nonce;
        Display = display;
        Prompt = prompt;
        MaxAge = maxAge;
        UiLocales = uiLocales;
        LoginHint = loginHint;
        AcrValues = acrValues;
    }

    public DateTimeOffset RequestDate { get; }

    public TClient Client { get; }

    public string RedirectUri { get; }

    public ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> GrantedResources { get; }

    public string CodeChallenge { get; }

    public string CodeChallengeMethod { get; }

    public string ResponseType { get; }

    public string? State { get; }

    public string ResponseMode { get; }

    public AuthenticatedUserSession UserSession { get; }

    #region OpenId Connect 1.0

    public string? Nonce { get; }

    public string? Display { get; }

    public IReadOnlySet<string>? Prompt { get; }

    public long? MaxAge { get; }

    public string? UiLocales { get; }

    public string? LoginHint { get; }

    public string[]? AcrValues { get; }

    #endregion
}
