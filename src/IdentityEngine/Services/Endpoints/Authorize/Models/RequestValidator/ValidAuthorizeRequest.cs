using IdentityEngine.Models.Configuration;
using IdentityEngine.Services.Core.Models.ResourceValidator;

namespace IdentityEngine.Services.Endpoints.Authorize.Models.RequestValidator;

public class ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    public ValidAuthorizeRequest(
        DateTimeOffset requestDate,
        TClient client,
        string redirectUri,
        ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> resources,
        string codeChallenge,
        string codeChallengeMethod,
        string responseType,
        string? state,
        string responseMode,
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

        ArgumentNullException.ThrowIfNull(resources);

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

        if (string.IsNullOrWhiteSpace(responseMode))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseMode));
        }

        RequestDate = requestDate;
        Client = client;
        RedirectUri = redirectUri;
        Resources = resources;
        CodeChallenge = codeChallenge;
        CodeChallengeMethod = codeChallengeMethod;
        ResponseType = responseType;
        State = state;
        ResponseMode = responseMode;
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

    public ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> Resources { get; }

    public string CodeChallenge { get; }

    public string CodeChallengeMethod { get; }

    public string ResponseType { get; }

    public string? State { get; }

    public string ResponseMode { get; }

    public string? Nonce { get; }

    public string? Display { get; }

    public IReadOnlySet<string>? Prompt { get; }

    public long? MaxAge { get; }

    public string? UiLocales { get; }

    public string? LoginHint { get; }

    public string[]? AcrValues { get; }
}
