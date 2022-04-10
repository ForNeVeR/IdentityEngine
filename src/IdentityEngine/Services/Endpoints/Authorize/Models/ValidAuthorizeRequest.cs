using IdentityEngine.Models.Configuration;
using IdentityEngine.Services.Scope.Models;

namespace IdentityEngine.Services.Endpoints.Authorize.Models;

public class ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>
    where TClient : IClient<TClientSecret>
    where TClientSecret : ISecret
    where TIdTokenScope : IIdTokenScope
    where TAccessTokenScope : IAccessTokenScope
    where TApi : IApi<TApiSecret>
    where TApiSecret : ISecret
{
    public ValidAuthorizeRequest(
        TClient client,
        string redirectUri,
        ValidScopes<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret> requestedScopes,
        string codeChallenge,
        string codeChallengeMethod,
        string responseType,
        string? state,
        string? responseMode,
        string? nonce,
        string? display,
        string[]? prompt,
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

        ArgumentNullException.ThrowIfNull(requestedScopes);
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

        Client = client;
        RedirectUri = redirectUri;
        RequestedScopes = requestedScopes;
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

    public TClient Client { get; }

    public string RedirectUri { get; }

    public ValidScopes<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret> RequestedScopes { get; }

    public string CodeChallenge { get; }

    public string CodeChallengeMethod { get; }

    public string ResponseType { get; }

    public string? State { get; }

    public string? ResponseMode { get; }

    public string? Nonce { get; }

    public string? Display { get; }

    public string[]? Prompt { get; }

    public long? MaxAge { get; }

    public string? UiLocales { get; }

    public string? LoginHint { get; }

    public string[]? AcrValues { get; }
}
