using IdentityEngine.Models.Configuration;

namespace IdentityEngine.Services.Scope.Models;

public class ValidScopes<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>
    where TIdTokenScope : IIdTokenScope
    where TAccessTokenScope : IAccessTokenScope
    where TApi : IApi<TApiSecret>
    where TApiSecret : ISecret
{
    public ValidScopes(
        bool allowRefreshTokens,
        IReadOnlySet<TIdTokenScope> idTokenScopes,
        IReadOnlySet<TAccessTokenScope> accessTokenScopes,
        IReadOnlySet<TApi> apis)
    {
        ArgumentNullException.ThrowIfNull(idTokenScopes);
        ArgumentNullException.ThrowIfNull(accessTokenScopes);
        ArgumentNullException.ThrowIfNull(apis);
        foreach (var api in apis)
        {
            if (!api.Enabled)
            {
                throw new InvalidOperationException(
                    $"Disabled API with name: \"{api.ProtocolName}\" occurs in {nameof(ValidScopes<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>)} ctor.");
            }
        }

        var allScopesCapacity = idTokenScopes.Count + accessTokenScopes.Count + 1;
        var allScopes = new HashSet<string>(allScopesCapacity, StringComparer.InvariantCulture);
        var requiredScopes = new HashSet<string>(allScopesCapacity, StringComparer.InvariantCulture);
        foreach (var idTokenScope in idTokenScopes)
        {
            if (!idTokenScope.Enabled)
            {
                throw new InvalidOperationException(
                    $"Disabled id_token scope with name: \"{idTokenScope.ProtocolName}\" occurs {nameof(ValidScopes<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>)} ctor.");
            }

            allScopes.Add(idTokenScope.ProtocolName);
            if (idTokenScope.Required)
            {
                requiredScopes.Add(idTokenScope.ProtocolName);
            }
        }

        foreach (var accessTokenScope in accessTokenScopes)
        {
            if (!accessTokenScope.Enabled)
            {
                throw new InvalidOperationException(
                    $"Disabled access_token scope with name: \"{accessTokenScope.ProtocolName}\" occurs {nameof(ValidScopes<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>)} ctor.");
            }

            allScopes.Add(accessTokenScope.ProtocolName);
            if (accessTokenScope.Required)
            {
                requiredScopes.Add(accessTokenScope.ProtocolName);
            }
        }

        if (allowRefreshTokens)
        {
            allScopes.Add(Constants.Requests.Values.Scope.OfflineAccess);
        }

        IdTokenScopes = idTokenScopes;
        AccessTokenScopes = accessTokenScopes;
        Apis = apis;
        AllScopes = allScopes;
        RequiredScopes = requiredScopes;
        AllowRefreshTokens = allowRefreshTokens;
    }

    public IReadOnlySet<TIdTokenScope> IdTokenScopes { get; }
    public IReadOnlySet<TAccessTokenScope> AccessTokenScopes { get; }
    public IReadOnlySet<TApi> Apis { get; }
    public IReadOnlySet<string> AllScopes { get; }
    public IReadOnlySet<string> RequiredScopes { get; }
    public bool AllowRefreshTokens { get; }
}
