using IdentityEngine.Models.Configuration;

namespace IdentityEngine.Services.Core.Models.ResourceValidator;

public class ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    public ValidResources(
        bool allowRefreshTokens,
        IReadOnlySet<TIdTokenScope> idTokenScopes,
        IReadOnlySet<TAccessTokenScope> accessTokenScopes,
        IReadOnlySet<TResource> resources)
    {
        ArgumentNullException.ThrowIfNull(idTokenScopes);
        ArgumentNullException.ThrowIfNull(accessTokenScopes);
        ArgumentNullException.ThrowIfNull(resources);
        foreach (var resource in resources)
        {
            if (!resource.Enabled)
            {
                throw new InvalidOperationException(
                    $"Disabled resource with name: \"{resource.ProtocolName}\" occurs in {nameof(ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>)} ctor.");
            }
        }

        var allScopesCapacity = idTokenScopes.Count + accessTokenScopes.Count + 1;
        var allScopes = new HashSet<string>(allScopesCapacity, StringComparer.Ordinal);
        var requiredScopes = new HashSet<string>(allScopesCapacity, StringComparer.Ordinal);
        foreach (var idTokenScope in idTokenScopes)
        {
            if (!idTokenScope.Enabled)
            {
                throw new InvalidOperationException(
                    $"Disabled id_token scope with name: \"{idTokenScope.ProtocolName}\" occurs {nameof(ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>)} ctor.");
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
                    $"Disabled access_token scope with name: \"{accessTokenScope.ProtocolName}\" occurs {nameof(ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>)} ctor.");
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
        Resources = resources;
        AllScopes = allScopes;
        RequiredScopes = requiredScopes;
        AllowRefreshTokens = allowRefreshTokens;
    }

    public IReadOnlySet<TIdTokenScope> IdTokenScopes { get; }
    public IReadOnlySet<TAccessTokenScope> AccessTokenScopes { get; }
    public IReadOnlySet<TResource> Resources { get; }
    public IReadOnlySet<string> AllScopes { get; }
    public IReadOnlySet<string> RequiredScopes { get; }
    public bool AllowRefreshTokens { get; }

    public ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> FilterConsentedScopes(IReadOnlySet<string> consentedScopes)
    {
        ArgumentNullException.ThrowIfNull(consentedScopes);
        var allowRefreshTokens = consentedScopes.Contains(Constants.Requests.Values.Scope.OfflineAccess);
        var idTokenScopes = new HashSet<TIdTokenScope>(IdTokenScopes.Count);
        var accessTokenScopes = new HashSet<TAccessTokenScope>(AccessTokenScopes.Count);
        var resources = new HashSet<TResource>(Resources.Count);
        foreach (var idTokenScope in IdTokenScopes)
        {
            if (consentedScopes.Contains(idTokenScope.ProtocolName))
            {
                idTokenScopes.Add(idTokenScope);
            }
        }

        foreach (var accessTokenScope in AccessTokenScopes)
        {
            if (consentedScopes.Contains(accessTokenScope.ProtocolName))
            {
                accessTokenScopes.Add(accessTokenScope);
            }
        }

        foreach (var resource in Resources)
        {
            if (resource.AccessTokenScopes != null)
            {
                foreach (var accessTokenScope in accessTokenScopes)
                {
                    if (resource.AccessTokenScopes.Contains(accessTokenScope.ProtocolName))
                    {
                        resources.Add(resource);
                        break;
                    }
                }
            }
        }

        return new(allowRefreshTokens, idTokenScopes, accessTokenScopes, resources);
    }
}
