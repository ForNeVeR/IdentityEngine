using IdentityEngine.Models.Configuration;

namespace IdentityEngine.Storage.Configuration.Models;

public class ScopesResourcesSearchResult<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    public ScopesResourcesSearchResult(
        IReadOnlyCollection<TIdTokenScope>? idTokenScopes,
        IReadOnlyCollection<TAccessTokenScope>? accessTokenScopes,
        IReadOnlyCollection<TResource>? resources)
    {
        IdTokenScopes = idTokenScopes;
        AccessTokenScopes = accessTokenScopes;
        Resources = resources;
    }

    public IReadOnlyCollection<TIdTokenScope>? IdTokenScopes { get; }
    public IReadOnlyCollection<TAccessTokenScope>? AccessTokenScopes { get; }
    public IReadOnlyCollection<TResource>? Resources { get; }

    public void Deconstruct(
        out IReadOnlyCollection<TIdTokenScope>? idTokenScopes,
        out IReadOnlyCollection<TAccessTokenScope>? accessTokenScopes,
        out IReadOnlyCollection<TResource>? resources)
    {
        idTokenScopes = IdTokenScopes;
        accessTokenScopes = AccessTokenScopes;
        resources = Resources;
    }
}
