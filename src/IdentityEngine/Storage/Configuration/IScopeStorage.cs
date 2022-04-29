using IdentityEngine.Models.Configuration;
using IdentityEngine.Storage.Configuration.Models;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Storage.Configuration;

public interface IScopeStorage<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    Task<ScopesResourcesSearchResult<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>> FindEnabledScopesAndResourcesAsync(
        HttpContext httpContext,
        IReadOnlySet<string> scopesToSearch,
        CancellationToken cancellationToken = default);
}
