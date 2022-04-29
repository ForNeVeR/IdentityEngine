using IdentityEngine.Models.Configuration;
using IdentityEngine.Services.Core.Models.ResourceValidator;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Core;

public interface IResourceValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    Task<ResourcesValidationResult<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>> ValidateRequestedResourcesAsync(
        HttpContext httpContext,
        TClient client,
        IReadOnlySet<string> requestedScopes,
        CancellationToken cancellationToken = default);
}
