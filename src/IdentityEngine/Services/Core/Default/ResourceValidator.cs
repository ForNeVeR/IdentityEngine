using System.Diagnostics.CodeAnalysis;
using IdentityEngine.Models.Configuration;
using IdentityEngine.Services.Core.Models.ResourceValidator;
using IdentityEngine.Storage.Configuration;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Core.Default;

public class ResourceValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    : IResourceValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    private readonly IScopeStorage<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> _storage;

    public ResourceValidator(IScopeStorage<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> storage)
    {
        ArgumentNullException.ThrowIfNull(storage);
        _storage = storage;
    }

    public async Task<ResourcesValidationResult<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>> ValidateRequestedResourcesAsync(
        HttpContext httpContext,
        TClient client,
        IReadOnlySet<string> requestedScopes,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(requestedScopes);
        var (dbIdTokenScopes, dbAccessTokenScopes, dbResources) =
            await _storage.FindEnabledScopesAndResourcesAsync(httpContext, requestedScopes, cancellationToken);
        if (!IsOpenIdConnectRequest(requestedScopes) && dbIdTokenScopes?.Count > 0)
        {
            return new(dbIdTokenScopes.Select(x => x.ProtocolName).ToHashSet(StringComparer.Ordinal));
        }

        if (!IsConfigurationValid(dbIdTokenScopes, dbAccessTokenScopes, dbResources, out var misconfiguredResources))
        {
            return new(misconfiguredResources);
        }

        return Validate(dbIdTokenScopes, dbAccessTokenScopes, dbResources, requestedScopes, client);
    }

    private static bool IsOpenIdConnectRequest(IReadOnlySet<string> requestedScopes)
    {
        return requestedScopes.Contains(Constants.Requests.Values.Scope.OpenId);
    }

    private static ResourcesValidationResult<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> Validate(
        IReadOnlyCollection<TIdTokenScope>? idTokenScopes,
        IReadOnlyCollection<TAccessTokenScope>? accessTokenScopes,
        IReadOnlyCollection<TResource>? resources,
        IReadOnlySet<string> requestedScopes,
        TClient client)
    {
        var invalidScopes = new HashSet<string>(Math.Max(requestedScopes.Count / 2, 1), StringComparer.Ordinal);
        var validIdTokenScopes = new HashSet<TIdTokenScope>(idTokenScopes?.Count ?? 0);
        var validAccessTokenScopes = new HashSet<TAccessTokenScope>(accessTokenScopes?.Count ?? 0);
        var validResources = new HashSet<TResource>(resources?.Count ?? 0);
        var allowRefreshTokens = false;
        foreach (var requestedScope in requestedScopes)
        {
            var accessTokensScope = accessTokenScopes?.FirstOrDefault(x => x.ProtocolName == requestedScope);
            if (accessTokensScope != null)
            {
                if (client.AccessTokenScopes?.Contains(requestedScope) == true)
                {
                    validAccessTokenScopes.Add(accessTokensScope);
                    if (resources != null)
                    {
                        foreach (var resource in resources)
                        {
                            if (resource.AccessTokenScopes?.Contains(requestedScope) == true)
                            {
                                validResources.Add(resource);
                            }
                        }
                    }
                }
                else
                {
                    invalidScopes.Add(requestedScope);
                }

                continue;
            }

            var idTokenScope = idTokenScopes?.FirstOrDefault(x => x.ProtocolName == requestedScope);
            if (idTokenScope != null)
            {
                if (client.IdTokenScopes?.Contains(requestedScope) == true)
                {
                    validIdTokenScopes.Add(idTokenScope);
                }
                else
                {
                    invalidScopes.Add(requestedScope);
                }

                continue;
            }

            if (requestedScope == Constants.Requests.Values.Scope.OfflineAccess && client.EnableRefreshTokens)
            {
                allowRefreshTokens = true;
                continue;
            }

            invalidScopes.Add(requestedScope);
        }

        if (invalidScopes.Count > 0)
        {
            return new(invalidScopes);
        }

        return new(new ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>(
            allowRefreshTokens,
            validIdTokenScopes,
            validAccessTokenScopes,
            validResources));
    }


    private static bool IsConfigurationValid(
        IReadOnlyCollection<TIdTokenScope>? idTokenScopes,
        IReadOnlyCollection<TAccessTokenScope>? accessTokenScopes,
        IReadOnlyCollection<TResource>? resources,
        [NotNullWhen(false)] out MisconfiguredResources? misconfiguredScopes)
    {
        HashSet<string>? overlapped = null;
        if (idTokenScopes != null && accessTokenScopes != null)
        {
            overlapped = idTokenScopes
                .Select(x => x.ProtocolName)
                .Intersect(accessTokenScopes.Select(x => x.ProtocolName))
                .ToHashSet(StringComparer.Ordinal);
        }

        HashSet<string>? invalidIdTokenScopes = null;
        if (idTokenScopes != null)
        {
            // duplicates
            invalidIdTokenScopes = idTokenScopes
                .Select(x => x.ProtocolName)
                .GroupBy(x => x)
                .Where(x => x.Count() > 1)
                .Select(x => x.Key)
                .ToHashSet(StringComparer.Ordinal);

            // disabled
            foreach (var disabledIdTokenScope in idTokenScopes.Where(x => x.Enabled == false).Select(x => x.ProtocolName))
            {
                invalidIdTokenScopes.Add(disabledIdTokenScope);
            }

            // offline_access
            if (idTokenScopes.Any(x => x.ProtocolName == Constants.Requests.Values.Scope.OfflineAccess))
            {
                overlapped ??= new(1, StringComparer.Ordinal);
                overlapped.Add(Constants.Requests.Values.Scope.OfflineAccess);
            }
        }

        HashSet<string>? invalidAccessTokenScopes = null;
        if (accessTokenScopes != null)
        {
            // duplicates
            invalidAccessTokenScopes = accessTokenScopes
                .Select(x => x.ProtocolName)
                .GroupBy(x => x)
                .Where(x => x.Count() > 1)
                .Select(x => x.Key)
                .ToHashSet(StringComparer.Ordinal);

            // disabled
            foreach (var disabledAccessTokenScope in accessTokenScopes.Where(x => x.Enabled == false).Select(x => x.ProtocolName))
            {
                invalidAccessTokenScopes.Add(disabledAccessTokenScope);
            }

            // offline_access
            if (accessTokenScopes.Any(x => x.ProtocolName == Constants.Requests.Values.Scope.OfflineAccess))
            {
                overlapped ??= new(1, StringComparer.Ordinal);
                overlapped.Add(Constants.Requests.Values.Scope.OfflineAccess);
            }
        }

        HashSet<string>? invalidResources = null;
        if (resources != null)
        {
            // duplicates
            invalidResources = resources
                .Select(x => x.ProtocolName)
                .GroupBy(x => x)
                .Where(x => x.Count() > 1)
                .Select(x => x.Key)
                .ToHashSet(StringComparer.Ordinal);
            // disabled
            foreach (var disabledResource in resources.Where(x => x.Enabled == false).Select(x => x.ProtocolName))
            {
                invalidResources.Add(disabledResource);
            }
        }

        if ((invalidIdTokenScopes?.Count ?? 0) == 0
            && (invalidAccessTokenScopes?.Count ?? 0) == 0
            && (overlapped?.Count ?? 0) == 0
            && (invalidResources?.Count ?? 0) == 0)
        {
            misconfiguredScopes = null;
            return true;
        }

        misconfiguredScopes = new(invalidIdTokenScopes, invalidAccessTokenScopes, overlapped, invalidResources);
        return false;
    }
}
