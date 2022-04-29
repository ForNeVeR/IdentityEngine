using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Operation;
using IdentityEngine.Storage.Operation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Core.Default;

public class GrantedConsentService<TClient, TClientSecret, TGrantedConsent> : IGrantedConsentService<TClient, TClientSecret, TGrantedConsent>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TGrantedConsent : class, IGrantedConsent
{
    private readonly IGrantedConsentStorage<TGrantedConsent> _storage;
    private readonly ISystemClock _systemClock;

    public GrantedConsentService(IGrantedConsentStorage<TGrantedConsent> storage, ISystemClock systemClock)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentNullException.ThrowIfNull(systemClock);
        _storage = storage;
        _systemClock = systemClock;
    }

    public async Task<TGrantedConsent?> FindAsync(HttpContext httpContext, string subjectId, TClient client, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(subjectId);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrEmpty(subjectId))
        {
            return null;
        }

        // if can't remember - nothing will be returned
        if (!client.AllowToRememberConsent)
        {
            return null;
        }

        var consent = await _storage.FindAsync(httpContext, subjectId, client.ClientId, cancellationToken);
        if (consent == null)
        {
            return null;
        }

        var currentDate = _systemClock.UtcNow;
        if (consent.ClientId == client.ClientId
            && consent.SubjectId == subjectId)
        {
            if (!consent.ExpiresAt.HasValue || currentDate < consent.ExpiresAt.Value)
            {
                return consent;
            }

            // consent expires
            await _storage.DeleteAsync(httpContext, subjectId, client.ClientId, cancellationToken);
        }

        return null;
    }

    public async Task UpsertAsync(HttpContext httpContext, string subjectId, TClient client, IReadOnlySet<string> grantedScopes, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(subjectId);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(grantedScopes);
        cancellationToken.ThrowIfCancellationRequested();
        if (client.AllowToRememberConsent)
        {
            if (grantedScopes.Count > 0)
            {
                DateTimeOffset? expiresAt = client.ConsentLifetime.HasValue
                    ? _systemClock.UtcNow.Add(client.ConsentLifetime.Value)
                    : null;
                await _storage.UpsertAsync(httpContext, subjectId, client.ClientId, grantedScopes, expiresAt, cancellationToken);
            }
            else
            {
                await _storage.DeleteAsync(httpContext, subjectId, client.ClientId, cancellationToken);
            }
        }
    }

    public async Task DeleteAsync(HttpContext httpContext, string subjectId, TClient client, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(subjectId);
        ArgumentNullException.ThrowIfNull(client);
        cancellationToken.ThrowIfCancellationRequested();
        await _storage.DeleteAsync(httpContext, subjectId, client.ClientId, cancellationToken);
    }
}
