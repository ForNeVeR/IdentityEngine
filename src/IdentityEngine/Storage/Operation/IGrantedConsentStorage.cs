using IdentityEngine.Models.Operation;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Storage.Operation;

public interface IGrantedConsentStorage<TGrantedConsent>
    where TGrantedConsent : class, IGrantedConsent
{
    Task<TGrantedConsent?> FindAsync(
        HttpContext httpContext,
        string subjectId,
        string clientId,
        CancellationToken cancellationToken = default);

    Task<TGrantedConsent?> UpsertAsync(
        HttpContext httpContext,
        string subjectId,
        string clientId,
        IReadOnlySet<string> grantedScopes,
        DateTimeOffset? expiresAt,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        HttpContext httpContext,
        string subjectId,
        string clientId,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        HttpContext httpContext,
        string clientId,
        CancellationToken cancellationToken = default);
}
