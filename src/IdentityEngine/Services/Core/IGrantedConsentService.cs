using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Operation;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Core;

public interface IGrantedConsentService<TClient, TClientSecret, TGrantedConsent>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TGrantedConsent : class, IGrantedConsent
{
    Task<TGrantedConsent?> FindAsync(
        HttpContext httpContext,
        string subjectId,
        TClient client,
        CancellationToken cancellationToken = default);

    Task UpsertAsync(
        HttpContext httpContext,
        string subjectId,
        TClient client,
        IReadOnlySet<string> grantedScopes,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        HttpContext httpContext,
        string subjectId,
        TClient client,
        CancellationToken cancellationToken = default);
}
