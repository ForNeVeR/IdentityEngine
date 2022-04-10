using IdentityEngine.Models.Configuration;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Storage.Configuration;

public interface IClientStorage<TClient, TClientSecret>
    where TClient : IClient<TClientSecret>
    where TClientSecret : ISecret
{
    Task<TClient?> FindAsync(
        HttpContext httpContext,
        string clientId,
        CancellationToken cancellationToken = default);
}
