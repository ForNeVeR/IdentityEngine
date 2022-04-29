using IdentityEngine.Models.Intermediate;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Storage.Intermediate;

public interface IErrorStorage<TError>
    where TError : class, IError
{
    Task<string> WriteAsync(
        HttpContext httpContext,
        string error,
        string? errorDescription,
        string? clientId,
        string? redirectUri,
        string? responseMode,
        CancellationToken cancellationToken = default);

    Task<TError?> ReadAndDeleteAsync(
        HttpContext httpContext,
        string errorId,
        CancellationToken cancellationToken = default);
}
