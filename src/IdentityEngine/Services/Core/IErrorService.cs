using IdentityEngine.Models.Intermediate;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Core;

public interface IErrorService<TError>
    where TError : class, IError
{
    Task<string> CreateAsync(
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
