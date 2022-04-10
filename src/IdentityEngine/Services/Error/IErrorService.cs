using IdentityEngine.Models.Infrastructure;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Error;

public interface IErrorService<TError>
    where TError : IError
{
    Task<string> CreateAsync(
        HttpContext httpContext,
        string error,
        string? errorDescription,
        string? clientId,
        string? redirectUri,
        string? responseMode,
        CancellationToken cancellationToken = default);
}
