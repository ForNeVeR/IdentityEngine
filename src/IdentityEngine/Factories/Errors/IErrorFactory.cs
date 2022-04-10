using IdentityEngine.Models.Infrastructure;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Factories.Errors;

public interface IErrorFactory<TError>
    where TError : IError
{
    Task<TError> CreateAsync(
        HttpContext httpContext,
        string error,
        string? errorDescription,
        string? clientId,
        string? redirectUri,
        string? responseMode,
        CancellationToken cancellationToken = default);
}
