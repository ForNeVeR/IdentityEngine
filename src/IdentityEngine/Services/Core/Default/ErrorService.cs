using IdentityEngine.Models.Intermediate;
using IdentityEngine.Storage.Intermediate;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Core.Default;

public sealed class ErrorService<TError> : IErrorService<TError>
    where TError : class, IError
{
    private readonly IErrorStorage<TError> _errorStorage;

    public ErrorService(IErrorStorage<TError> errorStorage)
    {
        ArgumentNullException.ThrowIfNull(errorStorage);
        _errorStorage = errorStorage;
    }

    public async Task<string> CreateAsync(
        HttpContext httpContext,
        string error,
        string? errorDescription,
        string? clientId,
        string? redirectUri,
        string? responseMode,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        var errorId = await _errorStorage.WriteAsync(httpContext,
            error,
            errorDescription,
            clientId,
            redirectUri,
            responseMode,
            cancellationToken);
        return errorId;
    }

    public async Task<TError?> ReadAndDeleteAsync(HttpContext httpContext, string errorId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        return await _errorStorage.ReadAndDeleteAsync(httpContext, errorId, cancellationToken);
    }
}
