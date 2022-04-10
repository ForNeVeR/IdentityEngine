using IdentityEngine.Factories.Errors;
using IdentityEngine.Models.Infrastructure;
using IdentityEngine.Storage.Infrastructure;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Error.Default;

public sealed class ErrorService<TError> : IErrorService<TError>
    where TError : IError
{
    private readonly IErrorFactory<TError> _errorFactory;
    private readonly IErrorStorage<TError> _errorStorage;

    public ErrorService(
        IErrorFactory<TError> errorFactory,
        IErrorStorage<TError> errorStorage)
    {
        ArgumentNullException.ThrowIfNull(errorFactory);
        ArgumentNullException.ThrowIfNull(errorStorage);
        _errorFactory = errorFactory;
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
        var resultError = await _errorFactory.CreateAsync(
            httpContext,
            error,
            errorDescription,
            clientId,
            redirectUri,
            responseMode,
            cancellationToken);
        var errorId = await _errorStorage.WriteAsync(httpContext, resultError, cancellationToken);
        return errorId;
    }
}
