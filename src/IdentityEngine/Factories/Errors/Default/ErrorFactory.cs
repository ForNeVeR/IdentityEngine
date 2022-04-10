using IdentityEngine.Models.Default.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Factories.Errors.Default;

public sealed class ErrorFactory : IErrorFactory<DefaultError>
{
    private readonly ISystemClock _clock;

    public ErrorFactory(ISystemClock clock)
    {
        ArgumentNullException.ThrowIfNull(clock);
        _clock = clock;
    }

    public Task<DefaultError> CreateAsync(
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
        var currentDate = _clock.UtcNow;
        var resultError = new DefaultError(
            httpContext.TraceIdentifier,
            error,
            errorDescription,
            clientId,
            redirectUri,
            responseMode,
            currentDate);
        return Task.FromResult(resultError);
    }
}
