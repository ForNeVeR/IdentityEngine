using System.Net;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Endpoints.Results.Default;

public sealed class StatusCodeResult : IEndpointHandlerResult
{
    private readonly int _statusCode;

    public StatusCodeResult(HttpStatusCode httpStatusCode)
    {
        _statusCode = (int) httpStatusCode;
    }

    public Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        httpContext.Response.StatusCode = _statusCode;
        return Task.CompletedTask;
    }
}
