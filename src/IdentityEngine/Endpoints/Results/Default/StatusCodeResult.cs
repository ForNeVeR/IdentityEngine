using System.Net;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Endpoints.Results.Default;

public class StatusCodeResult : IEndpointHandlerResult
{
    private readonly int _statusCode;

    public StatusCodeResult(HttpStatusCode httpStatusCode)
    {
        _statusCode = (int) httpStatusCode;
    }

    public virtual Task ExecuteAsync(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        httpContext.RequestAborted.ThrowIfCancellationRequested();
        httpContext.Response.StatusCode = _statusCode;
        return Task.CompletedTask;
    }
}
