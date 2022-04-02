using IdentityEngine.Endpoints.Results;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Endpoints;

public interface IEndpointHandler
{
    Task<IEndpointHandlerResult> HandleAsync(HttpContext httpContext, CancellationToken cancellationToken = default);
}
