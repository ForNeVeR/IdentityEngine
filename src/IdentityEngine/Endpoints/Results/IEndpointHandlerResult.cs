using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Endpoints.Results;

public interface IEndpointHandlerResult
{
    Task ExecuteAsync(HttpContext httpContext);
}
