using IdentityEngine.Models.Infrastructure;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Storage.Infrastructure;

public interface IErrorStorage<TError>
    where TError : IError
{
    Task<string> WriteAsync(HttpContext httpContext, TError error, CancellationToken cancellationToken = default);
}
