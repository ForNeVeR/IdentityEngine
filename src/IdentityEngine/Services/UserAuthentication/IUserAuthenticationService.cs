using IdentityEngine.Models;
using IdentityEngine.Services.UserAuthentication.Models;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.UserAuthentication;

public interface IUserAuthenticationService<TSubjectContext>
    where TSubjectContext : ISubjectContext
{
    Task<UserAuthenticationResult<TSubjectContext>> AuthenticateAsync(HttpContext httpContext, CancellationToken cancellationToken = default);
}
