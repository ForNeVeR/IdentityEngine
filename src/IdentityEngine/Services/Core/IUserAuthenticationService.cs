using IdentityEngine.Services.Core.Models.UserAuthentication;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Core;

public interface IUserAuthenticationService
{
    Task<UserAuthenticationResult> AuthenticateAsync(HttpContext httpContext, CancellationToken cancellationToken = default);
}
