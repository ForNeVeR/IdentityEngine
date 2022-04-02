using IdentityEngine.Models;
using IdentityEngine.Services.UserAuthentication.Models;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.UserAuthentication;

public interface IUserAuthenticationService<TSubjectId>
    where TSubjectId : ISubjectId
{
    Task<UserAuthenticationResult<TSubjectId>> AuthenticateAsync(HttpContext httpContext);
}
