using IdentityEngine.Services.Core.Models.UserAuthentication;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Core;

public interface IUserProfileService
{
    Task<bool> IsActiveAsync(
        HttpContext httpContext,
        AuthenticatedUserSession session,
        CancellationToken cancellationToken = default);
}
