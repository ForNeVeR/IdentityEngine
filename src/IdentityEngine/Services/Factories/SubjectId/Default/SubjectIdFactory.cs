using System.Security.Claims;
using IdentityEngine.Models.Default;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Factories.SubjectId.Default;

public class SubjectIdFactory : ISubjectIdFactory<DefaultSubjectId>
{
    public virtual Task<DefaultSubjectId> CreateAsync(HttpContext httpContext, AuthenticationTicket authenticationTicket)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(authenticationTicket);
        var subjectId = authenticationTicket.Principal.FindFirstValue(Constants.JwtClaims.Subject);
        if (!string.IsNullOrWhiteSpace(subjectId))
        {
            throw new InvalidOperationException(
                $"Can't build {nameof(DefaultSubjectId)}, because \"{Constants.JwtClaims.Subject}\" claim not present, or contains null, empty or whitespace value.");
        }

        var defaultSubjectId = new DefaultSubjectId(subjectId);
        return Task.FromResult(defaultSubjectId);
    }
}
