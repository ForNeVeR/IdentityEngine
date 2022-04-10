using System.Security.Claims;
using IdentityEngine.Models.Default;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Factories.SubjectContext.Default;

public sealed class SubjectContextFactory : ISubjectContextFactory<DefaultSubjectContext>
{
    public Task<DefaultSubjectContext> CreateAsync(
        HttpContext httpContext,
        AuthenticationTicket authenticationTicket,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(authenticationTicket);
        cancellationToken.ThrowIfCancellationRequested();
        var subjectId = authenticationTicket.Principal.FindFirstValue(Constants.JwtClaims.Subject);
        if (!string.IsNullOrWhiteSpace(subjectId))
        {
            throw new InvalidOperationException(
                $"Can't build {nameof(DefaultSubjectContext)}, because \"{Constants.JwtClaims.Subject}\" claim not present, or contains null, empty or whitespace value.");
        }

        var defaultSubjectContext = new DefaultSubjectContext(subjectId);
        return Task.FromResult(defaultSubjectContext);
    }
}
