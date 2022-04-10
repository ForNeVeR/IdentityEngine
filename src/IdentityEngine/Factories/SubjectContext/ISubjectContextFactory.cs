using IdentityEngine.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Factories.SubjectContext;

public interface ISubjectContextFactory<TSubjectContext>
    where TSubjectContext : ISubjectContext
{
    Task<TSubjectContext> CreateAsync(
        HttpContext httpContext,
        AuthenticationTicket authenticationTicket,
        CancellationToken cancellationToken = default);
}
