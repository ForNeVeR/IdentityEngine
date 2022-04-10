using IdentityEngine.Models;
using Microsoft.AspNetCore.Authentication;

namespace IdentityEngine.Services.UserAuthentication.Models;

public class AuthenticatedUserSession<TSubjectContext>
    where TSubjectContext : ISubjectContext
{
    public AuthenticatedUserSession(TSubjectContext subjectContext, AuthenticationTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        ArgumentNullException.ThrowIfNull(subjectContext);
        if (ticket.Principal.Identity?.IsAuthenticated != true)
        {
            throw new InvalidOperationException("ClaimsPrincipal in authentication ticket is missing Identity or not authenticated.");
        }

        SubjectContext = subjectContext;
        Ticket = ticket;
    }

    public TSubjectContext SubjectContext { get; }

    public AuthenticationTicket Ticket { get; }
}
