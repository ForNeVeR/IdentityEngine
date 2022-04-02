using IdentityEngine.Models;
using Microsoft.AspNetCore.Authentication;

namespace IdentityEngine.Services.UserAuthentication.Models;

public class AuthenticatedUserSession<TSubjectId>
    where TSubjectId : ISubjectId
{
    public AuthenticatedUserSession(TSubjectId subjectId, AuthenticationTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        ArgumentNullException.ThrowIfNull(subjectId);
        if (ticket.Principal.Identity?.IsAuthenticated != true)
        {
            throw new InvalidOperationException("ClaimsPrincipal in authentication ticket is missing Identity or not authenticated.");
        }

        SubjectId = subjectId;
        Ticket = ticket;
    }

    public TSubjectId SubjectId { get; }

    public AuthenticationTicket Ticket { get; }
}
