using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

namespace IdentityEngine.Services.Core.Models.UserAuthentication;

public class AuthenticatedUserSession
{
    public AuthenticatedUserSession(AuthenticationTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        if (ticket.Principal.Identity?.IsAuthenticated != true)
        {
            throw new InvalidOperationException("ClaimsPrincipal in authentication ticket is missing Identity or not authenticated");
        }

        Ticket = ticket;
        SubjectId = GetSubjectId(ticket.Principal);
        SessionId = GetSessionId(ticket.Principal);
        IdentityProvider = GetIdentityProvider(ticket.Principal);
        AuthenticationTime = GetAuthenticationTime(ticket.Principal);
    }

    /// <summary>
    ///     Ticket of authenticated user.
    /// </summary>
    public AuthenticationTicket Ticket { get; }

    /// <summary>
    ///     Subject context of current user.
    /// </summary>
    public string SubjectId { get; }

    /// <summary>
    ///     Unique session identifier.
    /// </summary>
    public string SessionId { get; }

    /// <summary>
    ///     Identity provider that used for authentication.
    /// </summary>
    public string IdentityProvider { get; }

    /// <summary>
    ///     Authentication date and time.
    /// </summary>
    public DateTimeOffset AuthenticationTime { get; }

    private static string GetSubjectId(ClaimsPrincipal principal)
    {
        var claim = principal.FindFirst(Constants.ClaimTypes.SubjectId);
        return claim switch
        {
            null => throw new InvalidOperationException($"{Constants.ClaimTypes.SubjectId} claim is missing"),
            _ => !string.IsNullOrWhiteSpace(claim.Value)
                ? claim.Value
                : throw new InvalidOperationException($"{Constants.ClaimTypes.SubjectId} claim contains null or whitespace string")
        };
    }

    private static DateTimeOffset GetAuthenticationTime(ClaimsPrincipal principal)
    {
        var claim = principal.FindFirst(Constants.ClaimTypes.AuthenticationTime);
        if (claim == null)
        {
            throw new InvalidOperationException($"{Constants.ClaimTypes.AuthenticationTime} is missing");
        }

        var epochTime = long.Parse(claim.Value, NumberStyles.Integer, CultureInfo.InvariantCulture);
        return DateTimeOffset.FromUnixTimeSeconds(epochTime);
    }

    private static string GetIdentityProvider(ClaimsPrincipal principal)
    {
        var claim = principal.FindFirst(Constants.ClaimTypes.IdentityProvider);
        return claim switch
        {
            null => throw new InvalidOperationException($"{Constants.ClaimTypes.IdentityProvider} claim is missing"),
            _ => !string.IsNullOrWhiteSpace(claim.Value)
                ? claim.Value
                : throw new InvalidOperationException($"{Constants.ClaimTypes.IdentityProvider} claim contains null or whitespace string")
        };
    }

    private static string GetSessionId(ClaimsPrincipal principal)
    {
        var claim = principal.FindFirst(Constants.ClaimTypes.SessionId);
        return claim switch
        {
            null => throw new InvalidOperationException($"{Constants.ClaimTypes.SessionId} claim is missing"),
            _ => !string.IsNullOrWhiteSpace(claim.Value)
                ? claim.Value
                : throw new InvalidOperationException($"{Constants.ClaimTypes.SessionId} claim contains null or whitespace string")
        };
    }
}
