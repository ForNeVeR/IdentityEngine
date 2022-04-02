using System.Diagnostics.CodeAnalysis;
using IdentityEngine.Models;

namespace IdentityEngine.Services.UserAuthentication.Models;

public class UserAuthenticationResult<TSubjectId>
    where TSubjectId : ISubjectId
{
    public UserAuthenticationResult(AuthenticatedUserSession<TSubjectId> session)
    {
        ArgumentNullException.ThrowIfNull(session);
        IsAuthenticated = true;
        Session = session;
        HasError = false;
        ProtocolError = null;
    }

    public UserAuthenticationResult(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        IsAuthenticated = false;
        Session = null;
        HasError = true;
        ProtocolError = protocolError;
    }

    public UserAuthenticationResult()
    {
        IsAuthenticated = false;
        Session = null;
        HasError = false;
        ProtocolError = null;
    }

    [MemberNotNullWhen(true, nameof(Session))]
    public bool IsAuthenticated { get; }

    public AuthenticatedUserSession<TSubjectId>? Session { get; }

    [MemberNotNullWhen(true, nameof(ProtocolError))]
    public bool HasError { get; }

    public ProtocolError? ProtocolError { get; }
}
