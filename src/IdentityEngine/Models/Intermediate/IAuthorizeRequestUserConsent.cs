using System.Diagnostics.CodeAnalysis;

namespace IdentityEngine.Models.Intermediate;

public interface IAuthorizeRequestUserConsent
{
    ProtocolError? Error { get; }

    IReadOnlySet<string>? Scopes { get; }

    [MemberNotNullWhen(true, nameof(Scopes))]
    [MemberNotNullWhen(false, nameof(Error))]
    bool Granted { get; }

    bool Remember { get; }
}
