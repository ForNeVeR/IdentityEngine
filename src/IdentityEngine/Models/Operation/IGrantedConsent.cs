namespace IdentityEngine.Models.Operation;

public interface IGrantedConsent
{
    string SubjectId { get; }

    string ClientId { get; }

    IReadOnlySet<string> GrantedScopes { get; }

    DateTimeOffset CreatedAt { get; }

    DateTimeOffset? ExpiresAt { get; }
}
