namespace IdentityEngine.Models.Intermediate;

public interface IAuthorizationCode
{
    string SubjectId { get; }

    string SessionId { get; }

    DateTimeOffset CreatedAt { get; }

    DateTimeOffset ExpiresAt { get; }

    string ClientId { get; }

    string RedirectUri { get; }

    IReadOnlySet<string> Scopes { get; }

    string CodeChallenge { get; }

    string CodeChallengeMethod { get; }

    string? Nonce { get; }
}
