namespace IdentityEngine.Models.Intermediate;

public interface IAuthorizeRequestParameters
{
    DateTimeOffset RequestDate { get; }

    string ClientId { get; }

    string RedirectUri { get; }

    IReadOnlySet<string> Scope { get; }

    string CodeChallenge { get; }

    string CodeChallengeMethod { get; }

    string ResponseType { get; }

    string? State { get; }

    string ResponseMode { get; }

    string? Nonce { get; }

    string? Display { get; }

    IReadOnlySet<string>? Prompt { get; }

    long? MaxAge { get; }

    string? UiLocales { get; }

    string? LoginHint { get; }

    string[]? AcrValues { get; }
}
