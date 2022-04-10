using IdentityEngine.Models.Configuration.Enums;

namespace IdentityEngine.Models.Configuration;

/// <summary>
///     Models an OAuth 2.1 / OpenID Connect 1.0 client.
/// </summary>
/// <typeparam name="TClientSecret"></typeparam>
public interface IClient<TClientSecret> where TClientSecret : ISecret
{
    /// <summary>
    ///     Unique client identifier.
    /// </summary>
    string ClientId { get; }

    /// <summary>
    ///     Specifies if client is enabled (defaults should be <see langword="true" />).
    /// </summary>
    bool Enabled { get; }

    /// <summary>
    ///     Client type.
    /// </summary>
    ClientType Type { get; }

    /// <summary>
    ///     Specifies allowed URIs to return tokens or authorization codes to.
    /// </summary>
    IReadOnlySet<string>? RedirectUris { get; }

    /// <summary>
    ///     Specifies the "id_token" that the client is allowed to request.
    /// </summary>
    IReadOnlySet<string>? AllowedIdTokenScopes { get; }

    /// <summary>
    ///     Specifies the "access_token" that the client is allowed to request.
    /// </summary>
    IReadOnlySet<string>? AllowedAccessTokenScopes { get; }

    /// <summary>
    ///     Specifies the allowed "code_challenge_method" values that the client is allowed to request via authorization code flow.
    /// </summary>
    IReadOnlySet<string> CodeChallengeMethods { get; }

    /// <summary>
    ///     A value indicating whether allow refresh tokens (offline access, defaults should be <see langword="false" /> and only enabled if you need it).
    /// </summary>
    bool AllowRefreshTokens { get; }

    /// <summary>
    ///     The maximum duration since the last time the user authenticated.
    /// </summary>
    TimeSpan? UserSsoLifetime { get; }

    /// <summary>
    ///     Client secrets - only relevant for flows that require a secret.
    /// </summary>
    IReadOnlySet<TClientSecret>? Secrets { get; }

    /// <summary>
    ///     A value indicating whether the local login is allowed for this client (defaults should be <see langword="true" />).
    /// </summary>
    bool EnableLocalLogin { get; }

    /// <summary>
    ///     Specifies which external identity providers (IdPs) can be used with this client (if list is null or empty then all IdPs are allowed). Defaults to <see langword="null" />.
    /// </summary>
    IReadOnlySet<string>? IdentityProviderRestrictions { get; }

    /// <summary>
    ///     Specifies whether a consent screen is required (defaults should be <see langword="false" />).
    /// </summary>
    bool RequireConsent { get; }

    /// <summary>
    ///     Specifies whether user can choose to store consent decisions (defaults should be <see langword="true" />).
    /// </summary>
    bool AllowRememberConsent { get; }

    /// <summary>
    ///     Lifetime of a user consent. Defaults to null (defaults should be <see langword="null" />, that means no expiration).
    /// </summary>
    TimeSpan? ConsentLifetime { get; }

    /// <summary>
    ///     Specifies the allowed grant types.
    /// </summary>
    IReadOnlySet<string> AllowedGrantTypes { get; }

    /// <summary>
    ///     Lifetime of authorization code (defaults should be 300 seconds / 5 minutes).
    /// </summary>
    TimeSpan AuthorizationCodeLifetime { get; }
}
