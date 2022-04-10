namespace IdentityEngine.Models.Configuration;

/// <summary>
///     Models an access token scope.
/// </summary>
public interface IAccessTokenScope
{
    /// <summary>
    ///     Indicates if this access token scope is enabled (defaults should be <see langword="true" />).
    /// </summary>
    bool Enabled { get; }

    /// <summary>
    ///     The unique name of the access token scope that will be used with OAuth/OIDC protocols.
    /// </summary>
    string ProtocolName { get; }

    /// <summary>
    ///     Display name of the access token scope.
    /// </summary>
    string? DisplayName { get; }

    /// <summary>
    ///     Description of the access token scope.
    /// </summary>
    string? Description { get; }

    /// <summary>
    ///     Specifies whether this scope is shown in the discovery document (defaults should be <see langword="true" />).
    /// </summary>
    bool ShowInDiscoveryDocument { get; }

    /// <summary>
    ///     List of associated user claims that should be included when this access token scope is requested.
    /// </summary>
    IReadOnlySet<string>? UserClaims { get; }

    /// <summary>
    ///     Specifies whether the user can de-select the scope on the consent screen (defaults should be <see langword="false" />).
    /// </summary>
    bool Required { get; }

    /// <summary>
    ///     Specifies whether the consent screen will emphasize this scope. Use this setting for sensitive or important scopes (defaults should be <see langword="false" />).
    /// </summary>
    bool Emphasize { get; }
}
