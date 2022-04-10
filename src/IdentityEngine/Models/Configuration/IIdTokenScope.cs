namespace IdentityEngine.Models.Configuration;

/// <summary>
///     Models a user identity scope.
/// </summary>
public interface IIdTokenScope
{
    /// <summary>
    ///     Indicates if this identity scope is enabled (defaults should be <see langword="true" />).
    /// </summary>
    bool Enabled { get; }

    /// <summary>
    ///     The unique name of the identity scope that will be used with OIDC protocol.
    /// </summary>
    string ProtocolName { get; }

    /// <summary>
    ///     Display name of the identity scope.
    /// </summary>
    string? DisplayName { get; }

    /// <summary>
    ///     Description of the identity scope.
    /// </summary>
    string? Description { get; }

    /// <summary>
    ///     Specifies whether this scope is shown in the discovery document (defaults should be <see langword="true" />).
    /// </summary>
    bool ShowInDiscoveryDocument { get; }

    /// <summary>
    ///     List of associated user claims that should be included when this id token scope is requested.
    /// </summary>
    IReadOnlySet<string> UserClaimTypes { get; }

    /// <summary>
    ///     Specifies whether the user can de-select the scope on the consent screen (defaults should be <see langword="false" />).
    /// </summary>
    bool Required { get; }
}
