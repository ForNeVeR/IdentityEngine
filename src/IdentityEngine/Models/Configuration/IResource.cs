namespace IdentityEngine.Models.Configuration;

/// <summary>
///     Models an resource (API) that IdentityEngine protects.
/// </summary>
/// <typeparam name="TResourceSecret">Type of resource (API) secret.</typeparam>
public interface IResource<TResourceSecret> where TResourceSecret : class, ISecret
{
    /// <summary>
    ///     Indicates if this resource (API) is enabled (defaults should be <see langword="true" />).
    /// </summary>
    bool Enabled { get; }

    /// <summary>
    ///     The unique name of the resource (API) that will be used with OAuth/OIDC protocols.
    /// </summary>
    string ProtocolName { get; }

    /// <summary>
    ///     Display name of the resource (API).
    /// </summary>
    string? DisplayName { get; }

    /// <summary>
    ///     Description of the resource (API).
    /// </summary>
    string? Description { get; }

    /// <summary>
    ///     The resource (API) secret is used for the introspection endpoint. The resource (API) can authenticate with introspection using the API <see cref="ProtocolName" /> and one of
    ///     it's <see cref="Secrets" />.
    /// </summary>
    IReadOnlySet<TResourceSecret> Secrets { get; }

    /// <summary>
    ///     Models the scopes this resource (API) allows.
    /// </summary>
    IReadOnlySet<string>? AccessTokenScopes { get; }
}
