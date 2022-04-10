namespace IdentityEngine.Models.Configuration;

/// <summary>
///     Models an API that IdentityEngine protects.
/// </summary>
/// <typeparam name="TApiSecret">Type of API secret.</typeparam>
public interface IApi<TApiSecret> where TApiSecret : ISecret
{
    /// <summary>
    ///     Indicates if this API is enabled (defaults should be <see langword="true" />).
    /// </summary>
    bool Enabled { get; }

    /// <summary>
    ///     The unique name of the API that will be used with OAuth/OIDC protocols.
    /// </summary>
    string ProtocolName { get; }

    /// <summary>
    ///     Display name of the API.
    /// </summary>
    string? DisplayName { get; }

    /// <summary>
    ///     Description of the API.
    /// </summary>
    string? Description { get; }

    /// <summary>
    ///     The API secret is used for the introspection endpoint. The API can authenticate with introspection using the API protocol name and secret.
    /// </summary>
    IReadOnlySet<TApiSecret> Secrets { get; }

    /// <summary>
    ///     Models the scopes this API allows.
    /// </summary>
    IReadOnlySet<string>? AccessTokenScopes { get; }
}
