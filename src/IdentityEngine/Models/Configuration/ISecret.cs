namespace IdentityEngine.Models.Configuration;

/// <summary>
///     Models a secret with identifier and expiration.
/// </summary>
public interface ISecret
{
    /// <summary>
    ///     The type of the secret.
    /// </summary>
    string Type { get; }

    /// <summary>
    ///     The value.
    /// </summary>
    byte[]? Value { get; }

    /// <summary>
    ///     The description.
    /// </summary>
    string? Description { get; }

    /// <summary>
    ///     The creation date.
    /// </summary>
    DateTimeOffset? CreatedAt { get; }

    /// <summary>
    ///     The expiration date.
    /// </summary>
    DateTimeOffset? ExpiresAt { get; }
}
