using IdentityEngine.Models.Infrastructure;

namespace IdentityEngine.Models.Default.Infrastructure;

public class DefaultError : IError
{
    public DefaultError(
        string requestId,
        string error,
        string? errorDescription,
        string? clientId,
        string? redirectUri,
        string? responseMode,
        DateTimeOffset createdAt)
    {
        if (string.IsNullOrWhiteSpace(requestId))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(requestId));
        }

        if (string.IsNullOrWhiteSpace(error))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(error));
        }

        RequestId = requestId;
        Error = error;
        ErrorDescription = errorDescription;
        ClientId = clientId;
        RedirectUri = redirectUri;
        ResponseMode = responseMode;
        CreatedAt = createdAt;
    }

    public string RequestId { get; }
    public string Error { get; }
    public string? ErrorDescription { get; }
    public string? ClientId { get; }
    public string? RedirectUri { get; }
    public string? ResponseMode { get; }
    public DateTimeOffset CreatedAt { get; }
}
