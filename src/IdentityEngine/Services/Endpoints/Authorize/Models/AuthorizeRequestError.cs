using IdentityEngine.Models;

namespace IdentityEngine.Services.Endpoints.Authorize.Models;

public class AuthorizeRequestError
{
    public AuthorizeRequestError(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        Error = protocolError.Error;
        ErrorDescription = protocolError.ErrorDescription;
    }

    public AuthorizeRequestError(
        ProtocolError protocolError,
        string clientId,
        string redirectUri,
        string? state,
        string responseType,
        string responseMode)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(clientId));
        }

        if (string.IsNullOrWhiteSpace(redirectUri))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(redirectUri));
        }

        if (string.IsNullOrWhiteSpace(responseType))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseType));
        }

        if (string.IsNullOrWhiteSpace(responseMode))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseMode));
        }

        Error = protocolError.Error;
        ErrorDescription = protocolError.ErrorDescription;
        ClientId = clientId;
        RedirectUri = redirectUri;
        State = state;
        ResponseType = responseType;
        ResponseMode = responseMode;
    }

    public string Error { get; }
    public string? ErrorDescription { get; }
    public string? ClientId { get; }
    public string? RedirectUri { get; }
    public string? State { get; }
    public string? ResponseType { get; }
    public string? ResponseMode { get; }
}
