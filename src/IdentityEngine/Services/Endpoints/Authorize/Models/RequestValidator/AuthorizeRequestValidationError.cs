using System.Diagnostics.CodeAnalysis;
using IdentityEngine.Models;

namespace IdentityEngine.Services.Endpoints.Authorize.Models.RequestValidator;

public class AuthorizeRequestValidationError
{
    public AuthorizeRequestValidationError(ProtocolError protocolError)
    {
        ArgumentNullException.ThrowIfNull(protocolError);
        ProtocolError = protocolError;
        CanRedirect = false;
    }

    public AuthorizeRequestValidationError(
        ProtocolError protocolError,
        string clientId,
        string redirectUri,
        string? state,
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

        if (string.IsNullOrWhiteSpace(responseMode))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(responseMode));
        }

        ProtocolError = protocolError;
        ClientId = clientId;
        RedirectUri = redirectUri;
        State = state;
        ResponseMode = responseMode;
        CanRedirect = protocolError.IsSafe;
    }

    public ProtocolError ProtocolError { get; }
    public string? ClientId { get; }
    public string? RedirectUri { get; }
    public string? State { get; }
    public string? ResponseMode { get; }

    [MemberNotNullWhen(true, nameof(ClientId))]
    [MemberNotNullWhen(true, nameof(RedirectUri))]
    [MemberNotNullWhen(true, nameof(ResponseMode))]
    public bool CanRedirect { get; }
}
