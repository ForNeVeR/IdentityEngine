namespace IdentityEngine.Models;

public class ProtocolError
{
    public ProtocolError(
        string error,
        string? description)
    {
        if (string.IsNullOrWhiteSpace(error))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(error));
        }

        Error = error;
        Description = description;
        IsSafe = IsSafeError(error);
    }

    public string Error { get; }
    public string? Description { get; }
    public bool IsSafe { get; }

    private static bool IsSafeError(string error)
    {
        return error is Constants.Responses.Errors.Values.AccessDenied
            or Constants.Responses.Errors.Values.TemporarilyUnavailable
            or Constants.Responses.Errors.Values.OpenIdConnect.AccountSelectionRequired
            or Constants.Responses.Errors.Values.OpenIdConnect.LoginRequired
            or Constants.Responses.Errors.Values.OpenIdConnect.ConsentRequired
            or Constants.Responses.Errors.Values.OpenIdConnect.InteractionRequired;
    }
}
