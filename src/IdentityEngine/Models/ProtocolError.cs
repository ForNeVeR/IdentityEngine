namespace IdentityEngine.Models;

public class ProtocolError
{
    public ProtocolError(string error, string? errorDescription)
    {
        if (string.IsNullOrWhiteSpace(error))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(error));
        }

        Error = error;
        if (!string.IsNullOrWhiteSpace(errorDescription))
        {
            ErrorDescription = errorDescription;
        }
    }

    public string Error { get; }

    public string? ErrorDescription { get; }
}
