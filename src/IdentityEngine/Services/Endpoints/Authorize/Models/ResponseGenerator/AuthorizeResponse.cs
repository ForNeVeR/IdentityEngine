namespace IdentityEngine.Services.Endpoints.Authorize.Models.ResponseGenerator;

public class AuthorizeResponse
{
    public AuthorizeResponse(string code, string? state)
    {
        Code = code;
        State = state;
    }

    public string Code { get; }

    public string? State { get; }
}
