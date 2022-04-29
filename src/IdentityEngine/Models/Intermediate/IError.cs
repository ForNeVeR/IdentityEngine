namespace IdentityEngine.Models.Intermediate;

public interface IError
{
    string Error { get; set; }
    string? ErrorDescription { get; set; }
    string? ClientId { get; set; }
    string? RedirectUri { get; set; }
    string? ResponseMode { get; set; }
}
