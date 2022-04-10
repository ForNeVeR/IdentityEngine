namespace IdentityEngine.Models.Infrastructure;

public interface IError
{
    string RequestId { get; }
    string Error { get; }
    string? ErrorDescription { get; }
    string? ClientId { get; }
    string? RedirectUri { get; }
    string? ResponseMode { get; }
    DateTimeOffset CreatedAt { get; }
}
