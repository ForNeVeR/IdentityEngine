namespace IdentityEngine.Services.Core.Models.ResourceValidator;

public class MisconfiguredResources
{
    public MisconfiguredResources(
        IReadOnlySet<string>? idTokenScopes,
        IReadOnlySet<string>? accessTokenScopes,
        IReadOnlySet<string>? overlappedScopes,
        IReadOnlySet<string>? resources)
    {
        if (idTokenScopes?.Count > 0)
        {
            IdTokenScopes = idTokenScopes;
        }

        if (accessTokenScopes?.Count > 0)
        {
            AccessTokenScopes = accessTokenScopes;
        }

        if (overlappedScopes?.Count > 0)
        {
            OverlappedScopes = overlappedScopes;
        }

        if (resources?.Count > 0)
        {
            Resources = resources;
        }
    }

    public IReadOnlySet<string>? IdTokenScopes { get; }
    public IReadOnlySet<string>? AccessTokenScopes { get; }
    public IReadOnlySet<string>? OverlappedScopes { get; }
    public IReadOnlySet<string>? Resources { get; }
}
