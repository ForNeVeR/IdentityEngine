using IdentityEngine.Configuration.Options.Endpoints;

namespace IdentityEngine.Configuration.Options;

public class IdentityEngineOptions
{
    public EndpointOptions Endpoints { get; set; } = new();

    public AuthenticationOptions Authentication { get; set; } = new();

    public UserInteractionOptions UserInteraction { get; set; } = new();

    public InputLengthRestrictionsOptions InputLengthRestrictions { get; set; } = new();
}
