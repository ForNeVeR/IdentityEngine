using IdentityEngine.Configuration.Options.Endpoints;

namespace IdentityEngine.Configuration.Options;

public class IdentityEngineOptions
{
    public EndpointOptions Endpoints { get; set; } = new();
}
