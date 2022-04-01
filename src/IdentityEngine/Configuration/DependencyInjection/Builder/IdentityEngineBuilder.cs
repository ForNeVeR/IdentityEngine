using Microsoft.Extensions.DependencyInjection;

namespace IdentityEngine.Configuration.DependencyInjection.Builder;

public class IdentityEngineBuilder : IIdentityEngineBuilder
{
    public IdentityEngineBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }
}
