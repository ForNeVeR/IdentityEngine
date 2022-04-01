using Microsoft.Extensions.DependencyInjection;

namespace IdentityEngine.Configuration.DependencyInjection.Builder;

public interface IIdentityEngineBuilder
{
    IServiceCollection Services { get; }
}
