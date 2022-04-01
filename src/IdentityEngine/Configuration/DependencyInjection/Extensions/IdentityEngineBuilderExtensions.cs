using IdentityEngine.Configuration.DependencyInjection.Builder;
using IdentityEngine.Configuration.Options;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace IdentityEngine.Configuration.DependencyInjection.Extensions;

public static class IdentityEngineBuilderExtensions
{
    public static IIdentityEngineBuilder AddRequiredPlatformServices(this IIdentityEngineBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddOptions();
        builder.Services.AddSingleton(
            static resolver => resolver.GetRequiredService<IOptions<IdentityEngineOptions>>().Value);
        builder.Services.AddHttpClient();
        return builder;
    }

    public static IIdentityEngineBuilder AddCookieAuthentication(this IIdentityEngineBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddAuthentication(Constants.AuthenticationSchemes.DefaultIdentityEngineCookie)
            .AddCookie(Constants.AuthenticationSchemes.DefaultIdentityEngineCookie)
            .AddCookie(Constants.AuthenticationSchemes.DefaultIdentityEngineExternalCookie);
        return builder;
    }
}
