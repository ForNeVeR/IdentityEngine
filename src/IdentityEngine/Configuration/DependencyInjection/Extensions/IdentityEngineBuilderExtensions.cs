using IdentityEngine.Configuration.DependencyInjection.Builder;
using IdentityEngine.Configuration.Options;
using IdentityEngine.Endpoints.Handlers;
using IdentityEngine.Endpoints.Handlers.Default;
using IdentityEngine.Models;
using IdentityEngine.Services.Factories.SubjectId;
using IdentityEngine.Services.UserAuthentication;
using IdentityEngine.Services.UserAuthentication.Default;
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

    public static IIdentityEngineBuilder AddCoreServices<TSubjectId, TSubjectIdFactory>(this IIdentityEngineBuilder builder)
        where TSubjectId : ISubjectId
        where TSubjectIdFactory : class, ISubjectIdFactory<TSubjectId>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddSingleton<IUserAuthenticationService<TSubjectId>, UserAuthenticationService<TSubjectId>>();
        builder.Services.AddSingleton<ISubjectIdFactory<TSubjectId>, TSubjectIdFactory>();
        return builder;
    }

    public static IIdentityEngineBuilder AddDefaultEndpoints<TSubjectId>(this IIdentityEngineBuilder builder)
        where TSubjectId : ISubjectId
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddSingleton<IAuthorizeEndpointHandler, AuthorizeEndpointHandler<TSubjectId>>();
        return builder;
    }

    public static IIdentityEngineBuilder AddValidators(this IIdentityEngineBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder;
    }
}
