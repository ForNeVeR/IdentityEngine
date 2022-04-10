using IdentityEngine.Configuration.DependencyInjection.Builder;
using IdentityEngine.Configuration.Options;
using IdentityEngine.Endpoints.Handlers;
using IdentityEngine.Endpoints.Handlers.Default;
using IdentityEngine.Factories.Errors;
using IdentityEngine.Factories.SubjectContext;
using IdentityEngine.Models;
using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Infrastructure;
using IdentityEngine.Services.Endpoints.Authorize;
using IdentityEngine.Services.Endpoints.Authorize.Default;
using IdentityEngine.Services.Error;
using IdentityEngine.Services.Error.Default;
using IdentityEngine.Services.Scope;
using IdentityEngine.Services.UserAuthentication;
using IdentityEngine.Services.UserAuthentication.Default;
using IdentityEngine.Storage.Configuration;
using IdentityEngine.Storage.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace IdentityEngine.Configuration.DependencyInjection.Extensions;

public static class IdentityEngineBuilderExtensions
{
    public static IIdentityEngineBuilder AddRequiredPlatformServices(this IIdentityEngineBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.AddOptions();
        builder.Services.TryAddSingleton(
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

    public static IIdentityEngineBuilder AddCoreServices<
        TSubjectContext,
        TError,
        TSubjectContextFactory,
        TErrorFactory>(
        this IIdentityEngineBuilder builder)
        where TSubjectContext : ISubjectContext
        where TError : IError
        where TSubjectContextFactory : class, ISubjectContextFactory<TSubjectContext>
        where TErrorFactory : class, IErrorFactory<TError>
    {
        ArgumentNullException.ThrowIfNull(builder);
        // Factories
        builder.Services.TryAddSingleton<ISubjectContextFactory<TSubjectContext>, TSubjectContextFactory>();
        builder.Services.TryAddSingleton<IErrorFactory<TError>, TErrorFactory>();
        // Services
        builder.Services.TryAddSingleton<IUserAuthenticationService<TSubjectContext>, UserAuthenticationService<TSubjectContext>>();
        builder.Services.TryAddSingleton<IErrorService<TError>, ErrorService<TError>>();
        return builder;
    }

    public static IIdentityEngineBuilder AddDefaultEndpoints<TSubjectContext, TError, TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>(
        this IIdentityEngineBuilder builder)
        where TSubjectContext : ISubjectContext
        where TError : IError
        where TClient : IClient<TClientSecret>
        where TClientSecret : ISecret
        where TIdTokenScope : IIdTokenScope
        where TAccessTokenScope : IAccessTokenScope
        where TApi : IApi<TApiSecret>
        where TApiSecret : ISecret
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services
            .AddSingleton<
                IAuthorizeEndpointHandler,
                AuthorizeEndpointHandler<TSubjectContext, TError, TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>>();
        return builder;
    }

    public static IIdentityEngineBuilder AddValidators<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>(
        this IIdentityEngineBuilder builder)
        where TClient : IClient<TClientSecret>
        where TClientSecret : ISecret
        where TIdTokenScope : IIdTokenScope
        where TAccessTokenScope : IAccessTokenScope
        where TApi : IApi<TApiSecret>
        where TApiSecret : ISecret
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<
            IAuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>,
            AuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>>();
        builder.Services.TryAddSingleton<
            IScopeValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>,
            IScopeValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>>();
        return builder;
    }

    public static IIdentityEngineBuilder AddStorages<TError, TErrorStorage, TClient, TClientSecret, TClientStorage>(
        this IIdentityEngineBuilder builder)
        where TError : IError
        where TErrorStorage : class, IErrorStorage<TError>
        where TClient : IClient<TClientSecret>
        where TClientSecret : ISecret
        where TClientStorage : class, IClientStorage<TClient, TClientSecret>
    {
        ArgumentNullException.ThrowIfNull(builder);
        builder.Services.TryAddSingleton<IErrorStorage<TError>, TErrorStorage>();
        builder.Services.TryAddSingleton<IClientStorage<TClient, TClientSecret>, TClientStorage>();
        return builder;
    }
}
