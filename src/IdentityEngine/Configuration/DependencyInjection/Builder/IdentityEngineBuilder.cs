using IdentityEngine.Configuration.Options;
using IdentityEngine.Endpoints.Handlers;
using IdentityEngine.Endpoints.Handlers.Default;
using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Intermediate;
using IdentityEngine.Models.Operation;
using IdentityEngine.Services.Core;
using IdentityEngine.Services.Core.Default;
using IdentityEngine.Services.Endpoints.Authorize;
using IdentityEngine.Services.Endpoints.Authorize.Default;
using IdentityEngine.Storage.Configuration;
using IdentityEngine.Storage.Intermediate;
using IdentityEngine.Storage.Operation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace IdentityEngine.Configuration.DependencyInjection.Builder;

public class IdentityEngineBuilder<
        TError,
        TClient,
        TClientSecret,
        TIdTokenScope,
        TAccessTokenScope,
        TResource,
        TResourceSecret,
        TAuthorizeRequestUserConsent,
        TGrantedConsent,
        TAuthorizationCode,
        TAuthorizeRequestParameters>
    : IIdentityEngineBuilder<
        TError,
        TClient,
        TClientSecret,
        TIdTokenScope,
        TAccessTokenScope,
        TResource,
        TResourceSecret,
        TAuthorizeRequestUserConsent,
        TGrantedConsent,
        TAuthorizationCode,
        TAuthorizeRequestParameters>
    where TError : class, IError
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
    where TAuthorizeRequestUserConsent : class, IAuthorizeRequestUserConsent
    where TGrantedConsent : class, IGrantedConsent
    where TAuthorizationCode : class, IAuthorizationCode
    where TAuthorizeRequestParameters : class, IAuthorizeRequestParameters
{
    public IdentityEngineBuilder(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        Services = services;
    }

    public IServiceCollection Services { get; }

    public IIdentityEngineBuilder<
        TError,
        TClient,
        TClientSecret,
        TIdTokenScope,
        TAccessTokenScope,
        TResource,
        TResourceSecret,
        TAuthorizeRequestUserConsent,
        TGrantedConsent,
        TAuthorizationCode,
        TAuthorizeRequestParameters> AddRequiredPlatformServices()
    {
        Services.AddOptions();
        Services.TryAddSingleton(
            static resolver => resolver.GetRequiredService<IOptions<IdentityEngineOptions>>().Value);
        Services.AddHttpClient();
        return this;
    }

    public IIdentityEngineBuilder<
        TError,
        TClient,
        TClientSecret,
        TIdTokenScope,
        TAccessTokenScope,
        TResource,
        TResourceSecret,
        TAuthorizeRequestUserConsent,
        TGrantedConsent,
        TAuthorizationCode,
        TAuthorizeRequestParameters> AddCookieAuthentication()
    {
        Services.AddAuthentication(Constants.AuthenticationSchemes.DefaultIdentityEngineCookie)
            .AddCookie(Constants.AuthenticationSchemes.DefaultIdentityEngineCookie)
            .AddCookie(Constants.AuthenticationSchemes.DefaultIdentityEngineExternalCookie);
        return this;
    }


    public IIdentityEngineBuilder<
        TError,
        TClient,
        TClientSecret,
        TIdTokenScope,
        TAccessTokenScope,
        TResource,
        TResourceSecret,
        TAuthorizeRequestUserConsent,
        TGrantedConsent,
        TAuthorizationCode,
        TAuthorizeRequestParameters> AddCoreServices()
    {
        Services.TryAddSingleton<
            IErrorService<TError>,
            ErrorService<TError>>();
        Services.TryAddSingleton<
            IGrantedConsentService<TClient, TClientSecret, TGrantedConsent>,
            GrantedConsentService<TClient, TClientSecret, TGrantedConsent>>();
        Services.TryAddSingleton<
            IOriginUrls,
            OriginUrls>();
        Services.TryAddSingleton<
            IResourceValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>,
            ResourceValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>>();
        Services.TryAddSingleton<
            IUserAuthenticationService,
            UserAuthenticationService>();
        return this;
    }

    public IIdentityEngineBuilder<
        TError,
        TClient,
        TClientSecret,
        TIdTokenScope,
        TAccessTokenScope,
        TResource,
        TResourceSecret,
        TAuthorizeRequestUserConsent,
        TGrantedConsent,
        TAuthorizationCode,
        TAuthorizeRequestParameters> AddDefaultEndpointHandlers()
    {
        // Authorize
        Services
            .TryAddSingleton<
                IAuthorizeEndpointHandler,
                AuthorizeEndpointHandler<TError, TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret, TAuthorizeRequestUserConsent>>();
        Services
            .TryAddSingleton<
                IAuthorizationCodeService<TAuthorizationCode>,
                AuthorizationCodeService<TAuthorizationCode>>();
        Services
            .TryAddSingleton<
                IAuthorizeRequestInteractionHandler<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret, TAuthorizeRequestUserConsent>,
                AuthorizeRequestInteractionHandler<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret, TAuthorizeRequestUserConsent, TGrantedConsent>>();
        Services
            .TryAddSingleton<
                IAuthorizeRequestParametersService<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>,
                AuthorizeRequestParametersService<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret, TAuthorizeRequestParameters>>();
        Services
            .TryAddSingleton<
                IAuthorizeRequestResponseGenerator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>,
                AuthorizeRequestResponseGenerator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret, TAuthorizationCode>>();
        Services
            .TryAddSingleton<
                IAuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>,
                AuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>>();
        return this;
    }

    public IIdentityEngineBuilder<
            TError,
            TClient,
            TClientSecret,
            TIdTokenScope,
            TAccessTokenScope,
            TResource,
            TResourceSecret,
            TAuthorizeRequestUserConsent,
            TGrantedConsent,
            TAuthorizationCode,
            TAuthorizeRequestParameters>
        RegisterIntermediateStorages<
            TAuthorizationCodeStorage,
            TAuthorizeRequestParametersStorage,
            TErrorStorage>()
        where TAuthorizationCodeStorage : class, IAuthorizationCodeStorage<TAuthorizationCode>
        where TAuthorizeRequestParametersStorage : class, IAuthorizeRequestParametersStorage<TAuthorizeRequestParameters>
        where TErrorStorage : class, IErrorStorage<TError>
    {
        Services.TryAddSingleton<IAuthorizationCodeStorage<TAuthorizationCode>, TAuthorizationCodeStorage>();
        Services.TryAddSingleton<IAuthorizeRequestParametersStorage<TAuthorizeRequestParameters>, TAuthorizeRequestParametersStorage>();
        Services.TryAddSingleton<IErrorStorage<TError>, TErrorStorage>();
        return this;
    }

    public IIdentityEngineBuilder<
            TError,
            TClient,
            TClientSecret,
            TIdTokenScope,
            TAccessTokenScope,
            TResource,
            TResourceSecret,
            TAuthorizeRequestUserConsent,
            TGrantedConsent,
            TAuthorizationCode,
            TAuthorizeRequestParameters>
        RegisterConfigurationStorages<
            TClientStorage,
            TScopeStorage>()
        where TClientStorage : class, IClientStorage<TClient, TClientSecret>
        where TScopeStorage : class, IScopeStorage<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    {
        Services.TryAddSingleton<IClientStorage<TClient, TClientSecret>, TClientStorage>();
        Services.TryAddSingleton<IScopeStorage<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>, TScopeStorage>();
        return this;
    }

    public IIdentityEngineBuilder<
            TError,
            TClient,
            TClientSecret,
            TIdTokenScope,
            TAccessTokenScope,
            TResource,
            TResourceSecret,
            TAuthorizeRequestUserConsent,
            TGrantedConsent,
            TAuthorizationCode,
            TAuthorizeRequestParameters>
        RegisterOperationStorages<TGrantedConsentStorage>()
        where TGrantedConsentStorage : class, IGrantedConsentStorage<TGrantedConsent>
    {
        Services.TryAddSingleton<IGrantedConsentStorage<TGrantedConsent>, TGrantedConsentStorage>();
        return this;
    }

    public IIdentityEngineBuilder<
            TError,
            TClient,
            TClientSecret,
            TIdTokenScope,
            TAccessTokenScope,
            TResource,
            TResourceSecret,
            TAuthorizeRequestUserConsent,
            TGrantedConsent,
            TAuthorizationCode,
            TAuthorizeRequestParameters>
        RegisterUserProfile<TUserProfileService>()
        where TUserProfileService : class, IUserProfileService
    {
        Services.TryAddSingleton<IUserProfileService, TUserProfileService>();
        return this;
    }

    public IIdentityEngineBuilder<
            TError,
            TClient,
            TClientSecret,
            TIdTokenScope,
            TAccessTokenScope,
            TResource,
            TResourceSecret,
            TAuthorizeRequestUserConsent,
            TGrantedConsent,
            TAuthorizationCode,
            TAuthorizeRequestParameters>
        AddUserProfile<TUserProfileService>(Func<IServiceProvider, TUserProfileService> resolver)
        where TUserProfileService : class, IUserProfileService
    {
        ArgumentNullException.ThrowIfNull(resolver);
        Services.TryAddSingleton<IUserProfileService>(resolver);
        return this;
    }
}
