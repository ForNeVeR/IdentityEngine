using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Intermediate;
using IdentityEngine.Models.Operation;
using IdentityEngine.Services.Core;
using IdentityEngine.Storage.Configuration;
using IdentityEngine.Storage.Intermediate;
using IdentityEngine.Storage.Operation;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityEngine.Configuration.DependencyInjection.Builder;

public interface IIdentityEngineBuilder<
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
    IServiceCollection Services { get; }

    IIdentityEngineBuilder<
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
        TAuthorizeRequestParameters> AddRequiredPlatformServices();

    IIdentityEngineBuilder<
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
        TAuthorizeRequestParameters> AddCookieAuthentication();

    IIdentityEngineBuilder<
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
        TAuthorizeRequestParameters> AddCoreServices();

    IIdentityEngineBuilder<
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
        TAuthorizeRequestParameters> AddDefaultEndpointHandlers();

    IIdentityEngineBuilder<
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
        where TErrorStorage : class, IErrorStorage<TError>;

    IIdentityEngineBuilder<
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
        where TScopeStorage : class, IScopeStorage<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>;

    IIdentityEngineBuilder<
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
        where TGrantedConsentStorage : class, IGrantedConsentStorage<TGrantedConsent>;

    IIdentityEngineBuilder<
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
        where TUserProfileService : class, IUserProfileService;

    IIdentityEngineBuilder<
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
        where TUserProfileService : class, IUserProfileService;
}
