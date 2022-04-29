using IdentityEngine.Models;
using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Intermediate;
using IdentityEngine.Models.Operation;
using IdentityEngine.Services.Core;
using IdentityEngine.Services.Core.Models.UserAuthentication;
using IdentityEngine.Services.Endpoints.Authorize.Models.RequestInteractionHandler;
using IdentityEngine.Services.Endpoints.Authorize.Models.RequestValidator;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Endpoints.Authorize.Default;

public class AuthorizeRequestInteractionHandler<
        TClient,
        TClientSecret,
        TIdTokenScope,
        TAccessTokenScope,
        TResource,
        TResourceSecret,
        TAuthorizeRequestUserConsent,
        TGrantedConsent>
    : IAuthorizeRequestInteractionHandler<
        TClient,
        TClientSecret,
        TIdTokenScope,
        TAccessTokenScope,
        TResource,
        TResourceSecret,
        TAuthorizeRequestUserConsent>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
    where TAuthorizeRequestUserConsent : class, IAuthorizeRequestUserConsent
    where TGrantedConsent : class, IGrantedConsent
{
    private readonly IGrantedConsentService<TClient, TClientSecret, TGrantedConsent> _consents;
    private readonly ISystemClock _systemClock;
    private readonly IUserProfileService _userProfile;

    public AuthorizeRequestInteractionHandler(
        ISystemClock systemClock,
        IUserProfileService userProfile,
        IGrantedConsentService<TClient, TClientSecret, TGrantedConsent> consents)
    {
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(userProfile);
        ArgumentNullException.ThrowIfNull(consents);
        _systemClock = systemClock;
        _userProfile = userProfile;
        _consents = consents;
    }

    public async Task<AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>> HandleInteractionAsync(
        HttpContext httpContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> authorizeRequest,
        AuthenticatedUserSession? userSession,
        TAuthorizeRequestUserConsent? authorizeRequestConsent,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(authorizeRequest);
        cancellationToken.ThrowIfCancellationRequested();
        // special case when anonymous user has issued an error prior to authenticating
        if (userSession == null && authorizeRequestConsent is { Granted: false })
        {
            return authorizeRequestConsent.Error.Error switch
            {
                Constants.Responses.Errors.Values.OpenIdConnect.LoginRequired => ErrorLoginRequired,
                Constants.Responses.Errors.Values.OpenIdConnect.ConsentRequired => ErrorConsentRequired,
                Constants.Responses.Errors.Values.OpenIdConnect.InteractionRequired => ErrorInteractionRequired,
                Constants.Responses.Errors.Values.OpenIdConnect.AccountSelectionRequired => ErrorAccountSelectionRequired,
                _ => ErrorAccessDenied
            };
        }

        var isPromptNone = authorizeRequest.Prompt?.Contains(Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.None) == true;
        if (userSession == null)
        {
            return isPromptNone ? ErrorLoginRequired : LoginInteraction;
        }

        var loginResult = await HandleLoginAsync(httpContext, authorizeRequest, userSession, isPromptNone, cancellationToken);
        if (loginResult != null)
        {
            return loginResult;
        }

        return await HandleConsentAsync(httpContext, authorizeRequest, userSession, authorizeRequestConsent, isPromptNone, cancellationToken);
    }

    private async Task<AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>?> HandleLoginAsync(
        HttpContext httpContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> request,
        AuthenticatedUserSession userSession,
        bool isPromptNone,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!await _userProfile.IsActiveAsync(httpContext, userSession, cancellationToken))
        {
            return isPromptNone ? ErrorLoginRequired : ReAuthenticationInteraction;
        }

        // OpenID Connect 1.0 - max age check
        var currentDate = _systemClock.UtcNow;
        if (request.MaxAge.HasValue)
        {
            if (request.MaxAge.Value > 0)
            {
                var absoluteMaxAge = userSession.AuthenticationTime.AddSeconds(request.MaxAge.Value);
                if (currentDate > absoluteMaxAge)
                {
                    return isPromptNone ? ErrorLoginRequired : ReAuthenticationInteraction;
                }
            }
            // force re-authentication once when max_age=0
            else
            {
                // isReAuthenticationPerformed?
                if (!IsReAuthenticationPerformed(request, userSession))
                {
                    return isPromptNone ? ErrorLoginRequired : ReAuthenticationInteraction;
                }
            }
        }

        // Client-related restrictions
        if (userSession.IdentityProvider == Constants.ClaimTypes.Values.LocalIdentityProvider)
        {
            if (!request.Client.EnableLocalLogin)
            {
                return isPromptNone ? ErrorLoginRequired : ReAuthenticationInteraction;
            }
        }
        else if (request.Client.IdentityProviderRestrictions != null
                 && request.Client.IdentityProviderRestrictions.Any()
                 && !request.Client.IdentityProviderRestrictions.Contains(userSession.IdentityProvider))
        {
            return isPromptNone ? ErrorLoginRequired : ReAuthenticationInteraction;
        }

        // Client configuration max SSO lifetime check
        if (request.Client.UserSsoLifetime.HasValue)
        {
            var actualLifetime = currentDate - userSession.AuthenticationTime;
            if (actualLifetime > request.Client.UserSsoLifetime.Value)
            {
                return isPromptNone ? ErrorLoginRequired : ReAuthenticationInteraction;
            }
        }

        // request requires to re-authenticate
        var shouldReAuthenticate =
            request.Prompt != null
            && (request.Prompt.Contains(Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Login)
                || request.Prompt.Contains(Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.SelectAccount));
        if (shouldReAuthenticate && !IsReAuthenticationPerformed(request, userSession))
        {
            return isPromptNone ? ErrorLoginRequired : ReAuthenticationInteraction;
        }

        return null;
    }

    private static bool IsReAuthenticationPerformed(
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> request,
        AuthenticatedUserSession userSession)
    {
        return userSession.AuthenticationTime >= request.RequestDate;
    }

    private async Task<AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>> HandleConsentAsync(
        HttpContext httpContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> request,
        AuthenticatedUserSession userSession,
        TAuthorizeRequestUserConsent? authorizeRequestConsent,
        bool isPromptNone,
        CancellationToken cancellationToken)
    {
        var consentRequired = await IsConsentRequiredAsync(httpContext, request, userSession, cancellationToken);
        if (consentRequired && isPromptNone)
        {
            return ErrorConsentRequired;
        }

        if (consentRequired || request.Prompt?.Contains(Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Consent) == true)
        {
            if (authorizeRequestConsent == null)
            {
                return ConsentInteraction;
            }

            if (!authorizeRequestConsent.Granted)
            {
                return authorizeRequestConsent.Error.Error switch
                {
                    Constants.Responses.Errors.Values.OpenIdConnect.LoginRequired => ErrorLoginRequired,
                    Constants.Responses.Errors.Values.OpenIdConnect.ConsentRequired => ErrorConsentRequired,
                    Constants.Responses.Errors.Values.OpenIdConnect.InteractionRequired => ErrorInteractionRequired,
                    Constants.Responses.Errors.Values.OpenIdConnect.AccountSelectionRequired => ErrorAccountSelectionRequired,
                    _ => ErrorAccessDenied
                };
            }

            if (!authorizeRequestConsent.Scopes.IsSupersetOf(request.Resources.RequiredScopes))
            {
                return ErrorAccessDenied;
            }

            var grantedResources = request.Resources.FilterConsentedScopes(authorizeRequestConsent.Scopes);
            var grantedScopes = authorizeRequestConsent.Remember ? grantedResources.AllScopes : new HashSet<string>(0);
            await _consents.UpsertAsync(httpContext, userSession.SubjectId, request.Client, grantedScopes, cancellationToken);

            return new(new ValidAuthorizeRequestInteraction<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>(
                request.RequestDate,
                request.Client,
                request.RedirectUri,
                grantedResources,
                request.CodeChallenge,
                request.CodeChallengeMethod,
                request.ResponseType,
                request.State,
                request.ResponseMode,
                userSession,
                request.Nonce,
                request.Display,
                request.Prompt,
                request.MaxAge,
                request.UiLocales,
                request.LoginHint,
                request.AcrValues));
        }

        await _consents.UpsertAsync(httpContext, userSession.SubjectId, request.Client, request.Resources.AllScopes, cancellationToken);
        return new(new ValidAuthorizeRequestInteraction<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>(
            request.RequestDate,
            request.Client,
            request.RedirectUri,
            request.Resources,
            request.CodeChallenge,
            request.CodeChallengeMethod,
            request.ResponseType,
            request.State,
            request.ResponseMode,
            userSession,
            request.Nonce,
            request.Display,
            request.Prompt,
            request.MaxAge,
            request.UiLocales,
            request.LoginHint,
            request.AcrValues));
    }

    private async Task<bool> IsConsentRequiredAsync(
        HttpContext httpContext,
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> request,
        AuthenticatedUserSession userSession,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!request.Client.RequireConsent)
        {
            return false;
        }

        if (request.Resources.AllScopes.Count == 0)
        {
            return false;
        }

        if (!request.Client.AllowToRememberConsent)
        {
            return true;
        }

        if (request.Resources.AllowRefreshTokens)
        {
            return true;
        }

        var grantedConsent = await _consents.FindAsync(httpContext, userSession.SubjectId, request.Client, cancellationToken);

        if (grantedConsent?.GrantedScopes.IsSupersetOf(request.Resources.AllScopes) == true)
        {
            return false;
        }

        return true;
    }

    #region Interactions

    private static readonly AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> LoginInteraction =
        new(Constants.Intermediate.RequiredInteractions.AuthenticateUser);

    private static readonly AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> ConsentInteraction =
        new(Constants.Intermediate.RequiredInteractions.Consent);

    private static readonly AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> ReAuthenticationInteraction =
        new(Constants.Intermediate.RequiredInteractions.ReAuthenticateUser);

    #endregion

    #region Errors

    private static readonly AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> ErrorLoginRequired =
        new(new ProtocolError(Constants.Responses.Errors.Values.OpenIdConnect.LoginRequired, null));

    private static readonly AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> ErrorConsentRequired =
        new(new ProtocolError(Constants.Responses.Errors.Values.OpenIdConnect.ConsentRequired, null));

    private static readonly AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> ErrorInteractionRequired =
        new(new ProtocolError(Constants.Responses.Errors.Values.OpenIdConnect.InteractionRequired, null));

    private static readonly AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> ErrorAccountSelectionRequired =
        new(new ProtocolError(Constants.Responses.Errors.Values.OpenIdConnect.AccountSelectionRequired, null));

    private static readonly AuthorizeRequestInteractionResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> ErrorAccessDenied =
        new(new ProtocolError(Constants.Responses.Errors.Values.AccessDenied, null));

    #endregion
}
