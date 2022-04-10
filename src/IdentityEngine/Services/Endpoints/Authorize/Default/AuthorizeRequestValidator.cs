using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using IdentityEngine.Configuration.Options;
using IdentityEngine.Models;
using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Configuration.Enums;
using IdentityEngine.Services.Endpoints.Authorize.Models;
using IdentityEngine.Services.Endpoints.Common;
using IdentityEngine.Services.Scope;
using IdentityEngine.Services.Scope.Models;
using IdentityEngine.Storage.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace IdentityEngine.Services.Endpoints.Authorize.Default;

public class AuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>
    : IAuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>
    where TClient : IClient<TClientSecret>
    where TClientSecret : ISecret
    where TIdTokenScope : IIdTokenScope
    where TAccessTokenScope : IAccessTokenScope
    where TApi : IApi<TApiSecret>
    where TApiSecret : ISecret
{
    private readonly IClientStorage<TClient, TClientSecret> _clients;
    private readonly IdentityEngineOptions _options;
    private readonly IScopeValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret> _scopeValidator;

    public AuthorizeRequestValidator(
        IClientStorage<TClient, TClientSecret> clients,
        IdentityEngineOptions options,
        IScopeValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret> scopeValidator)
    {
        ArgumentNullException.ThrowIfNull(clients);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(scopeValidator);
        _clients = clients;
        _options = options;
        _scopeValidator = scopeValidator;
    }

    public async Task<AuthorizeRequestValidationResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>> ValidateAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> authorizeRequestParameters,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(authorizeRequestParameters);
        cancellationToken.ThrowIfCancellationRequested();

        var clientValidation = await ValidateClientAsync(httpContext, authorizeRequestParameters, cancellationToken);
        if (clientValidation.HasError)
        {
            return new(new AuthorizeRequestError(clientValidation.Error));
        }

        var stateValidation = ValidateState(authorizeRequestParameters);
        if (stateValidation.HasError)
        {
            return new(new AuthorizeRequestError(stateValidation.Error));
        }

        var redirectUriValidation = ValidateRedirectUri(authorizeRequestParameters, clientValidation.EnabledClient);
        if (redirectUriValidation.HasError)
        {
            return new(new AuthorizeRequestError(redirectUriValidation.Error));
        }

        var responseTypeValidation = ValidateResponseType(authorizeRequestParameters, clientValidation.EnabledClient);
        if (responseTypeValidation.HasError)
        {
            return new(new AuthorizeRequestError(responseTypeValidation.Error));
        }

        var responseModeValidation = ValidateResponseMode(authorizeRequestParameters);
        if (responseModeValidation.HasError)
        {
            return new(new AuthorizeRequestError(responseModeValidation.Error));
        }

        var scopeValidation = await ValidateScopeAsync(httpContext, authorizeRequestParameters, clientValidation.EnabledClient, cancellationToken);
        if (scopeValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                scopeValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var codeChallengeMethodValidation = ValidateCodeChallengeMethod(authorizeRequestParameters, clientValidation.EnabledClient);
        if (codeChallengeMethodValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                codeChallengeMethodValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var codeChallengeValidation = ValidateCodeChallenge(authorizeRequestParameters);
        if (codeChallengeValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                codeChallengeValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var nonceValidation = ValidateNonce(authorizeRequestParameters);
        if (nonceValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                nonceValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var promptValidation = ValidatePrompt(authorizeRequestParameters);
        if (promptValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                promptValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var maxAgeValidation = ValidateMaxAge(authorizeRequestParameters);
        if (maxAgeValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                maxAgeValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var loginHintValidation = ValidateLoginHint(authorizeRequestParameters);
        if (loginHintValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                loginHintValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var acrValuesValidation = ValidateAcrValues(authorizeRequestParameters);
        if (acrValuesValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                acrValuesValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var displayValidation = ValidateDisplay(authorizeRequestParameters);
        if (displayValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                displayValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var uiLocalesValidation = ValidateUiLocales(authorizeRequestParameters);
        if (uiLocalesValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                uiLocalesValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var requestValidation = ValidateRequest(authorizeRequestParameters);
        if (requestValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                requestValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var requestUriValidation = ValidateRequestUri(authorizeRequestParameters);
        if (requestUriValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                requestUriValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        var registrationValidation = ValidateRegistration(authorizeRequestParameters);
        if (registrationValidation.HasError)
        {
            return new(new AuthorizeRequestError(
                registrationValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseTypeValidation.ResponseType,
                responseModeValidation.ResponseMode));
        }

        return new(new ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>(
            clientValidation.EnabledClient,
            redirectUriValidation.RedirectUri,
            scopeValidation.ValidScopes,
            codeChallengeValidation.CodeChallenge,
            codeChallengeMethodValidation.CodeChallengeMethod,
            responseTypeValidation.ResponseType,
            stateValidation.State,
            responseModeValidation.ResponseMode,
            nonceValidation.Nonce,
            displayValidation.Display,
            promptValidation.Prompt,
            maxAgeValidation.MaxAge,
            uiLocalesValidation.UiLocales,
            loginHintValidation.LoginHint,
            acrValuesValidation.AcrValues));
    }

    private async Task<ClientValidationResult> ValidateClientAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // client_id is required in both specifications
        if (!parameters.TryGetValue(Constants.Requests.Authorize.ClientId, out var clientIdValues) || clientIdValues.Count == 0)
        {
            return ClientValidationResult.ClientIdIsMissing;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (clientIdValues.Count != 1)
        {
            return ClientValidationResult.MultipleClientId;
        }

        var clientId = clientIdValues[0];
        // client_id is required in both specifications
        if (string.IsNullOrEmpty(clientId))
        {
            return ClientValidationResult.UnknownOrDisabledClient;
        }

        // length check
        if (clientId.Length > _options.InputLengthRestrictions.ClientId)
        {
            return ClientValidationResult.ClientIdIsTooLong;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.1
        // syntax validation
        if (!VsCharValueValidator.IsValid(clientId))
        {
            return ClientValidationResult.InvalidClientIdSyntax;
        }

        // client not found
        var client = await _clients.FindAsync(httpContext, clientId, cancellationToken);
        if (client == null)
        {
            return ClientValidationResult.UnknownOrDisabledClient;
        }

        // client disabled
        if (!client.Enabled)
        {
            return ClientValidationResult.UnknownOrDisabledClient;
        }

        // client is valid
        return new(client);
    }

    private StateValidationResult ValidateState(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // state is optional for OAuth 2.1 and recommended for OpenID Connect 1.0
        if (!parameters.TryGetValue(Constants.Requests.Authorize.State, out var stateValues) || stateValues.Count == 0)
        {
            return StateValidationResult.Empty;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (stateValues.Count != 1)
        {
            return StateValidationResult.MultipleState;
        }

        var state = stateValues[0];
        // state is optional for OAuth 2.1 and recommended for OpenID Connect 1.0
        if (string.IsNullOrEmpty(state))
        {
            return StateValidationResult.Empty;
        }

        // length check
        if (state.Length > _options.InputLengthRestrictions.State)
        {
            return StateValidationResult.StateIsTooLong;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.5
        // syntax validation
        if (!VsCharValueValidator.IsValid(state))
        {
            return StateValidationResult.InvalidStateSyntax;
        }

        // state is valid
        return new(state);
    }

    private RedirectUriValidationResult ValidateRedirectUri(IReadOnlyDictionary<string, StringValues> parameters, TClient client)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // redirect_uri is optional
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // redirect_uri is required for any OpenID Connect 1.0 request
        // In current implementation the usage of redirect_uri is REQUIRED, because it's OpenID Connect 1.0 on top of OAuth 2.1, not just an OAuth 2.1 pure implementation.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.RedirectUri, out var redirectUriValues) || redirectUriValues.Count == 0)
        {
            return RedirectUriValidationResult.RedirectUriIsMissing;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (redirectUriValues.Count != 1)
        {
            return RedirectUriValidationResult.MultipleRedirectUri;
        }

        var redirectUri = redirectUriValues[0];
        // required to perform request
        if (string.IsNullOrEmpty(redirectUri))
        {
            return RedirectUriValidationResult.RedirectUriIsMissing;
        }

        // length check
        if (redirectUri.Length > _options.InputLengthRestrictions.RedirectUri)
        {
            return RedirectUriValidationResult.RedirectUriIsTooLong;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-2.3
        // The redirect URI MUST be an absolute URI as defined by [RFC3986] Section 4.3.
        // The endpoint URI MAY include an "application/x-www-form-urlencoded" formatted query component which MUST be retained when adding additional query parameters.
        // The endpoint URI MUST NOT include a fragment component.
        if (!(Uri.TryCreate(redirectUri, UriKind.Absolute, out var typedRedirectUri)
              && typedRedirectUri.IsWellFormedOriginalString()
              && string.IsNullOrEmpty(typedRedirectUri.Fragment)))
        {
            return RedirectUriValidationResult.InvalidRedirectUriSyntax;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-2.3.1
        // Authorization servers MUST require clients to register their complete redirect URI (including the path component)
        // and reject authorization that specify a redirect URI that doesn't exactly match one that was registered;
        // the exception is loopback redirects, where an exact match is required except for the port URI component.
        if (client.RedirectUris == null)
        {
            // no redirect_uri registered in client config
            return RedirectUriValidationResult.NoAllowedRedirectUrisInClientConfiguration;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-1.5
        // OAuth URLs MUST use the https scheme except for loopback interface redirect URIs, which MAY use the http scheme.
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // When comparing the two URIs the authorization server MUST using simple character-by-character string comparison as defined in [RFC3986], Section 6.2.1.
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-8.1
        // Except when using a mechanism like Dynamic Client Registration to provision per-instance secrets, native apps are classified as public clients, as defined in Section 2.1
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-8.4.3
        // The authorization server MUST allow any port to be specified at the time of the request for loopback IP redirect URIs,
        // to accommodate clients that obtain an available ephemeral port from the operating system at the time of the request.
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // redirect_uri - REQUIRED. This URI MUST exactly match one of the Redirection URI values for the Client pre-registered at the OpenID Provider,
        // with the matching performed as described in Section 6.2.1 of [RFC3986] (Simple String Comparison).
        // When using this flow, the Redirection URI SHOULD use the https scheme; however, it MAY use the http scheme, provided that the Client Type is confidential.
        // The Redirection URI MAY use an alternate scheme, such as one that is intended to identify a callback into a native application.
        if (client.Type is ClientType.Credentialed or ClientType.Confidential && IsLoopbackRedirectUri(typedRedirectUri))
        {
            foreach (var existingRedirectUri in client.RedirectUris)
            {
                // client redirect uri is loopback IPv4/6 address for http scheme, without fragment and with any port
                if (Uri.TryCreate(existingRedirectUri, UriKind.Absolute, out var typedExistingRedirectUri)
                    && typedExistingRedirectUri.IsWellFormedOriginalString()
                    && string.IsNullOrEmpty(typedExistingRedirectUri.Fragment)
                    && IsLoopbackRedirectUri(typedExistingRedirectUri)
                    && typedRedirectUri.Scheme == typedExistingRedirectUri.Scheme
                    && typedRedirectUri.Host == typedExistingRedirectUri.Host
                    && typedRedirectUri.PathAndQuery == typedExistingRedirectUri.PathAndQuery)
                {
                    // uri is present in client configuration.
                    // port doesn't matters
                    return new(redirectUri);
                }
            }
        }
        else
        {
            foreach (var clientRedirectUri in client.RedirectUris)
            {
                if (redirectUri == clientRedirectUri)
                {
                    return new(redirectUri);
                }
            }
        }

        // other redirect uris is not supported
        return RedirectUriValidationResult.InvalidRedirectUri;

        static bool IsLoopbackRedirectUri(Uri uri)
        {
            return uri.IsLoopback
                   && uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6
                   && uri.DnsSafeHost is "127.0.0.1" or "::1"
                   && uri.Scheme == "http"
                   && string.IsNullOrEmpty(uri.Fragment);
        }
    }

    private static ResponseTypeValidationResult ValidateResponseType(
        IReadOnlyDictionary<string, StringValues> parameters,
        TClient client)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // response_type is required in both specifications
        if (!parameters.TryGetValue(Constants.Requests.Authorize.ResponseType, out var responseTypeValues) || responseTypeValues.Count == 0)
        {
            return ResponseTypeValidationResult.ResponseTypeIsMissing;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once
        if (responseTypeValues.Count != 1)
        {
            return ResponseTypeValidationResult.MultipleResponseType;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // This specification defines the value "code", which must be used to signal that the client wants to use the authorization code flow.
        // https://openid.net/specs/openid-connect-core-1_0.html#Authentication
        // "response_type" [value = code, Flow = Authorization Code Flow]
        // In current implementation only "code" flow is supported.
        var responseType = responseTypeValues[0];
        if (responseType == Constants.Requests.Authorize.Values.ResponseType.Code
            && client.AllowedGrantTypes.Contains(Constants.Configuration.GrantTypes.AuthorizationCode, StringComparer.InvariantCulture))
        {
            return ResponseTypeValidationResult.Code;
        }

        // other response types is not supported
        return ResponseTypeValidationResult.UnsupportedResponseType;
    }

    private static ResponseModeValidationResult ValidateResponseMode(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // response_mode is optional
        // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
        // Each Response Type (required parameter) value also defines a default Response Mode mechanism to be used, if no Response Mode is specified using the request parameter.
        // query - compatible with OAuth 2.1 and OpenID Connect 1.0
        // fragment - used only in implicit flow and incompatible with OAuth 2.1
        // form_post - defined in https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html and compatible with OAuth 2.1 / OpenID Connect 1.0
        // In current implementation only "code" flow is supported. Default "response_mode" for "code" flow is "query".
        if (!parameters.TryGetValue(Constants.Requests.Authorize.ResponseMode, out var responseModeValues) || responseModeValues.Count == 0)
        {
            return ResponseModeValidationResult.Query;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (responseModeValues.Count != 1)
        {
            return ResponseModeValidationResult.MultipleResponseMode;
        }

        var responseMode = responseModeValues[0];
        // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html
        // query is compatible with OAuth 2.1, but fragment is not https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-2.3
        // The endpoint URI MUST NOT include a fragment component, that's why hybrid flow is dropped.
        if (responseMode == Constants.Requests.Authorize.Values.ResponseMode.Query)
        {
            return ResponseModeValidationResult.Query;
        }

        // https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html
        // form_post is compatible with OAuth 2.1
        if (responseMode == Constants.Requests.Authorize.Values.ResponseMode.FormPost)
        {
            return ResponseModeValidationResult.FormPost;
        }

        // other response modes is not supported
        return ResponseModeValidationResult.UnsupportedResponseMode;
    }

    private async Task<ScopeValidationResult> ValidateScopeAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        TClient client,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // scope is optional, but
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.2.2.1
        // If the client omits the scope parameter when requesting authorization, the authorization server MUST either process the request using a pre-defined default value
        // or fail the request indicating an invalid scope. The authorization server SHOULD document its scope requirements and default value (if defined).
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // scope - REQUIRED. OpenID Connect requests MUST contain the openid scope value. If the openid scope value is not present, the behavior is entirely unspecified.
        // In current implementation "scope" is required and must contain at least "openid" value.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.Scope, out var scopeValues) || scopeValues.Count == 0)
        {
            return ScopeValidationResult.ScopeIsMissing;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (scopeValues.Count != 1)
        {
            return ScopeValidationResult.MultipleScope;
        }

        var scope = scopeValues[0];
        // scope is required in current implementation
        if (string.IsNullOrEmpty(scope))
        {
            return ScopeValidationResult.ScopeIsMissing;
        }

        // length check
        if (scope.Length > _options.InputLengthRestrictions.Scope)
        {
            return ScopeValidationResult.ScopeIsTooLong;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.2.2.1
        // The value of the scope parameter is expressed as a list of space-delimited, case-sensitive strings.
        var requestedScopes = scope
            .Split(' ')
            .ToHashSet(StringComparer.InvariantCulture);

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.4
        // syntax validation
        foreach (var requestedScope in requestedScopes)
        {
            if (string.IsNullOrEmpty(requestedScope) && !NqCharValueValidator.IsValid(requestedScope))
            {
                return ScopeValidationResult.InvalidScopeSyntax;
            }
        }

        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // scope - REQUIRED. OpenID Connect requests MUST contain the openid scope value.
        if (!requestedScopes.Contains(Constants.Requests.Values.Scope.OpenId))
        {
            return ScopeValidationResult.RequireOpenIdScope;
        }

        // validate resources
        var resourceValidation = await _scopeValidator.ValidateRequestedScopesAsync(httpContext, client, requestedScopes, cancellationToken);
        if (resourceValidation.HasError)
        {
            return ScopeValidationResult.InvalidScope;
        }

        // scope is valid
        return new(resourceValidation.ValidScopes);
    }


    private static CodeChallengeMethodValidationResult ValidateCodeChallengeMethod(
        IReadOnlyDictionary<string, StringValues> parameters,
        TClient client)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // defaults to plain if not present in the request.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.CodeChallengeMethod, out var codeChallengeMethodValues) || codeChallengeMethodValues.Count == 0)
        {
            if (client.CodeChallengeMethods.Contains(Constants.Requests.Authorize.Values.CodeChallengeMethod.Plain, StringComparer.InvariantCulture))
            {
                return CodeChallengeMethodValidationResult.Plain;
            }

            return CodeChallengeMethodValidationResult.CodeChallengeMethodIsMissing;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (codeChallengeMethodValues.Count != 1)
        {
            return CodeChallengeMethodValidationResult.MultipleCodeChallengeMethod;
        }

        var codeChallengeMethod = codeChallengeMethodValues[0];
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // Code verifier transformation method is S256 or plain.
        if (codeChallengeMethod == null)
        {
            return CodeChallengeMethodValidationResult.CodeChallengeMethodIsMissing;
        }

        if (codeChallengeMethod == Constants.Requests.Authorize.Values.CodeChallengeMethod.Plain
            && client.CodeChallengeMethods.Contains(codeChallengeMethod, StringComparer.InvariantCulture))
        {
            return CodeChallengeMethodValidationResult.Plain;
        }

        if (codeChallengeMethod == Constants.Requests.Authorize.Values.CodeChallengeMethod.S256
            && client.CodeChallengeMethods.Contains(codeChallengeMethod, StringComparer.InvariantCulture))
        {
            return CodeChallengeMethodValidationResult.S256;
        }

        // other code challenge methods is not supported
        return CodeChallengeMethodValidationResult.UnknownCodeChallengeMethod;
    }

    private CodeChallengeValidationResult ValidateCodeChallenge(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-7.6
        // To prevent injection of authorization codes into the client, using code_challenge and code_verifier is REQUIRED for clients,
        // and authorization servers MUST enforce their use, unless both of the following criteria are met:
        //    * The client is a confidential client.
        //    * In the specific deployment and the specific request, there is reasonable assurance by the authorization server that the client implements
        //      the OpenID Connect nonce mechanism properly.
        // In this case, using and enforcing code_challenge and code_verifier is still RECOMMENDED.
        //
        // In current implementation the usage of Proof Key for Code Exchange is REQUIRED.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.CodeChallenge, out var codeChallengeValues) || codeChallengeValues.Count == 0)
        {
            return CodeChallengeValidationResult.CodeChallengeIsMissing;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (codeChallengeValues.Count != 1)
        {
            return CodeChallengeValidationResult.MultipleCodeChallenge;
        }

        var codeChallenge = codeChallengeValues[0];
        if (string.IsNullOrWhiteSpace(codeChallenge))
        {
            return CodeChallengeValidationResult.CodeChallengeIsMissing;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.18
        if (codeChallenge.Length < _options.InputLengthRestrictions.CodeChallengeMinLength)
        {
            return CodeChallengeValidationResult.CodeChallengeIsTooShort;
        }

        if (codeChallenge.Length > _options.InputLengthRestrictions.CodeChallengeMaxLength)
        {
            return CodeChallengeValidationResult.CodeChallengeIsTooLong;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.18
        if (!UnreservedCharValueValidator.IsValid(codeChallenge))
        {
            return CodeChallengeValidationResult.InvalidCodeChallengeSyntax;
        }

        return new(codeChallenge);
    }

    private NonceValidationResult ValidateNonce(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // nonce - OPTIONAL. String value used to associate a Client session with an ID Token, and to mitigate replay attacks.
        // The value is passed through unmodified from the Authentication Request to the ID Token.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.OpenIdConnect.Nonce, out var nonceValues) || nonceValues.Count == 0)
        {
            return NonceValidationResult.Empty;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (nonceValues.Count != 1)
        {
            return NonceValidationResult.MultipleNonce;
        }

        var nonce = nonceValues[0];
        if (nonce == null)
        {
            return NonceValidationResult.Empty;
        }

        if (nonce.Length > _options.InputLengthRestrictions.Nonce)
        {
            return NonceValidationResult.NonceIsTooLong;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.16
        if (!EndpointParameterValueValidator.IsValid(nonce))
        {
            return NonceValidationResult.InvalidNonceSyntax;
        }

        return new(nonce);
    }

    private static PromptValidationResult ValidatePrompt(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // prompt - OPTIONAL. Space delimited, case sensitive list of ASCII string values
        // that specifies whether the Authorization Server prompts the End-User for re-authentication and consent.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.OpenIdConnect.Prompt, out var promptValues) || promptValues.Count == 0)
        {
            return PromptValidationResult.Empty;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (promptValues.Count != 1)
        {
            return PromptValidationResult.MultiplePrompt;
        }

        var prompt = promptValues[0];
        if (string.IsNullOrEmpty(prompt))
        {
            return PromptValidationResult.Empty;
        }

        // Space delimited, case sensitive list of ASCII string values
        var requestedPrompts = prompt
            .Split(' ')
            .ToHashSet(StringComparer.InvariantCulture);

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-6.2
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.16
        foreach (var requestedPrompt in requestedPrompts)
        {
            if (string.IsNullOrEmpty(requestedPrompt) || !EndpointParameterValueValidator.IsValid(requestedPrompt))
            {
                return PromptValidationResult.InvalidPromptSyntax;
            }
        }

        return requestedPrompts.Count switch
        {
            1 => prompt switch
            {
                Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.None => PromptValidationResult.None,
                Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Login => PromptValidationResult.Login,
                Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Consent => PromptValidationResult.Consent,
                Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.SelectAccount => PromptValidationResult.SelectAccount,
                _ => PromptValidationResult.UnsupportedPrompt
            },
            2 when requestedPrompts.Contains(Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Login) &&
                   requestedPrompts.Contains(Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Consent) => PromptValidationResult.LoginConsent,
            _ => PromptValidationResult.UnsupportedPrompt
        };
    }

    private static MaxAgeValidationResult ValidateMaxAge(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // max_age - OPTIONAL. Maximum Authentication Age. Specifies the allowable elapsed time in seconds since the last time the End-User was actively authenticated by the OP.
        // The max_age request parameter corresponds to the OpenID 2.0 PAPE (https://openid.net/specs/openid-provider-authentication-policy-extension-1_0.html#anchor8)
        // openid.pape.max_auth_age - Value: Integer value greater than or equal to zero in seconds.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.OpenIdConnect.MaxAge, out var maxAgeValues) || maxAgeValues.Count == 0)
        {
            return MaxAgeValidationResult.Empty;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (maxAgeValues.Count != 1)
        {
            return MaxAgeValidationResult.MultipleMaxAge;
        }

        var maxAgeString = maxAgeValues[0];
        if (string.IsNullOrEmpty(maxAgeString))
        {
            return MaxAgeValidationResult.Empty;
        }

        // Integer value greater than or equal to zero in seconds.
        if (long.TryParse(maxAgeString, NumberStyles.Integer, CultureInfo.InvariantCulture, out var maxAge) && maxAge >= 0)
        {
            return new(maxAge);
        }

        return MaxAgeValidationResult.InvalidMaxAge;
    }

    private LoginHintValidationResult ValidateLoginHint(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // login_hint - OPTIONAL. Hint to the Authorization Server about the login identifier the End-User might use to log in (if necessary).
        if (!parameters.TryGetValue(Constants.Requests.Authorize.OpenIdConnect.LoginHint, out var loginHintValues) || loginHintValues.Count == 0)
        {
            return LoginHintValidationResult.Empty;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (loginHintValues.Count != 1)
        {
            return LoginHintValidationResult.MultipleLoginHint;
        }

        var loginHint = loginHintValues[0];
        if (string.IsNullOrEmpty(loginHint))
        {
            return LoginHintValidationResult.Empty;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-6.2
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.16
        if (!EndpointParameterValueValidator.IsValid(loginHint))
        {
            return LoginHintValidationResult.InvalidLoginHintSyntax;
        }

        if (loginHint.Length > _options.InputLengthRestrictions.LoginHint)
        {
            return LoginHintValidationResult.LoginHintIsTooLong;
        }

        return new(loginHint);
    }

    private AcrValuesValidationResult ValidateAcrValues(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // acr_values - OPTIONAL. Requested Authentication Context Class Reference values.
        // Space-separated string that specifies the acr values that the Authorization Server is being requested to
        // use for processing this Authentication Request, with the values appearing in order of preference.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.OpenIdConnect.AcrValues, out var acrValuesValues) || acrValuesValues.Count == 0)
        {
            return AcrValuesValidationResult.Empty;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (acrValuesValues.Count != 1)
        {
            return AcrValuesValidationResult.MultipleAcrValuesValues;
        }

        var acrValues = acrValuesValues[0];
        if (string.IsNullOrEmpty(acrValues))
        {
            return AcrValuesValidationResult.Empty;
        }

        if (acrValues.Length > _options.InputLengthRestrictions.AcrValues)
        {
            return AcrValuesValidationResult.AcrValuesIsTooLong;
        }

        // Space-separated string with the values appearing in order of preference.
        var requestedAcrValues = acrValues
            .Split(' ');
        foreach (var requestedAcrValue in requestedAcrValues)
        {
            if (string.IsNullOrEmpty(requestedAcrValue) || !EndpointParameterValueValidator.IsValid(requestedAcrValue))
            {
                return AcrValuesValidationResult.InvalidAcrValuesSyntax;
            }
        }

        return new(requestedAcrValues);
    }

    private static DisplayValidationResult ValidateDisplay(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // display - OPTIONAL. ASCII string value that specifies how the Authorization Server displays the authentication and consent user interface pages to the End-User.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.OpenIdConnect.Display, out var displayValues) || displayValues.Count == 0)
        {
            return DisplayValidationResult.Empty;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (displayValues.Count != 1)
        {
            return DisplayValidationResult.MultipleDisplayValues;
        }

        var display = displayValues[0];
        if (string.IsNullOrEmpty(display))
        {
            return DisplayValidationResult.Empty;
        }

        return display switch
        {
            Constants.Requests.Authorize.OpenIdConnect.Values.Display.Page => DisplayValidationResult.Page,
            Constants.Requests.Authorize.OpenIdConnect.Values.Display.Popup => DisplayValidationResult.Popup,
            Constants.Requests.Authorize.OpenIdConnect.Values.Display.Touch => DisplayValidationResult.Touch,
            Constants.Requests.Authorize.OpenIdConnect.Values.Display.Wap => DisplayValidationResult.Wap,
            _ => DisplayValidationResult.UnsupportedDisplay
        };
    }

    private UiLocalesValidationResult ValidateUiLocales(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // ui_locales - OPTIONAL. End-User's preferred languages and scripts for the user interface,
        // represented as a space-separated list of BCP47 [RFC5646] language tag values, ordered by preference.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.OpenIdConnect.UiLocales, out var uiLocaleValues) || uiLocaleValues.Count == 0)
        {
            return UiLocalesValidationResult.Empty;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (uiLocaleValues.Count != 1)
        {
            return UiLocalesValidationResult.MultipleUiLocalesValues;
        }

        var uiLocales = uiLocaleValues[0];
        if (string.IsNullOrEmpty(uiLocales))
        {
            return UiLocalesValidationResult.Empty;
        }

        if (uiLocales.Length > _options.InputLengthRestrictions.UiLocales)
        {
            return UiLocalesValidationResult.UiLocalesIsTooLong;
        }

        // TODO: syntax validation for language tags
        return new(uiLocales);
    }

    private static RequestValidationResult ValidateRequest(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#JWTRequests
        // Support for the request parameter is OPTIONAL.
        // Should an OP not support this parameter and an RP uses it, the OP MUST return the request_not_supported error.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.OpenIdConnect.Request, out var requestValues) || requestValues.Count == 0)
        {
            return RequestValidationResult.Empty;
        }

        if (requestValues.Count != 1)
        {
            return RequestValidationResult.MultipleRequestValues;
        }

        return RequestValidationResult.RequestNotSupported;
    }

    private static RequestUriValidationResult ValidateRequestUri(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#RequestUriParameter
        // Should an OP not support this parameter and an RP uses it, the OP MUST return the request_uri_not_supported error.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.OpenIdConnect.RequestUri, out var requestUriValues) || requestUriValues.Count == 0)
        {
            return RequestUriValidationResult.Empty;
        }

        if (requestUriValues.Count != 1)
        {
            return RequestUriValidationResult.MultipleRequestUriValues;
        }

        return RequestUriValidationResult.RequestUriNotSupported;
    }

    private static RegistrationValidationResult ValidateRegistration(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthError
        // registration_not_supported - The OP does not support use of the registration parameter defined in Section 7.2.1.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.OpenIdConnect.Registration, out var registrationValues) || registrationValues.Count == 0)
        {
            return RegistrationValidationResult.Empty;
        }

        if (registrationValues.Count != 1)
        {
            return RegistrationValidationResult.MultipleRegistrationValues;
        }

        return RegistrationValidationResult.RegistrationNotSupported;
    }


    #region ValidationResults

    private class ClientValidationResult
    {
        public static readonly ClientValidationResult ClientIdIsMissing = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"client_id\" is missing"));

        public static readonly ClientValidationResult MultipleClientId = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"client_id\" values are present, but only 1 has allowed"));

        public static readonly ClientValidationResult ClientIdIsTooLong = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"client_id\" is too long"));

        public static readonly ClientValidationResult InvalidClientIdSyntax = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"client_id\" syntax"));

        public static readonly ClientValidationResult UnknownOrDisabledClient = new(new ProtocolError(
            Constants.Responses.Errors.Values.UnauthorizedClient,
            "Unknown or disabled client"));

        private ClientValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public ClientValidationResult(TClient enabledClient)
        {
            EnabledClient = enabledClient;
            HasError = false;
        }

        public TClient? EnabledClient { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(EnabledClient))]
        public bool HasError { get; }
    }

    private class StateValidationResult
    {
        public static readonly StateValidationResult Empty = new();

        public static readonly StateValidationResult MultipleState = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"state\" values are present, but only 1 has allowed"));

        public static readonly StateValidationResult StateIsTooLong = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"state\" is too long"));

        public static readonly StateValidationResult InvalidStateSyntax = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"state\" syntax"));

        private StateValidationResult()
        {
            State = null;
            HasError = false;
        }

        private StateValidationResult(ProtocolError error)
        {
            ArgumentNullException.ThrowIfNull(error);
            Error = error;
            HasError = true;
        }

        public StateValidationResult(string state)
        {
            State = state;
            HasError = false;
        }

        public string? State { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    private class RedirectUriValidationResult
    {
        public static readonly RedirectUriValidationResult RedirectUriIsMissing = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"redirect_uri\" is missing"));

        public static readonly RedirectUriValidationResult MultipleRedirectUri = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"redirect_uri\" values are present, but only 1 has allowed"));

        public static readonly RedirectUriValidationResult RedirectUriIsTooLong = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"redirect_uri\" is too long"));

        public static readonly RedirectUriValidationResult InvalidRedirectUriSyntax = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"redirect_uri\" syntax"));

        public static readonly RedirectUriValidationResult NoAllowedRedirectUrisInClientConfiguration = new(new ProtocolError(
            Constants.Responses.Errors.Values.ServerError,
            "Client configuration doesn't contain any allowed \"redirect_uri\""));

        public static readonly RedirectUriValidationResult InvalidRedirectUri = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"redirect_uri\""));

        private RedirectUriValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public RedirectUriValidationResult(string redirectUri)
        {
            RedirectUri = redirectUri;
            HasError = false;
        }

        public string? RedirectUri { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(RedirectUri))]
        public bool HasError { get; }
    }

    private class ResponseTypeValidationResult
    {
        public static readonly ResponseTypeValidationResult Code = new(Constants.Requests.Authorize.Values.ResponseType.Code);

        public static readonly ResponseTypeValidationResult ResponseTypeIsMissing = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"response_type\" is missing"));

        public static readonly ResponseTypeValidationResult MultipleResponseType = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"response_type\" values are present, but only 1 has allowed"));

        public static readonly ResponseTypeValidationResult UnsupportedResponseType = new(new ProtocolError(
            Constants.Responses.Errors.Values.UnsupportedResponseType,
            "Unsupported \"response_type\""));

        private ResponseTypeValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        private ResponseTypeValidationResult(string? responseType)
        {
            ResponseType = responseType;
            HasError = false;
        }

        public string? ResponseType { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(ResponseType))]
        public bool HasError { get; }
    }

    private class ResponseModeValidationResult
    {
        public static readonly ResponseModeValidationResult Query = new(Constants.Requests.Authorize.Values.ResponseMode.Query);

        public static readonly ResponseModeValidationResult FormPost = new(Constants.Requests.Authorize.Values.ResponseMode.FormPost);

        public static readonly ResponseModeValidationResult MultipleResponseMode = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"response_mode\" values are present, but only 1 has allowed"));

        public static readonly ResponseModeValidationResult UnsupportedResponseMode = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Unsupported \"response_mode\""));

        private ResponseModeValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        private ResponseModeValidationResult(string responseMode)
        {
            ResponseMode = responseMode;
            HasError = false;
        }

        public string? ResponseMode { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(ResponseMode))]
        public bool HasError { get; }
    }

    private class ScopeValidationResult
    {
        public static readonly ScopeValidationResult ScopeIsMissing = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"scope\" is missing"));

        public static readonly ScopeValidationResult MultipleScope = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"scope\" values are present, but only 1 has allowed"));

        public static readonly ScopeValidationResult ScopeIsTooLong = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"scope\" parameter is too long"));

        public static readonly ScopeValidationResult InvalidScopeSyntax = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"scope\" syntax"));

        public static readonly ScopeValidationResult RequireOpenIdScope = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidScope,
            "\"scope\" must contain \"openid\""));

        public static readonly ScopeValidationResult InvalidScope = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidScope,
            "Invalid \"scope\""));

        private ScopeValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public ScopeValidationResult(ValidScopes<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret> validScopes)
        {
            ValidScopes = validScopes;
            HasError = false;
        }

        public ValidScopes<TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>? ValidScopes { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(ValidScopes))]
        public bool HasError { get; }
    }

    private class CodeChallengeMethodValidationResult
    {
        public static readonly CodeChallengeMethodValidationResult CodeChallengeMethodIsMissing = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"code_challenge_method\" is missing"));

        public static readonly CodeChallengeMethodValidationResult MultipleCodeChallengeMethod = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"code_challenge_method\" values are present, but only 1 has allowed"));

        public static readonly CodeChallengeMethodValidationResult UnknownCodeChallengeMethod = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Unknown \"code_challenge_method\""));

        public static readonly CodeChallengeMethodValidationResult Plain = new(Constants.Requests.Authorize.Values.CodeChallengeMethod.Plain);

        public static readonly CodeChallengeMethodValidationResult S256 = new(Constants.Requests.Authorize.Values.CodeChallengeMethod.S256);

        private CodeChallengeMethodValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        private CodeChallengeMethodValidationResult(string codeChallengeMethod)
        {
            CodeChallengeMethod = codeChallengeMethod;
            HasError = false;
        }

        public string? CodeChallengeMethod { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(CodeChallengeMethod))]
        public bool HasError { get; }
    }

    private class CodeChallengeValidationResult
    {
        public static readonly CodeChallengeValidationResult CodeChallengeIsMissing = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"code_challenge\" is missing"));

        public static readonly CodeChallengeValidationResult MultipleCodeChallenge = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"code_challenge\" values are present, but only 1 has allowed"));

        public static readonly CodeChallengeValidationResult CodeChallengeIsTooShort = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"code_challenge\" parameter is too short"));

        public static readonly CodeChallengeValidationResult CodeChallengeIsTooLong = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"code_challenge\" parameter is too long"));

        public static readonly CodeChallengeValidationResult InvalidCodeChallengeSyntax = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"code_challenge\" syntax"));

        private CodeChallengeValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public CodeChallengeValidationResult(string codeChallenge)
        {
            CodeChallenge = codeChallenge;
            HasError = false;
        }

        public string? CodeChallenge { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(CodeChallenge))]
        public bool HasError { get; }
    }

    private class NonceValidationResult
    {
        public static readonly NonceValidationResult Empty = new();

        public static readonly NonceValidationResult MultipleNonce = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"nonce\" values are present, but only 1 has allowed"));

        public static readonly NonceValidationResult NonceIsTooLong = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"nonce\" parameter is too long"));

        public static readonly NonceValidationResult InvalidNonceSyntax = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"nonce\" syntax"));

        private NonceValidationResult()
        {
            Nonce = null;
            HasError = false;
        }

        private NonceValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public NonceValidationResult(string nonce)
        {
            Nonce = nonce;
            HasError = false;
        }

        public string? Nonce { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    private class PromptValidationResult
    {
        public static readonly PromptValidationResult Empty = new();

        public static readonly PromptValidationResult None = new(new[] { Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.None });

        public static readonly PromptValidationResult Login = new(new[] { Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Login });

        public static readonly PromptValidationResult Consent = new(new[] { Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Consent });

        public static readonly PromptValidationResult SelectAccount = new(new[] { Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.SelectAccount });

        public static readonly PromptValidationResult LoginConsent = new(new[]
        {
            Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Login,
            Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Consent
        });

        public static readonly PromptValidationResult InvalidPromptSyntax = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"prompt\" syntax"));

        public static readonly PromptValidationResult MultiplePrompt = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"prompt\" parameter values are present, but only 1 has allowed"));

        public static readonly PromptValidationResult UnsupportedPrompt = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Provided \"prompt\" is not supported"));

        private PromptValidationResult()
        {
            Prompt = null;
            HasError = false;
        }

        private PromptValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        private PromptValidationResult(string[] prompt)
        {
            Prompt = prompt;
            HasError = false;
        }

        public string[]? Prompt { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    private class MaxAgeValidationResult
    {
        public static readonly MaxAgeValidationResult Empty = new();

        public static readonly MaxAgeValidationResult MultipleMaxAge = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"max_age\" parameter values are present, but only 1 has allowed"));

        public static readonly MaxAgeValidationResult InvalidMaxAge = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"max_age\" parameter value"));

        private MaxAgeValidationResult()
        {
            MaxAge = null;
            HasError = false;
        }

        private MaxAgeValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public MaxAgeValidationResult(long maxAge)
        {
            MaxAge = maxAge;
            HasError = false;
        }

        public long? MaxAge { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    private class LoginHintValidationResult
    {
        public static readonly LoginHintValidationResult Empty = new();

        public static readonly LoginHintValidationResult MultipleLoginHint = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"login_hint\" parameter values are present, but only 1 has allowed"));

        public static readonly LoginHintValidationResult LoginHintIsTooLong = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"login_hint\" parameter is too long"));

        public static readonly LoginHintValidationResult InvalidLoginHintSyntax = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"login_hint\" syntax"));

        private LoginHintValidationResult()
        {
            LoginHint = null;
            HasError = false;
        }

        private LoginHintValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public LoginHintValidationResult(string loginHint)
        {
            LoginHint = loginHint;
            HasError = false;
        }

        public string? LoginHint { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    private class AcrValuesValidationResult
    {
        public static readonly AcrValuesValidationResult Empty = new();

        public static readonly AcrValuesValidationResult MultipleAcrValuesValues = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"acr_values\" parameter values are present, but only 1 has allowed"));

        public static readonly AcrValuesValidationResult AcrValuesIsTooLong = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"acr_values\" parameter is too long"));

        public static readonly AcrValuesValidationResult InvalidAcrValuesSyntax = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"acr_values\" syntax"));

        private AcrValuesValidationResult()
        {
            AcrValues = null;
            HasError = false;
        }

        private AcrValuesValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public AcrValuesValidationResult(string[] acrValues)
        {
            AcrValues = acrValues;
            HasError = false;
        }

        public string[]? AcrValues { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    private class DisplayValidationResult
    {
        public static readonly DisplayValidationResult Empty = new();

        public static readonly DisplayValidationResult Page = new(Constants.Requests.Authorize.OpenIdConnect.Values.Display.Page);

        public static readonly DisplayValidationResult Popup = new(Constants.Requests.Authorize.OpenIdConnect.Values.Display.Popup);

        public static readonly DisplayValidationResult Touch = new(Constants.Requests.Authorize.OpenIdConnect.Values.Display.Touch);

        public static readonly DisplayValidationResult Wap = new(Constants.Requests.Authorize.OpenIdConnect.Values.Display.Wap);

        public static readonly DisplayValidationResult MultipleDisplayValues = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"display\" parameter values are present, but only 1 has allowed"));

        public static readonly DisplayValidationResult UnsupportedDisplay = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Provided \"display\" is not supported"));

        private DisplayValidationResult()
        {
            Display = null;
            HasError = false;
        }

        private DisplayValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        private DisplayValidationResult(string display)
        {
            Display = display;
            HasError = false;
        }

        public string? Display { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    private class UiLocalesValidationResult
    {
        public static readonly UiLocalesValidationResult Empty = new();

        public static readonly UiLocalesValidationResult MultipleUiLocalesValues = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"ui_locales\" parameter values are present, but only 1 has allowed"));

        public static readonly UiLocalesValidationResult UiLocalesIsTooLong = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"ui_locales\" parameter is too long"));

        private UiLocalesValidationResult()
        {
            UiLocales = null;
            HasError = false;
        }

        private UiLocalesValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public UiLocalesValidationResult(string uiLocales)
        {
            UiLocales = uiLocales;
            HasError = false;
        }

        public string? UiLocales { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    private class RequestValidationResult
    {
        public static readonly RequestValidationResult Empty = new();

        public static readonly RequestValidationResult MultipleRequestValues = new(new(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"request\" parameter values are present, but only 1 has allowed"));

        public static readonly RequestValidationResult RequestNotSupported = new(new(
            Constants.Responses.Errors.Values.OpenIdConnect.RequestNotSupported,
            "\"request\" parameter provided but not supported"));

        private RequestValidationResult()
        {
            HasError = false;
        }

        private RequestValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    private class RequestUriValidationResult
    {
        public static readonly RequestUriValidationResult Empty = new();

        public static readonly RequestUriValidationResult MultipleRequestUriValues = new(new(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"request_uri\" parameter values are present, but only 1 has allowed"));

        public static readonly RequestUriValidationResult RequestUriNotSupported = new(new(
            Constants.Responses.Errors.Values.OpenIdConnect.RequestUriNotSupported,
            "\"request_uri\" parameter provided but not supported"));

        private RequestUriValidationResult()
        {
            HasError = false;
        }

        private RequestUriValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    private class RegistrationValidationResult
    {
        public static readonly RegistrationValidationResult Empty = new();

        public static readonly RegistrationValidationResult MultipleRegistrationValues = new(new(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Multiple \"registration\" parameter values are present, but only 1 has allowed"));

        public static readonly RegistrationValidationResult RegistrationNotSupported = new(new(
            Constants.Responses.Errors.Values.OpenIdConnect.RegistrationNotSupported,
            "\"registration\" parameter provided but not supported"));

        private RegistrationValidationResult()
        {
            HasError = false;
        }

        private RegistrationValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    #endregion
}
