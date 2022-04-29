using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using IdentityEngine.Configuration.Options;
using IdentityEngine.Models;
using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Configuration.Enums;
using IdentityEngine.Services.Core;
using IdentityEngine.Services.Core.Models.ResourceValidator;
using IdentityEngine.Services.Endpoints.Authorize.Models.RequestValidator;
using IdentityEngine.Services.Validation.Parameters;
using IdentityEngine.Storage.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace IdentityEngine.Services.Endpoints.Authorize.Default;

public class AuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    : IAuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
{
    private readonly IClientStorage<TClient, TClientSecret> _clients;
    private readonly IdentityEngineOptions _options;
    private readonly IResourceValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> _resourceValidator;

    public AuthorizeRequestValidator(
        IClientStorage<TClient, TClientSecret> clients,
        IdentityEngineOptions options,
        IResourceValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> resourceValidator)
    {
        ArgumentNullException.ThrowIfNull(clients);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(resourceValidator);
        _clients = clients;
        _options = options;
        _resourceValidator = resourceValidator;
    }

    public async Task<AuthorizeRequestValidationResult<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>> ValidateAsync(
        HttpContext httpContext,
        IReadOnlyDictionary<string, StringValues> parameters,
        DateTimeOffset requestDate,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        ArgumentNullException.ThrowIfNull(parameters);
        cancellationToken.ThrowIfCancellationRequested();

        var clientValidation = await ValidateClientAsync(httpContext, parameters, cancellationToken);
        if (clientValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(clientValidation.Error));
        }

        var responseTypeValidation = ValidateResponseType(parameters, clientValidation.EnabledClient);
        if (responseTypeValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(responseTypeValidation.Error));
        }

        var stateValidation = ValidateState(parameters);
        if (stateValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(stateValidation.Error));
        }

        var responseModeValidation = ValidateResponseMode(parameters, responseTypeValidation.ResponseType);
        if (responseModeValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(responseModeValidation.Error));
        }

        var redirectUriValidation = ValidateRedirectUri(parameters, clientValidation.EnabledClient);
        if (redirectUriValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(redirectUriValidation.Error));
        }

        var scopeValidation = await ValidateScopeAsync(httpContext, parameters, clientValidation.EnabledClient, cancellationToken);
        if (scopeValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                scopeValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var codeChallengeMethodValidation = ValidateCodeChallengeMethod(parameters, clientValidation.EnabledClient);
        if (codeChallengeMethodValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                codeChallengeMethodValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var codeChallengeValidation = ValidateCodeChallenge(parameters);
        if (codeChallengeValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                codeChallengeValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var nonceValidation = ValidateNonce(parameters);
        if (nonceValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                nonceValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var promptValidation = ValidatePrompt(parameters);
        if (promptValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                promptValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var maxAgeValidation = ValidateMaxAge(parameters);
        if (maxAgeValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                maxAgeValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var loginHintValidation = ValidateLoginHint(parameters);
        if (loginHintValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                loginHintValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var acrValuesValidation = ValidateAcrValues(parameters);
        if (acrValuesValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                acrValuesValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var displayValidation = ValidateDisplay(parameters);
        if (displayValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                displayValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var uiLocalesValidation = ValidateUiLocales(parameters);
        if (uiLocalesValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                uiLocalesValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var requestValidation = ValidateRequest(parameters);
        if (requestValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                requestValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var requestUriValidation = ValidateRequestUri(parameters);
        if (requestUriValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                requestUriValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        var registrationValidation = ValidateRegistration(parameters);
        if (registrationValidation.HasError)
        {
            return new(new AuthorizeRequestValidationError(
                registrationValidation.Error,
                clientValidation.EnabledClient.ClientId,
                redirectUriValidation.RedirectUri,
                stateValidation.State,
                responseModeValidation.ResponseMode));
        }

        return new(new ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>(
            requestDate,
            clientValidation.EnabledClient,
            redirectUriValidation.RedirectUri,
            scopeValidation.ValidResources,
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

        var clientId = clientIdValues.ToString();
        // client_id is required in both specifications
        if (string.IsNullOrEmpty(clientId))
        {
            return ClientValidationResult.ClientIdValueIsMissing;
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
        var responseType = responseTypeValues.ToString();
        if (responseType == Constants.Requests.Authorize.Values.ResponseType.Code
            && client.AllowedGrantTypes.Contains(Constants.Configuration.GrantTypes.AuthorizationCode))
        {
            return ResponseTypeValidationResult.Code;
        }

        // other response types is not supported
        return ResponseTypeValidationResult.UnsupportedResponseType;
    }

    private StateValidationResult ValidateState(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // state is optional for OAuth 2.1 and recommended for OpenID Connect 1.0
        if (!parameters.TryGetValue(Constants.Requests.Authorize.State, out var stateValues) || stateValues.Count == 0)
        {
            return StateValidationResult.Null;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (stateValues.Count != 1)
        {
            return StateValidationResult.MultipleState;
        }

        var state = stateValues.ToString();
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

    private static ResponseModeValidationResult ValidateResponseMode(IReadOnlyDictionary<string, StringValues> parameters, string responseType)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // response_mode is optional
        // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
        // Each Response Type value also defines a default Response Mode mechanism to be used, if no Response Mode is specified using the request parameter.
        // query - compatible with OAuth 2.1 and OpenID Connect 1.0 (default for authorization code)
        // fragment - used only in implicit flow and incompatible with OAuth 2.1
        // form_post - defined in https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html and compatible with OAuth 2.1 / OpenID Connect 1.0
        // In current implementation only "code" flow is supported. Default "response_mode" for "code" flow is "query".
        if (!parameters.TryGetValue(Constants.Requests.Authorize.ResponseMode, out var responseModeValues) || responseModeValues.Count == 0)
        {
            return responseType == Constants.Requests.Authorize.Values.ResponseType.Code
                ? ResponseModeValidationResult.Query
                : ResponseModeValidationResult.UnsupportedResponseMode;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (responseModeValues.Count != 1)
        {
            return ResponseModeValidationResult.MultipleResponseMode;
        }

        var responseMode = responseModeValues.ToString();
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

    private RedirectUriValidationResult ValidateRedirectUri(
        IReadOnlyDictionary<string, StringValues> parameters,
        TClient client)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // redirect_uri is optional
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // redirect_uri is required for any OpenID Connect 1.0 request
        // In current implementation "redirect_uri" is required.
        // like Microsoft Identity Platform https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
        // like Okta https://developer.okta.com/docs/reference/api/oidc/#request-parameters
        // like Google https://developers.google.com/identity/protocols/oauth2/openid-connect#scope-param
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

        var redirectUri = redirectUriValues.ToString();
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
        // The (redirect) endpoint URI MAY include an "application/x-www-form-urlencoded" formatted query component which MUST be retained when adding additional query parameters.
        // The (redirect) endpoint URI MUST NOT include a fragment component.
        if (!IsSyntacticallyCorrect(redirectUri, out var typedRequestRedirectUri))
        {
            return RedirectUriValidationResult.InvalidRedirectUriSyntax;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-2.3.1
        // Authorization servers MUST require clients to register their complete redirect URI (including the path component)
        // and reject authorization that specify a redirect URI that doesn't exactly match one that was registered;
        // the exception is loopback redirects, where an exact match is required except for the port URI component.
        if (client.RedirectUris == null || client.RedirectUris.Count == 0)
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
        if (client.Type is ClientType.Credentialed or ClientType.Confidential && IsCorrectHttpLoopbackRedirectUri(typedRequestRedirectUri))
        {
            foreach (var clientRedirectUri in client.RedirectUris)
            {
                // client redirect uri is loopback IPv4/6 address for http scheme, without fragment and with any port
                if (IsSyntacticallyCorrect(clientRedirectUri, out var typedClientRedirectUri)
                    && IsCorrectHttpLoopbackRedirectUri(typedClientRedirectUri)
                    && typedRequestRedirectUri.Scheme == typedClientRedirectUri.Scheme
                    && typedRequestRedirectUri.Host == typedClientRedirectUri.Host
                    && typedRequestRedirectUri.PathAndQuery == typedClientRedirectUri.PathAndQuery)
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

        // valid redirect uri not found
        return RedirectUriValidationResult.InvalidRedirectUri;

        static bool IsCorrectHttpLoopbackRedirectUri(Uri uri)
        {
            return uri.IsLoopback
                   && uri.HostNameType is UriHostNameType.IPv4 or UriHostNameType.IPv6
                   && uri.DnsSafeHost is "127.0.0.1" or "::1"
                   && uri.Scheme == "http"
                   && string.IsNullOrEmpty(uri.Fragment);
        }

        static bool IsSyntacticallyCorrect(string redirectUri, [NotNullWhen(true)] out Uri? syntacticallyCorrectUri)
        {
            if (Uri.TryCreate(redirectUri, UriKind.Absolute, out var typedRedirectUri)
                && typedRedirectUri.IsWellFormedOriginalString()
                && string.IsNullOrEmpty(typedRedirectUri.Fragment))
            {
                syntacticallyCorrectUri = typedRedirectUri;
                return true;
            }

            syntacticallyCorrectUri = null;
            return false;
        }
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
        // scope - REQUIRED. OpenID Connect requests MUST contain the "openid" scope value. If the "openid" scope value is not present, the behavior is entirely unspecified.
        // In current implementation "scope" is required.
        // like Microsoft Identity Platform https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow
        // like Okta https://developer.okta.com/docs/reference/api/oidc/#request-parameters
        // like Google https://developers.google.com/identity/protocols/oauth2/openid-connect#scope-param
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

        var scope = scopeValues.ToString();
        // scope is required in current implementation
        if (string.IsNullOrEmpty(scope))
        {
            return ScopeValidationResult.InvalidScope;
        }

        // length check
        if (scope.Length > _options.InputLengthRestrictions.Scope)
        {
            return ScopeValidationResult.ScopeIsTooLong;
        }

        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.2.2.1
        // The value of the scope parameter is expressed as a list of space-delimited, case-sensitive strings. The strings are defined by the authorization server.
        // If the value contains multiple space-delimited strings, their order does not matter, and each string adds an additional access range to the requested scope.
        // https://docs.microsoft.com/en-us/dotnet/standard/base-types/best-practices-strings#recommendations-for-string-usage
        // Use the non-linguistic StringComparison.Ordinal or StringComparison.OrdinalIgnoreCase values instead of string operations based on CultureInfo.InvariantCulture
        // when the comparison is linguistically irrelevant (symbolic, for example).
        var requestedScopes = scope
            .Split(' ')
            .ToHashSet(StringComparer.Ordinal);

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
            return ScopeValidationResult.InvalidScope;
        }

        // validate resources
        var resourceValidation = await _resourceValidator.ValidateRequestedResourcesAsync(
            httpContext,
            client,
            requestedScopes,
            cancellationToken);
        if (resourceValidation.HasError)
        {
            if (resourceValidation.HasMisconfigured)
            {
                return ScopeValidationResult.Misconfigured;
            }

            return ScopeValidationResult.InvalidScope;
        }

        // scope is valid
        return new(resourceValidation.Valid);
    }

    private static CodeChallengeMethodValidationResult ValidateCodeChallengeMethod(
        IReadOnlyDictionary<string, StringValues> parameters,
        TClient client)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // defaults to plain if not present in the request.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.CodeChallengeMethod, out var codeChallengeMethodValues) || codeChallengeMethodValues.Count == 0)
        {
            if (client.CodeChallengeMethods.Contains(Constants.Requests.Authorize.Values.CodeChallengeMethod.Plain))
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

        var codeChallengeMethod = codeChallengeMethodValues.ToString();
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-4.1.1
        // Code verifier transformation method is S256 or plain.
        return codeChallengeMethod switch
        {
            Constants.Requests.Authorize.Values.CodeChallengeMethod.Plain
                when client.CodeChallengeMethods.Contains(codeChallengeMethod) => CodeChallengeMethodValidationResult.Plain,
            Constants.Requests.Authorize.Values.CodeChallengeMethod.S256
                when client.CodeChallengeMethods.Contains(codeChallengeMethod) => CodeChallengeMethodValidationResult.S256,
            _ => CodeChallengeMethodValidationResult.UnknownCodeChallengeMethod
        };

        // other code challenge methods is not supported
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

        var codeChallenge = codeChallengeValues.ToString();
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
            return NonceValidationResult.Null;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (nonceValues.Count != 1)
        {
            return NonceValidationResult.MultipleNonce;
        }

        var nonce = nonceValues.ToString();
        if (string.IsNullOrEmpty(nonce))
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
            return PromptValidationResult.Null;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (promptValues.Count != 1)
        {
            return PromptValidationResult.MultiplePrompt;
        }

        var prompt = promptValues.ToString();
        if (string.IsNullOrEmpty(prompt))
        {
            // if prompt provided - it must contain valid value, otherwise it shouldn't be included in request
            return PromptValidationResult.InvalidPromptSyntax;
        }

        // Space delimited, case sensitive list of ASCII string values
        var requestedPrompts = prompt
            .Split(' ')
            .ToHashSet(StringComparer.Ordinal);

        foreach (var requestedPrompt in requestedPrompts)
        {
            if (string.IsNullOrWhiteSpace(requestedPrompt))
            {
                return PromptValidationResult.InvalidPromptSyntax;
            }

            if (!IsValidPrompt(requestedPrompt))
            {
                return PromptValidationResult.UnsupportedPrompt;
            }
        }

        // If this parameter contains "none" with any other value, an error is returned.
        if (requestedPrompts.Contains(Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.None) && requestedPrompts.Count > 1)
        {
            return PromptValidationResult.UnsupportedPrompt;
        }

        return new(requestedPrompts);

        static bool IsValidPrompt(string prompt)
        {
            return prompt switch
            {
                Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.None => true,
                Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Login => true,
                Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.Consent => true,
                Constants.Requests.Authorize.OpenIdConnect.Values.Prompt.SelectAccount => true,
                _ => false
            };
        }
    }

    private static MaxAgeValidationResult ValidateMaxAge(IReadOnlyDictionary<string, StringValues> parameters)
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // max_age - OPTIONAL. Maximum Authentication Age. Specifies the allowable elapsed time in seconds since the last time the End-User was actively authenticated by the OP.
        // The max_age request parameter corresponds to the OpenID 2.0 PAPE (https://openid.net/specs/openid-provider-authentication-policy-extension-1_0.html#anchor8)
        // openid.pape.max_auth_age - Value: Integer value greater than or equal to zero in seconds.
        if (!parameters.TryGetValue(Constants.Requests.Authorize.OpenIdConnect.MaxAge, out var maxAgeValues) || maxAgeValues.Count == 0)
        {
            return MaxAgeValidationResult.Null;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (maxAgeValues.Count != 1)
        {
            return MaxAgeValidationResult.MultipleMaxAge;
        }

        var maxAgeString = maxAgeValues.ToString();
        if (string.IsNullOrEmpty(maxAgeString))
        {
            // if max_age provided - it must contain valid value, otherwise it shouldn't be included in request
            return MaxAgeValidationResult.InvalidMaxAge;
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
            return LoginHintValidationResult.Null;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (loginHintValues.Count != 1)
        {
            return LoginHintValidationResult.MultipleLoginHint;
        }

        var loginHint = loginHintValues.ToString();
        if (string.IsNullOrEmpty(loginHint))
        {
            return LoginHintValidationResult.Null;
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
            return AcrValuesValidationResult.Null;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (acrValuesValues.Count != 1)
        {
            return AcrValuesValidationResult.MultipleAcrValuesValues;
        }

        var acrValues = acrValuesValues.ToString();
        if (string.IsNullOrEmpty(acrValues))
        {
            return AcrValuesValidationResult.Null;
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
            return DisplayValidationResult.Null;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (displayValues.Count != 1)
        {
            return DisplayValidationResult.MultipleDisplayValues;
        }

        return displayValues.ToString() switch
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
            return UiLocalesValidationResult.Null;
        }

        // Inherit from OAuth 2.1 (because OpenID Connect 1.0 doesn't define behaviour).
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // request and response parameters defined by this specification MUST NOT be included more than once.
        if (uiLocaleValues.Count != 1)
        {
            return UiLocalesValidationResult.MultipleUiLocalesValues;
        }

        var uiLocales = uiLocaleValues.ToString();
        if (string.IsNullOrEmpty(uiLocales))
        {
            return UiLocalesValidationResult.Null;
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
            return RequestValidationResult.Null;
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
            return RequestUriValidationResult.Null;
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
            return RegistrationValidationResult.Null;
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

        public static readonly ClientValidationResult ClientIdValueIsMissing = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"client_id\" value is missing"));

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
        public static readonly StateValidationResult Null = new();

        public static readonly StateValidationResult Empty = new(string.Empty);

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
            Constants.Responses.Errors.Values.InvalidScope,
            "\"scope\" is missing"));

        public static readonly ScopeValidationResult MultipleScope = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidScope,
            "Multiple \"scope\" values are present, but only 1 has allowed"));

        public static readonly ScopeValidationResult ScopeIsTooLong = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "\"scope\" parameter is too long"));

        public static readonly ScopeValidationResult InvalidScopeSyntax = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidRequest,
            "Invalid \"scope\" syntax"));

        public static readonly ScopeValidationResult InvalidScope = new(new ProtocolError(
            Constants.Responses.Errors.Values.InvalidScope,
            "Invalid \"scope\""));

        public static readonly ScopeValidationResult Misconfigured = new(new ProtocolError(
            Constants.Responses.Errors.Values.ServerError,
            "\"scope\" contains misconfigured scopes"));

        private ScopeValidationResult(ProtocolError error)
        {
            Error = error;
            HasError = true;
        }

        public ScopeValidationResult(ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> validResources)
        {
            ValidResources = validResources;
            HasError = false;
        }

        public ValidResources<TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret>? ValidResources { get; }

        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        [MemberNotNullWhen(false, nameof(ValidResources))]
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
        public static readonly NonceValidationResult Null = new();

        public static readonly NonceValidationResult Empty = new(string.Empty);

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
        public static readonly PromptValidationResult Null = new();

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

        public PromptValidationResult(IReadOnlySet<string> prompt)
        {
            Prompt = prompt;
            HasError = false;
        }

        public IReadOnlySet<string>? Prompt { get; }
        public ProtocolError? Error { get; }

        [MemberNotNullWhen(true, nameof(Error))]
        public bool HasError { get; }
    }

    private class MaxAgeValidationResult
    {
        public static readonly MaxAgeValidationResult Null = new();

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
        public static readonly LoginHintValidationResult Null = new();

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
        public static readonly AcrValuesValidationResult Null = new();

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
        public static readonly DisplayValidationResult Null = new();

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
        public static readonly UiLocalesValidationResult Null = new();

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
        public static readonly RequestValidationResult Null = new();

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
        public static readonly RequestUriValidationResult Null = new();

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
        public static readonly RegistrationValidationResult Null = new();

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
