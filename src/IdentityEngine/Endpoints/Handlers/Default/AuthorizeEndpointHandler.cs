using System.Net;
using IdentityEngine.Configuration.Options;
using IdentityEngine.Endpoints.Results;
using IdentityEngine.Endpoints.Results.Default;
using IdentityEngine.Extensions;
using IdentityEngine.Models;
using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Intermediate;
using IdentityEngine.Services.Core;
using IdentityEngine.Services.Endpoints.Authorize;
using IdentityEngine.Services.Endpoints.Authorize.Models.RequestValidator;
using IdentityEngine.Services.Endpoints.Authorize.Models.ResponseGenerator;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace IdentityEngine.Endpoints.Handlers.Default;

public sealed class AuthorizeEndpointHandler<TError, TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret, TAuthorizeRequestUserConsent>
    : IAuthorizeEndpointHandler
    where TError : class, IError
    where TClient : class, IClient<TClientSecret>
    where TClientSecret : class, ISecret
    where TIdTokenScope : class, IIdTokenScope
    where TAccessTokenScope : class, IAccessTokenScope
    where TResource : class, IResource<TResourceSecret>
    where TResourceSecret : class, ISecret
    where TAuthorizeRequestUserConsent : class, IAuthorizeRequestUserConsent
{
    private readonly IErrorService<TError> _errors;
    private readonly IAuthorizeRequestInteractionHandler<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret, TAuthorizeRequestUserConsent> _interaction;
    private readonly IdentityEngineOptions _options;
    private readonly IOriginUrls _originUrls;
    private readonly IAuthorizeRequestParametersService<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> _parameters;
    private readonly IAuthorizeRequestResponseGenerator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> _responseGenerator;
    private readonly ISystemClock _systemClock;
    private readonly IUserAuthenticationService _userAuthentication;
    private readonly IAuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> _validator;

    public AuthorizeEndpointHandler(
        IdentityEngineOptions options,
        IUserAuthenticationService userAuthentication,
        IErrorService<TError> errors,
        IAuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> validator,
        IAuthorizeRequestInteractionHandler<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret, TAuthorizeRequestUserConsent> interaction,
        ISystemClock systemClock,
        IAuthorizeRequestParametersService<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> parameters,
        IAuthorizeRequestResponseGenerator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> responseGenerator,
        IOriginUrls originUrls)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(userAuthentication);
        ArgumentNullException.ThrowIfNull(errors);
        ArgumentNullException.ThrowIfNull(validator);
        ArgumentNullException.ThrowIfNull(interaction);
        ArgumentNullException.ThrowIfNull(systemClock);
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(responseGenerator);
        ArgumentNullException.ThrowIfNull(originUrls);
        _options = options;
        _userAuthentication = userAuthentication;
        _errors = errors;
        _validator = validator;
        _interaction = interaction;
        _systemClock = systemClock;
        _parameters = parameters;
        _responseGenerator = responseGenerator;
        _originUrls = originUrls;
    }

    public async Task<IEndpointHandlerResult> HandleAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // The authorization server MUST support the use of the HTTP GET method for the authorization endpoint and MAY support the use of the POST method as well.
        // https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        // Authorization Servers MUST support the use of the HTTP GET and POST methods defined in RFC 2616 [RFC2616] at the Authorization Endpoint.
        IReadOnlyDictionary<string, StringValues> parameters;
        if (HttpMethods.IsGet(httpContext.Request.Method))
        {
            parameters = httpContext.Request.Query.AsReadOnlyDictionary();
        }
        else if (HttpMethods.IsPost(httpContext.Request.Method))
        {
            if (!httpContext.Request.HasApplicationFormContentType())
            {
                return new StatusCodeResult(HttpStatusCode.UnsupportedMediaType);
            }

            var form = await httpContext.Request.ReadFormAsync(cancellationToken);
            parameters = form.AsReadOnlyDictionary();
        }
        else
        {
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var requestDate = _systemClock.UtcNow;
        var validationResult = await _validator.ValidateAsync(httpContext, parameters, requestDate, cancellationToken);
        if (validationResult.HasError)
        {
            return await HandleAuthorizeRequestValidationError(httpContext, validationResult.ValidationError, cancellationToken);
        }

        var authenticationResult = await _userAuthentication.AuthenticateAsync(httpContext, cancellationToken);
        if (authenticationResult.HasError)
        {
            return await HandleErrorAsync(httpContext, authenticationResult.ProtocolError, validationResult.ValidRequest, cancellationToken);
        }

        var interactionResult = await _interaction.HandleInteractionAsync(httpContext, validationResult.ValidRequest, authenticationResult.Session, null, cancellationToken);
        if (!interactionResult.IsValid)
        {
            if (interactionResult.HasError)
            {
                return await HandleErrorAsync(httpContext, interactionResult.ProtocolError, validationResult.ValidRequest, cancellationToken);
            }

            if (interactionResult.RequireInteraction)
            {
                return await HandleRequiredInteraction(
                    httpContext,
                    interactionResult.RequiredInteraction,
                    validationResult.ValidRequest,
                    cancellationToken);
            }

            return await HandleErrorAsync(
                httpContext,
                new(Constants.Responses.Errors.Values.ServerError, "Incorrect interaction state"),
                validationResult.ValidRequest,
                cancellationToken);
        }


        var response = await _responseGenerator.CreateResponseAsync(httpContext, interactionResult.ValidRequest, cancellationToken);
        var issuer = _originUrls.GetOrigin(httpContext);
        var successfulResponseParameters = BuildSuccessfulResponseParameters(response, issuer);
        return new DirectClientResult(
            successfulResponseParameters,
            _options.ContentSecurityPolicy,
            interactionResult.ValidRequest.RedirectUri,
            interactionResult.ValidRequest.ResponseMode);
    }

    private async Task<IEndpointHandlerResult> HandleAuthorizeRequestValidationError(
        HttpContext httpContext,
        AuthorizeRequestValidationError validationError,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (validationError.CanRedirect)
        {
            var issuer = _originUrls.GetOrigin(httpContext);
            var errorParameters = BuildErrorResponseParameters(_options, validationError.ProtocolError, validationError.State, issuer);
            return new DirectClientResult(errorParameters, _options.ContentSecurityPolicy, validationError.RedirectUri, validationError.ResponseMode);
        }

        var errorId = await _errors.CreateAsync(
            httpContext,
            validationError.ProtocolError.Error,
            validationError.ProtocolError.Description,
            validationError.ClientId,
            validationError.RedirectUri,
            validationError.ResponseMode,
            cancellationToken);
        return new ErrorPageResult(errorId, _options);
    }

    private async Task<IEndpointHandlerResult> HandleErrorAsync(
        HttpContext httpContext,
        ProtocolError error,
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (error.IsSafe)
        {
            var issuer = _originUrls.GetOrigin(httpContext);
            var errorParameters = BuildErrorResponseParameters(_options, error, request.State, issuer);
            return new DirectClientResult(errorParameters, _options.ContentSecurityPolicy, request.RedirectUri, request.ResponseMode);
        }

        var errorId = await _errors.CreateAsync(
            httpContext,
            error.Error,
            error.Description,
            request.Client.ClientId,
            request.RedirectUri,
            request.ResponseMode,
            cancellationToken);
        return new ErrorPageResult(errorId, _options);
    }


    private async Task<IEndpointHandlerResult> HandleRequiredInteraction(
        HttpContext httpContext,
        string requiredInteraction,
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TResource, TResourceSecret> request,
        CancellationToken cancellationToken)
    {
        switch (requiredInteraction)
        {
            case Constants.Intermediate.RequiredInteractions.AuthenticateUser:
                {
                    var authorizeRequestId = await _parameters.WriteAsync(httpContext, request, cancellationToken);
                    return new LoginUserPageResult(_options, authorizeRequestId);
                }
            case Constants.Intermediate.RequiredInteractions.ReAuthenticateUser:
                {
                    var authorizeRequestId = await _parameters.WriteAsync(httpContext, request, cancellationToken);
                    return new LoginUserPageResult(_options, authorizeRequestId);
                }
            case Constants.Intermediate.RequiredInteractions.Consent:
                {
                    var authorizeRequestId = await _parameters.WriteAsync(httpContext, request, cancellationToken);
                    return new ConsentPageResult(_options, authorizeRequestId);
                }

            default:
                {
                    return await HandleErrorAsync(
                        httpContext,
                        new(Constants.Responses.Errors.Values.ServerError, "Unsupported interaction"),
                        request,
                        cancellationToken);
                }
        }
    }

    private static IEnumerable<KeyValuePair<string, string?>> BuildErrorResponseParameters(
        IdentityEngineOptions options,
        ProtocolError error,
        string? state,
        string issuer)
    {
        yield return new(Constants.Responses.Error, error.Error);
        if (!options.ErrorHandling.HideErrorDescriptionsOnSafeErrorResponses && !string.IsNullOrWhiteSpace(error.Description))
        {
            yield return new(Constants.Responses.ErrorDescription, error.Description);
        }

        if (state != null)
        {
            yield return new(Constants.Responses.State, state);
        }

        yield return new(Constants.Responses.Issuer, issuer);
    }

    private static IEnumerable<KeyValuePair<string, string?>> BuildSuccessfulResponseParameters(AuthorizeResponse response, string issuer)
    {
        yield return new(Constants.Responses.Authorize.Code, response.Code);
        if (response.State != null)
        {
            yield return new(Constants.Responses.State, response.State);
        }

        yield return new(Constants.Responses.Issuer, issuer);
    }
}
