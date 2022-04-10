using System.Net;
using IdentityEngine.Configuration.Options;
using IdentityEngine.Endpoints.Results;
using IdentityEngine.Endpoints.Results.Default;
using IdentityEngine.Extensions;
using IdentityEngine.Models;
using IdentityEngine.Models.Configuration;
using IdentityEngine.Models.Infrastructure;
using IdentityEngine.Services.Endpoints.Authorize;
using IdentityEngine.Services.Endpoints.Authorize.Models;
using IdentityEngine.Services.Error;
using IdentityEngine.Services.UserAuthentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace IdentityEngine.Endpoints.Handlers.Default;

public sealed class AuthorizeEndpointHandler<TSubjectContext, TError, TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret> : IAuthorizeEndpointHandler
    where TSubjectContext : ISubjectContext
    where TError : IError
    where TClient : IClient<TClientSecret>
    where TClientSecret : ISecret
    where TIdTokenScope : IIdTokenScope
    where TAccessTokenScope : IAccessTokenScope
    where TApi : IApi<TApiSecret>
    where TApiSecret : ISecret
{
    private readonly IErrorService<TError> _errors;
    private readonly ILogger<AuthorizeEndpointHandler<TSubjectContext, TError, TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>> _logger;
    private readonly IdentityEngineOptions _options;
    private readonly IUserAuthenticationService<TSubjectContext> _userAuthentication;
    private readonly IAuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret> _validator;

    public AuthorizeEndpointHandler(
        IdentityEngineOptions options,
        ILogger<AuthorizeEndpointHandler<TSubjectContext, TError, TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret>> logger,
        IUserAuthenticationService<TSubjectContext> userAuthentication,
        IErrorService<TError> errors,
        IAuthorizeRequestValidator<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret> validator)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(userAuthentication);
        ArgumentNullException.ThrowIfNull(errors);
        ArgumentNullException.ThrowIfNull(validator);
        _options = options;
        _logger = logger;
        _userAuthentication = userAuthentication;
        _errors = errors;
        _validator = validator;
    }


    public async Task<IEndpointHandlerResult> HandleAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        _logger.Start();
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
                _logger.EndUnsupportedMediaType();
                return new StatusCodeResult(HttpStatusCode.UnsupportedMediaType);
            }

            var form = await httpContext.Request.ReadFormAsync(cancellationToken);
            parameters = form.AsReadOnlyDictionary();
        }
        else
        {
            _logger.EndMethodNotAllowed(httpContext.Request.Method);
            return new StatusCodeResult(HttpStatusCode.MethodNotAllowed);
        }

        var validationResult = await _validator.ValidateAsync(httpContext, parameters, cancellationToken);
        if (validationResult.HasError)
        {
            var errorId = await CreateErrorAsync(httpContext, validationResult.Error, cancellationToken);
            _logger.EndRequestValidationError(errorId);
            return new ErrorResult(errorId, _options);
        }

        var authenticationResult = await _userAuthentication.AuthenticateAsync(httpContext, cancellationToken);
        if (authenticationResult.HasError)
        {
            var errorId = await CreateErrorAsync(
                httpContext,
                authenticationResult.ProtocolError,
                validationResult.ValidRequest,
                cancellationToken);
            _logger.EndUserAuthenticationError(errorId);
            return new ErrorResult(errorId, _options);
        }

        _logger.EndSuccessful();
        throw new NotImplementedException();
    }

    private async Task<string> CreateErrorAsync(
        HttpContext httpContext,
        AuthorizeRequestError error,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var errorId = await _errors.CreateAsync(
            httpContext,
            error.Error,
            error.ErrorDescription,
            error.ClientId,
            error.RedirectUri,
            error.ResponseMode,
            cancellationToken);
        return errorId;
    }

    private async Task<string> CreateErrorAsync(
        HttpContext httpContext,
        ProtocolError error,
        ValidAuthorizeRequest<TClient, TClientSecret, TIdTokenScope, TAccessTokenScope, TApi, TApiSecret> request,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var errorId = await _errors.CreateAsync(
            httpContext,
            error.Error,
            error.ErrorDescription,
            request.Client.ClientId,
            request.RedirectUri,
            request.ResponseMode,
            cancellationToken);
        return errorId;
    }
}

public static partial class AuthorizeEndpointHandlerLogs
{
    [LoggerMessage(
        EventId = LogEvents.AuthorizeEndpointHandler.Start,
        Level = LogLevel.Debug,
        Message = "Start authorize request.")]
    public static partial void Start(this ILogger logger);

    [LoggerMessage(
        EventId = LogEvents.AuthorizeEndpointHandler.EndSuccessful,
        Level = LogLevel.Debug,
        Message = "End authorize request. Request was successfully handled.")]
    public static partial void EndSuccessful(this ILogger logger);

    [LoggerMessage(
        EventId = LogEvents.AuthorizeEndpointHandler.EndMethodNotAllowed,
        Level = LogLevel.Information,
        Message = "End authorize request. Error. HTTP {HttpMethod} requests not supported.")]
    public static partial void EndMethodNotAllowed(this ILogger logger, string httpMethod);

    [LoggerMessage(
        EventId = LogEvents.AuthorizeEndpointHandler.EndUnsupportedMediaType,
        Level = LogLevel.Information,
        Message = "End authorize request. Error. Unsupported media type.")]
    public static partial void EndUnsupportedMediaType(this ILogger logger);

    [LoggerMessage(
        EventId = LogEvents.AuthorizeEndpointHandler.EndRequestValidationError,
        Level = LogLevel.Information,
        Message = "End authorize request. Request validation error. Id: {ErrorId}. Redirect to error page.")]
    public static partial void EndRequestValidationError(this ILogger logger, string errorId);


    [LoggerMessage(
        EventId = LogEvents.AuthorizeEndpointHandler.EndUserAuthenticationError,
        Level = LogLevel.Information,
        Message = "End authorize request. User authentication error. Id: {ErrorId}. Redirect to error page.")]
    public static partial void EndUserAuthenticationError(this ILogger logger, string errorId);
}
