using System.Net;
using IdentityEngine.Endpoints.Results;
using IdentityEngine.Endpoints.Results.Default;
using IdentityEngine.Extensions;
using IdentityEngine.Models;
using IdentityEngine.Services.UserAuthentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace IdentityEngine.Endpoints.Handlers.Default;

public class AuthorizeEndpointHandler<TSubjectId> : IAuthorizeEndpointHandler
    where TSubjectId : ISubjectId
{
    private readonly ILogger<AuthorizeEndpointHandler<TSubjectId>> _logger;
    private readonly IUserAuthenticationService<TSubjectId> _userAuthentication;

    public AuthorizeEndpointHandler(
        ILogger<AuthorizeEndpointHandler<TSubjectId>> logger,
        IUserAuthenticationService<TSubjectId> userAuthentication)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(userAuthentication);
        _logger = logger;
        _userAuthentication = userAuthentication;
    }

    public virtual async Task<IEndpointHandlerResult> HandleAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        _logger.Start();
        cancellationToken.ThrowIfCancellationRequested();
        // According to https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-3.1
        // The authorization server MUST support the use of the HTTP GET method for the authorization endpoint and MAY support the use of
        // the POST method as well.
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

        var authenticationResult = await _userAuthentication.AuthenticateAsync(httpContext, cancellationToken);
        if (authenticationResult.HasError)
        {
        }

        _logger.EndSuccessful();
        throw new NotImplementedException();
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
        Level = LogLevel.Trace,
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
}
