using IdentityEngine.Configuration.Options;
using IdentityEngine.Models;
using IdentityEngine.Services.Factories.SubjectId;
using IdentityEngine.Services.UserAuthentication.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IdentityEngine.Services.UserAuthentication.Default;

public class UserAuthenticationService<TSubjectId> : IUserAuthenticationService<TSubjectId>
    where TSubjectId : ISubjectId
{
    private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;
    private readonly ILogger<UserAuthenticationService<TSubjectId>> _logger;
    private readonly IdentityEngineOptions _options;
    private readonly ISubjectIdFactory<TSubjectId> _subjectIdFactory;

    public UserAuthenticationService(
        IdentityEngineOptions options,
        IAuthenticationSchemeProvider authenticationSchemeProvider,
        ISubjectIdFactory<TSubjectId> subjectIdFactory,
        ILogger<UserAuthenticationService<TSubjectId>> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(authenticationSchemeProvider);
        ArgumentNullException.ThrowIfNull(subjectIdFactory);
        ArgumentNullException.ThrowIfNull(logger);
        _options = options;
        _authenticationSchemeProvider = authenticationSchemeProvider;
        _subjectIdFactory = subjectIdFactory;
        _logger = logger;
    }

    public virtual async Task<UserAuthenticationResult<TSubjectId>> AuthenticateAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        _logger.Start();
        httpContext.RequestAborted.ThrowIfCancellationRequested();
        string runtimeScheme;
        if (_options.Authentication.AuthenticationScheme != null)
        {
            runtimeScheme = _options.Authentication.AuthenticationScheme;
        }
        else
        {
            var authenticationScheme = await _authenticationSchemeProvider.GetDefaultAuthenticateSchemeAsync();
            if (authenticationScheme == null)
            {
                _logger.EndAuthenticationSchemeNotFound();
                return new(new ProtocolError(
                    Constants.Responses.Errors.Values.ServerError,
                    "Authentication scheme not found"));
            }

            runtimeScheme = authenticationScheme.Name;
        }

        // should retrieved in run-time, because registered as scoped by-default
        // https://github.com/dotnet/aspnetcore/blob/c911002ab43b7b989ed67090f2a48d9073d5118d/src/Http/Authentication.Core/src/AuthenticationCoreServiceCollectionExtensions.cs#L29
        var handlerProvider = httpContext.RequestServices.GetRequiredService<IAuthenticationHandlerProvider>();
        var schemeHandler = await handlerProvider.GetHandlerAsync(httpContext, runtimeScheme);
        if (schemeHandler == null)
        {
            _logger.EndAuthenticationHandlerNotFound(runtimeScheme);
            return new(new ProtocolError(
                Constants.Responses.Errors.Values.ServerError,
                "Authentication scheme handler not found"));
        }

        var result = await schemeHandler.AuthenticateAsync();
        if (!result.Succeeded || result.Ticket.Principal.Identity?.IsAuthenticated != true)
        {
            _logger.EndUserNotAuthenticated();
            return new();
        }

        var subjectId = await _subjectIdFactory.CreateAsync(httpContext, result.Ticket);
        var session = new AuthenticatedUserSession<TSubjectId>(subjectId, result.Ticket);
        _logger.EndSuccessful();
        return new(session);
    }
}

public static partial class UserAuthenticationServiceLogs
{
    [LoggerMessage(
        EventId = LogEvents.UserAuthenticationService.Start,
        Level = LogLevel.Debug,
        Message = "Start user authentication.")]
    public static partial void Start(this ILogger logger);

    [LoggerMessage(
        EventId = LogEvents.UserAuthenticationService.EndAuthenticationSchemeNotFound,
        Level = LogLevel.Error,
        Message = "End user authentication. Error. Authentication schemes not found.")]
    public static partial void EndAuthenticationSchemeNotFound(this ILogger logger);

    [LoggerMessage(
        EventId = LogEvents.UserAuthenticationService.EndAuthenticationHandlerNotFound,
        Level = LogLevel.Error,
        Message =
            "End user authentication. Error. No authentication handler is configured to authenticate for the scheme \"{AuthenticationScheme}\"")]
    public static partial void EndAuthenticationHandlerNotFound(this ILogger logger, string authenticationScheme);

    [LoggerMessage(
        EventId = LogEvents.UserAuthenticationService.EndUserNotAuthenticated,
        Level = LogLevel.Debug,
        Message = "End user authentication. User is not authenticated.")]
    public static partial void EndUserNotAuthenticated(this ILogger logger);

    [LoggerMessage(
        EventId = LogEvents.UserAuthenticationService.EndSuccessful,
        Level = LogLevel.Debug,
        Message = "End user authentication. User authenticated successfully.")]
    public static partial void EndSuccessful(this ILogger logger);
}
