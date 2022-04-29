using IdentityEngine.Configuration.Options;
using IdentityEngine.Models;
using IdentityEngine.Services.Core.Models.UserAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityEngine.Services.Core.Default;

public sealed class UserAuthenticationService : IUserAuthenticationService
{
    private readonly IAuthenticationSchemeProvider _authenticationSchemeProvider;
    private readonly IdentityEngineOptions _options;

    public UserAuthenticationService(
        IdentityEngineOptions options,
        IAuthenticationSchemeProvider authenticationSchemeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(authenticationSchemeProvider);
        _options = options;
        _authenticationSchemeProvider = authenticationSchemeProvider;
    }

    public async Task<UserAuthenticationResult> AuthenticateAsync(
        HttpContext httpContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
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
            return new(new ProtocolError(
                Constants.Responses.Errors.Values.ServerError,
                "Authentication scheme handler not found"));
        }

        var result = await schemeHandler.AuthenticateAsync();
        if (!result.Succeeded || result.Ticket.Principal.Identity?.IsAuthenticated != true)
        {
            return new();
        }

        var session = new AuthenticatedUserSession(result.Ticket);
        return new(session);
    }
}
