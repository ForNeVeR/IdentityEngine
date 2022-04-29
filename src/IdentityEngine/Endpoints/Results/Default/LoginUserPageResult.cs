using IdentityEngine.Configuration.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityEngine.Endpoints.Results.Default;

public class LoginUserPageResult : IEndpointHandlerResult
{
    private readonly string _authorizeRequestId;
    private readonly IdentityEngineOptions _options;

    public LoginUserPageResult(IdentityEngineOptions options, string authorizeRequestId)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(authorizeRequestId);
        _options = options;
        _authorizeRequestId = authorizeRequestId;
    }

    public Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        httpContext.Response.Redirect(QueryHelpers.AddQueryString(
            _options.UserInteraction.LoginUrl,
            BuildParameters()));
        return Task.CompletedTask;
    }

    private IEnumerable<KeyValuePair<string, string?>> BuildParameters()
    {
        yield return new(_options.UserInteraction.AuthorizeRequestId, _authorizeRequestId);
    }
}
