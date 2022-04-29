using IdentityEngine.Configuration.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityEngine.Endpoints.Results.Default;

public sealed class ErrorPageResult : IEndpointHandlerResult
{
    private readonly string _errorId;
    private readonly IdentityEngineOptions _options;

    public ErrorPageResult(string errorId, IdentityEngineOptions options)
    {
        if (string.IsNullOrWhiteSpace(errorId))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", nameof(errorId));
        }

        ArgumentNullException.ThrowIfNull(options);

        _errorId = errorId;
        _options = options;
    }

    public Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        var errorUri = QueryHelpers.AddQueryString(
            _options.UserInteraction.ErrorUrl,
            _options.UserInteraction.ErrorIdParameter,
            _errorId);
        httpContext.Response.Redirect(errorUri);
        return Task.CompletedTask;
    }
}
