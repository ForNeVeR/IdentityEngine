using System.Text;
using System.Text.Encodings.Web;
using IdentityEngine.Configuration.Options;
using IdentityEngine.Extensions;
using IdentityEngine.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityEngine.Endpoints.Results.Default;

public class DirectErrorResult : IEndpointHandlerResult
{
    private readonly ProtocolError _error;
    private readonly string _issuer;
    private readonly IdentityEngineOptions _options;
    private readonly string _redirectUri;
    private readonly string _responseMode;
    private readonly string? _state;

    public DirectErrorResult(ProtocolError error, IdentityEngineOptions options, string redirectUri, string responseMode, string? state, string issuer)
    {
        _error = error;
        _options = options;
        _redirectUri = redirectUri;
        _responseMode = responseMode;
        _state = state;
        _issuer = issuer;
    }

    public async Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        switch (_responseMode)
        {
            case Constants.Requests.Authorize.Values.ResponseMode.Query:
                {
                    HandleQueryResponse(httpContext);
                    return;
                }
            case Constants.Requests.Authorize.Values.ResponseMode.FormPost:
                {
                    await HandlePostResponseAsync(httpContext, cancellationToken);
                    return;
                }
            default:
                throw new InvalidOperationException(
                    $"Unexpected response mode. Expected values are: {Constants.Requests.Authorize.Values.ResponseMode.Query}, {Constants.Requests.Authorize.Values.ResponseMode.FormPost}, but actual was: {_responseMode}");
        }
    }

    private void HandleQueryResponse(HttpContext httpContext)
    {
        httpContext.Response.SetNoCache();
        httpContext.Response.Redirect(QueryHelpers.AddQueryString(
            _redirectUri,
            BuildParameters()));
    }

    private async Task HandlePostResponseAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        httpContext.Response.SetNoCache();
        httpContext.Response.SetNoReferrer();
        // echo -n "window.addEventListener('load', function(){document.forms[0].submit();});" | openssl sha256 -binary | openssl base64
        httpContext.Response.AddScriptCspHeaders(_options.ContentSecurityPolicy, "sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8=");
        await httpContext.Response.WriteHtmlAsync(BuildHtml(), cancellationToken);
    }

    private string BuildHtml()
    {
        var builder = new StringBuilder(8192);
        builder.Append("<html><head><meta http-equiv='X-UA-Compatible' content='IE=edge' /><base target='_self'/></head><body><form method='post' action='");
        builder.Append(HtmlEncoder.Default.Encode(_redirectUri));
        builder.Append("'>");
        foreach (var (key, value) in BuildParameters())
        {
            builder.Append("<input type='hidden' name='");
            builder.Append(key);
            builder.Append("' value='");
            builder.Append(value != null ? HtmlEncoder.Default.Encode(value) : string.Empty);
            builder.Append("' />\n");
        }

        builder.Append("<noscript><button>Click to continue</button></noscript></form><script>window.addEventListener('load', function(){document.forms[0].submit();});</script></body></html>");
        return builder.ToString();
    }

    private IEnumerable<KeyValuePair<string, string?>> BuildParameters()
    {
        yield return new(Constants.Responses.Error, _error.Error);
        if (!_options.ErrorHandling.HideErrorDescriptionsOnSafeErrorResponses && !string.IsNullOrWhiteSpace(_error.Description))
        {
            yield return new(Constants.Responses.ErrorDescription, _error.Description);
        }

        if (_state != null)
        {
            yield return new(Constants.Responses.State, _state);
        }

        yield return new(Constants.Responses.Issuer, _issuer);
    }
}
