using System.Text;
using System.Text.Encodings.Web;
using IdentityEngine.Configuration.Options;
using IdentityEngine.Extensions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityEngine.Endpoints.Results.Default;

public class DirectClientResult : IEndpointHandlerResult
{
    private readonly ContentSecurityPolicyOptions _cspOptions;
    private readonly IEnumerable<KeyValuePair<string, string?>> _parameters;
    private readonly string _redirectUri;
    private readonly string _responseMode;

    public DirectClientResult(
        IEnumerable<KeyValuePair<string, string?>> parameters,
        ContentSecurityPolicyOptions cspOptions,
        string redirectUri,
        string responseMode)
    {
        _parameters = parameters;
        _cspOptions = cspOptions;
        _redirectUri = redirectUri;
        _responseMode = responseMode;
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
            _parameters));
    }

    private async Task HandlePostResponseAsync(HttpContext httpContext, CancellationToken cancellationToken)
    {
        httpContext.Response.SetNoCache();
        httpContext.Response.SetNoReferrer();
        // echo -n "window.addEventListener('load', function(){document.forms[0].submit();});" | openssl sha256 -binary | openssl base64
        httpContext.Response.AddScriptCspHeaders(_cspOptions, "sha256-orD0/VhH8hLqrLxKHD/HUEMdwqX6/0ve7c5hspX5VJ8=");
        await httpContext.Response.WriteHtmlAsync(BuildHtml(), cancellationToken);
    }

    private string BuildHtml()
    {
        var builder = new StringBuilder(8192);
        builder.Append("<html><head><meta http-equiv='X-UA-Compatible' content='IE=edge' /><base target='_self'/></head><body><form method='post' action='");
        builder.Append(HtmlEncoder.Default.Encode(_redirectUri));
        builder.Append("'>");
        foreach (var (key, value) in _parameters)
        {
            builder.Append("<input type='hidden' name='");
            builder.Append(key);
            builder.Append("' value='");
            if (value != null)
            {
                builder.Append(HtmlEncoder.Default.Encode(value));
            }

            builder.Append("' />\n");
        }

        builder.Append("<noscript><button>Click to continue</button></noscript></form><script>window.addEventListener('load', function(){document.forms[0].submit();});</script></body></html>");
        return builder.ToString();
    }
}
