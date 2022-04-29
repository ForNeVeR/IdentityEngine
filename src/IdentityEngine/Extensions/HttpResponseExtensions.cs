using System.Text;
using IdentityEngine.Configuration.Options;
using IdentityEngine.Models.Configuration.Enums;
using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Extensions;

public static class HttpResponseExtensions
{
    public static void SetNoCache(this HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        response.Headers["Cache-Control"] = "no-store, no-cache, max-age=0";
        response.Headers["Pragma"] = "no-cache";
    }

    public static void SetNoReferrer(this HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        response.Headers["Referrer-Policy"] = "no-referrer";
    }

    public static void AddScriptCspHeaders(this HttpResponse response, ContentSecurityPolicyOptions cspOptions, string hash)
    {
        ArgumentNullException.ThrowIfNull(response);
        ArgumentNullException.ThrowIfNull(cspOptions);
        var cspHeader = cspOptions.Level switch
        {
            ContentSecurityPolicyLevel.One => $"default-src 'none'; script-src 'unsafe-inline' '{hash}'",
            ContentSecurityPolicyLevel.Two => $"default-src 'none'; script-src '{hash}'",
            _ => throw new ArgumentOutOfRangeException(nameof(cspOptions.Level), "Invalid content security policy level")
        };
        response.Headers["Content-Security-Policy"] = cspHeader;
        if (cspOptions.AddDeprecatedHeader)
        {
            response.Headers["X-Content-Security-Policy"] = cspHeader;
        }
    }

    public static async Task WriteHtmlAsync(this HttpResponse response, string html, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(response);
        response.ContentType = "text/html; charset=UTF-8";
        await response.WriteAsync(html, Encoding.UTF8, cancellationToken);
        await response.Body.FlushAsync(cancellationToken);
    }
}
