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
        if (!response.Headers.ContainsKey("Cache-Control"))
        {
            response.Headers.Add("Cache-Control", "no-store, no-cache, max-age=0");
        }
        else
        {
            response.Headers["Cache-Control"] = "no-store, no-cache, max-age=0";
        }

        if (!response.Headers.ContainsKey("Pragma"))
        {
            response.Headers.Add("Pragma", "no-cache");
        }
    }

    public static void SetNoReferrer(this HttpResponse response)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (!response.Headers.ContainsKey("Referrer-Policy"))
        {
            response.Headers.Add("Referrer-Policy", "no-referrer");
        }
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

        if (!response.Headers.ContainsKey("Content-Security-Policy"))
        {
            response.Headers.Add("Content-Security-Policy", cspHeader);
        }

        if (cspOptions.AddDeprecatedHeader && !response.Headers.ContainsKey("X-Content-Security-Policy"))
        {
            response.Headers.Add("X-Content-Security-Policy", cspHeader);
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
