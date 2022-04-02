using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace IdentityEngine.Extensions;

public static class HttpRequestExtensions
{
    public static bool HasApplicationFormContentType(this HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        return MediaTypeHeaderValue.TryParse(request.ContentType, out var header)
               && header.MediaType.Equals("application/x-www-form-urlencoded", StringComparison.Ordinal);
    }
}
