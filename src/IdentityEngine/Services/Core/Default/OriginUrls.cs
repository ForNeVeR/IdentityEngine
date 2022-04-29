using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Core.Default;

public class OriginUrls : IOriginUrls
{
    public string GetOrigin(HttpContext httpContext)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        return httpContext.Request.Scheme + Uri.SchemeDelimiter + httpContext.Request.Host + httpContext.Request.PathBase;
    }
}
