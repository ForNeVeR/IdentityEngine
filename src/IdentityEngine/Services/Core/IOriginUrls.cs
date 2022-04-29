using Microsoft.AspNetCore.Http;

namespace IdentityEngine.Services.Core;

public interface IOriginUrls
{
    string GetOrigin(HttpContext httpContext);
}
