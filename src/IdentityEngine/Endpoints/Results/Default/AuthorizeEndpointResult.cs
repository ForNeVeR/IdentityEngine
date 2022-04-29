using IdentityEngine.Services.Endpoints.Authorize.Models.ResponseGenerator;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace IdentityEngine.Endpoints.Results.Default;

public class AuthorizeEndpointResult : IEndpointHandlerResult
{
    private readonly string _issuer;
    private readonly string _redirectUrl;
    private readonly AuthorizeResponse _response;

    public AuthorizeEndpointResult(string redirectUrl, string issuer, AuthorizeResponse response)
    {
        _redirectUrl = redirectUrl;
        _issuer = issuer;
        _response = response;
    }

    public Task ExecuteAsync(HttpContext httpContext, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(httpContext);
        cancellationToken.ThrowIfCancellationRequested();
        httpContext.Response.Redirect(QueryHelpers.AddQueryString(
            _redirectUrl,
            BuildParameters()));
        return Task.CompletedTask;
    }

    private IEnumerable<KeyValuePair<string, string?>> BuildParameters()
    {
        yield return new(Constants.Responses.Authorize.Code, _response.Code);
        if (_response.State != null)
        {
            yield return new(Constants.Responses.State, _response.State);
        }

        yield return new(Constants.Responses.Issuer, _issuer);
    }
}
