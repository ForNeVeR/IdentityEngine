using IdentityEngine.Configuration.Options;
using IdentityEngine.Endpoints;
using IdentityEngine.Endpoints.Handlers;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityEngine.Configuration.DependencyInjection.Extensions;

public static class EndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapIdentityEngineEndpoints(this IEndpointRouteBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var options = builder.ServiceProvider.GetRequiredService<IdentityEngineOptions>();
        if (options.Endpoints.Authorize.Enable)
        {
            builder.AddEndpoint<IAuthorizeEndpointHandler>(
                options.Endpoints.Authorize.Path,
                new(new[] { HttpMethods.Get, HttpMethods.Post }));
            builder.AddEndpoint<IAuthorizeEndpointCallbackHandler>(
                options.Endpoints.Authorize.CallbackPath,
                new(new[] { HttpMethods.Get }));
        }

        return builder;
    }

    public static void AddEndpoint<THandler>(
        this IEndpointRouteBuilder builder,
        string path,
        HttpMethodMetadata metadata)
        where THandler : class, IEndpointHandler
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(metadata);
        var endpointBuilder = builder.Map(
            RoutePatternFactory.Parse(path),
            static async httpContext =>
            {
                httpContext.RequestAborted.ThrowIfCancellationRequested();
                var handler = httpContext.RequestServices.GetRequiredService<THandler>();
                var result = await handler.HandleAsync(httpContext).ConfigureAwait(false);
                await result.ExecuteAsync(httpContext).ConfigureAwait(false);
            });
        endpointBuilder.WithMetadata(metadata);
        endpointBuilder.WithDisplayName($"{path} HTTP: {string.Join(", ", metadata.HttpMethods)}");
    }
}
