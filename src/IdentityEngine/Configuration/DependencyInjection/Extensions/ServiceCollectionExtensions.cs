using IdentityEngine.Configuration.DependencyInjection.Builder;
using IdentityEngine.Configuration.Options;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityEngine.Configuration.DependencyInjection.Extensions;

public static class ServiceCollectionExtensions
{
    public static IIdentityEngineBuilder AddIdentityEngineBuilder(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        return new IdentityEngineBuilder(services);
    }

    public static IIdentityEngineBuilder AddIdentityEngine(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        var builder = services.AddIdentityEngineBuilder();
        builder
            .AddRequiredPlatformServices()
            .AddCookieAuthentication();
        return builder;
    }

    public static IIdentityEngineBuilder AddIdentityEngine(
        this IServiceCollection services,
        Action<IdentityEngineOptions> setupAction)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(setupAction);
        services.Configure(setupAction);
        return services.AddIdentityEngine();
    }

    public static IIdentityEngineBuilder AddIdentityEngine(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        services.Configure<IdentityEngineOptions>(configuration);
        return services.AddIdentityEngine();
    }

    public static IServiceCollection ConfigureSameSiteNoneCookiePolicy(this IServiceCollection services)
    {
        // https://devblogs.microsoft.com/aspnet/upcoming-samesite-cookie-changes-in-asp-net-and-asp-net-core/
        ArgumentNullException.ThrowIfNull(services);
        services.Configure<CookiePolicyOptions>(options =>
        {
            options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
            options.OnAppendCookie = static cookieContext =>
            {
                CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
            };
            options.OnDeleteCookie = static cookieContext =>
                CheckSameSite(cookieContext.Context, cookieContext.CookieOptions);
        });
        return services;

        static void CheckSameSite(HttpContext httpContext, CookieOptions options)
        {
            if (options.SameSite == SameSiteMode.None)
            {
                var userAgent = httpContext.Request.Headers.UserAgent;
                if (!httpContext.Request.IsHttps || DisallowsSameSiteNone(userAgent))
                {
                    options.SameSite = SameSiteMode.Unspecified;
                }
            }
        }

        static bool DisallowsSameSiteNone(string userAgent)
        {
            // Cover all iOS based browsers here. This includes:
            // - Safari on iOS 12 for iPhone, iPod Touch, iPad
            // - WkWebview on iOS 12 for iPhone, iPod Touch, iPad
            // - Chrome on iOS 12 for iPhone, iPod Touch, iPad
            // All of which are broken by SameSite=None, because they use the iOS networking stack
            if (userAgent.Contains("CPU iPhone OS 12", StringComparison.Ordinal) ||
                userAgent.Contains("iPad; CPU OS 12", StringComparison.Ordinal))
            {
                return true;
            }

            // Cover Mac OS X based browsers that use the Mac OS networking stack. This includes:
            // - Safari on Mac OS X.
            // This does not include:
            // - Chrome on Mac OS X
            // Because they do not use the Mac OS networking stack.
            if (userAgent.Contains("Macintosh; Intel Mac OS X 10_14", StringComparison.Ordinal)
                && userAgent.Contains("Version/", StringComparison.Ordinal)
                && userAgent.Contains("Safari", StringComparison.Ordinal))
            {
                return true;
            }

            // Cover Chrome 50-69, because some versions are broken by SameSite=None,
            // and none in this range require it.
            // Note: this covers some pre-Chromium Edge versions,
            // but pre-Chromium Edge does not require SameSite=None.
            return userAgent.Contains("Chrome/5", StringComparison.Ordinal) || userAgent.Contains("Chrome/6", StringComparison.Ordinal);
        }
    }
}
