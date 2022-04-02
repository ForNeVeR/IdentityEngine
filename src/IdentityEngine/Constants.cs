using System.Diagnostics.CodeAnalysis;

namespace IdentityEngine;

[SuppressMessage("Design", "CA1034:Nested types should not be visible")]
public static class Constants
{
    public static class AuthenticationSchemes
    {
        public static readonly string DefaultIdentityEngineCookie = "idngn";
        public static readonly string DefaultIdentityEngineExternalCookie = "idngn.ext";
    }

    public static class JwtClaims
    {
        public static readonly string Subject = "sub";
    }

    public static class Ui
    {
        public static class DefaultRoutes
        {
            public static readonly string Authorize = "/connect/authorize";
            public static readonly string AuthorizeCallback = "/connect/authorize/callback";
        }
    }

    public static class Responses
    {
        public static class Errors
        {
            public static class Values
            {
                public static readonly string ServerError = "server_error";
            }
        }
    }
}
