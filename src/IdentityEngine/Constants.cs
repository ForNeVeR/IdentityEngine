using System.Diagnostics.CodeAnalysis;

namespace IdentityEngine;

[SuppressMessage("Design", "CA1034:Nested types should not be visible")]
[SuppressMessage("Design", "CA1724:The type name conflicts")]
[SuppressMessage("ReSharper", "MemberHidesStaticFromOuterClass")]
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
            public static readonly string Error = "/error";
        }

        public static class DefaultRoutesParameters
        {
            public static readonly string ErrorId = "errorId";
        }
    }

    public static class Requests
    {
        public static class Authorize
        {
            public static readonly string ClientId = "client_id";
            public static readonly string CodeChallenge = "code_challenge";
            public static readonly string CodeChallengeMethod = "code_challenge_method";
            public static readonly string RedirectUri = "redirect_uri";
            public static readonly string ResponseType = "response_type";
            public static readonly string Scope = "scope";
            public static readonly string State = "state";
            public static readonly string ResponseMode = "response_mode";

            public static class OpenIdConnect
            {
                public const string Nonce = "nonce";
                public const string Display = "display";
                public const string Prompt = "prompt";
                public const string MaxAge = "max_age";
                public const string UiLocales = "ui_locales";
                public const string LoginHint = "login_hint";
                public const string AcrValues = "acr_values";
                public const string Request = "request";
                public const string RequestUri = "request_uri";
                public const string Registration = "registration";

                public static class Values
                {
                    public static class Display
                    {
                        public const string Page = "page";
                        public const string Popup = "popup";
                        public const string Touch = "touch";
                        public const string Wap = "wap";
                    }

                    public static class Prompt
                    {
                        public const string None = "none";
                        public const string Login = "login";
                        public const string Consent = "consent";
                        public const string SelectAccount = "select_account";
                    }
                }
            }

            public static class Values
            {
                public static class ResponseMode
                {
                    public const string Query = "query";
                    public const string FormPost = "form_post";
                }

                public static class ResponseType
                {
                    public const string Code = "code";
                }

                public static class CodeChallengeMethod
                {
                    public const string Plain = "plain";
                    public const string S256 = "S256";
                }
            }
        }

        public static class Values
        {
            public static class Scope
            {
                public const string OpenId = "openid";
                public const string OfflineAccess = "offline_access";
            }
        }
    }

    public static class Responses
    {
        public static readonly string State = "state";
        public static readonly string Error = "error";
        public static readonly string ErrorDescription = "error_description";

        public static class Errors
        {
            public static class Values
            {
                public static readonly string InvalidRequest = "invalid_request";
                public static readonly string UnauthorizedClient = "unauthorized_client";
                public static readonly string AccessDenied = "access_denied";
                public static readonly string UnsupportedResponseType = "unsupported_response_type";
                public static readonly string InvalidScope = "invalid_scope";
                public static readonly string ServerError = "server_error";
                public static readonly string TemporarilyUnavailable = "temporarily_unavailable";

                public static class OpenIdConnect
                {
                    public static readonly string InteractionRequired = "interaction_required";
                    public static readonly string LoginRequired = "login_required";
                    public static readonly string AccountSelectionRequired = "account_selection_required";
                    public static readonly string ConsentRequired = "consent_required";
                    public static readonly string InvalidRequestUri = "invalid_request_uri";
                    public static readonly string InvalidRequestObject = "invalid_request_object";
                    public static readonly string RequestNotSupported = "request_not_supported";
                    public static readonly string RequestUriNotSupported = "request_uri_not_supported";
                    public static readonly string RegistrationNotSupported = "registration_not_supported";
                }
            }
        }

        public static class Authorize
        {
            public static readonly string Code = "code";
        }
    }

    public static class Configuration
    {
        [SuppressMessage("ReSharper", "InconsistentNaming")]
        [SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores")]
        public static class Protocols
        {
            public const string OAuth_2_1 = "oauth2_1";
            public const string OpenIdConnect_1_0 = "oidc1_0";
        }

        public static class SecretTypes
        {
            public const string Pbkdf2Sha256 = "pbkdf2:sha256";
        }

        public static class EndpointAuthenticationMethods
        {
            public const string PostBody = "client_secret_post";
            public const string BasicAuthentication = "client_secret_basic";
        }

        public static class GrantTypes
        {
            public const string AuthorizationCode = "authorization_code";
            public const string ClientCredentials = "client_credentials";
            public const string DeviceFlow = "urn:ietf:params:oauth:grant-type:device_code";
        }
    }
}
