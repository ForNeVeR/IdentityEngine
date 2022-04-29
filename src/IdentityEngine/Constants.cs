using System.Diagnostics.CodeAnalysis;

namespace IdentityEngine;

[SuppressMessage("Design", "CA1034:Nested types should not be visible")]
[SuppressMessage("Design", "CA1724:The type name conflicts")]
[SuppressMessage("ReSharper", "MemberHidesStaticFromOuterClass")]
public static class Constants
{
    public static class AuthenticationSchemes
    {
        public const string DefaultIdentityEngineCookie = "idngn";
        public const string DefaultIdentityEngineExternalCookie = "idngn.ext";
    }

    public static class ClaimTypes
    {
        public const string SubjectId = "i:sub";
        public const string Login = "i:login";
        public const string AuthenticationTime = "i:auth_time";
        public const string IdentityProvider = "i:idp";
        public const string SessionId = "i:sid";

        public static class Values
        {
            public const string LocalIdentityProvider = "local";
        }
    }

    public static class JwtClaims
    {
        public const string Subject = "sub";
    }

    public static class Ui
    {
        public static class DefaultRoutes
        {
            public const string Authorize = "/connect/authorize";
            public const string AuthorizeCallback = "/connect/authorize/callback";

            public const string Error = "/error";
            public const string Login = "/login";
            public const string Consent = "/consent";
        }

        public static class DefaultRoutesParameters
        {
            public const string ErrorId = "errorId";
            public const string AuthorizeRequestId = "authzId";
        }
    }

    public static class Requests
    {
        public static class Authorize
        {
            public const string ClientId = "client_id";
            public const string CodeChallenge = "code_challenge";
            public const string CodeChallengeMethod = "code_challenge_method";
            public const string RedirectUri = "redirect_uri";
            public const string ResponseType = "response_type";
            public const string Scope = "scope";
            public const string State = "state";
            public const string ResponseMode = "response_mode";

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
        public const string State = "state";
        public const string Error = "error";
        public const string ErrorDescription = "error_description";
        public const string Issuer = "iss";

        public static class Errors
        {
            public static class Values
            {
                public const string InvalidRequest = "invalid_request";
                public const string UnauthorizedClient = "unauthorized_client";
                public const string AccessDenied = "access_denied";
                public const string UnsupportedResponseType = "unsupported_response_type";
                public const string InvalidScope = "invalid_scope";
                public const string ServerError = "server_error";
                public const string TemporarilyUnavailable = "temporarily_unavailable";

                public static class OpenIdConnect
                {
                    public const string InteractionRequired = "interaction_required";
                    public const string LoginRequired = "login_required";
                    public const string AccountSelectionRequired = "account_selection_required";
                    public const string ConsentRequired = "consent_required";
                    public const string InvalidRequestUri = "invalid_request_uri";
                    public const string InvalidRequestObject = "invalid_request_object";
                    public const string RequestNotSupported = "request_not_supported";
                    public const string RequestUriNotSupported = "request_uri_not_supported";
                    public const string RegistrationNotSupported = "registration_not_supported";
                }
            }
        }

        public static class Authorize
        {
            public const string Code = "code";
        }
    }

    public static class Intermediate
    {
        public static class RequiredInteractions
        {
            public const string AuthenticateUser = "authz";
            public const string Consent = "consent";
            public const string ReAuthenticateUser = "reauthz";
        }
    }

    public static class Configuration
    {
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
