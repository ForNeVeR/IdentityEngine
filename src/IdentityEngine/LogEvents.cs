using System.Diagnostics.CodeAnalysis;

namespace IdentityEngine;

[SuppressMessage("Design", "CA1034:Nested types should not be visible")]
public static class LogEvents
{
    public static class AuthorizeEndpointHandler
    {
        public const int Start = 100_000_000;
        public const int EndSuccessful = 100_000_001;
        public const int EndMethodNotAllowed = 100_000_002;
        public const int EndUnsupportedMediaType = 100_000_003;
        public const int EndRequestValidationError = 100_000_004;
        public const int EndUserAuthenticationError = 100_000_005;
    }

    public static class UserAuthenticationService
    {
        public const int Start = 100_001_000;
        public const int EndAuthenticationSchemeNotFound = 100_001_001;
        public const int EndAuthenticationHandlerNotFound = 100_001_002;
        public const int EndUserNotAuthenticated = 100_001_003;
        public const int EndSuccessful = 100_001_004;
    }

    public static class AuthorizeRequestValidator
    {
        public const int Start = 100_002_000;
    }
}
