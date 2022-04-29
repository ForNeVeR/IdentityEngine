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
        public const int EndUnredirectableRequestValidationError = 100_000_004;
        public const int EndUserAuthenticationError = 100_000_005;
        public const int EndInteractionValidationError = 100_000_006;
    }

    public static class UserAuthenticationService
    {
        public const int Start = 100_002_000;
        public const int EndAuthenticationSchemeNotFound = 100_002_001;
        public const int EndAuthenticationHandlerNotFound = 100_002_002;
        public const int EndUserNotAuthenticated = 100_002_003;
        public const int EndSuccessful = 100_002_004;
    }
}
