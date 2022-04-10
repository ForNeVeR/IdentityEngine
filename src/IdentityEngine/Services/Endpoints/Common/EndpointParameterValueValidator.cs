namespace IdentityEngine.Services.Endpoints.Common;

public static class EndpointParameterValueValidator
{
    public static bool IsValid(ReadOnlySpan<char> value)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#section-6.2
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.16
        foreach (var ch in value)
        {
            if (!((ch >= 0x30 && ch <= 0x39) || (ch >= 0x41 && ch <= 0x5a) || (ch >= 0x61 && ch <= 0x7a) || ch is '-' or '.' or '_'))
            {
                return false;
            }
        }

        return true;
    }
}
