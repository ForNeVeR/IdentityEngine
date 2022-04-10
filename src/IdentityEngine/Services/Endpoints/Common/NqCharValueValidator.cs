namespace IdentityEngine.Services.Endpoints.Common;

public static class NqCharValueValidator
{
    public static bool IsValid(ReadOnlySpan<char> value)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A
        foreach (var ch in value)
        {
            if (!(ch == 0x21 || (ch >= 0x23 && ch <= 0x5b) || (ch >= 0x5d && ch <= 0x7e)))
            {
                return false;
            }
        }

        return true;
    }
}
