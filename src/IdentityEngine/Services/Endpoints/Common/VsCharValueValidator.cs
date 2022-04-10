namespace IdentityEngine.Services.Endpoints.Common;

public static class VsCharValueValidator
{
    public static bool IsValid(ReadOnlySpan<char> value)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A
        foreach (var ch in value)
        {
            if (!(ch >= 0x20 && ch <= 0x7e))
            {
                return false;
            }
        }

        return true;
    }
}
