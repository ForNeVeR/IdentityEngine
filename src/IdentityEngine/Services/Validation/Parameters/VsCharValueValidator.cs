namespace IdentityEngine.Services.Validation.Parameters;

public static class VsCharValueValidator
{
    public static bool IsValid(ReadOnlySpan<char> value)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A
        foreach (var ch in value)
        {
            if (ch is < ' ' or > '~') // space is 0x20, ~ is 0x7e
            {
                return false;
            }
        }

        return true;
    }
}
