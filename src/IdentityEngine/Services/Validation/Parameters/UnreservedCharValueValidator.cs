using System.Runtime.CompilerServices;

namespace IdentityEngine.Services.Validation.Parameters;

public static class UnreservedCharValueValidator
{
    public static bool IsValid(ReadOnlySpan<char> value)
    {
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05#appendix-A.18
        foreach (var ch in value)
        {
            if (!IsUnreserved(ch))
            {
                return false;
            }
        }

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsUnreserved(char ch)
    {
        return IsAlpha(ch) || IsDigit(ch) || IsAllowedNonAlphaOrDigit(ch);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsAlpha(char ch)
    {
        return ch is >= 'A' and <= 'Z' or >= 'a' and <= 'z'; // A is 0x41, Z is 0x5a, a is 0x61, z is 0x7a
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsDigit(char ch)
    {
        return ch is >= '0' and <= '9'; // 0 is 0x30, 9 is 0x39
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    private static bool IsAllowedNonAlphaOrDigit(char ch)
    {
        return ch is '-' or '.' or '_' or '~';
    }
}
