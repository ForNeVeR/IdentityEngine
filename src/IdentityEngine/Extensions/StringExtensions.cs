using System.Security.Cryptography;
using System.Text;

namespace IdentityEngine.Extensions;

public static class StringExtensions
{
    public static string ToSha256(this string input)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        Span<byte> hashBuffer = stackalloc byte[256 / 8];
        var maxUtf8Bytes = Encoding.UTF8.GetMaxByteCount(input.Length);
        if (maxUtf8Bytes <= 1024)
        {
            Span<byte> inputBuffer = stackalloc byte[maxUtf8Bytes];
            var utf8BytesCount = Encoding.UTF8.GetBytes(input.AsSpan(), inputBuffer);
            SHA256.HashData(inputBuffer[..utf8BytesCount], hashBuffer);
        }
        else
        {
            var utf8Bytes = Encoding.UTF8.GetBytes(input);
            SHA256.HashData(utf8Bytes, hashBuffer);
        }

        return Convert.ToBase64String(hashBuffer);
    }
}
