namespace PostQuantum.Cryptography.Tests;

internal static class TestHelpers
{
    public static byte[] Hex(string hex) => Convert.FromHexString(hex);

    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
}
