using System.Security.Cryptography;

namespace PostQuantum.Cryptography.Internal;

/// <summary>
/// Disambiguates PEM payloads before they reach a typed import helper, so that
/// passing (for example) a public-key PEM to a "Import<i>Private</i>KeyFromPem"
/// fails fast with a clear <see cref="ArgumentException"/> instead of succeeding
/// silently and then throwing a confusing <see cref="CryptographicException"/>
/// later when a private-key-only operation is invoked.
/// </summary>
internal static class PemLabels
{
    internal const string PublicKey = "PUBLIC KEY";
    internal const string PrivateKey = "PRIVATE KEY";
    internal const string EncryptedPrivateKey = "ENCRYPTED PRIVATE KEY";

    public static void RequirePrivateKeyLabel(ReadOnlySpan<char> pem)
    {
        string label = ReadFirstLabel(pem);
        if (label == PrivateKey)
        {
            return;
        }

        if (label == EncryptedPrivateKey)
        {
            throw new ArgumentException(
                "Encrypted PKCS#8 private-key PEM is not supported by this overload. " +
                "Decrypt it first, or use the BCL's encrypted-import APIs directly.",
                nameof(pem));
        }

        throw new ArgumentException(
            $"Expected a PEM-encoded PKCS#8 private key (-----BEGIN PRIVATE KEY-----) but found '{label}'.",
            nameof(pem));
    }

    public static void RequirePublicKeyLabel(ReadOnlySpan<char> pem)
    {
        string label = ReadFirstLabel(pem);
        if (label == PublicKey)
        {
            return;
        }

        throw new ArgumentException(
            $"Expected a PEM-encoded SubjectPublicKeyInfo (-----BEGIN PUBLIC KEY-----) but found '{label}'.",
            nameof(pem));
    }

    private static string ReadFirstLabel(ReadOnlySpan<char> pem)
    {
        if (!PemEncoding.TryFind(pem, out PemFields fields))
        {
            throw new ArgumentException("Input is not a valid PEM-encoded structure.", nameof(pem));
        }

        return pem[fields.Label].ToString();
    }
}
