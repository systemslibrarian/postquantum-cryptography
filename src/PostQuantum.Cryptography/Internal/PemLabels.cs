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
                "This is an encrypted PKCS#8 private-key PEM. Use " +
                "ImportEncryptedPrivateKeyFromPem with the password instead.",
                nameof(pem));
        }

        throw new ArgumentException(
            $"Expected a PEM-encoded PKCS#8 private key (-----BEGIN PRIVATE KEY-----) but found '{label}'.",
            nameof(pem));
    }

    public static void RequireEncryptedPrivateKeyLabel(ReadOnlySpan<char> pem)
    {
        string label = ReadFirstLabel(pem);
        if (label == EncryptedPrivateKey)
        {
            return;
        }

        if (label == PrivateKey)
        {
            throw new ArgumentException(
                "The first PEM block is an unencrypted PKCS#8 private key. If that key is " +
                "the one you intend to import, use ImportPrivateKeyFromPem (no password); " +
                "if you expected an encrypted key, pass a PEM whose first block is " +
                "-----BEGIN ENCRYPTED PRIVATE KEY-----.",
                nameof(pem));
        }

        throw new ArgumentException(
            $"Expected a PEM-encoded encrypted PKCS#8 private key (-----BEGIN ENCRYPTED PRIVATE KEY-----) but found '{label}'.",
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
