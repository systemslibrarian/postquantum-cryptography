using System.Security.Cryptography;
using PostQuantum.Cryptography.Internal;

#pragma warning disable SYSLIB5006 // SLH-DSA shares this; we touch only ML-DSA APIs here.

namespace PostQuantum.Cryptography;

/// <summary>
/// Byte-oriented, one-shot ML-DSA (FIPS 204) operations. Each method takes
/// raw byte spans, performs the operation against a transient key handle, and
/// returns raw byte arrays — there is no key object for the caller to dispose.
/// </summary>
/// <remarks>
/// <para>
/// Companion to <see cref="MlKemOperations"/>. Use this when you have a
/// signing or verifying need that doesn't justify holding a key object: e.g.
/// "verify this signed package's signature against a pinned public key".
/// For long-lived signing keys, prefer the typed
/// <see cref="MLDsaPrivateKey"/> / <see cref="MLDsaPublicKey"/> API.
/// </para>
/// <para>
/// <b>Algorithm selection:</b> pass the BCL parameter set
/// (<see cref="MLDsaAlgorithm.MLDsa44"/> / <see cref="MLDsaAlgorithm.MLDsa65"/>
/// / <see cref="MLDsaAlgorithm.MLDsa87"/>). 87 is the conservative default for
/// long-lived signatures.
/// </para>
/// </remarks>
public static class MLDsaOperations
{
    /// <summary>
    /// Generates a fresh ML-DSA key pair and returns both halves as raw byte
    /// arrays — the public key and the 32-byte private seed that
    /// deterministically derives the pair.
    /// </summary>
    public static (byte[] PublicKey, byte[] PrivateSeed) GenerateKeyPair(MLDsaAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(algorithm);

        using MLDsaPrivateKey priv = new(MLDsa.GenerateKey(algorithm));
        return (priv.ExportPublicKey(), priv.ExportPrivateSeed());
    }

    /// <summary>
    /// Signs <paramref name="data"/> using a private key derived from
    /// <paramref name="privateSeed"/> (32 bytes for all ML-DSA parameter sets).
    /// </summary>
    public static byte[] SignData(
        MLDsaAlgorithm algorithm,
        ReadOnlySpan<byte> privateSeed,
        ReadOnlySpan<byte> data)
        => SignData(algorithm, privateSeed, data, context: default);

    /// <summary>
    /// Signs <paramref name="data"/> bound to a usage <paramref name="context"/>
    /// (FIPS 204 §5.2) using a private key derived from <paramref name="privateSeed"/>.
    /// </summary>
    public static byte[] SignData(
        MLDsaAlgorithm algorithm,
        ReadOnlySpan<byte> privateSeed,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> context)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        EnsureLength(privateSeed, algorithm.PrivateSeedSizeInBytes, nameof(privateSeed), algorithm, "private seed");
        MLDsaLimits.EnsureContextLength(context, nameof(context));

        using MLDsa dsa = MLDsa.ImportMLDsaPrivateSeed(algorithm, privateSeed);
        byte[] signature = new byte[algorithm.SignatureSizeInBytes];
        dsa.SignData(data, signature, context);
        return signature;
    }

    /// <summary>
    /// Verifies a signature over <paramref name="data"/> against
    /// <paramref name="publicKey"/>.
    /// </summary>
    public static bool VerifyData(
        MLDsaAlgorithm algorithm,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
        => VerifyData(algorithm, publicKey, data, signature, context: default);

    /// <summary>
    /// Verifies a context-bound signature over <paramref name="data"/> against
    /// <paramref name="publicKey"/>. The verifier must supply the same
    /// <paramref name="context"/> bytes that the signer used.
    /// </summary>
    public static bool VerifyData(
        MLDsaAlgorithm algorithm,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> context)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        EnsureLength(publicKey, algorithm.PublicKeySizeInBytes, nameof(publicKey), algorithm, "public key");
        MLDsaLimits.EnsureContextLength(context, nameof(context));

        // Verify is tolerant of wrong-size signatures — return false instead
        // of throwing on signature-length mismatch (matches BCL behavior).
        if (signature.Length != algorithm.SignatureSizeInBytes)
        {
            return false;
        }

        using MLDsa dsa = MLDsa.ImportMLDsaPublicKey(algorithm, publicKey);
        return dsa.VerifyData(data, signature, context);
    }

    private static void EnsureLength(ReadOnlySpan<byte> input, int expected, string paramName, MLDsaAlgorithm algorithm, string what)
    {
        if (input.Length != expected)
        {
            throw new ArgumentException(
                $"Expected a {expected}-byte {what} for {algorithm.Name} but got {input.Length} bytes.",
                paramName);
        }
    }
}
