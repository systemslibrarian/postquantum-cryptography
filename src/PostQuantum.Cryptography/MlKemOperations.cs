using System.Security.Cryptography;

namespace PostQuantum.Cryptography;

/// <summary>
/// Byte-oriented, one-shot ML-KEM (FIPS 203) operations. Each method takes
/// raw byte spans, performs the operation against a transient key handle, and
/// returns raw byte arrays — there is no key object for the caller to dispose.
/// </summary>
/// <remarks>
/// <para>
/// This is the simplest possible surface for "I just want to do one KEM
/// operation and move on": fire-and-forget. It's a complement to, not a
/// replacement for, the typed API (<see cref="MLKem768"/> and friends), which
/// is the right choice when a single key is reused across many operations or
/// when you want explicit ownership of the underlying native handle.
/// </para>
/// <para>
/// Every method here internally imports the necessary key, performs the
/// operation, and disposes the handle — including zeroing any intermediate
/// secrets. The price is one extra import per call; the win is no
/// <c>using</c>, no <see cref="IDisposable"/>, no chance of leaking a key
/// object.
/// </para>
/// <para>
/// <b>Algorithm selection:</b> pass the BCL parameter set
/// (<see cref="MLKemAlgorithm.MLKem512"/> / <see cref="MLKemAlgorithm.MLKem768"/>
/// / <see cref="MLKemAlgorithm.MLKem1024"/>). 768 is the recommended general
/// default.
/// </para>
/// </remarks>
public static class MlKemOperations
{
    /// <summary>
    /// Generates a fresh ML-KEM key pair and returns both halves as raw byte
    /// arrays — the encapsulation (public) key and the 64-byte private seed
    /// (<c>d || z</c>) that deterministically derives the key pair.
    /// </summary>
    /// <param name="algorithm">The ML-KEM parameter set (512, 768, or 1024).</param>
    public static (byte[] EncapsulationKey, byte[] PrivateSeed) GenerateKeyPair(MLKemAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(algorithm);

        using MLKemPrivateKey priv = new(MLKem.GenerateKey(algorithm));
        return (priv.ExportEncapsulationKey(), priv.ExportPrivateSeed());
    }

    /// <summary>
    /// Encapsulates a fresh random shared secret to the recipient's
    /// <paramref name="encapsulationKey"/>. Returns both halves of the
    /// resulting <see cref="KemEncapsulation"/>.
    /// </summary>
    public static KemEncapsulation Encapsulate(MLKemAlgorithm algorithm, ReadOnlySpan<byte> encapsulationKey)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        EnsureLength(encapsulationKey, algorithm.EncapsulationKeySizeInBytes, nameof(encapsulationKey), algorithm, "encapsulation key");

        using MLKem kem = MLKem.ImportEncapsulationKey(algorithm, encapsulationKey);
        kem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret);
        return new KemEncapsulation(ciphertext, sharedSecret);
    }

    /// <summary>
    /// Recovers the shared secret from a <paramref name="ciphertext"/> using
    /// the expanded <paramref name="decapsulationKey"/>.
    /// </summary>
    /// <remarks>
    /// If you have a 64-byte <i>private seed</i> instead of the expanded
    /// decapsulation key, use <see cref="DecapsulateFromSeed"/>.
    /// </remarks>
    public static byte[] Decapsulate(
        MLKemAlgorithm algorithm,
        ReadOnlySpan<byte> decapsulationKey,
        ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        EnsureLength(decapsulationKey, algorithm.DecapsulationKeySizeInBytes, nameof(decapsulationKey), algorithm, "decapsulation key");
        EnsureLength(ciphertext, algorithm.CiphertextSizeInBytes, nameof(ciphertext), algorithm, "ciphertext");

        using MLKem kem = MLKem.ImportDecapsulationKey(algorithm, decapsulationKey);
        byte[] sharedSecret = new byte[algorithm.SharedSecretSizeInBytes];
        kem.Decapsulate(ciphertext, sharedSecret);
        return sharedSecret;
    }

    /// <summary>
    /// Recovers the shared secret from a <paramref name="ciphertext"/> using
    /// the 64-byte ML-KEM <paramref name="privateSeed"/> (<c>d || z</c>) that
    /// deterministically derives the key pair. Equivalent to importing the
    /// seed and then calling <see cref="Decapsulate"/>.
    /// </summary>
    public static byte[] DecapsulateFromSeed(
        MLKemAlgorithm algorithm,
        ReadOnlySpan<byte> privateSeed,
        ReadOnlySpan<byte> ciphertext)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        EnsureLength(privateSeed, algorithm.PrivateSeedSizeInBytes, nameof(privateSeed), algorithm, "private seed");
        EnsureLength(ciphertext, algorithm.CiphertextSizeInBytes, nameof(ciphertext), algorithm, "ciphertext");

        using MLKem kem = MLKem.ImportPrivateSeed(algorithm, privateSeed);
        byte[] sharedSecret = new byte[algorithm.SharedSecretSizeInBytes];
        kem.Decapsulate(ciphertext, sharedSecret);
        return sharedSecret;
    }

    private static void EnsureLength(ReadOnlySpan<byte> input, int expected, string paramName, MLKemAlgorithm algorithm, string what)
    {
        if (input.Length != expected)
        {
            throw new ArgumentException(
                $"Expected a {expected}-byte {what} for {algorithm.Name} but got {input.Length} bytes.",
                paramName);
        }
    }
}
