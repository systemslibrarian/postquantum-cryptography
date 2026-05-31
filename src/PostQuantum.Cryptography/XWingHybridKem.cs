namespace PostQuantum.Cryptography;

/// <summary>
/// Byte-oriented, one-shot X-Wing hybrid KEM operations
/// (<c>draft-connolly-cfrg-xwing-kem</c>: ML-KEM-768 ⊕ X25519). Each method
/// takes raw byte spans and returns raw byte arrays — there is no key object
/// for the caller to dispose.
/// </summary>
/// <remarks>
/// <para>
/// Companion to <see cref="MlKemOperations"/> / <see cref="MLDsaOperations"/>.
/// This is the simplest possible entry point for "do one X-Wing handshake
/// and move on" — it bundles import + operation + dispose into a single call.
/// </para>
/// <para>
/// For repeated operations against the same recipient (e.g. a server doing
/// many handshakes with the same long-lived key pair) prefer the typed API
/// (<see cref="XWing"/> + <see cref="XWingPrivateKey"/> /
/// <see cref="XWingPublicKey"/>), which keeps the expanded key handles cached
/// across calls.
/// </para>
/// </remarks>
public static class XWingHybridKem
{
    /// <summary>Size, in bytes, of an X-Wing decapsulation key (a 32-byte seed).</summary>
    public const int DecapsulationKeySizeInBytes = XWing.DecapsulationKeySizeInBytes;

    /// <summary>Size, in bytes, of an X-Wing encapsulation key.</summary>
    public const int EncapsulationKeySizeInBytes = XWing.EncapsulationKeySizeInBytes;

    /// <summary>Size, in bytes, of an X-Wing ciphertext.</summary>
    public const int CiphertextSizeInBytes = XWing.CiphertextSizeInBytes;

    /// <summary>Size, in bytes, of an X-Wing shared secret.</summary>
    public const int SharedSecretSizeInBytes = XWing.SharedSecretSizeInBytes;

    /// <summary>Gets whether X-Wing is supported on the current platform.</summary>
    public static bool IsSupported => XWing.IsSupported;

    /// <summary>
    /// Generates a fresh X-Wing key pair and returns both halves as raw byte
    /// arrays — the 1216-byte encapsulation (public) key and the 32-byte
    /// decapsulation (private) key seed.
    /// </summary>
    public static (byte[] EncapsulationKey, byte[] DecapsulationKey) GenerateKeyPair()
    {
        using XWingPrivateKey priv = XWing.GenerateKeyPair();
        return (priv.ExportEncapsulationKey(), priv.ExportDecapsulationKey());
    }

    /// <summary>
    /// Encapsulates a fresh random shared secret to the recipient's
    /// <paramref name="encapsulationKey"/>. Returns the 1120-byte ciphertext
    /// (transmit to recipient) and the 32-byte shared secret (use as a
    /// symmetric key).
    /// </summary>
    public static KemEncapsulation Encapsulate(ReadOnlySpan<byte> encapsulationKey)
    {
        if (encapsulationKey.Length != EncapsulationKeySizeInBytes)
        {
            throw new ArgumentException(
                $"Expected a {EncapsulationKeySizeInBytes}-byte X-Wing encapsulation key but got {encapsulationKey.Length} bytes.",
                nameof(encapsulationKey));
        }

        using XWingPublicKey pub = XWing.ImportEncapsulationKey(encapsulationKey);
        return pub.Encapsulate();
    }

    /// <summary>
    /// Recovers the shared secret from <paramref name="ciphertext"/> using the
    /// 32-byte X-Wing <paramref name="decapsulationKey"/> (seed).
    /// </summary>
    public static byte[] Decapsulate(ReadOnlySpan<byte> decapsulationKey, ReadOnlySpan<byte> ciphertext)
    {
        if (decapsulationKey.Length != DecapsulationKeySizeInBytes)
        {
            throw new ArgumentException(
                $"Expected a {DecapsulationKeySizeInBytes}-byte X-Wing decapsulation key but got {decapsulationKey.Length} bytes.",
                nameof(decapsulationKey));
        }

        if (ciphertext.Length != CiphertextSizeInBytes)
        {
            throw new ArgumentException(
                $"Expected a {CiphertextSizeInBytes}-byte X-Wing ciphertext but got {ciphertext.Length} bytes.",
                nameof(ciphertext));
        }

        using XWingPrivateKey priv = XWing.ImportDecapsulationKey(decapsulationKey);
        return priv.Decapsulate(ciphertext);
    }
}
