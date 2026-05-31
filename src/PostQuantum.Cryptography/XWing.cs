using System.Security.Cryptography;
using PostQuantum.Cryptography.Internal;

namespace PostQuantum.Cryptography;

/// <summary>
/// High-level, secure-by-default API for the X-Wing hybrid key-encapsulation
/// mechanism, combining ML-KEM-768 with X25519.
/// </summary>
/// <remarks>
/// X-Wing (see <see href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">
/// draft-connolly-cfrg-xwing-kem</see>) is a hybrid PQ/T KEM. It runs ML-KEM-768
/// and X25519 in parallel and binds their outputs together with SHA3-256, so the
/// derived shared secret stays secure as long as <em>either</em> component remains
/// unbroken. This makes it a strong default for migrating transport and storage
/// protocols to post-quantum security without abandoning well-understood classical
/// cryptography.
///
/// Sizes are fixed: a 32-byte decapsulation key (a seed), a 1216-byte
/// encapsulation key, a 1120-byte ciphertext, and a 32-byte shared secret.
///
/// The ML-KEM-768 half uses the native .NET 10 implementation. The X25519 half
/// uses a constant-time implementation bundled with this library (see
/// <see cref="X25519"/>), because the BCL does not expose X25519.
/// </remarks>
public static class XWing
{
    /// <summary>Size, in bytes, of an X-Wing decapsulation (private) key, which is a 32-byte seed.</summary>
    public const int DecapsulationKeySizeInBytes = 32;

    /// <summary>Size, in bytes, of an X-Wing encapsulation (public) key (ML-KEM-768 || X25519).</summary>
    public const int EncapsulationKeySizeInBytes = 1216;

    /// <summary>Size, in bytes, of an X-Wing ciphertext (ML-KEM-768 || X25519).</summary>
    public const int CiphertextSizeInBytes = 1120;

    /// <summary>Size, in bytes, of the shared secret produced by encapsulation / decapsulation.</summary>
    public const int SharedSecretSizeInBytes = 32;

    // Internal component sizes, per the X-Wing specification.
    internal const int MLKemEncapsulationKeySize = 1184;
    internal const int MLKemCiphertextSize = 1088;
    internal const int X25519Size = 32;

    // XWingLabel = concat("\./", "/^\") == 0x5c 0x2e 0x2f 0x2f 0x5e 0x5c.
    private static ReadOnlySpan<byte> Label => [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

    /// <summary>
    /// Gets a value indicating whether X-Wing is supported on the current platform.
    /// </summary>
    public static bool IsSupported => MLKem.IsSupported && Shake256.IsSupported && SHA3_256.IsSupported;

    /// <summary>
    /// Generates a fresh X-Wing key pair using a cryptographically secure random
    /// number generator.
    /// </summary>
    public static XWingPrivateKey GenerateKeyPair()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(DecapsulationKeySizeInBytes);
        try
        {
            return XWingPrivateKey.FromSeed(seed);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
        }
    }

    /// <summary>
    /// Imports a private key from its 32-byte decapsulation key (seed).
    /// </summary>
    public static XWingPrivateKey ImportDecapsulationKey(ReadOnlySpan<byte> decapsulationKey)
    {
        if (decapsulationKey.Length != DecapsulationKeySizeInBytes)
        {
            throw new ArgumentException($"Decapsulation key must be {DecapsulationKeySizeInBytes} bytes.", nameof(decapsulationKey));
        }

        return XWingPrivateKey.FromSeed(decapsulationKey);
    }

    /// <summary>
    /// Imports a public key from its 1216-byte encapsulation key.
    /// </summary>
    public static XWingPublicKey ImportEncapsulationKey(ReadOnlySpan<byte> encapsulationKey)
    {
        if (encapsulationKey.Length != EncapsulationKeySizeInBytes)
        {
            throw new ArgumentException($"Encapsulation key must be {EncapsulationKeySizeInBytes} bytes.", nameof(encapsulationKey));
        }

        byte[] pkM = encapsulationKey[..MLKemEncapsulationKeySize].ToArray();
        byte[] pkX = encapsulationKey[MLKemEncapsulationKeySize..].ToArray();
        return new XWingPublicKey(pkM, pkX);
    }

    /// <summary>
    /// The X-Wing combiner: SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel).
    /// </summary>
    internal static byte[] Combiner(ReadOnlySpan<byte> ssM, ReadOnlySpan<byte> ssX, ReadOnlySpan<byte> ctX, ReadOnlySpan<byte> pkX)
    {
        byte[] sharedSecret = new byte[SharedSecretSizeInBytes];
        Combiner(ssM, ssX, ctX, pkX, sharedSecret);
        return sharedSecret;
    }

    /// <summary>
    /// The X-Wing combiner: SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
    /// written into the caller-provided <paramref name="destination"/>.
    /// </summary>
    internal static void Combiner(ReadOnlySpan<byte> ssM, ReadOnlySpan<byte> ssX, ReadOnlySpan<byte> ctX, ReadOnlySpan<byte> pkX, Span<byte> destination)
    {
        Span<byte> buffer = stackalloc byte[(X25519Size * 4) + 6];
        try
        {
            ssM.CopyTo(buffer);
            ssX.CopyTo(buffer[32..]);
            ctX.CopyTo(buffer[64..]);
            pkX.CopyTo(buffer[96..]);
            Label.CopyTo(buffer[128..]);

            SHA3_256.HashData(buffer, destination);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }
}

/// <summary>
/// An X-Wing public key (encapsulation key). Holds only public material.
/// </summary>
public sealed class XWingPublicKey
{
    private readonly byte[] _pkM; // ML-KEM-768 encapsulation key (1184 bytes)
    private readonly byte[] _pkX; // X25519 public key (32 bytes)

    internal XWingPublicKey(byte[] pkM, byte[] pkX)
    {
        _pkM = pkM;
        _pkX = pkX;
    }

    /// <summary>
    /// Encapsulates a fresh random shared secret to this public key.
    /// </summary>
    public KemEncapsulation Encapsulate()
    {
        byte[] ciphertext = new byte[XWing.CiphertextSizeInBytes];
        byte[] sharedSecret = new byte[XWing.SharedSecretSizeInBytes];
        EncapsulateCore(ciphertext, sharedSecret);
        return new KemEncapsulation(ciphertext, sharedSecret);
    }

    /// <summary>
    /// Encapsulates a fresh random shared secret to this public key, writing the
    /// 1120-byte ciphertext and 32-byte shared secret into the caller-provided
    /// buffers. This overload performs no allocation on the result path.
    /// </summary>
    public void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        if (ciphertext.Length != XWing.CiphertextSizeInBytes)
        {
            throw new ArgumentException($"Ciphertext buffer must be {XWing.CiphertextSizeInBytes} bytes.", nameof(ciphertext));
        }

        if (sharedSecret.Length != XWing.SharedSecretSizeInBytes)
        {
            throw new ArgumentException($"Shared-secret buffer must be {XWing.SharedSecretSizeInBytes} bytes.", nameof(sharedSecret));
        }

        EncapsulateCore(ciphertext, sharedSecret);
    }

    private void EncapsulateCore(Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        using MLKem mlkem = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, _pkM);
        byte[]? ekX = null;
        byte[]? ssX = null;
        try
        {
            Span<byte> ssM = stackalloc byte[MLKem768.SharedSecretSizeInBytes];
            mlkem.Encapsulate(ciphertext[..XWing.MLKemCiphertextSize], ssM);
            ekX = RandomNumberGenerator.GetBytes(XWing.X25519Size);
            byte[] ctX = X25519.ScalarMultBase(ekX);
            ssX = X25519.ScalarMult(ekX, _pkX);

            ctX.CopyTo(ciphertext[XWing.MLKemCiphertextSize..]);
            XWing.Combiner(ssM, ssX, ctX, _pkX, sharedSecret);

            CryptographicOperations.ZeroMemory(ssM);
        }
        finally
        {
            if (ekX is not null) CryptographicOperations.ZeroMemory(ekX);
            if (ssX is not null) CryptographicOperations.ZeroMemory(ssX);
        }
    }

    /// <summary>
    /// Exports this key as its 1216-byte encapsulation key.
    /// </summary>
    public byte[] Export()
    {
        byte[] encoded = new byte[XWing.EncapsulationKeySizeInBytes];
        _pkM.CopyTo(encoded, 0);
        _pkX.CopyTo(encoded, XWing.MLKemEncapsulationKeySize);
        return encoded;
    }
}

/// <summary>
/// An X-Wing private key (decapsulation key). Owns sensitive key material;
/// dispose it when finished to release the underlying secrets.
/// </summary>
/// <remarks>
/// This type realizes the cached "expanded decapsulation key" optimization from
/// §5.5.1 of the X-Wing specification: the 32-byte seed is expanded
/// (<c>expandDecapsulationKey</c>) exactly once — when the key is generated or
/// imported — and the resulting ML-KEM decapsulation key and X25519 scalar are
/// retained in this object. Every subsequent <see cref="Decapsulate(ReadOnlySpan{byte})"/> reuses
/// that cached expansion instead of re-deriving it, which is the recommended
/// pattern when one key decapsulates multiple ciphertexts.
///
/// In the spec's terms, the 32-byte seed returned by
/// <see cref="ExportDecapsulationKey"/> is the <em>packed</em> form, and importing
/// it via <see cref="XWing.ImportDecapsulationKey"/> performs the <em>unpack</em>
/// (re-expansion). The expanded form is never exported, in keeping with the
/// spec's requirement that it MUST NOT be transmitted between implementations
/// (doing so would break X-Wing's MAL-BIND-K-PK / MAL-BIND-K-CT binding).
/// </remarks>
public sealed class XWingPrivateKey : IDisposable
{
    private readonly byte[] _seed; // 32-byte decapsulation key
    private readonly MLKem _mlkem; // expanded ML-KEM-768 decapsulation key
    private readonly byte[] _skX;  // X25519 private key (32 bytes)
    private readonly byte[] _pkM;  // ML-KEM-768 encapsulation key (1184 bytes)
    private readonly byte[] _pkX;  // X25519 public key (32 bytes)
    private bool _disposed;

    private XWingPrivateKey(byte[] seed, MLKem mlkem, byte[] skX, byte[] pkM, byte[] pkX)
    {
        _seed = seed;
        _mlkem = mlkem;
        _skX = skX;
        _pkM = pkM;
        _pkX = pkX;
    }

    /// <summary>
    /// Expands a 32-byte seed into a full X-Wing decapsulation key per
    /// <c>expandDecapsulationKey</c> in the X-Wing specification.
    /// </summary>
    internal static XWingPrivateKey FromSeed(ReadOnlySpan<byte> seed)
    {
        // expanded = SHAKE256(seed, 96); the first 64 bytes are the ML-KEM
        // private seed (d || z); the last 32 bytes are the X25519 private key.
        byte[] expanded = Shake256.HashData(seed, 96);
        try
        {
            MLKem mlkem = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, expanded.AsSpan(0, 64));
            byte[] skX = expanded.AsSpan(64, 32).ToArray();
            byte[] pkX = X25519.ScalarMultBase(skX);
            byte[] pkM = mlkem.ExportEncapsulationKey();
            return new XWingPrivateKey(seed.ToArray(), mlkem, skX, pkM, pkX);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(expanded);
        }
    }

    /// <summary>
    /// Returns the public (encapsulation) key corresponding to this private key.
    /// </summary>
    public XWingPublicKey GetPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new XWingPublicKey((byte[])_pkM.Clone(), (byte[])_pkX.Clone());
    }

    /// <summary>
    /// Recovers the shared secret from a ciphertext produced for this key.
    /// </summary>
    public byte[] Decapsulate(ReadOnlySpan<byte> ciphertext)
    {
        byte[] sharedSecret = new byte[XWing.SharedSecretSizeInBytes];
        DecapsulateCore(ciphertext, sharedSecret);
        return sharedSecret;
    }

    /// <summary>
    /// Recovers the shared secret from <paramref name="ciphertext"/>, writing it
    /// into the caller-provided 32-byte <paramref name="sharedSecret"/> buffer.
    /// This overload performs no allocation on the result path.
    /// </summary>
    public void Decapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        if (sharedSecret.Length != XWing.SharedSecretSizeInBytes)
        {
            throw new ArgumentException($"Shared-secret buffer must be {XWing.SharedSecretSizeInBytes} bytes.", nameof(sharedSecret));
        }

        DecapsulateCore(ciphertext, sharedSecret);
    }

    private void DecapsulateCore(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (ciphertext.Length != XWing.CiphertextSizeInBytes)
        {
            throw new ArgumentException($"Ciphertext must be {XWing.CiphertextSizeInBytes} bytes.", nameof(ciphertext));
        }

        ReadOnlySpan<byte> ctM = ciphertext[..XWing.MLKemCiphertextSize];
        ReadOnlySpan<byte> ctX = ciphertext[XWing.MLKemCiphertextSize..];

        Span<byte> ssM = stackalloc byte[MLKem768.SharedSecretSizeInBytes];
        byte[]? ssX = null;
        try
        {
            _mlkem.Decapsulate(ctM, ssM);
            ssX = X25519.ScalarMult(_skX, ctX);
            XWing.Combiner(ssM, ssX, ctX, _pkX, sharedSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ssM);
            if (ssX is not null) CryptographicOperations.ZeroMemory(ssX);
        }
    }

    /// <summary>Exports the 32-byte decapsulation key (seed).</summary>
    public byte[] ExportDecapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (byte[])_seed.Clone();
    }

    /// <summary>Exports the matching 1216-byte encapsulation (public) key.</summary>
    public byte[] ExportEncapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] encoded = new byte[XWing.EncapsulationKeySizeInBytes];
        _pkM.CopyTo(encoded, 0);
        _pkX.CopyTo(encoded, XWing.MLKemEncapsulationKeySize);
        return encoded;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _mlkem.Dispose();
        CryptographicOperations.ZeroMemory(_seed);
        CryptographicOperations.ZeroMemory(_skX);
        _disposed = true;
    }
}
