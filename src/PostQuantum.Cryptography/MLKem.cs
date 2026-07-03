using System.Diagnostics;
using System.Security.Cryptography;
using PostQuantum.Cryptography.Internal;

// The PKCS#8 / SubjectPublicKeyInfo / PEM members of MLKem are annotated
// [Experimental("SYSLIB5006")] in .NET 10. The *encodings* themselves are
// IETF-standardized and stable; the .NET API simply still carries the
// evaluation flag. We expose them deliberately (and document this in
// KNOWN-GAPS.md), suppressing the diagnostic only in this file. SLH-DSA — which
// shares the same diagnostic ID — lives in no file we suppress, so it remains
// correctly blocked.
#pragma warning disable SYSLIB5006

namespace PostQuantum.Cryptography;

/// <summary>
/// An ML-KEM public key (encapsulation key). Holds no secret material.
/// </summary>
/// <remarks>
/// <para>
/// This type is algorithm-aware: the parameter set (ML-KEM-512/768/1024) and all
/// sizes are taken from the underlying key, so it works uniformly across the
/// facades <see cref="MLKem512"/>, <see cref="MLKem768"/>, and <see cref="MLKem1024"/>.
/// </para>
/// <para>
/// <b>Thread-safety:</b> instances are <i>not</i> thread-safe. Do not invoke
/// methods on the same instance from multiple threads concurrently. See
/// <c>SECURITY.md</c> for the full thread-safety contract and safe usage
/// patterns.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// using MLKemPublicKey pub = MLKem768.ImportEncapsulationKey(publicKeyBytes);
/// KemEncapsulation enc = pub.Encapsulate();
/// // enc.Ciphertext is sent to the holder of the private key;
/// // enc.SharedSecret is used to key a symmetric algorithm.
/// </code>
/// </example>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class MLKemPublicKey : IDisposable
{
    private readonly MLKem _kem;
    private bool _disposed;

    internal MLKemPublicKey(MLKem kem) => _kem = kem;

    private string DebuggerDisplay => _disposed
        ? "MLKemPublicKey (disposed)"
        : $"MLKemPublicKey ({_kem.Algorithm.Name})";

    /// <summary>The ML-KEM parameter set this key belongs to.</summary>
    public MLKemAlgorithm Algorithm
    {
        get
        {
            // The BCL property tolerates a disposed handle; we enforce the
            // documented "disposed keys throw" contract uniformly.
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _kem.Algorithm;
        }
    }

    /// <summary>
    /// Encapsulates a fresh random shared secret to this public key.
    /// </summary>
    public KemEncapsulation Encapsulate()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _kem.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret);
        return new KemEncapsulation(ciphertext, sharedSecret);
    }

    /// <summary>
    /// Encapsulates a fresh random shared secret to this public key, writing the
    /// ciphertext and shared secret into caller-provided buffers. The buffers
    /// must be exactly <see cref="MLKemAlgorithm.CiphertextSizeInBytes"/> and
    /// <see cref="MLKemAlgorithm.SharedSecretSizeInBytes"/> bytes for
    /// <see cref="Algorithm"/>. This overload performs no allocation.
    /// </summary>
    public void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int expectedCt = _kem.Algorithm.CiphertextSizeInBytes;
        int expectedSs = _kem.Algorithm.SharedSecretSizeInBytes;
        if (ciphertext.Length != expectedCt)
        {
            throw new ArgumentException($"Ciphertext buffer must be {expectedCt} bytes for {_kem.Algorithm.Name}.", nameof(ciphertext));
        }

        if (sharedSecret.Length != expectedSs)
        {
            throw new ArgumentException($"Shared-secret buffer must be {expectedSs} bytes for {_kem.Algorithm.Name}.", nameof(sharedSecret));
        }

        _kem.Encapsulate(ciphertext, sharedSecret);
    }

    /// <summary>Exports the raw encapsulation key.</summary>
    public byte[] Export()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _kem.ExportEncapsulationKey();
    }

    /// <summary>Exports the public key as a DER-encoded SubjectPublicKeyInfo (X.509) structure.</summary>
    public byte[] ExportSubjectPublicKeyInfo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _kem.ExportSubjectPublicKeyInfo();
    }

    /// <summary>Exports the public key as a PEM-encoded SubjectPublicKeyInfo structure.</summary>
    public string ExportSubjectPublicKeyInfoPem()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _kem.ExportSubjectPublicKeyInfoPem();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _kem.Dispose();
        _disposed = true;
    }
}

/// <summary>
/// An ML-KEM private key (decapsulation key). Owns sensitive key material;
/// dispose it when finished to release the underlying secrets.
/// </summary>
/// <remarks>
/// <para>
/// This type is algorithm-aware (ML-KEM-512/768/1024); all sizes are taken from
/// the underlying key.
/// </para>
/// <para>
/// <b>Thread-safety:</b> instances are <i>not</i> thread-safe. Use one
/// instance per thread (or per request); see <c>SECURITY.md</c>.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
/// byte[] seed = priv.ExportPrivateSeed();  // 64 bytes, store securely
///
/// // Later: rebuild the same key pair from the seed.
/// using MLKemPrivateKey restored = MLKem768.ImportPrivateSeed(seed);
/// byte[] sharedSecret = restored.Decapsulate(ciphertext);
/// </code>
/// </example>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class MLKemPrivateKey : IDisposable
{
    private readonly MLKem _kem;
    private bool _disposed;

    internal MLKemPrivateKey(MLKem kem) => _kem = kem;

    private string DebuggerDisplay => _disposed
        ? "MLKemPrivateKey (disposed)"
        : $"MLKemPrivateKey ({_kem.Algorithm.Name}, secret material redacted)";

    /// <summary>The ML-KEM parameter set this key belongs to.</summary>
    public MLKemAlgorithm Algorithm
    {
        get
        {
            // The BCL property tolerates a disposed handle; we enforce the
            // documented "disposed keys throw" contract uniformly.
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _kem.Algorithm;
        }
    }

    /// <summary>
    /// Returns the public (encapsulation) key corresponding to this private key.
    /// </summary>
    /// <remarks>
    /// The returned <see cref="MLKemPublicKey"/> owns its own native handle
    /// (it's a fresh import of the encapsulation key, not a shared view),
    /// so <see cref="IDisposable.Dispose"/> it when finished. Wrap it in a
    /// <see langword="using"/> block to avoid leaking the handle.
    /// </remarks>
    public MLKemPublicKey GetPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new MLKemPublicKey(MLKem.ImportEncapsulationKey(_kem.Algorithm, _kem.ExportEncapsulationKey()));
    }

    /// <summary>Recovers the shared secret from a ciphertext produced for this key.</summary>
    public byte[] Decapsulate(ReadOnlySpan<byte> ciphertext)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int expected = _kem.Algorithm.CiphertextSizeInBytes;
        if (ciphertext.Length != expected)
        {
            throw new ArgumentException($"Ciphertext must be {expected} bytes for {_kem.Algorithm.Name}.", nameof(ciphertext));
        }

        byte[] sharedSecret = new byte[_kem.Algorithm.SharedSecretSizeInBytes];
        _kem.Decapsulate(ciphertext, sharedSecret);
        return sharedSecret;
    }

    /// <summary>
    /// Recovers the shared secret from <paramref name="ciphertext"/>, writing it
    /// into the caller-provided <paramref name="sharedSecret"/> buffer (which must
    /// be exactly <see cref="MLKemAlgorithm.SharedSecretSizeInBytes"/> bytes for
    /// <see cref="Algorithm"/>). This overload performs no allocation.
    /// </summary>
    public void Decapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int expectedCt = _kem.Algorithm.CiphertextSizeInBytes;
        int expectedSs = _kem.Algorithm.SharedSecretSizeInBytes;
        if (ciphertext.Length != expectedCt)
        {
            throw new ArgumentException($"Ciphertext must be {expectedCt} bytes for {_kem.Algorithm.Name}.", nameof(ciphertext));
        }

        if (sharedSecret.Length != expectedSs)
        {
            throw new ArgumentException($"Shared-secret buffer must be {expectedSs} bytes for {_kem.Algorithm.Name}.", nameof(sharedSecret));
        }

        _kem.Decapsulate(ciphertext, sharedSecret);
    }

    /// <summary>Exports the matching encapsulation (public) key.</summary>
    public byte[] ExportEncapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _kem.ExportEncapsulationKey();
    }

    /// <summary>Exports the expanded decapsulation (private) key.</summary>
    public byte[] ExportDecapsulationKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _kem.ExportDecapsulationKey();
    }

    /// <summary>Exports the private seed that deterministically derives this key pair.</summary>
    public byte[] ExportPrivateSeed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _kem.ExportPrivateSeed();
    }

    /// <summary>Exports the public key as a DER-encoded SubjectPublicKeyInfo (X.509) structure.</summary>
    public byte[] ExportSubjectPublicKeyInfo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _kem.ExportSubjectPublicKeyInfo();
    }

    /// <summary>Exports the public key as a PEM-encoded SubjectPublicKeyInfo structure.</summary>
    public string ExportSubjectPublicKeyInfoPem()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _kem.ExportSubjectPublicKeyInfoPem();
    }

    /// <summary>Exports the private key as a DER-encoded PKCS#8 PrivateKeyInfo structure.</summary>
    public byte[] ExportPkcs8PrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _kem.ExportPkcs8PrivateKey();
    }

    /// <summary>Exports the private key as a PEM-encoded PKCS#8 PrivateKeyInfo structure.</summary>
    public string ExportPkcs8PrivateKeyPem()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _kem.ExportPkcs8PrivateKeyPem();
    }

    /// <summary>
    /// Exports the private key as a DER-encoded PKCS#8 EncryptedPrivateKeyInfo
    /// structure, protected by <paramref name="password"/>. The encryption is
    /// fixed at PBES2 / PBKDF2-HMAC-SHA256 (600,000 iterations) / AES-256-CBC —
    /// there are no weaker knobs to select. Re-import with
    /// <see cref="MLKemKey.ImportEncryptedPkcs8PrivateKey"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
    public byte[] ExportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Pbe.RequireNonEmptyPassword(password);
        return _kem.ExportEncryptedPkcs8PrivateKey(password, Pbe.Parameters);
    }

    /// <summary>
    /// Exports the private key as a PEM-encoded PKCS#8 EncryptedPrivateKeyInfo
    /// structure (a <c>-----BEGIN ENCRYPTED PRIVATE KEY-----</c> block),
    /// protected by <paramref name="password"/>. See
    /// <see cref="ExportEncryptedPkcs8PrivateKey"/> for the fixed encryption
    /// parameters. Re-import with
    /// <see cref="MLKemKey.ImportEncryptedPrivateKeyFromPem"/>.
    /// </summary>
    /// <exception cref="ArgumentException"><paramref name="password"/> is empty.</exception>
    public string ExportEncryptedPkcs8PrivateKeyPem(ReadOnlySpan<char> password)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        Pbe.RequireNonEmptyPassword(password);
        return _kem.ExportEncryptedPkcs8PrivateKeyPem(password, Pbe.Parameters);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _kem.Dispose();
        _disposed = true;
    }
}

/// <summary>
/// Shared import helpers for ML-KEM keys in DER / PEM (PKCS#8, SubjectPublicKeyInfo)
/// formats. The parameter set is recovered from the encoded structure.
/// </summary>
/// <example>
/// <code>
/// // Export to PEM for storage / interchange.
/// using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
/// string privatePem = priv.ExportPkcs8PrivateKeyPem();
/// string publicPem  = priv.GetPublicKey().ExportSubjectPublicKeyInfoPem();
///
/// // Re-import. PEM label is validated up front: a public-key PEM passed to
/// // ImportPrivateKeyFromPem throws ArgumentException immediately.
/// using MLKemPrivateKey loaded = MLKemKey.ImportPrivateKeyFromPem(privatePem);
/// using MLKemPublicKey  pub    = MLKemKey.ImportPublicKeyFromPem(publicPem);
/// </code>
/// </example>
public static class MLKemKey
{
    /// <summary>Imports a private key from a DER-encoded PKCS#8 PrivateKeyInfo structure.</summary>
    public static MLKemPrivateKey ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
        => new(MLKem.ImportPkcs8PrivateKey(source));

    /// <summary>Imports a public key from a DER-encoded SubjectPublicKeyInfo structure.</summary>
    public static MLKemPublicKey ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
        => new(MLKem.ImportSubjectPublicKeyInfo(source));

    /// <summary>
    /// Imports a private key from a PEM-encoded PKCS#8 PrivateKeyInfo structure
    /// (a <c>-----BEGIN PRIVATE KEY-----</c> block). Throws
    /// <see cref="ArgumentException"/> if <paramref name="pem"/> is a public-key
    /// PEM, an encrypted-private-key PEM, or otherwise unrecognized.
    /// </summary>
    public static MLKemPrivateKey ImportPrivateKeyFromPem(ReadOnlySpan<char> pem)
    {
        PemLabels.RequirePrivateKeyLabel(pem);
        return new(MLKem.ImportFromPem(pem));
    }

    /// <summary>
    /// Imports a public key from a PEM-encoded SubjectPublicKeyInfo structure
    /// (a <c>-----BEGIN PUBLIC KEY-----</c> block). Throws
    /// <see cref="ArgumentException"/> if <paramref name="pem"/> is a private-key
    /// PEM or otherwise unrecognized.
    /// </summary>
    public static MLKemPublicKey ImportPublicKeyFromPem(ReadOnlySpan<char> pem)
    {
        PemLabels.RequirePublicKeyLabel(pem);
        return new(MLKem.ImportFromPem(pem));
    }

    /// <summary>
    /// Imports a private key from a DER-encoded PKCS#8 EncryptedPrivateKeyInfo
    /// structure, decrypting with <paramref name="password"/>. The decryption
    /// parameters are read from the structure itself. Throws
    /// <see cref="System.Security.Cryptography.CryptographicException"/> when
    /// the password is wrong.
    /// </summary>
    public static MLKemPrivateKey ImportEncryptedPkcs8PrivateKey(ReadOnlySpan<char> password, ReadOnlySpan<byte> source)
        => new(MLKem.ImportEncryptedPkcs8PrivateKey(password, source));

    /// <summary>
    /// Imports a private key from a PEM-encoded PKCS#8 EncryptedPrivateKeyInfo
    /// structure (a <c>-----BEGIN ENCRYPTED PRIVATE KEY-----</c> block),
    /// decrypting with <paramref name="password"/>. Throws
    /// <see cref="ArgumentException"/> if <paramref name="pem"/> is an
    /// unencrypted private-key PEM (use <see cref="ImportPrivateKeyFromPem"/>),
    /// a public-key PEM, or otherwise unrecognized, and
    /// <see cref="System.Security.Cryptography.CryptographicException"/> when
    /// the password is wrong.
    /// </summary>
    public static MLKemPrivateKey ImportEncryptedPrivateKeyFromPem(ReadOnlySpan<char> password, ReadOnlySpan<char> pem)
    {
        PemLabels.RequireEncryptedPrivateKeyLabel(pem);
        return new(MLKem.ImportFromEncryptedPem(pem, password));
    }
}

/// <summary>
/// High-level, secure-by-default API for ML-KEM-512 (FIPS 203, NIST security category 1).
/// </summary>
/// <remarks>
/// ML-KEM-512 is the smallest, fastest parameter set. For most applications the
/// recommended default is <see cref="MLKem768"/>; choose 512 only when its security
/// category is sufficient and size/speed are at a premium.
/// </remarks>
public static class MLKem512
{
    /// <summary>Size, in bytes, of an ML-KEM-512 encapsulation (public) key.</summary>
    public const int EncapsulationKeySizeInBytes = 800;

    /// <summary>Size, in bytes, of an ML-KEM-512 decapsulation (private) key.</summary>
    public const int DecapsulationKeySizeInBytes = 1632;

    /// <summary>Size, in bytes, of the 64-byte private seed (d || z).</summary>
    public const int PrivateSeedSizeInBytes = 64;

    /// <summary>Size, in bytes, of an ML-KEM-512 ciphertext.</summary>
    public const int CiphertextSizeInBytes = 768;

    /// <summary>Size, in bytes, of the shared secret.</summary>
    public const int SharedSecretSizeInBytes = 32;

    /// <summary>Gets whether ML-KEM is supported on the current platform.</summary>
    public static bool IsSupported => MLKem.IsSupported;

    /// <summary>Generates a fresh ML-KEM-512 key pair using a CSPRNG.</summary>
    public static MLKemPrivateKey GenerateKeyPair() => new(MLKem.GenerateKey(MLKemAlgorithm.MLKem512));

    /// <summary>Imports a private key from its 64-byte private seed.</summary>
    public static MLKemPrivateKey ImportPrivateSeed(ReadOnlySpan<byte> privateSeed)
        => MLKemFacade.ImportPrivateSeed(MLKemAlgorithm.MLKem512, privateSeed, PrivateSeedSizeInBytes);

    /// <summary>Imports a private key from its expanded decapsulation key.</summary>
    public static MLKemPrivateKey ImportDecapsulationKey(ReadOnlySpan<byte> decapsulationKey)
        => MLKemFacade.ImportDecapsulationKey(MLKemAlgorithm.MLKem512, decapsulationKey, DecapsulationKeySizeInBytes);

    /// <summary>Imports a public key from its encapsulation key.</summary>
    public static MLKemPublicKey ImportEncapsulationKey(ReadOnlySpan<byte> encapsulationKey)
        => MLKemFacade.ImportEncapsulationKey(MLKemAlgorithm.MLKem512, encapsulationKey, EncapsulationKeySizeInBytes);
}

/// <summary>
/// High-level, secure-by-default API for ML-KEM-768 (FIPS 203, NIST security category 3).
/// </summary>
/// <remarks>
/// ML-KEM-768 is the recommended general-purpose parameter set and the default
/// throughout the <c>PostQuantum.*</c> ecosystem. For a hybrid (classical +
/// post-quantum) construction, prefer <see cref="XWing"/>.
/// </remarks>
/// <example>
/// <code>
/// // Recipient generates a key pair and publishes the encapsulation key.
/// using MLKemPrivateKey recipient = MLKem768.GenerateKeyPair();
/// byte[] publicKeyBytes = recipient.ExportEncapsulationKey();
///
/// // Sender encapsulates a fresh 32-byte shared secret to the recipient.
/// using MLKemPublicKey publicKey = MLKem768.ImportEncapsulationKey(publicKeyBytes);
/// KemEncapsulation result = publicKey.Encapsulate();
///
/// // Recipient recovers the same shared secret from the ciphertext.
/// byte[] recipientSecret = recipient.Decapsulate(result.Ciphertext);
/// // result.SharedSecret.SequenceEqual(recipientSecret) == true
/// </code>
/// </example>
public static class MLKem768
{
    /// <summary>Size, in bytes, of an ML-KEM-768 encapsulation (public) key.</summary>
    public const int EncapsulationKeySizeInBytes = 1184;

    /// <summary>Size, in bytes, of an ML-KEM-768 decapsulation (private) key.</summary>
    public const int DecapsulationKeySizeInBytes = 2400;

    /// <summary>Size, in bytes, of the 64-byte private seed (d || z).</summary>
    public const int PrivateSeedSizeInBytes = 64;

    /// <summary>Size, in bytes, of an ML-KEM-768 ciphertext.</summary>
    public const int CiphertextSizeInBytes = 1088;

    /// <summary>Size, in bytes, of the shared secret.</summary>
    public const int SharedSecretSizeInBytes = 32;

    /// <summary>Gets whether ML-KEM is supported on the current platform.</summary>
    public static bool IsSupported => MLKem.IsSupported;

    /// <summary>Generates a fresh ML-KEM-768 key pair using a CSPRNG.</summary>
    public static MLKemPrivateKey GenerateKeyPair() => new(MLKem.GenerateKey(MLKemAlgorithm.MLKem768));

    /// <summary>Imports a private key from its 64-byte private seed.</summary>
    public static MLKemPrivateKey ImportPrivateSeed(ReadOnlySpan<byte> privateSeed)
        => MLKemFacade.ImportPrivateSeed(MLKemAlgorithm.MLKem768, privateSeed, PrivateSeedSizeInBytes);

    /// <summary>Imports a private key from its expanded decapsulation key.</summary>
    public static MLKemPrivateKey ImportDecapsulationKey(ReadOnlySpan<byte> decapsulationKey)
        => MLKemFacade.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, decapsulationKey, DecapsulationKeySizeInBytes);

    /// <summary>Imports a public key from its encapsulation key.</summary>
    public static MLKemPublicKey ImportEncapsulationKey(ReadOnlySpan<byte> encapsulationKey)
        => MLKemFacade.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, encapsulationKey, EncapsulationKeySizeInBytes);
}

/// <summary>
/// High-level, secure-by-default API for ML-KEM-1024 (FIPS 203, NIST security category 5).
/// </summary>
/// <remarks>
/// ML-KEM-1024 is the highest-strength parameter set. Choose it for long-lived
/// secrets where the largest security margin is desired; for most applications
/// <see cref="MLKem768"/> is the recommended balance.
/// </remarks>
public static class MLKem1024
{
    /// <summary>Size, in bytes, of an ML-KEM-1024 encapsulation (public) key.</summary>
    public const int EncapsulationKeySizeInBytes = 1568;

    /// <summary>Size, in bytes, of an ML-KEM-1024 decapsulation (private) key.</summary>
    public const int DecapsulationKeySizeInBytes = 3168;

    /// <summary>Size, in bytes, of the 64-byte private seed (d || z).</summary>
    public const int PrivateSeedSizeInBytes = 64;

    /// <summary>Size, in bytes, of an ML-KEM-1024 ciphertext.</summary>
    public const int CiphertextSizeInBytes = 1568;

    /// <summary>Size, in bytes, of the shared secret.</summary>
    public const int SharedSecretSizeInBytes = 32;

    /// <summary>Gets whether ML-KEM is supported on the current platform.</summary>
    public static bool IsSupported => MLKem.IsSupported;

    /// <summary>Generates a fresh ML-KEM-1024 key pair using a CSPRNG.</summary>
    public static MLKemPrivateKey GenerateKeyPair() => new(MLKem.GenerateKey(MLKemAlgorithm.MLKem1024));

    /// <summary>Imports a private key from its 64-byte private seed.</summary>
    public static MLKemPrivateKey ImportPrivateSeed(ReadOnlySpan<byte> privateSeed)
        => MLKemFacade.ImportPrivateSeed(MLKemAlgorithm.MLKem1024, privateSeed, PrivateSeedSizeInBytes);

    /// <summary>Imports a private key from its expanded decapsulation key.</summary>
    public static MLKemPrivateKey ImportDecapsulationKey(ReadOnlySpan<byte> decapsulationKey)
        => MLKemFacade.ImportDecapsulationKey(MLKemAlgorithm.MLKem1024, decapsulationKey, DecapsulationKeySizeInBytes);

    /// <summary>Imports a public key from its encapsulation key.</summary>
    public static MLKemPublicKey ImportEncapsulationKey(ReadOnlySpan<byte> encapsulationKey)
        => MLKemFacade.ImportEncapsulationKey(MLKemAlgorithm.MLKem1024, encapsulationKey, EncapsulationKeySizeInBytes);
}

/// <summary>Shared validation/import logic for the ML-KEM facades.</summary>
internal static class MLKemFacade
{
    public static MLKemPrivateKey ImportPrivateSeed(MLKemAlgorithm algorithm, ReadOnlySpan<byte> seed, int expected)
    {
        if (seed.Length != expected)
        {
            throw new ArgumentException($"Private seed must be {expected} bytes for {algorithm.Name}.", nameof(seed));
        }

        return new MLKemPrivateKey(MLKem.ImportPrivateSeed(algorithm, seed));
    }

    public static MLKemPrivateKey ImportDecapsulationKey(MLKemAlgorithm algorithm, ReadOnlySpan<byte> key, int expected)
    {
        if (key.Length != expected)
        {
            throw new ArgumentException($"Decapsulation key must be {expected} bytes for {algorithm.Name}.", nameof(key));
        }

        return new MLKemPrivateKey(MLKem.ImportDecapsulationKey(algorithm, key));
    }

    public static MLKemPublicKey ImportEncapsulationKey(MLKemAlgorithm algorithm, ReadOnlySpan<byte> key, int expected)
    {
        if (key.Length != expected)
        {
            throw new ArgumentException($"Encapsulation key must be {expected} bytes for {algorithm.Name}.", nameof(key));
        }

        return new MLKemPublicKey(MLKem.ImportEncapsulationKey(algorithm, key));
    }
}
