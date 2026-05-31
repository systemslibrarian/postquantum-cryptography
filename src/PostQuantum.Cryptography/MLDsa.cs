using System.Security.Cryptography;
using PostQuantum.Cryptography.Internal;

// The PKCS#8 / SubjectPublicKeyInfo / PEM members of MLDsa are annotated
// [Experimental("SYSLIB5006")] in .NET 10. The *encodings* themselves are
// IETF-standardized and stable; the .NET API simply still carries the
// evaluation flag. We expose them deliberately (and document this in
// KNOWN-GAPS.md), suppressing the diagnostic only in this file. SLH-DSA — which
// shares the same diagnostic ID — lives in no file we suppress, so it remains
// correctly blocked.
#pragma warning disable SYSLIB5006

namespace PostQuantum.Cryptography;

/// <summary>
/// An ML-DSA public key, used to verify signatures. Holds no secret material.
/// </summary>
/// <remarks>
/// Algorithm-aware across ML-DSA-44/65/87; sizes come from the underlying key.
/// </remarks>
/// <example>
/// <code>
/// using MLDsaPublicKey verifier = MLDsaKey.ImportPublicKeyFromPem(publicPem);
/// bool ok = verifier.Verify(message, signature);
/// </code>
/// </example>
public sealed class MLDsaPublicKey : IDisposable
{
    private readonly MLDsa _dsa;
    private bool _disposed;

    internal MLDsaPublicKey(MLDsa dsa) => _dsa = dsa;

    /// <summary>The ML-DSA parameter set this key belongs to.</summary>
    public MLDsaAlgorithm Algorithm => _dsa.Algorithm;

    /// <summary>Verifies a signature over <paramref name="data"/>.</summary>
    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        => Verify(data, signature, context: default);

    /// <summary>
    /// Verifies a signature over <paramref name="data"/> bound to the
    /// supplied <paramref name="context"/> (FIPS 204 §5.2). The signer and
    /// verifier must agree on the same context bytes.
    /// </summary>
    public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> context)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _dsa.VerifyData(data, signature, context);
    }

    /// <summary>Exports the raw public key.</summary>
    public byte[] Export()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _dsa.ExportMLDsaPublicKey();
    }

    /// <summary>Exports the public key as a DER-encoded SubjectPublicKeyInfo (X.509) structure.</summary>
    public byte[] ExportSubjectPublicKeyInfo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _dsa.ExportSubjectPublicKeyInfo();
    }

    /// <summary>Exports the public key as a PEM-encoded SubjectPublicKeyInfo structure.</summary>
    public string ExportSubjectPublicKeyInfoPem()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _dsa.ExportSubjectPublicKeyInfoPem();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _dsa.Dispose();
        _disposed = true;
    }
}

/// <summary>
/// An ML-DSA private key, used to produce signatures. Owns sensitive key
/// material; dispose it when finished to release the underlying secrets.
/// </summary>
/// <remarks>
/// Algorithm-aware across ML-DSA-44/65/87. The optional <c>context</c> on signing
/// and verification (FIPS 204 §5.2) binds a signature to a usage domain; both
/// sides must agree on it.
/// </remarks>
/// <example>
/// <code>
/// using MLDsaPrivateKey signer = MLDsa87.GenerateKeyPair();
///
/// // Allocating overload.
/// byte[] sig = signer.SignData(message);
///
/// // Zero-allocation overload — writes into caller-provided buffer.
/// Span&lt;byte&gt; dest = stackalloc byte[MLDsa87.SignatureSizeInBytes];
/// signer.SignData(message, dest);
/// </code>
/// </example>
public sealed class MLDsaPrivateKey : IDisposable
{
    private readonly MLDsa _dsa;
    private bool _disposed;

    internal MLDsaPrivateKey(MLDsa dsa) => _dsa = dsa;

    /// <summary>The ML-DSA parameter set this key belongs to.</summary>
    public MLDsaAlgorithm Algorithm => _dsa.Algorithm;

    /// <summary>Returns the public (verifying) key corresponding to this private key.</summary>
    public MLDsaPublicKey GetPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new MLDsaPublicKey(MLDsa.ImportMLDsaPublicKey(_dsa.Algorithm, _dsa.ExportMLDsaPublicKey()));
    }

    /// <summary>Signs <paramref name="data"/>, returning a freshly-allocated signature.</summary>
    public byte[] SignData(ReadOnlySpan<byte> data)
        => SignData(data, context: default);

    /// <summary>
    /// Signs <paramref name="data"/> bound to <paramref name="context"/>
    /// (FIPS 204 §5.2), returning a freshly-allocated signature. The verifier
    /// must supply the same context bytes.
    /// </summary>
    public byte[] SignData(ReadOnlySpan<byte> data, ReadOnlySpan<byte> context)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] signature = new byte[_dsa.Algorithm.SignatureSizeInBytes];
        _dsa.SignData(data, signature, context);
        return signature;
    }

    /// <summary>
    /// Signs <paramref name="data"/>, writing the signature into the
    /// caller-provided <paramref name="destination"/> buffer (which must be
    /// exactly <see cref="MLDsaAlgorithm.SignatureSizeInBytes"/> bytes for
    /// <see cref="Algorithm"/>). Allocation-free.
    /// </summary>
    public void SignData(ReadOnlySpan<byte> data, Span<byte> destination)
        => SignData(data, destination, context: default);

    /// <summary>
    /// Signs <paramref name="data"/> bound to <paramref name="context"/>
    /// (FIPS 204 §5.2), writing the signature into <paramref name="destination"/>
    /// (which must be exactly <see cref="MLDsaAlgorithm.SignatureSizeInBytes"/>
    /// bytes for <see cref="Algorithm"/>). Allocation-free.
    /// </summary>
    public void SignData(ReadOnlySpan<byte> data, Span<byte> destination, ReadOnlySpan<byte> context)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int expected = _dsa.Algorithm.SignatureSizeInBytes;
        if (destination.Length != expected)
        {
            throw new ArgumentException($"Destination buffer must be {expected} bytes for {_dsa.Algorithm.Name}.", nameof(destination));
        }

        _dsa.SignData(data, destination, context);
    }

    /// <summary>Exports the matching public key.</summary>
    public byte[] ExportPublicKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _dsa.ExportMLDsaPublicKey();
    }

    /// <summary>Exports the expanded secret key.</summary>
    public byte[] ExportSecretKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _dsa.ExportMLDsaPrivateKey();
    }

    /// <summary>Exports the private seed that deterministically derives this key pair.</summary>
    public byte[] ExportPrivateSeed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _dsa.ExportMLDsaPrivateSeed();
    }

    /// <summary>Exports the public key as a DER-encoded SubjectPublicKeyInfo (X.509) structure.</summary>
    public byte[] ExportSubjectPublicKeyInfo()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _dsa.ExportSubjectPublicKeyInfo();
    }

    /// <summary>Exports the public key as a PEM-encoded SubjectPublicKeyInfo structure.</summary>
    public string ExportSubjectPublicKeyInfoPem()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _dsa.ExportSubjectPublicKeyInfoPem();
    }

    /// <summary>Exports the private key as a DER-encoded PKCS#8 PrivateKeyInfo structure.</summary>
    public byte[] ExportPkcs8PrivateKey()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _dsa.ExportPkcs8PrivateKey();
    }

    /// <summary>Exports the private key as a PEM-encoded PKCS#8 PrivateKeyInfo structure.</summary>
    public string ExportPkcs8PrivateKeyPem()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _dsa.ExportPkcs8PrivateKeyPem();
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _dsa.Dispose();
        _disposed = true;
    }
}

/// <summary>
/// Shared import helpers for ML-DSA keys in DER / PEM (PKCS#8, SubjectPublicKeyInfo)
/// formats. The parameter set is recovered from the encoded structure.
/// </summary>
public static class MLDsaKey
{
    /// <summary>Imports a private key from a DER-encoded PKCS#8 PrivateKeyInfo structure.</summary>
    public static MLDsaPrivateKey ImportPkcs8PrivateKey(ReadOnlySpan<byte> source)
        => new(MLDsa.ImportPkcs8PrivateKey(source));

    /// <summary>Imports a public key from a DER-encoded SubjectPublicKeyInfo structure.</summary>
    public static MLDsaPublicKey ImportSubjectPublicKeyInfo(ReadOnlySpan<byte> source)
        => new(MLDsa.ImportSubjectPublicKeyInfo(source));

    /// <summary>
    /// Imports a private key from a PEM-encoded PKCS#8 PrivateKeyInfo structure
    /// (a <c>-----BEGIN PRIVATE KEY-----</c> block). Throws
    /// <see cref="ArgumentException"/> if <paramref name="pem"/> is a public-key
    /// PEM, an encrypted-private-key PEM, or otherwise unrecognized.
    /// </summary>
    public static MLDsaPrivateKey ImportPrivateKeyFromPem(ReadOnlySpan<char> pem)
    {
        PemLabels.RequirePrivateKeyLabel(pem);
        return new(MLDsa.ImportFromPem(pem));
    }

    /// <summary>
    /// Imports a public key from a PEM-encoded SubjectPublicKeyInfo structure
    /// (a <c>-----BEGIN PUBLIC KEY-----</c> block). Throws
    /// <see cref="ArgumentException"/> if <paramref name="pem"/> is a private-key
    /// PEM or otherwise unrecognized.
    /// </summary>
    public static MLDsaPublicKey ImportPublicKeyFromPem(ReadOnlySpan<char> pem)
    {
        PemLabels.RequirePublicKeyLabel(pem);
        return new(MLDsa.ImportFromPem(pem));
    }
}

/// <summary>
/// High-level, secure-by-default API for ML-DSA-44 (FIPS 204, NIST security category 2).
/// </summary>
/// <remarks>The recommended general-purpose default is <see cref="MLDsa87"/>.</remarks>
public static class MLDsa44
{
    /// <summary>Size, in bytes, of an ML-DSA-44 public key.</summary>
    public const int PublicKeySizeInBytes = 1312;

    /// <summary>Size, in bytes, of an ML-DSA-44 expanded secret key.</summary>
    public const int SecretKeySizeInBytes = 2560;

    /// <summary>Size, in bytes, of the 32-byte private seed.</summary>
    public const int PrivateSeedSizeInBytes = 32;

    /// <summary>Size, in bytes, of an ML-DSA-44 signature.</summary>
    public const int SignatureSizeInBytes = 2420;

    /// <summary>Gets whether ML-DSA is supported on the current platform.</summary>
    public static bool IsSupported => MLDsa.IsSupported;

    /// <summary>Generates a fresh ML-DSA-44 key pair using a CSPRNG.</summary>
    public static MLDsaPrivateKey GenerateKeyPair() => new(MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44));

    /// <summary>Imports a private key from its 32-byte private seed.</summary>
    public static MLDsaPrivateKey ImportPrivateSeed(ReadOnlySpan<byte> privateSeed)
        => MLDsaFacade.ImportPrivateSeed(MLDsaAlgorithm.MLDsa44, privateSeed, PrivateSeedSizeInBytes);

    /// <summary>Imports a private key from its expanded secret key.</summary>
    public static MLDsaPrivateKey ImportSecretKey(ReadOnlySpan<byte> secretKey)
        => MLDsaFacade.ImportSecretKey(MLDsaAlgorithm.MLDsa44, secretKey, SecretKeySizeInBytes);

    /// <summary>Imports a public key from its encoding.</summary>
    public static MLDsaPublicKey ImportPublicKey(ReadOnlySpan<byte> publicKey)
        => MLDsaFacade.ImportPublicKey(MLDsaAlgorithm.MLDsa44, publicKey, PublicKeySizeInBytes);
}

/// <summary>
/// High-level, secure-by-default API for ML-DSA-65 (FIPS 204, NIST security category 3).
/// </summary>
/// <remarks>The recommended general-purpose default is <see cref="MLDsa87"/>.</remarks>
public static class MLDsa65
{
    /// <summary>Size, in bytes, of an ML-DSA-65 public key.</summary>
    public const int PublicKeySizeInBytes = 1952;

    /// <summary>Size, in bytes, of an ML-DSA-65 expanded secret key.</summary>
    public const int SecretKeySizeInBytes = 4032;

    /// <summary>Size, in bytes, of the 32-byte private seed.</summary>
    public const int PrivateSeedSizeInBytes = 32;

    /// <summary>Size, in bytes, of an ML-DSA-65 signature.</summary>
    public const int SignatureSizeInBytes = 3309;

    /// <summary>Gets whether ML-DSA is supported on the current platform.</summary>
    public static bool IsSupported => MLDsa.IsSupported;

    /// <summary>Generates a fresh ML-DSA-65 key pair using a CSPRNG.</summary>
    public static MLDsaPrivateKey GenerateKeyPair() => new(MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65));

    /// <summary>Imports a private key from its 32-byte private seed.</summary>
    public static MLDsaPrivateKey ImportPrivateSeed(ReadOnlySpan<byte> privateSeed)
        => MLDsaFacade.ImportPrivateSeed(MLDsaAlgorithm.MLDsa65, privateSeed, PrivateSeedSizeInBytes);

    /// <summary>Imports a private key from its expanded secret key.</summary>
    public static MLDsaPrivateKey ImportSecretKey(ReadOnlySpan<byte> secretKey)
        => MLDsaFacade.ImportSecretKey(MLDsaAlgorithm.MLDsa65, secretKey, SecretKeySizeInBytes);

    /// <summary>Imports a public key from its encoding.</summary>
    public static MLDsaPublicKey ImportPublicKey(ReadOnlySpan<byte> publicKey)
        => MLDsaFacade.ImportPublicKey(MLDsaAlgorithm.MLDsa65, publicKey, PublicKeySizeInBytes);
}

/// <summary>
/// High-level, secure-by-default API for ML-DSA-87 (FIPS 204, NIST security category 5).
/// </summary>
/// <remarks>
/// ML-DSA-87 is the highest-strength parameter set and the conservative default
/// for long-lived signatures throughout the <c>PostQuantum.*</c> ecosystem.
/// </remarks>
/// <example>
/// <code>
/// using MLDsaPrivateKey signer  = MLDsa87.GenerateKeyPair();
/// using MLDsaPublicKey verifier = signer.GetPublicKey();
///
/// byte[] message   = "To God be the glory."u8.ToArray();
/// byte[] signature = signer.SignData(message);
///
/// bool ok = verifier.Verify(message, signature); // true
///
/// // Context-bound signatures (FIPS 204 §5.2): both sides must agree.
/// byte[] context = "invoice-signing-v1"u8.ToArray();
/// byte[] boundSig = signer.SignData(message, context);
/// bool boundOk = verifier.Verify(message, boundSig, context);
/// </code>
/// </example>
public static class MLDsa87
{
    /// <summary>Size, in bytes, of an ML-DSA-87 public key.</summary>
    public const int PublicKeySizeInBytes = 2592;

    /// <summary>Size, in bytes, of an ML-DSA-87 expanded secret key.</summary>
    public const int SecretKeySizeInBytes = 4896;

    /// <summary>Size, in bytes, of the 32-byte private seed.</summary>
    public const int PrivateSeedSizeInBytes = 32;

    /// <summary>Size, in bytes, of an ML-DSA-87 signature.</summary>
    public const int SignatureSizeInBytes = 4627;

    /// <summary>Gets whether ML-DSA is supported on the current platform.</summary>
    public static bool IsSupported => MLDsa.IsSupported;

    /// <summary>Generates a fresh ML-DSA-87 key pair using a CSPRNG.</summary>
    public static MLDsaPrivateKey GenerateKeyPair() => new(MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87));

    /// <summary>Imports a private key from its 32-byte private seed.</summary>
    public static MLDsaPrivateKey ImportPrivateSeed(ReadOnlySpan<byte> privateSeed)
        => MLDsaFacade.ImportPrivateSeed(MLDsaAlgorithm.MLDsa87, privateSeed, PrivateSeedSizeInBytes);

    /// <summary>Imports a private key from its expanded secret key.</summary>
    public static MLDsaPrivateKey ImportSecretKey(ReadOnlySpan<byte> secretKey)
        => MLDsaFacade.ImportSecretKey(MLDsaAlgorithm.MLDsa87, secretKey, SecretKeySizeInBytes);

    /// <summary>Imports a public key from its encoding.</summary>
    public static MLDsaPublicKey ImportPublicKey(ReadOnlySpan<byte> publicKey)
        => MLDsaFacade.ImportPublicKey(MLDsaAlgorithm.MLDsa87, publicKey, PublicKeySizeInBytes);
}

/// <summary>Shared validation/import logic for the ML-DSA facades.</summary>
internal static class MLDsaFacade
{
    public static MLDsaPrivateKey ImportPrivateSeed(MLDsaAlgorithm algorithm, ReadOnlySpan<byte> seed, int expected)
    {
        if (seed.Length != expected)
        {
            throw new ArgumentException($"Private seed must be {expected} bytes for {algorithm.Name}.", nameof(seed));
        }

        return new MLDsaPrivateKey(MLDsa.ImportMLDsaPrivateSeed(algorithm, seed));
    }

    public static MLDsaPrivateKey ImportSecretKey(MLDsaAlgorithm algorithm, ReadOnlySpan<byte> key, int expected)
    {
        if (key.Length != expected)
        {
            throw new ArgumentException($"Secret key must be {expected} bytes for {algorithm.Name}.", nameof(key));
        }

        return new MLDsaPrivateKey(MLDsa.ImportMLDsaPrivateKey(algorithm, key));
    }

    public static MLDsaPublicKey ImportPublicKey(MLDsaAlgorithm algorithm, ReadOnlySpan<byte> key, int expected)
    {
        if (key.Length != expected)
        {
            throw new ArgumentException($"Public key must be {expected} bytes for {algorithm.Name}.", nameof(key));
        }

        return new MLDsaPublicKey(MLDsa.ImportMLDsaPublicKey(algorithm, key));
    }
}
