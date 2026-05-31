using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Systematic disposal-idempotency tests across every disposable key type,
/// plus cross-algorithm misuse tests (verifying with the wrong parameter set,
/// decapsulating a ciphertext from the wrong parameter set, etc.) — these
/// must fail cleanly with a clear exception, never silently corrupt or crash.
/// </summary>
public class DisposalAndCrossAlgorithmTests
{
    // -- Disposal idempotency ------------------------------------------------

    [PqcFact]
    public void MLKemPrivateKey_Dispose_IsIdempotent()
    {
        MLKemPrivateKey k = MLKem768.GenerateKeyPair();
        k.Dispose();
        k.Dispose(); // must not throw
    }

    [PqcFact]
    public void MLKemPublicKey_Dispose_IsIdempotent()
    {
        using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
        MLKemPublicKey pub = priv.GetPublicKey();
        pub.Dispose();
        pub.Dispose();
    }

    [PqcFact]
    public void MLDsaPrivateKey_Dispose_IsIdempotent()
    {
        MLDsaPrivateKey k = MLDsa87.GenerateKeyPair();
        k.Dispose();
        k.Dispose();
    }

    [PqcFact]
    public void MLDsaPublicKey_Dispose_IsIdempotent()
    {
        using MLDsaPrivateKey priv = MLDsa87.GenerateKeyPair();
        MLDsaPublicKey pub = priv.GetPublicKey();
        pub.Dispose();
        pub.Dispose();
    }

    [PqcFact]
    public void XWingPrivateKey_Dispose_IsIdempotent()
    {
        XWingPrivateKey k = XWing.GenerateKeyPair();
        k.Dispose();
        k.Dispose();
    }

    [PqcFact]
    public void XWingPublicKey_Dispose_IsIdempotent()
    {
        using XWingPrivateKey priv = XWing.GenerateKeyPair();
        XWingPublicKey pub = priv.GetPublicKey();
        pub.Dispose();
        pub.Dispose();
    }

    // -- Use-after-dispose throws ObjectDisposedException --------------------

    [PqcFact]
    public void MLKemPrivateKey_AfterDispose_AllOpsThrow()
    {
        MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
        priv.Dispose();
        Assert.Throws<ObjectDisposedException>(() => priv.Decapsulate(new byte[MLKem768.CiphertextSizeInBytes]));
        Assert.Throws<ObjectDisposedException>(() => priv.ExportEncapsulationKey());
        Assert.Throws<ObjectDisposedException>(() => priv.ExportDecapsulationKey());
        Assert.Throws<ObjectDisposedException>(() => priv.ExportPrivateSeed());
        Assert.Throws<ObjectDisposedException>(() => priv.GetPublicKey());
    }

    [PqcFact]
    public void MLDsaPrivateKey_AfterDispose_AllOpsThrow()
    {
        MLDsaPrivateKey priv = MLDsa87.GenerateKeyPair();
        priv.Dispose();
        Assert.Throws<ObjectDisposedException>(() => priv.SignData("x"u8));
        Assert.Throws<ObjectDisposedException>(() => priv.ExportPublicKey());
        Assert.Throws<ObjectDisposedException>(() => priv.ExportSecretKey());
        Assert.Throws<ObjectDisposedException>(() => priv.ExportPrivateSeed());
        Assert.Throws<ObjectDisposedException>(() => priv.GetPublicKey());
    }

    [PqcFact]
    public void XWingPrivateKey_AfterDispose_AllOpsThrow()
    {
        XWingPrivateKey priv = XWing.GenerateKeyPair();
        priv.Dispose();
        Assert.Throws<ObjectDisposedException>(() => priv.Decapsulate(new byte[XWing.CiphertextSizeInBytes]));
        Assert.Throws<ObjectDisposedException>(() => priv.ExportDecapsulationKey());
        Assert.Throws<ObjectDisposedException>(() => priv.ExportEncapsulationKey());
        Assert.Throws<ObjectDisposedException>(() => priv.GetPublicKey());
    }

    // -- Cross-algorithm misuse ----------------------------------------------

    [PqcFact]
    public void MLKem_DecapsulatingWrongAlgorithmCiphertext_Throws()
    {
        using MLKemPrivateKey k768 = MLKem768.GenerateKeyPair();
        using MLKemPrivateKey k1024 = MLKem1024.GenerateKeyPair();
        using MLKemPublicKey pub1024 = k1024.GetPublicKey();

        // Build a ciphertext at ML-KEM-1024 size (1568 bytes); feed it to
        // ML-KEM-768 (expects 1088). Must fail at the wrapper boundary with
        // ArgumentException, not crash inside the BCL.
        KemEncapsulation enc1024 = pub1024.Encapsulate();
        Assert.Equal(MLKem1024.CiphertextSizeInBytes, enc1024.Ciphertext.Length);

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => k768.Decapsulate(enc1024.Ciphertext));
        Assert.Contains("1088", ex.Message, StringComparison.Ordinal);
    }

    [PqcFact]
    public void MLDsa_VerifyingWithWrongAlgorithmKey_ReturnsFalseOrThrowsCleanly()
    {
        // Sign with ML-DSA-44, verify with ML-DSA-87. The signature length is
        // wrong for 87; the call must fail cleanly (false or a documented
        // exception type), never crash.
        using MLDsaPrivateKey signer44 = MLDsa44.GenerateKeyPair();
        using MLDsaPrivateKey signer87 = MLDsa87.GenerateKeyPair();
        using MLDsaPublicKey verifier87 = signer87.GetPublicKey();

        byte[] message = "cross-algorithm"u8.ToArray();
        byte[] sig44 = signer44.SignData(message);

        bool result;
        try
        {
            result = verifier87.Verify(message, sig44);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            // Either a clean false or a documented exception is acceptable.
            return;
        }

        Assert.False(result);
    }

    [PqcFact]
    public void MLKem_ImportEncapsulationKeyOfWrongParameterSet_Throws()
    {
        using MLKemPrivateKey k1024 = MLKem1024.GenerateKeyPair();
        byte[] ek1024 = k1024.ExportEncapsulationKey();
        Assert.Equal(MLKem1024.EncapsulationKeySizeInBytes, ek1024.Length);

        // Try to import a 1568-byte ML-KEM-1024 encapsulation key as ML-KEM-768.
        Assert.Throws<ArgumentException>(() => MLKem768.ImportEncapsulationKey(ek1024));
    }

    [PqcFact]
    public void MLDsa_ImportPrivateSeedOfWrongParameterSet_StillImportsTheBytes()
    {
        // ML-DSA-44/65/87 all share the 32-byte private seed format. So this
        // import succeeds (the seed length matches), and the resulting key is
        // a valid ML-DSA-44 key — NOT a confusion. The cross-algorithm
        // misuse here is "I called the wrong facade"; the result is a
        // perfectly valid key of the requested parameter set. Document by test.
        byte[] seed = new byte[MLDsa44.PrivateSeedSizeInBytes];
        for (int i = 0; i < seed.Length; i++) seed[i] = (byte)i;

        using MLDsaPrivateKey k44 = MLDsa44.ImportPrivateSeed(seed);
        using MLDsaPrivateKey k87 = MLDsa87.ImportPrivateSeed(seed);

        Assert.Equal(MLDsaAlgorithm.MLDsa44, k44.Algorithm);
        Assert.Equal(MLDsaAlgorithm.MLDsa87, k87.Algorithm);

        // Different parameter sets ⇒ different derived public keys.
        Assert.NotEqual(k44.ExportPublicKey(), k87.ExportPublicKey());
    }
}
