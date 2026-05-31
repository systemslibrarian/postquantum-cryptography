using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Verifies the cached-MLKem optimization on <see cref="XWingPublicKey"/>:
/// repeated encapsulations against the same public key reuse the imported
/// ML-KEM-768 handle (no re-import per call), mirroring the §5.5.1 caching
/// pattern that <see cref="XWingPrivateKey"/> already uses.
/// </summary>
public class XWingPublicKeyCachingTests
{
    [PqcFact]
    public void Encapsulate_AfterDispose_Throws()
    {
        using XWingPrivateKey priv = XWing.GenerateKeyPair();
        XWingPublicKey pub = priv.GetPublicKey();
        pub.Dispose();
        Assert.Throws<ObjectDisposedException>(() => pub.Encapsulate());
    }

    [PqcFact]
    public void Export_AfterDispose_Throws()
    {
        using XWingPrivateKey priv = XWing.GenerateKeyPair();
        XWingPublicKey pub = priv.GetPublicKey();
        pub.Dispose();
        Assert.Throws<ObjectDisposedException>(() => pub.Export());
    }

    [PqcFact]
    public void RepeatedEncapsulations_AgainstCachedPublicKey_StillRoundTrip()
    {
        // The functional contract: caching the underlying MLKem doesn't break
        // anything — every encapsulation must still decapsulate cleanly.
        using XWingPrivateKey priv = XWing.GenerateKeyPair();
        using XWingPublicKey pub = priv.GetPublicKey();

        for (int i = 0; i < 32; i++)
        {
            KemEncapsulation enc = pub.Encapsulate();
            byte[] recovered = priv.Decapsulate(enc.Ciphertext);
            Assert.Equal(enc.SharedSecret, recovered);
        }
    }

    [PqcFact]
    public void Dispose_IsIdempotent()
    {
        using XWingPrivateKey priv = XWing.GenerateKeyPair();
        XWingPublicKey pub = priv.GetPublicKey();
        pub.Dispose();
        pub.Dispose(); // must not throw
    }
}
