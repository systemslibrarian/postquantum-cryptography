using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Documents the thread-safety contract by exercising it. The library does
/// not lock or otherwise paper over the underlying BCL types, so:
///
///   1. Operations on <b>different</b> key instances in parallel are safe and
///      independent — verified here under heavy parallelism.
///   2. Operations on the <b>same</b> key instance from multiple threads are
///      not supported. We don't try to "test" that here (the behavior is
///      undefined; a passing test today does not document a future guarantee).
/// </summary>
public class ThreadSafetyTests
{
    [PqcFact]
    public void ManyMLKemKeys_InParallel_AllRoundTrip()
    {
        const int parallelism = 16;
        const int iterationsPerKey = 8;

        Parallel.For(0, parallelism, _ =>
        {
            using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
            using MLKemPublicKey pub = priv.GetPublicKey();

            for (int i = 0; i < iterationsPerKey; i++)
            {
                KemEncapsulation enc = pub.Encapsulate();
                byte[] recovered = priv.Decapsulate(enc.Ciphertext);
                Assert.Equal(enc.SharedSecret, recovered);
            }
        });
    }

    [PqcFact]
    public void ManyMLDsaKeys_InParallel_AllSignAndVerify()
    {
        const int parallelism = 16;
        const int iterationsPerKey = 4;
        byte[] message = "thread-safety/parallel"u8.ToArray();

        Parallel.For(0, parallelism, _ =>
        {
            using MLDsaPrivateKey signer = MLDsa87.GenerateKeyPair();
            using MLDsaPublicKey verifier = signer.GetPublicKey();

            for (int i = 0; i < iterationsPerKey; i++)
            {
                byte[] sig = signer.SignData(message);
                Assert.True(verifier.Verify(message, sig));
            }
        });
    }

    [PqcFact]
    public void ManyXWingKeys_InParallel_AllRoundTrip()
    {
        const int parallelism = 16;
        const int iterationsPerKey = 4;

        Parallel.For(0, parallelism, _ =>
        {
            using XWingPrivateKey priv = XWing.GenerateKeyPair();
            using XWingPublicKey pub = priv.GetPublicKey();

            for (int i = 0; i < iterationsPerKey; i++)
            {
                KemEncapsulation enc = pub.Encapsulate();
                byte[] recovered = priv.Decapsulate(enc.Ciphertext);
                Assert.Equal(enc.SharedSecret, recovered);
            }
        });
    }

    [PqcFact]
    public void StaticFacades_ImportFromSeed_InParallel_AllDeterministic()
    {
        // Static facades like MLKem768.ImportPrivateSeed are safe to call from
        // any thread — they create fresh instances. With the same seed every
        // call produces byte-identical keys.
        byte[] seed = new byte[MLKem768.PrivateSeedSizeInBytes];
        for (int i = 0; i < seed.Length; i++) seed[i] = (byte)i;

        byte[][] keys = new byte[32][];
        Parallel.For(0, keys.Length, i =>
        {
            using MLKemPrivateKey priv = MLKem768.ImportPrivateSeed(seed);
            keys[i] = priv.ExportEncapsulationKey();
        });

        byte[] reference = keys[0];
        foreach (byte[] k in keys)
        {
            Assert.Equal(reference, k);
        }
    }
}
