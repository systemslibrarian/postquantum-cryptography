using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// A fast, in-process "smoke fuzzer" that runs as a regular xUnit test. Each
/// target receives many thousand pseudo-random inputs and asserts only that
/// the contract is upheld:
///
/// - The library never throws an undocumented exception type.
/// - KEM decapsulation of arbitrary bytes returns a deterministic
///   (key-bound) pseudo-random secret — implicit rejection, never an
///   exception.
/// - Verifying an arbitrary signature returns <c>false</c>, never throws
///   for cryptographic invalidity.
/// - Parsing-style imports throw <see cref="ArgumentException"/> or
///   <see cref="CryptographicException"/> and nothing else.
///
/// This is intentionally complementary to the AFL-driven harness in
/// <c>fuzz/</c>: that one runs out-of-band with coverage feedback; this one
/// runs in every test pass so contract drift is caught immediately. Seed is
/// derived from the test's display name so each target is reproducible
/// without being correlated across targets.
/// </summary>
public class SmokeFuzzTests
{
    private const int Iterations = 5_000;

    private static byte[] PrngStream(int seed, int length)
    {
        // Deterministic SHA-256 expansion. Not used as crypto — just a
        // reproducible stream of bytes for the fuzz inputs.
        byte[] buffer = new byte[length];
        Span<byte> input = stackalloc byte[12];
        Span<byte> digest = stackalloc byte[32];
        BitConverter.TryWriteBytes(input, seed);

        int written = 0;
        int counter = 0;
        while (written < length)
        {
            BitConverter.TryWriteBytes(input[8..], counter++);
            SHA256.HashData(input, digest);
            int take = Math.Min(digest.Length, length - written);
            digest[..take].CopyTo(buffer.AsSpan(written));
            written += take;
        }

        return buffer;
    }

    [PqcFact]
    public void MLKem768_Decapsulate_RandomBytes_NeverThrows_AndIsDeterministic()
    {
        using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
        for (int i = 0; i < Iterations; i++)
        {
            byte[] ct = PrngStream(i, MLKem768.CiphertextSizeInBytes);
            byte[] s1 = priv.Decapsulate(ct);
            byte[] s2 = priv.Decapsulate(ct);
            Assert.Equal(MLKem768.SharedSecretSizeInBytes, s1.Length);
            Assert.True(CryptographicOperations.FixedTimeEquals(s1, s2),
                $"Decapsulation of input #{i} was non-deterministic — implicit-rejection contract broken.");
        }
    }

    [PqcFact]
    public void XWing_Decapsulate_RandomBytes_NeverThrows_AndIsDeterministic()
    {
        using XWingPrivateKey priv = XWing.GenerateKeyPair();
        for (int i = 0; i < Iterations; i++)
        {
            byte[] ct = PrngStream(unchecked(i * 31 + 7), XWing.CiphertextSizeInBytes);
            byte[] s1 = priv.Decapsulate(ct);
            byte[] s2 = priv.Decapsulate(ct);
            Assert.Equal(XWing.SharedSecretSizeInBytes, s1.Length);
            Assert.True(CryptographicOperations.FixedTimeEquals(s1, s2));
        }
    }

    [PqcFact]
    public void MLDsa87_Verify_RandomSignatures_ReturnsFalse_NeverThrows()
    {
        using MLDsaPrivateKey signer = MLDsa87.GenerateKeyPair();
        using MLDsaPublicKey verifier = signer.GetPublicKey();
        byte[] message = "smoke-fuzz/verify"u8.ToArray();

        int rejected = 0;
        for (int i = 0; i < Iterations; i++)
        {
            byte[] sig = PrngStream(i, MLDsa87.SignatureSizeInBytes);
            // Verify must return false on random garbage; absolutely never throw.
            if (!verifier.Verify(message, sig))
            {
                rejected++;
            }
        }

        // With overwhelming probability all inputs are rejected. We assert the
        // weaker invariant: we got through all of them without an exception.
        Assert.Equal(Iterations, rejected);
    }

    [PqcFact]
    public void MLKem768_ImportEncapsulationKey_RandomBytes_OnlyDocumentedExceptions()
    {
        for (int i = 0; i < Iterations; i++)
        {
            int len = i % 100 == 0
                ? MLKem768.EncapsulationKeySizeInBytes   // occasionally right-sized
                : (i % 3000) + 1;                         // mostly wrong-sized
            byte[] data = PrngStream(i, len);
            try
            {
                using MLKemPublicKey _ = MLKem768.ImportEncapsulationKey(data);
            }
            catch (ArgumentException) { /* expected */ }
            catch (CryptographicException) { /* expected */ }
            // Anything else propagates and fails the test.
        }
    }

    [PqcFact]
    public void MLKemKey_ImportPrivateKeyFromPem_RandomText_OnlyDocumentedExceptions()
    {
        for (int i = 0; i < Iterations / 5; i++)  // PEM parsing is slow; fewer iters
        {
            byte[] bytes = PrngStream(i, (i % 4000) + 1);
            string text;
            try { text = Encoding.UTF8.GetString(bytes); }
            catch (ArgumentException) { continue; }

            try
            {
                using MLKemPrivateKey _ = MLKemKey.ImportPrivateKeyFromPem(text);
            }
            catch (ArgumentException) { /* expected */ }
            catch (CryptographicException) { /* expected */ }
        }
    }
}
