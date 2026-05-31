using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Lightweight randomized "fuzz"-style robustness tests. They feed many random
/// and malformed inputs through the KEM/decapsulation paths to assert the
/// library never crashes and honours KEM implicit-rejection semantics (a wrong
/// ciphertext yields a deterministic pseudo-random secret, not an exception).
/// </summary>
/// <remarks>
/// This is a fast in-process property check, not a substitute for a coverage-
/// guided fuzzer; see KNOWN-GAPS.md.
/// </remarks>
public class RobustnessTests
{
    [PqcFact]
    public void MLKem768_RandomGarbageCiphertext_DoesNotThrow_AndIsDeterministic()
    {
        using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();

        for (int i = 0; i < 100; i++)
        {
            byte[] garbage = RandomNumberGenerator.GetBytes(MLKem768.CiphertextSizeInBytes);

            // Implicit rejection: decapsulation of an invalid ciphertext returns
            // a (deterministic, key-bound) value rather than throwing.
            byte[] s1 = priv.Decapsulate(garbage);
            byte[] s2 = priv.Decapsulate(garbage);

            Assert.Equal(MLKem768.SharedSecretSizeInBytes, s1.Length);
            Assert.Equal(s1, s2);
        }
    }

    [PqcFact]
    public void XWing_RandomGarbageCiphertext_DoesNotThrow_AndIsDeterministic()
    {
        using XWingPrivateKey priv = XWing.GenerateKeyPair();

        for (int i = 0; i < 100; i++)
        {
            byte[] garbage = RandomNumberGenerator.GetBytes(XWing.CiphertextSizeInBytes);

            byte[] s1 = priv.Decapsulate(garbage);
            byte[] s2 = priv.Decapsulate(garbage);

            Assert.Equal(XWing.SharedSecretSizeInBytes, s1.Length);
            Assert.Equal(s1, s2);
        }
    }

    [PqcFact]
    public void MLKem768_RepeatedEncapsulation_ProducesDistinctCiphertexts()
    {
        using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
        using MLKemPublicKey pub = priv.GetPublicKey();

        var seen = new HashSet<string>();
        for (int i = 0; i < 50; i++)
        {
            KemEncapsulation enc = pub.Encapsulate();
            Assert.True(seen.Add(Convert.ToHexString(enc.Ciphertext)), "Encapsulation produced a duplicate ciphertext.");
            Assert.Equal(enc.SharedSecret, priv.Decapsulate(enc.Ciphertext));
        }
    }

    [PqcTheory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(1119)]
    [InlineData(1121)]
    public void XWing_WrongCiphertextLength_ThrowsArgumentException(int length)
    {
        using XWingPrivateKey priv = XWing.GenerateKeyPair();
        Assert.Throws<ArgumentException>(() => priv.Decapsulate(new byte[length]));
    }
}
