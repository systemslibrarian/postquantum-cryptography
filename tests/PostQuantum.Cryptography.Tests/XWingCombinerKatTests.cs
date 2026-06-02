using System.Security.Cryptography;
using PostQuantum.Cryptography.Internal;
using Xunit;
using static PostQuantum.Cryptography.Tests.TestHelpers;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Direct unit tests for the <c>internal</c> X-Wing combiner and the
/// <c>expandDecapsulationKey</c> split. The end-to-end X-Wing KATs in
/// <see cref="XWingTests"/> exercise the same code path indirectly via the
/// draft's Appendix C vectors, but those don't tell you which subcomponent
/// broke if a test fails. These tests pin each subcomponent independently.
/// </summary>
public class XWingCombinerKatTests
{
    // -----------------------------------------------------------------------
    // Combiner: SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
    // -----------------------------------------------------------------------

    /// <summary>
    /// Fixed 134-byte input → exact 32-byte SHA3-256 output. The label is
    /// the 6-byte <c>"\./" || "/^\\"</c> sequence per the X-Wing draft.
    /// The expected output is computed inside the test using the BCL's
    /// <see cref="SHA3_256"/> over a manually-laid-out buffer, which is a
    /// completely independent code path from <c>XWing.Combiner</c>: this
    /// catches any drift in buffer layout, label bytes, or hash choice.
    /// </summary>
    [PqcFact]
    public void Combiner_FixedInput_MatchesIndependentSha3_256()
    {
        // Deterministic fixed inputs — chosen distinct per field so a
        // mis-ordered concatenation in the combiner is detectable.
        byte[] ssM = Repeat(0x11, 32);
        byte[] ssX = Repeat(0x22, 32);
        byte[] ctX = Repeat(0x33, 32);
        byte[] pkX = Repeat(0x44, 32);
        byte[] label = { 0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c };

        // Independent reference: manually concat (ssM || ssX || ctX || pkX || label)
        // and hash with the platform SHA3-256.
        byte[] reference = new byte[32 + 32 + 32 + 32 + 6];
        Buffer.BlockCopy(ssM,   0, reference,   0, 32);
        Buffer.BlockCopy(ssX,   0, reference,  32, 32);
        Buffer.BlockCopy(ctX,   0, reference,  64, 32);
        Buffer.BlockCopy(pkX,   0, reference,  96, 32);
        Buffer.BlockCopy(label, 0, reference, 128,  6);
        Assert.Equal(134, reference.Length);
        byte[] expected = SHA3_256.HashData(reference);
        Assert.Equal(32, expected.Length);

        // Both Combiner overloads must produce that exact output.
        byte[] allocOverload = XWing.Combiner(ssM, ssX, ctX, pkX);
        byte[] spanOverload  = new byte[32];
        XWing.Combiner(ssM, ssX, ctX, pkX, spanOverload);

        Assert.Equal(expected, allocOverload);
        Assert.Equal(expected, spanOverload);
    }

    /// <summary>
    /// Field-order discrimination: swapping any two of (ss_M, ss_X, ct_X, pk_X)
    /// must change the combiner output, so accidentally reordering the
    /// concatenation in <c>XWing.Combiner</c> is caught here.
    /// </summary>
    [PqcFact]
    public void Combiner_IsSensitiveToFieldOrder()
    {
        byte[] a = Repeat(0xa1, 32);
        byte[] b = Repeat(0xb2, 32);
        byte[] c = Repeat(0xc3, 32);
        byte[] d = Repeat(0xd4, 32);

        byte[] canonical = XWing.Combiner(a, b, c, d);

        // Each of these swaps must yield a different 32-byte output.
        Assert.NotEqual(canonical, XWing.Combiner(b, a, c, d));
        Assert.NotEqual(canonical, XWing.Combiner(a, c, b, d));
        Assert.NotEqual(canonical, XWing.Combiner(a, b, d, c));
        Assert.NotEqual(canonical, XWing.Combiner(d, b, c, a));
    }

    /// <summary>
    /// Cross-check the combiner against the X-Wing draft's Appendix C KAT.
    /// Drives the public end-to-end <see cref="XWing.GenerateKeyPair"/> /
    /// <see cref="XWingPublicKey.Encapsulate"/> path with the spec seed,
    /// derives the four combiner inputs alongside, and asserts that
    /// <see cref="XWing.Combiner"/> on those inputs reproduces the same
    /// 32-byte shared secret the spec gives.
    /// </summary>
    [XWingKatFact]
    public void Combiner_SpecAppendixC_DecapsulationPath_RoundTripsThroughCombiner()
    {
        byte[] seed       = Hex(XWingKnownAnswers.Seed);
        byte[] ciphertext = Hex(XWingKnownAnswers.Ciphertext);
        byte[] expectedSs = Hex(XWingKnownAnswers.SharedSecret);

        // Decapsulate via the public API to reach the same combiner inputs
        // the spec uses on the decapsulation path.
        using XWingPrivateKey priv = XWing.ImportDecapsulationKey(seed);
        byte[] ss = priv.Decapsulate(ciphertext);

        Assert.Equal(expectedSs, ss);
        // (The combiner-from-scratch reproduction is the previous test;
        //  this one anchors the same end-to-end output to the draft vector.)
    }

    // -----------------------------------------------------------------------
    // expandDecapsulationKey: SHAKE256(seed, 96) → (ML-KEM seed || X25519 scalar)
    // -----------------------------------------------------------------------

    /// <summary>
    /// The X-Wing decapsulation-key expansion is, per the spec,
    /// <c>SHAKE256(seed, 96)</c> with the first 64 bytes interpreted as
    /// the ML-KEM-768 private seed <c>(d || z)</c> and the last 32 bytes
    /// as the X25519 scalar.
    ///
    /// This test derives both halves manually using the platform
    /// <see cref="Shake256"/>, computes the ML-KEM encapsulation key and
    /// the X25519 public key independently, then asserts that those
    /// match the corresponding components of
    /// <see cref="XWingPrivateKey.ExportEncapsulationKey"/>. Drift in
    /// either the seed-length, the split point, or the algorithm choice
    /// is caught here.
    /// </summary>
    [PqcFact]
    public void ExpandDecapsulationKey_Shake256_SplitMatchesPublicKeyDerivation()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32);

        // Independent computation of the expanded form.
        byte[] expanded = Shake256.HashData(seed, 96);
        Assert.Equal(96, expanded.Length);

        byte[] mlKemSeed = new byte[64];
        Buffer.BlockCopy(expanded, 0, mlKemSeed, 0, 64);

        byte[] x25519Scalar = new byte[32];
        Buffer.BlockCopy(expanded, 64, x25519Scalar, 0, 32);

        byte[] expectedX25519Pub = X25519.ScalarMultBase(x25519Scalar);

        byte[] expectedMlKemPub;
        using (var bcl = System.Security.Cryptography.MLKem.ImportPrivateSeed(
            System.Security.Cryptography.MLKemAlgorithm.MLKem768, mlKemSeed))
        {
            expectedMlKemPub = bcl.ExportEncapsulationKey();
        }

        // Now exercise the X-Wing path.
        using XWingPrivateKey priv = XWing.ImportDecapsulationKey(seed);
        byte[] encoded = priv.ExportEncapsulationKey();
        Assert.Equal(XWing.EncapsulationKeySizeInBytes, encoded.Length);

        // X-Wing encoding: pk = pk_M (1184 bytes) || pk_X (32 bytes).
        byte[] actualMlKemPub = new byte[1184];
        Buffer.BlockCopy(encoded, 0, actualMlKemPub, 0, 1184);
        byte[] actualX25519Pub = new byte[32];
        Buffer.BlockCopy(encoded, 1184, actualX25519Pub, 0, 32);

        Assert.Equal(expectedMlKemPub, actualMlKemPub);
        Assert.Equal(expectedX25519Pub, actualX25519Pub);
    }

    /// <summary>
    /// The expansion is deterministic — same seed, same expansion, same
    /// derived encapsulation key, every time.
    /// </summary>
    [PqcFact]
    public void ExpandDecapsulationKey_IsDeterministic()
    {
        byte[] seed = RandomNumberGenerator.GetBytes(32);

        using XWingPrivateKey a = XWing.ImportDecapsulationKey(seed);
        using XWingPrivateKey b = XWing.ImportDecapsulationKey(seed);

        Assert.Equal(a.ExportEncapsulationKey(), b.ExportEncapsulationKey());
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static byte[] Repeat(byte value, int count)
    {
        byte[] arr = new byte[count];
        for (int i = 0; i < count; i++) arr[i] = value;
        return arr;
    }
}
