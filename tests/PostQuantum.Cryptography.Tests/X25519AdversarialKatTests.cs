using System.Security.Cryptography;
using PostQuantum.Cryptography.Internal;
using Xunit;
using static PostQuantum.Cryptography.Tests.TestHelpers;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Adversarial known-answer tests for the bundled X25519. These exercise the
/// inputs an external auditor will care about most: non-canonical u-coordinate
/// encodings, the standard small-subgroup ("low-order point") set, and the
/// RFC 7748 §5.2 one-million-iteration chain.
///
/// The 1M-iteration chain is gated as <c>Category=LongRunning</c> so it does
/// not slow down every CI build; everything else runs by default.
/// </summary>
public class X25519AdversarialKatTests
{
    // -----------------------------------------------------------------------
    // Non-canonical u
    // -----------------------------------------------------------------------

    /// <summary>
    /// RFC 7748 §5 requires implementations to mask the high bit of the
    /// u-coordinate before use. Setting that bit on a known-good u must
    /// produce the same output as not setting it.
    /// </summary>
    [Fact]
    public void NonCanonicalU_HighBitSet_IsMaskedAndProducesSameResult()
    {
        // Use the RFC 7748 §6.1 base-point exchange as the known-good input.
        byte[] alicePriv = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPub    = Hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

        byte[] expected = X25519.ScalarMult(alicePriv, bobPub);

        byte[] bobPubHighBitSet = (byte[])bobPub.Clone();
        bobPubHighBitSet[31] |= 0x80;

        byte[] actual = X25519.ScalarMult(alicePriv, bobPubHighBitSet);

        Assert.Equal(expected, actual);
        Assert.Equal(
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
            Hex(actual));
    }

    /// <summary>
    /// The 32-byte u-coordinate is interpreted modulo p = 2^255 - 19. An
    /// encoding equal to p must reduce to 0, and X25519(k, 0) is all zeros
    /// for any clamped k.
    /// </summary>
    [Fact]
    public void NonCanonicalU_EqualToFieldPrime_ReducesToZero()
    {
        byte[] anyScalar = RandomNumberGenerator.GetBytes(32);
        byte[] uZero = new byte[32];

        // p = 2^255 - 19 in little-endian:
        // 0xed, 0xff*30, 0x7f
        byte[] uEqualToP = new byte[32];
        for (int i = 0; i < 32; i++) uEqualToP[i] = 0xff;
        uEqualToP[0] = 0xed;
        uEqualToP[31] = 0x7f;

        byte[] outZero = X25519.ScalarMult(anyScalar, uZero);
        byte[] outP    = X25519.ScalarMult(anyScalar, uEqualToP);

        Assert.Equal(new byte[32], outZero);
        Assert.Equal(outZero, outP);
    }

    /// <summary>
    /// Encoding equal to p+1 must reduce to 1 (and so must encoding equal to
    /// 2^255-1, which is p+18, mod p = 18). These verify that the field
    /// arithmetic correctly accepts inputs in [p, 2^255).
    /// </summary>
    [Fact]
    public void NonCanonicalU_GreaterThanFieldPrime_AgreesWithReducedRepresentative()
    {
        byte[] anyScalar = RandomNumberGenerator.GetBytes(32);

        // p+1 == 2^255 - 18, little-endian: 0xee, 0xff*30, 0x7f
        byte[] uPplus1 = new byte[32];
        for (int i = 0; i < 32; i++) uPplus1[i] = 0xff;
        uPplus1[0] = 0xee;
        uPplus1[31] = 0x7f;

        byte[] uOne = new byte[32];
        uOne[0] = 0x01;

        byte[] outPplus1 = X25519.ScalarMult(anyScalar, uPplus1);
        byte[] outOne    = X25519.ScalarMult(anyScalar, uOne);

        Assert.Equal(outOne, outPplus1);

        // 2^255 - 1 == p + 18, little-endian: 0xff*31, 0x7f
        byte[] u2Pow255minus1 = new byte[32];
        for (int i = 0; i < 32; i++) u2Pow255minus1[i] = 0xff;
        u2Pow255minus1[31] = 0x7f;

        byte[] uEighteen = new byte[32];
        uEighteen[0] = 0x12;

        byte[] outBig = X25519.ScalarMult(anyScalar, u2Pow255minus1);
        byte[] out18  = X25519.ScalarMult(anyScalar, uEighteen);

        Assert.Equal(out18, outBig);
    }

    // -----------------------------------------------------------------------
    // Low-order points
    // -----------------------------------------------------------------------

    /// <summary>
    /// The canonical curve-side small-subgroup ("low-order") u-coordinates
    /// from libsodium's <c>has_small_order</c> blacklist — seven distinct
    /// values whose corresponding points on Curve25519 have order dividing 8.
    /// With the RFC 7748 scalar clamping (low 3 bits cleared, so the clamped
    /// scalar is a multiple of 8), X25519 against any of them yields the
    /// all-zero output. Larger published "low-order" lists add twist-side
    /// points, which do NOT satisfy this all-zero property and are out of
    /// scope here (they are an invalid-curve concern, not a small-subgroup
    /// concern for the bare primitive).
    /// </summary>
    public static IEnumerable<object[]> LowOrderPoints => new[]
    {
        // 0 (order 4 on the curve)
        new object[] { "0000000000000000000000000000000000000000000000000000000000000000" },
        // 1 (order 4)
        new object[] { "0100000000000000000000000000000000000000000000000000000000000000" },
        // Order-8 point: 325606250916557431795983626356110631294008115727848805560023387167927233504
        new object[] { "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800" },
        // Order-8 point: 39382357235489614581723060781553021112529911719440698176882885853963445705823
        new object[] { "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157" },
        // p - 1 (order 4)
        new object[] { "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" },
        // p (order 4, == 0 mod p)
        new object[] { "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" },
        // p + 1 (order 4, == 1 mod p)
        new object[] { "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" },
    };

    [Theory]
    [MemberData(nameof(LowOrderPoints))]
    public void LowOrderPoint_ClampedScalarMult_YieldsAllZeroOutput(string lowOrderHex)
    {
        byte[] u = Hex(lowOrderHex);

        // Try several independent random scalars; under RFC 7748 clamping
        // each one's low 3 bits are forced to zero, so k mod 8 == 0, and
        // k * P == identity == all-zero u-coordinate for every point whose
        // order divides 8.
        for (int trial = 0; trial < 8; trial++)
        {
            byte[] scalar = RandomNumberGenerator.GetBytes(32);
            byte[] result = X25519.ScalarMult(scalar, u);
            Assert.Equal(new byte[32], result);
        }
    }

    /// <summary>
    /// Determinism cross-check: regardless of clamped scalar, X25519 against a
    /// fixed low-order point is the same output. This is what X-Wing relies
    /// on (an attacker-chosen low-order <c>pk_X</c> collapses ss_X to a fixed
    /// value, but the combiner binds <c>pk_X</c> into the derived secret so
    /// no information is leaked across sessions).
    /// </summary>
    [Fact]
    public void LowOrderPoint_OutputIsScalarIndependent()
    {
        byte[] u = Hex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");

        byte[] first = X25519.ScalarMult(RandomNumberGenerator.GetBytes(32), u);
        for (int trial = 0; trial < 16; trial++)
        {
            byte[] next = X25519.ScalarMult(RandomNumberGenerator.GetBytes(32), u);
            Assert.Equal(first, next);
        }
    }

    // -----------------------------------------------------------------------
    // RFC 7748 §5.2 iterated chain — 1,000,000 iterations
    // -----------------------------------------------------------------------

    /// <summary>
    /// RFC 7748 §5.2 iterated test, one million rounds. This is the canonical
    /// proof that the carry chain holds under whatever code the JIT actually
    /// emits (tiered compilation, R2R, etc.) — passing the 1M chain on top
    /// of the 1K chain is overwhelming evidence the field arithmetic is
    /// correct end-to-end.
    ///
    /// Gated <c>Category=LongRunning</c> so it is excluded from the default
    /// CI run. Run with
    /// <c>dotnet test --filter Category=LongRunning</c> when you want it.
    /// </summary>
    [Fact]
    [Trait("Category", "LongRunning")]
    public void Rfc7748_IteratedScalarMult_After1MillionIterations()
    {
        byte[] k = new byte[32];
        k[0] = 9;
        byte[] u = (byte[])k.Clone();

        for (int i = 0; i < 1_000_000; i++)
        {
            byte[] next = X25519.ScalarMult(k, u);
            u = k;
            k = next;
        }

        Assert.Equal(
            "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424",
            Hex(k));
    }
}
