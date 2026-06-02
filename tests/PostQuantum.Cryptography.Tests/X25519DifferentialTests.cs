using System.Security.Cryptography;
using PostQuantum.Cryptography.Internal;
using Xunit;
using BcX25519 = Org.BouncyCastle.Math.EC.Rfc7748.X25519;
using static PostQuantum.Cryptography.Tests.TestHelpers;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Byte-for-byte differential KAT of the bundled X25519 against
/// <c>Org.BouncyCastle.Math.EC.Rfc7748.X25519</c>. BouncyCastle is an
/// independent, widely-deployed RFC 7748 implementation; agreement
/// across both implementations on every vector and on random inputs is
/// the canonical proof of cross-implementation correctness.
///
/// The BouncyCastle dependency lives on the tests project only — see
/// the comment in <c>PostQuantum.Cryptography.Tests.csproj</c>. The
/// library itself does NOT depend on BouncyCastle and its NuGet
/// package is unchanged by these tests.
/// </summary>
public class X25519DifferentialTests
{
    /// <summary>
    /// RFC 7748 §5.2 — vectors 1 and 2. Both implementations must agree
    /// with the spec value and with each other.
    /// </summary>
    [Theory]
    [InlineData(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")]
    [InlineData(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")]
    public void Rfc7748_KnownVector_AgreesWithBouncyCastleAndSpec(string scalarHex, string uHex, string expectedHex)
    {
        byte[] scalar = Hex(scalarHex);
        byte[] u      = Hex(uHex);

        byte[] ours = X25519.ScalarMult(scalar, u);
        byte[] theirs = BouncyCastleScalarMult(scalar, u);

        Assert.Equal(expectedHex, Hex(ours));
        Assert.Equal(ours, theirs);
    }

    /// <summary>
    /// RFC 7748 §6.1 base-point exchange via <c>ScalarMultBase</c>. Both
    /// implementations must agree with the spec public keys and with each
    /// other.
    /// </summary>
    [Theory]
    [InlineData(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")]
    [InlineData(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")]
    public void Rfc7748_ScalarMultBase_AgreesWithBouncyCastleAndSpec(string scalarHex, string expectedHex)
    {
        byte[] scalar = Hex(scalarHex);

        byte[] ours = X25519.ScalarMultBase(scalar);
        byte[] theirs = BouncyCastleScalarMultBase(scalar);

        Assert.Equal(expectedHex, Hex(ours));
        Assert.Equal(ours, theirs);
    }

    /// <summary>
    /// 128 random (scalar, u) pairs. Each pair must produce byte-identical
    /// output across both implementations.
    /// </summary>
    [Fact]
    public void Random_ScalarMult_AgreesWithBouncyCastle()
    {
        for (int i = 0; i < 128; i++)
        {
            byte[] scalar = RandomNumberGenerator.GetBytes(32);
            byte[] u      = RandomNumberGenerator.GetBytes(32);

            byte[] ours = X25519.ScalarMult(scalar, u);
            byte[] theirs = BouncyCastleScalarMult(scalar, u);

            Assert.Equal(theirs, ours);
        }
    }

    /// <summary>
    /// 128 random scalars through <c>ScalarMultBase</c>.
    /// </summary>
    [Fact]
    public void Random_ScalarMultBase_AgreesWithBouncyCastle()
    {
        for (int i = 0; i < 128; i++)
        {
            byte[] scalar = RandomNumberGenerator.GetBytes(32);

            byte[] ours = X25519.ScalarMultBase(scalar);
            byte[] theirs = BouncyCastleScalarMultBase(scalar);

            Assert.Equal(theirs, ours);
        }
    }

    /// <summary>
    /// Adversarial cross-check: u-coordinates with the high bit set should
    /// produce identical output in both implementations, because both must
    /// mask the high bit per RFC 7748 §5.
    /// </summary>
    [Fact]
    public void HighBitSetU_AgreesWithBouncyCastle()
    {
        for (int i = 0; i < 64; i++)
        {
            byte[] scalar = RandomNumberGenerator.GetBytes(32);
            byte[] u      = RandomNumberGenerator.GetBytes(32);
            u[31] |= 0x80;

            byte[] ours = X25519.ScalarMult(scalar, u);
            byte[] theirs = BouncyCastleScalarMult(scalar, u);

            Assert.Equal(theirs, ours);
        }
    }

    private static byte[] BouncyCastleScalarMult(byte[] scalar, byte[] u)
    {
        byte[] output = new byte[32];
        BcX25519.ScalarMult(scalar, 0, u, 0, output, 0);
        return output;
    }

    private static byte[] BouncyCastleScalarMultBase(byte[] scalar)
    {
        byte[] output = new byte[32];
        BcX25519.ScalarMultBase(scalar, 0, output, 0);
        return output;
    }
}
