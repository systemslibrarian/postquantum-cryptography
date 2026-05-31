using PostQuantum.Cryptography.Internal;
using Xunit;
using static PostQuantum.Cryptography.Tests.TestHelpers;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Known-answer tests for the bundled X25519 implementation, taken verbatim
/// from RFC 7748 (Sections 5.2 and 6.1).
/// </summary>
public class X25519Tests
{
    [Fact]
    public void ScalarMult_Rfc7748_Vector1()
    {
        byte[] scalar = Hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        byte[] u = Hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");

        string result = Hex(X25519.ScalarMult(scalar, u));

        Assert.Equal("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", result);
    }

    [Fact]
    public void ScalarMult_Rfc7748_Vector2()
    {
        byte[] scalar = Hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        byte[] u = Hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");

        string result = Hex(X25519.ScalarMult(scalar, u));

        Assert.Equal("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", result);
    }

    [Fact]
    public void DiffieHellman_Rfc7748_AgreesOnSharedSecret()
    {
        byte[] alicePriv = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPriv = Hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

        byte[] alicePub = X25519.ScalarMultBase(alicePriv);
        byte[] bobPub = X25519.ScalarMultBase(bobPriv);

        Assert.Equal("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", Hex(alicePub));
        Assert.Equal("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", Hex(bobPub));

        string aliceShared = Hex(X25519.ScalarMult(alicePriv, bobPub));
        string bobShared = Hex(X25519.ScalarMult(bobPriv, alicePub));

        Assert.Equal("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", aliceShared);
        Assert.Equal(aliceShared, bobShared);
    }
}
