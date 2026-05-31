using Xunit;
using static PostQuantum.Cryptography.Tests.TestHelpers;

namespace PostQuantum.Cryptography.Tests;

public class XWingTests
{
    [PqcFact]
    public void IsSupported_OnThisPlatform()
    {
        Assert.True(XWing.IsSupported);
    }

    [PqcFact]
    public void RoundTrip_ProducesMatchingSharedSecret()
    {
        using XWingPrivateKey privateKey = XWing.GenerateKeyPair();
        XWingPublicKey publicKey = privateKey.GetPublicKey();

        KemEncapsulation encapsulation = publicKey.Encapsulate();
        byte[] recovered = privateKey.Decapsulate(encapsulation.Ciphertext);

        Assert.Equal(XWing.CiphertextSizeInBytes, encapsulation.Ciphertext.Length);
        Assert.Equal(XWing.SharedSecretSizeInBytes, encapsulation.SharedSecret.Length);
        Assert.Equal(encapsulation.SharedSecret, recovered);
    }

    [PqcFact]
    public void CachedExpandedKey_RepeatedDecapsulation_IsConsistent()
    {
        // Exercises the §5.5.1 cached expanded-decapsulation-key optimization:
        // the seed is expanded once and reused across many decapsulations.
        using XWingPrivateKey recipient = XWing.GenerateKeyPair();
        XWingPublicKey publicKey = recipient.GetPublicKey();

        for (int i = 0; i < 16; i++)
        {
            KemEncapsulation enc = publicKey.Encapsulate();
            byte[] recovered = recipient.Decapsulate(enc.Ciphertext);
            Assert.Equal(enc.SharedSecret, recovered);
        }
    }

    [PqcFact]
    public void CrossParty_AliceEncapsulatesToBob()
    {
        // Bob generates a key pair and publishes his encapsulation key.
        using XWingPrivateKey bob = XWing.GenerateKeyPair();
        byte[] bobPublicKeyBytes = bob.ExportEncapsulationKey();

        // Alice imports it and encapsulates.
        XWingPublicKey bobPublicKey = XWing.ImportEncapsulationKey(bobPublicKeyBytes);
        KemEncapsulation encapsulation = bobPublicKey.Encapsulate();

        // Bob decapsulates and recovers the same secret.
        byte[] bobSecret = bob.Decapsulate(encapsulation.Ciphertext);

        Assert.Equal(encapsulation.SharedSecret, bobSecret);
    }

    [PqcFact]
    public void ExportedKeys_HaveStandardSizes()
    {
        using XWingPrivateKey privateKey = XWing.GenerateKeyPair();

        Assert.Equal(XWing.DecapsulationKeySizeInBytes, privateKey.ExportDecapsulationKey().Length);
        Assert.Equal(XWing.EncapsulationKeySizeInBytes, privateKey.ExportEncapsulationKey().Length);
        Assert.Equal(XWing.EncapsulationKeySizeInBytes, privateKey.GetPublicKey().Export().Length);
    }

    [PqcFact]
    public void DecapsulationKey_DeterministicallyDerivesEncapsulationKey()
    {
        using XWingPrivateKey original = XWing.GenerateKeyPair();
        byte[] seed = original.ExportDecapsulationKey();

        using XWingPrivateKey reimported = XWing.ImportDecapsulationKey(seed);

        Assert.Equal(original.ExportEncapsulationKey(), reimported.ExportEncapsulationKey());
    }

    [PqcFact]
    public void Decapsulate_WrongCiphertextLength_Throws()
    {
        using XWingPrivateKey privateKey = XWing.GenerateKeyPair();
        Assert.Throws<ArgumentException>(() => privateKey.Decapsulate(new byte[10]));
    }

    [PqcFact]
    public void ImportEncapsulationKey_WrongLength_Throws()
    {
        Assert.Throws<ArgumentException>(() => XWing.ImportEncapsulationKey(new byte[10]));
    }

    [PqcFact]
    public void UseAfterDispose_Throws()
    {
        XWingPrivateKey privateKey = XWing.GenerateKeyPair();
        privateKey.Dispose();
        Assert.Throws<ObjectDisposedException>(() => privateKey.ExportDecapsulationKey());
    }

    [XWingKatFact]
    public void Kat_KeyGeneration_MatchesSpecEncapsulationKey()
    {
        using XWingPrivateKey privateKey = XWing.ImportDecapsulationKey(Hex(XWingKnownAnswers.Seed));

        Assert.Equal(XWingKnownAnswers.EncapsulationKey, Hex(privateKey.ExportEncapsulationKey()));
    }

    [XWingKatFact]
    public void Kat_Decapsulation_MatchesSpecSharedSecret()
    {
        using XWingPrivateKey privateKey = XWing.ImportDecapsulationKey(Hex(XWingKnownAnswers.Seed));
        byte[] sharedSecret = privateKey.Decapsulate(Hex(XWingKnownAnswers.Ciphertext));

        Assert.Equal(XWingKnownAnswers.SharedSecret, Hex(sharedSecret));
    }
}
