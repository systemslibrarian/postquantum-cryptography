using Xunit;

namespace PostQuantum.Cryptography.Tests;

public class MLKem768Tests
{
    [PqcFact]
    public void IsSupported_OnThisPlatform()
    {
        Assert.True(MLKem768.IsSupported);
    }

    [PqcFact]
    public void RoundTrip_ProducesMatchingSharedSecret()
    {
        using MLKemPrivateKey privateKey = MLKem768.GenerateKeyPair();
        using MLKemPublicKey publicKey = privateKey.GetPublicKey();

        KemEncapsulation encapsulation = publicKey.Encapsulate();
        byte[] recovered = privateKey.Decapsulate(encapsulation.Ciphertext);

        Assert.Equal(MLKem768.CiphertextSizeInBytes, encapsulation.Ciphertext.Length);
        Assert.Equal(MLKem768.SharedSecretSizeInBytes, encapsulation.SharedSecret.Length);
        Assert.Equal(encapsulation.SharedSecret, recovered);
    }

    [PqcFact]
    public void Constants_MatchNativeAlgorithm()
    {
        var algorithm = System.Security.Cryptography.MLKemAlgorithm.MLKem768;
        Assert.Equal(MLKem768.EncapsulationKeySizeInBytes, algorithm.EncapsulationKeySizeInBytes);
        Assert.Equal(MLKem768.DecapsulationKeySizeInBytes, algorithm.DecapsulationKeySizeInBytes);
        Assert.Equal(MLKem768.CiphertextSizeInBytes, algorithm.CiphertextSizeInBytes);
        Assert.Equal(MLKem768.SharedSecretSizeInBytes, algorithm.SharedSecretSizeInBytes);
        Assert.Equal(MLKem768.PrivateSeedSizeInBytes, algorithm.PrivateSeedSizeInBytes);
    }

    [PqcFact]
    public void PrivateSeed_DeterministicallyDerivesKeyPair()
    {
        using MLKemPrivateKey original = MLKem768.GenerateKeyPair();
        byte[] seed = original.ExportPrivateSeed();

        using MLKemPrivateKey reimported = MLKem768.ImportPrivateSeed(seed);

        Assert.Equal(original.ExportEncapsulationKey(), reimported.ExportEncapsulationKey());
        Assert.Equal(original.ExportDecapsulationKey(), reimported.ExportDecapsulationKey());
    }

    [PqcFact]
    public void ExportedKeys_HaveStandardSizes()
    {
        using MLKemPrivateKey privateKey = MLKem768.GenerateKeyPair();

        Assert.Equal(MLKem768.EncapsulationKeySizeInBytes, privateKey.ExportEncapsulationKey().Length);
        Assert.Equal(MLKem768.DecapsulationKeySizeInBytes, privateKey.ExportDecapsulationKey().Length);
        Assert.Equal(MLKem768.PrivateSeedSizeInBytes, privateKey.ExportPrivateSeed().Length);
    }

    [PqcFact]
    public void Decapsulate_WrongCiphertextLength_Throws()
    {
        using MLKemPrivateKey privateKey = MLKem768.GenerateKeyPair();
        Assert.Throws<ArgumentException>(() => privateKey.Decapsulate(new byte[10]));
    }

    [PqcFact]
    public void ImportEncapsulationKey_WrongLength_Throws()
    {
        Assert.Throws<ArgumentException>(() => MLKem768.ImportEncapsulationKey(new byte[10]));
    }

    [PqcFact]
    public void UseAfterDispose_Throws()
    {
        MLKemPrivateKey privateKey = MLKem768.GenerateKeyPair();
        privateKey.Dispose();
        Assert.Throws<ObjectDisposedException>(() => privateKey.ExportPrivateSeed());
    }
}
