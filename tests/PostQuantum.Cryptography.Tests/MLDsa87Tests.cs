using System.Text;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

public class MLDsa87Tests
{
    private static readonly byte[] Message = Encoding.UTF8.GetBytes("To God be the glory.");

    [PqcFact]
    public void IsSupported_OnThisPlatform()
    {
        Assert.True(MLDsa87.IsSupported);
    }

    [PqcFact]
    public void SignVerify_RoundTrip()
    {
        using MLDsaPrivateKey privateKey = MLDsa87.GenerateKeyPair();
        using MLDsaPublicKey publicKey = privateKey.GetPublicKey();

        byte[] signature = privateKey.SignData(Message);

        Assert.Equal(MLDsa87.SignatureSizeInBytes, signature.Length);
        Assert.True(publicKey.Verify(Message, signature));
    }

    [PqcFact]
    public void Verify_TamperedMessage_Fails()
    {
        using MLDsaPrivateKey privateKey = MLDsa87.GenerateKeyPair();
        using MLDsaPublicKey publicKey = privateKey.GetPublicKey();

        byte[] signature = privateKey.SignData(Message);
        byte[] tampered = (byte[])Message.Clone();
        tampered[0] ^= 0xff;

        Assert.False(publicKey.Verify(tampered, signature));
    }

    [PqcFact]
    public void Verify_TamperedSignature_Fails()
    {
        using MLDsaPrivateKey privateKey = MLDsa87.GenerateKeyPair();
        using MLDsaPublicKey publicKey = privateKey.GetPublicKey();

        byte[] signature = privateKey.SignData(Message);
        signature[0] ^= 0xff;

        Assert.False(publicKey.Verify(Message, signature));
    }

    [PqcFact]
    public void Context_MustMatchBetweenSignAndVerify()
    {
        byte[] context = Encoding.UTF8.GetBytes("ctx-v1");
        byte[] otherContext = Encoding.UTF8.GetBytes("ctx-v2");

        using MLDsaPrivateKey privateKey = MLDsa87.GenerateKeyPair();
        using MLDsaPublicKey publicKey = privateKey.GetPublicKey();

        byte[] signature = privateKey.SignData(Message, context);

        Assert.True(publicKey.Verify(Message, signature, context));
        Assert.False(publicKey.Verify(Message, signature, otherContext));
        Assert.False(publicKey.Verify(Message, signature));
    }

    [PqcFact]
    public void Constants_MatchNativeAlgorithm()
    {
        var algorithm = System.Security.Cryptography.MLDsaAlgorithm.MLDsa87;
        Assert.Equal(MLDsa87.PublicKeySizeInBytes, algorithm.PublicKeySizeInBytes);
        Assert.Equal(MLDsa87.SecretKeySizeInBytes, algorithm.PrivateKeySizeInBytes);
        Assert.Equal(MLDsa87.SignatureSizeInBytes, algorithm.SignatureSizeInBytes);
        Assert.Equal(MLDsa87.PrivateSeedSizeInBytes, algorithm.PrivateSeedSizeInBytes);
    }

    [PqcFact]
    public void PrivateSeed_DeterministicallyDerivesKeyPair()
    {
        using MLDsaPrivateKey original = MLDsa87.GenerateKeyPair();
        byte[] seed = original.ExportPrivateSeed();

        using MLDsaPrivateKey reimported = MLDsa87.ImportPrivateSeed(seed);

        Assert.Equal(original.ExportPublicKey(), reimported.ExportPublicKey());
        Assert.Equal(original.ExportSecretKey(), reimported.ExportSecretKey());
    }

    [PqcFact]
    public void ImportedSecretKey_CanSign()
    {
        using MLDsaPrivateKey original = MLDsa87.GenerateKeyPair();
        byte[] secretKey = original.ExportSecretKey();

        using MLDsaPrivateKey reimported = MLDsa87.ImportSecretKey(secretKey);
        byte[] signature = reimported.SignData(Message);

        using MLDsaPublicKey publicKey = original.GetPublicKey();
        Assert.True(publicKey.Verify(Message, signature));
    }
}
