using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Round-trip, size, and PEM/PKCS#8 interchange tests across all three ML-DSA
/// parameter sets (44 / 65 / 87).
/// </summary>
public class MLDsaParameterSetTests
{
    private static readonly byte[] Message = Encoding.UTF8.GetBytes("To God be the glory.");

    public static TheoryData<string> ParameterSets => new() { "44", "65", "87" };

    private static MLDsaPrivateKey Generate(string set) => set switch
    {
        "44" => MLDsa44.GenerateKeyPair(),
        "65" => MLDsa65.GenerateKeyPair(),
        "87" => MLDsa87.GenerateKeyPair(),
        _ => throw new ArgumentOutOfRangeException(nameof(set)),
    };

    [PqcTheory]
    [MemberData(nameof(ParameterSets))]
    public void SignVerify_AllParameterSets(string set)
    {
        using MLDsaPrivateKey priv = Generate(set);
        using MLDsaPublicKey pub = priv.GetPublicKey();

        byte[] sig = priv.SignData(Message);

        Assert.Equal(priv.Algorithm.SignatureSizeInBytes, sig.Length);
        Assert.True(pub.Verify(Message, sig));
    }

    [PqcTheory]
    [MemberData(nameof(ParameterSets))]
    public void ExportedSizes_MatchNativeAlgorithm(string set)
    {
        using MLDsaPrivateKey priv = Generate(set);
        MLDsaAlgorithm alg = priv.Algorithm;

        Assert.Equal(alg.PublicKeySizeInBytes, priv.ExportPublicKey().Length);
        Assert.Equal(alg.PrivateKeySizeInBytes, priv.ExportSecretKey().Length);
        Assert.Equal(alg.PrivateSeedSizeInBytes, priv.ExportPrivateSeed().Length);
    }

    [PqcFact]
    public void Constants_MatchNativeAlgorithm_44()
    {
        MLDsaAlgorithm a = MLDsaAlgorithm.MLDsa44;
        Assert.Equal(MLDsa44.PublicKeySizeInBytes, a.PublicKeySizeInBytes);
        Assert.Equal(MLDsa44.SecretKeySizeInBytes, a.PrivateKeySizeInBytes);
        Assert.Equal(MLDsa44.SignatureSizeInBytes, a.SignatureSizeInBytes);
    }

    [PqcFact]
    public void Constants_MatchNativeAlgorithm_65()
    {
        MLDsaAlgorithm a = MLDsaAlgorithm.MLDsa65;
        Assert.Equal(MLDsa65.PublicKeySizeInBytes, a.PublicKeySizeInBytes);
        Assert.Equal(MLDsa65.SecretKeySizeInBytes, a.PrivateKeySizeInBytes);
        Assert.Equal(MLDsa65.SignatureSizeInBytes, a.SignatureSizeInBytes);
    }

    [PqcFact]
    public void Pkcs8Pem_PrivateKey_RoundTrips_AndSigns()
    {
        using MLDsaPrivateKey original = MLDsa65.GenerateKeyPair();
        string pem = original.ExportPkcs8PrivateKeyPem();

        using MLDsaPrivateKey reimported = MLDsaKey.ImportPrivateKeyFromPem(pem);
        byte[] sig = reimported.SignData(Message);

        using MLDsaPublicKey pub = original.GetPublicKey();
        Assert.True(pub.Verify(Message, sig));
        Assert.Equal(MLDsaAlgorithm.MLDsa65, reimported.Algorithm);
    }

    [PqcFact]
    public void SubjectPublicKeyInfoPem_PublicKey_RoundTrips_AndVerifies()
    {
        using MLDsaPrivateKey priv = MLDsa87.GenerateKeyPair();
        byte[] sig = priv.SignData(Message);

        using MLDsaPublicKey pub = priv.GetPublicKey();
        string pem = pub.ExportSubjectPublicKeyInfoPem();

        using MLDsaPublicKey reimported = MLDsaKey.ImportPublicKeyFromPem(pem);
        Assert.True(reimported.Verify(Message, sig));
    }
}
