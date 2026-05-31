using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Round-trip, size, and PEM/PKCS#8 interchange tests across all three ML-KEM
/// parameter sets (512 / 768 / 1024).
/// </summary>
public class MLKemParameterSetTests
{
    public static TheoryData<string> ParameterSets => new() { "512", "768", "1024" };

    private static MLKemPrivateKey Generate(string set) => set switch
    {
        "512" => MLKem512.GenerateKeyPair(),
        "768" => MLKem768.GenerateKeyPair(),
        "1024" => MLKem1024.GenerateKeyPair(),
        _ => throw new ArgumentOutOfRangeException(nameof(set)),
    };

    [PqcTheory]
    [MemberData(nameof(ParameterSets))]
    public void RoundTrip_AllParameterSets(string set)
    {
        using MLKemPrivateKey priv = Generate(set);
        using MLKemPublicKey pub = priv.GetPublicKey();

        KemEncapsulation enc = pub.Encapsulate();
        byte[] recovered = priv.Decapsulate(enc.Ciphertext);

        Assert.Equal(enc.SharedSecret, recovered);
        Assert.Equal(priv.Algorithm.CiphertextSizeInBytes, enc.Ciphertext.Length);
        Assert.Equal(32, enc.SharedSecret.Length);
    }

    [PqcTheory]
    [MemberData(nameof(ParameterSets))]
    public void ExportedSizes_MatchNativeAlgorithm(string set)
    {
        using MLKemPrivateKey priv = Generate(set);
        MLKemAlgorithm alg = priv.Algorithm;

        Assert.Equal(alg.EncapsulationKeySizeInBytes, priv.ExportEncapsulationKey().Length);
        Assert.Equal(alg.DecapsulationKeySizeInBytes, priv.ExportDecapsulationKey().Length);
        Assert.Equal(alg.PrivateSeedSizeInBytes, priv.ExportPrivateSeed().Length);
    }

    [PqcFact]
    public void Constants_MatchNativeAlgorithm_512()
    {
        MLKemAlgorithm a = MLKemAlgorithm.MLKem512;
        Assert.Equal(MLKem512.EncapsulationKeySizeInBytes, a.EncapsulationKeySizeInBytes);
        Assert.Equal(MLKem512.DecapsulationKeySizeInBytes, a.DecapsulationKeySizeInBytes);
        Assert.Equal(MLKem512.CiphertextSizeInBytes, a.CiphertextSizeInBytes);
    }

    [PqcFact]
    public void Constants_MatchNativeAlgorithm_1024()
    {
        MLKemAlgorithm a = MLKemAlgorithm.MLKem1024;
        Assert.Equal(MLKem1024.EncapsulationKeySizeInBytes, a.EncapsulationKeySizeInBytes);
        Assert.Equal(MLKem1024.DecapsulationKeySizeInBytes, a.DecapsulationKeySizeInBytes);
        Assert.Equal(MLKem1024.CiphertextSizeInBytes, a.CiphertextSizeInBytes);
    }

    [PqcFact]
    public void Pkcs8Pem_PrivateKey_RoundTrips()
    {
        using MLKemPrivateKey original = MLKem768.GenerateKeyPair();
        string pem = original.ExportPkcs8PrivateKeyPem();

        using MLKemPrivateKey reimported = MLKemKey.ImportPrivateKeyFromPem(pem);

        Assert.Equal(original.ExportDecapsulationKey(), reimported.ExportDecapsulationKey());
        Assert.Equal(MLKemAlgorithm.MLKem768, reimported.Algorithm);
    }

    [PqcFact]
    public void Pkcs8Der_PrivateKey_RoundTrips()
    {
        using MLKemPrivateKey original = MLKem1024.GenerateKeyPair();
        byte[] der = original.ExportPkcs8PrivateKey();

        using MLKemPrivateKey reimported = MLKemKey.ImportPkcs8PrivateKey(der);

        Assert.Equal(original.ExportDecapsulationKey(), reimported.ExportDecapsulationKey());
        Assert.Equal(MLKemAlgorithm.MLKem1024, reimported.Algorithm);
    }

    [PqcFact]
    public void SubjectPublicKeyInfoPem_PublicKey_RoundTrips_AndEncapsulates()
    {
        using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
        using MLKemPublicKey pub = priv.GetPublicKey();
        string pem = pub.ExportSubjectPublicKeyInfoPem();

        using MLKemPublicKey reimported = MLKemKey.ImportPublicKeyFromPem(pem);
        KemEncapsulation enc = reimported.Encapsulate();
        byte[] recovered = priv.Decapsulate(enc.Ciphertext);

        Assert.Equal(enc.SharedSecret, recovered);
    }
}
