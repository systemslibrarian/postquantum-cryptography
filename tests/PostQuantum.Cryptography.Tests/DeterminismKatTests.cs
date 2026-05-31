using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Regression-style known-answer tests anchoring the deterministic
/// <c>seed → public key</c> mapping for every primitive in the library.
/// </summary>
/// <remarks>
/// These fingerprints were captured from the BCL's own FIPS 203 / FIPS 204
/// implementations via <c>tools/ComputeFingerprints</c> against a fixed,
/// non-zero seed (each byte equal to its index modulo 256). They guard against
/// any future drift in the wrapper layer that would silently perturb the
/// deterministic mapping — which would be a correctness regression and an
/// interop break.
///
/// Because we don't (and can't) ship official ACVP test vectors here, the
/// authoritative source for the values is the .NET 10 BCL itself. The point
/// of these tests is to detect divergence between "what the BCL would produce
/// directly" and "what callers see through our wrapper."
/// </remarks>
public class DeterminismKatTests
{
    private static byte[] FixedSeed(int size)
    {
        byte[] seed = new byte[size];
        for (int i = 0; i < size; i++)
        {
            seed[i] = (byte)(i & 0xFF);
        }

        return seed;
    }

    private static string Sha256(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    // -- ML-KEM ---------------------------------------------------------

    [PqcFact]
    public void MLKem512_SeedDerivation_MatchesFingerprint()
    {
        using MLKemPrivateKey priv = MLKem512.ImportPrivateSeed(FixedSeed(MLKem512.PrivateSeedSizeInBytes));
        Assert.Equal("3ae268dccc5456ac0d0f9b39257dc48fe081383b97c400512d712b739762daee", Sha256(priv.ExportEncapsulationKey()));
        Assert.Equal("17fb29b8c4baf74fb81eea15ffd583b3e37f5a5b8dcf6db96c72c3b3751d6f17", Sha256(priv.ExportDecapsulationKey()));
    }

    [PqcFact]
    public void MLKem768_SeedDerivation_MatchesFingerprint()
    {
        using MLKemPrivateKey priv = MLKem768.ImportPrivateSeed(FixedSeed(MLKem768.PrivateSeedSizeInBytes));
        Assert.Equal("0b7934c83125c788995e2ba6bd761e33046b3e40571be53e023309a29f398cc9", Sha256(priv.ExportEncapsulationKey()));
        Assert.Equal("dac268bde6a8dd238e9887117d6b664e7a7a9350ad6b7c08a948e504809572a5", Sha256(priv.ExportDecapsulationKey()));
    }

    [PqcFact]
    public void MLKem1024_SeedDerivation_MatchesFingerprint()
    {
        using MLKemPrivateKey priv = MLKem1024.ImportPrivateSeed(FixedSeed(MLKem1024.PrivateSeedSizeInBytes));
        Assert.Equal("c7b8fa0aa471d5ae18922d6ccad5b31e1d84f92ae723abfd13747018740a8530", Sha256(priv.ExportEncapsulationKey()));
        Assert.Equal("3a2a676c5a242ee683cb6097c8f3e64fbef4d90267f9250ec2beab8f99621fad", Sha256(priv.ExportDecapsulationKey()));
    }

    // -- ML-DSA ---------------------------------------------------------

    [PqcFact]
    public void MLDsa44_SeedDerivation_MatchesFingerprint()
    {
        using MLDsaPrivateKey priv = MLDsa44.ImportPrivateSeed(FixedSeed(MLDsa44.PrivateSeedSizeInBytes));
        Assert.Equal("9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46", Sha256(priv.ExportPublicKey()));
        Assert.Equal("04bf6b9f579166a627961dfc5c3bf9717df868db88863856356c4668c8b56b0b", Sha256(priv.ExportSecretKey()));
    }

    [PqcFact]
    public void MLDsa65_SeedDerivation_MatchesFingerprint()
    {
        using MLDsaPrivateKey priv = MLDsa65.ImportPrivateSeed(FixedSeed(MLDsa65.PrivateSeedSizeInBytes));
        Assert.Equal("d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9", Sha256(priv.ExportPublicKey()));
        Assert.Equal("9f1e24f47795fe50040384e3d6183988047170fa2d866406b70fe0a3f8216063", Sha256(priv.ExportSecretKey()));
    }

    [PqcFact]
    public void MLDsa87_SeedDerivation_MatchesFingerprint()
    {
        using MLDsaPrivateKey priv = MLDsa87.ImportPrivateSeed(FixedSeed(MLDsa87.PrivateSeedSizeInBytes));
        Assert.Equal("91dc389cfaa01470b7f66eee45a4ae9026d154817c754dfe22298b3fa241ffcd", Sha256(priv.ExportPublicKey()));
        Assert.Equal("764d3e223ed90c07bc91a0ab6ecd170e5c66ffe39f7039298596039a36005435", Sha256(priv.ExportSecretKey()));
    }

    // -- X-Wing ---------------------------------------------------------

    [PqcFact]
    public void XWing_SeedDerivation_MatchesFingerprint()
    {
        using XWingPrivateKey priv = XWing.ImportDecapsulationKey(FixedSeed(XWing.DecapsulationKeySizeInBytes));
        Assert.Equal("c9a3565ffde4f72b51661be391ee13e46378d7f06dd5c8bf5af9d2cfb5b8336b", Sha256(priv.ExportEncapsulationKey()));
    }

    // -- Cross-check: wrapper byte-equality with direct BCL --------------

    [PqcFact]
    public void MLKem768_Wrapper_ProducesSameBytes_AsDirectBcl()
    {
        byte[] seed = FixedSeed(MLKem768.PrivateSeedSizeInBytes);
        using MLKemPrivateKey wrapper = MLKem768.ImportPrivateSeed(seed);
        using MLKem direct = MLKem.ImportPrivateSeed(MLKemAlgorithm.MLKem768, seed);

        Assert.Equal(direct.ExportEncapsulationKey(), wrapper.ExportEncapsulationKey());
        Assert.Equal(direct.ExportDecapsulationKey(), wrapper.ExportDecapsulationKey());
        Assert.Equal(direct.ExportPrivateSeed(),      wrapper.ExportPrivateSeed());
    }

    [PqcFact]
    public void MLDsa87_Wrapper_ProducesSameBytes_AsDirectBcl()
    {
        byte[] seed = FixedSeed(MLDsa87.PrivateSeedSizeInBytes);
        using MLDsaPrivateKey wrapper = MLDsa87.ImportPrivateSeed(seed);
        using MLDsa direct = MLDsa.ImportMLDsaPrivateSeed(MLDsaAlgorithm.MLDsa87, seed);

        Assert.Equal(direct.ExportMLDsaPublicKey(), wrapper.ExportPublicKey());
        Assert.Equal(direct.ExportMLDsaPrivateKey(), wrapper.ExportSecretKey());
        Assert.Equal(direct.ExportMLDsaPrivateSeed(), wrapper.ExportPrivateSeed());
    }

}
