using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Cross-checks the byte-oriented one-shot facades (<see cref="MlKemOperations"/>,
/// <see cref="MLDsaOperations"/>, <see cref="XWingHybridKem"/>) against the
/// typed API. The two surfaces must produce bit-identical results for the
/// same inputs.
/// </summary>
public class ConvenienceFacadeTests
{
    private static readonly byte[] Message = "convenience-facade"u8.ToArray();

    // -- MlKemOperations -----------------------------------------------------

    [PqcTheory]
    [InlineData("MLKem512")]
    [InlineData("MLKem768")]
    [InlineData("MLKem1024")]
    public void MlKemOperations_RoundTrip_AgainstAllParameterSets(string set)
    {
        MLKemAlgorithm algorithm = set switch
        {
            "MLKem512" => MLKemAlgorithm.MLKem512,
            "MLKem768" => MLKemAlgorithm.MLKem768,
            "MLKem1024" => MLKemAlgorithm.MLKem1024,
            _ => throw new ArgumentOutOfRangeException(nameof(set)),
        };

        (byte[] ek, byte[] seed) = MlKemOperations.GenerateKeyPair(algorithm);
        Assert.Equal(algorithm.EncapsulationKeySizeInBytes, ek.Length);
        Assert.Equal(algorithm.PrivateSeedSizeInBytes, seed.Length);

        KemEncapsulation enc = MlKemOperations.Encapsulate(algorithm, ek);
        byte[] recoveredFromSeed = MlKemOperations.DecapsulateFromSeed(algorithm, seed, enc.Ciphertext);

        Assert.Equal(enc.SharedSecret, recoveredFromSeed);
    }

    [PqcFact]
    public void MlKemOperations_AgreesWithTypedApi_FromSameSeed()
    {
        byte[] seed = new byte[MLKemAlgorithm.MLKem768.PrivateSeedSizeInBytes];
        for (int i = 0; i < seed.Length; i++) seed[i] = (byte)i;

        // Typed path: import seed → public key bytes
        using MLKemPrivateKey typedPriv = MLKem768.ImportPrivateSeed(seed);
        byte[] typedEk = typedPriv.ExportEncapsulationKey();

        // Convenience path: derive a brand-new pair, but re-derive the typed
        // way too and assert the typed-derived public key is byte-equal to
        // what we'd get if we passed the same seed through the convenience
        // facade (we can't, since GenerateKeyPair has no seed-input variant;
        // instead we round-trip through the typed path and use the convenience
        // facade for encap/decap).
        KemEncapsulation enc = MlKemOperations.Encapsulate(MLKemAlgorithm.MLKem768, typedEk);
        byte[] recovered = MlKemOperations.DecapsulateFromSeed(MLKemAlgorithm.MLKem768, seed, enc.Ciphertext);

        Assert.Equal(enc.SharedSecret, recovered);
    }

    [PqcFact]
    public void MlKemOperations_WrongSizedInputs_ThrowClearArgumentException()
    {
        byte[] bogus = new byte[10];

        ArgumentException ex1 = Assert.Throws<ArgumentException>(
            () => MlKemOperations.Encapsulate(MLKemAlgorithm.MLKem768, bogus));
        Assert.Contains(MLKemAlgorithm.MLKem768.Name, ex1.Message, StringComparison.Ordinal);
        Assert.Contains("1184", ex1.Message, StringComparison.Ordinal);

        ArgumentException ex2 = Assert.Throws<ArgumentException>(
            () => MlKemOperations.Decapsulate(MLKemAlgorithm.MLKem768, new byte[10], new byte[10]));
        Assert.Contains(MLKemAlgorithm.MLKem768.Name, ex2.Message, StringComparison.Ordinal);
    }

    // -- MLDsaOperations -----------------------------------------------------

    [PqcTheory]
    [InlineData("MLDsa44")]
    [InlineData("MLDsa65")]
    [InlineData("MLDsa87")]
    public void MLDsaOperations_RoundTrip_AgainstAllParameterSets(string set)
    {
        MLDsaAlgorithm algorithm = set switch
        {
            "MLDsa44" => MLDsaAlgorithm.MLDsa44,
            "MLDsa65" => MLDsaAlgorithm.MLDsa65,
            "MLDsa87" => MLDsaAlgorithm.MLDsa87,
            _ => throw new ArgumentOutOfRangeException(nameof(set)),
        };

        (byte[] pk, byte[] seed) = MLDsaOperations.GenerateKeyPair(algorithm);
        Assert.Equal(algorithm.PublicKeySizeInBytes, pk.Length);
        Assert.Equal(algorithm.PrivateSeedSizeInBytes, seed.Length);

        byte[] sig = MLDsaOperations.SignData(algorithm, seed, Message);
        Assert.Equal(algorithm.SignatureSizeInBytes, sig.Length);

        Assert.True(MLDsaOperations.VerifyData(algorithm, pk, Message, sig));
    }

    [PqcFact]
    public void MLDsaOperations_ContextBinding_IsEnforced()
    {
        (byte[] pk, byte[] seed) = MLDsaOperations.GenerateKeyPair(MLDsaAlgorithm.MLDsa87);
        byte[] context = "test-domain"u8.ToArray();

        byte[] sig = MLDsaOperations.SignData(MLDsaAlgorithm.MLDsa87, seed, Message, context);

        Assert.True(MLDsaOperations.VerifyData(MLDsaAlgorithm.MLDsa87, pk, Message, sig, context));
        Assert.False(MLDsaOperations.VerifyData(MLDsaAlgorithm.MLDsa87, pk, Message, sig, "other"u8));
        Assert.False(MLDsaOperations.VerifyData(MLDsaAlgorithm.MLDsa87, pk, Message, sig));
    }

    [PqcFact]
    public void MLDsaOperations_VerifyData_WrongSignatureLength_ReturnsFalse()
    {
        (byte[] pk, byte[] seed) = MLDsaOperations.GenerateKeyPair(MLDsaAlgorithm.MLDsa87);

        // Wrong-size signature must just return false, never throw.
        Assert.False(MLDsaOperations.VerifyData(MLDsaAlgorithm.MLDsa87, pk, Message, new byte[10]));
    }

    [PqcFact]
    public void MLDsaOperations_ContextOverFipsLimit_Throws()
    {
        (byte[] _, byte[] seed) = MLDsaOperations.GenerateKeyPair(MLDsaAlgorithm.MLDsa87);
        Assert.Throws<ArgumentException>(
            () => MLDsaOperations.SignData(MLDsaAlgorithm.MLDsa87, seed, Message, new byte[300]));
    }

    // -- XWingHybridKem ------------------------------------------------------

    [PqcFact]
    public void XWingHybridKem_RoundTrip()
    {
        (byte[] ek, byte[] dk) = XWingHybridKem.GenerateKeyPair();
        Assert.Equal(XWingHybridKem.EncapsulationKeySizeInBytes, ek.Length);
        Assert.Equal(XWingHybridKem.DecapsulationKeySizeInBytes, dk.Length);

        KemEncapsulation enc = XWingHybridKem.Encapsulate(ek);
        Assert.Equal(XWingHybridKem.CiphertextSizeInBytes, enc.Ciphertext.Length);
        Assert.Equal(XWingHybridKem.SharedSecretSizeInBytes, enc.SharedSecret.Length);

        byte[] recovered = XWingHybridKem.Decapsulate(dk, enc.Ciphertext);
        Assert.Equal(enc.SharedSecret, recovered);
    }

    [PqcFact]
    public void XWingHybridKem_AgreesWithTypedApi()
    {
        // Use the convenience facade to generate; verify the typed API can
        // decapsulate the same ciphertext using the seed bytes.
        (byte[] ek, byte[] dk) = XWingHybridKem.GenerateKeyPair();
        KemEncapsulation enc = XWingHybridKem.Encapsulate(ek);

        using XWingPrivateKey typed = XWing.ImportDecapsulationKey(dk);
        byte[] viaTyped = typed.Decapsulate(enc.Ciphertext);

        Assert.Equal(enc.SharedSecret, viaTyped);
    }

    [PqcFact]
    public void XWingHybridKem_WrongSizedInputs_ThrowClearArgumentException()
    {
        Assert.Throws<ArgumentException>(() => XWingHybridKem.Encapsulate(new byte[10]));
        Assert.Throws<ArgumentException>(() => XWingHybridKem.Decapsulate(new byte[10], new byte[XWingHybridKem.CiphertextSizeInBytes]));
        Assert.Throws<ArgumentException>(() => XWingHybridKem.Decapsulate(new byte[XWingHybridKem.DecapsulationKeySizeInBytes], new byte[10]));
    }

    // -- PqKeyPair -----------------------------------------------------------

    [PqcFact]
    public void PqKeyPair_BundlesAndDeconstructs()
    {
        using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
        using MLKemPublicKey pub = priv.GetPublicKey();
        var pair = new PqKeyPair<MLKemPublicKey, MLKemPrivateKey>(pub, priv);

        var (extractedPub, extractedPriv) = pair;
        Assert.Same(pub, extractedPub);
        Assert.Same(priv, extractedPriv);
    }
}
