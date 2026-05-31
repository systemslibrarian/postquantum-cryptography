using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Verifies that the typed PEM importers reject mismatched payloads up front
/// (e.g., feeding a SubjectPublicKeyInfo PEM to a private-key importer) instead
/// of failing later with a confusing <see cref="System.Security.Cryptography.CryptographicException"/>.
/// </summary>
public class PemDisambiguationTests
{
    [PqcFact]
    public void MLKem_ImportPrivateKeyFromPem_RejectsPublicKeyPem()
    {
        using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
        string publicPem = priv.GetPublicKey().ExportSubjectPublicKeyInfoPem();

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => MLKemKey.ImportPrivateKeyFromPem(publicPem));

        Assert.Contains("PRIVATE KEY", ex.Message, System.StringComparison.Ordinal);
        Assert.Contains("PUBLIC KEY", ex.Message, System.StringComparison.Ordinal);
    }

    [PqcFact]
    public void MLKem_ImportPublicKeyFromPem_RejectsPrivateKeyPem()
    {
        using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
        string privatePem = priv.ExportPkcs8PrivateKeyPem();

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => MLKemKey.ImportPublicKeyFromPem(privatePem));

        Assert.Contains("PUBLIC KEY", ex.Message, System.StringComparison.Ordinal);
        Assert.Contains("PRIVATE KEY", ex.Message, System.StringComparison.Ordinal);
    }

    [PqcFact]
    public void MLDsa_ImportPrivateKeyFromPem_RejectsPublicKeyPem()
    {
        using MLDsaPrivateKey priv = MLDsa87.GenerateKeyPair();
        string publicPem = priv.GetPublicKey().ExportSubjectPublicKeyInfoPem();

        Assert.Throws<ArgumentException>(() => MLDsaKey.ImportPrivateKeyFromPem(publicPem));
    }

    [PqcFact]
    public void MLDsa_ImportPublicKeyFromPem_RejectsPrivateKeyPem()
    {
        using MLDsaPrivateKey priv = MLDsa87.GenerateKeyPair();
        string privatePem = priv.ExportPkcs8PrivateKeyPem();

        Assert.Throws<ArgumentException>(() => MLDsaKey.ImportPublicKeyFromPem(privatePem));
    }

    [Fact]
    public void ImportPrivateKeyFromPem_GarbageInput_Throws()
    {
        Assert.Throws<ArgumentException>(() => MLKemKey.ImportPrivateKeyFromPem("this is not a PEM"));
        Assert.Throws<ArgumentException>(() => MLDsaKey.ImportPrivateKeyFromPem("this is not a PEM"));
    }
}
