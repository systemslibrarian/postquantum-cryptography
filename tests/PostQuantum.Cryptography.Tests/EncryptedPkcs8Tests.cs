using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Tests for the encrypted PKCS#8 (EncryptedPrivateKeyInfo) surface on
/// ML-KEM and ML-DSA private keys: round-trips (DER + PEM), wrong-password
/// rejection, the empty-password export refusal, and up-front PEM label
/// disambiguation between encrypted and unencrypted private keys.
/// </summary>
public class EncryptedPkcs8Tests
{
    private const string Password = "correct horse battery staple";

    [PqcFact]
    public void MLKem_EncryptedDer_RoundTrips()
    {
        using MLKemPrivateKey original = MLKem768.GenerateKeyPair();
        byte[] encrypted = original.ExportEncryptedPkcs8PrivateKey(Password);

        using MLKemPrivateKey restored = MLKemKey.ImportEncryptedPkcs8PrivateKey(Password, encrypted);

        Assert.Equal(original.ExportDecapsulationKey(), restored.ExportDecapsulationKey());
    }

    [PqcFact]
    public void MLKem_EncryptedPem_RoundTrips()
    {
        using MLKemPrivateKey original = MLKem768.GenerateKeyPair();
        string pem = original.ExportEncryptedPkcs8PrivateKeyPem(Password);

        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", pem, StringComparison.Ordinal);

        using MLKemPrivateKey restored = MLKemKey.ImportEncryptedPrivateKeyFromPem(Password, pem);

        Assert.Equal(original.ExportDecapsulationKey(), restored.ExportDecapsulationKey());
    }

    [PqcFact]
    public void MLDsa_EncryptedDer_RoundTrips()
    {
        using MLDsaPrivateKey original = MLDsa87.GenerateKeyPair();
        byte[] encrypted = original.ExportEncryptedPkcs8PrivateKey(Password);

        using MLDsaPrivateKey restored = MLDsaKey.ImportEncryptedPkcs8PrivateKey(Password, encrypted);

        Assert.Equal(original.ExportSecretKey(), restored.ExportSecretKey());
    }

    [PqcFact]
    public void MLDsa_EncryptedPem_RoundTrips_AndRestoredKeySigns()
    {
        using MLDsaPrivateKey original = MLDsa87.GenerateKeyPair();
        string pem = original.ExportEncryptedPkcs8PrivateKeyPem(Password);

        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", pem, StringComparison.Ordinal);

        using MLDsaPrivateKey restored = MLDsaKey.ImportEncryptedPrivateKeyFromPem(Password, pem);
        using MLDsaPublicKey verifier = original.GetPublicKey();

        byte[] message = "encrypted pkcs8 round-trip"u8.ToArray();
        byte[] signature = restored.SignData(message);
        Assert.True(verifier.Verify(message, signature));
    }

    [PqcFact]
    public void WrongPassword_ThrowsCryptographicException()
    {
        using MLKemPrivateKey kem = MLKem768.GenerateKeyPair();
        byte[] encryptedKem = kem.ExportEncryptedPkcs8PrivateKey(Password);
        Assert.Throws<CryptographicException>(
            () => MLKemKey.ImportEncryptedPkcs8PrivateKey("wrong password", encryptedKem).Dispose());

        using MLDsaPrivateKey dsa = MLDsa87.GenerateKeyPair();
        string encryptedDsaPem = dsa.ExportEncryptedPkcs8PrivateKeyPem(Password);
        Assert.Throws<CryptographicException>(
            () => MLDsaKey.ImportEncryptedPrivateKeyFromPem("wrong password", encryptedDsaPem).Dispose());
    }

    [PqcFact]
    public void EmptyPassword_ExportRefused()
    {
        using MLKemPrivateKey kem = MLKem768.GenerateKeyPair();
        Assert.Throws<ArgumentException>(() => kem.ExportEncryptedPkcs8PrivateKey(string.Empty));
        Assert.Throws<ArgumentException>(() => kem.ExportEncryptedPkcs8PrivateKeyPem(string.Empty));

        using MLDsaPrivateKey dsa = MLDsa87.GenerateKeyPair();
        Assert.Throws<ArgumentException>(() => dsa.ExportEncryptedPkcs8PrivateKey(string.Empty));
        Assert.Throws<ArgumentException>(() => dsa.ExportEncryptedPkcs8PrivateKeyPem(string.Empty));
    }

    [PqcFact]
    public void PemLabelMismatch_FailsFastBothDirections()
    {
        using MLKemPrivateKey key = MLKem768.GenerateKeyPair();

        // Unencrypted PEM into the encrypted importer: clear ArgumentException.
        string plainPem = key.ExportPkcs8PrivateKeyPem();
        ArgumentException ex1 = Assert.Throws<ArgumentException>(
            () => MLKemKey.ImportEncryptedPrivateKeyFromPem(Password, plainPem).Dispose());
        Assert.Contains("unencrypted", ex1.Message, StringComparison.OrdinalIgnoreCase);

        // Encrypted PEM into the plain importer: clear ArgumentException.
        string encryptedPem = key.ExportEncryptedPkcs8PrivateKeyPem(Password);
        ArgumentException ex2 = Assert.Throws<ArgumentException>(
            () => MLKemKey.ImportPrivateKeyFromPem(encryptedPem).Dispose());
        Assert.Contains("encrypted", ex2.Message, StringComparison.OrdinalIgnoreCase);

        // Public-key PEM into the encrypted importer: clear ArgumentException.
        string publicPem = key.ExportSubjectPublicKeyInfoPem();
        Assert.Throws<ArgumentException>(
            () => MLKemKey.ImportEncryptedPrivateKeyFromPem(Password, publicPem).Dispose());
    }

    [PqcFact]
    public void EncryptedExport_UsesPbkdf2Sha256Aes256()
    {
        // Lock in the advertised PBE policy: the EncryptedPrivateKeyInfo must
        // reference PBES2 (1.2.840.113549.1.5.13), PBKDF2, HMAC-SHA256
        // (1.2.840.113549.2.9) and AES-256-CBC (2.16.840.1.101.3.4.1.42).
        using MLKemPrivateKey key = MLKem768.GenerateKeyPair();
        byte[] encrypted = key.ExportEncryptedPkcs8PrivateKey(Password);
        string der = Convert.ToHexString(encrypted);

        Assert.Contains(OidToHex("1.2.840.113549.1.5.13"), der, StringComparison.Ordinal); // PBES2
        Assert.Contains(OidToHex("1.2.840.113549.1.5.12"), der, StringComparison.Ordinal); // PBKDF2
        Assert.Contains(OidToHex("1.2.840.113549.2.9"), der, StringComparison.Ordinal);    // hmacWithSHA256
        Assert.Contains(OidToHex("2.16.840.1.101.3.4.1.42"), der, StringComparison.Ordinal); // aes256-CBC
    }

    private static string OidToHex(string oid)
    {
        // DER content octets of an OBJECT IDENTIFIER (without tag/length).
        int[] parts = [.. oid.Split('.').Select(int.Parse)];
        var bytes = new List<byte> { (byte)(parts[0] * 40 + parts[1]) };
        byte[] tmp = new byte[5];
        foreach (int part in parts.Skip(2))
        {
            int value = part;
            int i = tmp.Length;
            tmp[--i] = (byte)(value & 0x7f);
            value >>= 7;
            while (value > 0)
            {
                tmp[--i] = (byte)((value & 0x7f) | 0x80);
                value >>= 7;
            }

            bytes.AddRange(tmp[i..]);
        }

        return Convert.ToHexString(bytes.ToArray());
    }
}
