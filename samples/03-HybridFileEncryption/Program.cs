// Sample 03 — Hybrid file encryption: X-Wing KEM → HKDF → AES-GCM.
//
// Demonstrates the canonical "encrypt to a public key" pattern using only
// post-quantum-secure primitives:
//
//   1. Encapsulate a fresh shared secret to the recipient's X-Wing public key.
//   2. Expand the 32-byte KEM secret through HKDF-SHA-256 into a 32-byte
//      AES key + a 12-byte nonce, both bound to a per-file salt and to a
//      domain label so subkeys can't be cross-purposed.
//   3. Encrypt the file body with AES-GCM (authenticated encryption).
//   4. Wire format on disk: [magic(4) | salt(16) | ciphertext(1120) | nonce(12) | tag(16) | body...]
//
// To decrypt, the recipient performs the same HKDF expansion on the
// decapsulated secret and runs AES-GCM in decrypt mode.

using System.Security.Cryptography;
using System.Text;
using PostQuantum.Cryptography;

if (!XWing.IsSupported)
{
    Console.Error.WriteLine("X-Wing is not supported on this runtime.");
    return 1;
}

Console.WriteLine("=== Sample 03: Hybrid file encryption (X-Wing + HKDF + AES-GCM) ===\n");

// ---------------------------------------------------------------------------
// 0. Set up: recipient generates a long-lived key pair.
// ---------------------------------------------------------------------------

string workDir = Path.Combine(Path.GetTempPath(), "pqc-sample-03");
Directory.CreateDirectory(workDir);
string plaintextPath = Path.Combine(workDir, "secret.txt");
string envelopePath  = Path.Combine(workDir, "secret.txt.pqenv");

File.WriteAllText(plaintextPath,
    "Top-secret: the meeting moved to 3pm.\nThis file is end-to-end encrypted with PQ + classical hybrid crypto.\n");

using XWingPrivateKey recipientKey = XWing.GenerateKeyPair();
byte[] recipientPublicKey = recipientKey.ExportEncapsulationKey();

// ---------------------------------------------------------------------------
// 1. Encrypt.
// ---------------------------------------------------------------------------

EncryptToEnvelope(plaintextPath, envelopePath, recipientPublicKey);
Console.WriteLine($"Encrypted {plaintextPath}");
Console.WriteLine($"        → {envelopePath} ({new FileInfo(envelopePath).Length} bytes)");

// ---------------------------------------------------------------------------
// 2. Decrypt with the recipient's private key.
// ---------------------------------------------------------------------------

string decryptedPath = Path.Combine(workDir, "secret.decrypted.txt");
DecryptFromEnvelope(envelopePath, decryptedPath, recipientKey);
Console.WriteLine($"Decrypted to {decryptedPath}");
Console.WriteLine($"---\n{File.ReadAllText(decryptedPath)}---");

return 0;

// ============================ implementation ================================

static void EncryptToEnvelope(string inputPath, string envelopePath, byte[] recipientPublicKeyBytes)
{
    using XWingPublicKey pub = XWing.ImportEncapsulationKey(recipientPublicKeyBytes);
    KemEncapsulation kem = pub.Encapsulate();
    byte[] sharedSecret = kem.SharedSecret;
    byte[] ciphertext = kem.Ciphertext;

    // Per-message salt for the KDF so two envelopes to the same recipient
    // can't be correlated and don't reuse the AES-GCM nonce.
    byte[] salt = RandomNumberGenerator.GetBytes(16);
    (byte[] aesKey, byte[] nonce) = DeriveKeyAndNonce(sharedSecret, salt);

    byte[] body = File.ReadAllBytes(inputPath);
    byte[] encryptedBody = new byte[body.Length];
    byte[] tag = new byte[16];

    using (var aes = new AesGcm(aesKey, tagSizeInBytes: 16))
    {
        // Authenticate the salt + ciphertext so they can't be swapped post-hoc.
        byte[] associatedData = new byte[salt.Length + ciphertext.Length];
        salt.CopyTo(associatedData, 0);
        ciphertext.CopyTo(associatedData, salt.Length);
        aes.Encrypt(nonce, body, encryptedBody, tag, associatedData);
    }

    using var fs = new FileStream(envelopePath, FileMode.Create, FileAccess.Write);
    fs.Write(EnvelopeMagic());   // 4
    fs.Write(salt);            // 16
    fs.Write(ciphertext);      // XWing.CiphertextSizeInBytes (1120)
    fs.Write(nonce);           // 12
    fs.Write(tag);             // 16
    fs.Write(encryptedBody);   // body length

    CryptographicOperations.ZeroMemory(sharedSecret);
    CryptographicOperations.ZeroMemory(aesKey);
}

static void DecryptFromEnvelope(string envelopePath, string outPath, XWingPrivateKey recipientKey)
{
    byte[] envelope = File.ReadAllBytes(envelopePath);
    int offset = 0;

    // Validate the length up front so a truncated file fails with a clear
    // InvalidDataException instead of an ArgumentOutOfRangeException from a
    // slice below. (Header = magic 4 + salt 16 + KEM ciphertext + nonce 12
    // + tag 16; the body may be empty.)
    int headerLength = 4 + 16 + XWing.CiphertextSizeInBytes + 12 + 16;
    if (envelope.Length < headerLength)
    {
        throw new InvalidDataException(
            $"Envelope is truncated: {envelope.Length} bytes, but the header alone is {headerLength}.");
    }

    ReadOnlySpan<byte> magic = envelope.AsSpan(offset, 4); offset += 4;
    if (!magic.SequenceEqual(EnvelopeMagic()))
    {
        throw new InvalidDataException("Not a PostQuantum envelope (bad magic).");
    }

    byte[] salt = envelope.AsSpan(offset, 16).ToArray(); offset += 16;
    byte[] ciphertext = envelope.AsSpan(offset, XWing.CiphertextSizeInBytes).ToArray();
    offset += XWing.CiphertextSizeInBytes;
    byte[] nonce = envelope.AsSpan(offset, 12).ToArray(); offset += 12;
    byte[] tag = envelope.AsSpan(offset, 16).ToArray(); offset += 16;
    byte[] encryptedBody = envelope.AsSpan(offset).ToArray();

    byte[] sharedSecret = recipientKey.Decapsulate(ciphertext);
    (byte[] aesKey, byte[] recoveredNonce) = DeriveKeyAndNonce(sharedSecret, salt);

    // Sanity: the nonce we derived had better match the one on the wire.
    if (!CryptographicOperations.FixedTimeEquals(nonce, recoveredNonce))
    {
        throw new CryptographicException("Envelope nonce does not match the KDF-derived nonce.");
    }

    byte[] plaintext = new byte[encryptedBody.Length];
    using (var aes = new AesGcm(aesKey, tagSizeInBytes: 16))
    {
        byte[] associatedData = new byte[salt.Length + ciphertext.Length];
        salt.CopyTo(associatedData, 0);
        ciphertext.CopyTo(associatedData, salt.Length);
        aes.Decrypt(nonce, encryptedBody, tag, plaintext, associatedData);
    }

    File.WriteAllBytes(outPath, plaintext);

    CryptographicOperations.ZeroMemory(sharedSecret);
    CryptographicOperations.ZeroMemory(aesKey);
}

static (byte[] AesKey, byte[] Nonce) DeriveKeyAndNonce(byte[] ikm, byte[] salt)
{
    // HKDF-SHA-256 expansion: deterministically derive an AES-256 key + a
    // 12-byte AES-GCM nonce from the KEM shared secret. The "info" string
    // domain-separates this purpose from anything else that might one day
    // be derived from the same secret.
    byte[] info = Encoding.UTF8.GetBytes("pqc-sample-03/aes-gcm/v1");
    byte[] okm = HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, 32 + 12, salt, info);
    (byte[] AesKey, byte[] Nonce) result = (okm.AsSpan(0, 32).ToArray(), okm.AsSpan(32, 12).ToArray());
    // okm contains the AES key — clear it like every other secret we hold.
    CryptographicOperations.ZeroMemory(okm);
    return result;
}

static ReadOnlySpan<byte> EnvelopeMagic() => "PQ03"u8;
