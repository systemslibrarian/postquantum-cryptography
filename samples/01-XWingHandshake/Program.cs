// Sample 01 — X-Wing hybrid key exchange between two parties.
//
// Demonstrates: how to use X-Wing (ML-KEM-768 + X25519) to agree on a
// shared 32-byte secret that stays secure as long as either component
// remains unbroken — the cleanest answer to "how do I do PQ-secure key
// exchange today" while the world transitions to post-quantum crypto.
//
// Scenario: Bob publishes a long-lived encapsulation key; Alice
// encapsulates a fresh secret to it; both parties derive the same 32-byte
// key, which we then feed into AES-GCM to encrypt a payload end-to-end.

using System.Security.Cryptography;
using System.Text;
using PostQuantum.Cryptography;

if (!XWing.IsSupported)
{
    Console.Error.WriteLine("X-Wing is not supported on this runtime.");
    return 1;
}

Console.WriteLine("=== Sample 01: X-Wing hybrid handshake ===\n");

// ---------------------------------------------------------------------------
// 1. Bob generates a key pair once and publishes the public part.
// ---------------------------------------------------------------------------

using XWingPrivateKey bobPrivate = XWing.GenerateKeyPair();
byte[] bobPublicBytes = bobPrivate.ExportEncapsulationKey();
Console.WriteLine($"Bob   : published a {bobPublicBytes.Length}-byte encapsulation key.");

// ---------------------------------------------------------------------------
// 2. Alice imports Bob's public key and encapsulates a fresh shared secret.
// ---------------------------------------------------------------------------

using XWingPublicKey bobPublic = XWing.ImportEncapsulationKey(bobPublicBytes);
KemEncapsulation aliceResult = bobPublic.Encapsulate();
byte[] aliceSecret = aliceResult.SharedSecret;

Console.WriteLine($"Alice : encapsulated a fresh 32-byte shared secret + {aliceResult.Ciphertext.Length}-byte ciphertext.");

// ---------------------------------------------------------------------------
// 3. Bob decapsulates and recovers the same 32-byte secret.
// ---------------------------------------------------------------------------

byte[] bobSecret = bobPrivate.Decapsulate(aliceResult.Ciphertext);
Console.WriteLine($"Bob   : decapsulated. Secrets equal? {CryptographicOperations.FixedTimeEquals(aliceSecret, bobSecret)}");

// ---------------------------------------------------------------------------
// 4. Both parties derive a per-purpose AES key from the shared secret via
//    HKDF, then encrypt a real message with AES-GCM. Never key a cipher with
//    the raw KEM secret: HKDF binds the key to a purpose label, so the same
//    handshake can safely feed multiple keys (encryption, MAC, ...) without
//    them being interchangeable.
// ---------------------------------------------------------------------------

byte[] info = Encoding.UTF8.GetBytes("sample-01/aes-256-gcm/v1");
byte[] aliceAesKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, aliceSecret, outputLength: 32, salt: null, info: info);
byte[] bobAesKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, bobSecret, outputLength: 32, salt: null, info: info);

byte[] plaintext = Encoding.UTF8.GetBytes("This message was protected by a post-quantum handshake.");
byte[] nonce = RandomNumberGenerator.GetBytes(12);
byte[] ciphertext = new byte[plaintext.Length];
byte[] tag = new byte[16];

using (var aes = new AesGcm(aliceAesKey, tagSizeInBytes: 16))
{
    aes.Encrypt(nonce, plaintext, ciphertext, tag);
}

Console.WriteLine($"Alice → Bob ciphertext (base64): {Convert.ToBase64String(ciphertext)}");
Console.WriteLine($"             auth tag (hex)    : {Convert.ToHexString(tag)}");

byte[] decrypted = new byte[ciphertext.Length];
using (var aes = new AesGcm(bobAesKey, tagSizeInBytes: 16))
{
    aes.Decrypt(nonce, ciphertext, tag, decrypted);
}

Console.WriteLine($"Bob decrypted: {Encoding.UTF8.GetString(decrypted)}");

// ---------------------------------------------------------------------------
// 5. Hygiene: zero secrets we still hold. (The library zeros its own internal
//    intermediates and zeros the private key on Dispose. The shared secret
//    and the keys *we* derived are ours to clear.)
// ---------------------------------------------------------------------------

CryptographicOperations.ZeroMemory(aliceSecret);
CryptographicOperations.ZeroMemory(bobSecret);
CryptographicOperations.ZeroMemory(aliceAesKey);
CryptographicOperations.ZeroMemory(bobAesKey);

return 0;
