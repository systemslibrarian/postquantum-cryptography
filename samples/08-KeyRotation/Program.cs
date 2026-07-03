// Sample 08 — Rotating a long-lived ML-DSA-87 signing key without breaking verifiers.
//
// Real-world scenario: a publisher signs artifacts with a long-lived key, and
// one day that key must be replaced — routinely (annual rotation) or urgently
// (compromise). The trick that makes this survivable is from RECIPES.md
// Recipe 15: give every key an identifier, embed that id in everything you
// publish, and let verifiers hold a *keyring* (a set of currently-trusted
// keys) instead of a single key. Rotation then becomes keyring surgery, not a
// flag day.
//
// Layout we end up with:
//   /publisher/    signer-2026.key.pem   — encrypted PKCS#8 private key
//                  signer-2027.key.pem   — its successor
//   /consumer/     pinned-keys/signer-2026.pub.pem   — trust anchors; the
//                  pinned-keys/signer-2027.pub.pem     file name IS the key id
//
// The interesting bits:
//   - Private keys are persisted as *encrypted* PKCS#8 PEM
//     (ExportEncryptedPkcs8PrivateKeyPem — PBKDF2-HMAC-SHA256 at 600k
//     iterations + AES-256-CBC, the library's single fixed policy).
//   - Every signed bundle carries the key id of the key that signed it. The
//     key id is untrusted routing data: it only selects which pinned key to
//     try. The signature check is what actually decides — a bundle that
//     *claims* the new key id but was signed by the old key fails.
//   - Retirement has an honest consequence, demonstrated below: once a key
//     leaves the keyring, everything it signed stops verifying. Old artifacts
//     must be re-signed (or re-fetched, re-signed by the publisher) *before*
//     retirement completes.
//   - Compromise is rotation with the steps reordered: removal is step 1,
//     not step 3, and everything the key ever signed must be re-signed.

using System.Text.Json;
using PostQuantum.Cryptography;

if (!MLDsa87.IsSupported)
{
    Console.Error.WriteLine("ML-DSA-87 is not supported on this runtime.");
    return 1;
}

Console.WriteLine("=== Sample 08: signing-key rotation with versioned trust anchors ===\n");

string root = Path.Combine(Path.GetTempPath(), "pqc-sample-08");
string publisherDir = Path.Combine(root, "publisher");
string pinnedDir = Path.Combine(root, "consumer", "pinned-keys");
Directory.CreateDirectory(publisherDir);
Directory.CreateDirectory(pinnedDir);
foreach (string stale in Directory.EnumerateFiles(pinnedDir))
{
    File.Delete(stale); // fresh keyring on every run
}

// In a real deployment the password comes from a secret manager, KMS, or an
// operator prompt — never from source code.
const string KeyPassword = "sample-08-demo-password (use a secret manager in production)";

// FIPS 204 §5.2 domain-binding context: a signature minted for this rotation
// scheme cannot be replayed as anything else.
byte[] context = "rotation-sample/v1"u8.ToArray();

// ---------------------------------------------------------------------------
// 1. PUBLISHER: mint "signer-2026". The private key goes to disk as encrypted
//    PKCS#8 PEM; the public key is published as SPKI PEM into the consumer's
//    pinned-keys directory, where the FILE NAME is the key id. Sign artifact A.
// ---------------------------------------------------------------------------

const string KeyId2026 = "signer-2026";
GenerateAndPersistKeyPair(KeyId2026, publisherDir, pinnedDir, KeyPassword);
Console.WriteLine($"PUBLISHER : minted {KeyId2026} (private key encrypted PKCS#8, public key pinned)");

byte[] artifactABytes = "artifact A: release 1.0 of the flux capacitor firmware\n"u8.ToArray();
string bundleAPath = SignToBundle(KeyId2026, artifactABytes, "artifact-a", publisherDir, KeyPassword, context);
Console.WriteLine($"PUBLISHER : signed artifact A with {KeyId2026} → {Path.GetFileName(bundleAPath)}");

// ---------------------------------------------------------------------------
// 2. CONSUMER: load the keyring from the pinned-keys directory. Verification
//    of a bundle = look up its key id in the keyring; unknown id → reject;
//    known id → verify the signature under that key with our context.
// ---------------------------------------------------------------------------

Dictionary<string, MLDsaPublicKey> keyring = LoadKeyring(pinnedDir);
Console.WriteLine($"\nCONSUMER  : keyring loaded — trusted key ids: [{string.Join(", ", keyring.Keys)}]");

Check(VerifyBundle(ReadBundle(bundleAPath), keyring, context), expected: true,
    label: $"artifact A (signed by {KeyId2026})");

// ---------------------------------------------------------------------------
// 3. ROTATION: mint "signer-2027" and ADD it to the keyring — this is the
//    overlap window in which BOTH keys are trusted. New artifacts are signed
//    with 2027; everything signed by 2026 keeps verifying. Deploy this state
//    to every verifier BEFORE the signer switches over.
// ---------------------------------------------------------------------------

Console.WriteLine("\n--- ROTATION: overlap window (both keys trusted) ---");

const string KeyId2027 = "signer-2027";
GenerateAndPersistKeyPair(KeyId2027, publisherDir, pinnedDir, KeyPassword);
keyring[KeyId2027] = LoadPinnedKey(pinnedDir, KeyId2027);
Console.WriteLine($"PUBLISHER : minted {KeyId2027}; CONSUMER added it to the keyring");
Console.WriteLine($"CONSUMER  : trusted key ids: [{string.Join(", ", keyring.Keys)}]");

byte[] artifactBBytes = "artifact B: release 2.0 of the flux capacitor firmware\n"u8.ToArray();
string bundleBPath = SignToBundle(KeyId2027, artifactBBytes, "artifact-b", publisherDir, KeyPassword, context);
Console.WriteLine($"PUBLISHER : signed artifact B with {KeyId2027}");

Check(VerifyBundle(ReadBundle(bundleAPath), keyring, context), expected: true,
    label: $"artifact A (old key, overlap window)");
Check(VerifyBundle(ReadBundle(bundleBPath), keyring, context), expected: true,
    label: $"artifact B (new key, overlap window)");

// ---------------------------------------------------------------------------
// 4. RETIREMENT: remove signer-2026 from the keyring (and its pinned file).
//    Artifact B still verifies. Artifact A now REJECTS — its key id is no
//    longer in the keyring. That is the honest consequence of retirement:
//    anything still signed by the retired key must be re-signed or re-fetched
//    BEFORE retirement completes, or it becomes unverifiable. Never reuse a
//    retired key id.
// ---------------------------------------------------------------------------

Console.WriteLine("\n--- RETIREMENT: signer-2026 leaves the keyring ---");

File.Delete(Path.Combine(pinnedDir, KeyId2026 + ".pub.pem"));
keyring.Remove(KeyId2026, out MLDsaPublicKey? retired);
retired?.Dispose();
Console.WriteLine($"CONSUMER  : trusted key ids: [{string.Join(", ", keyring.Keys)}]");

Check(VerifyBundle(ReadBundle(bundleBPath), keyring, context), expected: true,
    label: "artifact B after retirement");
Check(VerifyBundle(ReadBundle(bundleAPath), keyring, context), expected: false,
    label: "artifact A after retirement (unknown key id → reject)");
Console.WriteLine("            ^ honest consequence: artifacts signed by a retired key must be");
Console.WriteLine("              re-signed or re-fetched before retirement completes.");

// ---------------------------------------------------------------------------
// 5. COMPROMISE drill. If a key is COMPROMISED rather than routinely rotated,
//    the order changes: removal from every keyring is step 1, not step 3 —
//    there is no overlap window, because the attacker holds the key *now*.
//    Then everything the key ever signed must be re-signed by a healthy key.
//    We already removed signer-2026 above; here is the recovery: re-sign
//    artifact A with signer-2027 and it verifies again.
// ---------------------------------------------------------------------------

Console.WriteLine("\n--- COMPROMISE drill: recover artifact A by re-signing ---");

string bundleAResignedPath = SignToBundle(KeyId2027, artifactABytes, "artifact-a-resigned", publisherDir, KeyPassword, context);
Console.WriteLine($"PUBLISHER : re-signed artifact A with {KeyId2027}");
Check(VerifyBundle(ReadBundle(bundleAResignedPath), keyring, context), expected: true,
    label: $"artifact A re-signed by {KeyId2027}");

// ---------------------------------------------------------------------------
// 6. Negative: key substitution. A bundle whose key id CLAIMS signer-2027 but
//    whose signature was actually made by signer-2026 must fail — the key id
//    only routes the lookup; ML-DSA-87 verification under the looked-up key
//    is what decides.
// ---------------------------------------------------------------------------

Console.WriteLine("\n--- Negative: key-substitution attempt ---");

SignedBundle honest2026 = ReadBundle(bundleAPath);                 // genuinely signed by signer-2026
SignedBundle forged = honest2026 with { KeyId = KeyId2027 };       // ...but claims signer-2027
Check(VerifyBundle(forged, keyring, context), expected: false,
    label: "bundle claiming signer-2027 with a signer-2026 signature");

foreach (MLDsaPublicKey key in keyring.Values)
{
    key.Dispose();
}

Console.WriteLine("\nAll rotation-lifecycle expectations held.");
return 0;

// ============================ implementation ================================

static void GenerateAndPersistKeyPair(string keyId, string publisherDir, string pinnedDir, string password)
{
    using MLDsaPrivateKey key = MLDsa87.GenerateKeyPair();
    using MLDsaPublicKey pub = key.GetPublicKey();
    File.WriteAllText(Path.Combine(publisherDir, keyId + ".key.pem"), key.ExportEncryptedPkcs8PrivateKeyPem(password));
    File.WriteAllText(Path.Combine(pinnedDir, keyId + ".pub.pem"), pub.ExportSubjectPublicKeyInfoPem());
}

static string SignToBundle(string keyId, byte[] payload, string bundleName, string publisherDir, string password, byte[] context)
{
    string privatePem = File.ReadAllText(Path.Combine(publisherDir, keyId + ".key.pem"));
    using MLDsaPrivateKey signer = MLDsaKey.ImportEncryptedPrivateKeyFromPem(password, privatePem);
    byte[] signature = signer.SignData(payload, context);

    var bundle = new SignedBundle(
        KeyId: keyId,
        PayloadBase64: Convert.ToBase64String(payload),
        SignatureBase64: Convert.ToBase64String(signature));

    string bundlePath = Path.Combine(publisherDir, bundleName + ".pqbundle");
    File.WriteAllText(bundlePath, JsonSerializer.Serialize(bundle, SignedBundleJsonContext.Default.SignedBundle));
    return bundlePath;
}

static SignedBundle ReadBundle(string bundlePath) =>
    JsonSerializer.Deserialize(File.ReadAllText(bundlePath), SignedBundleJsonContext.Default.SignedBundle)!;

// The keyring is loaded from the pinned-keys directory: file name = key id.
// In a real app this directory ships with the application (or lives in
// configuration management) — it is the consumer's root of trust.
static Dictionary<string, MLDsaPublicKey> LoadKeyring(string pinnedDir)
{
    var keyring = new Dictionary<string, MLDsaPublicKey>(StringComparer.Ordinal);
    foreach (string path in Directory.EnumerateFiles(pinnedDir, "*.pub.pem"))
    {
        string keyId = Path.GetFileName(path)[..^".pub.pem".Length];
        keyring[keyId] = MLDsaKey.ImportPublicKeyFromPem(File.ReadAllText(path));
    }
    return keyring;
}

static MLDsaPublicKey LoadPinnedKey(string pinnedDir, string keyId) =>
    MLDsaKey.ImportPublicKeyFromPem(File.ReadAllText(Path.Combine(pinnedDir, keyId + ".pub.pem")));

// Verify(bundle) per Recipe 15: look the key id up in the keyring; an unknown
// key id is a hard reject (no fallback, no "try every key"); a known id must
// then survive ML-DSA-87 verification under our usage-domain context.
static bool VerifyBundle(SignedBundle bundle, Dictionary<string, MLDsaPublicKey> keyring, byte[] context)
{
    if (!keyring.TryGetValue(bundle.KeyId, out MLDsaPublicKey? key))
    {
        return false; // unknown key id → reject
    }

    byte[] payload = Convert.FromBase64String(bundle.PayloadBase64);
    byte[] signature = Convert.FromBase64String(bundle.SignatureBase64);
    return key.Verify(payload, signature, context);
}

static void Check(bool actual, bool expected, string label)
{
    string status = actual ? "VALID  " : "INVALID";
    string outcome = actual == expected ? "ok  " : "FAIL";
    Console.WriteLine($"  {outcome} {status} ({label})");
    if (actual != expected)
    {
        throw new InvalidOperationException($"verification result {actual} did not match expected {expected} for {label}");
    }
}

// ---- Wire types ----
//
// Source-generated System.Text.Json context so the sample stays AOT-friendly,
// matching the pattern production code should use (see sample 06).

internal sealed record SignedBundle(
    string KeyId,
    string PayloadBase64,
    string SignatureBase64);

[System.Text.Json.Serialization.JsonSerializable(typeof(SignedBundle))]
internal sealed partial class SignedBundleJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
