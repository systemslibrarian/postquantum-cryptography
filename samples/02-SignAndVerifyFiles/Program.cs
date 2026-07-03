// Sample 02 — Sign and verify files with persistent PEM keys.
//
// Demonstrates: how to (1) generate an ML-DSA-87 key pair, (2) save the
// private key as PKCS#8 PEM and the public key as SubjectPublicKeyInfo PEM,
// (3) reload them later, (4) sign a file's bytes with a domain-binding
// context, and (5) verify the detached signature.
//
// PEM exchange is the right interop format for keys you'll persist or share
// out of band; raw byte strings are smaller but lose the algorithm identifier
// that lets the importer recover the parameter set.

using System.Security.Cryptography;
using System.Text;
using PostQuantum.Cryptography;

if (!MLDsa87.IsSupported)
{
    Console.Error.WriteLine("ML-DSA-87 is not supported on this runtime.");
    return 1;
}

Console.WriteLine("=== Sample 02: ML-DSA-87 file signing with persistent keys ===\n");

string workDir = Path.Combine(Path.GetTempPath(), "pqc-sample-02");
Directory.CreateDirectory(workDir);
string privatePemPath = Path.Combine(workDir, "signer.key.pem");
string publicPemPath = Path.Combine(workDir, "signer.pub.pem");
string documentPath = Path.Combine(workDir, "document.txt");
string signaturePath = Path.Combine(workDir, "document.sig");

// Bind every signature this app produces to a usage domain so a signature
// minted for one purpose cannot be replayed for another (FIPS 204 §5.2).
byte[] context = Encoding.UTF8.GetBytes("postquantum-sample-02/v1");

// ---------------------------------------------------------------------------
// 1. Generate keys and persist them as PEM. The private key goes to disk
//    password-protected (encrypted PKCS#8 — PBKDF2-HMAC-SHA256 at 600k
//    iterations + AES-256-CBC, the library's single fixed policy). In a real
//    app the password comes from a secret manager or operator prompt, never
//    from source code.
// ---------------------------------------------------------------------------

const string keyPassword = "sample-02-demo-password (use a secret manager in production)";

using (MLDsaPrivateKey signer = MLDsa87.GenerateKeyPair())
using (MLDsaPublicKey verifier = signer.GetPublicKey())
{
    File.WriteAllText(privatePemPath, signer.ExportEncryptedPkcs8PrivateKeyPem(keyPassword));
    File.WriteAllText(publicPemPath, verifier.ExportSubjectPublicKeyInfoPem());
}

Console.WriteLine($"Persisted PEM keys to {workDir} (private key encrypted)");

// ---------------------------------------------------------------------------
// 2. Author the document and sign it with the reloaded key.
// ---------------------------------------------------------------------------

File.WriteAllText(documentPath, "Sworn statement: 2 + 2 = 4.\n");

using (MLDsaPrivateKey signer = MLDsaKey.ImportEncryptedPrivateKeyFromPem(keyPassword, File.ReadAllText(privatePemPath)))
{
    byte[] document = File.ReadAllBytes(documentPath);
    byte[] signature = signer.SignData(document, context);
    File.WriteAllBytes(signaturePath, signature);
    Console.WriteLine($"Signed document ({document.Length} bytes) → signature ({signature.Length} bytes)");
}

// ---------------------------------------------------------------------------
// 3. Verify the signature using only the public PEM.
// ---------------------------------------------------------------------------

using (MLDsaPublicKey verifier = MLDsaKey.ImportPublicKeyFromPem(File.ReadAllText(publicPemPath)))
{
    byte[] document = File.ReadAllBytes(documentPath);
    byte[] signature = File.ReadAllBytes(signaturePath);

    bool ok = verifier.Verify(document, signature, context);
    Console.WriteLine($"Verify (correct context)   : {ok}");

    // Verifying with the wrong context (or no context) must fail.
    bool wrongCtx = verifier.Verify(document, signature, "wrong-domain"u8);
    bool noCtx = verifier.Verify(document, signature);
    Console.WriteLine($"Verify (wrong context)     : {wrongCtx}");
    Console.WriteLine($"Verify (no context)        : {noCtx}");

    // Tampering with even one byte of the document breaks the signature.
    byte[] tampered = (byte[])document.Clone();
    tampered[0] ^= 0xFF;
    Console.WriteLine($"Verify (tampered document) : {verifier.Verify(tampered, signature, context)}");
}

// ---------------------------------------------------------------------------
// 4. Footgun rejection: load a *public* PEM through the *private* importer.
//    The library validates the PEM label up-front and throws immediately.
// ---------------------------------------------------------------------------

try
{
    using MLDsaPrivateKey _ = MLDsaKey.ImportPrivateKeyFromPem(File.ReadAllText(publicPemPath));
    Console.Error.WriteLine("ERROR: a mismatched PEM should have been rejected.");
    return 1;
}
catch (ArgumentException ex)
{
    Console.WriteLine($"\nFootgun caught early: {ex.Message}");
}

return 0;
