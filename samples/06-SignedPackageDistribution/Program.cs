// Sample 06 — Signed package distribution.
//
// Real-world scenario: a software publisher releases a build artifact (a
// "package") and a small detached metadata file containing a signature.
// Consumers ship with the publisher's pinned ML-DSA-87 public key embedded
// in the application; they download the package + its metadata, verify
// against the pinned key, and refuse to install anything that doesn't
// verify.
//
// This is the same pattern container image signing (cosign), OS package
// signing (apt, rpm), OTA firmware updates, and software-update channels
// all use. The ML-DSA-87 substitution makes it post-quantum-secure.
//
// Layout we end up with:
//   /publisher/    pkg-v1.bin           — the artifact
//                  pkg-v1.bin.pqsig      — detached signature + manifest
//                  publisher.pub.pem     — the publisher's public key (only)
//   /consumer/     pinned-keys/publisher-2026.pub.pem  — pinned trust anchor
//                  downloaded/...        — what we pretend to fetch over HTTPS
//
// The interesting bits:
//   - The manifest is JSON, signed alongside the artifact bytes so we can
//     bind metadata (artifact SHA-256, version, publish time) to the
//     signature.
//   - We use a usage-domain context ("publisher.example/release-channel/v1")
//     so a signature minted for release artifacts can't be replayed as
//     anything else.
//   - The verifier refuses on: tampered artifact, tampered manifest,
//     wrong-publisher key, missing/empty signature.

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PostQuantum.Cryptography;

if (!MLDsa87.IsSupported)
{
    Console.Error.WriteLine("ML-DSA-87 is not supported on this runtime.");
    return 1;
}

Console.WriteLine("=== Sample 06: signed package distribution ===\n");

string root = Path.Combine(Path.GetTempPath(), "pqc-sample-06");
string publisherDir = Path.Combine(root, "publisher");
string consumerDir = Path.Combine(root, "consumer", "downloaded");
string pinnedDir = Path.Combine(root, "consumer", "pinned-keys");
Directory.CreateDirectory(publisherDir);
Directory.CreateDirectory(consumerDir);
Directory.CreateDirectory(pinnedDir);

byte[] domainContext = Encoding.UTF8.GetBytes("publisher.example/release-channel/v1");

// ---------------------------------------------------------------------------
// PUBLISHER side: generate keys once; publish the public key; sign a package.
// ---------------------------------------------------------------------------

string publisherPubPath = Path.Combine(publisherDir, "publisher.pub.pem");
string publisherPrivPath = Path.Combine(publisherDir, "publisher.key.pem"); // in reality: an HSM/KMS, or at minimum
                                                                            // ExportEncryptedPkcs8PrivateKeyPem (see samples 02/05)

using (MLDsaPrivateKey publisherKey = MLDsa87.GenerateKeyPair())
using (MLDsaPublicKey publisherPub = publisherKey.GetPublicKey())
{
    File.WriteAllText(publisherPrivPath, publisherKey.ExportPkcs8PrivateKeyPem());
    File.WriteAllText(publisherPubPath, publisherPub.ExportSubjectPublicKeyInfoPem());
}
Console.WriteLine($"PUBLISHER : generated key pair");

string artifactPath = Path.Combine(publisherDir, "pkg-v1.bin");
byte[] artifactBytes = Encoding.UTF8.GetBytes("(pretend this is a 50 MB installer)\n");
File.WriteAllBytes(artifactPath, artifactBytes);

string sigPath = SignArtifact(
    artifactPath: artifactPath,
    privatePemPath: publisherPrivPath,
    version: "1.0.0",
    publisher: "publisher.example",
    context: domainContext);
Console.WriteLine($"PUBLISHER : published artifact + signature manifest");
Console.WriteLine($"            {Path.GetFileName(artifactPath)} ({artifactBytes.Length} bytes)");
Console.WriteLine($"            {Path.GetFileName(sigPath)}");

// ---------------------------------------------------------------------------
// CONSUMER setup: pin the publisher's key once (this would be baked into the
// app at build time, not fetched dynamically — that's the whole point).
// ---------------------------------------------------------------------------

string pinnedKeyPath = Path.Combine(pinnedDir, "publisher-2026.pub.pem");
File.Copy(publisherPubPath, pinnedKeyPath, overwrite: true);
Console.WriteLine($"\nCONSUMER  : pinned publisher key to {pinnedKeyPath}");

// ---------------------------------------------------------------------------
// CONSUMER download + verify (happy path).
// ---------------------------------------------------------------------------

string downloadedArtifact = Path.Combine(consumerDir, "pkg-v1.bin");
string downloadedSig = Path.Combine(consumerDir, "pkg-v1.bin.pqsig");
File.Copy(artifactPath, downloadedArtifact, overwrite: true);
File.Copy(sigPath, downloadedSig, overwrite: true);

Console.WriteLine($"\nCONSUMER  : downloaded artifact + signature.");
VerifyAndReport(downloadedArtifact, downloadedSig, pinnedKeyPath, domainContext);

// ---------------------------------------------------------------------------
// Negative cases: tamper with the artifact / manifest / use wrong pinned key.
// ---------------------------------------------------------------------------

Console.WriteLine("\nCONSUMER  : negative tests.");

// 1. Flip a byte in the artifact.
byte[] tampered = (byte[])artifactBytes.Clone();
tampered[0] ^= 0xFF;
File.WriteAllBytes(downloadedArtifact, tampered);
VerifyAndReport(downloadedArtifact, downloadedSig, pinnedKeyPath, domainContext, expect: false, label: "tampered artifact");

// 2. Restore artifact; flip a byte in the signature.
File.WriteAllBytes(downloadedArtifact, artifactBytes);
SignatureBundle sigBundle = JsonSerializer.Deserialize(File.ReadAllText(downloadedSig), SignatureBundleJsonContext.Default.SignatureBundle)!;
byte[] tamperedSig = Convert.FromBase64String(sigBundle.SignatureBase64);
tamperedSig[0] ^= 0xFF;
SignatureBundle bad = sigBundle with { SignatureBase64 = Convert.ToBase64String(tamperedSig) };
File.WriteAllText(downloadedSig, JsonSerializer.Serialize(bad, SignatureBundleJsonContext.Default.SignatureBundle));
VerifyAndReport(downloadedArtifact, downloadedSig, pinnedKeyPath, domainContext, expect: false, label: "tampered signature");

// 3. Restore signature; verify against a key from a different publisher.
File.WriteAllText(downloadedSig, JsonSerializer.Serialize(sigBundle, SignatureBundleJsonContext.Default.SignatureBundle));
using (MLDsaPrivateKey rogueKey = MLDsa87.GenerateKeyPair())
using (MLDsaPublicKey roguePub = rogueKey.GetPublicKey())
{
    string roguePath = Path.Combine(pinnedDir, "rogue.pub.pem");
    File.WriteAllText(roguePath, roguePub.ExportSubjectPublicKeyInfoPem());
    VerifyAndReport(downloadedArtifact, downloadedSig, roguePath, domainContext, expect: false, label: "wrong publisher key");
}

// 4. Tamper with the manifest metadata (bump the version, keep everything
//    else). The signature covers the manifest bytes, so this must fail.
SignatureBundle versionBumped = sigBundle with { Manifest = sigBundle.Manifest with { Version = "9.9.9" } };
File.WriteAllText(downloadedSig, JsonSerializer.Serialize(versionBumped, SignatureBundleJsonContext.Default.SignatureBundle));
VerifyAndReport(downloadedArtifact, downloadedSig, pinnedKeyPath, domainContext, expect: false, label: "tampered manifest");

// 5. Empty signature.
SignatureBundle emptySig = sigBundle with { SignatureBase64 = string.Empty };
File.WriteAllText(downloadedSig, JsonSerializer.Serialize(emptySig, SignatureBundleJsonContext.Default.SignatureBundle));
VerifyAndReport(downloadedArtifact, downloadedSig, pinnedKeyPath, domainContext, expect: false, label: "empty signature");

return 0;

// ============================ implementation ================================

static string SignArtifact(string artifactPath, string privatePemPath, string version, string publisher, byte[] context)
{
    byte[] artifact = File.ReadAllBytes(artifactPath);
    byte[] artifactSha256 = SHA256.HashData(artifact);

    var manifest = new ReleaseManifest(
        Version: version,
        Publisher: publisher,
        ArtifactSha256Hex: Convert.ToHexString(artifactSha256).ToLowerInvariant(),
        ArtifactSizeBytes: artifact.LongLength,
        PublishedAtUtc: DateTime.UtcNow);

    // The bytes we sign cover both the artifact (by hash) and the manifest's
    // canonical JSON. Tampering with EITHER invalidates the signature.
    byte[] manifestJson = JsonSerializer.SerializeToUtf8Bytes(manifest, ReleaseManifestJsonContext.Default.ReleaseManifest);
    byte[] payload = Concat(artifactSha256, manifestJson);

    using MLDsaPrivateKey signer = MLDsaKey.ImportPrivateKeyFromPem(File.ReadAllText(privatePemPath));
    byte[] signature = signer.SignData(payload, context);

    var bundle = new SignatureBundle(
        Manifest: manifest,
        SignatureBase64: Convert.ToBase64String(signature),
        ContextUtf8: Encoding.UTF8.GetString(context));

    string sigPath = artifactPath + ".pqsig";
    File.WriteAllText(sigPath, JsonSerializer.Serialize(bundle, SignatureBundleJsonContext.Default.SignatureBundle));
    return sigPath;
}

static bool VerifyArtifact(string artifactPath, string sigPath, string pinnedPubKeyPath, byte[] expectedContext)
{
    byte[] artifact = File.ReadAllBytes(artifactPath);
    byte[] artifactSha256 = SHA256.HashData(artifact);

    SignatureBundle bundle = JsonSerializer.Deserialize(File.ReadAllText(sigPath), SignatureBundleJsonContext.Default.SignatureBundle)!;

    // Sanity: the manifest says SHA-256(artifact) = X. Verify that ourselves
    // before bothering with the post-quantum check.
    string ourHashHex = Convert.ToHexString(artifactSha256).ToLowerInvariant();
    if (!CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(bundle.Manifest.ArtifactSha256Hex),
            Encoding.ASCII.GetBytes(ourHashHex)))
    {
        return false;
    }

    // Context must match exactly — refuses a signature minted for another purpose.
    if (!CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(bundle.ContextUtf8),
            expectedContext))
    {
        return false;
    }

    // CAVEAT for production copies: this re-serializes the deserialized
    // manifest and assumes the result is byte-identical to what was signed.
    // That holds here (same System.Text.Json version, source-generated
    // contract, no re-encoding hop), but it is brittle across serializer
    // versions or intermediaries. A hardened format stores the signed
    // manifest as opaque bytes (e.g. base64 of the exact JSON) and verifies
    // those received bytes directly.
    byte[] manifestJson = JsonSerializer.SerializeToUtf8Bytes(bundle.Manifest, ReleaseManifestJsonContext.Default.ReleaseManifest);
    byte[] payload = Concat(artifactSha256, manifestJson);
    byte[] signature = Convert.FromBase64String(bundle.SignatureBase64);

    using MLDsaPublicKey publisher = MLDsaKey.ImportPublicKeyFromPem(File.ReadAllText(pinnedPubKeyPath));
    return publisher.Verify(payload, signature, expectedContext);
}

static void VerifyAndReport(string artifactPath, string sigPath, string pinnedPubKeyPath, byte[] context, bool expect = true, string label = "valid")
{
    bool ok = VerifyArtifact(artifactPath, sigPath, pinnedPubKeyPath, context);
    string status = ok ? "VALID  " : "INVALID";
    string outcome = ok == expect ? "ok  " : "FAIL";
    Console.WriteLine($"  {outcome} {status} ({label})");
    if (ok != expect)
    {
        throw new InvalidOperationException($"verification result {ok} did not match expected {expect} for {label}");
    }
}

static byte[] Concat(byte[] a, byte[] b)
{
    byte[] result = new byte[a.Length + b.Length];
    a.CopyTo(result, 0);
    b.CopyTo(result, a.Length);
    return result;
}

// ---- Wire types ----
//
// Source-generated System.Text.Json contexts are used so the sample stays
// AOT-friendly and shows the pattern that production code should use rather
// than reflection-based serialization.

internal sealed record ReleaseManifest(
    string Version,
    string Publisher,
    string ArtifactSha256Hex,
    long ArtifactSizeBytes,
    DateTime PublishedAtUtc);

internal sealed record SignatureBundle(
    ReleaseManifest Manifest,
    string SignatureBase64,
    string ContextUtf8);

[System.Text.Json.Serialization.JsonSerializable(typeof(ReleaseManifest))]
internal partial class ReleaseManifestJsonContext : System.Text.Json.Serialization.JsonSerializerContext;

[System.Text.Json.Serialization.JsonSerializable(typeof(SignatureBundle))]
internal partial class SignatureBundleJsonContext : System.Text.Json.Serialization.JsonSerializerContext;
