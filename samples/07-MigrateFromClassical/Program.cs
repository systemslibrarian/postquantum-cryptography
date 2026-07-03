// Sample 07 — Migrate from ECDSA to ML-DSA without a flag day (dual-signing).
//
// Real-world scenario (docs/RECIPES.md, Recipe 12): you have ECDSA P-256
// signatures in production today and cannot flip every verifier at once.
// The standard transition pattern is **hybrid (dual) signing**: the publisher
// emits BOTH a classical and a post-quantum signature for every payload, and
// the verifier fleet is rolled forward through three phases:
//
//   Phase 1 (deploy and observe) : ECDSA must verify. The ML-DSA signature is
//                                  verified too, but failures are only LOGGED
//                                  — you gather telemetry, you don't reject.
//   Phase 2 (both fleets ready)  : BOTH signatures must verify.
//   Phase 3 (classical sunset)   : only ML-DSA must verify; ECDSA is retired.
//
// At no point does any consumer break: old verifiers keep checking the ECDSA
// field they already understand while new ones phase the ML-DSA check in.
//
// TWO NON-NEGOTIABLES when you copy this pattern:
//
//   1. TWO INDEPENDENT KEYS. The ECDSA key and the ML-DSA key are generated
//      separately and share nothing. NEVER derive one from the other (e.g. by
//      seeding ML-DSA key generation from ECDSA key material) — that would
//      let a quantum-capable attacker who breaks the ECDSA key recover the
//      "post-quantum" key too, defeating the entire migration.
//
//   2. PLAN FOR THE SIZE DELTA. An ECDSA-P256 signature is ~64 bytes; an
//      ML-DSA-87 signature is 4,627 bytes — roughly 72x larger. Database
//      columns, protocol frames, HTTP headers, and cache entries sized for
//      classical signatures WILL truncate or reject the PQ one. Fix the
//      schema before Phase 1, not during the incident.
//
// The wire format is a small JSON "dual-signature envelope" (source-generated
// System.Text.Json contract, AOT-friendly — same pattern as sample 06):
//   { payload, ecdsaSignature, mldsaSignature, mldsaKeyId }
// with the signatures base64-encoded and mldsaKeyId identifying which pinned
// PQ trust anchor signed it (rotation-ready from day one; see Recipe 15).

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using PostQuantum.Cryptography;

if (!MLDsa87.IsSupported)
{
    Console.Error.WriteLine("ML-DSA-87 is not supported on this runtime.");
    return 1;
}

Console.WriteLine("=== Sample 07: migrate from ECDSA to ML-DSA via dual-signing ===\n");

// Bind every ML-DSA signature to a usage domain (FIPS 204 §5.2) so a
// signature minted during this migration can't be replayed elsewhere.
byte[] context = "migration-sample/v1"u8.ToArray();

// ---------------------------------------------------------------------------
// 1. PUBLISHER: hold both keys — ECDSA P-256 (the incumbent) and ML-DSA-87
//    (the future) — generated INDEPENDENTLY (non-negotiable #1 above).
// ---------------------------------------------------------------------------

using ECDsa ecdsaSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using MLDsaPrivateKey mldsaSigner = MLDsa87.GenerateKeyPair();

// A short identifier for the ML-DSA public key so verifiers can pick the
// right pinned trust anchor when the PQ key eventually rotates.
using MLDsaPublicKey mldsaSignerPub = mldsaSigner.GetPublicKey();
string mldsaKeyId = Convert.ToHexString(SHA256.HashData(mldsaSignerPub.Export()))[..16].ToLowerInvariant();

byte[] payload = Encoding.UTF8.GetBytes("invoice#8412: pay 100 to Alice by 2026-08-01");

// One payload, two signatures — the dual-signature envelope.
byte[] ecdsaSignature = ecdsaSigner.SignData(payload, HashAlgorithmName.SHA256);
byte[] mldsaSignature = mldsaSigner.SignData(payload, context);

var dualEnvelope = new DualSignatureEnvelope(
    PayloadBase64: Convert.ToBase64String(payload),
    EcdsaSignatureBase64: Convert.ToBase64String(ecdsaSignature),
    MLDsaSignatureBase64: Convert.ToBase64String(mldsaSignature),
    MLDsaKeyId: mldsaKeyId);

string wireJson = JsonSerializer.Serialize(dualEnvelope, EnvelopeJsonContext.Default.DualSignatureEnvelope);

Console.WriteLine("PUBLISHER : signed one payload with BOTH keys.");
Console.WriteLine($"            ECDSA P-256 signature : {ecdsaSignature.Length,5} bytes  (incumbent)");
Console.WriteLine($"            ML-DSA-87 signature   : {mldsaSignature.Length,5} bytes  (post-quantum — ~72x larger; size your schema for it)");
Console.WriteLine($"            envelope JSON         : {wireJson.Length,5} bytes  (mldsaKeyId {mldsaKeyId})");

// ---------------------------------------------------------------------------
// 2. VERIFIER setup: only PUBLIC material crosses to the verifying side —
//    the ECDSA key via SubjectPublicKeyInfo, the ML-DSA key as raw public
//    bytes, plus the pinned key id. Private keys never leave the publisher.
// ---------------------------------------------------------------------------

using ECDsa ecdsaVerifier = ECDsa.Create();
ecdsaVerifier.ImportSubjectPublicKeyInfo(ecdsaSigner.ExportSubjectPublicKeyInfo(), out _);
using MLDsaPublicKey mldsaVerifier = MLDsa87.ImportPublicKey(mldsaSignerPub.Export());
string pinnedMLDsaKeyId = mldsaKeyId;

// ---------------------------------------------------------------------------
// 3. Build the test envelopes. The verifier receives them off the wire as
//    JSON, exactly as a real consumer would.
//      a. the genuine dual-signed envelope;
//      b. the same envelope with one payload byte flipped (both sigs break);
//      c. an envelope with no ML-DSA signature (a legacy signer that hasn't
//         been upgraded yet — the case Phase 1 exists to tolerate);
//      d. an envelope with no ECDSA signature (a PQ-only signer — only
//         acceptable once the fleet reaches Phase 3).
// ---------------------------------------------------------------------------

DualSignatureEnvelope received = JsonSerializer.Deserialize(wireJson, EnvelopeJsonContext.Default.DualSignatureEnvelope)!;

byte[] tamperedPayload = (byte[])payload.Clone();
tamperedPayload[0] ^= 0xFF;
DualSignatureEnvelope tampered = received with { PayloadBase64 = Convert.ToBase64String(tamperedPayload) };

DualSignatureEnvelope missingMLDsa = received with { MLDsaSignatureBase64 = string.Empty };
DualSignatureEnvelope missingEcdsa = received with { EcdsaSignatureBase64 = string.Empty };

// Expected accept/reject per (envelope, phase) — the self-check contract.
(string Label, DualSignatureEnvelope Envelope, bool[] Expected)[] cases =
[
    ("dual-signed (valid)",     received,     [true,  true,  true]),
    ("tampered payload",        tampered,     [false, false, false]),
    ("missing ML-DSA signature", missingMLDsa, [true,  false, false]),
    ("missing ECDSA signature", missingEcdsa, [false, false, true]),
];

MigrationPhase[] phases =
[
    MigrationPhase.Phase1_ClassicalRequired,
    MigrationPhase.Phase2_BothRequired,
    MigrationPhase.Phase3_PqOnly,
];

// ---------------------------------------------------------------------------
// 4. Run every envelope through every phase. Phase-1 "observe" warnings print
//    inline — in production those lines are your telemetry that tells you
//    when it is safe to advance to Phase 2.
// ---------------------------------------------------------------------------

Console.WriteLine("\nVERIFIER  : running all envelopes through all three phases (Phase-1 observe log below):\n");

var results = new bool[cases.Length][];
for (int c = 0; c < cases.Length; c++)
{
    Console.WriteLine($"  checking '{cases[c].Label}'");
    results[c] = new bool[phases.Length];
    for (int p = 0; p < phases.Length; p++)
    {
        results[c][p] = Verify(cases[c].Envelope, phases[p]);
    }
}

// ---------------------------------------------------------------------------
// 5. Results table + self-check. Any deviation from the expected contract
//    throws, so this sample doubles as an executable test of Recipe 12.
// ---------------------------------------------------------------------------

Console.WriteLine($"\n  {"envelope",-27} {"Phase1(observe)",-16} {"Phase2(both)",-13} {"Phase3(pq-only)",-15}");
Console.WriteLine($"  {new string('-', 27)} {new string('-', 16)} {new string('-', 13)} {new string('-', 15)}");

bool allAsExpected = true;
for (int c = 0; c < cases.Length; c++)
{
    string[] cells = new string[phases.Length];
    for (int p = 0; p < phases.Length; p++)
    {
        bool ok = results[c][p] == cases[c].Expected[p];
        allAsExpected &= ok;
        cells[p] = (results[c][p] ? "accept" : "reject") + (ok ? "" : " *FAIL*");
    }
    Console.WriteLine($"  {cases[c].Label,-27} {cells[0],-16} {cells[1],-13} {cells[2],-15}");
}

if (!allAsExpected)
{
    throw new InvalidOperationException("a verification result did not match the expected migration contract (see *FAIL* cells above)");
}

Console.WriteLine("\n  note: 'missing ML-DSA signature' is accepted in Phase 1 by design — the");
Console.WriteLine("  warning above is the observe-phase log line that drives your rollout metrics.");
Console.WriteLine("\nAll phase results matched the expected migration contract.");
return 0;

// ============================ implementation ================================

// The three-phase rollout, as ONE verify function switched on the phase.
// Roll your fleet forward by changing a config value, not by shipping code.
bool Verify(DualSignatureEnvelope envelope, MigrationPhase phase)
{
    byte[] data = Convert.FromBase64String(envelope.PayloadBase64);
    byte[] classicalSig = Convert.FromBase64String(envelope.EcdsaSignatureBase64);
    byte[] pqSig = Convert.FromBase64String(envelope.MLDsaSignatureBase64);

    bool ecdsaOk = classicalSig.Length > 0
        && ecdsaVerifier.VerifyData(data, classicalSig, HashAlgorithmName.SHA256);

    bool mldsaOk = pqSig.Length > 0
        && envelope.MLDsaKeyId == pinnedMLDsaKeyId
        && mldsaVerifier.Verify(data, pqSig, context);

    switch (phase)
    {
        case MigrationPhase.Phase1_ClassicalRequired:
            // Deploy-and-observe: PQ failures are telemetry, not rejections.
            if (!mldsaOk)
            {
                Console.WriteLine("      [phase1 observe] WARN: ML-DSA signature missing or invalid — logged only, envelope not rejected");
            }
            return ecdsaOk;

        case MigrationPhase.Phase2_BothRequired:
            return ecdsaOk && mldsaOk;

        case MigrationPhase.Phase3_PqOnly:
            return mldsaOk;

        default:
            throw new ArgumentOutOfRangeException(nameof(phase));
    }
}

// ---- Rollout phases ----

internal enum MigrationPhase
{
    /// <summary>ECDSA required; ML-DSA verified but failures only logged.</summary>
    Phase1_ClassicalRequired,

    /// <summary>Both signatures must verify.</summary>
    Phase2_BothRequired,

    /// <summary>Only ML-DSA must verify; classical is sunset.</summary>
    Phase3_PqOnly,
}

// ---- Wire type ----
//
// Source-generated System.Text.Json contract: AOT-friendly and the pattern
// production code should use rather than reflection-based serialization.
// A missing signature is the empty string (decodes to zero bytes).

internal sealed record DualSignatureEnvelope(
    [property: JsonPropertyName("payload")] string PayloadBase64,
    [property: JsonPropertyName("ecdsaSignature")] string EcdsaSignatureBase64,
    [property: JsonPropertyName("mldsaSignature")] string MLDsaSignatureBase64,
    [property: JsonPropertyName("mldsaKeyId")] string MLDsaKeyId);

[JsonSerializable(typeof(DualSignatureEnvelope))]
internal sealed partial class EnvelopeJsonContext : JsonSerializerContext;
