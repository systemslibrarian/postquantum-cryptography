using System.Text.Json;
using Xunit;
using static PostQuantum.Cryptography.Tests.TestHelpers;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// NIST ACVP known-answer tests for ML-DSA (FIPS 204), curated from the
/// ACVP-Server gen-val reference vectors (<c>usnistgov/ACVP-Server</c>,
/// <c>gen-val/json-files</c>; commit and retrieval date recorded in each
/// vector file's <c>_provenance</c> block).
/// </summary>
/// <remarks>
/// Coverage is the deterministic surface reachable through the public API:
/// <list type="bullet">
/// <item><b>keyGen</b> — seed ξ → expected public key and secret key,
/// 10 cases per parameter set.</item>
/// <item><b>sigVer</b> — the external-interface / pure / non-external-mu
/// groups, which is exactly the contract of
/// <see cref="MLDsaPublicKey.Verify(ReadOnlySpan{byte}, ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>:
/// 15 cases per parameter set, mixing valid signatures with modified
/// message / signature / hint negatives, all with FIPS 204 §5.2 contexts.</item>
/// </list>
/// Signature <b>generation</b> KATs are not representable: FIPS 204 signing
/// through the BCL is hedged (randomized), and the wrapper deliberately
/// exposes no deterministic-signing knob. Signing is covered by round-trip
/// tests and the BCL byte-equality cross-checks.
/// </remarks>
public class AcvpMlDsaKatTests
{
    [PqcTheory]
    [MemberData(nameof(KeyGenCases))]
    public void KeyGen_SeedProducesExpectedKeyPair(string parameterSet, int tcId)
    {
        JsonElement test = AcvpMlKemKatTests.FindCase("acvp_mldsa_keygen.json", parameterSet, tcId);

        using MLDsaPrivateKey key = ImportPrivateSeed(
            parameterSet, Hex(test.GetProperty("seed").GetString()!));

        // ACVP vector files use uppercase hex; the local helper emits lowercase.
        Assert.Equal(test.GetProperty("pk").GetString(), Hex(key.ExportPublicKey()), ignoreCase: true);
        Assert.Equal(test.GetProperty("sk").GetString(), Hex(key.ExportSecretKey()), ignoreCase: true);
    }

    [PqcTheory]
    [MemberData(nameof(SigVerCases))]
    public void SigVer_MatchesExpectedVerdict(string parameterSet, int tcId)
    {
        JsonElement test = AcvpMlKemKatTests.FindCase("acvp_mldsa_sigver.json", parameterSet, tcId);

        using MLDsaPublicKey key = ImportPublicKey(
            parameterSet, Hex(test.GetProperty("pk").GetString()!));

        bool verified = key.Verify(
            Hex(test.GetProperty("message").GetString()!),
            Hex(test.GetProperty("signature").GetString()!),
            Hex(test.GetProperty("context").GetString()!));

        bool expected = test.GetProperty("testPassed").GetBoolean();
        string reason = test.GetProperty("reason").GetString()!;
        Assert.True(
            verified == expected,
            $"{parameterSet} tcId {tcId}: expected {expected} ({reason}), got {verified}.");
    }

    public static TheoryData<string, int> KeyGenCases() =>
        AcvpMlKemKatTests.CaseIds("acvp_mldsa_keygen.json");

    public static TheoryData<string, int> SigVerCases() =>
        AcvpMlKemKatTests.CaseIds("acvp_mldsa_sigver.json");

    private static MLDsaPrivateKey ImportPrivateSeed(string parameterSet, byte[] seed) =>
        parameterSet switch
        {
            "ML-DSA-44" => MLDsa44.ImportPrivateSeed(seed),
            "ML-DSA-65" => MLDsa65.ImportPrivateSeed(seed),
            "ML-DSA-87" => MLDsa87.ImportPrivateSeed(seed),
            _ => throw new ArgumentException($"Unknown parameter set '{parameterSet}'."),
        };

    private static MLDsaPublicKey ImportPublicKey(string parameterSet, byte[] publicKey) =>
        parameterSet switch
        {
            "ML-DSA-44" => MLDsa44.ImportPublicKey(publicKey),
            "ML-DSA-65" => MLDsa65.ImportPublicKey(publicKey),
            "ML-DSA-87" => MLDsa87.ImportPublicKey(publicKey),
            _ => throw new ArgumentException($"Unknown parameter set '{parameterSet}'."),
        };
}
