using System.Text.Json;
using Xunit;
using static PostQuantum.Cryptography.Tests.TestHelpers;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// NIST ACVP known-answer tests for ML-KEM (FIPS 203), curated from the
/// ACVP-Server gen-val reference vectors (<c>usnistgov/ACVP-Server</c>,
/// <c>gen-val/json-files</c>; commit and retrieval date recorded in each
/// vector file's <c>_provenance</c> block).
/// </summary>
/// <remarks>
/// Coverage is the deterministic surface reachable through the public API:
/// <list type="bullet">
/// <item><b>keyGen</b> — seed (d‖z) → expected encapsulation and decapsulation
/// keys, 10 cases per parameter set.</item>
/// <item><b>decap (VAL)</b> — expanded decapsulation key + ciphertext →
/// expected shared secret, including the implicit-rejection ("modified
/// ciphertext") cases, 10 per parameter set.</item>
/// </list>
/// Encapsulation AFT cases are derandomized in ACVP (they fix the message
/// <c>m</c>); the wrapper deliberately exposes no derandomized encapsulation,
/// so those cases are not representable here — encapsulation is instead
/// covered by round-trip tests and the BCL byte-equality cross-checks.
/// </remarks>
public class AcvpMlKemKatTests
{
    [PqcTheory]
    [MemberData(nameof(KeyGenCases))]
    public void KeyGen_SeedProducesExpectedKeyPair(string parameterSet, int tcId)
    {
        JsonElement test = FindCase("acvp_mlkem_keygen.json", parameterSet, tcId);

        // FIPS 203 KeyGen takes (d, z); the BCL private seed is the
        // concatenation d ‖ z.
        byte[] seed = [.. Hex(test.GetProperty("d").GetString()!), .. Hex(test.GetProperty("z").GetString()!)];

        using MLKemPrivateKey key = ImportPrivateSeed(parameterSet, seed);

        // ACVP vector files use uppercase hex; the local helper emits lowercase.
        Assert.Equal(test.GetProperty("ek").GetString(), Hex(key.ExportEncapsulationKey()), ignoreCase: true);
        Assert.Equal(test.GetProperty("dk").GetString(), Hex(key.ExportDecapsulationKey()), ignoreCase: true);
    }

    [PqcTheory]
    [MemberData(nameof(DecapCases))]
    public void Decap_CiphertextProducesExpectedSharedSecret(string parameterSet, int tcId)
    {
        JsonElement test = FindCase("acvp_mlkem_decap.json", parameterSet, tcId);

        using MLKemPrivateKey key = ImportDecapsulationKey(
            parameterSet, Hex(test.GetProperty("dk").GetString()!));

        byte[] sharedSecret = key.Decapsulate(Hex(test.GetProperty("c").GetString()!));

        // VAL cases include implicit-rejection inputs ("modified ciphertext");
        // FIPS 203 defines the expected shared secret for those too, so the
        // assertion is unconditional byte equality.
        Assert.Equal(test.GetProperty("k").GetString(), Hex(sharedSecret), ignoreCase: true);
    }

    public static TheoryData<string, int> KeyGenCases() => CaseIds("acvp_mlkem_keygen.json");

    public static TheoryData<string, int> DecapCases() => CaseIds("acvp_mlkem_decap.json");

    private static MLKemPrivateKey ImportPrivateSeed(string parameterSet, byte[] seed) =>
        parameterSet switch
        {
            "ML-KEM-512" => MLKem512.ImportPrivateSeed(seed),
            "ML-KEM-768" => MLKem768.ImportPrivateSeed(seed),
            "ML-KEM-1024" => MLKem1024.ImportPrivateSeed(seed),
            _ => throw new ArgumentException($"Unknown parameter set '{parameterSet}'."),
        };

    private static MLKemPrivateKey ImportDecapsulationKey(string parameterSet, byte[] dk) =>
        parameterSet switch
        {
            "ML-KEM-512" => MLKem512.ImportDecapsulationKey(dk),
            "ML-KEM-768" => MLKem768.ImportDecapsulationKey(dk),
            "ML-KEM-1024" => MLKem1024.ImportDecapsulationKey(dk),
            _ => throw new ArgumentException($"Unknown parameter set '{parameterSet}'."),
        };

    internal static TheoryData<string, int> CaseIds(string fileName)
    {
        var data = new TheoryData<string, int>();
        using JsonDocument doc = LoadVectorFile(fileName);
        foreach (JsonElement group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            string parameterSet = group.GetProperty("parameterSet").GetString()!;
            foreach (JsonElement test in group.GetProperty("tests").EnumerateArray())
            {
                data.Add(parameterSet, test.GetProperty("tcId").GetInt32());
            }
        }

        return data;
    }

    internal static JsonElement FindCase(string fileName, string parameterSet, int tcId)
    {
        using JsonDocument doc = LoadVectorFile(fileName);
        foreach (JsonElement group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            if (group.GetProperty("parameterSet").GetString() != parameterSet)
            {
                continue;
            }

            foreach (JsonElement test in group.GetProperty("tests").EnumerateArray())
            {
                if (test.GetProperty("tcId").GetInt32() == tcId)
                {
                    return test.Clone();
                }
            }
        }

        throw new InvalidOperationException($"{fileName}: no case {parameterSet}/{tcId}.");
    }

    private static JsonDocument LoadVectorFile(string fileName) =>
        JsonDocument.Parse(File.ReadAllText(
            Path.Combine(AppContext.BaseDirectory, "TestData", fileName)));
}
