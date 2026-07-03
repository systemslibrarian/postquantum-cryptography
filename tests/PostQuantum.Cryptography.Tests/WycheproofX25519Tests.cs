using System.Text.Json;
using PostQuantum.Cryptography.Internal;
using Xunit;
using static PostQuantum.Cryptography.Tests.TestHelpers;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Runs the bundled X25519 implementation against the full Project Wycheproof
/// x25519 vector set (518 cases from <c>testvectors_v1/x25519_test.json</c>,
/// C2SP/wycheproof). The set concentrates on adversarial inputs the RFC 7748
/// KATs do not reach: twist points, low-order points (all-zero shared secret),
/// non-canonical u-coordinates, and public keys constructed so that internal
/// field-arithmetic variables hit edge values (-1, 0, 1) during the ladder.
/// </summary>
/// <remarks>
/// Every vector in the set is <c>valid</c> or <c>acceptable</c> and carries an
/// expected shared secret, because RFC 7748 defines the function's output for
/// every 32-byte input. The bundled X25519 is the raw RFC 7748 primitive — it
/// deliberately does not reject low-order or all-zero outputs (safe only
/// inside X-Wing; see <c>KNOWN-GAPS.md</c>) — so the correct expectation here
/// is exact byte equality on all 518 cases, including the 31 that produce an
/// all-zero shared secret.
/// </remarks>
public class WycheproofX25519Tests
{
    private const int ExpectedVectorCount = 518;

    private static readonly string VectorPath =
        Path.Combine(AppContext.BaseDirectory, "TestData", "x25519_test.json");

    public static TheoryData<int> VectorIds()
    {
        var data = new TheoryData<int>();
        foreach (WycheproofCase c in LoadCases())
        {
            data.Add(c.TcId);
        }

        return data;
    }

    [Fact]
    public void VectorFile_ContainsTheFullPublishedSet()
    {
        Assert.Equal(ExpectedVectorCount, LoadCases().Count);
    }

    [Theory]
    [MemberData(nameof(VectorIds))]
    public void ScalarMult_MatchesWycheproofExpectedSharedSecret(int tcId)
    {
        WycheproofCase c = LoadCases().Single(v => v.TcId == tcId);

        byte[] shared = X25519.ScalarMult(Hex(c.Private), Hex(c.Public));

        Assert.Equal(c.Shared, TestHelpers.Hex(shared));
    }

    private static IReadOnlyList<WycheproofCase> LoadCases() => s_cases.Value;

    private static readonly Lazy<IReadOnlyList<WycheproofCase>> s_cases = new(() =>
    {
        using JsonDocument doc = JsonDocument.Parse(File.ReadAllText(VectorPath));
        var cases = new List<WycheproofCase>();

        foreach (JsonElement group in doc.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            Assert.Equal("curve25519", group.GetProperty("curve").GetString());

            foreach (JsonElement test in group.GetProperty("tests").EnumerateArray())
            {
                string result = test.GetProperty("result").GetString()!;
                Assert.True(
                    result is "valid" or "acceptable",
                    $"tcId {test.GetProperty("tcId").GetInt32()}: unexpected result '{result}' — " +
                    "the vector set changed shape; re-review the expectations in this test.");

                cases.Add(new WycheproofCase(
                    test.GetProperty("tcId").GetInt32(),
                    test.GetProperty("private").GetString()!,
                    test.GetProperty("public").GetString()!,
                    test.GetProperty("shared").GetString()!));
            }
        }

        return cases;
    });

    private sealed record WycheproofCase(int TcId, string Private, string Public, string Shared);
}
