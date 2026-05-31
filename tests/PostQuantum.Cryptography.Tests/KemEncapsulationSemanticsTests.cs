using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Locks down the surprising-but-deliberate semantics of <see cref="KemEncapsulation"/>:
/// equality is reference-based on the inner arrays (NOT content-based) to avoid
/// accidental non–constant-time comparisons of secret material, and
/// <c>ToString()</c> never emits the bytes.
/// </summary>
public class KemEncapsulationSemanticsTests
{
    [Fact]
    public void Equality_OnIdenticalBytesButDistinctArrays_IsFalse()
    {
        byte[] ct1 = [1, 2, 3];
        byte[] ss1 = [4, 5, 6];
        byte[] ct2 = [1, 2, 3];
        byte[] ss2 = [4, 5, 6];

        KemEncapsulation a = new(ct1, ss1);
        KemEncapsulation b = new(ct2, ss2);

        // Reference equality on the inner arrays — they're DIFFERENT instances
        // even though the contents match.
        Assert.False(a == b);
        Assert.False(a.Equals(b));
    }

    [Fact]
    public void Equality_OnSameArrayInstances_IsTrue()
    {
        byte[] ct = [1, 2, 3];
        byte[] ss = [4, 5, 6];
        KemEncapsulation a = new(ct, ss);
        KemEncapsulation b = new(ct, ss);

        Assert.True(a == b);
        Assert.True(a.Equals(b));
    }

    [Fact]
    public void ContentEquality_RequiresFixedTimeEquals()
    {
        // The documented escape hatch for content equality, used in
        // constant-time mode — no leak about which byte differs.
        KemEncapsulation a = new([1, 2, 3], [9, 9, 9]);
        KemEncapsulation b = new([1, 2, 3], [9, 9, 9]);

        Assert.True(CryptographicOperations.FixedTimeEquals(a.Ciphertext, b.Ciphertext));
        Assert.True(CryptographicOperations.FixedTimeEquals(a.SharedSecret, b.SharedSecret));
    }

    [Fact]
    public void ToString_DoesNotLeakBytesOrLengths()
    {
        KemEncapsulation enc = new([1, 2, 3, 4, 5], [42, 42, 42]);
        string s = enc.ToString();

        Assert.Equal(nameof(KemEncapsulation), s);
        Assert.DoesNotContain("1", s, StringComparison.Ordinal);
        Assert.DoesNotContain("42", s, StringComparison.Ordinal);
    }
}
