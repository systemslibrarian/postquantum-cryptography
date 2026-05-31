using System.Security.Cryptography;
using PostQuantum.Cryptography.Internal;
using Xunit;
using static PostQuantum.Cryptography.Tests.TestHelpers;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Additional X25519 conformance and property tests beyond the basic RFC 7748
/// vectors. These are pure-managed and run on every platform.
/// </summary>
public class X25519PropertyTests
{
    [Fact]
    public void Rfc7748_IteratedScalarMult_AfterOneIteration()
    {
        // RFC 7748 §5.2 iterated test: start k = u = 9, then repeatedly set
        // k, u = X25519(k, u), k. After 1 iteration the expected value is fixed.
        byte[] k = new byte[32];
        k[0] = 9;
        byte[] u = (byte[])k.Clone();

        byte[] result = X25519.ScalarMult(k, u);

        Assert.Equal("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", Hex(result));
    }

    [Fact]
    public void Rfc7748_IteratedScalarMult_After1000Iterations()
    {
        byte[] k = new byte[32];
        k[0] = 9;
        byte[] u = (byte[])k.Clone();

        for (int i = 0; i < 1000; i++)
        {
            byte[] next = X25519.ScalarMult(k, u);
            u = k;
            k = next;
        }

        Assert.Equal("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", Hex(k));
    }

    [Fact]
    public void DiffieHellman_IsCommutative_OverRandomKeys()
    {
        // Property: X25519(a, B(b)) == X25519(b, B(a)) for random a, b.
        for (int i = 0; i < 64; i++)
        {
            byte[] a = RandomNumberGenerator.GetBytes(32);
            byte[] b = RandomNumberGenerator.GetBytes(32);

            byte[] sharedAb = X25519.ScalarMult(a, X25519.ScalarMultBase(b));
            byte[] sharedBa = X25519.ScalarMult(b, X25519.ScalarMultBase(a));

            Assert.Equal(sharedAb, sharedBa);
        }
    }

    [Fact]
    public void ScalarMult_RejectsWrongLengthInputs()
    {
        Assert.Throws<ArgumentException>(() => X25519.ScalarMult(new byte[31], new byte[32]));
        Assert.Throws<ArgumentException>(() => X25519.ScalarMult(new byte[32], new byte[33]));
        Assert.Throws<ArgumentException>(() => X25519.ScalarMultBase(new byte[16]));
    }
}
