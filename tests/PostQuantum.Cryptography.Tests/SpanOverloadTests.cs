using System.Text;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Exercises the allocation-free Span overloads on the KEM and signature APIs,
/// confirming that they round-trip identically with the allocating variants.
/// </summary>
public class SpanOverloadTests
{
    [PqcFact]
    public void MLKem768_Encapsulate_Decapsulate_SpanOverloads_RoundTrip()
    {
        using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
        using MLKemPublicKey pub = priv.GetPublicKey();

        Span<byte> ct = stackalloc byte[MLKem768.CiphertextSizeInBytes];
        Span<byte> ssSender = stackalloc byte[MLKem768.SharedSecretSizeInBytes];
        Span<byte> ssRecipient = stackalloc byte[MLKem768.SharedSecretSizeInBytes];

        pub.Encapsulate(ct, ssSender);
        priv.Decapsulate(ct, ssRecipient);

        Assert.True(ssSender.SequenceEqual(ssRecipient));
    }

    [PqcFact]
    public void XWing_Encapsulate_Decapsulate_SpanOverloads_RoundTrip()
    {
        using XWingPrivateKey priv = XWing.GenerateKeyPair();
        using XWingPublicKey pub = priv.GetPublicKey();

        Span<byte> ct = stackalloc byte[XWing.CiphertextSizeInBytes];
        Span<byte> ssSender = stackalloc byte[XWing.SharedSecretSizeInBytes];
        Span<byte> ssRecipient = stackalloc byte[XWing.SharedSecretSizeInBytes];

        pub.Encapsulate(ct, ssSender);
        priv.Decapsulate(ct, ssRecipient);

        Assert.True(ssSender.SequenceEqual(ssRecipient));
    }

    [PqcFact]
    public void MLDsa87_SignData_SpanOverload_RoundTrips_WithAndWithoutContext()
    {
        byte[] message = "To God be the glory."u8.ToArray();
        byte[] context = Encoding.UTF8.GetBytes("ctx-v1");

        using MLDsaPrivateKey priv = MLDsa87.GenerateKeyPair();
        using MLDsaPublicKey pub = priv.GetPublicKey();

        Span<byte> sig = stackalloc byte[MLDsa87.SignatureSizeInBytes];
        priv.SignData(message, sig);
        Assert.True(pub.Verify(message, sig));

        priv.SignData(message, sig, context);
        Assert.True(pub.Verify(message, sig, context));
        Assert.False(pub.Verify(message, sig));
    }

    [PqcTheory]
    [InlineData(0)]
    [InlineData(MLKem768.CiphertextSizeInBytes - 1)]
    [InlineData(MLKem768.CiphertextSizeInBytes + 1)]
    public void MLKem768_Encapsulate_SpanOverload_RejectsWrongCiphertextSize(int size)
    {
        using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
        using MLKemPublicKey pub = priv.GetPublicKey();
        byte[] ct = new byte[size];
        byte[] ss = new byte[MLKem768.SharedSecretSizeInBytes];
        Assert.Throws<ArgumentException>(() => pub.Encapsulate(ct, ss));
    }

    [PqcTheory]
    [InlineData(0)]
    [InlineData(MLKem768.SharedSecretSizeInBytes - 1)]
    [InlineData(MLKem768.SharedSecretSizeInBytes + 1)]
    public void MLKem768_Encapsulate_SpanOverload_RejectsWrongSharedSecretSize(int size)
    {
        using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
        using MLKemPublicKey pub = priv.GetPublicKey();
        byte[] ct = new byte[MLKem768.CiphertextSizeInBytes];
        byte[] ss = new byte[size];
        Assert.Throws<ArgumentException>(() => pub.Encapsulate(ct, ss));
    }

    [PqcFact]
    public void MLDsa87_SignData_SpanOverload_RejectsWrongDestinationSize()
    {
        byte[] message = "To God be the glory."u8.ToArray();
        using MLDsaPrivateKey priv = MLDsa87.GenerateKeyPair();
        // Wrap in a Span<byte> explicitly so overload resolution picks the
        // (data, destination) void overload rather than the (data, context)
        // byte[]-returning one.
        byte[] backing = new byte[MLDsa87.SignatureSizeInBytes - 1];
        Span<byte> tooSmall = backing;
        Assert.Throws<ArgumentException>(() =>
        {
            // Capture via a helper because Span<byte> can't be captured directly.
            byte[] data = message;
            byte[] dest = backing;
            priv.SignData(data, dest.AsSpan());
        });
    }
}
