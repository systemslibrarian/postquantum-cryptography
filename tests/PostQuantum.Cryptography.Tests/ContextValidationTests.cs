using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// FIPS 204 §5.2 caps the optional signature context at 255 bytes. The wrapper
/// validates this up-front so callers see a clear <see cref="ArgumentException"/>
/// instead of a generic <see cref="System.Security.Cryptography.CryptographicException"/>
/// surfaced from deep inside the BCL.
/// </summary>
public class ContextValidationTests
{
    private static readonly byte[] Message = "ctx-validation"u8.ToArray();

    [PqcTheory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(255)]
    public void SignAndVerify_AcceptsContextWithinSpec(int contextLength)
    {
        byte[] context = new byte[contextLength];
        using MLDsaPrivateKey signer = MLDsa87.GenerateKeyPair();
        using MLDsaPublicKey verifier = signer.GetPublicKey();

        byte[] sig = signer.SignData(Message, context);
        Assert.True(verifier.Verify(Message, sig, context));
    }

    [PqcTheory]
    [InlineData(256)]
    [InlineData(1024)]
    [InlineData(65536)]
    public void SignData_ContextOverSpecLimit_ThrowsArgumentException(int contextLength)
    {
        byte[] context = new byte[contextLength];
        using MLDsaPrivateKey signer = MLDsa87.GenerateKeyPair();

        ArgumentException ex = Assert.Throws<ArgumentException>(
            () => signer.SignData(Message, context));

        Assert.Contains("255", ex.Message, System.StringComparison.Ordinal);
        Assert.Equal("context", ex.ParamName);
    }

    [PqcFact]
    public void SignData_SpanOverload_ContextOverSpecLimit_ThrowsArgumentException()
    {
        byte[] context = new byte[256];
        using MLDsaPrivateKey signer = MLDsa87.GenerateKeyPair();
        byte[] dest = new byte[MLDsa87.SignatureSizeInBytes];

        Assert.Throws<ArgumentException>(() =>
        {
            byte[] msg = Message;
            byte[] ctx = context;
            byte[] d = dest;
            signer.SignData(msg, d.AsSpan(), ctx);
        });
    }

    [PqcFact]
    public void Verify_ContextOverSpecLimit_ThrowsArgumentException()
    {
        byte[] context = new byte[300];
        using MLDsaPrivateKey signer = MLDsa87.GenerateKeyPair();
        using MLDsaPublicKey verifier = signer.GetPublicKey();
        // Sign with a valid short context so the signature itself is well-formed.
        byte[] sig = signer.SignData(Message);

        Assert.Throws<ArgumentException>(() => verifier.Verify(Message, sig, context));
    }
}
