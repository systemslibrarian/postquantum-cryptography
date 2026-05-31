using BenchmarkDotNet.Attributes;

namespace PostQuantum.Cryptography.Benchmarks;

[MemoryDiagnoser]
public class XWingBenchmarks
{
    private XWingPrivateKey _priv = null!;
    private XWingPublicKey _pub = null!;
    private byte[] _ciphertext = null!;
    private readonly byte[] _ctBuffer = new byte[XWing.CiphertextSizeInBytes];
    private readonly byte[] _ssBuffer = new byte[XWing.SharedSecretSizeInBytes];

    [GlobalSetup]
    public void Setup()
    {
        _priv = XWing.GenerateKeyPair();
        _pub = _priv.GetPublicKey();
        _pub.Encapsulate(_ctBuffer, _ssBuffer);
        _ciphertext = (byte[])_ctBuffer.Clone();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _pub.Dispose();
        _priv.Dispose();
    }

    [Benchmark]
    public XWingPrivateKey GenerateKeyPair()
    {
        XWingPrivateKey k = XWing.GenerateKeyPair();
        k.Dispose();
        return k;
    }

    [Benchmark]
    public KemEncapsulation Encapsulate_Allocating() => _pub.Encapsulate();

    [Benchmark]
    public void Encapsulate_SpanOverload() => _pub.Encapsulate(_ctBuffer, _ssBuffer);

    [Benchmark]
    public byte[] Decapsulate_Allocating() => _priv.Decapsulate(_ciphertext);

    [Benchmark]
    public void Decapsulate_SpanOverload() => _priv.Decapsulate(_ciphertext, _ssBuffer);
}
