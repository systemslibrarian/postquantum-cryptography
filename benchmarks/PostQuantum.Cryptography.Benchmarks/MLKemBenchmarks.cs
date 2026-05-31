using BenchmarkDotNet.Attributes;

namespace PostQuantum.Cryptography.Benchmarks;

[MemoryDiagnoser]
public class MLKemBenchmarks
{
    private MLKemPrivateKey _priv = null!;
    private MLKemPublicKey _pub = null!;
    private byte[] _ciphertext = null!;
    private readonly byte[] _ssBuffer = new byte[MLKem768.SharedSecretSizeInBytes];
    private readonly byte[] _ctBuffer = new byte[MLKem768.CiphertextSizeInBytes];

    [GlobalSetup]
    public void Setup()
    {
        _priv = MLKem768.GenerateKeyPair();
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
    public MLKemPrivateKey GenerateKeyPair()
    {
        MLKemPrivateKey k = MLKem768.GenerateKeyPair();
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
