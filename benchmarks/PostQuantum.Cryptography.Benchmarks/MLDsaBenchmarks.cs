using BenchmarkDotNet.Attributes;

namespace PostQuantum.Cryptography.Benchmarks;

[MemoryDiagnoser]
public class MLDsaBenchmarks
{
    private MLDsaPrivateKey _signer = null!;
    private MLDsaPublicKey _verifier = null!;
    private byte[] _message = null!;
    private byte[] _signature = null!;
    private readonly byte[] _sigBuffer = new byte[MLDsa87.SignatureSizeInBytes];

    [GlobalSetup]
    public void Setup()
    {
        _signer = MLDsa87.GenerateKeyPair();
        _verifier = _signer.GetPublicKey();
        _message = "To God be the glory."u8.ToArray();
        _signature = _signer.SignData(_message);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _verifier.Dispose();
        _signer.Dispose();
    }

    [Benchmark]
    public MLDsaPrivateKey GenerateKeyPair()
    {
        MLDsaPrivateKey k = MLDsa87.GenerateKeyPair();
        k.Dispose();
        return k;
    }

    [Benchmark]
    public byte[] SignData_Allocating() => _signer.SignData(_message);

    [Benchmark]
    public void SignData_SpanOverload() => _signer.SignData(_message, _sigBuffer.AsSpan());

    [Benchmark]
    public bool Verify() => _verifier.Verify(_message, _signature);
}
