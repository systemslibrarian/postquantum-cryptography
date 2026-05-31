// Sample 04 — Zero-allocation encapsulation in a hot loop.
//
// Demonstrates: the Span<byte> overloads on every primitive let high-throughput
// code (server doing many handshakes per second, batch signing, etc.) avoid
// touching the GC heap on each operation.
//
// We compare an allocating loop (returns byte[]) to a Span loop (writes into
// caller-provided stack buffers) and measure GC pressure on each.

using System.Diagnostics;
using System.Security.Cryptography;
using PostQuantum.Cryptography;

if (!MLKem768.IsSupported)
{
    Console.Error.WriteLine("ML-KEM-768 is not supported on this runtime.");
    return 1;
}

const int iterations = 5000;

Console.WriteLine("=== Sample 04: zero-alloc hot loop ===\n");
Console.WriteLine($"Iterations: {iterations:N0}\n");

using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
using MLKemPublicKey pub = priv.GetPublicKey();

// Quick warm-up so JIT and BCL setup don't skew the first measurement.
for (int i = 0; i < 50; i++)
{
    KemEncapsulation warm = pub.Encapsulate();
    _ = priv.Decapsulate(warm.Ciphertext);
}

// -- Allocating path ---------------------------------------------------------

long gc0Before = GC.CollectionCount(0);
long allocBefore = GC.GetTotalAllocatedBytes(precise: true);
Stopwatch swAlloc = Stopwatch.StartNew();
for (int i = 0; i < iterations; i++)
{
    KemEncapsulation enc = pub.Encapsulate();   // allocates byte[]+byte[]
    byte[] recovered = priv.Decapsulate(enc.Ciphertext);   // allocates byte[]
    if (!CryptographicOperations.FixedTimeEquals(enc.SharedSecret, recovered))
    {
        throw new InvalidOperationException("Round-trip failure.");
    }
}
swAlloc.Stop();
long gc0AfterAlloc = GC.CollectionCount(0);
long allocAfterAlloc = GC.GetTotalAllocatedBytes(precise: true);

Console.WriteLine("Allocating (byte[]-returning overloads):");
Report(swAlloc, iterations, allocAfterAlloc - allocBefore, gc0AfterAlloc - gc0Before);

// -- Span (zero-alloc) path --------------------------------------------------

Span<byte> ctBuffer = stackalloc byte[MLKem768.CiphertextSizeInBytes];
Span<byte> ssAlice  = stackalloc byte[MLKem768.SharedSecretSizeInBytes];
Span<byte> ssBob    = stackalloc byte[MLKem768.SharedSecretSizeInBytes];

long gc0BeforeSpan = GC.CollectionCount(0);
long allocBeforeSpan = GC.GetTotalAllocatedBytes(precise: true);
Stopwatch swSpan = Stopwatch.StartNew();
for (int i = 0; i < iterations; i++)
{
    pub.Encapsulate(ctBuffer, ssAlice);
    priv.Decapsulate(ctBuffer, ssBob);
    if (!CryptographicOperations.FixedTimeEquals(ssAlice, ssBob))
    {
        throw new InvalidOperationException("Round-trip failure.");
    }
}
swSpan.Stop();
long gc0AfterSpan = GC.CollectionCount(0);
long allocAfterSpan = GC.GetTotalAllocatedBytes(precise: true);

Console.WriteLine("\nZero-alloc (Span<byte> overloads):");
Report(swSpan, iterations, allocAfterSpan - allocBeforeSpan, gc0AfterSpan - gc0BeforeSpan);

// Clear our local copies of the secrets once we're done.
CryptographicOperations.ZeroMemory(ssAlice);
CryptographicOperations.ZeroMemory(ssBob);

return 0;

static void Report(Stopwatch sw, int iterations, long bytesAllocated, long gen0Collections)
{
    double perOp = sw.Elapsed.TotalMicroseconds / iterations;
    double bytesPerOp = (double)bytesAllocated / iterations;
    Console.WriteLine($"  total time      : {sw.Elapsed.TotalMilliseconds,8:F1} ms");
    Console.WriteLine($"  per op          : {perOp,8:F1} µs");
    Console.WriteLine($"  bytes allocated : {bytesAllocated,12:N0}");
    Console.WriteLine($"  per-op bytes    : {bytesPerOp,8:F1}");
    Console.WriteLine($"  gen-0 GCs       : {gen0Collections}");
}
