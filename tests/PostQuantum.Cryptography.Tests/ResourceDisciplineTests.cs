using System.Diagnostics;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Locks down the resource-cleanup discipline introduced when we made
/// <c>XWingPrivateKey.FromSeed</c> exception-safe (the freshly imported
/// <c>MLKem</c> handle and the X25519 scalar are released even if
/// construction fails partway). Symptom of any regression: handle leaks
/// across many import/dispose cycles. We can't directly trigger a fault on
/// the happy path (BCL imports always succeed for a valid seed), but we can
/// prove the happy path doesn't leak by running it many thousand times
/// without unbounded handle / managed-memory growth.
/// </summary>
public class ResourceDisciplineTests
{
    [PqcFact]
    public void XWingPrivateKey_ImportDispose_DoesNotLeakHandles_OverManyIterations()
    {
        // 5000 iterations is enough to exhaust any naive handle leak on
        // every supported platform we run on, but cheap enough to keep the
        // test suite snappy.
        const int iterations = 5000;
        byte[] seed = new byte[XWing.DecapsulationKeySizeInBytes];
        for (int i = 0; i < seed.Length; i++) seed[i] = (byte)i;

        long baselineHandles = SafeHandleCount();
        long baselineWorkingSet = Environment.WorkingSet;

        for (int i = 0; i < iterations; i++)
        {
            using XWingPrivateKey priv = XWing.ImportDecapsulationKey(seed);
            // Touch the key so JIT doesn't elide the construction entirely.
            _ = priv.ExportEncapsulationKey().Length;
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();

        long afterHandles = SafeHandleCount();
        long afterWorkingSet = Environment.WorkingSet;

        // Generous upper bound — we'd only see growth measured in MB or
        // thousands of handles if we were leaking. Steady-state noise is
        // tens of KB / single-digit handle delta.
        long handleDelta = afterHandles - baselineHandles;
        long workingSetDeltaMb = (afterWorkingSet - baselineWorkingSet) / (1024L * 1024L);

        Assert.True(handleDelta < 100, $"OS handle count grew by {handleDelta} across {iterations} import/dispose cycles — possible handle leak.");
        Assert.True(workingSetDeltaMb < 50, $"Working set grew by {workingSetDeltaMb} MB across {iterations} import/dispose cycles — possible managed-memory leak.");
    }

    private static long SafeHandleCount()
    {
        try
        {
            return Process.GetCurrentProcess().HandleCount;
        }
        catch (PlatformNotSupportedException)
        {
            return 0; // Some platforms (constrained sandboxes) don't expose this.
        }
    }
}
