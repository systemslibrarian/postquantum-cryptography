using System.Diagnostics;
using System.Security.Cryptography;
using PostQuantum.Cryptography.Internal;
using Xunit;

namespace PostQuantum.Cryptography.Tests;

/// <summary>
/// Dudect-style statistical timing test for the bundled X25519
/// (Reparaz, Balasch &amp; Verbauwhede, "Dude, is my code constant time?",
/// DATE 2017). Measures <c>ScalarMult</c> over two interleaved input
/// classes — a fixed scalar vs. a fresh random scalar per sample, with the
/// u-coordinate held constant — and applies Welch's t-test to the cropped
/// timing distributions. The scalar is the secret input in X-Wing
/// decapsulation, so a scalar-value-dependent timing difference is exactly
/// the leak this library must not have.
/// </summary>
/// <remarks>
/// <para>
/// This is <b>evidence, not proof</b>: a passing run means "no timing
/// dependence on the scalar value was detectable at this sample size on this
/// host and JIT". It measures the code the current JIT actually emitted —
/// which is the gap source review cannot close (see <c>AUDIT-SCOPE.md</c> §3)
/// — but it does not cover other microarchitectures, cache/port-contention
/// channels, or speculative execution.
/// </para>
/// <para>
/// Threshold: dudect's convention is |t| &gt; 10 ⇒ "definitely not constant
/// time"; |t| &lt; 10 ⇒ no leak detected at this sample size. We assert the
/// definite-leak line rather than a tighter bound so the test is meaningful
/// on noisy shared CI runners without being flaky.
/// </para>
/// <para>
/// Gated <c>Category=LongRunning</c> (runs ~10–30 s). Exercised by the
/// <c>constant-time.yml</c> workflow lane; run locally with
/// <c>dotnet test --filter FullyQualifiedName~X25519TimingLeakTests</c>.
/// </para>
/// </remarks>
public class X25519TimingLeakTests
{
    private const int SamplesPerClass = 20_000;
    private const int WarmupIterations = 2_000;
    private const double DefiniteLeakThreshold = 10.0;

    [Fact]
    [Trait("Category", "LongRunning")]
    public void ScalarMult_FixedVsRandomScalar_NoDetectableTimingLeak()
    {
        // Fixed, arbitrary u (public in the threat model: the attacker chooses
        // or knows the ciphertext's ephemeral public key).
        byte[] u = new byte[32];
        u[0] = 9;

        byte[] fixedScalar = new byte[32];
        fixedScalar.AsSpan().Fill(0x55);

        byte[] randomScalar = new byte[32];

        // ONE input buffer used for every measured call, whichever class the
        // iteration belongs to — same address, same cache lines. And the
        // per-iteration preparation below is IDENTICAL for both classes
        // (always draw fresh randomness, always copy 32 bytes); only the
        // copied VALUE differs. Any class-correlated difference in the work
        // done before the timer starts — e.g. calling the CSPRNG only on
        // random-class iterations — shows up as a systematic timing bias
        // that the t-test happily reports as a "leak" (observed at t≈13 on
        // Ubuntu CI runners with an earlier, asymmetric version of this
        // loop, while the same library code passed on Windows).
        byte[] scalar = new byte[32];

        // Warm-up: get ScalarMult to its final JIT tier before measuring.
        for (int i = 0; i < WarmupIterations; i++)
        {
            X25519.ScalarMult(fixedScalar, u);
        }

        var fixedTimes = new double[SamplesPerClass];
        var randomTimes = new double[SamplesPerClass];
        int fixedCount = 0, randomCount = 0;

        // Interleave the classes in random order so slow environmental drift
        // (thermal, scheduler) decorrelates from class membership.
        Span<byte> coin = stackalloc byte[1];
        while (fixedCount < SamplesPerClass || randomCount < SamplesPerClass)
        {
            RandomNumberGenerator.Fill(coin);
            bool pickFixed = (coin[0] & 1) == 0;
            if (pickFixed && fixedCount >= SamplesPerClass)
            {
                pickFixed = false;
            }
            else if (!pickFixed && randomCount >= SamplesPerClass)
            {
                pickFixed = true;
            }

            // Identical preparation for both classes (see comment above).
            RandomNumberGenerator.Fill(randomScalar);
            if (pickFixed)
            {
                fixedScalar.CopyTo(scalar, 0);
            }
            else
            {
                randomScalar.CopyTo(scalar, 0);
            }

            long start = Stopwatch.GetTimestamp();
            X25519.ScalarMult(scalar, u);
            long elapsed = Stopwatch.GetTimestamp() - start;

            if (pickFixed)
            {
                fixedTimes[fixedCount++] = elapsed;
            }
            else
            {
                randomTimes[randomCount++] = elapsed;
            }
        }

        // Crop the upper tail (dudect post-processing): scheduler preemptions
        // and GC pauses produce extreme outliers that carry no signal.
        double[] fixedCropped = CropAtPercentile(fixedTimes, 0.90);
        double[] randomCropped = CropAtPercentile(randomTimes, 0.90);

        double t = WelchT(fixedCropped, randomCropped);

        Assert.True(
            Math.Abs(t) < DefiniteLeakThreshold,
            $"Welch t = {t:F2} (|t| >= {DefiniteLeakThreshold} is dudect's definite-leak line). " +
            $"ScalarMult timing appears to depend on the scalar value — investigate before shipping. " +
            $"n = {fixedCropped.Length}/{randomCropped.Length} cropped samples per class.");
    }

    private static double[] CropAtPercentile(double[] samples, double percentile)
    {
        double[] sorted = [.. samples.Order()];
        double cutoff = sorted[(int)(sorted.Length * percentile)];
        return [.. samples.Where(s => s <= cutoff)];
    }

    private static double WelchT(double[] a, double[] b)
    {
        double meanA = a.Average(), meanB = b.Average();
        double varA = a.Sum(x => (x - meanA) * (x - meanA)) / (a.Length - 1);
        double varB = b.Sum(x => (x - meanB) * (x - meanB)) / (b.Length - 1);
        return (meanA - meanB) / Math.Sqrt(varA / a.Length + varB / b.Length);
    }
}
