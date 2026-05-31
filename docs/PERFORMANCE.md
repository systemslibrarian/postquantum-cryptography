# Performance

Measured baselines for every primitive, with a reproducible methodology.
These numbers will move with hardware, runtime, and BCL improvements — treat
them as ballpark guidance, and re-run the benchmarks on your target hardware
before making throughput decisions.

## Methodology

- **Tool:** [BenchmarkDotNet](https://benchmarkdotnet.org/) 0.14.0, ShortRun
  job (3 iterations, 3 warmups). Reproduce with:
  ```bash
  dotnet run -c Release --project benchmarks/PostQuantum.Cryptography.Benchmarks -- --filter "*" --job short
  ```
- **Allocation accounting:** `MemoryDiagnoser` enabled, so `Allocated` is
  managed bytes per single operation (inclusive).
- **`Span` overloads** write into caller-provided buffers and skip the
  result-array allocation; for ML-KEM/ML-DSA these are genuinely
  **zero-allocation** on the result path. For X-Wing the bundled X25519
  implementation still allocates temporary `long[]` work arrays internally
  — see [Known gaps](#known-performance-gaps).

## Results

Captured on Windows 11 (x64, AVX2), .NET 10.0.8 SDK 10.0.300, single thread,
in-process. Your numbers will vary; the *ratios* between operations are the
useful part.

### ML-KEM-768

| Method                   | Mean      | Allocated |
|--------------------------|-----------|-----------|
| GenerateKeyPair          | 89.9 µs   | 104 B     |
| Encapsulate (allocating) | 16.5 µs   | 1168 B    |
| Encapsulate (Span)       | 16.1 µs   | **0 B**   |
| Decapsulate (allocating) | 26.2 µs   | 56 B      |
| Decapsulate (Span)       | 25.5 µs   | **0 B**   |

**Read this as:** ~60,000 encaps/sec or ~38,000 decaps/sec per core. The Span
overloads cost the same wall time but allocate zero result bytes — that's
the path to use in a request hot loop.

### ML-DSA-87

| Method            | Mean      | Allocated |
|-------------------|-----------|-----------|
| GenerateKeyPair   | 1.09 ms   | 105 B     |
| SignData (alloc)  | 638 µs    | 4656 B    |
| SignData (Span)   | 629 µs    | **0 B**   |
| Verify            | 94.2 µs   | 0 B       |

**Read this as:** ~1,600 signs/sec or ~10,600 verifies/sec per core. ML-DSA
signing is hedged-randomized in the BCL default — that's the reason a 4 KB
signature costs ~640 µs. Verify is much cheaper.

### X-Wing (hybrid: ML-KEM-768 + X25519)

| Method                   | Mean      | Allocated |
|--------------------------|-----------|-----------|
| GenerateKeyPair          | 1.14 ms   | 138 KB    |
| Encapsulate (allocating) | 2.17 ms   | 274 KB    |
| Encapsulate (Span)       | 2.28 ms   | 273 KB    |
| Decapsulate (allocating) | 1.68 ms   | 137 KB    |
| Decapsulate (Span)       | 1.56 ms   | 137 KB    |

**Read this as:** ~460 encaps/sec or ~640 decaps/sec per core. X-Wing is
heavier than pure ML-KEM because (a) it adds an X25519 scalar mult on each
side, and (b) the bundled X25519 currently allocates temporary work arrays
per call — see [Known gaps](#known-performance-gaps).

## Picking based on your workload

- **TLS-style handshake throughput.** Use **`MLKem768`** if you can: ~60,000
  encaps/sec per core. Use **`XWing`** when you need hybrid security; budget
  for an order of magnitude less throughput per core and consider keeping a
  per-thread pool of `XWingPrivateKey` instances rather than creating one
  per connection.
- **Batch signing.** `MLDsa87.SignData` at ~640 µs/op means ~1,600
  signatures/sec/core. Parallelize across cores with one signer instance per
  worker thread (instances are not thread-safe).
- **High-volume verification.** `Verify` is ~95 µs/op (>10,000/sec/core).
  Cache the `MLDsaPublicKey` for a given identity and reuse it.
- **Zero-allocation paths matter** when you're driving thousands of
  operations per second on a GC-sensitive workload. Use the `Span` overloads
  on the result side; the underlying compute time is unchanged but
  pause-time is much friendlier.

## Known performance gaps

- **X25519 allocates work arrays.** The bundled `Internal/X25519.cs`
  allocates roughly nine small `long[]` buffers per scalar-mult call. For
  X-Wing that means ~140 KB managed allocations per encap / decap. Moving
  these to `stackalloc` (the buffers are bounded — `long[80]` is 640 B) is
  a tracked optimization for a future release. See [`KNOWN-GAPS.md`](../KNOWN-GAPS.md).
- **No AVX-512 special-casing** in the bundled X25519. The BCL's ML-KEM /
  ML-DSA use hardware acceleration where available; X25519 is portable
  managed code.

---

*To God be the glory.* — 1 Corinthians 10:31
