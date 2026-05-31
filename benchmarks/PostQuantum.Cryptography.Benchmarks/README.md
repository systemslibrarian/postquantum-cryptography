# PostQuantum.Cryptography Benchmarks

[BenchmarkDotNet](https://benchmarkdotnet.org/) micro-benchmarks for the
library's hot paths, with `MemoryDiagnoser` enabled so the Span overloads can
be verified to allocate zero bytes on the result path.

## Run

```bash
# All benchmarks
dotnet run -c Release --project benchmarks/PostQuantum.Cryptography.Benchmarks

# A single class
dotnet run -c Release --project benchmarks/PostQuantum.Cryptography.Benchmarks -- --filter "*MLKemBenchmarks*"

# Quick smoke run
dotnet run -c Release --project benchmarks/PostQuantum.Cryptography.Benchmarks -- --job short
```

## What's covered

- **ML-KEM-768**: keygen / encapsulate / decapsulate, allocating and Span overloads.
- **ML-DSA-87**: keygen / sign / verify, allocating and Span overloads.
- **X-Wing**: keygen / encapsulate / decapsulate, allocating and Span overloads.

## Use

Benchmarks are excluded from the main solution (`PostQuantum.Cryptography.slnx`)
so they don't slow down ordinary build/test cycles, and they don't ship in the
NuGet package. Run them on demand when you want to:

- Confirm the Span overloads remain zero-allocation.
- Spot a regression after a dependency bump or BCL update.
- Compare two branches before merging a performance-sensitive change.
