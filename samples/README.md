# Samples

Runnable, focused mini-applications that show how to use
`PostQuantum.Cryptography` for real tasks — not just snippets.

Each sample is a standalone `dotnet` project under this directory. They all
reference the library by **`<ProjectReference>`** (not the NuGet package), so
edits to the library are picked up instantly while you're working through
them.

## Running

```bash
# From the repo root:
dotnet run --project samples/01-XWingHandshake
dotnet run --project samples/02-SignAndVerifyFiles
dotnet run --project samples/03-HybridFileEncryption
dotnet run --project samples/04-ZeroAllocHotLoop
dotnet run --project samples/05-DetachedSignatureCli -- help
```

The samples skip cleanly with a clear message on hosts where the runtime
doesn't expose ML-KEM / ML-DSA (see the platform matrix in the top-level
[`README.md`](../README.md)).

## What's in the box

| #  | Sample                                                              | What you'll learn                                                                                       |
| -- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 01 | [`01-XWingHandshake`](01-XWingHandshake/)                           | Hybrid post-quantum key exchange end-to-end: encapsulate → decapsulate → drive AES-GCM with the secret. |
| 02 | [`02-SignAndVerifyFiles`](02-SignAndVerifyFiles/)                   | Sign files with ML-DSA-87; persist & reload PEM keys; bind signatures to a domain via `context`.        |
| 03 | [`03-HybridFileEncryption`](03-HybridFileEncryption/)               | Realistic "encrypt to a public key" envelope: X-Wing KEM → HKDF-SHA-256 → AES-GCM with associated data. |
| 04 | [`04-ZeroAllocHotLoop`](04-ZeroAllocHotLoop/)                       | Compare the allocating overloads to the `Span<byte>` overloads with byte counts and GC counts.          |
| 05 | [`05-DetachedSignatureCli`](05-DetachedSignatureCli/)               | Build a small but realistic `pqcsign` CLI (`keygen` / `sign` / `verify`) with proper exit codes.        |

## Reading order

If you're new to the library, work through them in order. 01 → 02 gives you
the two core primitives (KEM, signatures). 03 shows you how to combine the
KEM with symmetric crypto for real "encrypt this file" use cases. 04 covers
performance for high-throughput services. 05 ties it all together as a CLI.

For broader pattern guidance — "how do I do X?" — see
[`docs/RECIPES.md`](../docs/RECIPES.md).
