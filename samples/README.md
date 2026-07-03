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
dotnet run --project samples/06-SignedPackageDistribution
dotnet run --project samples/07-MigrateFromClassical
dotnet run --project samples/08-KeyRotation
dotnet run --project samples/09-LargeFileStreaming
dotnet run --project samples/10-AspNetCoreSigningService
```

On hosts where the runtime doesn't expose ML-KEM / ML-DSA, the samples print
a clear message and exit **non-zero** (they don't pretend to succeed — treat
that as "unsupported host", not a bug; see the platform matrix in the
top-level [`README.md`](../README.md)).

## What's in the box

| #  | Sample                                                              | What you'll learn                                                                                       |
| -- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 01 | [`01-XWingHandshake`](01-XWingHandshake/)                           | Hybrid post-quantum key exchange end-to-end: encapsulate → decapsulate → drive AES-GCM with the secret. |
| 02 | [`02-SignAndVerifyFiles`](02-SignAndVerifyFiles/)                   | Sign files with ML-DSA-87; persist & reload PEM keys; bind signatures to a domain via `context`.        |
| 03 | [`03-HybridFileEncryption`](03-HybridFileEncryption/)               | Realistic "encrypt to a public key" envelope: X-Wing KEM → HKDF-SHA-256 → AES-GCM with associated data. |
| 04 | [`04-ZeroAllocHotLoop`](04-ZeroAllocHotLoop/)                       | Compare the allocating overloads to the `Span<byte>` overloads with byte counts and GC counts.          |
| 05 | [`05-DetachedSignatureCli`](05-DetachedSignatureCli/)               | Build a small but realistic `pqcsign` CLI (`keygen` / `sign` / `verify`) with proper exit codes.        |
| 06 | [`06-SignedPackageDistribution`](06-SignedPackageDistribution/)     | Software-update / container-signing pattern: publisher signs an artifact + JSON manifest with a domain-bound context; consumer pins the public key and verifies (incl. tampering negative tests). |
| 07 | [`07-MigrateFromClassical`](07-MigrateFromClassical/)               | Migrate off ECDSA without a flag day: dual-signature envelope + the three-phase verifier rollout (observe → require both → PQ-only), with the full accept/reject matrix self-checked. |
| 08 | [`08-KeyRotation`](08-KeyRotation/)                                 | Versioned trust anchors: keyring rotation with an overlap window, honest retirement consequences, a compromise drill, and a key-substitution negative test. Encrypted PKCS#8 keys at rest. |
| 09 | [`09-LargeFileStreaming`](09-LargeFileStreaming/)                   | Files too big for memory: hash-then-sign with bounded buffers, chunked AES-GCM whose associated data pins chunk order and completeness — tamper/reorder/truncate all rejected. |
| 10 | [`10-AspNetCoreSigningService`](10-AspNetCoreSigningService/)       | Minimal-API signing service with the safe DI key lifetime (seed singleton, key scoped), self-tested with 48 concurrent requests. The wrong pattern is shown and explained. |

## Reading order

If you're new to the library, work through them in order. 01 → 02 gives you
the two core primitives (KEM, signatures) — 02 also shows password-protected
(encrypted PKCS#8) private keys at rest. 03 shows you how to combine the
KEM with symmetric crypto for real "encrypt this file" use cases. 04 covers
performance for high-throughput services. 05 ties it all together as a CLI
(including a `--password` flag for encrypted keys). 06 is the capstone of
the basics: publisher/consumer package signing with a pinned trust anchor
and a full set of tamper negative tests.

07–10 are the production-adoption set: 07 answers "how do I get off
RSA/ECDSA without breaking anyone" (dual-signing, three-phase rollout);
08 answers "what happens when I need to replace a key" (versioned keyring
rotation); 09 answers "what about files too big for memory" (hash-then-sign
+ chunked authenticated encryption); 10 answers "how do I use this in a web
service" (the safe DI key-lifetime pattern, proven under concurrency).

For broader pattern guidance — "how do I do X?" — see
[`docs/RECIPES.md`](../docs/RECIPES.md).
