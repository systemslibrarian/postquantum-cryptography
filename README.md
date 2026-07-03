# PostQuantum.Cryptography

[![NuGet](https://img.shields.io/nuget/v/PostQuantum.Cryptography?label=NuGet&color=blue)](https://www.nuget.org/packages/PostQuantum.Cryptography)
[![NuGet preview](https://img.shields.io/nuget/vpre/PostQuantum.Cryptography?label=preview&color=blueviolet)](https://www.nuget.org/packages/PostQuantum.Cryptography)
[![Downloads](https://img.shields.io/nuget/dt/PostQuantum.Cryptography?label=downloads&color=brightgreen)](https://www.nuget.org/packages/PostQuantum.Cryptography)
[![CI](https://github.com/systemslibrarian/postquantum-cryptography/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/systemslibrarian/postquantum-cryptography/actions/workflows/ci.yml)
[![CodeQL](https://github.com/systemslibrarian/postquantum-cryptography/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/systemslibrarian/postquantum-cryptography/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![.NET 10](https://img.shields.io/badge/.NET-10.0-512BD4)](https://dotnet.microsoft.com/)
[![AOT compatible](https://img.shields.io/badge/AOT-compatible-success)](src/PostQuantum.Cryptography.csproj)

**The clean, high-level, secure-by-default post-quantum cryptography library for .NET 10.**

`PostQuantum.Cryptography` is the foundation library of the `PostQuantum.*` ecosystem. It gives you NIST-standardized post-quantum primitives — ML-KEM (FIPS 203), ML-DSA (FIPS 204) — and the IETF X-Wing hybrid KEM, behind a small API designed so the secure path is the *only* path.

It does not reimplement lattice cryptography. ML-KEM and ML-DSA come straight from the .NET 10 runtime; this library is the surface on top: clean naming, fixed-size byte strings, disposable key types, span-based zero-allocation overloads, honest documentation, and runnable samples for the patterns you'll actually need.

> ℹ️ **Status:** `1.0.0` general availability — **not independently audited.** The `1.0` reflects API stability and engineering discipline, not third-party assurance. An external security audit is fully scoped and ready to commission ([`AUDIT-SCOPE.md`](AUDIT-SCOPE.md)) but is **currently unfunded — we cannot pay for it right now, and we will commission it if funding comes through** (sponsorship, grant, or a commercial consumer underwriting it). Audit findings will ship as `1.0.x` patches, or a new major version if anything structural surfaces. The public API surface is locked by `Microsoft.CodeAnalysis.PublicApiAnalyzers` and any unintentional break fails CI. See [`SECURITY.md`](SECURITY.md) for the assurance level, [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for what's deliberately not in scope, and the X-Wing IETF-draft-tracking caveat below.

---

## Why this library exists

Post-quantum cryptography is no longer a research topic. NIST has standardized ML-KEM (FIPS 203, August 2024) and ML-DSA (FIPS 204, August 2024); .NET 10 ships these natively in `System.Security.Cryptography`. But the native BCL types expose every knob and edge case — parameter sets, raw key formats, optional contexts, derandomized variants — which is exactly right for a foundation but a footgun for application code.

`PostQuantum.Cryptography` fills the gap between the BCL primitives and the way most application teams want to use them:

- **Fixed-size byte strings matching the standards**, not opaque key handles.
- **Disposable key types** that zero secrets on disposal.
- **Span-based zero-allocation overloads** on every hot path.
- **PEM importers that validate the label up-front** — passing a public-key PEM to a private-key importer fails fast with a clear `ArgumentException`, not a confusing `CryptographicException` from deep in the BCL.
- **FIPS 204 §5.2 context-length validation** up front, again with a clear error.
- **Spec-compliant X-Wing hybrid KEM** (ML-KEM-768 + X25519) for the recommended migration path.

If you're writing a TLS-style handshake, signing build artifacts, encrypting blobs at rest, or rotating long-lived signing keys, this library is meant to be the obvious choice for the post-quantum half.

---

## How it differs from raw BCL and BouncyCastle

| Concern | Raw .NET 10 BCL | BouncyCastle | **PostQuantum.Cryptography** |
| --- | --- | --- | --- |
| ML-KEM / ML-DSA implementation | Native, hardware-accelerated | Managed reference impl | **Delegates to the BCL** — same speed, same hardening |
| API shape | Low-level, every knob exposed | Java-style class hierarchies | **One small surface; secure-by-default** |
| Fixed-size byte strings | Sometimes; mixed conventions | Often abstracted away | **Always, matching the spec** |
| PEM label validation | None — wrong PEM throws late | Mixed | **Validated up front with clear `ArgumentException`** |
| `[Experimental]` annotations | Yes (PEM members, SLH-DSA) | N/A | **Suppressed only for stable IETF encodings; SLH-DSA deliberately not exposed yet** |
| X-Wing hybrid KEM | Not included | Not included | **Spec-compliant, KAT-validated against the IETF draft** |
| Zero-allocation hot paths | Partial | No | **Span overloads on every encap / decap / sign** |
| AOT + trim compatibility | Yes | Partial | **`IsAotCompatible=true`, `IsTrimmable=true`** |
| Thread-safety | Documented per type | Documented per type | **Documented; tests demonstrate safe parallel use across instances** |
| Disposal hygiene | Mixed | Mixed | **All key types `IDisposable` + zero on dispose; idempotent dispose** |
| Honest assurance level | n/a | n/a | **No claims we haven't validated; `SECURITY.md` + `KNOWN-GAPS.md` are authoritative** |

The short version: **if you wanted to write `using` blocks against the BCL anyway, this library is the missing 1,000 lines of safety and ergonomics.**

---

## Install

```bash
dotnet add package PostQuantum.Cryptography
```

Requires **.NET 10** or later. PQC availability also depends on the runtime build's underlying crypto provider — see the [platform support matrix](#platform--runtime-support-matrix) below.

---

## What's included

| Primitive | Standard | Purpose | Recommended default |
| --- | --- | --- | --- |
| **ML-KEM-512 / 768 / 1024** | FIPS 203 (NIST levels 1 / 3 / 5) | Key encapsulation | `MLKem768` |
| **ML-DSA-44 / 65 / 87** | FIPS 204 (NIST levels 2 / 3 / 5) | Digital signatures | `MLDsa87` |
| **X-Wing** | [`draft-connolly-cfrg-xwing-kem`](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) | Hybrid KEM: ML-KEM-768 ⊕ X25519 | use directly for hybrid PQ/T |

SLH-DSA (FIPS 205) is **deliberately not included yet** — the BCL `SlhDsa` type is still marked `[Experimental("SYSLIB5006")]` and we don't wrap unstable APIs. See [`KNOWN-GAPS.md`](KNOWN-GAPS.md).

---

## Two API styles — pick whichever fits

### A. **Typed API** *(recommended for long-lived keys)*

Disposable key objects, span-based hot paths, explicit ownership. Use when you'll do many operations against the same key.

```csharp
using PostQuantum.Cryptography;

// Recipient: generate once, publish the public part.
using MLKemPrivateKey recipient = MLKem768.GenerateKeyPair();
byte[] recipientPublicKey = recipient.ExportEncapsulationKey();

// Sender: import, encapsulate, transmit.
using MLKemPublicKey pub = MLKem768.ImportEncapsulationKey(recipientPublicKey);
KemEncapsulation handshake = pub.Encapsulate();

// Recipient: recover.
byte[] sharedSecret = recipient.Decapsulate(handshake.Ciphertext);
// handshake.SharedSecret.SequenceEqual(sharedSecret) == true
```

### B. **Byte-oriented one-shot API** *(recommended for fire-and-forget)*

No key objects, no `using`. Each call imports, operates, and disposes internally. Use when a key only needs to live for a single operation.

```csharp
using System.Security.Cryptography;
using PostQuantum.Cryptography;

// One-shot signing — no key objects to manage.
(byte[] publicKey, byte[] privateSeed) = MLDsaOperations.GenerateKeyPair(MLDsaAlgorithm.MLDsa87);

byte[] signature = MLDsaOperations.SignData(MLDsaAlgorithm.MLDsa87, privateSeed, message);
bool ok = MLDsaOperations.VerifyData(MLDsaAlgorithm.MLDsa87, publicKey, message, signature);
```

The two surfaces are **bit-identical** for the same inputs — `ConvenienceFacadeTests` proves it. Pick based on lifetime: typed for "I'll use this key all afternoon", one-shot for "I just need this once and I'm done."

---

## Quick-start by primitive

### ML-KEM-768 — key encapsulation

```csharp
using PostQuantum.Cryptography;

using MLKemPrivateKey recipient = MLKem768.GenerateKeyPair();
using MLKemPublicKey pub        = recipient.GetPublicKey();

KemEncapsulation enc      = pub.Encapsulate();
byte[] recoveredSecret    = recipient.Decapsulate(enc.Ciphertext);
```

For other parameter sets: `MLKem512` (NIST level 1), `MLKem1024` (NIST level 5). All three return the same algorithm-aware `MLKemPrivateKey` / `MLKemPublicKey` types.

### ML-DSA-87 — digital signatures

```csharp
using PostQuantum.Cryptography;

using MLDsaPrivateKey signer    = MLDsa87.GenerateKeyPair();
using MLDsaPublicKey  verifier  = signer.GetPublicKey();

byte[] signature = signer.SignData(message);
bool ok          = verifier.Verify(message, signature);
```

**Domain-binding (FIPS 204 §5.2):**

```csharp
byte[] context = "invoice-signing/v1"u8.ToArray();
byte[] sig = signer.SignData(message, context);
bool good = verifier.Verify(message, sig, context); // true only if context matches
```

Context is capped at 255 bytes per FIPS 204; the library validates this up-front and throws `ArgumentException` on overflow.

### X-Wing — hybrid PQ + classical KEM (recommended for migrations)

```csharp
using PostQuantum.Cryptography;

using XWingPrivateKey recipient = XWing.GenerateKeyPair();
byte[] recipientPublic          = recipient.ExportEncapsulationKey(); // 1216 bytes

using XWingPublicKey pub = XWing.ImportEncapsulationKey(recipientPublic);
KemEncapsulation handshake = pub.Encapsulate();
byte[] recoveredSecret = recipient.Decapsulate(handshake.Ciphertext);
```

X-Wing's shared secret stays secure as long as **either** ML-KEM-768 **or** X25519 is unbroken. This is the strongest practical default during the post-quantum transition.

> ⚠️ **X-Wing wire-format policy.** X-Wing is an IETF draft. The wire format has been stable across recent revisions, but if the final RFC changes it we **will rev the major version** of this package and document the migration — we will not silently change bytes you've already serialized. Pin a major version if interop with other implementations matters.

### Zero-allocation hot loops

```csharp
using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
using MLKemPublicKey  pub  = priv.GetPublicKey();

Span<byte> ciphertext   = stackalloc byte[MLKem768.CiphertextSizeInBytes];
Span<byte> sharedSecret = stackalloc byte[MLKem768.SharedSecretSizeInBytes];

for (int i = 0; i < N; i++)
{
    pub.Encapsulate(ciphertext, sharedSecret);   // 0 heap bytes per call
    // ...
}
```

Same pattern on `XWingPublicKey.Encapsulate`, `XWingPrivateKey.Decapsulate`, `MLKemPrivateKey.Decapsulate`, and `MLDsaPrivateKey.SignData`. Measured **0 B / op** vs ~1,224 B / op for the allocating equivalent — see [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md).

### Key persistence (PKCS#8 / SubjectPublicKeyInfo / PEM)

```csharp
using MLKemPrivateKey priv = MLKem768.GenerateKeyPair();
string privatePem = priv.ExportPkcs8PrivateKeyPem();
string publicPem  = priv.GetPublicKey().ExportSubjectPublicKeyInfoPem();

// PEM label is validated up front — passing publicPem to ImportPrivateKeyFromPem
// throws ArgumentException immediately, NOT a CryptographicException later.
using MLKemPrivateKey loaded = MLKemKey.ImportPrivateKeyFromPem(privatePem);
using MLKemPublicKey  pub    = MLKemKey.ImportPublicKeyFromPem(publicPem);
```

**Password-protected (encrypted PKCS#8):** one strong policy, no knobs — PBES2 with PBKDF2-HMAC-SHA256 (600,000 iterations) and AES-256-CBC. Empty passwords are refused.

```csharp
string encryptedPem = priv.ExportEncryptedPkcs8PrivateKeyPem(password);
using MLKemPrivateKey restored = MLKemKey.ImportEncryptedPrivateKeyFromPem(password, encryptedPem);
```

Same surface for ML-DSA via `MLDsaKey`.

---

## Security posture

**This library has not undergone an independent third-party security audit.** The `1.0.0` version signals a stable, locked API and a disciplined engineering process — not external assurance. An audit is fully scoped ([`AUDIT-SCOPE.md`](AUDIT-SCOPE.md)); the project cannot fund it right now, and commissioning it is the first priority if funding comes through. Until then: build with confidence for evaluation, prototyping, and helping your codebase move to post-quantum — but where these primitives are the sole protection of high-value secrets, do your own review of the small original-crypto surface (or help fund the audit; the maintainer welcomes coordination — see [`SECURITY.md`](SECURITY.md)).

What this library trusts:

1. **The .NET 10 BCL.** `MLKem` (FIPS 203), `MLDsa` (FIPS 204), and the SHA-3 / SHAKE primitives come straight from the runtime. We do not reimplement them.
2. **A bundled X25519 implementation.** The BCL doesn't expose X25519, which X-Wing requires. We include a constant-time port of TweetNaCl's `crypto_scalarmult` (public domain), validated against RFC 7748 known-answer tests. This is the only original cryptographic primitive in the library.

Design choices that reduce risk:

- **No insecure modes.** One strong parameter set per primitive; no weak knobs to set by accident.
- **CSPRNG-only key generation.**
- **Secret hygiene.** Private-key types implement `IDisposable` and zero key material and intermediate shared secrets on disposal (in `try/finally` so they're cleared even on exception paths).
- **Spec-faithful X-Wing.** Combiner, key expansion, and encoding follow `draft-connolly-cfrg-xwing-kem` exactly — KAT-validated against the IETF draft Appendix C.
- **Third-party vectors on every push.** The full Project Wycheproof x25519 adversarial set (518 vectors: twist points, low-order points, non-canonical encodings, arithmetic edge cases) and curated NIST ACVP known-answer sets for ML-KEM (keyGen, decapsulation incl. implicit rejection) and ML-DSA (keyGen, sigVer with tamper negatives) across all six parameter sets.
- **Measured constant-time evidence for X25519.** A dudect-style statistical timing test and a per-run capture of the JIT's emitted disassembly run in a dedicated CI lane — see [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) and `AUDIT-SCOPE.md` for exactly what this does and does not prove.
- **`KemEncapsulation` does not leak bytes** through `ToString()` (overridden), and its `Equals` is reference-based on the inner arrays to make accidental non–constant-time comparison harder.

Thread-safety: instances are **not** thread-safe (matching the BCL contract); use one per thread or per request. Static facades are safe. See [`SECURITY.md`](SECURITY.md) for the full contract, response-time targets, and private vulnerability reporting (`security@…` or GitHub Security Advisories).

---

## Performance characteristics

Measured on Windows 11 x64 (AVX2), .NET 10.0.8, single thread, in-process. Reproduce with `dotnet run --project benchmarks/PostQuantum.Cryptography.Benchmarks -- --filter "*" --job short`. See [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) for the full table and methodology.

| Primitive | Operation                | Mean      | Allocations |
|-----------|--------------------------|-----------|-------------|
| ML-KEM-768 | `GenerateKeyPair`       | 90 µs     | 104 B       |
| ML-KEM-768 | `Encapsulate` (alloc)   | 16 µs     | 1168 B      |
| ML-KEM-768 | `Encapsulate` (Span)    | 16 µs     | **0 B**     |
| ML-KEM-768 | `Decapsulate` (Span)    | 26 µs     | **0 B**     |
| ML-DSA-87 | `SignData` (Span)        | 629 µs    | **0 B**     |
| ML-DSA-87 | `Verify`                 | 94 µs     | 0 B         |
| X-Wing    | `Encapsulate` (Span)     | 3.0 ms    | **171 B**   |
| X-Wing    | `Decapsulate` (Span)     | 1.3 ms    | **57 B**    |

### Picking based on your workload

- **TLS-style handshakes** at maximum throughput → `MLKem768`, ~60,000 encaps/sec/core.
- **TLS-style handshakes with hybrid security** → `XWing`, budget ~340 encaps/sec/core, keep a per-thread pool.
- **Batch signing** → `MLDsa87`, ~1,600 signs/sec/core, parallelize across cores.
- **High-volume verification** → `MLDsa87`, ~10,600 verifies/sec/core. Cache public keys per identity.

---

## Platform / runtime support matrix

PQC availability depends on the **crypto provider the .NET 10 runtime was built against** — not the SDK alone. Gate calls on `MLKem768.IsSupported` / `MLDsa87.IsSupported` / `XWing.IsSupported`.

| OS                              | Provider                | ML-KEM / ML-DSA           | X-Wing                  | X25519 (RFC 7748)         |
| ------------------------------- | ----------------------- | ------------------------- | ----------------------- | ------------------------- |
| **Windows 11 / Server 2025+**   | CNG (PQC-enabled build) | Supported                 | Supported               | Supported (managed)       |
| **Linux**, OpenSSL 3.5+ wired   | OpenSSL                 | Supported                 | Supported               | Supported (managed)       |
| **Linux**, OpenSSL &lt; 3.5     | OpenSSL                 | `IsSupported == false`    | `IsSupported == false`  | Supported (managed)       |
| **macOS** (Apple Silicon/Intel) | runtime-dependent       | runtime-dependent         | runtime-dependent       | Supported (managed)       |

The bundled X25519 is pure managed code and runs unconditionally — that's why X-Wing key-generation KATs can be exercised in CI on hosts that don't have OpenSSL 3.5 yet.

---

## Learning the library

- **[`samples/`](samples/)** — ten runnable mini-apps: the basics (hybrid handshake, signed files, encrypt-to-public-key, zero-alloc hot loop, detached signature CLI, signed-package distribution) plus the production-adoption set (RSA/ECDSA migration via dual-signing, key rotation, large-file streaming, ASP.NET Core service integration).
- **[`docs/RECIPES.md`](docs/RECIPES.md)** — pattern cookbook, 11 "how do I do X?" answers cross-linked to samples.
- **[`docs/PERFORMANCE.md`](docs/PERFORMANCE.md)** — measured benchmarks and "picking based on your workload" guidance.
- **[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md)** — assets, trust boundaries, attacker capabilities, and honest residual risks.
- **[`docs/REPRODUCIBLE-BUILDS.md`](docs/REPRODUCIBLE-BUILDS.md)** — verify the published package matches this source: rebuild-and-compare recipe + `gh attestation verify`.

---

## Project layout

```
src/        PostQuantum.Cryptography              — the library
tests/      PostQuantum.Cryptography.Tests        — unit, KAT, property, smoke-fuzz tests
tests/      PostQuantum.Cryptography.SmokeTest    — consumes the packed .nupkg
samples/    01-10                                  — runnable demos
benchmarks/ PostQuantum.Cryptography.Benchmarks   — BenchmarkDotNet hot-path metrics
fuzz/       PostQuantum.Cryptography.Fuzz         — SharpFuzz coverage-guided fuzzer
tools/      ComputeFingerprints                    — regenerate deterministic KAT fingerprints
tools/      X25519JitDisasm                        — capture the JIT's emitted X25519 disassembly
docs/       RECIPES.md, PERFORMANCE.md, THREAT-MODEL.md, REPRODUCIBLE-BUILDS.md, README.md
```

---

## Building and testing

```bash
dotnet build PostQuantum.Cryptography.slnx -c Release
dotnet test  PostQuantum.Cryptography.slnx -c Release
```

The PQC tests are skipped cleanly on hosts where the runtime doesn't expose ML-KEM / ML-DSA; the pure-managed X25519 tests always run.

---

## About this library

`PostQuantum.Cryptography` is built and maintained by **Paul Clark** ([@systemslibrarian](https://github.com/systemslibrarian)) as part of the broader `PostQuantum.*` ecosystem of clean, secure-by-default .NET libraries.

**Transparency about AI assistance.** This library was built with substantial help from Anthropic's Claude (Opus 4.7). Claude accelerated the implementation, testing, documentation, and tooling work — it wrote most of the C#, the samples, the recipes, the CI pipelines, and these very docs, under direction and review. Cryptographic *correctness* of the wrapped BCL primitives belongs to .NET; the wrapper layer, the bundled X25519 port, the X-Wing composition, and every design choice were specified by a human and exercised against (a) the IETF draft KATs, (b) the RFC 7748 X25519 KATs, (c) byte-equality cross-checks against the BCL, (d) a coverage-guided fuzzer, and (e) an in-process smoke fuzzer that runs on every CI build. The library has not undergone an independent third-party audit (see [`SECURITY.md`](SECURITY.md)) — one is scoped and will be commissioned when funding allows, and doing your own review remains the right move for anyone shipping this in safety-critical or high-value-secret contexts.

If you find a bug, please file an issue. If you find a security issue, please [report it privately](SECURITY.md#reporting-a-vulnerability).

---

## License

[MIT](LICENSE) © 2026 Paul Clark.

Third-party notices: see [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md). The bundled X25519 is a port of TweetNaCl, dedicated to the public domain.

---

*To God be the glory.* — 1 Corinthians 10:31
