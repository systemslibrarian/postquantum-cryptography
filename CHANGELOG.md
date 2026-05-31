# Changelog

All notable changes to **PostQuantum.Cryptography** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-preview.3] — 2026-05-31

### Added

- **Byte-oriented one-shot convenience layer** alongside the typed API —
  `MlKemOperations`, `MLDsaOperations`, `XWingHybridKem`, and a small
  `PqKeyPair<TPublic, TPrivate>` bundle struct. These complement the typed
  `MLKem768` / `MLDsa87` / `XWing` surface for fire-and-forget use cases
  where a key only needs to live for a single operation. Bit-identical
  results to the typed API for the same inputs (proven by
  `ConvenienceFacadeTests`).
- **Completely rewritten `README.md`** to a professional foundation-library
  standard: motivation, differentiation from raw BCL / BouncyCastle, two-API
  decision guide, quick-start per primitive, performance table, platform
  matrix, and an explicit "About this library" section with the
  human + AI transparency paragraph.

### Changed

- **NuGet metadata polished** — sharper Title and Description aimed at
  discoverability, expanded tag set, version bumped to `0.1.0-preview.3`
  to ship the new convenience layer.

## [0.1.0-preview.2] — 2026-05-31

### Added

- **Thread-safety contract documented** in `SECURITY.md` and on every public
  key type's `<remarks>` — instances are not thread-safe; static facades are.
  New `ThreadSafetyTests` exercises parallel use across distinct instances
  to lock in the safe pattern.
- **`[DebuggerDisplay]`** on every public key type, including
  `KemEncapsulation`. Watch windows now show `MLKemPrivateKey (ML-KEM-768, secret material redacted)`
  instead of dumping internal byte arrays into the IDE.
- **Disposal & cross-algorithm test sweep** (`DisposalAndCrossAlgorithmTests`):
  every disposable type tolerates double-Dispose; use-after-dispose throws
  `ObjectDisposedException` on every export/operation path; decapsulating a
  wrong-parameter-set ciphertext fails at the wrapper boundary with a clear
  `ArgumentException`, never inside the BCL.
- **In-process smoke fuzzer** (`SmokeFuzzTests`) — 5,000 pseudo-random
  inputs per target on every CI run. Asserts implicit-rejection determinism
  on KEM decap, false-on-garbage on signature verify, and documented
  exception types only on importer paths. Complements the AFL-driven harness
  in `fuzz/`.
- **`docs/PERFORMANCE.md`** — measured BenchmarkDotNet results for every
  primitive (ML-KEM, ML-DSA, X-Wing — allocating and Span overloads) with
  reproduction instructions and "picking based on workload" guidance.
- **Sample 06 — `06-SignedPackageDistribution`**: real-world container-/
  package-signing pattern. Publisher signs an artifact + JSON manifest with
  a domain-bound context; consumer pins the public key and verifies, with
  negative tests for tampered artifact, tampered signature, and wrong
  publisher key.
- **README badges**: NuGet version, preview version, downloads, CI status,
  CodeQL status, license, .NET 10, AOT compatibility.

## [0.1.0-preview.2] — 2026-05-31

### Added

- **Five runnable samples** under `samples/` covering the canonical patterns:
  hybrid X-Wing handshake (01), persistent-PEM ML-DSA file signing (02),
  hybrid file encryption with HKDF + AES-GCM (03), zero-alloc hot-loop
  measurement (04), and a small `pqcsign` CLI (05). Each is a standalone
  `dotnet` project referencing the library directly.
- **`docs/RECIPES.md`** — pattern cookbook with eleven recipes covering
  algorithm selection, KEM use, signatures with domain binding, key
  persistence, deterministic derivation, zero-alloc paths, constant-time
  comparison, and graceful detection of unsupported platforms. Cross-linked
  to the samples.
- **Public API frozen.** The `0.1.0-preview.1` surface moved from
  `PublicAPI.Unshipped.txt` into `PublicAPI.Shipped.txt`. Subsequent
  unintentional API changes now fail the build via `PublicApiAnalyzers`.
- **IntelliSense examples.** `<example>` XML doc blocks on the primary public
  entry-points (`MLKem768`, `MLKemPrivateKey`/`PublicKey`, `MLKemKey`,
  `MLDsa87`, `MLDsaPrivateKey`/`PublicKey`, `XWing`).
- **BenchmarkDotNet project** under `benchmarks/` with `MemoryDiagnoser`
  covering ML-KEM, ML-DSA, and X-Wing — including allocation checks on the
  Span overloads.
- **Coverage-guided fuzzing harness** under `fuzz/` using SharpFuzz, with
  multiple targets (decap, verify, importer entry points).
- **Packaged-consumption smoke test** under
  `tests/PostQuantum.Cryptography.SmokeTest/` that builds the `.nupkg` and
  exercises it from a clean project via a local NuGet feed.
- **Platform / runtime support matrix** in `README.md`.
- **Explicit X-Wing wire-format compatibility policy**: if the IETF spec
  changes the wire format before publication as an RFC, we will rev the
  package major version and document the migration.
- **`PackageIcon` wiring** with conditional pack — drop a 128×128 PNG at
  `assets/icon.png` and uncomment one line to ship it.

### Changed

- **`XWingPublicKey` now implements `IDisposable`** and caches the imported
  ML-KEM-768 handle internally, mirroring the §5.5.1 caching pattern the
  decapsulation side already uses. Repeated `Encapsulate()` calls against
  the same public key are noticeably cheaper. Wrap returned keys in
  `using`.
- **`KemEncapsulation.ToString()`** now returns only the type name — never
  the underlying bytes — so secrets cannot accidentally leak into logs or
  exception messages.
- **`KemEncapsulation` documentation** now spells out the equality semantics
  (reference-based on inner arrays — by design, to make non–constant-time
  comparison harder to take by accident) and the `default(KemEncapsulation)`
  null-array footgun.
- **`GetPublicKey()` doc** on every private-key type now states that the
  returned public-key object owns its own native handle and must be
  disposed.
- **Release workflow** requires package signing for non-preview tags (fails
  closed), generates a CycloneDX SBOM as a release asset, and runs the
  smoke test against the packed artifact before publishing.
- **`PackageReleaseNotes`** points to the corresponding section of the
  online `CHANGELOG.md`.
- **`SECURITY.md`** strengthened with explicit response-time targets, a
  GitHub Security Advisories pointer, and a forward-looking
  supported-versions table.

### Fixed

- **ML-DSA context length** is now validated against the FIPS 204 §5.2
  255-byte limit on every signing/verifying path. Oversized contexts surface
  as a clear `ArgumentException` with a precise message instead of an opaque
  `CryptographicException` bubbling up from the BCL.
- **IntelliSense examples.** `<example>` XML doc blocks on the primary public
  entry-points (`MLKem768`, `MLKemPrivateKey`/`PublicKey`, `MLKemKey`, `MLDsa87`,
  `MLDsaPrivateKey`/`PublicKey`, `XWing`) so users see usage in-IDE.
- **BenchmarkDotNet project** under `benchmarks/` with `MemoryDiagnoser`
  covering ML-KEM, ML-DSA, and X-Wing — including allocation checks on the Span
  overloads.
- **Coverage-guided fuzzing harness** under `fuzz/` using SharpFuzz, with
  multiple targets (decap, verify, importer entry points). See `fuzz/README.md`.
- **Packaged-consumption smoke test** under
  `tests/PostQuantum.Cryptography.SmokeTest/`. Builds the `.nupkg`, restores it
  into a clean project via a local NuGet feed, and exercises ML-KEM, ML-DSA,
  X-Wing, the Span overloads, and PEM label validation against the packaged
  artifact. Catches packaging mistakes that unit tests miss.
- **Platform / runtime support matrix** in `README.md`.
- **Explicit X-Wing wire-format compatibility policy**: if the IETF spec
  changes the wire format before publication as an RFC, we will rev the
  package major version and document the migration.
- **`PackageIcon` wiring** with conditional pack. Drop a 128×128 PNG at
  `assets/icon.png` and uncomment one line to ship it; no placeholder
  branding is checked in.

### Changed

- **Release workflow** now requires package signing for non-preview tags
  (fails closed), generates a CycloneDX SBOM as a release asset, and runs
  the smoke test against the packed artifact before publishing.
- **`PackageReleaseNotes`** points to the corresponding section of the
  online `CHANGELOG.md` for the package's version, so NuGet detail pages
  link to a real list of changes.
- **`SECURITY.md`** strengthened with explicit response-time targets, a
  GitHub Security Advisories pointer (preferred private reporting channel),
  and a forward-looking supported-versions table.

## [0.1.0-preview.1] — 2026-05-31

Initial preview.

### Added

- **ML-KEM** (FIPS 203): high-level facades for all three parameter sets —
  `MLKem512`, `MLKem768` (recommended default), `MLKem1024` — over the native
  .NET 10 BCL implementation. Algorithm-aware `MLKemPrivateKey` and
  `MLKemPublicKey` types with `Encapsulate` / `Decapsulate`.
- **ML-DSA** (FIPS 204): high-level facades for all three parameter sets —
  `MLDsa44`, `MLDsa65`, `MLDsa87` (recommended default). `SignData` / `Verify`
  with optional FIPS 204 §5.2 context binding.
- **X-Wing** hybrid KEM (`draft-connolly-cfrg-xwing-kem`): ML-KEM-768 ⊕ X25519,
  with the §5.5.1 cached expanded-decapsulation-key optimization. Bundled
  constant-time X25519 (TweetNaCl port, RFC 7748 validated).
- **Span-based zero-allocation overloads** on every hot path:
  - `MLKemPublicKey.Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)`
  - `MLKemPrivateKey.Decapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)`
  - `XWingPublicKey.Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)`
  - `XWingPrivateKey.Decapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)`
  - `MLDsaPrivateKey.SignData(ReadOnlySpan<byte>, Span<byte> destination[, context])`
- **PKCS#8 / SubjectPublicKeyInfo / PEM** import & export for ML-KEM and ML-DSA
  via `MLKemKey` and `MLDsaKey`. PEM importers validate the label up-front
  (`-----BEGIN PRIVATE KEY-----` vs `-----BEGIN PUBLIC KEY-----`) and throw a
  clear `ArgumentException` on a mismatch.
- **Secure-by-default behavior**: CSPRNG-only key generation; private-key types
  `IDisposable` with `CryptographicOperations.ZeroMemory` on disposal;
  intermediate shared secrets always zeroed (now via `try/finally`, so
  cleanup happens even if a downstream call throws).
- **AOT + trimming-ready**: `IsAotCompatible` and `IsTrimmable` set on the
  package; the entire library delegates to BCL APIs that are AOT-friendly.
- **API surface guarded** by `Microsoft.CodeAnalysis.PublicApiAnalyzers`
  (`PublicAPI.Shipped.txt` / `PublicAPI.Unshipped.txt`) so accidental binary
  breakage is caught at build time.
- **Deterministic, reproducible builds** with SourceLink to GitHub and symbol
  packages (`.snupkg`). CI verifies two consecutive builds produce
  byte-identical assemblies.
- **NuGet audit on every restore** (`NuGetAudit=true`, `NuGetAuditLevel=low`).
- **Tests**: round-trip, size, determinism, tamper detection, context binding,
  PEM/PKCS#8/SPKI interchange across all six parameter sets, RFC 7748 X25519
  KATs (single + 1000-iteration + DH commutativity property), KEM
  implicit-rejection robustness, and X-Wing key-generation and decapsulation
  KATs from the IETF draft.

### Known gaps

See [`KNOWN-GAPS.md`](KNOWN-GAPS.md) for the authoritative, current list.

[Unreleased]: https://github.com/systemslibrarian/postquantum-cryptography/compare/v0.1.0-preview.1...HEAD
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-cryptography/releases/tag/v0.1.0-preview.1

---

*To God be the glory.* — 1 Corinthians 10:31
