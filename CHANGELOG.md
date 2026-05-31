# Changelog

All notable changes to **PostQuantum.Cryptography** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Public API frozen.** The `0.1.0-preview.1` surface has been moved from
  `PublicAPI.Unshipped.txt` to `PublicAPI.Shipped.txt`. Subsequent unintentional
  API changes now fail the build via `PublicApiAnalyzers`.
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
