# Changelog

All notable changes to **PostQuantum.Cryptography** are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.1] — 2026-08-20

Patch: dependency maintenance. No public API change and no behavioural change; a drop-in over 1.1.0.

### Changed

- Test and CI toolchain updated — the test-stack and microsoft-analyzers dependency groups,
  `BouncyCastle.Cryptography` 2.4.0 → 2.7.0 in the test project, and the GitHub Actions used by
  CI and release. None of these reach the published package: `PostQuantum.Cryptography` itself has
  no consumer-visible dependency change in this release.

## [1.1.0] — 2026-07-03

Feature and assurance release: encrypted PKCS#8, third-party vector
suites, measured constant-time evidence, four production-adoption
samples, supply-chain provenance, and NuGet Trusted Publishing support.
The eight encrypted-PKCS#8 members are the only public-API additions
(promoted from `PublicAPI.Unshipped.txt` to `Shipped.txt`); everything
else is additive tooling, tests, and documentation.

### Added (samples & release infrastructure)

- **Four production-adoption samples**, each self-checking (throws on
  any unexpected verdict, exits non-zero):
  - `07-MigrateFromClassical` — dual-signature (ECDSA P-256 + ML-DSA-87)
    envelope with the three-phase verifier rollout (observe → require
    both → PQ-only) and the full accept/reject matrix.
  - `08-KeyRotation` — versioned trust-anchor keyring: overlap window,
    retirement (with its honest consequence demonstrated), compromise
    drill, key-substitution negative. Encrypted PKCS#8 keys at rest.
  - `09-LargeFileStreaming` — 32 MB file with bounded memory:
    hash-then-sign (mid-file bit-flip negative) and chunked AES-GCM
    where the associated data pins chunk order and completeness
    (tamper / reorder / truncation all rejected).
  - `10-AspNetCoreSigningService` — minimal-API service with the safe
    DI key lifetime (seed singleton, key scoped), self-tested with 48
    concurrent requests; the unsafe singleton pattern documented.
- **NuGet Trusted Publishing support** in the release workflow: when no
  `NUGET_API_KEY` secret is configured, the `NuGet/login` action
  exchanges the workflow's OIDC identity for a short-lived API key.
  The legacy secret, if present, still takes precedence — delete it
  once the Trusted Publishing policy is configured on nuget.org.

### Changed (release mechanics)

- **Package version** `1.0.0` → `1.1.0` (new public API ⇒ minor bump).
  `FileVersion` `1.1.0.0`; `AssemblyVersion` stays `1.0.0.0`.
- **Encrypted PKCS#8 API promoted** to `PublicAPI.Shipped.txt`.
- `SmokeTestPackageVersion` default → `1.1.0`; NuGet `Description`
  refreshed (encrypted PKCS#8, ten samples); `SECURITY.md`
  supported-versions table updated (`1.1.x` current, `1.0.x` still
  receives fixes as the second-most-recent minor line).

### Added

- **Encrypted PKCS#8 (password-protected private keys)** for ML-KEM and
  ML-DSA: `ExportEncryptedPkcs8PrivateKey[Pem](password)` on the
  private-key types and `ImportEncryptedPkcs8PrivateKey` /
  `ImportEncryptedPrivateKeyFromPem` on `MLKemKey` / `MLDsaKey`.
  Secure-by-default: fixed PBE policy (PBES2, PBKDF2-HMAC-SHA256 at
  600,000 iterations, AES-256-CBC), empty passwords refused on export,
  PEM labels disambiguated up front (encrypted vs unencrypted vs
  public) with clear `ArgumentException`s in both mistaken directions.
  New public API recorded in `PublicAPI.Unshipped.txt`; the DER-level
  PBE algorithm identifiers are locked in by test.
- **Project Wycheproof x25519 sweep** (`WycheproofX25519Tests`): the
  full 518-vector adversarial set (twist points, low-order points,
  non-canonical u, arithmetic edge cases) asserted to exact expected
  shared secrets on every push. Vector file vendored with provenance
  under `tests/.../TestData/`.
- **NIST ACVP known-answer tests** (`AcvpMlKemKatTests`,
  `AcvpMlDsaKatTests`): curated subsets from `usnistgov/ACVP-Server`
  gen-val — ML-KEM keyGen (d‖z → ek/dk) and decapsulation VAL cases
  including implicit rejection; ML-DSA keyGen (seed → pk/sk) and
  sigVer (external/pure, with FIPS 204 contexts and tamper negatives) —
  across all six parameter sets. Provenance (upstream commit,
  retrieval date) recorded in each vector file.
- **Measured constant-time evidence for the bundled X25519**:
  a dudect-style fixed-vs-random Welch t-test on `ScalarMult`
  (`X25519TimingLeakTests`, gated `Category=LongRunning`) and a
  self-checking JIT-disassembly capture harness
  (`tools/X25519JitDisasm`), both run by the new
  `constant-time.yml` workflow lane (monthly + on any X25519 change,
  Linux + Windows) with the disassembly archived as an artifact.
  `AUDIT-SCOPE.md` §3, `KNOWN-GAPS.md`, and `SECURITY.md` updated from
  "by-construction, not by-measurement" to "by-construction plus
  first-party measurement, not independently verified".
- **`docs/THREAT-MODEL.md`** — assets, trust boundaries, attacker
  capabilities, STRIDE table, residual risks (claims verified against
  source, including the GC-relocation caveat on heap-held seeds).
- **`docs/REPRODUCIBLE-BUILDS.md`** — third-party verification recipe:
  rebuild at tag and compare the assembly inside the package (the
  nupkg envelope itself differs post-upload due to nuget.org's
  repository signature), plus `gh attestation verify`.
- **OpenSSF Scorecard workflow** (`scorecard.yml`) — weekly + on push
  to main, publishing to the code-scanning dashboard and the public
  Scorecard API.
- **SLSA build provenance attestation** in the release workflow
  (`actions/attest-build-provenance`) for the `.nupkg`/`.snupkg`,
  placed after the (optional) author-signing step so attested hashes
  match published bytes.
- **Tracking issues** #11–#16 for deferred items: BCL X25519
  replacement, X-Wing RFC watch, SLH-DSA, NuGet reserved prefix,
  continuous fuzzing (OSS-Fuzz does not accept .NET — verified
  2026-07-03), and the OpenSSF Best Practices self-certification.

### Fixed (post-1.0.0 review sweep)

A three-angle review (crypto core vs specs, wrapper/API safety, samples
audit) found **zero bugs in the cryptographic core** — X25519 verified
operation-by-operation against TweetNaCl/RFC 7748, X-Wing against the IETF
draft — and the following real issues elsewhere, all fixed:

- **`PqKeyPair<,>` XML docs described an API that does not exist.** The
  summary claimed facades return the type and both usage examples called
  `MLKem768.GenerateKeyPair_Pair()`, which was never shipped — copying the
  IntelliSense example produced CS0117. Docs rewritten to describe the type
  as the caller-side bundle it actually is, with a new `default`-instance
  footgun warning (matching `KemEncapsulation`'s standard).
- **`Algorithm` property getters now throw `ObjectDisposedException` on
  disposed keys** (all four key types). The BCL property tolerates a
  disposed handle, so these were the only members violating the documented
  "operations on a disposed key throw" contract.
- **`PemLabels` mixed-file error message** no longer gives wrong advice
  when a PEM contains an unencrypted block followed by an encrypted one.

### Hardened

- **X25519 no longer silently depends on `stackalloc` zero-initialization**:
  explicit `.Clear()` on the ladder temporaries and `Mul`'s accumulator
  (the spots where TweetNaCl zeroes explicitly), with a comment explaining
  why they are load-bearing. No behavior change — verified bit-identical
  against the RFC 7748 KATs, all 518 Wycheproof vectors, and the X-Wing
  draft KATs.

### Samples & recipes (developer-experience sweep)

- **Sample 01** now derives the AES key through HKDF in the copyable code
  (previously the raw KEM secret keyed AES-GCM with only a comment saying
  not to).
- **Sample 02** persists the private key as **encrypted PKCS#8** and
  reloads it with the password.
- **Sample 03**: HKDF output (`okm`) is now zeroed like every other secret;
  truncated envelopes fail with a clear `InvalidDataException` instead of a
  slice exception.
- **Sample 05 (CLI)** gains `--password` (encrypted-PKCS#8 keygen/sign),
  catches `DirectoryNotFoundException`/wrong-password cleanly (exit 2), and
  rejects a trailing flag with no value instead of silently dropping it.
- **Sample 06** now actually demonstrates all the negative cases its header
  promised (added tampered-manifest and empty-signature tests) and
  documents the manifest re-serialization caveat for production copies.
- **`docs/RECIPES.md`**: Recipe 7 covers encrypted PKCS#8 (and the X-Wing
  raw-seed exception); four new adoption recipes — dual-signing migration
  from RSA/ECDSA (12), ASP.NET Core / DI key-lifetime patterns (13),
  large-file hash-then-sign / chunked AEAD (14), key rotation with
  versioned trust anchors (15).
- **`samples/README.md`**: reading order now includes 06; corrected the
  "skip cleanly" claim (unsupported hosts exit non-zero with a message).

### Changed

- **CI and release test runs now exclude `Category=LongRunning`**
  (the 1M-iteration RFC 7748 chain and the dudect timing test), making
  the documented gating actually true — previously the 1M chain ran on
  every push. The `constant-time.yml` lane and manual runs cover the
  gated set.
- `PemLabels.RequirePrivateKeyLabel`'s encrypted-PEM error message now
  points at `ImportEncryptedPrivateKeyFromPem` instead of telling the
  caller to use the BCL directly.

## [1.0.0] — 2026-07-03

General availability. **Version, documentation, and release-policy changes
only** — no crypto logic and no public-API changes; the shipped assembly is
functionally identical to `1.0.0-rc.1`.

### Changed

- **Package version** bumped to `1.0.0` (from `1.0.0-rc.1`).
  `InformationalVersion` follows; `AssemblyVersion` / `FileVersion`
  remain `1.0.0.0`.
- **The external audit no longer gates general availability.** The
  independent third-party audit previously described as "pending" is
  not funded and has no schedulable date; holding `1.0.0` indefinitely
  behind it no longer served consumers. The release ships now with the
  caveat stated plainly everywhere it matters: **`1.0` means API
  stability, not third-party assurance.** The audit remains fully
  scoped in `AUDIT-SCOPE.md` and will be commissioned if funding comes
  through; findings will ship as `1.0.x` patches (or a major bump if
  anything structural surfaces). Updated accordingly: `README.md`
  (status callout, security posture, about section), `SECURITY.md`
  (assurance level, supported-versions table), `KNOWN-GAPS.md`, and
  `VERSION-RECONCILIATION.md` (addendum).
- **Release workflow author-signing policy relaxed.** Stable tags no
  longer fail closed when no code-signing certificate secret is
  configured; the signing step now warns loudly and continues.
  A certificate is a recurring cost under the same funding constraint
  as the audit. Packages still carry nuget.org's repository signature.
  Documented in `KNOWN-GAPS.md`; fail-closed will be restored once a
  certificate is configured.
- **`SmokeTestPackageVersion`** default aligned to `1.0.0`.
- **README install command** drops `--prerelease`.

## [1.0.0-rc.1] — 2026-06-01

First release candidate of the `1.0` line. **Version-only** bump as part
of the suite-wide version reconciliation — no crypto logic or public-API
changes in this commit. `1.0.0` general availability is **gated on a
pending independent third-party audit**; until that audit lands and is
addressed, this package ships only under the `-rc.N` suffix.

### Changed

- **Package version** bumped to `1.0.0-rc.1` (from `0.2.0-preview.1`).
  This package is the suite anchor — the version is moving up so that
  nothing in the `PostQuantum.*` suite advertises more maturity than it.
- **`AssemblyVersion` / `FileVersion`** bumped to `1.0.0.0`;
  `InformationalVersion` to `1.0.0-rc.1`.
- **README assurance language** updated from "preview" to
  "release candidate (`1.0.0-rc.1`) — not independently audited",
  making the rc maturity caveat and the audit-gated path to `1.0.0`
  visible in the README at HEAD (the dynamic NuGet badges only update
  post-publish). The X-Wing IETF-draft wire-format policy callout is
  unchanged.
- **`SmokeTestPackageVersion`** default in
  `tests/PostQuantum.Cryptography.SmokeTest` aligned to `1.0.0-rc.1` so
  the consumer smoke test exercises the version this repo now ships.
- **Public API entries promoted** from `PublicAPI.Unshipped.txt` to
  `PublicAPI.Shipped.txt` for the rc — pure text-file bookkeeping; no
  symbol additions, removals, or signature changes. The promoted set is
  the convenience layer (`MlKemOperations`, `MLDsaOperations`,
  `XWingHybridKem`, `PqKeyPair<TPublic, TPrivate>`) plus
  `XWingPublicKey.Dispose()`, `KemEncapsulation.ToString()` override,
  and the `PqKeyPair` constructors / operators / `Deconstruct` /
  `Equals` / `GetHashCode` already present in the codebase since
  `0.2.0-preview.1`.

### Added (audit remediation, not API change)

- **`X25519AdversarialKatTests`** — non-canonical u-coordinate handling
  (high bit set, values ≥ 2²⁵⁵−19), the 8 standard low-order points,
  and a `[Trait("Category","LongRunning")]`-gated 1,000,000-iteration
  RFC 7748 §5.2 chain. The 1M chain is excluded from the default test
  run; everything else runs on every push.
- **`X25519DifferentialTests`** — byte-for-byte cross-check of
  `ScalarMult` / `ScalarMultBase` against
  `Org.BouncyCastle.Math.EC.Rfc7748.X25519` over the RFC 7748 vectors
  and randomized inputs. BouncyCastle is a **test-only** package
  reference on `PostQuantum.Cryptography.Tests`; the library's own
  dependency graph is unchanged.
- **`XWingCombinerKatTests`** — fixed 134-byte input → exact
  SHA3-256(32) output for the internal `XWing.Combiner`, plus the
  `expandDecapsulationKey` SHAKE256(seed, 96) split into ML-KEM seed +
  X25519 scalar exercised standalone.
- **`AUDIT-SCOPE.md`** — concise external-reviewer brief covering the
  X-Wing combiner / key expansion / encoding vs
  `draft-connolly-cfrg-xwing-kem`, the bundled X25519 vs RFC 7748,
  JIT / tiered-compilation constant-time review, a KAT coverage
  matrix, and the deliberately-uncovered paths (non-canonical u,
  low-order points, microarchitectural side channels, derandomized
  X-Wing encapsulation).

### Documentation

- **`X25519` `<remarks>`** softened from a flat "constant-time" claim
  to "designed branch-free w.r.t. secret data; not validated under the
  .NET JIT / tiered compilation". The "raw RFC 7748 primitive — safe
  only inside X-Wing" contract is made explicit on the type.
- **`KNOWN-GAPS.md`** extended with two new bullets under
  "Cryptographic caveats": the JIT-not-validated constant-time caveat,
  and the "raw X25519 accepts non-canonical u and does not reject
  low-order points" contract.
- **`SECURITY.md`** mirrors the JIT constant-time caveat.

### Not changed

- No `<PackageReference>` to other `PostQuantum.*` packages exists in
  this repo (this is the foundation package; the suite depends on it,
  not the other way around), so no inter-package version constraints
  were re-pinned.
- **Crypto logic is untouched.** The X25519 field arithmetic
  (`Internal/X25519.cs`) and the X-Wing combiner (`XWing.cs`) are
  bit-for-bit identical to `0.2.0-preview.1`. The remediation work is
  evidence (new KATs / differential harness) and honest documentation,
  not code edits to the verified-correct primitives.
- `Microsoft.CodeAnalysis.PublicApiAnalyzers` remains wired in the
  `.csproj`.

## [0.2.0-preview.1] — 2026-05-31

The first preview of the `0.2.x` line. Consolidates the API and engineering
work that landed across `0.1.0-preview.{2,3}` plus one substantive
performance fix, and is the version intended for the first nuget.org
publication.

### Added

- **Byte-oriented one-shot convenience layer** alongside the typed API:
  `MlKemOperations`, `MLDsaOperations`, `XWingHybridKem`, and the small
  `PqKeyPair<TPublic, TPrivate>` bundle struct. For fire-and-forget use
  where a key only needs to live for a single operation. Bit-identical
  results to the typed API for the same inputs (proven by
  `ConvenienceFacadeTests`).
- **Resource-discipline test** (`ResourceDisciplineTests`) — 5,000
  import/dispose cycles of `XWingPrivateKey` with handle-count and
  working-set assertions, locking in the new exception-safe `FromSeed`.
- **Six runnable samples** under `samples/` covering hybrid handshake,
  signed files, hybrid file encryption, zero-allocation hot loops, a small
  `pqcsign` CLI, and signed-package distribution.
- **`docs/RECIPES.md`** — 11-recipe pattern cookbook cross-linked to the
  samples.
- **`docs/PERFORMANCE.md`** — measured benchmark numbers with
  reproduction instructions.

### Changed

- **`XWingPublicKey` is now `IDisposable`** and caches an expanded
  ML-KEM-768 handle internally (mirrors the §5.5.1 caching the
  decapsulation side already uses).
- **X25519 work arrays moved to `stackalloc`**: X-Wing per-call heap
  pressure drops by >1500× on the Span overloads (273 KB → 171 B per
  encap; 137 KB → 57 B per decap). Wall-clock time unchanged. The bundled
  X25519 retains its constant-time core ladder.
- **`XWingPrivateKey.FromSeed` is now exception-safe**: the freshly
  imported ML-KEM handle and the X25519 scalar are zeroed/disposed if
  construction throws partway.
- **ML-DSA context length validation**: FIPS 204 §5.2 caps at 255 bytes;
  the wrapper now validates up-front with a clear `ArgumentException`
  instead of a generic `CryptographicException` from the BCL.
- **PEM importers validate the label up-front** (`PRIVATE KEY` vs
  `PUBLIC KEY`); passing the wrong kind throws `ArgumentException`
  immediately, not a delayed `CryptographicException`.
- **`KemEncapsulation.ToString()`** returns only the type name — never
  the bytes — so secrets can't leak via logs or exception messages.
- **`[DebuggerDisplay]`** on every public key type so watch windows show
  algorithm + state without dumping internal byte arrays.
- **Thread-safety contract documented** in `SECURITY.md` and on every
  key type's `<remarks>` (instances NOT thread-safe; static facades are).
  `ThreadSafetyTests` proves the safe pattern.
- **NuGet metadata polished**: sharper Title and Description, expanded
  tag set, `PackageReleaseNotes` URL pointing at the changelog,
  `PackageIcon` wiring conditional on `assets/icon.png`.
- **Release workflow** requires package signing for stable tags (fails
  closed), generates and attaches a CycloneDX SBOM to the GitHub Release,
  and runs the consumer smoke test against the packed `.nupkg` before
  publishing.
- **Public API locked**: the surface lives in `PublicAPI.Shipped.txt`,
  guarded by `Microsoft.CodeAnalysis.PublicApiAnalyzers`.
- **Completely rewritten README** to a professional foundation-library
  standard: motivation, differentiation table vs raw BCL / BouncyCastle,
  two-API decision guide, quick-start per primitive, security posture,
  measured performance, platform support matrix, and an explicit
  "About this library" section with the human + AI transparency
  paragraph.

### Fixed

- README documentation type-name bugs (`MLKem768PrivateKey` →
  `MLKemPrivateKey`, etc.).
- X-Wing `Encapsulate` / `Decapsulate` now zero intermediate secrets in
  `try/finally` so the cleanup runs even on exception paths.
- All `ArgumentException` messages now consistently include both expected
  and actual lengths plus the algorithm name where relevant.

### Test coverage

140+ unit tests covering: round-trips and KATs across every parameter
set; deterministic seed→public-key fingerprints; byte-equality
cross-checks vs direct BCL; PEM label disambiguation; ML-DSA context
limit; Span-overload zero-allocation; disposal idempotency and
use-after-dispose; cross-algorithm misuse; thread-safety; resource
discipline; an in-process smoke fuzzer (5,000 random inputs per target)
that runs on every CI build; X-Wing IETF draft Appendix C KATs;
RFC 7748 X25519 KATs (single + 1000-iteration + DH commutativity).

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

[Unreleased]: https://github.com/systemslibrarian/postquantum-cryptography/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/systemslibrarian/postquantum-cryptography/releases/tag/v1.1.0
[1.0.0]: https://github.com/systemslibrarian/postquantum-cryptography/releases/tag/v1.0.0
[1.0.0-rc.1]: https://github.com/systemslibrarian/postquantum-cryptography/releases/tag/v1.0.0-rc.1
[0.1.0-preview.1]: https://github.com/systemslibrarian/postquantum-cryptography/releases/tag/v0.1.0-preview.1

---

*To God be the glory.* — 1 Corinthians 10:31
