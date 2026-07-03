# Threat model — PostQuantum.Cryptography

A concise STRIDE-lite threat model for the `1.0.x` line. It states what the
library defends, against whom, and — just as importantly — what it does not.
Nothing here claims more assurance than we have: the library has **not** been
independently audited (see [`SECURITY.md`](../SECURITY.md) and
[`AUDIT-SCOPE.md`](../AUDIT-SCOPE.md)), and the residual risks below are real.

## Scope and assets

**Assets the library protects:**

- **Private key material in memory** — ML-KEM decapsulation keys, ML-DSA
  signing keys, the X-Wing 32-byte seed and its expanded X25519 scalar.
- **Shared secrets** produced by encapsulation/decapsulation, including the
  intermediate `ss_M` / `ss_X` values inside the X-Wing combiner.
- **Signature integrity** — a verified ML-DSA signature (optionally
  context-bound per FIPS 204 §5.2) means the message was signed by the holder
  of the private key, within the strength of ML-DSA itself.

**Explicitly out of scope:**

- **Key storage at rest.** The library exports raw bytes, PKCS#8, and PEM,
  plus password-protected encrypted PKCS#8 for ML-KEM/ML-DSA (fixed strong
  PBE policy). Where and how exported keys are stored — and password quality
  for the encrypted form — is the caller's job.
- **Transport.** Ciphertexts and public keys are handed to the caller as
  bytes; how they travel is not this library's concern.
- **Protocol design.** This is a primitives library. Replay protection, key
  rotation, identity binding, and session semantics belong to the protocol
  built on top.
- **A compromised host.** No defense is claimed against an attacker with
  arbitrary code execution, debugger access, or kernel/hypervisor privileges
  in the same process or machine.

## Trust boundaries

1. **The .NET 10 BCL primitives** (`MLKem`, `MLDsa`, `SHA3_256`, `Shake256`,
   `RandomNumberGenerator`). Trusted; their correctness and side-channel
   posture are the platform's responsibility and out of scope here and in
   `AUDIT-SCOPE.md`.
2. **The bundled X25519** (`src/PostQuantum.Cryptography/Internal/X25519.cs`),
   a port of the public-domain TweetNaCl `crypto_scalarmult`. The only
   original cryptographic code in the library and the highest-scrutiny
   component. `internal`; reachable by consumers only through X-Wing.
3. **The wrapper layer** — facades, key types, importers, the X-Wing
   combiner/expansion. Original non-crypto code: validation, disposal,
   zeroization, encoding.
4. **Caller code.** Trusted with the secrets it is handed (exported seeds,
   `KemEncapsulation.SharedSecret`), but assumed capable of mistakes — the
   API is shaped to make misuse hard, not impossible.
5. **The build/release pipeline.** Deterministic builds (byte-determinism
   verified in CI), SourceLink, CycloneDX SBOM attached to releases, SLSA
   build-provenance attestation (`gh attestation verify … --repo
   systemslibrarian/postquantum-cryptography`), and nuget.org's repository
   signature. Packages are **not author-signed** — a funding-constrained,
   loudly-warned gap documented in `KNOWN-GAPS.md`.

## Attacker capabilities considered

- **Adjacent-process / microarchitectural timing observer.** Can measure
  operation timing, cache, or branch-predictor state from co-located code.
  The bundled X25519 is designed branch-free with respect to secret data
  (bitmask `Sel25519`, no scalar-dependent control flow). First-party
  measured evidence exists — a dudect-style wall-clock timing test and a
  capture of the JIT's emitted disassembly, run by the `constant-time.yml`
  lane — but the finer microarchitectural channels (cache, branch-predictor,
  port-contention, prefetch, speculative execution) remain unmeasured and
  independently unverified. Acknowledged residual risk; first-order item in
  `AUDIT-SCOPE.md`.
- **Malicious-input attacker.** Supplies garbage or adversarial bytes to
  importers, PEM parsers, decapsulation, and verification. Mitigated by
  up-front length validation, PEM label validation, and FIPS 204 context
  limits; exercised by an in-process smoke fuzzer on every CI build (5,000
  pseudo-random inputs per target) and an out-of-band coverage-guided AFL
  harness (`fuzz/`).
- **API-misuse (accidental).** Mitigated by design: one strong parameter set
  per primitive, no insecure modes, CSPRNG-only key generation, disposable
  key types, `ObjectDisposedException` on use-after-dispose, and
  `KemEncapsulation.ToString()` that never prints bytes.
- **Memory-disclosure-after-free.** Reads process memory after a key is
  logically released (heap dumps, crash dumps, memory-scraping). Mitigated by
  best-effort zeroization on dispose and `try/finally` clearing of
  intermediates — with the honest caveats in the residual-risks section.
- **Supply-chain attacker.** Tampers with the package between build and
  consumer. Partially mitigated (see boundary 5); author signing is the known
  missing layer.

## STRIDE-lite by boundary

### Boundary 1 — BCL primitives

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Tampering / info-disclosure inside `MLKem` / `MLDsa` / SHA-3 | None from this library; trusted. Wrapper output is byte-equality cross-checked against direct BCL invocation in tests. | Fully inherited from the platform. Out of scope (`AUDIT-SCOPE.md`). |
| DoS: PQC provider absent at runtime | `IsSupported` gates; documented platform matrix; tests skip cleanly. | Callers who skip the `IsSupported` check get `PlatformNotSupportedException`. |

### Boundary 2 — bundled X25519

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Info-disclosure via timing/microarchitectural side channels | Branch-free ladder and `Sel25519` by construction; all working arrays `stackalloc`'d and cleared in `finally`; scalar `z` zeroed; dudect-style timing test + JIT disassembly capture in the `constant-time.yml` lane. | Wall-clock timing measured on two runner types only; cache, branch-predictor, port-contention, prefetch, and speculative-execution channels unmeasured and independently unaudited. |
| Tampering: incorrect arithmetic (carry-chain bugs) | RFC 7748 KATs (single, 1k, gated 1M iterations), low-order and non-canonical-u adversarial vectors, differential testing vs BouncyCastle. | Differential coverage is against one reference; no formal verification. |
| Spoofing: low-order / all-zero shared-secret outputs | Deliberately **not rejected** by the raw primitive — safe *only inside X-Wing*, whose combiner binds `ct_X` and `pk_X`. Type is `internal`. | If ever lifted out as general-purpose DH, this becomes a real vulnerability. Documented in `KNOWN-GAPS.md`. |

### Boundary 3 — wrapper layer

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Tampering: malformed keys / ciphertexts / PEM | Length validation with `ArgumentException` on every import/decap/sign path; PEM label checked up-front; fuzzed in CI. | Fuzzing is smoke-depth per build; deep campaigns are out-of-band. |
| Info-disclosure: secrets outliving use | X-Wing intermediates (`ss_M` stackalloc'd, `ss_X`, `ekX`, combiner buffer) zeroed in `try/finally`; `XWingPrivateKey.Dispose` zeroes `_seed` and `_skX` and disposes the ML-KEM handle; `FromSeed` zeroes partial state on exception; ML-KEM/ML-DSA key types hold **no** managed secret copies — only the BCL handle, disposed on `Dispose`. | Managed `byte[]` secrets are **not pinned**: a compacting GC may relocate arrays before zeroization, leaving stale copies zeroization never reaches. Zeroization is best-effort, not a guarantee. |
| Info-disclosure: secrets in logs/debuggers | `ToString()` overridden on `KemEncapsulation`; `DebuggerDisplay` redacts secret material. | Callers can still log the byte arrays they own. |
| Info-disclosure: non-constant-time comparison of secrets | `KemEncapsulation` equality is reference-based by design; docs point to `FixedTimeEquals`. | Callers using `SequenceEqual` on secrets defeat this. |
| Repudiation / signature confusion across contexts | FIPS 204 §5.2 context parameter, validated ≤ 255 bytes. | Context use is opt-in; the library cannot force domain separation. |
| Elevation: use-after-dispose, cross-algorithm misuse | `ObjectDisposedException`; idempotent dispose; cross-parameter-set misuse tested. | Concurrent use of one instance from multiple threads is undefended by design (documented in `SECURITY.md`). |

### Boundary 4 — caller code

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Info-disclosure: caller mishandles returned secrets | Docs instruct zeroing `SharedSecret`; span overloads let callers keep secrets in stack buffers they control. | Returned `byte[]` secrets (one-shot APIs, `Decapsulate()`, exported seeds) are caller-owned heap memory. **Not mitigated** beyond documentation. |
| Tampering: caller persists keys unprotected | Encrypted PKCS#8 export with a fixed strong PBE policy (empty passwords refused). | Password strength and storage location are the caller's; X-Wing keys have no encrypted encoding (raw seed only, `KNOWN-GAPS.md`). |
| Spoofing: caller trusts an unverified public key | Out of scope — key authenticity/PKI is protocol-layer. | Not mitigated; by design. |

### Boundary 5 — build/release pipeline

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| Tampering: package modified after build | Deterministic build verified in CI; SLSA provenance attestation binds artifact hashes to the workflow; nuget.org repository signature; SBOM per release; SourceLink for source verification. | **No author signature** — consumers cannot verify the *maintainer* signed the bytes, only that nuget.org and GitHub did. Funding-constrained; warned on every release (`KNOWN-GAPS.md`). |
| Tampering: compromised dependency | The shipped library has no third-party runtime dependencies (BCL only); CI audits transitive packages for known CVEs. | Build-time tooling and GitHub Actions themselves are trusted. |
| Spoofing: maintainer account / CI compromise | GitHub-side protections; provenance ties releases to this repo's workflow. | A fully compromised repo or maintainer account defeats all of the above. Not mitigated. |

## Residual risks and assumptions (summary)

1. **X25519 side channels beyond wall-clock timing are unmeasured.**
   Constant-time is by-construction plus first-party measurement (dudect-style
   timing, JIT disassembly review artifacts); cache/branch-predictor/
   port-contention/speculative channels remain the first-order open item — see
   `KNOWN-GAPS.md` and `AUDIT-SCOPE.md` §3.
2. **Zeroization of managed arrays is best-effort.** `XWingPrivateKey`'s seed
   and scalar, and every secret returned to the caller as `byte[]`, live in
   unpinned GC heap memory; compaction may leave copies that zeroization
   never reaches, and copies survive until overwritten. Stack-allocated
   intermediates (X25519 work arrays, `ss_M`, the combiner buffer) narrow but
   do not eliminate this.
3. **No independent audit.** Scoped and ready (`AUDIT-SCOPE.md`), currently
   unfunded. `1.0.0` signals API stability, not third-party assurance.
4. **No author signing** of NuGet packages; repository signature and
   provenance attestation only (`KNOWN-GAPS.md`).
5. **Compromised host is out of scope.** Same-process attackers, debuggers,
   and privileged malware win; the library does not claim otherwise.
6. **BCL trust is assumed.** ML-KEM/ML-DSA/SHA-3 correctness and side-channel
   posture are inherited from .NET 10.
7. **X-Wing tracks an IETF draft.** A wire-format change before RFC
   publication would rev the major version (`README.md` policy).

Assumptions: the platform CSPRNG is sound; the .NET runtime is genuine and
un-tampered; callers dispose key objects and treat exported secrets as
secrets.

---

*To God be the glory.* — 1 Corinthians 10:31
