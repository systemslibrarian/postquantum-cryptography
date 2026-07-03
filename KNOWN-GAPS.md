# Known Gaps

This document is an honest, running inventory of what `PostQuantum.Cryptography` does **not** do yet, or does with caveats. It is part of the project's commitment to transparency: nothing here is hidden in the hope you won't notice.

If something important is missing from this list, that itself is a gap — please open an issue.

## Scope and algorithms

- **ML-KEM:** all three FIPS 203 parameter sets are exposed — `MLKem512`, `MLKem768` (recommended default), `MLKem1024`.
- **ML-DSA:** all three FIPS 204 parameter sets are exposed — `MLDsa44`, `MLDsa65`, `MLDsa87` (recommended default).
- **SLH-DSA (FIPS 205) is deliberately deferred.** The .NET 10 BCL type `System.Security.Cryptography.SlhDsa` is annotated `[Experimental("SYSLIB5006")]` — "for evaluation purposes only and is subject to change or removal." Exposing an experimental, unstable primitive would contradict this library's secure-by-default, no-surprises discipline, so SLH-DSA is intentionally **not** wrapped until it ships as a stable API.
- **No streaming / pre-hash / external-mu signing.** `MLDsa.SignPreHash`, `SignMu`, and external-mu flows are not surfaced. Only `SignData` / `Verify` (with optional FIPS 204 §5.2 context) are exposed. A `SignData(Stream)` overload is deliberately not provided, because the .NET 10 BCL has no native streaming variant for ML-DSA and a wrapper that silently buffered an arbitrarily-large stream into memory would be deceptive — callers can `ReadAllBytes` themselves and own the memory decision.
- **No X.509 / certificate integration** (no `CertificateRequest` helpers, etc.).

## Key formats

- **Raw, PKCS#8, and SubjectPublicKeyInfo (DER + PEM) are supported** for ML-KEM and ML-DSA keys: raw fixed-size byte strings (seeds, encapsulation/decapsulation keys, public/secret keys), plus `ExportPkcs8PrivateKey[Pem]`, `ExportSubjectPublicKeyInfo[Pem]`, and the matching `MLKemKey` / `MLDsaKey` importers.
- **Encrypted PKCS#8** (password-protected private keys) is not yet wrapped, though the BCL supports it.
- **X-Wing has no standardized PKCS#8/PEM encoding here.** X-Wing keys are exchanged as their raw fixed-size byte strings (32-byte seed / 1216-byte encapsulation key) only.

## X-Wing specifics

- **Core KEM with the §5.5.1 caching optimization.** `GenerateKeyPair`, `Encapsulate`, `Decapsulate`, and import/export are provided. The "expanded decapsulation key" is cached: the 32-byte seed is expanded once (on generate/import) and reused across every `Decapsulate`. The packed (transmittable) form is the seed; the expanded form is never exported, per the spec's binding requirements.
- **Derandomized encapsulation is not public.** `EncapsulateDerand` is a testing aid in the spec and is not part of the API. The bundled known-answer tests therefore cover **key generation** (seed → encapsulation key) and **decapsulation** (seed + ciphertext → shared secret) against the specification vectors, but not derandomized encapsulation.
- **Draft, not final.** X-Wing is an IETF draft. The wire format is stable across recent revisions, but until it is published as an RFC, treat interoperability with other implementations as "verify before you rely." If the spec changes the wire format before publication as an RFC, this library will rev the **major version** and document the migration; we will not silently change bytes you've already serialized (see the wire-format policy in `README.md`).

## Cryptographic caveats

- **X25519 is bundled, not from the BCL.** .NET 10 does not expose X25519, so this library includes a port of TweetNaCl's `crypto_scalarmult` (public domain), validated against RFC 7748 test vectors (single, 1-iteration, 1000-iteration, and — gated as a long-running test — 1,000,000-iteration), and byte-for-byte cross-checked against `Org.BouncyCastle.Math.EC.Rfc7748.X25519` over the same vectors and randomized inputs. It is the only original cryptographic primitive here.
- **X25519 constant-time posture is by-construction, not by-measurement.** The Montgomery ladder and `Sel25519` are designed branch-free with respect to secret data (bitmask selection, no scalar-dependent control flow). This guarantee has **not** been validated under the .NET JIT, tiered compilation, or speculative execution, and has **not** been independently audited for microarchitectural side channels (cache, branch-predictor, port-contention, prefetch). Listed as first-order in [`AUDIT-SCOPE.md`](AUDIT-SCOPE.md).
- **Raw X25519 contract — safe only inside X-Wing.** The bundled `X25519.ScalarMult` / `ScalarMultBase` are the raw RFC 7748 primitive: they do **not** reject low-order or all-zero outputs, and they accept non-canonical u-coordinates (the high bit of `u` is masked per the RFC). That is correct *inside X-Wing*, whose combiner cryptographically binds `ct_X` and `pk_X` into the derived secret, so an adversarially-chosen `pk_X` cannot collapse the shared secret across multiple sessions. Outside X-Wing those properties would be footguns. The type is `internal` and exposed to tests only — consumers cannot reach it directly. Do not lift it out into a general-purpose Diffie-Hellman without adding the missing checks.
- **No independent security audit.** Nothing in this library has been formally audited. An external audit is fully scoped and ready to commission ([`AUDIT-SCOPE.md`](AUDIT-SCOPE.md)) but is **currently unfunded** — the project cannot pay for it right now and will commission it if funding comes through. `1.0.0` shipped without it; the version signals API stability, not third-party assurance.
- **No FIPS 140-3 validation** is claimed for this wrapper. The underlying BCL algorithms' validation status is the platform's matter.
- **Side channels of the BCL primitives** are out of this library's control and inherited from .NET.

## Platform / runtime availability

- **ML-KEM and ML-DSA require a PQC-capable platform crypto provider at runtime.** On .NET 10 these are surfaced from the BCL, but the underlying provider must support them — on Linux that means OpenSSL 3.5+ wired into the runtime build. Where it is not available, `MLKem.IsSupported` / `MLDsa.IsSupported` return `false` and the APIs throw `PlatformNotSupportedException`. Always check `MLKem768.IsSupported` / `MLDsa87.IsSupported` / `XWing.IsSupported` before use.
- This was observed in development: some .NET 10.0.x runtime builds report `IsSupported == false` even with OpenSSL 3.5 installed, because the runtime was not built against a PQC-enabled provider. The library is correct in that case (it faithfully delegates and the BCL throws); the limitation is environmental. The test suite **skips** (does not fail) the ML-KEM/ML-DSA/X-Wing tests on such hosts, while the pure-managed X25519 tests always run.

## Testing

- Tests cover round-trips, key/secret sizes, determinism, tamper detection, context binding (including FIPS 204 §5.2 255-byte limit), PEM/PKCS#8/SPKI interchange (including label-mismatch rejection), all ML-KEM and ML-DSA parameter sets, the RFC 7748 X25519 KATs (single + iterated) and DH commutativity property, KEM implicit-rejection robustness, the Span-based zero-allocation overloads, byte-oriented one-shot convenience facades (cross-checked against the typed API for bit-identical output), regression-style SHA-256 fingerprints of the deterministic `seed → public-key` mapping for every primitive, byte-equality cross-checks between the wrapper and direct BCL invocation, disposal idempotency and use-after-dispose for every key type, cross-algorithm misuse (decapsulating with a wrong-parameter-set key), thread-safety (parallel use across distinct instances), resource-discipline smoke (5000 import/dispose cycles), and X-Wing key-generation and decapsulation KATs from the IETF draft (Appendix C).
- ML-KEM / ML-DSA / X-Wing tests are gated on platform support (see above) and skip cleanly where the runtime does not expose the primitives. The X25519 tests are unconditional.
- An **in-process smoke fuzzer** runs on every CI build (5,000 pseudo-random inputs per target, asserting only documented exception types escape and that KEM decapsulation of garbage is deterministic per-key). A **coverage-guided AFL harness** lives in [`fuzz/`](fuzz/) for out-of-band runs.
- The deterministic-fingerprint KATs anchor wrapper integrity against the BCL's own implementation; they are **not** a substitute for a full NIST ACVP / Wycheproof interop battery.
- Performance baselines are published in [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) along with a reproducible benchmark project (`benchmarks/PostQuantum.Cryptography.Benchmarks`). The bundled X25519's working arrays are stack-allocated, so X-Wing's per-call heap pressure is small (≤200 B on the Span overloads).

## Operational

- **CI** (GitHub Actions) builds + tests on Ubuntu, Windows, and macOS; runs CodeQL on every push and weekly; audits transitive packages for known CVEs; verifies the build is byte-deterministic; and reports runtime PQC support so the skip/pass split is visible.
- **Release workflow** (`.github/workflows/release.yml`) packs, runs a smoke test against the freshly packed `.nupkg`, generates and attaches a CycloneDX SBOM to the GitHub Release, and publishes to nuget.org.
- **NuGet packages are not author-signed.** The release workflow supports author signing via a code-signing certificate, but no certificate is currently configured — a certificate is a recurring cost subject to the same funding constraint as the external audit. Published packages carry only nuget.org's **repository signature** (applied to every package on nuget.org). The signing step warns loudly on every unsigned release; author signing will be enabled, and the workflow returned to fail-closed for stable tags, if/when a certificate is funded.
- **No `AssemblyOriginatorKeyFile` strong-name signing** of the assembly. Once shipped, this would be permanent ABI surface; we'll add it only if a real enterprise consumer requires it.

---

*To God be the glory.* — 1 Corinthians 10:31
