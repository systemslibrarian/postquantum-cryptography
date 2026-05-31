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
- **Draft, not final.** X-Wing is an IETF draft. The wire format is stable across recent revisions, but until it is published as an RFC, treat interoperability with other implementations as "verify before you rely."

## Cryptographic caveats

- **X25519 is bundled, not from the BCL.** .NET 10 does not expose X25519, so this library includes a constant-time port of TweetNaCl's `crypto_scalarmult` (public domain), validated against RFC 7748 test vectors (single, 1-iteration, and 1000-iteration). It is the only original cryptographic primitive here. Its core Montgomery ladder is constant-time, but it has **not** been independently audited for microarchitectural side channels (cache, timing on specific CPUs).
- **No independent security audit.** Nothing in this library has been formally audited.
- **No FIPS 140-3 validation** is claimed for this wrapper. The underlying BCL algorithms' validation status is the platform's matter.
- **Side channels of the BCL primitives** are out of this library's control and inherited from .NET.

## Platform / runtime availability

- **ML-KEM and ML-DSA require a PQC-capable platform crypto provider at runtime.** On .NET 10 these are surfaced from the BCL, but the underlying provider must support them — on Linux that means OpenSSL 3.5+ wired into the runtime build. Where it is not available, `MLKem.IsSupported` / `MLDsa.IsSupported` return `false` and the APIs throw `PlatformNotSupportedException`. Always check `MLKem768.IsSupported` / `MLDsa87.IsSupported` / `XWing.IsSupported` before use.
- This was observed in development: some .NET 10.0.x runtime builds report `IsSupported == false` even with OpenSSL 3.5 installed, because the runtime was not built against a PQC-enabled provider. The library is correct in that case (it faithfully delegates and the BCL throws); the limitation is environmental. The test suite **skips** (does not fail) the ML-KEM/ML-DSA/X-Wing tests on such hosts, while the pure-managed X25519 tests always run.

## Testing

- Tests cover round-trips, key/secret sizes, determinism, tamper detection, context binding, PEM/PKCS#8/SPKI interchange (including label-mismatch rejection), all ML-KEM and ML-DSA parameter sets, the RFC 7748 X25519 KATs (single + iterated) and DH commutativity property, KEM implicit-rejection robustness ("fuzz"-style random/garbage ciphertext), the new Span-based zero-allocation overloads, regression-style SHA-256 fingerprints of the deterministic `seed → public-key` mapping for every primitive (anchoring wrapper integrity), byte-equality cross-checks between the wrapper and direct BCL invocation, and X-Wing key-generation and decapsulation KATs from the IETF draft (Appendix C).
- ML-KEM / ML-DSA / X-Wing tests are gated on platform support (see above) and skip cleanly where the runtime does not expose the primitives. The X25519 tests are unconditional.
- The robustness tests are a fast in-process property check, **not** a coverage-guided fuzzer. A dedicated fuzzing harness (e.g. SharpFuzz) is future work.
- The deterministic-fingerprint KATs anchor wrapper integrity against the BCL's own implementation; they are **not** a substitute for a full NIST ACVP / Wycheproof interop battery.
- No performance benchmarks are published.

## Operational

- **CI** (GitHub Actions) builds, tests, packs, generates a CycloneDX SBOM, and verifies the build is deterministic (identical assembly hash across two builds). It also reports runtime PQC support so the skip/pass split is visible.
- **Package signing** is wired into CI but runs only when a `CODESIGN_PFX_BASE64` secret is configured; no signing certificate ships with the repo.
- No `AssemblyOriginatorKeyFile` strong-name signing of the assembly.
- SBOM is generated in CI but not yet published as a release asset.

---

*To God be the glory.* — 1 Corinthians 10:31
